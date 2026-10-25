//! P-256 arithmetic on top of RustCrypto `p256`'s public API, free of the kernel ABI so that
//! ../../check can test it natively against the calls it replaces.
//!
//! p256's field arithmetic is the fastest available here (its 64-bit Montgomery multiply is
//! ~1,930 wasm instructions; fiat-crypto's 32-bit one ~2,510), so the savings are algorithmic:
//!  - k*G (publicKey, derivePublicKey, signing) by a fixed-base comb over a static table
//!    instead of the generic double-and-add: 16 doublings and 64 additions instead of 256 and
//!    ~80. Constant time: every entry of every table is scanned with a conditional move, and
//!    the loop does not depend on the scalar.
//!  - u1*G + u2*Q (verification) by one Strauss-Shamir pass over two width-w NAFs, sharing
//!    the doublings, instead of two separate multiplications; in Jacobian coordinates on
//!    p256's FieldElement (the `expose-field` feature) with the standard variable-time
//!    formulas for a = -3 (EFD dbl-2001-b, madd-2007-bl, add-2007-bl): a doubling is 3M + 5S
//!    instead of p256's complete 8M + 3S plus constants, and the final x check is X == r Z^2,
//!    no inversion. Variable time: u1, u2 and Q are public.
//!  - scalar inversion by crypto-bigint's constant-time binary algorithm (`inv_odd_mod`)
//!    instead of p256's Fermat exponentiation (~420 scalar multiplications).
//! The results are the same group elements and scalars, so every output is unchanged.
use crate::tables;
use p256::ecdsa::Signature;
use p256::elliptic_curve::{
    bigint::{ArrayEncoding, Limb, U256},
    ff::{Field, PrimeField},
    ops::Reduce,
    point::AffineCoordinates,
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    subtle::{ConditionallySelectable, ConstantTimeEq},
    Curve, FieldBytesEncoding, Group,
};
use p256::{AffinePoint, FieldBytes, FieldElement as Fe, NistP256, NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use sha2::Sha256;

/// A table point (x || y, big-endian), checked to be on the curve as it is decoded.
fn point(b: &[u8; 64]) -> AffinePoint {
    Option::from(AffinePoint::from_encoded_point(&EncodedPoint::<NistP256>::from_untagged_bytes(b.into())))
        .expect("P256: corrupt static table")
}

/// k*G, constant time: a comb with tables::COMB_TABLES tables of 15 points. Bit
/// `row + ROWS*t + 64*c` of k is bit c of table t's digit in row `row`, and
/// COMB[t][d-1] = sum over the bits c of d of 2^(ROWS*t + 64*c) * G.
pub fn mul_g(k: &Scalar) -> ProjectivePoint {
    use tables::{COMB, COMB_ROWS as ROWS, COMB_TABLES as TABLES};
    let mut table = [[AffinePoint::IDENTITY; 15]; TABLES];
    for (t, enc) in table.iter_mut().zip(COMB.iter()) {
        for (p, e) in t.iter_mut().zip(enc.iter()) { *p = point(e) }
    }
    let bytes = k.to_bytes();
    let bit = |i: usize| (bytes[31 - i / 8] >> (i % 8)) & 1;
    let mut acc = ProjectivePoint::IDENTITY;
    for row in (0..ROWS).rev() {
        acc = acc.double();
        for (t, entries) in table.iter().enumerate() {
            let mut digit = 0u8;
            for c in 0..4 { digit |= bit(row + ROWS * t + 64 * c) << c }
            let mut sel = AffinePoint::IDENTITY;
            for (i, e) in entries.iter().enumerate() {
                sel.conditional_assign(e, digit.ct_eq(&(i as u8 + 1)));
            }
            acc += sel; // complete mixed addition; the identity (digit 0) is handled by it
        }
    }
    acc
}

/// The width-w NAF of a scalar, least significant digit first: odd digits in (-2^(w-1),
/// 2^(w-1)), each followed by at least w-1 zeros. Variable time (public scalars only).
pub fn wnaf(k: &Scalar, w: u32) -> [i8; 258] {
    let b = k.to_bytes();
    let mut n = [0u64; 5];
    for i in 0..4 { n[i] = u64::from_be_bytes(b[24 - 8 * i..32 - 8 * i].try_into().unwrap()) }
    let mut out = [0i8; 258];
    let mut i = 0;
    while n.iter().any(|&l| l != 0) {
        if n[0] & 1 == 1 {
            let mut d = (n[0] & ((1 << w) - 1)) as i64;
            if d >= 1 << (w - 1) { d -= 1 << w }
            out[i] = d as i8;
            // n -= d
            let (mut borrow, mut carry) = (if d > 0 { d as u64 } else { 0 }, if d < 0 { (-d) as u64 } else { 0 });
            for l in n.iter_mut() {
                let (v, b1) = l.overflowing_sub(borrow);
                let (v, c1) = v.overflowing_add(carry);
                *l = v;
                borrow = b1 as u64;
                carry = c1 as u64;
            }
        }
        for j in 0..4 { n[j] = (n[j] >> 1) | (n[j + 1] << 63) }
        n[4] >>= 1;
        i += 1;
    }
    out
}

/// A field element from big-endian u64 words, evaluated at compile time (Horner in 2^64).
const fn fe(w: &[u64]) -> Fe {
    let b = Fe::from_u64(1 << 32).multiply(&Fe::from_u64(1 << 32));
    Fe::from_u64(w[0]).multiply(&b).add(&Fe::from_u64(w[1])).multiply(&b).add(&Fe::from_u64(w[2]))
        .multiply(&b).add(&Fe::from_u64(w[3]))
}

/// G, 3G, ..., (2^(ODD_G_WIDTH-1) - 1)G as field elements, built from tables::ODD_G when the
/// kernel is compiled (no per-call decoding).
static ODD_G: [(Fe, Fe); tables::ODD_G.len()] = {
    let mut t = [(Fe::ZERO, Fe::ZERO); tables::ODD_G.len()];
    let mut i = 0;
    while i < t.len() {
        let w = &tables::ODD_G[i];
        t[i] = (fe(&[w[0], w[1], w[2], w[3]]), fe(&[w[4], w[5], w[6], w[7]]));
        i += 1;
    }
    t
};

/// A point in Jacobian coordinates (x = X/Z^2, y = Y/Z^3); Z = 0 is the point at infinity.
#[derive(Clone, Copy)]
pub struct Jac { pub x: Fe, pub y: Fe, pub z: Fe }

impl Jac {
    pub const INFINITY: Jac = Jac { x: Fe::ONE, y: Fe::ONE, z: Fe::ZERO };

    pub fn is_infinity(&self) -> bool { bool::from(self.z.is_zero()) }

    fn neg(&self) -> Jac { Jac { y: -self.y, ..*self } }

    /// dbl-2001-b (a = -3). The point at infinity stays there (Z3 = 0 when Z1 = 0); no other
    /// point has y = 0 on a curve of prime order.
    pub fn double(&self) -> Jac {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x * gamma;
        let t = (self.x - delta) * (self.x + delta);
        let alpha = t.double() + t;
        let beta4 = beta.double().double();
        let x = alpha.square() - beta4.double();
        let z = (self.y + self.z).square() - gamma - delta;
        let y = alpha * (beta4 - x) - gamma.square().double().double().double();
        Jac { x, y, z }
    }

    /// madd-2007-bl: self + (x2, y2), with the cases the formula does not cover.
    pub fn add_affine(&self, x2: &Fe, y2: &Fe) -> Jac {
        if self.is_infinity() { return Jac { x: *x2, y: *y2, z: Fe::ONE } }
        let z1z1 = self.z.square();
        let u2 = *x2 * z1z1;
        let s2 = *y2 * self.z * z1z1;
        let h = u2 - self.x;
        let r = (s2 - self.y).double();
        if bool::from(h.is_zero()) { return if bool::from(r.is_zero()) { self.double() } else { Jac::INFINITY } }
        let hh = h.square();
        let i = hh.double().double();
        let j = h * i;
        let v = self.x * i;
        let x = r.square() - j - v.double();
        let y = r * (v - x) - (self.y * j).double();
        let z = (self.z + h).square() - z1z1 - hh;
        Jac { x, y, z }
    }

    /// add-2007-bl: self + o, with the cases the formula does not cover.
    pub fn add(&self, o: &Jac) -> Jac {
        if self.is_infinity() { return *o }
        if o.is_infinity() { return *self }
        let z1z1 = self.z.square();
        let z2z2 = o.z.square();
        let u1 = self.x * z2z2;
        let u2 = o.x * z1z1;
        let s1 = self.y * o.z * z2z2;
        let s2 = o.y * self.z * z1z1;
        let h = u2 - u1;
        let r = (s2 - s1).double();
        if bool::from(h.is_zero()) { return if bool::from(r.is_zero()) { self.double() } else { Jac::INFINITY } }
        let i = h.double().square();
        let j = h * i;
        let v = u1 * i;
        let x = r.square() - j - v.double();
        let y = r * (v - x) - (s1 * j).double();
        let z = ((self.z + o.z).square() - z1z1 - z2z2) * h;
        Jac { x, y, z }
    }
}

/// The affine coordinates of a finite point (x, y).
pub fn coordinates(p: &AffinePoint) -> (Fe, Fe) {
    let e = p.to_encoded_point(false);
    let c = |b: &[u8]| Option::from(Fe::from_bytes(FieldBytes::from_slice(b))).expect("P256: coordinate < p");
    (c(&e.as_bytes()[1..33]), c(&e.as_bytes()[33..65]))
}

/// u1*G + u2*Q (Q finite), variable time.
pub fn lincomb_g(u1: &Scalar, q: &AffinePoint, u2: &Scalar) -> Jac {
    let (a, b) = (wnaf(u1, tables::ODD_G_WIDTH), wnaf(u2, 5));
    let (qx, qy) = coordinates(q);
    let qj = Jac { x: qx, y: qy, z: Fe::ONE };
    let q2 = qj.double();
    let mut qt = [qj; 8];
    for i in 1..8 { qt[i] = qt[i - 1].add(&q2) }
    let top = (0..258).rev().find(|&i| a[i] != 0 || b[i] != 0).map_or(0, |i| i + 1);
    let mut acc = Jac::INFINITY;
    for i in (0..top).rev() {
        acc = acc.double();
        match a[i] {
            0 => {}
            d if d > 0 => { let (x, y) = &ODD_G[d as usize / 2]; acc = acc.add_affine(x, y) }
            d => { let (x, y) = &ODD_G[(-d) as usize / 2]; acc = acc.add_affine(x, &-*y) }
        }
        match b[i] {
            0 => {}
            d if d > 0 => acc = acc.add(&qt[d as usize / 2]),
            d => acc = acc.add(&qt[(-d) as usize / 2].neg()),
        }
    }
    acc
}

/// Whether the x-coordinate of `p` is r mod n; false at infinity (whose affine x, as p256
/// encodes it, is 0, never a valid r). Since n < p < 2n, x mod n == r iff x == r, or
/// x == r + n when r + n < p. Compared as X == r Z^2: no inversion.
pub fn x_mod_n_is(p: &Jac, r: &Scalar) -> bool {
    if p.is_infinity() { return false }
    let z2 = p.z.square();
    let rb = r.to_bytes();
    let rf: Fe = Option::from(Fe::from_bytes(&rb)).expect("P256: r < n < p");
    if p.x == rf * z2 { return true }
    let (rn, carry) = U256::from_be_slice(&rb).adc(&NistP256::ORDER, Limb::ZERO);
    if carry != Limb::ZERO { return false }
    match Option::<Fe>::from(Fe::from_uint(rn)) { Some(x) => p.x == x * z2, None => false }
}

/// 1/s for a non-zero scalar, constant time.
pub fn invert(s: &Scalar) -> Scalar {
    let (inv, ok) = U256::from_be_slice(s.to_bytes().as_slice()).inv_odd_mod(&NistP256::ORDER);
    assert!(bool::from(ok), "P256: inverting zero");
    Option::from(Scalar::from_repr(inv.to_be_byte_array())).expect("P256: inverse out of range")
}

fn reduce(b: &FieldBytes) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(b)
}

/// RFC 6979 ECDSA over a 32-byte digest, s as computed (not normalized): what
/// `d.try_sign_prehashed_rfc6979::<Sha256>(z, &[])` (ecdsa 0.16.9 hazmat) computes with z the
/// digest reduced mod n, through the same steps, with mul_g for k*G and `invert` for 1/k.
/// None where that returns an error.
pub fn sign_prehash(d: &NonZeroScalar, h: &[u8; 32]) -> Option<[u8; 64]> {
    // RFC 6979 bits2octets: the nonce derivation takes the digest reduced mod n (ecdsa 0.16's
    // sign_prehash passes it unreduced, which differs from RFC 6979 for digests >= n).
    let z = reduce(FieldBytes::from_slice(h)).to_bytes();
    // try_sign_prehashed_rfc6979:
    let k = Option::<Scalar>::from(Scalar::from_repr(rfc6979::generate_k::<Sha256, _>(
        &(**d).to_repr(), &NistP256::ORDER.encode_field_bytes(), &z, &[],
    )))?;
    // hazmat::sign_prehashed:
    if bool::from(k.is_zero()) { return None }
    let z = reduce(&z);
    let k_inv = invert(&k);
    let r_point = mul_g(&k).to_affine();
    let r = reduce(&r_point.x());
    let s = k_inv * (z + r * **d);
    let sig = Signature::from_scalars(r, s).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Some(out)
}

/// ECDSA verification as `VerifyingKey::verify_prehash` (ecdsa 0.16.9 hazmat::verify_prehashed)
/// computes it for a 32-byte digest; low-S and high-S signatures are both accepted.
pub fn verify_prehash(key: &PublicKey, h: &[u8; 32], sig: &Signature) -> bool {
    let z = reduce(FieldBytes::from_slice(h));
    let (r, s) = sig.split_scalars();
    let s_inv = invert(&s);
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    x_mod_n_is(&lincomb_g(&u1, key.as_affine(), &u2), &r)
}
