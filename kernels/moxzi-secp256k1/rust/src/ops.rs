//! secp256k1 group arithmetic, free of the kernel ABI so that ../../check can test it natively
//! against the k256 calls it replaces.
//!
//! The points live in libsecp256k1-core (Parity's pure-Rust port of libsecp256k1: 10x26-bit
//! field, Jacobian coordinates); scalars, encodings, hashes and RFC 6979 stay with k256. The
//! reason is the field multiply: k256 picks its 5x52 field for any 64-bit target, and on wasm64
//! its u128 products are __multi3 calls, ~2,590 instructions per multiply against ~750 for the
//! 10x26 one (k256 builds 10x26 only for 32-bit targets, and that choice is not configurable).
//! Measured as whole operations: a k256 doubling ~19,400 instructions, libsecp256k1's ~5,200.
//!
//!  - k*G (public keys, signing, tweaks): a comb over a static table (tables.rs), constant
//!    time: every entry of every table is read and masked in (`select`), the loop does not
//!    depend on k, and the additions are libsecp256k1's constant-time formula (`add_ge` here,
//!    with masks where the Rust port branches). Each table
//!    entry carries a fixed offset point of unknown discrete log so that no entry is the
//!    point at infinity (add_ge needs that, as libsecp256k1's own ecmult_gen does); the sum of
//!    the offsets is subtracted at the end.
//!  - u1*G + u2*Q (ECDSA and BIP340 verification): one Strauss-Shamir pass over the GLV
//!    halves of both scalars -- four NAFs of ~128 bits (width 8 over a static table of odd
//!    multiples of G, width 5 over Q's), so ~128 doublings instead of 256. Variable time, on
//!    public data only.
//!  - 1/k for signing: crypto-bigint's constant-time inv_odd_mod (k256's Fermat chain is ~300
//!    multiplies of ~2,800 instructions).
//! The results are the same points and scalars, so every output is unchanged.
use crate::tables;
use k256::ecdsa::Signature;
use k256::elliptic_curve::{
    bigint::{ArrayEncoding, Limb},
    ff::PrimeField,
    ops::{Invert, Reduce},
    scalar::IsHigh,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    Curve, FieldBytesEncoding,
};
use k256::sha2::{Digest, Sha256};
use k256::{FieldBytes, NonZeroScalar, Scalar, Secp256k1, U256};
use libsecp256k1_core::curve::{Affine, AffineStorage, Field, FieldStorage, Jacobian};

/// A field element from 32 big-endian bytes; None if they are >= p.
pub fn field(b: &[u8]) -> Option<Field> {
    let mut f = Field::default();
    f.set_b32(b.try_into().ok()?).then_some(f)
}

fn fe_bytes(f: &Field) -> [u8; 32] {
    let mut f = *f;
    f.normalize();
    f.b32()
}

/// The x-coordinate of a finite point, big-endian.
pub fn x_bytes(a: &Affine) -> [u8; 32] { fe_bytes(&a.x) }

/// -x when `negate`, else x, without a branch on `negate`: every caller passes a secret bit (the
/// y parity of a secret multiple of G). Found by the constant-time gate
/// (instruction counts on PocketIC, 2026-10-23): the `if odd { -x } else { x }`
/// this replaces cost 58-64 more instructions for an odd y.
pub fn cneg(x: &Scalar, negate: bool) -> Scalar {
    Scalar::conditional_select(x, &-*x, Choice::from(negate as u8))
}

pub fn y_is_odd(a: &Affine) -> bool {
    let mut y = a.y;
    y.normalize();
    y.is_odd()
}

/// SEC1 encoding of a finite point: (bytes, length 33 or 65).
pub fn encode(a: &Affine, compressed: bool) -> ([u8; 65], usize) {
    let mut out = [0u8; 65];
    out[1..33].copy_from_slice(&x_bytes(a));
    if compressed {
        out[0] = 2 + y_is_odd(a) as u8;
        (out, 33)
    } else {
        out[0] = 4;
        out[33..].copy_from_slice(&fe_bytes(&a.y));
        (out, 65)
    }
}

/// Canonical SEC1, compressed (02/03 || x) or uncompressed (04 || x || y), x and y < p, on the
/// curve: exactly the keys k256's PublicKey::from_sec1_bytes accepts with those prefixes.
pub fn parse_public(b: &[u8]) -> Option<Affine> {
    let mut a = Affine::default();
    match (b.len(), b.first()) {
        (33, Some(&t @ (2 | 3))) => a.set_xo_var(&field(&b[1..])?, t == 3).then_some(a),
        (65, Some(4)) => {
            a.set_xy(&field(&b[1..33])?, &field(&b[33..])?);
            a.is_valid_var().then_some(a)
        }
        _ => None,
    }
}

/// BIP340 lift_x: the point with x-coordinate `b` (32 bytes, < p) and even y.
pub fn lift_x(b: &[u8]) -> Option<Affine> {
    if b.len() != 32 { return None }
    let mut a = Affine::default();
    a.set_xo_var(&field(b)?, false).then_some(a)
}

fn infinity() -> Jacobian {
    let mut j = Jacobian::default();
    j.set_infinity();
    j
}

/// The affine form of a point, None at infinity (constant-time inversion).
pub fn affine(j: &Jacobian) -> Option<Affine> {
    if j.is_infinity() { return None }
    let mut a = Affine::default();
    a.set_gej(j);
    Some(a)
}

/// k*G, constant time (see the module comment). Bit c of table t's digit in row `row` is bit
/// `row + R*t + R*T*c` of k, and COMB[t][d] = sum over the bits c of d of 2^(R*t + R*T*c) G,
/// plus offset t; COMB_FIX = -(2^R - 1) * (sum of the offsets).
pub fn mul_g(k: &Scalar) -> Jacobian {
    use tables::{COMB, COMB_FIX, COMB_R as R, COMB_T as T, COMB_W as W};
    let b = k.to_bytes();
    let bit = |i: usize| if i < 256 { ((b[31 - i / 8] >> (i % 8)) & 1) as u32 } else { 0 };
    let mut acc = infinity();
    for row in (0..R).rev() {
        if row != R - 1 { acc = acc.double_var(None) }
        for (t, entries) in COMB.iter().enumerate() {
            let mut digit = 0u32;
            for c in 0..W { digit |= bit(row + R * t + R * T * c) << c }
            acc = add_ge(&acc, &select(entries, digit));
        }
    }
    add_ge(&acc, &Affine::from(COMB_FIX))
}

/// a + b (b finite), constant time: C libsecp256k1's secp256k1_gej_add_ge (the version
/// libsecp256k1-core 0.3.0's `Jacobian::add_ge_in_place` ports, step for step, so the result is
/// the same Jacobian representation, limb for limb), with every data-dependent choice made by
/// masks: a == b (doubling) and the degenerate y1 == -y2, x1 != x2 (b = -LAMBDA a) through
/// `fe_cmov`, a at infinity by masking b's coordinates in, the sum at infinity from Z == 0.
///
/// Why not the crate's add_ge: its port writes normalizes_to_zero as `z0 == 0 || z1 == ..`,
/// `degenerate` as `m.normalizes_to_zero() && rr.normalizes_to_zero()` and Field::cmov as
/// `if flag { a } else { b }`, which the constant-time scan (kernels/ct-scan, 2026-10-24) found
/// compiled into 9 branches and 7 address selects in the alpha-10 pin. They only varied for
/// degenerate additions and on a.infinity (mul_g's first addition), so were not exploitable; this
/// has none (scan `ct`, no allowed site), and equals the crate's limb for limb (check:
/// add_ge_is_the_crates, comb_every_digit). Field magnitudes are exactly the crate's (<= 8 at mul).
#[inline(never)]
pub fn add_ge(a: &Jacobian, b: &Affine) -> Jacobian {
    const FE1: Field = Field::new(0, 0, 0, 0, 0, 0, 0, 1);
    debug_assert!(!b.infinity);
    let a_inf = Choice::from(a.infinity as u8);
    let zz = a.z.sqr(); // Z1^2
    let mut u1 = a.x;
    u1.normalize_weak(); // U1 = X1 (Z2 = 1)
    let u2 = b.x * zz; // U2 = X2 Z1^2
    let mut s1 = a.y;
    s1.normalize_weak(); // S1 = Y1
    let mut s2 = b.y * zz;
    s2 *= a.z; // S2 = Y2 Z1^3
    let mut t = u1;
    t += u2; // T = U1 + U2
    let mut m = s1;
    m += s2; // M = S1 + S2
    let mut rr = t.sqr();
    let mut m_alt = u2.neg(1);
    let tt = u1 * m_alt;
    rr += tt; // R = T^2 - U1 U2
    // R/M is lambda unless M == R == 0 (y1 == -y2, x1^3 == x2^3, x1 != x2): then (y1 - y2)/(x1 - x2).
    let degenerate = fe_is_zero(&m) & fe_is_zero(&rr);
    let mut rr_alt = s1;
    rr_alt.mul_int(2);
    m_alt += u1; // U1 - U2
    fe_cmov(&mut rr_alt, &rr, !degenerate);
    fe_cmov(&mut m_alt, &m, !degenerate);
    let mut n = m_alt.sqr();
    let mut q = n * t;
    n = n.sqr();
    fe_cmov(&mut n, &m, degenerate);
    t = rr_alt.sqr();
    let mut r = Jacobian::default();
    r.z = a.z * m_alt;
    let infinity = fe_is_zero(&r.z) & !a_inf;
    r.z.mul_int(2);
    q = q.neg(1);
    t += q;
    t.normalize_weak();
    r.x = t;
    t.mul_int(2);
    t += q;
    t *= rr_alt;
    t += n;
    r.y = t.neg(3);
    r.y.normalize_weak();
    r.x.mul_int(4);
    r.y.mul_int(4);
    // a at infinity: the sum is b, (b.x, b.y, 1).
    fe_cmov(&mut r.x, &b.x, a_inf);
    fe_cmov(&mut r.y, &b.y, a_inf);
    fe_cmov(&mut r.z, &FE1, a_inf);
    r.infinity = bool::from(infinity);
    r
}

/// r = a if `flag`, else r: the same limbs (and magnitude) as the crate's Field::cmov, with no
/// branch and no address chosen by the flag. The limbs are private to the crate, so the select is
/// r * (1 - flag) + a * flag through mul_int (its multiplier is opaque behind subtle's barrier;
/// mul_int scales the magnitude too, so the result carries the chosen element's).
fn fe_cmov(r: &mut Field, a: &Field, flag: Choice) {
    let mut take = *a;
    take.mul_int(flag.unwrap_u8() as u32);
    r.mul_int((!flag).unwrap_u8() as u32);
    *r += take;
}

/// Whether `f` is 0 mod p (the crate's normalizes_to_zero), as a Choice: the normalized limbs
/// ORed together, compared by subtle.
fn fe_is_zero(f: &Field) -> Choice {
    let mut t = *f;
    t.normalize();
    let s: FieldStorage = t.into();
    s.0.iter().fold(0u32, |acc, w| acc | w).ct_eq(&0)
}

/// entries[digit], reading every word of every entry and keeping one with a mask (subtle's u32
/// selection, its Choice behind subtle's optimisation barrier): no branch and no load address
/// depends on the digit. Not AffineStorage::cmov: that is `if flag { a } else { b }` per word,
/// which LLVM compiled (alpha-10 pin) into a branch over the chosen entry's loads plus selects of
/// load addresses keyed on the digit -- see check/wasm_ct_scan.py.
fn select(entries: &[AffineStorage], digit: u32) -> Affine {
    let (mut x, mut y) = ([0u32; 8], [0u32; 8]);
    for (i, e) in entries.iter().enumerate() {
        let c = (i as u32).ct_eq(&digit);
        for j in 0..8 {
            x[j].conditional_assign(&e.x.0[j], c);
            y[j].conditional_assign(&e.y.0[j], c);
        }
    }
    Affine::from(AffineStorage::new(FieldStorage(x), FieldStorage(y)))
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

/// The secp256k1 endomorphism: (x, y) -> (BETA x, y) is the multiplication by LAMBDA (below).
const BETA: Field = Field::new(
    0x7ae96a2b, 0x657c0710, 0x6e64479e, 0xac3434e9, 0x9cf04975, 0x12f58995, 0xc1396c28, 0x719501ee,
);

fn sc(b: [u8; 32]) -> Scalar {
    Option::from(Scalar::from_repr(b.into())).expect("Secp256k1: scalar constant")
}

/// round(k * g / 2^384), for the 256-bit constants g of `split`.
fn mul_shift_384(k: &Scalar, g: &[u8; 32]) -> Scalar {
    let (_, hi) = U256::from_be_slice(&k.to_bytes()).mul_wide(&U256::from_be_slice(g));
    let c = hi.shr_vartime(128).wrapping_add(&hi.shr_vartime(127).bitand(&U256::ONE));
    sc(c.to_be_byte_array().into())
}

/// The GLV split of a public scalar: k = r1 + r2 * LAMBDA (mod n) with |r1|, |r2| < 2^129,
/// each returned as (|r|, negated). The constants and the formula are k256's own
/// `decompose_scalar` (arithmetic/mul.rs, after libsecp256k1's scalar_split_lambda). Any
/// rounding error would only make r1, r2 longer, never the sum wrong: r1 is k - r2 * LAMBDA.
pub fn split(k: &Scalar) -> [(Scalar, bool); 2] {
    const MINUS_LAMBDA: [u8; 32] = [
        0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b, 0xa4,
        0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12, 0x83, 0xcf,
    ];
    const MINUS_B1: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
    ];
    const MINUS_B2: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1, 0x56, 0x2c,
    ];
    const G1: [u8; 32] = [
        0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15,
        0x3d, 0xaa, 0x8a, 0x14, 0x71, 0xe8, 0xca, 0x7f, 0xe8, 0x93, 0x20, 0x9a, 0x45, 0xdb, 0xb0, 0x31,
    ];
    const G2: [u8; 32] = [
        0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc4,
        0x22, 0x12, 0x08, 0xac, 0x9d, 0xf5, 0x06, 0xc6, 0x15, 0x71, 0xb4, 0xae, 0x8a, 0xc4, 0x7f, 0x71,
    ];
    let c1 = mul_shift_384(k, &G1) * sc(MINUS_B1);
    let c2 = mul_shift_384(k, &G2) * sc(MINUS_B2);
    let r2 = c1 + c2;
    let r1 = *k + r2 * sc(MINUS_LAMBDA);
    [r1, r2].map(|r| if bool::from(r.is_high()) { (-r, true) } else { (r, false) })
}

/// u1*G + u2*Q, variable time: one Strauss-Shamir pass over the GLV halves of both scalars
/// (four NAFs of ~128 bits, so ~128 doublings instead of 256). G's odd multiples come from
/// the static table, their endomorphism images by one multiplication by BETA.
pub fn mul_add_vartime(u1: &Scalar, q: &Affine, u2: &Scalar) -> Jacobian {
    let [(a1, na1), (a2, na2)] = split(u1);
    let [(b1, nb1), (b2, nb2)] = split(u2);
    let w = tables::ODD_G_WIDTH;
    let (da1, da2, db1, db2) = (wnaf(&a1, w), wnaf(&a2, w), wnaf(&b1, 5), wnaf(&b2, 5));
    let qj = Jacobian::from_ge(q);
    let q2 = qj.double_var(None);
    let mut qt = [qj; 8];
    for i in 1..8 { qt[i] = qt[i - 1].add_var(&q2, None) }
    let ql = qt.map(|j| Jacobian { x: j.x * BETA, ..j });
    let top = (0..258).rev().find(|&i| da1[i] != 0 || da2[i] != 0 || db1[i] != 0 || db2[i] != 0).map_or(0, |i| i + 1);
    let add_g = |acc: &mut Jacobian, d: i8, neg: bool, endo: bool| {
        if d == 0 { return }
        let mut e = Affine::from(tables::ODD_G[d.unsigned_abs() as usize / 2]);
        if endo { e.x = e.x * BETA }
        if (d < 0) != neg { e = e.neg() }
        *acc = acc.add_ge_var(&e, None);
    };
    let add_q = |acc: &mut Jacobian, d: i8, neg: bool, t: &[Jacobian; 8]| {
        if d == 0 { return }
        let e = &t[d.unsigned_abs() as usize / 2];
        *acc = if (d < 0) != neg { acc.add_var(&e.neg(), None) } else { acc.add_var(e, None) };
    };
    let mut acc = infinity();
    for i in (0..top).rev() {
        acc = acc.double_var(None);
        add_g(&mut acc, da1[i], na1, false);
        add_g(&mut acc, da2[i], na2, true);
        add_q(&mut acc, db1[i], nb1, &qt);
        add_q(&mut acc, db2[i], nb2, &ql);
    }
    acc
}

/// P + Q for finite points, variable time; None at infinity.
pub fn add_vartime(p: &Affine, q: &Affine) -> Option<Affine> {
    affine(&Jacobian::from_ge(p).add_ge_var(q, None))
}

/// k*G + P (P finite), constant time; None at infinity.
pub fn mul_g_add(k: &Scalar, p: &Affine) -> Option<Affine> {
    affine(&add_ge(&mul_g(k), p))
}

/// 1/s for a non-zero scalar, constant time.
pub fn invert(s: &Scalar) -> Scalar {
    let (inv, ok) = U256::from_be_slice(s.to_bytes().as_slice()).inv_odd_mod(&Secp256k1::ORDER);
    assert!(bool::from(ok), "Secp256k1: inverting zero");
    Option::from(Scalar::from_repr(inv.to_be_byte_array())).expect("Secp256k1: inverse out of range")
}

pub fn reduce(b: &[u8]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(b))
}

/// RFC 6979 ECDSA of a 32-byte digest, low-S: what `d.try_sign_prehashed_rfc6979::<Sha256>(z,
/// &[])` computes for k256 with z the digest reduced mod n -- ecdsa 0.16.9's rfc6979 nonce
/// and hazmat::sign_prehashed, then k256's normalize_s -- through the same steps, with mul_g
/// for k*G and `invert` for 1/k. None where that returns an error.
pub fn ecdsa_sign(d: &NonZeroScalar, h: &[u8; 32]) -> Option<[u8; 64]> {
    // RFC 6979 bits2octets: the nonce derivation takes the digest reduced mod n (ecdsa 0.16's
    // sign_prehash passes it unreduced, which differs from RFC 6979 for digests >= n).
    let z = reduce(h).to_bytes();
    let k = Option::<Scalar>::from(Scalar::from_repr(rfc6979::generate_k::<Sha256, _>(
        &(**d).to_repr(), &Secp256k1::ORDER.encode_field_bytes(), &z, &[],
    )))?;
    if bool::from(k.is_zero()) { return None }
    let z = reduce(&z);
    let k_inv = invert(&k);
    let big_r = affine(&mul_g(&k))?;
    let r = reduce(&x_bytes(&big_r));
    let s = k_inv * (z + r * **d);
    // Low-S as k256's normalize_s defines it (-s when s > n/2), without its branch: normalize_s
    // rebuilds the signature when s is high, 204 instructions the constant-time gate saw.
    let s = Scalar::conditional_select(&s, &-s, s.is_high());
    let sig = Signature::from_scalars(r, s).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Some(out)
}

/// ECDSA verification as k256's VerifyingKey::verify_prehash computes it for a 32-byte digest
/// (high-S refused, then ecdsa 0.16.9's hazmat::verify_prehashed), with the final x
/// comparison done projectively: x mod n == r iff x == r, or x == r + n when r + n < p.
pub fn ecdsa_verify(q: &Affine, h: &[u8; 32], sig: &Signature) -> bool {
    if bool::from(sig.s().is_high()) { return false }
    let z = reduce(h);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    x_mod_n_is(&mul_add_vartime(&(z * s_inv), q, &(*r * s_inv)), &r)
}

/// Whether the x-coordinate of `p` (a Jacobian point) is r mod n; false at infinity (whose
/// affine x, as k256 encodes it, is 0, never a valid r). Since n < p < 2n, x mod n == r iff
/// x == r, or x == r + n when r + n < p. Compared as X == r Z^2: no inversion.
pub fn x_mod_n_is(p: &Jacobian, r: &Scalar) -> bool {
    if p.is_infinity() { return false }
    let rb = r.to_bytes();
    if p.eq_x_var(&field(&rb).expect("Secp256k1: r < n < p")) { return true }
    let (rn, carry) = U256::from_be_slice(&rb).adc(&Secp256k1::ORDER, Limb::ZERO);
    if carry != Limb::ZERO { return false }
    match field(&rn.to_be_byte_array()) { Some(x) => p.eq_x_var(&x), None => false }
}

/// BIP340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || parts...).
fn tagged(tag: &[u8]) -> Sha256 {
    let t = Sha256::digest(tag);
    Sha256::new().chain_update(t).chain_update(t)
}

/// BIP340 signing, exactly the reference algorithm. None if the nonce is zero.
pub fn schnorr_sign(d0: &NonZeroScalar, msg: &[u8], aux: &[u8]) -> Option<[u8; 64]> {
    let p = affine(&mul_g(d0))?;
    let d = cneg(d0, y_is_odd(&p));
    let mut t = tagged(b"BIP0340/aux").chain_update(aux).finalize();
    for (x, y) in t.iter_mut().zip(d.to_bytes().iter()) { *x ^= y }
    let px = x_bytes(&p);
    let rand = tagged(b"BIP0340/nonce").chain_update(t).chain_update(px).chain_update(msg).finalize();
    let k0 = reduce(&rand);
    if bool::from(k0.is_zero()) { return None }
    let r = affine(&mul_g(&k0))?;
    let k = cneg(&k0, y_is_odd(&r));
    let rx = x_bytes(&r);
    let e = reduce(&tagged(b"BIP0340/challenge").chain_update(rx).chain_update(px).chain_update(msg).finalize());
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&rx);
    out[32..].copy_from_slice(&(k + e * d).to_bytes());
    Some(out)
}

/// BIP340 verification, exactly the reference algorithm (r < p and s < n; zero allowed).
pub fn schnorr_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 { return false }
    let Some(p) = lift_x(pk) else { return false };
    if field(&sig[..32]).is_none() { return false } // r < p
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(&sig[32..]))) else { return false };
    let e = reduce(&tagged(b"BIP0340/challenge").chain_update(&sig[..32]).chain_update(pk).chain_update(msg).finalize());
    let Some(r) = affine(&mul_add_vartime(&s, &p, &-e)) else { return false };
    !y_is_odd(&r) && x_bytes(&r)[..] == sig[..32]
}
