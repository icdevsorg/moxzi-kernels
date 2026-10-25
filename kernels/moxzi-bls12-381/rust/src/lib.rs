//! BLS12-381 kernels for the `moxzi-bls12-381` Motoko package (ABI 1, see moxzi-kernel).
//!
//! Encodings (the same as the Motoko bodies in src/Bls12381.mo):
//!  - G1 point: 48-byte compressed (IETF / Zcash flags); G2 point: 96-byte compressed, imaginary
//!    part of x first. Every point is checked: canonical encoding, on the curve, in the prime-order
//!    subgroup. The identity (0xc0 then zeros) is a valid group element.
//!  - Scalar: 32 bytes big-endian, below the group order r.
//!  - Field element (map): Fp 48 bytes big-endian below p; Fp2 96 bytes, real part (c0) first.
//!  - Lists: concatenated fixed-size items in one Blob (n x 48 for G1, n x 96 for G2, n x 32 for
//!    scalars and for Ethereum aggregate messages, n x 144 = G1 then G2 for pairing terms).
//! Group operations return null on any invalid input (bad length, bad point, scalar >= r, field
//! element >= p, mismatched list lengths); verification and pairingCheck return false.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField, MapToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use moxzi_kernel::{bytes, output, NONE};
use sha2::digest::generic_array::GenericArray;
use sha2::Sha256;

const ETH_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const ETH_POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const FP_MODULUS: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

type Fp = <G1Projective as MapToCurve>::Field;
type Fp2 = <G2Projective as MapToCurve>::Field;

/// The one encoding of the identity: 0xc0, then zeros. `from_compressed` maps exactly this
/// encoding to the identity, but recovers a square root first (constant time); skip that.
fn is_identity_encoding(b: &[u8]) -> bool {
    b[0] == 0xc0 && b[1..].iter().all(|&x| x == 0)
}

fn g1(b: &[u8]) -> Option<G1Affine> {
    let b: &[u8; 48] = b.try_into().ok()?;
    if is_identity_encoding(b) {
        return Some(G1Affine::identity());
    }
    Option::from(G1Affine::from_compressed(b))
}

fn g2(b: &[u8]) -> Option<G2Affine> {
    let b: &[u8; 96] = b.try_into().ok()?;
    if is_identity_encoding(b) {
        return Some(G2Affine::identity());
    }
    Option::from(G2Affine::from_compressed(b))
}

/// Decoding with a memo: equal encodings decode to equal points, so a list that repeats a point
/// (pairing terms sharing a G2 operand, say) pays the square root and subgroup check once.
struct Decoded<'a, T> {
    seen: Vec<(&'a [u8], Option<T>)>,
}

impl<'a, T: Copy> Decoded<'a, T> {
    fn new() -> Self {
        Decoded { seen: Vec::new() }
    }
    fn get(&mut self, b: &'a [u8], decode: fn(&[u8]) -> Option<T>) -> Option<T> {
        if let Some((_, p)) = self.seen.iter().find(|(e, _)| *e == b) {
            return *p;
        }
        let p = decode(b);
        self.seen.push((b, p));
        p
    }
}

fn scalar(b: &[u8]) -> Option<Scalar> {
    let mut le: [u8; 32] = b.try_into().ok()?;
    le.reverse();
    Option::from(Scalar::from_bytes(&le))
}

/// A canonical 48-byte big-endian Fp element, as `from_okm` input (64 bytes, reduced mod p).
fn field(b: &[u8], okm: &mut [u8]) -> Option<()> {
    if b.len() != 48 || b >= &FP_MODULUS[..] {
        return None;
    }
    okm[16..64].copy_from_slice(b);
    Some(())
}

fn map_fp(b: &[u8]) -> Option<G1Projective> {
    let mut okm = [0u8; 64];
    field(b, &mut okm)?;
    #[allow(deprecated)]
    let u = <Fp as HashToField>::from_okm(GenericArray::from_slice(&okm));
    Some(G1Projective::map_to_curve(&u).clear_h())
}

fn map_fp2(b: &[u8]) -> Option<G2Projective> {
    if b.len() != 96 {
        return None;
    }
    let mut okm = [0u8; 128];
    field(&b[..48], &mut okm[..64])?;
    field(&b[48..], &mut okm[64..])?;
    #[allow(deprecated)]
    let u = <Fp2 as HashToField>::from_okm(GenericArray::from_slice(&okm));
    Some(map_g2_field(&u).clear_h())
}

/// The SSWU + 3-isogeny map to the G2 curve (before cofactor clearing).
///
/// bls12_381 0.8.0 maps u = 0 wrongly (in map_g2.rs every alternate eta candidate is zero there,
/// so the last one overwrites the valid square root). For that single input this uses the RFC 9380
/// image, computed independently with py_ecc 8.0.0 (`map_to_curve_G2(FQ2.zero())`); the upstream
/// crate is used unmodified. The Motoko body (mo:bls12-381) maps u = 0 correctly.
fn map_g2_field(u: &Fp2) -> G2Projective {
    if u == &Fp2::default() {
        const ZERO_IMAGE: [u8; 96] = [
            0x88, 0x69, 0x82, 0x26, 0x66, 0xfe, 0x85, 0x0c, 0xb9, 0x3d, 0xfd, 0x4f, 0xa6, 0x4e, 0xbd, 0x9e,
            0xf7, 0x7b, 0xa6, 0x2b, 0x5c, 0x12, 0x05, 0x5e, 0xad, 0xb6, 0xe7, 0xcc, 0x89, 0x72, 0xf6, 0x4e,
            0x01, 0xc4, 0x57, 0x7d, 0x3d, 0x52, 0x45, 0x6c, 0x26, 0x86, 0x76, 0x47, 0xf5, 0x36, 0x65, 0x19,
            0x0c, 0xdf, 0xcc, 0x95, 0x23, 0x30, 0x5c, 0x43, 0xef, 0x59, 0xa4, 0xe3, 0x47, 0xcb, 0x3f, 0xc7,
            0x66, 0x88, 0xc6, 0x0b, 0x05, 0xba, 0xfe, 0xbd, 0x44, 0x5a, 0x65, 0x90, 0x1b, 0x5d, 0xd4, 0x06,
            0x44, 0xe2, 0x1d, 0x35, 0xdc, 0xbe, 0x50, 0xa9, 0x59, 0x55, 0xe4, 0xf8, 0xe2, 0x4f, 0xbe, 0x6f,
        ];
        // On the curve but deliberately not in the subgroup yet (the cofactor is cleared later).
        G2Projective::from(G2Affine::from_compressed_unchecked(&ZERO_IMAGE).unwrap())
    } else {
        G2Projective::map_to_curve(u)
    }
}

fn hash_g1(msg: &[u8], dst: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, dst)
}

fn hash_g2(msg: &[u8], dst: &[u8]) -> G2Projective {
    let mut u = [Fp2::default(); 2];
    Fp2::hash_to_field::<ExpandMsgXmd<Sha256>>(msg, dst, &mut u);
    (map_g2_field(&u[0]) + map_g2_field(&u[1])).clear_h()
}

/// prod e(p_i, q_i) == 1. Terms with an identity point contribute 1.
///
/// Before any Miller loop the product is shortened with bilinearity, which leaves its value
/// unchanged: e(a, Q) e(b, Q) = e(a + b, Q) and e(P, a) e(P, b) = e(P, a + b); terms with an
/// identity point (given, or a sum that cancelled) are dropped as e(O, Q) = e(P, O) = 1. An
/// empty product is 1 without a pairing. All points here are already validated (or hashed).
fn pairing_product_is_one(terms: &[(G1Affine, G2Affine)]) -> bool {
    let terms = merge_terms(terms);
    if terms.is_empty() {
        return true;
    }
    let prepared: Vec<(G1Affine, G2Prepared)> = terms.iter().map(|(p, q)| (*p, G2Prepared::from(*q))).collect();
    let refs: Vec<(&G1Affine, &G2Prepared)> = prepared.iter().map(|(p, q)| (p, q)).collect();
    multi_miller_loop(&refs).final_exponentiation() == Gt::identity()
}

/// The terms of `pairing_product_is_one` with equal G2 operands merged (G1 operands summed), then
/// equal G1 operands merged (G2 operands summed), and identity terms dropped.
fn merge_terms(terms: &[(G1Affine, G2Affine)]) -> Vec<(G1Affine, G2Affine)> {
    let live = |p: &G1Affine, q: &G2Affine| !bool::from(p.is_identity()) && !bool::from(q.is_identity());
    // Equal Q: sum the P's.
    let mut by_q: Vec<(G1Projective, G2Affine, bool)> = Vec::new();
    for (p, q) in terms.iter().filter(|(p, q)| live(p, q)) {
        match by_q.iter_mut().find(|(_, q2, _)| q2 == q) {
            Some((sum, _, merged)) => {
                *sum += p;
                *merged = true;
            }
            None => by_q.push((G1Projective::from(p), *q, false)),
        }
    }
    let merged = by_q.iter().any(|(_, _, m)| *m);
    let mut stage: Vec<(G1Affine, G2Affine)> = if merged {
        let sums: Vec<G1Projective> = by_q.iter().map(|(s, _, _)| *s).collect();
        let mut affine = alloc::vec![G1Affine::identity(); sums.len()];
        G1Projective::batch_normalize(&sums, &mut affine);
        affine.into_iter().zip(by_q.iter().map(|(_, q, _)| *q)).filter(|(p, q)| live(p, q)).collect()
    } else {
        terms.iter().copied().filter(|(p, q)| live(p, q)).collect()
    };
    // Equal P: sum the Q's.
    let mut by_p: Vec<(G1Affine, G2Projective, bool)> = Vec::new();
    for (p, q) in stage.iter() {
        match by_p.iter_mut().find(|(p2, _, _)| p2 == p) {
            Some((_, sum, merged)) => {
                *sum += q;
                *merged = true;
            }
            None => by_p.push((*p, G2Projective::from(q), false)),
        }
    }
    if by_p.iter().any(|(_, _, m)| *m) {
        let sums: Vec<G2Projective> = by_p.iter().map(|(_, s, _)| *s).collect();
        let mut affine = alloc::vec![G2Affine::identity(); sums.len()];
        G2Projective::batch_normalize(&sums, &mut affine);
        stage = by_p.iter().map(|(p, _, _)| *p).zip(affine).filter(|(p, q)| live(p, q)).collect();
    }
    stage
}

/// A public key for the Ethereum ciphersuite: valid, and not the identity (KeyValidate).
fn eth_key(b: &[u8]) -> Option<G1Affine> {
    g1(b).filter(|p| !bool::from(p.is_identity()))
}

/// A signature: valid, and not the identity.
fn eth_sig(b: &[u8]) -> Option<G2Affine> {
    g2(b).filter(|p| !bool::from(p.is_identity()))
}

/// e(pk, H(msg)) == e(g1, sig)
fn core_verify(pk: G1Affine, msg: &[u8], sig: G2Affine, dst: &[u8]) -> bool {
    pairing_product_is_one(&[(pk, G2Affine::from(hash_g2(msg, dst))), (-G1Affine::generator(), sig)])
}

fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Some(pk), Some(sig)) = (eth_key(pk), eth_sig(sig)) else { return false };
    core_verify(pk, msg, sig, ETH_DST)
}

fn pop_verify(pk_bytes: &[u8], proof: &[u8]) -> bool {
    let (Some(pk), Some(proof)) = (eth_key(pk_bytes), eth_sig(proof)) else { return false };
    core_verify(pk, pk_bytes, proof, ETH_POP_DST)
}

fn aggregate_verify(pks: &[u8], msgs: &[u8], sig: &[u8]) -> bool {
    let n = pks.len() / 48;
    if n == 0 || pks.len() % 48 != 0 || msgs.len() != 32 * n {
        return false;
    }
    let Some(sig) = eth_sig(sig) else { return false };
    let mut terms = Vec::with_capacity(n + 1);
    // A repeated message is hashed once (and its terms then merge in the pairing product).
    let mut hashes: Vec<(&[u8], G2Affine)> = Vec::with_capacity(n);
    for (pk, msg) in pks.chunks_exact(48).zip(msgs.chunks_exact(32)) {
        let Some(pk) = eth_key(pk) else { return false };
        let h = match hashes.iter().find(|(m, _)| *m == msg) {
            Some((_, h)) => *h,
            None => {
                let h = G2Affine::from(hash_g2(msg, ETH_DST));
                hashes.push((msg, h));
                h
            }
        };
        terms.push((pk, h));
    }
    terms.push((-G1Affine::generator(), sig));
    pairing_product_is_one(&terms)
}

fn fast_aggregate_verify(pks: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pks.is_empty() || pks.len() % 48 != 0 {
        return false;
    }
    let mut sum = G1Projective::identity();
    for pk in pks.chunks_exact(48) {
        let Some(pk) = eth_key(pk) else { return false };
        sum += pk;
    }
    let sum = G1Affine::from(sum);
    let Some(sig) = eth_sig(sig) else { return false };
    if bool::from(sum.is_identity()) {
        return false;
    }
    core_verify(sum, msg, sig, ETH_DST)
}

fn pairing_check(pairs: &[u8]) -> bool {
    if pairs.len() % 144 != 0 {
        return false;
    }
    let mut terms = Vec::with_capacity(pairs.len() / 144);
    let (mut ps, mut qs) = (Decoded::new(), Decoded::new());
    for t in pairs.chunks_exact(144) {
        let (Some(p), Some(q)) = (ps.get(&t[..48], g1), qs.get(&t[48..], g2)) else { return false };
        terms.push((p, q));
    }
    pairing_product_is_one(&terms)
}

fn g1_out(p: Option<G1Projective>) -> u64 {
    match p {
        Some(p) => output(&G1Affine::from(p).to_compressed()),
        None => NONE,
    }
}

fn g2_out(p: Option<G2Projective>) -> u64 {
    match p {
        Some(p) => output(&G2Affine::from(p).to_compressed()),
        None => NONE,
    }
}

fn g1_sum(points: &[u8]) -> Option<G1Projective> {
    if points.len() % 48 != 0 {
        return None;
    }
    let mut sum = G1Projective::identity();
    for p in points.chunks_exact(48) {
        sum += g1(p)?;
    }
    Some(sum)
}

fn g2_sum(points: &[u8]) -> Option<G2Projective> {
    if points.len() % 96 != 0 {
        return None;
    }
    let mut sum = G2Projective::identity();
    for p in points.chunks_exact(96) {
        sum += g2(p)?;
    }
    Some(sum)
}

/// Window width of the multi-scalar multiplication's signed digits.
const W: u32 = 5;
/// Digits of a scalar below 2^255: its width-W non-adjacent form can be one digit longer.
const DIGITS: usize = 257;

/// The width-W NAF of a scalar: k = sum d_i 2^i with every nonzero d_i odd, |d_i| < 2^(W-1),
/// and at most one nonzero digit in any W consecutive positions. Variable time.
fn wnaf(s: &Scalar) -> [i8; DIGITS] {
    let mut k = [0u64; 5];
    for (i, c) in s.to_bytes().chunks_exact(8).enumerate() {
        k[i] = u64::from_le_bytes(c.try_into().unwrap());
    }
    let mut digits = [0i8; DIGITS];
    let mut i = 0;
    while k.iter().any(|&w| w != 0) {
        if k[0] & 1 == 1 {
            let m = (k[0] & ((1 << W) - 1)) as i64;
            let d = if m >= 1 << (W - 1) { m - (1 << W) } else { m };
            digits[i] = d as i8;
            // k -= d (k - d is then divisible by 2^W).
            if d > 0 {
                let mut borrow = d as u64;
                for w in k.iter_mut() {
                    let (v, b) = w.overflowing_sub(borrow);
                    *w = v;
                    borrow = b as u64;
                    if borrow == 0 {
                        break;
                    }
                }
            } else {
                let mut carry = (-d) as u64;
                for w in k.iter_mut() {
                    let (v, c) = w.overflowing_add(carry);
                    *w = v;
                    carry = c as u64;
                    if carry == 0 {
                        break;
                    }
                }
            }
        }
        for j in 0..4 {
            k[j] = (k[j] >> 1) | (k[j + 1] << 63);
        }
        k[4] >>= 1;
        i += 1;
    }
    digits
}

/// sum s_i P_i by Straus' interleaving with width-5 NAF digits: one shared chain of doublings,
/// and per point a table of its odd multiples P, 3P, ..., 15P. Every point and scalar is checked
/// first (any invalid one gives null, as before); a point given more than once (the same
/// encoding) is decoded once and its scalars are added mod r. Variable time in the scalars, like
/// every MSM meant for verification; single multiplication (g1Mul, g2Mul) stays the crate's
/// constant-time one. The result is the same group element as the sum of the products.
macro_rules! msm {
    ($name:ident, $proj:ident, $decode:ident, $size:expr) => {
        fn $name(points: &[u8], scalars: &[u8]) -> Option<$proj> {
            if points.len() % $size != 0 || scalars.len() % 32 != 0 || points.len() / $size != scalars.len() / 32 {
                return None;
            }
            let mut terms: Vec<(&[u8], _, Scalar)> = Vec::with_capacity(points.len() / $size);
            for (p, s) in points.chunks_exact($size).zip(scalars.chunks_exact(32)) {
                let s = scalar(s)?;
                match terms.iter_mut().find(|(e, _, _)| *e == p) {
                    Some((_, _, sum)) => *sum += s,
                    None => terms.push((p, $decode(p)?, s)),
                }
            }
            let mut tables: Vec<[$proj; 1 << (W - 2)]> = Vec::with_capacity(terms.len());
            let mut digits: Vec<[i8; DIGITS]> = Vec::with_capacity(terms.len());
            for (_, p, s) in terms.iter() {
                let p = $proj::from(*p);
                let twice = p.double();
                let mut t = [p; 1 << (W - 2)];
                for j in 1..t.len() {
                    t[j] = t[j - 1] + twice;
                }
                tables.push(t);
                digits.push(wnaf(s));
            }
            let Some(top) = (0..DIGITS).rev().find(|&i| digits.iter().any(|d| d[i] != 0)) else {
                return Some($proj::identity());
            };
            let mut acc = $proj::identity();
            for i in (0..=top).rev() {
                if i != top {
                    acc = acc.double();
                }
                for (t, d) in tables.iter().zip(digits.iter()) {
                    let d = d[i];
                    if d > 0 {
                        acc += t[(d / 2) as usize];
                    } else if d < 0 {
                        acc -= t[(-d / 2) as usize];
                    }
                }
            }
            Some(acc)
        }
    };
}
msm!(g1_msm, G1Projective, g1, 48);
msm!(g2_msm, G2Projective, g2, 96);

#[no_mangle]
pub unsafe extern "C" fn bls_eth_verify(pk: *const u8, pkn: usize, m: *const u8, mn: usize, s: *const u8, sn: usize) -> u32 {
    verify(bytes(pk, pkn), bytes(m, mn), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_eth_pop_verify(pk: *const u8, pkn: usize, s: *const u8, sn: usize) -> u32 {
    pop_verify(bytes(pk, pkn), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_eth_aggregate_verify(pk: *const u8, pkn: usize, m: *const u8, mn: usize, s: *const u8, sn: usize) -> u32 {
    aggregate_verify(bytes(pk, pkn), bytes(m, mn), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_eth_fast_aggregate_verify(pk: *const u8, pkn: usize, m: *const u8, mn: usize, s: *const u8, sn: usize) -> u32 {
    fast_aggregate_verify(bytes(pk, pkn), bytes(m, mn), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_g1_add(a: *const u8, an: usize, b: *const u8, bn: usize) -> u64 {
    g1_out((|| Some(G1Projective::from(g1(bytes(a, an))?) + g1(bytes(b, bn))?))())
}

#[no_mangle]
pub unsafe extern "C" fn bls_g1_aggregate(a: *const u8, an: usize) -> u64 {
    g1_out(g1_sum(bytes(a, an)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_g1_mul(a: *const u8, an: usize, s: *const u8, sn: usize) -> u64 {
    g1_out((|| Some(g1(bytes(a, an))? * scalar(bytes(s, sn))?))())
}

#[no_mangle]
pub unsafe extern "C" fn bls_g1_msm(a: *const u8, an: usize, s: *const u8, sn: usize) -> u64 {
    g1_out(g1_msm(bytes(a, an), bytes(s, sn)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_g2_add(a: *const u8, an: usize, b: *const u8, bn: usize) -> u64 {
    g2_out((|| Some(G2Projective::from(g2(bytes(a, an))?) + g2(bytes(b, bn))?))())
}

#[no_mangle]
pub unsafe extern "C" fn bls_g2_aggregate(a: *const u8, an: usize) -> u64 {
    g2_out(g2_sum(bytes(a, an)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_g2_mul(a: *const u8, an: usize, s: *const u8, sn: usize) -> u64 {
    g2_out((|| Some(g2(bytes(a, an))? * scalar(bytes(s, sn))?))())
}

#[no_mangle]
pub unsafe extern "C" fn bls_g2_msm(a: *const u8, an: usize, s: *const u8, sn: usize) -> u64 {
    g2_out(g2_msm(bytes(a, an), bytes(s, sn)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_g1_validate(a: *const u8, an: usize) -> u32 {
    g1(bytes(a, an)).is_some() as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_g2_validate(a: *const u8, an: usize) -> u32 {
    g2(bytes(a, an)).is_some() as u32
}

#[no_mangle]
pub unsafe extern "C" fn bls_map_to_g1(u: *const u8, un: usize) -> u64 {
    g1_out(map_fp(bytes(u, un)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_map_to_g2(u: *const u8, un: usize) -> u64 {
    g2_out(map_fp2(bytes(u, un)))
}

#[no_mangle]
pub unsafe extern "C" fn bls_hash_to_g1(m: *const u8, mn: usize, d: *const u8, dn: usize, out: *mut u8) {
    let p = G1Affine::from(hash_g1(bytes(m, mn), bytes(d, dn))).to_compressed();
    core::ptr::copy_nonoverlapping(p.as_ptr(), out, 48);
}

#[no_mangle]
pub unsafe extern "C" fn bls_hash_to_g2(m: *const u8, mn: usize, d: *const u8, dn: usize, out: *mut u8) {
    let p = G2Affine::from(hash_g2(bytes(m, mn), bytes(d, dn))).to_compressed();
    core::ptr::copy_nonoverlapping(p.as_ptr(), out, 96);
}

#[no_mangle]
pub unsafe extern "C" fn bls_pairing_check(a: *const u8, an: usize) -> u32 {
    pairing_check(bytes(a, an)) as u32
}
