//! The kernel's arithmetic (../rust/src/ops.rs, libsecp256k1-core points) against the k256
//! code the kernel ran until 2026-10-23 (`old` below, its lib.rs minus the ABI), and the
//! static tables (../rust/src/tables.rs) against k256's arithmetic.
#![cfg(test)]
#![allow(deprecated)]
#[path = "../rust/src/ops.rs"]
mod ops;
#[path = "../rust/src/tables.rs"]
mod tables;

use k256::ecdsa::{hazmat::SignPrimitive, signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use k256::elliptic_curve::{
    bigint::{ArrayEncoding, U256},
    group::Group,
    ops::{MulByGenerator, Reduce},
    point::{AffineCoordinates, DecompressPoint},
    sec1::ToEncodedPoint,
    subtle::Choice,
    Field as _, PrimeField,
};
use k256::sha2::{Digest, Sha256};
use k256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use libsecp256k1_core::curve::{Affine, Jacobian};
use std::fmt::Write;

/// The kernel's k256 code before 2026-10-23.
mod old {
    use super::*;
    pub fn public(b: &[u8]) -> Option<PublicKey> {
        if !matches!((b.len(), b.first()), (33, Some(2 | 3)) | (65, Some(4))) { return None }
        PublicKey::from_sec1_bytes(b).ok()
    }
    pub fn lift_x(b: &[u8]) -> Option<AffinePoint> {
        if b.len() != 32 { return None }
        Option::from(AffinePoint::decompress(FieldBytes::from_slice(b), Choice::from(0)))
    }
    pub fn reduce(b: &[u8]) -> Scalar { <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(b)) }
    pub fn tagged(tag: &[u8]) -> Sha256 {
        let t = Sha256::digest(tag);
        Sha256::new().chain_update(t).chain_update(t)
    }
    pub fn sign(d: &NonZeroScalar, h: &[u8; 32]) -> Option<[u8; 64]> {
        let z = reduce(h).to_bytes();
        let (sig, _) = (**d).try_sign_prehashed_rfc6979::<Sha256>(&z, &[]).ok()?;
        Some(sig.to_bytes().as_slice().try_into().unwrap())
    }
    pub fn verify(k: &[u8], h: &[u8], g: &[u8]) -> bool {
        let Some(key) = public(k) else { return false };
        if h.len() != 32 { return false }
        let Some(sig) = (g.len() == 64).then(|| Signature::from_slice(g).ok()).flatten() else { return false };
        VerifyingKey::from(&key).verify_prehash(h, &sig).is_ok()
    }
    pub fn schnorr_sign(d0: &NonZeroScalar, msg: &[u8], aux: &[u8]) -> Option<[u8; 64]> {
        let p = ProjectivePoint::mul_by_generator(&**d0).to_affine();
        let d = if bool::from(p.y_is_odd()) { -**d0 } else { **d0 };
        let mut t = tagged(b"BIP0340/aux").chain_update(aux).finalize();
        for (x, y) in t.iter_mut().zip(d.to_bytes().iter()) { *x ^= y }
        let px = p.x();
        let rand = tagged(b"BIP0340/nonce").chain_update(t).chain_update(px).chain_update(msg).finalize();
        let k0 = reduce(&rand);
        if bool::from(k0.is_zero()) { return None }
        let r = ProjectivePoint::mul_by_generator(&k0).to_affine();
        let k = if bool::from(r.y_is_odd()) { -k0 } else { k0 };
        let rx = r.x();
        let e = reduce(&tagged(b"BIP0340/challenge").chain_update(rx).chain_update(px).chain_update(msg).finalize());
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&rx);
        out[32..].copy_from_slice(&(k + e * d).to_bytes());
        Some(out)
    }
    pub fn schnorr_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 { return false }
        let Some(p) = lift_x(pk) else { return false };
        const P: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
        ];
        if sig[..32] >= P[..] { return false }
        let Some(s) = Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(&sig[32..]))) else { return false };
        let e = reduce(&tagged(b"BIP0340/challenge").chain_update(&sig[..32]).chain_update(pk).chain_update(msg).finalize());
        let r = ProjectivePoint::mul_by_generator(&s) - ProjectivePoint::from(p) * e;
        if bool::from(r.is_identity()) { return false }
        let r = r.to_affine();
        !bool::from(r.y_is_odd()) && r.x()[..] == sig[..32]
    }
}

struct Rng(u64);
impl Rng {
    fn bytes(&mut self) -> [u8; 32] {
        self.0 += 1;
        Sha256::digest(self.0.to_le_bytes()).into()
    }
    fn scalar(&mut self) -> Scalar { old::reduce(&self.bytes()) }
    fn nonzero(&mut self) -> NonZeroScalar { NonZeroScalar::new(self.scalar()).unwrap() }
}

fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

/// `native` cases natively, `miri` under Miri (crypto under Miri runs ~10^4 times slower; every
/// class of edge case stays, see `edge_scalars`).
const fn iters(native: usize, miri: usize) -> usize { if cfg!(miri) { miri } else { native } }

fn edge_scalars() -> Vec<Scalar> {
    let mut v = vec![Scalar::ZERO];
    // Under Miri every class below stays with one or two members (ops.rs has no unsafe code: Miri
    // checks the dependencies' unsafe code it reaches, and each reference multiplication is
    // ~10 s of Miri): small values and n - small, powers of two at the ends and the middle.
    for i in 1..40u64 { if !cfg!(miri) || matches!(i, 1 | 2) { v.push(Scalar::from(i)); v.push(-Scalar::from(i)); } }
    let mut p = Scalar::ONE;
    for e in 0..256 {
        if !cfg!(miri) || matches!(e, 0 | 128 | 255) { v.push(p); v.push(p - Scalar::ONE); v.push(-p); }
        p = p.double();
    }
    for byte in [0x00u8, 0x0f, 0xf0, 0x55, 0xaa, 0xff, 0x80, 0x01, 0x1f] {
        if cfg!(miri) && !matches!(byte, 0x55 | 0xff) { continue }
        v.push(old::reduce(&[byte; 32]));
    }
    let h = Scalar::from_repr(FieldBytes::clone_from_slice(&hex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"))).unwrap();
    v.extend([h, h + Scalar::ONE, h - Scalar::ONE]); // around n/2
    v
}

/// k256's encoding of a k256 point (None at infinity).
fn k_enc(p: &ProjectivePoint, compressed: bool) -> Option<Vec<u8>> {
    (!bool::from(p.is_identity())).then(|| p.to_affine().to_encoded_point(compressed).as_bytes().to_vec())
}
fn l_enc(a: &Affine, compressed: bool) -> Vec<u8> { let (e, n) = ops::encode(a, compressed); e[..n].to_vec() }
fn j_enc(j: &Jacobian) -> Option<Vec<u8>> { ops::affine(j).map(|a| l_enc(&a, false)) }
/// The libsecp256k1 point for a k256 one.
fn to_l(p: &ProjectivePoint) -> Affine { ops::parse_public(&k_enc(p, false).unwrap()).unwrap() }

// ---- tables ------------------------------------------------------------------------------

fn words(b: &[u8]) -> String {
    let w: Vec<String> = (0..8).map(|i| format!("0x{:08x}", u32::from_be_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))).collect();
    format!("FieldStorage::new({})", w.join(", "))
}
fn storage(p: &ProjectivePoint) -> String {
    let e = p.to_affine().to_encoded_point(false);
    let b = e.as_bytes();
    format!("AffineStorage::new({}, {})", words(&b[1..33]), words(&b[33..65]))
}

/// The comb's offset points: x = SHA-256(tag || t || counter), the first that is on the
/// curve, with even y. Nobody knows their discrete logarithms.
fn offset(t: usize) -> ProjectivePoint {
    for ctr in 0u32.. {
        let x = Sha256::new().chain_update(b"moxzi-secp256k1 comb offset").chain_update([t as u8]).chain_update(ctr.to_le_bytes()).finalize();
        if let Some(p) = Option::<AffinePoint>::from(AffinePoint::decompress(&x, Choice::from(0))) { return p.into() }
    }
    unreachable!()
}

fn tables_source() -> String {
    let (w, t_n, r) = (tables::COMB_W, tables::COMB_T, tables::COMB_R);
    assert!(w * t_n * r >= 256);
    let pow2 = |e: usize| { let mut p = ProjectivePoint::GENERATOR; for _ in 0..e { p = p.double() } p };
    let mut s = String::new();
    s.push_str("//! Static tables for ops.rs. Generated by ../../check (MOXZI_WRITE_TABLES=1 cargo test\n//! --release), whose tests check every point against k256's arithmetic. Do not edit.\n");
    s.push_str("use libsecp256k1_core::curve::{AffineStorage, FieldStorage};\n\n");
    s.push_str("/// ops::mul_g's comb: COMB[t][d] = sum over the bits c of d of 2^(R*t + R*T*c) G, plus\n/// offset t (x = SHA-256(\"moxzi-secp256k1 comb offset\" || t || counter), the first on the\n/// curve, even y).\n");
    writeln!(s, "pub const COMB_W: usize = {w};\npub const COMB_T: usize = {t_n};\npub const COMB_R: usize = {r};").unwrap();
    writeln!(s, "pub static COMB: [[AffineStorage; {}]; {t_n}] = [", 1 << w).unwrap();
    let mut offsets = ProjectivePoint::IDENTITY;
    for t in 0..t_n {
        let off = offset(t);
        offsets += off;
        let basis: Vec<ProjectivePoint> = (0..w).map(|c| pow2(r * t + r * t_n * c)).collect();
        s.push_str("    [\n");
        for d in 0..1usize << w {
            let mut p = off;
            for c in 0..w { if d >> c & 1 == 1 { p += basis[c] } }
            assert!(!bool::from(p.is_identity()));
            writeln!(s, "        {},", storage(&p)).unwrap();
        }
        s.push_str("    ],\n");
    }
    s.push_str("];\n\n/// -(2^R - 1) * (the sum of the offsets).\n");
    let fix = -(offsets * Scalar::from((1u64 << r) - 1));
    writeln!(s, "pub static COMB_FIX: AffineStorage = {};\n", storage(&fix)).unwrap();
    s.push_str("/// G, 3G, 5G, ..., 127G for ops::mul_add_vartime's width-8 NAF of the G scalar.\npub const ODD_G_WIDTH: u32 = 8;\npub static ODD_G: [AffineStorage; 64] = [\n");
    for i in 0..64u64 {
        writeln!(s, "    {},", storage(&(ProjectivePoint::GENERATOR * Scalar::from(2 * i + 1)))).unwrap();
    }
    s.push_str("];\n");
    s
}

#[test]
#[cfg_attr(miri, ignore = "reads tables.rs from disk and regenerates it with the reference crate: native runs check it")]
fn tables_are_current() {
    let want = tables_source();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../rust/src/tables.rs");
    if std::env::var("MOXZI_WRITE_TABLES").is_ok() { std::fs::write(path, &want).unwrap() }
    assert!(std::fs::read_to_string(path).unwrap() == want, "tables.rs is stale: MOXZI_WRITE_TABLES=1");
}

// ---- arithmetic --------------------------------------------------------------------------

#[test]
fn mul_g_is_mul_by_generator() {
    let mut rng = Rng(1);
    let mut ks = edge_scalars();
    for _ in 0..iters(3_000, 2) { ks.push(rng.scalar()) }
    for k in ks {
        assert_eq!(j_enc(&ops::mul_g(&k)), k_enc(&ProjectivePoint::mul_by_generator(&k), false), "{k:?}");
    }
}

#[test]
fn wnaf_digits() {
    let mut rng = Rng(2);
    let mut ks = edge_scalars();
    for _ in 0..iters(3_000, 2) { ks.push(rng.scalar()) }
    for k in ks {
        for w in 2..=8u32 {
            let d = ops::wnaf(&k, w);
            let mut sum = Scalar::ZERO;
            for i in (0..258).rev() {
                sum = sum.double();
                let x = d[i] as i64;
                if x != 0 { assert!(x % 2 != 0 && x.abs() < 1 << (w - 1), "{x}") }
                sum += if x >= 0 { Scalar::from(x as u64) } else { -Scalar::from((-x) as u64) };
            }
            assert_eq!(sum, k);
            for i in 0..258 { if d[i] != 0 { for j in 1..w as usize { if i + j < 258 { assert_eq!(d[i + j], 0) } } } }
        }
    }
}

#[test]
fn mul_add_is_two_multiplications() {
    let mut rng = Rng(3);
    let edges = edge_scalars();
    let g = ProjectivePoint::GENERATOR;
    let mut qs = vec![g, -g, g.double(), g * Scalar::from(3u64)];
    for _ in 0..iters(30, 1) { qs.push(g * rng.scalar()) }
    for (i, q) in qs.iter().enumerate() {
        for (j, u1) in edges.iter().enumerate().filter(|(j, _)| j % 7 == i % 7).take(iters(usize::MAX, 3)) {
            let u2 = edges[(j * 31 + i) % edges.len()];
            assert_eq!(j_enc(&ops::mul_add_vartime(u1, &to_l(q), &u2)), k_enc(&(g * u1 + *q * u2), false));
        }
    }
    for _ in 0..iters(1_500, 2) {
        let (u1, u2, x) = (rng.scalar(), rng.scalar(), rng.nonzero());
        let q = g * *x;
        let ql = to_l(&q);
        assert_eq!(j_enc(&ops::mul_add_vartime(&u1, &ql, &u2)), k_enc(&(g * u1 + q * u2), false));
        assert!(ops::mul_add_vartime(&(-(u2 * *x)), &ql, &u2).is_infinity());
        assert_eq!(j_enc(&ops::mul_add_vartime(&(u2 * *x), &ql, &u2)), k_enc(&(q * u2).double(), false));
    }
}

#[test]
fn glv_split() {
    let lambda = Scalar::from_repr(FieldBytes::clone_from_slice(&hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"))).unwrap();
    // BETA x is the x of LAMBDA P.
    let g = ProjectivePoint::GENERATOR;
    let gl = to_l(&g);
    let mut e = gl;
    e.x = e.x * libsecp256k1_core::curve::Field::new(0x7ae96a2b, 0x657c0710, 0x6e64479e, 0xac3434e9, 0x9cf04975, 0x12f58995, 0xc1396c28, 0x719501ee);
    assert_eq!(l_enc(&e, false), k_enc(&(g * lambda), false).unwrap());
    let mut rng = Rng(10);
    let mut ks = edge_scalars();
    for _ in 0..iters(20_000, 4) { ks.push(rng.scalar()) }
    let bound = Scalar::from_repr(FieldBytes::clone_from_slice(&hex("0000000000000000000000000000000200000000000000000000000000000000"))).unwrap(); // 2^129
    for k in ks {
        let [(r1, n1), (r2, n2)] = ops::split(&k);
        let s1 = if n1 { -r1 } else { r1 };
        let s2 = if n2 { -r2 } else { r2 };
        assert_eq!(s1 + s2 * lambda, k);
        for r in [r1, r2] { assert!(r.to_bytes() < bound.to_bytes(), "{k:?}") }
        assert!(!(n1 && bool::from(r1.is_zero())) && !(n2 && bool::from(r2.is_zero())));
    }
}

#[test]
fn invert_is_invert() {
    let mut rng = Rng(4);
    let mut ks = edge_scalars();
    for _ in 0..iters(3_000, 2) { ks.push(rng.scalar()) }
    for k in ks.into_iter().filter(|k| !bool::from(k.is_zero())) { assert_eq!(ops::invert(&k), k.invert().unwrap()) }
}

/// Encodings around the edges: valid points both ways, x or y >= p, off the curve, flipped
/// parity, wrong prefixes and lengths.
fn encodings(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    let p = hex(P);
    let mut big: Vec<Vec<u8>> = vec![p.clone(), vec![0xff; 32]];
    let mut p1 = p.clone(); p1[31] += 1; big.push(p1);
    let mut pm1 = p.clone(); pm1[31] -= 1; big.push(pm1);
    big.push(vec![0; 32]);
    let mut one = vec![0; 32]; one[31] = 1; big.push(one);
    for x in &big {
        for t in [2u8, 3] { let mut e = vec![t]; e.extend(x); v.push(e) }
        let mut e = vec![4]; e.extend(x); e.extend(x); v.push(e);
    }
    for i in 0..iters(400, 3) as u64 {
        let q = ProjectivePoint::GENERATOR * rng.scalar();
        if bool::from(q.is_identity()) { continue }
        let c = k_enc(&q, true).unwrap();
        let u = k_enc(&q, false).unwrap();
        v.push(c.clone());
        v.push(u.clone());
        let mut f = c.clone(); f[0] ^= 1; v.push(f);            // the other parity: -q, valid
        let mut f = u.clone(); f[64] ^= 1; v.push(f);           // y + 1: off the curve
        let mut f = u.clone(); f[0] = 6 + (u[64] & 1); v.push(f); // hybrid
        let mut f = c.clone(); f[(i % 32) as usize + 1] ^= 1 << (i % 8); v.push(f); // another x
        let mut f = u.clone(); f[(i % 64) as usize + 1] ^= 1 << (i % 8); v.push(f);
        // y replaced by p - y (that is -y, valid) and by y + p when it fits (>= p: refused).
        let y = U256::from_be_slice(&u[33..]);
        let pp = U256::from_be_slice(&p);
        let mut f = u.clone(); f[33..].copy_from_slice(&pp.wrapping_sub(&y).to_be_byte_array()); v.push(f);
        let (yp, carry) = y.adc(&pp, k256::elliptic_curve::bigint::Limb::ZERO);
        if carry.0 == 0 { let mut f = u.clone(); f[33..].copy_from_slice(&yp.to_be_byte_array()); v.push(f) }
        v.push(c[..32].to_vec());
        v.push(u[..64].to_vec());
        v.push(c[1..].to_vec());
        let mut f = c.clone(); f.push(0); v.push(f);
    }
    v.push(vec![]);
    v.push(vec![0]);
    v
}

#[test]
fn parse_and_encode_are_k256s() {
    let mut rng = Rng(5);
    let mut accepted = 0;
    for e in encodings(&mut rng) {
        let new = ops::parse_public(&e);
        let old = old::public(&e);
        assert_eq!(new.is_some(), old.is_some(), "{e:02x?}");
        if let (Some(a), Some(k)) = (new, old) {
            accepted += 1;
            for c in [true, false] { assert_eq!(l_enc(&a, c), k.to_encoded_point(c).as_bytes()) }
            assert_eq!(ops::x_bytes(&a)[..], k.as_affine().x()[..]);
        }
        if e.len() >= 33 {
            let x = &e[1..33];
            let (n, o) = (ops::lift_x(x), old::lift_x(x));
            assert_eq!(n.is_some(), o.is_some());
            if let (Some(a), Some(k)) = (n, o) { assert_eq!(l_enc(&a, false), k.to_encoded_point(false).as_bytes()) }
        }
    }
    assert!(accepted > iters(1_000, 6));
}

#[test]
fn add_and_tweak_are_k256s() {
    let mut rng = Rng(6);
    let g = ProjectivePoint::GENERATOR;
    let mut ts = edge_scalars();
    for _ in 0..iters(1_000, 2) { ts.push(rng.scalar()) }
    for (i, t) in ts.iter().enumerate() {
        let x = rng.nonzero();
        let p = g * *x;
        let pl = to_l(&p);
        let q = if i % 3 == 0 { p } else if i % 3 == 1 { -p } else { g * rng.scalar() };
        if bool::from(q.is_identity()) { continue }
        let ql = to_l(&q);
        assert_eq!(ops::add_vartime(&pl, &ql).map(|a| l_enc(&a, true)), k_enc(&(p + q), true));
        assert_eq!(ops::mul_g_add(t, &pl).map(|a| l_enc(&a, true)), k_enc(&(p + ProjectivePoint::mul_by_generator(t)), true));
        // t*G = -P: the point at infinity.
        assert!(ops::mul_g_add(&-*x, &pl).is_none());
    }
}

#[test]
fn x_mod_n() {
    // Points whose x is in [n, p): r = x - n must match, as k256's reduce(x) == r does.
    let n = U256::from_be_slice(&hex(N));
    let mut found = 0;
    for k in 0u64..iters(200, 12) as u64 {
        let x = n.wrapping_add(&U256::from_u64(k));
        let xb: [u8; 32] = x.to_be_byte_array().into();
        let Some(a) = ops::lift_x(&xb) else { continue };
        found += 1;
        let mut j = Jacobian::from_ge(&a);
        j = j.double_var(None).add_ge_var(&a.neg(), None); // the same point, z != 1
        let r = old::reduce(&xb);
        assert_eq!(r, Scalar::from(k));
        if k > 0 { assert!(ops::x_mod_n_is(&j, &r)) }
        assert!(!ops::x_mod_n_is(&j, &(r + Scalar::ONE)));
    }
    assert!(found > iters(50, 2));
    let mut rng = Rng(7);
    for _ in 0..iters(2_000, 2) {
        let p = ProjectivePoint::GENERATOR * rng.nonzero().as_ref();
        let j = Jacobian::from_ge(&to_l(&p));
        let r = old::reduce(&p.to_affine().x());
        assert!(ops::x_mod_n_is(&j, &r) == !bool::from(r.is_zero()));
        assert!(!ops::x_mod_n_is(&j, &(r + Scalar::ONE)));
    }
}

#[test]
fn ecdsa_is_k256s() {
    let mut rng = Rng(8);
    let mut digests: Vec<[u8; 32]> = vec![[0; 32], [0xff; 32]];
    let n = hex(N);
    let mut n1 = n.clone(); n1[31] -= 1;
    let mut n2 = n.clone(); n2[31] += 1;
    for v in [n, n1, n2] { digests.push(v.try_into().unwrap()) }
    let mut keys: Vec<NonZeroScalar> = edge_scalars().into_iter().filter_map(|k| Option::from(NonZeroScalar::new(k))).take(iters(60, 6)).collect();
    for _ in 0..iters(1_000, 1) { keys.push(rng.nonzero()) }
    let mut accepted = 0;
    for (i, d) in keys.iter().enumerate() {
        let h = if i < digests.len() * 12 { digests[i % digests.len()] } else { rng.bytes() };
        let sig = ops::ecdsa_sign(d, &h);
        assert_eq!(sig, old::sign(d, &h));
        let sig = sig.unwrap();
        let key = PublicKey::from_secret_scalar(d);
        let kc = key.to_encoded_point(i % 2 == 0).as_bytes().to_vec();
        let parsed = ops::parse_public(&kc).unwrap();
        let s = Signature::from_slice(&sig).unwrap();
        let (r, sv) = s.split_scalars();
        let mut cases: Vec<([u8; 32], Vec<u8>)> = vec![(h, sig.to_vec())];
        cases.push((h, Signature::from_scalars(*r, -*sv).unwrap().to_bytes().to_vec())); // high S
        let mut b = sig; b[i % 64] ^= 1 << (i % 8); cases.push((h, b.to_vec()));
        let mut h2 = h; h2[i % 32] ^= 1; cases.push((h2, sig.to_vec()));
        cases.push((h, Signature::from_scalars(rng.scalar(), rng.scalar()).map(|x| x.to_bytes().to_vec()).unwrap_or_default()));
        for (hh, g) in cases {
            let Ok(gs) = Signature::from_slice(&g) else { continue };
            let new = ops::ecdsa_verify(&parsed, &hh, &gs);
            assert_eq!(new, old::verify(&kc, &hh, &g));
            accepted += new as u32;
        }
    }
    assert!(accepted >= iters(1_000, 7) as u32);
}

#[test]
fn schnorr_is_the_old_code() {
    let mut rng = Rng(9);
    let mut keys: Vec<NonZeroScalar> = edge_scalars().into_iter().filter_map(|k| Option::from(NonZeroScalar::new(k))).take(iters(60, 6)).collect();
    for _ in 0..iters(1_000, 1) { keys.push(rng.nonzero()) }
    let mut accepted = 0;
    for (i, d) in keys.iter().enumerate() {
        let msg = rng.bytes();
        let msg = &msg[..i % 33];
        let aux = rng.bytes();
        let sig = ops::schnorr_sign(d, msg, &aux);
        assert_eq!(sig, old::schnorr_sign(d, msg, &aux));
        let sig = sig.unwrap();
        let p = ProjectivePoint::mul_by_generator(&**d).to_affine();
        let pk: [u8; 32] = p.x().into();
        let mut cases: Vec<(Vec<u8>, Vec<u8>)> = vec![(pk.to_vec(), sig.to_vec())];
        let mut b = sig; b[i % 64] ^= 1 << (i % 8); cases.push((pk.to_vec(), b.to_vec()));
        let mut k2 = pk; k2[i % 32] ^= 1; cases.push((k2.to_vec(), sig.to_vec()));
        let mut rp = sig; rp[..32].copy_from_slice(&hex(P)); cases.push((pk.to_vec(), rp.to_vec())); // r = p
        let mut sn = sig; sn[32..].copy_from_slice(&hex(N)); cases.push((pk.to_vec(), sn.to_vec())); // s = n
        let mut s0 = sig; s0[32..].fill(0); cases.push((pk.to_vec(), s0.to_vec())); // s = 0
        cases.push((hex(P), sig.to_vec())); // x = p
        cases.push((pk.to_vec(), sig[..63].to_vec()));
        for (k, g) in cases {
            let new = ops::schnorr_verify(&k, msg, &g);
            assert_eq!(new, old::schnorr_verify(&k, msg, &g));
            accepted += new as u32;
        }
    }
    assert!(accepted >= iters(1_000, 7) as u32);
}

// ---- adversarial review (2026-10-24) -----------------------------------------------------
// Exceptional cases of the formulas, the comb's every (table, row, digit), ECDSA's x mod n
// path and the high-S boundary end to end, and the published vectors run natively.

const LAMBDA_HEX: &str = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
fn lambda() -> Scalar { sc_hex(LAMBDA_HEX) }
fn sc_hex(s: &str) -> Scalar { Scalar::from_repr(FieldBytes::clone_from_slice(&hex(s))).unwrap() }

/// The libsecp256k1 point for a k256 one, parsed from its COMPRESSED encoding (so y may carry
/// magnitude 2, as for every compressed key and every lift_x point the kernel parses).
fn to_lc(p: &ProjectivePoint) -> Affine { ops::parse_public(&k_enc(p, true).unwrap()).unwrap() }

/// A Jacobian point exactly as stored: each coordinate normalized (its limbs, not the affine
/// point it represents), and the infinity flag. ops::add_ge computes libsecp256k1-core's
/// add_ge step for step, so the two must agree here, not only up to the projective scale.
fn j_raw(j: &Jacobian) -> ([[u8; 32]; 3], bool) {
    let b = |f: &libsecp256k1_core::curve::Field| { let mut f = *f; f.normalize(); f.b32() };
    ([b(&j.x), b(&j.y), b(&j.z)], j.infinity)
}

/// The comb as it was until 2026-10-24: the same digits and tables, the entry read directly
/// (the reference for `select`) and libsecp256k1-core's own add_ge (the reference for ops::add_ge).
fn mul_g_crate(k: &Scalar) -> Jacobian {
    use tables::{COMB, COMB_FIX, COMB_R as R, COMB_T as T, COMB_W as W};
    let b = k.to_bytes();
    let bit = |i: usize| if i < 256 { ((b[31 - i / 8] >> (i % 8)) & 1) as usize } else { 0 };
    let mut acc = Jacobian::default();
    acc.set_infinity();
    for row in (0..R).rev() {
        if row != R - 1 { acc = acc.double_var(None) }
        for (t, entries) in COMB.iter().enumerate() {
            let mut digit = 0usize;
            for c in 0..W { digit |= bit(row + R * t + R * T * c) << c }
            acc = acc.add_ge(&Affine::from(entries[digit]));
        }
    }
    acc.add_ge(&Affine::from(COMB_FIX))
}

/// add_ge (the constant-time formula of the comb and of mul_g_add) on every exceptional
/// input: a == b with z != 1 (doubling), a == -b (infinity), the degenerate y1 == -y2 with
/// x1 != x2 (b = -LAMBDA a), a at infinity, and both encodings of b.
#[test]
#[cfg_attr(miri, ignore = "ops.rs has no unsafe code and the reference multiplications take minutes under Miri; native runs cover it")]
fn add_ge_exceptional_cases() {
    let g = ProjectivePoint::GENERATOR;
    let mut rng = Rng(100);
    let mut ks: Vec<Scalar> = vec![Scalar::ONE, -Scalar::ONE, Scalar::from(2u64), lambda()];
    for _ in 0..iters(300, 2) { ks.push(*rng.nonzero().as_ref()) }
    for k in ks {
        let a = ops::mul_g(&k); // z != 1
        let p = g * k;
        for to in [to_l as fn(&ProjectivePoint) -> Affine, to_lc] {
            let cases: [(ProjectivePoint, &str); 5] = [
                (p, "a == b"), (-p, "a == -b"), (-(p * lambda()), "degenerate b = -LAMBDA a"),
                (p * lambda(), "b = LAMBDA a"), (p * lambda() * lambda(), "b = LAMBDA^2 a"),
            ];
            for (b, what) in cases {
                let bl = to(&b);
                assert_eq!(j_enc(&ops::add_ge(&a, &bl)), k_enc(&(p + b), false), "{what} k={k:?}");
                assert_eq!(j_raw(&ops::add_ge(&a, &bl)), j_raw(&a.add_ge(&bl)), "the crate's add_ge: {what} k={k:?}");
                assert_eq!(j_enc(&a.add_ge_var(&bl, None)), k_enc(&(p + b), false), "var {what}");
                // The same cases with a in affine form (Z = 1, as for mul_g_add's P).
                let a1 = Jacobian::from_ge(&to(&p));
                assert_eq!(j_enc(&ops::add_ge(&a1, &bl)), k_enc(&(p + b), false), "z = 1: {what}");
                assert_eq!(j_raw(&ops::add_ge(&a1, &bl)), j_raw(&a1.add_ge(&bl)), "z = 1, the crate's: {what}");
            }
            let mut inf = Jacobian::default();
            inf.set_infinity();
            assert_eq!(j_enc(&ops::add_ge(&inf, &to(&p))), k_enc(&p, false));
            assert_eq!(j_raw(&ops::add_ge(&inf, &to(&p))), j_raw(&inf.add_ge(&to(&p))));
            // An infinity that add_ge itself produced (a + -a: Z = 0, X and Y left over), then
            // added to: the sum is b exactly, as in the crate.
            let zero = ops::add_ge(&a, &to(&-p));
            assert!(zero.is_infinity());
            assert_eq!(j_raw(&zero), j_raw(&a.add_ge(&to(&-p))));
            let q = p * lambda();
            assert_eq!(j_enc(&ops::add_ge(&zero, &to(&q))), k_enc(&q, false));
            assert_eq!(j_raw(&ops::add_ge(&zero, &to(&q))), j_raw(&zero.add_ge(&to(&q))));
        }
    }
}

/// ops::add_ge against the crate's add_ge on random sums (both encodings of b, a at the end of
/// chains of additions so its coordinates carry the magnitudes the comb sees). Equal limb for
/// limb after normalization, and the sum k256's.
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn add_ge_is_the_crates() {
    let g = ProjectivePoint::GENERATOR;
    let mut rng = Rng(102);
    for i in 0..iters(2_000, 2) {
        let (x, y) = (rng.scalar(), *rng.nonzero().as_ref());
        let a = if i % 2 == 0 { ops::mul_g(&x) } else { ops::add_ge(&ops::mul_g(&x), &to_l(&(g * rng.scalar() + g))) };
        let pa = if i % 2 == 0 { g * x } else { ProjectivePoint::from(ops_to_k(&a)) };
        let b = g * y;
        for bl in [to_l(&b), to_lc(&b)] {
            let (new, old) = (ops::add_ge(&a, &bl), a.add_ge(&bl));
            assert_eq!(j_raw(&new), j_raw(&old), "i={i}");
            assert_eq!(j_enc(&new), k_enc(&(pa + b), false), "i={i}");
        }
    }
}

/// The k256 point of a finite libsecp256k1 Jacobian one.
fn ops_to_k(j: &Jacobian) -> AffinePoint {
    let e = j_enc(j).unwrap();
    *old::public(&e).unwrap().as_affine()
}

/// mul_g_add(t, P) when t*G == P, t*G == -P and t*G == -LAMBDA P, with P parsed both ways and
/// lifted (the tweak functions take attacker-chosen keys and tweaks).
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn tweak_exceptional_cases() {
    let g = ProjectivePoint::GENERATOR;
    let mut rng = Rng(101);
    for i in 0..iters(300, 2) {
        let t = if i == 0 { Scalar::ONE } else { *rng.nonzero().as_ref() };
        let tg = g * t;
        for p in [tg, -tg, -(tg * lambda()), tg * lambda()] {
            let want = k_enc(&(p + tg), true);
            assert_eq!(ops::mul_g_add(&t, &to_l(&p)).map(|a| l_enc(&a, true)), want);
            assert_eq!(ops::mul_g_add(&t, &to_lc(&p)).map(|a| l_enc(&a, true)), want);
            let x: [u8; 32] = p.to_affine().x().into();
            let lifted = ops::lift_x(&x).unwrap();
            let even = if bool::from(p.to_affine().y_is_odd()) { -p } else { p };
            assert_eq!(ops::mul_g_add(&t, &lifted).map(|a| l_enc(&a, true)), k_enc(&(even + tg), true));
        }
    }
}

/// The comb: every digit of every table in every row, alone and over a background of ones,
/// plus the scalars at the ends of [0, n).
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn comb_every_digit() {
    use tables::{COMB_R as R, COMB_T as T, COMB_W as W};
    let n = U256::from_be_slice(&hex(N));
    let mut ks: Vec<Scalar> = Vec::new();
    for row in 0..R {
        for t in 0..T {
            for d in 0..1usize << W {
                let mut bits = U256::ZERO;
                for c in 0..W {
                    let i = row + R * t + R * T * c;
                    if d >> c & 1 == 1 && i < 256 { bits = bits.bitor(&U256::ONE.shl_vartime(i)) }
                }
                for v in [bits, bits.not()] {
                    let v = if v >= n { v.wrapping_sub(&n) } else { v };
                    ks.push(Scalar::from_repr(v.to_be_byte_array()).unwrap());
                }
            }
        }
    }
    for s in ["fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
              "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f", // n-2
              "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe", // 2^256 mod n
              "8000000000000000000000000000000000000000000000000000000000000000",
              "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] {
        ks.push(sc_hex(s));
    }
    for k in ks {
        let j = ops::mul_g(&k);
        assert_eq!(j_enc(&j), k_enc(&ProjectivePoint::mul_by_generator(&k), false), "{k:?}");
        // The comb before the masked add_ge (and before `select`): the same Jacobian point.
        assert_eq!(j_raw(&j), j_raw(&mul_g_crate(&k)), "{k:?}");
    }
}

/// mul_g against the comb on the crate's add_ge (mul_g_crate) and k256 on the edge scalars and
/// random ones: the same Jacobian representation, not only the same point.
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn mul_g_is_the_crates() {
    let mut rng = Rng(103);
    let mut ks = edge_scalars();
    for _ in 0..1_000 { ks.push(rng.scalar()) }
    for k in ks {
        let j = ops::mul_g(&k);
        assert_eq!(j_raw(&j), j_raw(&mul_g_crate(&k)), "{k:?}");
        assert_eq!(j_enc(&j), k_enc(&ProjectivePoint::mul_by_generator(&k), false), "{k:?}");
    }
}

/// A key for which (r, s) verifies over z with R = the given point: Q = (R - u1 G) / u2.
fn key_for(rp: &ProjectivePoint, r: &Scalar, s: &Scalar, z: &Scalar) -> ProjectivePoint {
    let si = s.invert().unwrap();
    let (u1, u2) = (*z * si, *r * si);
    (*rp - ProjectivePoint::GENERATOR * u1) * u2.invert().unwrap()
}

/// ECDSA end to end where R's x is in [n, p): the signature carries r = x - n, and only the
/// r + n comparison accepts it. Plus the high-S boundary: s = (n-1)/2 accepted, s + 1 refused.
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn ecdsa_x_above_n_and_high_s_boundary() {
    use k256::elliptic_curve::scalar::IsHigh;
    let n = U256::from_be_slice(&hex(N));
    let mut rng = Rng(102);
    let mut found = 0;
    for j in 1u64..iters(400, 20) as u64 {
        let x = n.wrapping_add(&U256::from_u64(j));
        let xb: [u8; 32] = x.to_be_byte_array().into();
        let Some(rp) = Option::<AffinePoint>::from(AffinePoint::decompress(FieldBytes::from_slice(&xb), Choice::from((j & 1) as u8))) else { continue };
        let rp = ProjectivePoint::from(rp);
        found += 1;
        let r = Scalar::from(j);
        let (z, s) = (rng.scalar(), *rng.nonzero().as_ref());
        let s = if bool::from(s.is_high()) { -s } else { s };
        let q = key_for(&rp, &r, &s, &z);
        let qe = k_enc(&q, j % 2 == 0).unwrap();
        let sig = Signature::from_scalars(r, s).unwrap();
        let zb: [u8; 32] = z.to_bytes().into();
        let ql = ops::parse_public(&qe).unwrap();
        assert!(ops::ecdsa_verify(&ql, &zb, &sig), "x = n + {j}");
        assert!(old::verify(&qe, &zb, &sig.to_bytes()));
        assert!(!ops::ecdsa_verify(&ql, &zb, &Signature::from_scalars(r + Scalar::ONE, s).unwrap()));
    }
    assert!(found > iters(100, 3));
    let half = sc_hex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    for (s, want) in [(half, true), (half + Scalar::ONE, false), (-half, false), (-(half + Scalar::ONE), true)] {
        let rp = ProjectivePoint::GENERATOR * Scalar::from(7u64);
        let r = old::reduce(&rp.to_affine().x());
        let z = rng.scalar();
        let q = key_for(&rp, &r, &s, &z);
        let qe = k_enc(&q, true).unwrap();
        let sig = Signature::from_scalars(r, s).unwrap();
        let zb: [u8; 32] = z.to_bytes().into();
        assert_eq!(ops::ecdsa_verify(&ops::parse_public(&qe).unwrap(), &zb, &sig), want, "s = {s:?}");
        assert_eq!(old::verify(&qe, &zb, &sig.to_bytes()), want);
    }
}

fn vectors(name: &str) -> String {
    std::fs::read_to_string(format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Wycheproof ECDSA secp256k1 / SHA-256, Bitcoin variant, natively: DER through k256's strict
/// parser (the kernel's signature_from_der), then ops::ecdsa_verify (the kernel's verify_prehash).
#[test]
#[cfg_attr(miri, ignore = "463 verifications; native runs cover it")]
fn wycheproof_bitcoin_natively() {
    let text = vectors("wycheproof-ecdsa-secp256k1-sha256-bitcoin.json");
    // The quoted strings, in order: ..., "key", key, "tests", then msg, sig, result per test.
    let strs: Vec<&str> = text.split('"').skip(1).step_by(2).collect();
    let (mut i, mut n, mut key) = (0, 0, String::new());
    while i < strs.len() {
        match strs[i] {
            "key" => { key = strs[i + 1].to_string(); i += 2 }
            s if !key.is_empty() && matches!(strs.get(i + 2), Some(&("valid" | "invalid" | "acceptable"))) => {
                let (msg, result) = (hex(s), strs[i + 2]);
                let h: [u8; 32] = Sha256::digest(&msg).into();
                let ok = match Signature::from_der(&hex(strs[i + 1])) {
                    Ok(sig) => ops::parse_public(&hex(&key)).map_or(false, |q| ops::ecdsa_verify(&q, &h, &sig)),
                    Err(_) => false,
                };
                assert_eq!(ok, result == "valid", "key {key} msg {s} sig {}", strs[i + 1]);
                n += 1;
                i += 3;
            }
            _ => i += 1,
        }
    }
    assert!(n > 450, "{n}");
}

/// BIP340's published vectors, natively.
#[test]
#[cfg_attr(miri, ignore = "native runs cover it")]
fn bip340_vectors_natively() {
    let text = vectors("bip340-test-vectors.csv");
    let mut n = 0;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.trim_end().split(',').collect();
        let (sk, pk, aux, msg, sig, result) = (f[1], hex(f[2]), hex(f[3]), hex(f[4]), hex(f[5]), f[6] == "TRUE");
        assert_eq!(ops::schnorr_verify(&pk, &msg, &sig), result, "{line}");
        if !sk.is_empty() {
            let d = NonZeroScalar::new(sc_hex(sk)).unwrap();
            assert_eq!(ops::schnorr_sign(&d, &msg, &aux).unwrap().to_vec(), sig, "{line}");
        }
        n += 1;
    }
    assert_eq!(n, 19);
}
