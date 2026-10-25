//! The kernel's operations (../rust/src/ops.rs) against the code they replaced: the dalek
//! calls the kernel made before (SigningKey::sign, decode by re-encoding).
#![cfg(test)]
#[path = "../rust/src/ops.rs"]
mod ops;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};

/// The decoding the kernel used until 2026-10-23.
fn decode_by_reencoding(b: &[u8]) -> Option<EdwardsPoint> {
    let c = CompressedEdwardsY(b.try_into().ok()?);
    let p = c.decompress()?;
    (p.compress() == c).then_some(p)
}

fn verify_before(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if key.len() != 32 || sig.len() != 64 { return false }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())) else { return false };
    let Some(a) = decode_by_reencoding(key) else { return false };
    if a.is_small_order() { return false }
    let Some(r) = decode_by_reencoding(&sig[..32]) else { return false };
    let h = Sha512::new().chain_update(&sig[..32]).chain_update(key).chain_update(msg).finalize();
    let k = Scalar::from_bytes_mod_order_wide(&h.into());
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s) == r
}

/// A deterministic byte stream (SHA-512 in counter mode).
struct Rng(u64);
impl Rng {
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(64) {
            self.0 += 1;
            let h = Sha512::digest(self.0.to_le_bytes());
            chunk.copy_from_slice(&h[..chunk.len()]);
        }
        out
    }
}

fn le(n: u64) -> [u8; 32] { let mut b = [0u8; 32]; b[..8].copy_from_slice(&n.to_le_bytes()); b }

/// `native` cases natively, `miri` under Miri (crypto under Miri runs ~10^4 times slower; every
/// class of edge case stays, see `edge_scalars`).
const fn iters(native: usize, miri: usize) -> usize { if cfg!(miri) { miri } else { native } }

/// p - d, little-endian, for small d.
fn p_minus(d: u8) -> [u8; 32] { let mut b = [0xffu8; 32]; b[31] = 0x7f; b[0] = 0xed - d; b }

fn same_decode(b: &[u8; 32]) {
    let new = ops::decode(b).map(|p| p.compress());
    let old = decode_by_reencoding(b).map(|p| p.compress());
    assert_eq!(new, old, "decode {:02x?}", b);
}

#[test]
fn decode_edges() {
    let mut ys: Vec<[u8; 32]> = Vec::new();
    // Under Miri every class stays with fewer members (the ends of each range).
    for n in 0..64 { if !cfg!(miri) || matches!(n, 0 | 1 | 2 | 3 | 63) { ys.push(le(n)); } }
    for d in 0..=0xed { if !cfg!(miri) || matches!(d, 0 | 1 | 2 | 0x12 | 0x13 | 0x14 | 0xec | 0xed) { ys.push(p_minus(d)); } }              // p-237 ..= 0 (wraps at d = 0xed)
    for k in 0..0x13u8 { let mut b = p_minus(0); b[0] = 0xed + k; ys.push(b); } // p .. 2^255-1
    // Values with 0xff runs that are not >= p.
    let mut b = [0xffu8; 32]; b[31] = 0x7e; ys.push(b);
    let mut b = [0xffu8; 32]; b[31] = 0x7f; b[17] = 0xfe; ys.push(b);
    let mut b = [0u8; 32]; b[0] = 1; b[16] = 1; ys.push(b);
    let mut n = 0;
    for y in ys {
        for sign in [0u8, 0x80] {
            let mut b = y; b[31] = (b[31] & 0x7f) | sign;
            same_decode(&b);
            n += 1;
        }
    }
    assert!(n > iters(600, 60));
}

#[test]
fn decode_random_and_points() {
    let mut rng = Rng(1);
    for _ in 0..iters(20_000, 4) { same_decode(&rng.bytes::<32>()); }
    for i in 0..iters(5_000, 8) as u64 {
        let p = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(rng.bytes::<32>()));
        let mut c = p.compress().0;
        same_decode(&c);
        c[31] ^= 0x80;
        same_decode(&c);
        // Small-order and mixed-order points.
        let t = curve25519_dalek::constants::EIGHT_TORSION[(i % 8) as usize];
        same_decode(&(p + t).compress().0);
        same_decode(&t.compress().0);
    }
}

#[test]
fn sign_and_public_key() {
    let mut rng = Rng(2);
    for i in 0..iters(3_000, 2) {
        let seed: [u8; 32] = rng.bytes();
        let msg = &rng.bytes::<128>()[..i % 129];
        let k = SigningKey::from_bytes(&seed);
        assert_eq!(ops::public_key(&seed), k.verifying_key().to_bytes());
        let sig = ops::sign(&seed, msg);
        assert_eq!(sig, k.sign(msg).to_bytes());
    }
}

#[test]
fn verify_same() {
    let mut rng = Rng(3);
    let mut accepted = 0;
    for i in 0..iters(3_000, 2) as u64 {
        let seed: [u8; 32] = rng.bytes();
        let msg = rng.bytes::<40>();
        let k = SigningKey::from_bytes(&seed);
        let key = k.verifying_key().to_bytes();
        let sig = k.sign(&msg).to_bytes();
        let mut cases: Vec<([u8; 32], [u8; 64])> = vec![(key, sig)];
        // One flipped bit anywhere, a flipped sign bit on R / A.
        let mut s2 = sig; s2[(i % 64) as usize] ^= 1 << (i % 8); cases.push((key, s2));
        let mut s3 = sig; s3[31] ^= 0x80; cases.push((key, s3));
        let mut k2 = key; k2[31] ^= 0x80; cases.push((k2, sig));
        // Small-order / mixed-order A and R.
        let t = curve25519_dalek::constants::EIGHT_TORSION[(i % 8) as usize];
        cases.push((t.compress().0, sig));
        let mut s4 = sig; s4[..32].copy_from_slice(&t.compress().0); cases.push((key, s4));
        // Non-canonical encodings: y + p for small y (y in 0..19), both signs.
        let mut nc = p_minus(0); nc[0] = 0xed + (i % 19) as u8; if i % 2 == 1 { nc[31] |= 0x80 }
        cases.push((nc, sig));
        let mut s5 = sig; s5[..32].copy_from_slice(&nc); cases.push((key, s5));
        // s >= L.
        let mut s6 = sig; s6[63] |= 0x10; cases.push((key, s6));
        for (a, g) in cases {
            let new = ops::verify(&a, &msg, &g);
            assert_eq!(new, verify_before(&a, &msg, &g));
            accepted += new as u32;
        }
    }
    assert!(accepted >= iters(3_000, 2) as u32);
}
