//! The Ed25519 operations, free of the kernel ABI so that ../../check can test them natively.
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha512};

/// The public key of a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    VerifyingKey::from(&ExpandedSecretKey::from(seed)).to_bytes()
}

/// RFC 8032 signing: what `SigningKey::from_bytes(seed).sign(msg)` computes, through the
/// functions it is made of. SigningKey::sign expands the seed (SHA-512) a second time; here
/// the one expansion serves the public key and the signature.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let esk = ExpandedSecretKey::from(seed);
    let vk = VerifyingKey::from(&esk);
    raw_sign::<Sha512>(&esk, msg, &vk).to_bytes()
}

/// RFC 8032 5.1.3 decoding: refuses y >= p and x = 0 with the sign bit set (dalek's own
/// decompression accepts both).
///
/// Was `decompress()` then "the canonical re-encoding is the input" (`compress() == c`), which
/// costs a field inversion per point. The re-encoding differs from the input exactly when y >= p
/// (compress writes y mod p) or when x = 0 and the sign bit is set (compress writes x's sign,
/// and -0 = 0): decompress gives x the input's sign whenever x != 0. x = 0 only for y = 1 and
/// y = p - 1. So the same points are refused by looking at the bytes (../../check tests this
/// against the old rule).
pub fn decode(b: &[u8]) -> Option<EdwardsPoint> {
    let c = CompressedEdwardsY(b.try_into().ok()?);
    let y = c.0;
    let sign = y[31] >> 7;
    // y (bit 255 cleared) >= p = 2^255 - 19, little-endian: 30 x 0xff below 0x7f, then >= 0xed.
    let top_ones = y[31] & 0x7f == 0x7f && y[1..31].iter().all(|&v| v == 0xff);
    if top_ones && y[0] >= 0xed { return None }
    // x = 0 with the sign bit: y = 1, or y = p - 1 (0xec, 30 x 0xff, 0x7f).
    let is_one = y[0] == 1 && y[1..31].iter().all(|&v| v == 0) && y[31] & 0x7f == 0;
    if sign == 1 && (is_one || (top_ones && y[0] == 0xec)) { return None }
    c.decompress()
}

/// RFC 8032 5.1.7, cofactorless, strict (see lib.rs).
pub fn verify(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if key.len() != 32 || sig.len() != 64 { return false }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())) else { return false };
    let Some(a) = decode(key) else { return false };
    if a.is_small_order() { return false }
    let Some(r) = decode(&sig[..32]) else { return false };
    let h = Sha512::new().chain_update(&sig[..32]).chain_update(key).chain_update(msg).finalize();
    let k = Scalar::from_bytes_mod_order_wide(&h.into());
    // [s]B - [k]A == R, compared projectively.
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s) == r
}
