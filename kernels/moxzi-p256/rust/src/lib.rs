//! NIST P-256 (secp256r1, prime256v1) kernels for the `moxzi-p256` Motoko package (ABI 1, see
//! moxzi-kernel), on RustCrypto `p256`. The Motoko declarations in ../src/P256.mo are the
//! specification: every function here accepts, rejects and traps exactly as the Motoko body.
//!
//! Encodings: secret keys are 32 big-endian bytes in [1, n); public keys canonical SEC1,
//! compressed (33 bytes, 02/03) or uncompressed (65 bytes, 04) -- hybrid, compact and identity
//! encodings are refused; signatures 64 bytes r || s with r, s in [1, n). Bad input to a
//! non-predicate traps with "P256.<fn>: <reason>"; `verifyPrehash` returns false.
//!
//! The group arithmetic is in ops.rs (comb, Strauss-Shamir in Jacobian coordinates, inversion;
//! tested natively in ../check). Measured 2026-10-23, instructions per call before -> after:
//! publicKey 11,201,742 -> 4,121,054; signPrehash 13,457,840 -> 4,551,536; verifyPrehash
//! 22,603,271 -> 8,429,689 (12,495,619 with p256's own projective additions); convertPublicKey
//! 1,165,290 -> 581,809.
#![no_std]
#![allow(deprecated)] // generic-array 0.14's from_slice, which the RustCrypto 0.13 crates use
mod ops;
mod tables;
use moxzi_kernel::{bytes, output, trap, NONE};
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey};

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

fn secret(b: &[u8], err: &[u8]) -> NonZeroScalar {
    if b.len() != 32 { trap(err) }
    Option::from(NonZeroScalar::from_repr(*FieldBytes::from_slice(b))).unwrap_or_else(|| trap(err))
}

/// Canonical SEC1, compressed or uncompressed only.
fn public(b: &[u8]) -> Option<PublicKey> {
    if !matches!((b.len(), b.first()), (33, Some(2 | 3)) | (65, Some(4))) { return None }
    PublicKey::from_sec1_bytes(b).ok()
}

fn signature(b: &[u8]) -> Option<Signature> {
    if b.len() != 64 { return None }
    Signature::from_slice(b).ok()
}

fn encode(p: &ProjectivePoint, compressed: bool) -> u64 {
    output(p.to_affine().to_encoded_point(compressed).as_bytes())
}

fn digest<'a>(h: &'a [u8]) -> Option<&'a [u8; 32]> {
    h.try_into().ok()
}

#[no_mangle]
pub unsafe extern "C" fn public_key(s: *const u8, sn: usize, compressed: u64) -> u64 {
    let d = secret(bytes(s, sn), b"P256.publicKey: invalid secret key");
    encode(&ops::mul_g(&d), compressed != 0)
}

#[no_mangle]
pub unsafe extern "C" fn derive_public_key(s: *const u8, sn: usize, out: *mut u8) {
    let d = secret(bytes(s, sn), b"P256.derivePublicKey: invalid secret key");
    put(out, ops::mul_g(&d).to_affine().to_encoded_point(true).as_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn convert_public_key(k: *const u8, kn: usize, compressed: u64) -> u64 {
    let p = public(bytes(k, kn)).unwrap_or_else(|| trap(b"P256.convertPublicKey: invalid public key"));
    // The parsed key is already affine (was: to_projective().to_affine(), a field inversion).
    output(p.as_affine().to_encoded_point(compressed != 0).as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn normalize_signature(g: *const u8, gn: usize, out: *mut u8) {
    let sig = signature(bytes(g, gn)).unwrap_or_else(|| trap(b"P256.normalizeSignature: invalid signature"));
    put(out, &sig.normalize_s().unwrap_or(sig).to_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn signature_from_der(d: *const u8, dn: usize) -> u64 {
    match Signature::from_der(bytes(d, dn)) { Ok(sig) => output(&sig.to_bytes()), Err(_) => NONE }
}

#[no_mangle]
pub unsafe extern "C" fn signature_to_der(g: *const u8, gn: usize) -> u64 {
    let sig = signature(bytes(g, gn)).unwrap_or_else(|| trap(b"P256.signatureToDer: invalid signature"));
    output(sig.to_der().as_bytes())
}

/// RFC 6979 ECDSA over a 32-byte digest; s exactly as computed (not normalized), so the
/// signatures are RFC 6979's own (A.2.5).
#[no_mangle]
pub unsafe extern "C" fn sign_prehash(s: *const u8, sn: usize, h: *const u8, hn: usize, out: *mut u8) {
    let d = secret(bytes(s, sn), b"P256.signPrehash: invalid secret key");
    let h = digest(bytes(h, hn)).unwrap_or_else(|| trap(b"P256.signPrehash: the digest must be 32 bytes"));
    let sig = ops::sign_prehash(&d, h).unwrap_or_else(|| trap(b"P256.signPrehash: signing failed"));
    put(out, &sig);
}

/// ECDSA verification; low-S and high-S signatures are both accepted.
#[no_mangle]
pub unsafe extern "C" fn verify_prehash(k: *const u8, kn: usize, h: *const u8, hn: usize, g: *const u8, gn: usize) -> u32 {
    let Some(key) = public(bytes(k, kn)) else { return 0 };
    let Some(h) = digest(bytes(h, hn)) else { return 0 };
    let Some(sig) = signature(bytes(g, gn)) else { return 0 };
    ops::verify_prehash(&key, h, &sig) as u32
}
