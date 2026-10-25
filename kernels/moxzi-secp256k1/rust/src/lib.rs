//! secp256k1 kernels for the `moxzi-secp256k1` Motoko package (ABI 1, see moxzi-kernel), on
//! RustCrypto `k256` (scalars, signatures, DER, RFC 6979, SHA-256) and libsecp256k1-core (the
//! point arithmetic; see ops.rs for why). The Motoko declarations in ../src/Secp256k1.mo are
//! the specification: every function here accepts, rejects and traps exactly as the Motoko
//! body does.
//!
//! Encodings: secret keys are 32 big-endian bytes in [1, n); scalars (tweaks, multipliers) 32
//! bytes in [0, n); public keys canonical SEC1, compressed (33 bytes, 02/03) or uncompressed (65
//! bytes, 04) -- hybrid, compact and identity encodings are refused; signatures 64 bytes r || s
//! with r, s in [1, n). Bad input to a non-predicate traps with "Secp256k1.<fn>: <reason>";
//! predicates return false; a point at infinity (or a zero tweaked secret) is `null`.
//!
//! Measured 2026-10-23, instructions per call with k256 points -> with ops.rs: verifyPrehash
//! 10,081,918 -> 2,210,458; signPrehash 7,450,684 -> 1,455,508; schnorrVerify 12,743,510 ->
//! 2,193,112; schnorrSign 12,761,079 -> 2,104,281; publicKey 6,350,400 -> 1,019,358;
//! decompressPublicKey 1,153,217 -> 173,880; compressPublicKey 590,489 -> 4,817.
#![no_std]
#![allow(deprecated)] // generic-array 0.14's from_slice, which the RustCrypto 0.13 crates use
mod ops;
mod tables;
use k256::ecdsa::Signature;
use k256::elliptic_curve::{
    group::Group,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    PrimeField,
};
use k256::{AffinePoint, EncodedPoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
use libsecp256k1_core::curve::Affine;
use moxzi_kernel::{bytes, output, trap, NONE};
use ops::{encode, parse_public, x_bytes};

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

fn secret(b: &[u8], err: &[u8]) -> NonZeroScalar {
    if b.len() != 32 { trap(err) }
    Option::from(NonZeroScalar::from_repr(*FieldBytes::from_slice(b))).unwrap_or_else(|| trap(err))
}

fn scalar(b: &[u8], err: &[u8]) -> Scalar {
    if b.len() != 32 { trap(err) }
    Option::from(Scalar::from_repr(*FieldBytes::from_slice(b))).unwrap_or_else(|| trap(err))
}

fn public_or(b: &[u8], err: &[u8]) -> Affine {
    parse_public(b).unwrap_or_else(|| trap(err))
}

/// The same point for k256 (pointMultiply), checked on the curve again as it is converted.
fn to_k256(a: &Affine) -> ProjectivePoint {
    let (e, n) = encode(a, false);
    let p: Option<AffinePoint> = Option::from(AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(&e[..n]).unwrap()));
    p.unwrap_or_else(|| trap(b"Secp256k1: point conversion failed")).into()
}

fn signature(b: &[u8]) -> Option<Signature> {
    if b.len() != 64 { return None }
    Signature::from_slice(b).ok()
}

unsafe fn put_point(out: *mut u8, p: &Affine, compressed: bool) {
    let (e, n) = encode(p, compressed);
    put(out, &e[..n]);
}

/// A compressed point, or null at infinity.
fn point_or_null(p: Option<Affine>) -> u64 {
    match p { Some(p) => { let (e, n) = encode(&p, true); output(&e[..n]) } None => NONE }
}

/// k*G for k != 0 (never the point at infinity).
fn base(k: &Scalar) -> Affine {
    ops::affine(&ops::mul_g(k)).unwrap_or_else(|| trap(b"Secp256k1: k*G at infinity"))
}

#[no_mangle]
pub unsafe extern "C" fn public_key(s: *const u8, sn: usize, out: *mut u8) {
    let d = secret(bytes(s, sn), b"Secp256k1.publicKey: invalid secret key");
    put_point(out, &base(&d), false);
}

#[no_mangle]
pub unsafe extern "C" fn derive_public_key(s: *const u8, sn: usize, out: *mut u8) {
    let d = secret(bytes(s, sn), b"Secp256k1.derivePublicKey: invalid secret key");
    put_point(out, &base(&d), true);
}

#[no_mangle]
pub unsafe extern "C" fn compress_public_key(k: *const u8, kn: usize, out: *mut u8) {
    put_point(out, &public_or(bytes(k, kn), b"Secp256k1.compressPublicKey: invalid public key"), true);
}

#[no_mangle]
pub unsafe extern "C" fn decompress_public_key(k: *const u8, kn: usize, out: *mut u8) {
    put_point(out, &public_or(bytes(k, kn), b"Secp256k1.decompressPublicKey: invalid public key"), false);
}

#[no_mangle]
pub unsafe extern "C" fn convert_public_key(k: *const u8, kn: usize, compressed: u64) -> u64 {
    let p = public_or(bytes(k, kn), b"Secp256k1.convertPublicKey: invalid public key");
    let (e, n) = encode(&p, compressed != 0);
    output(&e[..n])
}

#[no_mangle]
pub unsafe extern "C" fn x_only_public_key(k: *const u8, kn: usize, out: *mut u8) {
    let p = public_or(bytes(k, kn), b"Secp256k1.xOnlyPublicKey: invalid public key");
    put(out, &x_bytes(&p));
}

#[no_mangle]
pub unsafe extern "C" fn point_add(a: *const u8, an: usize, b: *const u8, bn: usize) -> u64 {
    let p = public_or(bytes(a, an), b"Secp256k1.pointAdd: invalid public key");
    let q = public_or(bytes(b, bn), b"Secp256k1.pointAdd: invalid public key");
    point_or_null(ops::add_vartime(&p, &q))
}

#[no_mangle]
pub unsafe extern "C" fn point_multiply(k: *const u8, kn: usize, s: *const u8, sn: usize) -> u64 {
    let p = public_or(bytes(k, kn), b"Secp256k1.pointMultiply: invalid public key");
    let t = scalar(bytes(s, sn), b"Secp256k1.pointMultiply: invalid scalar");
    // k256's constant-time multiplication of an arbitrary point.
    let r = to_k256(&p) * t;
    if bool::from(r.is_identity()) { NONE } else { output(r.to_affine().to_encoded_point(true).as_bytes()) }
}

#[no_mangle]
pub unsafe extern "C" fn base_multiply(s: *const u8, sn: usize) -> u64 {
    let t = scalar(bytes(s, sn), b"Secp256k1.baseMultiply: invalid scalar");
    point_or_null(ops::affine(&ops::mul_g(&t)))
}

#[no_mangle]
pub unsafe extern "C" fn tweak_public_key(k: *const u8, kn: usize, s: *const u8, sn: usize) -> u64 {
    let p = public_or(bytes(k, kn), b"Secp256k1.tweakPublicKey: invalid public key");
    let t = scalar(bytes(s, sn), b"Secp256k1.tweakPublicKey: invalid scalar");
    point_or_null(ops::mul_g_add(&t, &p))
}

#[no_mangle]
pub unsafe extern "C" fn tweak_x_only_public_key(x: *const u8, xn: usize, s: *const u8, sn: usize) -> u64 {
    let p = ops::lift_x(bytes(x, xn)).unwrap_or_else(|| trap(b"Secp256k1.tweakXOnlyPublicKey: invalid x-only public key"));
    let t = scalar(bytes(s, sn), b"Secp256k1.tweakXOnlyPublicKey: invalid scalar");
    point_or_null(ops::mul_g_add(&t, &p))
}

#[no_mangle]
pub unsafe extern "C" fn tweak_x_only_secret_key(s: *const u8, sn: usize, t: *const u8, tn: usize) -> u64 {
    let d = secret(bytes(s, sn), b"Secp256k1.tweakXOnlySecretKey: invalid secret key");
    let t = scalar(bytes(t, tn), b"Secp256k1.tweakXOnlySecretKey: invalid scalar");
    let d = ops::cneg(&d, ops::y_is_odd(&base(&d)));
    let r = d + t;
    if bool::from(r.is_zero()) { NONE } else { output(&r.to_bytes()) }
}

#[no_mangle]
pub unsafe extern "C" fn normalize_signature(g: *const u8, gn: usize, out: *mut u8) {
    let sig = signature(bytes(g, gn)).unwrap_or_else(|| trap(b"Secp256k1.normalizeSignature: invalid signature"));
    put(out, &sig.normalize_s().unwrap_or(sig).to_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn signature_from_der(d: *const u8, dn: usize) -> u64 {
    match Signature::from_der(bytes(d, dn)) { Ok(sig) => output(&sig.to_bytes()), Err(_) => NONE }
}

#[no_mangle]
pub unsafe extern "C" fn signature_to_der(g: *const u8, gn: usize) -> u64 {
    let sig = signature(bytes(g, gn)).unwrap_or_else(|| trap(b"Secp256k1.signatureToDer: invalid signature"));
    output(sig.to_der().as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn sign_prehash(s: *const u8, sn: usize, h: *const u8, hn: usize, out: *mut u8) {
    let d = secret(bytes(s, sn), b"Secp256k1.signPrehash: invalid secret key");
    let Ok(h) = <&[u8; 32]>::try_from(bytes(h, hn)) else { trap(b"Secp256k1.signPrehash: the digest must be 32 bytes") };
    let sig = ops::ecdsa_sign(&d, h).unwrap_or_else(|| trap(b"Secp256k1.signPrehash: signing failed"));
    put(out, &sig);
}

/// ECDSA verification as k256 (and libsecp256k1) define it: high-S signatures are refused.
#[no_mangle]
pub unsafe extern "C" fn verify_prehash(k: *const u8, kn: usize, h: *const u8, hn: usize, g: *const u8, gn: usize) -> u32 {
    let Some(key) = parse_public(bytes(k, kn)) else { return 0 };
    let Ok(h) = <&[u8; 32]>::try_from(bytes(h, hn)) else { return 0 };
    let Some(sig) = signature(bytes(g, gn)) else { return 0 };
    ops::ecdsa_verify(&key, h, &sig) as u32
}

/// BIP340 signing, exactly the reference algorithm (k256 scalars, SHA-256 tagged hashes).
#[no_mangle]
pub unsafe extern "C" fn schnorr_sign(s: *const u8, sn: usize, m: *const u8, mn: usize, a: *const u8, an: usize, out: *mut u8) {
    let d0 = secret(bytes(s, sn), b"Secp256k1.schnorrSign: invalid secret key");
    let aux = bytes(a, an);
    if aux.len() != 32 { trap(b"Secp256k1.schnorrSign: the auxiliary randomness must be 32 bytes") }
    let sig = ops::schnorr_sign(&d0, bytes(m, mn), aux).unwrap_or_else(|| trap(b"Secp256k1.schnorrSign: signing failed"));
    put(out, &sig);
}

/// BIP340 verification, exactly the reference algorithm (r < p and s < n; zero allowed).
#[no_mangle]
pub unsafe extern "C" fn schnorr_verify(x: *const u8, xn: usize, m: *const u8, mn: usize, g: *const u8, gn: usize) -> u32 {
    ops::schnorr_verify(bytes(x, xn), bytes(m, mn), bytes(g, gn)) as u32
}
