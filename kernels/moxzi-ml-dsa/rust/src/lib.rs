//! ML-DSA-44 (FIPS 204) kernels for the `moxzi-ml-dsa` Motoko package (ABI 1, see moxzi-kernel).
//!
//! The private key is the 32-byte seed xi of ML-DSA.KeyGen_internal; keys are re-derived from it
//! on every call, so no expanded secret key is ever imported. Signing is the external (pure)
//! ML-DSA.Sign with a context string of at most 255 bytes: `mldsa44_sign` is the deterministic
//! variant (rnd = 32 zero bytes), `mldsa44_sign_hedged` takes rnd as an argument (no RNG exists).
//! Errors trap with the same message as the Motoko body, checked in the same order.
//!
//! The implementation is Cryspen's `libcrux-ml-dsa` (portable code; constant time with respect
//! to secret data; no heap). Measured on the same inputs it computes the same bytes as RustCrypto
//! `ml-dsa` 0.1.1 (the first kernel) and `fips204` 0.4.6, in about a sixth and a half of their
//! instructions respectively (verify: 7.8 M, 3.0 M, 2.1 M).
#![no_std]

use libcrux_ml_dsa::ml_dsa_44::portable::{generate_key_pair, sign, verify};
use libcrux_ml_dsa::ml_dsa_44::{MLDSA44KeyPair, MLDSA44Signature, MLDSA44VerificationKey};
use moxzi_kernel::{bytes, trap};

const PK_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

/// KeyGen_internal (FIPS 204 Algorithm 6) from the 32-byte seed xi.
fn key(seed: &[u8], who: &[u8]) -> MLDSA44KeyPair {
    let Ok(seed) = <[u8; 32]>::try_from(seed) else { fail(who, b": the seed must be 32 bytes") };
    generate_key_pair(seed)
}

/// Trap with `who` followed by `what` (built on the stack: this kernel needs no allocator).
fn fail(who: &[u8], what: &[u8]) -> ! {
    let mut m = [0u8; 128];
    let n = (who.len() + what.len()).min(m.len());
    let w = who.len().min(n);
    m[..w].copy_from_slice(&who[..w]);
    m[w..n].copy_from_slice(&what[..n - w]);
    trap(&m[..n])
}

/// ML-DSA.Sign (FIPS 204 Algorithm 2): M' = 0 || |ctx| || ctx || M, then Sign_internal with rnd.
/// The crate bounds the rejection loop at 814 iterations (FIPS 204 Appendix C); reaching it
/// has negligible probability, and would trap with "signing failed".
unsafe fn sign_with(s: *const u8, sn: usize, m: *const u8, mn: usize, c: *const u8, cn: usize, rnd: Option<(*const u8, usize)>, who: &[u8], out: *mut u8) {
    let kp = key(bytes(s, sn), who);
    let ctx = bytes(c, cn);
    if ctx.len() > 255 {
        fail(who, b": the context must be at most 255 bytes");
    }
    let rnd = match rnd {
        // The deterministic variant: rnd = 32 zero bytes.
        None => [0u8; 32],
        Some((r, rn)) => match <[u8; 32]>::try_from(bytes(r, rn)) {
            Ok(r) => r,
            Err(_) => fail(who, b": the randomness must be 32 bytes"),
        },
    };
    let Ok(sig) = sign(&kp.signing_key, bytes(m, mn), ctx, rnd) else { fail(who, b": signing failed") };
    put(out, sig.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn mldsa44_public_key(s: *const u8, sn: usize, out: *mut u8) {
    let kp = key(bytes(s, sn), b"MlDsa44.publicKey");
    put(out, kp.verification_key.as_slice());
}

#[no_mangle]
pub unsafe extern "C" fn mldsa44_sign(s: *const u8, sn: usize, m: *const u8, mn: usize, c: *const u8, cn: usize, out: *mut u8) {
    sign_with(s, sn, m, mn, c, cn, None, b"MlDsa44.sign", out)
}

#[no_mangle]
pub unsafe extern "C" fn mldsa44_sign_hedged(
    s: *const u8, sn: usize, m: *const u8, mn: usize, c: *const u8, cn: usize, r: *const u8, rn: usize, out: *mut u8,
) {
    sign_with(s, sn, m, mn, c, cn, Some((r, rn)), b"MlDsa44.signHedged", out)
}

#[no_mangle]
pub unsafe extern "C" fn mldsa44_verify(p: *const u8, pn: usize, m: *const u8, mn: usize, s: *const u8, sn: usize, c: *const u8, cn: usize) -> u32 {
    let (pk, sig, ctx) = (bytes(p, pn), bytes(s, sn), bytes(c, cn));
    if pk.len() != PK_LEN || sig.len() != SIG_LEN || ctx.len() > 255 {
        return 0;
    }
    let (Ok(pk), Ok(sig)) = (<[u8; PK_LEN]>::try_from(pk), <[u8; SIG_LEN]>::try_from(sig)) else { return 0 };
    // Every 1312-byte string is a public key (t1 is 10-bit packed); the signature's decoding
    // checks (hint encoding, z range) are part of verify, which then fails.
    verify(&MLDSA44VerificationKey::new(pk), bytes(m, mn), ctx, &MLDSA44Signature::new(sig)).is_ok() as u32
}
