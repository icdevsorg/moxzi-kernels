//! BLS12-381 signature verification for `mo:ic-agent` (ABI 1, see moxzi-kernel).
//!
//! `bls_verify(pk, sig, msg, dst) -> bool` checks a minimal-signature-size BLS signature as the
//! IC uses it: public key a compressed G2 point (96 bytes), signature a compressed G1 point
//! (48 bytes), message hashed to G1 with `dst` (RFC 9380, expand_message_xmd with SHA-256).
//! It returns false for any malformed input, for the identity public key or signature (the
//! IETF KeyValidate rule), and for a signature that does not verify. Same contract as the
//! Motoko body of `Bls12381.verify`, which is the test oracle.
//!
//! The check e(sig, g2) == e(H(msg), pk) is computed as e(sig, g2) e(-H(msg), pk) == 1: one
//! two-term Miller loop and one final exponentiation, instead of two full pairings.
#![no_std]
extern crate alloc;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt};
use moxzi_kernel::bytes;

/// 0xc0 then zeros: the identity's encoding, which this contract refuses (KeyValidate).
fn is_identity_encoding(b: &[u8]) -> bool {
    b[0] == 0xc0 && b[1..].iter().all(|&x| x == 0)
}

fn verify(pk: &[u8], sig: &[u8], msg: &[u8], dst: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; 96]>::try_from(pk), <[u8; 48]>::try_from(sig)) else { return false };
    // The identity decodes (to the identity) and is then refused: refuse it before decoding.
    if is_identity_encoding(&pk) || is_identity_encoding(&sig) {
        return false;
    }
    // from_compressed checks the encoding, the curve equation and the subgroup.
    let pk = G2Affine::from_compressed(&pk);
    let sig = G1Affine::from_compressed(&sig);
    if bool::from(pk.is_none()) || bool::from(sig.is_none()) {
        return false;
    }
    let (pk, sig) = (pk.unwrap(), sig.unwrap());
    if bool::from(pk.is_identity()) || bool::from(sig.is_identity()) {
        return false;
    }
    let hm = G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, dst));
    let (g2, pk) = (G2Prepared::from(G2Affine::generator()), G2Prepared::from(pk));
    multi_miller_loop(&[(&sig, &g2), (&-hm, &pk)]).final_exponentiation() == Gt::identity()
}

#[no_mangle]
pub unsafe extern "C" fn bls_verify(
    pk: *const u8, pk_len: usize,
    sig: *const u8, sig_len: usize,
    msg: *const u8, msg_len: usize,
    dst: *const u8, dst_len: usize,
) -> u32 {
    verify(bytes(pk, pk_len), bytes(sig, sig_len), bytes(msg, msg_len), bytes(dst, dst_len)) as u32
}
