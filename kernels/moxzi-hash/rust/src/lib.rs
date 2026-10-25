//! Hash kernels for the `moxzi-hash` Motoko package (ABI 1, see moxzi-kernel). Each digest is a
//! fixed-size Blob result: the last parameter points at room for it.
#![no_std]
use hmac::{Hmac, Mac};
use moxzi_kernel::{bytes, trap};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

#[no_mangle]
pub unsafe extern "C" fn sha256(p: *const u8, n: usize, out: *mut u8) {
    put(out, &Sha256::digest(bytes(p, n)));
}

#[no_mangle]
pub unsafe extern "C" fn sha512(p: *const u8, n: usize, out: *mut u8) {
    put(out, &Sha512::digest(bytes(p, n)));
}

#[no_mangle]
pub unsafe extern "C" fn hmac_sha256(k: *const u8, kn: usize, p: *const u8, n: usize, out: *mut u8) {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(bytes(k, kn)).unwrap_or_else(|_| trap(b"Hmac.sha256: bad key"));
    m.update(bytes(p, n));
    put(out, &m.finalize().into_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn hmac_sha512(k: *const u8, kn: usize, p: *const u8, n: usize, out: *mut u8) {
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(bytes(k, kn)).unwrap_or_else(|_| trap(b"Hmac.sha512: bad key"));
    m.update(bytes(p, n));
    put(out, &m.finalize().into_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn ripemd160(p: *const u8, n: usize, out: *mut u8) {
    put(out, &Ripemd160::digest(bytes(p, n)));
}

#[no_mangle]
pub unsafe extern "C" fn blake3_hash(p: *const u8, n: usize, out: *mut u8) {
    put(out, blake3::hash(bytes(p, n)).as_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn blake3_keyed(k: *const u8, kn: usize, p: *const u8, n: usize, out: *mut u8) {
    let Ok(key) = <[u8; 32]>::try_from(bytes(k, kn)) else { trap(b"Blake3.keyedHash: the key must be 32 bytes") };
    put(out, blake3::keyed_hash(&key, bytes(p, n)).as_bytes());
}
