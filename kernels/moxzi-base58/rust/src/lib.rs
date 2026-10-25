//! Base58 and Base58Check kernels for the `moxzi-base58` Motoko package (ABI 1, see
//! moxzi-kernel), from the stock `bs58` crate (Bitcoin alphabet).
//!
//! Decoding follows the Motoko bodies (mo:bitcoin 0.2.1's Base58): ASCII spaces (0x20) before
//! and after the digits are ignored; any other character outside the alphabet, including a
//! space between digits, makes the result null.
#![no_std]
use moxzi_kernel::{bytes, output, text, NONE};

/// The input without leading and trailing ASCII spaces.
fn trim_spaces(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c != b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c != b' ').map_or(start, |i| i + 1);
    &s[start..end]
}

#[no_mangle]
pub unsafe extern "C" fn base58_encode(p: *const u8, n: usize) -> u64 {
    text(&bs58::encode(bytes(p, n)).into_string())
}

#[no_mangle]
pub unsafe extern "C" fn base58_decode(p: *const u8, n: usize) -> u64 {
    match bs58::decode(trim_spaces(bytes(p, n))).into_vec() {
        Ok(v) => output(&v),
        Err(_) => NONE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn base58check_encode(p: *const u8, n: usize) -> u64 {
    text(&bs58::encode(bytes(p, n)).with_check().into_string())
}

#[no_mangle]
pub unsafe extern "C" fn base58check_decode(p: *const u8, n: usize) -> u64 {
    match bs58::decode(trim_spaces(bytes(p, n))).with_check(None).into_vec() {
        Ok(v) => output(&v),
        Err(_) => NONE,
    }
}
