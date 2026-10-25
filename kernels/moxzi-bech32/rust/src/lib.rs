//! Bech32 / Bech32m (BIP173 / BIP350) and segwit address kernels for the `moxzi-bech32` Motoko
//! package (ABI 1, see moxzi-kernel), from the stock `bech32` crate.
//!
//! Every function returns null where the Motoko body (mo:bitcoin 0.2.1) returns an error or
//! would trap, so both paths agree on every input:
//! - strings are at most 90 characters (BIP173), every character is in `!`..`~`, upper and
//!   lower case are not mixed, the separator is the last `1`, and at least six characters
//!   (the checksum) follow it;
//! - an HRP to encode is 1 or more characters in `!`..`~`, none uppercase.
#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use bech32::primitives::decode::UncheckedHrpstring;
use bech32::primitives::iter::Fe32IterExt;
use bech32::{Bech32, Bech32m, Fe32, Hrp};
use moxzi_kernel::{bytes, output, text, NONE};

const MAX_LENGTH: usize = 90;

/// An HRP the encoders accept: non-empty, `!`..`~`, no uppercase (mo:bitcoin asserts this).
fn encodable_hrp(h: &[u8]) -> Option<Hrp> {
    if h.is_empty() || h.iter().any(|&c| !(33..=126).contains(&c) || c.is_ascii_uppercase()) {
        return None;
    }
    Hrp::parse(core::str::from_utf8(h).ok()?).ok()
}

/// `[0 = Bech32 | 1 = Bech32m][hrp length][hrp, lowercase][5-bit values]`.
fn decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() > MAX_LENGTH {
        return None;
    }
    let s = core::str::from_utf8(s).ok()?;
    let unchecked = UncheckedHrpstring::new(s).ok()?;
    let m = if unchecked.has_valid_checksum::<Bech32>() {
        0
    } else if unchecked.has_valid_checksum::<Bech32m>() {
        1
    } else {
        return None;
    };
    let hrp = unchecked.hrp();
    let data = unchecked.data_part_ascii();
    let data = &data[..data.len() - 6];
    let mut out = Vec::with_capacity(2 + hrp.len() + data.len());
    out.push(m);
    out.push(hrp.len() as u8);
    out.extend(hrp.lowercase_byte_iter());
    out.extend(data.iter().map(|&c| Fe32::from_char_unchecked(c).to_u8()));
    Some(out)
}

#[no_mangle]
pub unsafe extern "C" fn bech32_encode(h: *const u8, hn: usize, d: *const u8, dn: usize, m: u64) -> u64 {
    let (h, d) = (bytes(h, hn), bytes(d, dn));
    let Some(hrp) = encodable_hrp(h) else { return NONE };
    if h.len() + 1 + d.len() + 6 > MAX_LENGTH || d.iter().any(|&v| v > 31) {
        return NONE;
    }
    let fes = d.iter().map(|&v| Fe32::try_from(v).unwrap());
    let s: String = if m != 0 {
        fes.with_checksum::<Bech32m>(&hrp).chars().collect()
    } else {
        fes.with_checksum::<Bech32>(&hrp).chars().collect()
    };
    text(&s)
}

#[no_mangle]
pub unsafe extern "C" fn bech32_decode(p: *const u8, n: usize) -> u64 {
    match decode(bytes(p, n)) {
        Some(v) => output(&v),
        None => NONE,
    }
}

/// Regroup `data`'s `from`-bit values into `to`-bit values, most significant bit first
/// (BIP173's reference `convertbits`). Both widths are 1..8. Without `pad`, leftover bits must
/// be fewer than `from` and zero.
fn convert_bits(data: &[u8], from: u64, to: u64, pad: bool) -> Option<Vec<u8>> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return None;
    }
    let (from, to) = (from as u32, to as u32);
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = ((acc << from) | v as u32) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

#[no_mangle]
pub unsafe extern "C" fn bech32_convert_bits(p: *const u8, n: usize, from: u64, to: u64, pad: u64) -> u64 {
    match convert_bits(bytes(p, n), from, to, pad != 0) {
        Some(v) => output(&v),
        None => NONE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn segwit_encode(h: *const u8, hn: usize, version: u64, p: *const u8, n: usize) -> u64 {
    let (h, program) = (bytes(h, hn), bytes(p, n));
    let Some(hrp) = encodable_hrp(h) else { return NONE };
    if version > 16 {
        return NONE;
    }
    let Ok(v) = Fe32::try_from(version as u8) else { return NONE };
    match bech32::segwit::encode(hrp, v, program) {
        Ok(s) => text(&s),
        Err(_) => NONE,
    }
}

/// `[version][hrp length][hrp, lowercase][program]`.
#[no_mangle]
pub unsafe extern "C" fn segwit_decode(p: *const u8, n: usize) -> u64 {
    let Ok(s) = core::str::from_utf8(bytes(p, n)) else { return NONE };
    // The crate checks BIP350 completely: length <= 90, version <= 16, Bech32 for version 0
    // and Bech32m otherwise, padding, and the program length (2..40, 20 or 32 for version 0).
    let Ok((hrp, version, program)) = bech32::segwit::decode(s) else { return NONE };
    let mut out = Vec::with_capacity(2 + hrp.len() + program.len());
    out.push(version.to_u8());
    out.push(hrp.len() as u8);
    out.extend(hrp.lowercase_byte_iter());
    out.extend_from_slice(&program);
    output(&out)
}
