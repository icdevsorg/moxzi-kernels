//! Bitcoin kernels for the `moxzi-bitcoin` Motoko package (ABI 1, see moxzi-kernel): hashes,
//! addresses, BIP32 public derivation, output scripts and transaction hashes.
//!
//! Stock pure-Rust crates: sha2, ripemd, hmac, k256 (secp256k1 group arithmetic), bs58, bech32.
//! Every function returns null (or traps with the same text) exactly where the Motoko body in
//! src/*.mo does; the module docs there state the rules.
#![no_std]
extern crate alloc;
mod tx;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar};
use moxzi_kernel::{bytes, output, text, trap, NONE};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

unsafe fn put(out: *mut u8, d: &[u8]) {
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
}

fn opt(v: Option<Vec<u8>>) -> u64 {
    match v {
        Some(v) => output(&v),
        None => NONE,
    }
}

fn opt_text(v: Option<alloc::string::String>) -> u64 {
    match v {
        Some(s) => text(&s),
        None => NONE,
    }
}

// ---- Hash ------------------------------------------------------------------------------------

fn hash160(b: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(b)).into()
}

pub(crate) fn tagged(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

#[no_mangle]
pub unsafe extern "C" fn hash_sha256d(p: *const u8, n: usize, out: *mut u8) {
    put(out, &tx::sha256d(bytes(p, n)));
}

#[no_mangle]
pub unsafe extern "C" fn hash_hash160(p: *const u8, n: usize, out: *mut u8) {
    put(out, &hash160(bytes(p, n)));
}

#[no_mangle]
pub unsafe extern "C" fn hash_tagged(t: *const u8, tn: usize, p: *const u8, n: usize, out: *mut u8) {
    put(out, &tagged(bytes(t, tn), bytes(p, n)));
}

// ---- Networks and keys -----------------------------------------------------------------------

struct Net {
    p2pkh: u8,
    p2sh: u8,
    hrp: &'static str,
    xpub: [u8; 4],
}

fn network(name: &[u8], module: &[u8]) -> Net {
    match name {
        b"mainnet" => Net { p2pkh: 0x00, p2sh: 0x05, hrp: "bc", xpub: [0x04, 0x88, 0xb2, 0x1e] },
        b"testnet" => Net { p2pkh: 0x6f, p2sh: 0xc4, hrp: "tb", xpub: [0x04, 0x35, 0x87, 0xcf] },
        b"regtest" => Net { p2pkh: 0x6f, p2sh: 0xc4, hrp: "bcrt", xpub: [0x04, 0x35, 0x87, 0xcf] },
        _ => {
            let mut m = Vec::new();
            m.extend_from_slice(module);
            m.extend_from_slice(b": network must be \"mainnet\", \"testnet\" or \"regtest\"");
            trap(&m)
        }
    }
}

/// A SEC1 public key, compressed (33 bytes) or uncompressed (65): coordinates below the field
/// prime, on the curve, not the identity. The prefix is checked here because k256 (through the
/// sec1 crate) also accepts the non-standard "compact" tag 0x05 on 33 bytes.
fn sec1(b: &[u8]) -> Option<PublicKey> {
    match (b.len(), b.first()) {
        (33, Some(2 | 3)) | (65, Some(4)) => {}
        _ => return None,
    }
    PublicKey::from_sec1_bytes(b).ok()
}

fn compressed(k: &PublicKey) -> [u8; 33] {
    let e = k.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(e.as_bytes());
    out
}

/// `k + t*G` for a scalar given as 32 big-endian bytes; None if t >= n or the sum is the identity.
fn tweak_add(k: &PublicKey, t: &[u8; 32]) -> Option<PublicKey> {
    let t: Option<Scalar> = Scalar::from_repr(FieldBytes::clone_from_slice(t)).into();
    let q = ProjectivePoint::from(*k.as_affine()) + ProjectivePoint::GENERATOR * t?;
    if bool::from(q.is_identity()) {
        return None;
    }
    PublicKey::from_affine(q.to_affine()).ok()
}

fn base58check(payload: &[u8]) -> alloc::string::String {
    bs58::encode(payload).with_check().into_string()
}

fn unbase58check(s: &[u8]) -> Option<Vec<u8>> {
    bs58::decode(s).with_check(None).into_vec().ok()
}

fn segwit(hrp: &str, version: u8, program: &[u8]) -> Option<alloc::string::String> {
    let hrp = bech32::Hrp::parse(hrp).ok()?;
    let v = bech32::Fe32::try_from(version).ok()?;
    bech32::segwit::encode(hrp, v, program).ok()
}

fn with_prefix(prefix: u8, h: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + h.len());
    v.push(prefix);
    v.extend_from_slice(h);
    v
}

// ---- Address ---------------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn address_p2pkh(k: *const u8, kn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    let k = bytes(k, kn);
    if sec1(k).is_none() {
        return NONE;
    }
    text(&base58check(&with_prefix(net.p2pkh, &hash160(k))))
}

#[no_mangle]
pub unsafe extern "C" fn address_p2sh(s: *const u8, sn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    text(&base58check(&with_prefix(net.p2sh, &hash160(bytes(s, sn)))))
}

#[no_mangle]
pub unsafe extern "C" fn address_p2wpkh(k: *const u8, kn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    let k = bytes(k, kn);
    if k.len() != 33 || sec1(k).is_none() {
        return NONE;
    }
    opt_text(segwit(net.hrp, 0, &hash160(k)))
}

#[no_mangle]
pub unsafe extern "C" fn address_p2wsh(s: *const u8, sn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    match segwit(net.hrp, 0, &tx::sha256(bytes(s, sn))) {
        Some(a) => text(&a),
        None => trap(b"Address.p2wsh: unreachable"),
    }
}

/// BIP341 taproot_tweak_pubkey: Q = lift_x(P) + int(TapTweak(P || root))G, compressed.
fn taproot_output(p: &[u8], root: &[u8]) -> Option<[u8; 33]> {
    if p.len() != 32 || (!root.is_empty() && root.len() != 32) {
        return None;
    }
    let mut lifted = [2u8; 33];
    lifted[1..].copy_from_slice(p);
    let k = PublicKey::from_sec1_bytes(&lifted).ok()?;
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(p);
    m.extend_from_slice(root);
    let q = tweak_add(&k, &tagged(b"TapTweak", &m))?;
    Some(compressed(&q))
}

#[no_mangle]
pub unsafe extern "C" fn address_taproot_output_key(p: *const u8, pn: usize, r: *const u8, rn: usize) -> u64 {
    opt(taproot_output(bytes(p, pn), bytes(r, rn)).map(|q| q.to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn address_p2tr(p: *const u8, pn: usize, r: *const u8, rn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    let Some(q) = taproot_output(bytes(p, pn), bytes(r, rn)) else { return NONE };
    opt_text(segwit(net.hrp, 1, &q[1..]))
}

fn witness_script(version: u8, program: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + program.len());
    v.push(if version == 0 { 0 } else { 0x50 + version });
    v.push(program.len() as u8);
    v.extend_from_slice(program);
    v
}

fn to_script(a: &[u8], net: &Net) -> Option<Vec<u8>> {
    let s = core::str::from_utf8(a).ok()?;
    if let Ok((hrp, version, program)) = bech32::segwit::decode(s) {
        if !hrp.lowercase_byte_iter().eq(net.hrp.bytes()) {
            return None;
        }
        return Some(witness_script(version.to_u8(), &program));
    }
    let p = unbase58check(a)?;
    if p.len() != 21 {
        return None;
    }
    if p[0] == net.p2pkh {
        let mut v = Vec::from([0x76, 0xa9, 0x14]);
        v.extend_from_slice(&p[1..]);
        v.extend_from_slice(&[0x88, 0xac]);
        Some(v)
    } else if p[0] == net.p2sh {
        let mut v = Vec::from([0xa9, 0x14]);
        v.extend_from_slice(&p[1..]);
        v.push(0x87);
        Some(v)
    } else {
        None
    }
}

#[no_mangle]
pub unsafe extern "C" fn address_to_script(a: *const u8, an: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    opt(to_script(bytes(a, an), &net))
}

fn from_script(s: &[u8], net: &Net) -> Option<alloc::string::String> {
    if s.len() == 25 && s[..3] == [0x76, 0xa9, 0x14] && s[23..] == [0x88, 0xac] {
        return Some(base58check(&with_prefix(net.p2pkh, &s[3..23])));
    }
    if s.len() == 23 && s[..2] == [0xa9, 0x14] && s[22] == 0x87 {
        return Some(base58check(&with_prefix(net.p2sh, &s[2..22])));
    }
    if s.len() >= 4 && s.len() <= 42 && (s[0] == 0 || (0x51..=0x60).contains(&s[0])) && s[1] as usize + 2 == s.len() {
        let version = if s[0] == 0 { 0 } else { s[0] - 0x50 };
        return segwit(net.hrp, version, &s[2..]);
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn address_from_script(s: *const u8, sn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Address");
    opt_text(from_script(bytes(s, sn), &net))
}

// ---- BIP32 -----------------------------------------------------------------------------------

const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

/// The 78-byte payload of a valid xpub/tpub.
fn xpub_payload(p: &[u8]) -> Option<[u8; 78]> {
    if p.len() != 78 || (p[..4] != XPUB && p[..4] != TPUB) {
        return None;
    }
    if p[4] == 0 && (p[5..9] != [0; 4] || p[9..13] != [0; 4]) {
        return None;
    }
    if p[45] != 2 && p[45] != 3 {
        return None;
    }
    sec1(&p[45..78])?;
    let mut out = [0u8; 78];
    out.copy_from_slice(p);
    Some(out)
}

fn parse_xpub(s: &[u8]) -> Option<[u8; 78]> {
    xpub_payload(&unbase58check(s)?)
}

/// BIP32 CKDpub of a valid payload.
fn child(p: &[u8; 78], index: u64) -> Option<[u8; 78]> {
    if index >= 0x8000_0000 || p[4] == 255 {
        return None;
    }
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&p[13..45]).ok()?;
    mac.update(&p[45..78]);
    mac.update(&(index as u32).to_be_bytes());
    let i = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let k = sec1(&p[45..78])?;
    let c = tweak_add(&k, &il)?;
    let mut out = [0u8; 78];
    out[..4].copy_from_slice(&p[..4]);
    out[4] = p[4] + 1;
    out[5..9].copy_from_slice(&hash160(&p[45..78])[..4]);
    out[9..13].copy_from_slice(&(index as u32).to_be_bytes());
    out[13..45].copy_from_slice(&i[32..]);
    out[45..].copy_from_slice(&compressed(&c));
    Some(out)
}

/// "m", "m/" + indices (depth 0 only), or relative indices: decimal, below 2^31, '/'-separated.
fn path(s: &[u8], depth: u8) -> Option<Vec<u64>> {
    let rest = if s == b"m" {
        return if depth == 0 { Some(Vec::new()) } else { None };
    } else if s.starts_with(b"m/") {
        if depth != 0 {
            return None;
        }
        &s[2..]
    } else {
        s
    };
    let mut v = Vec::new();
    for seg in rest.split(|&c| c == b'/') {
        if seg.is_empty() {
            return None;
        }
        let mut n: u64 = 0;
        for &c in seg {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + (c - b'0') as u64;
            if n >= 0x8000_0000 {
                return None;
            }
        }
        v.push(n);
    }
    Some(v)
}

#[no_mangle]
pub unsafe extern "C" fn bip32_parse(s: *const u8, n: usize) -> u64 {
    opt(parse_xpub(bytes(s, n)).map(|p| p.to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn bip32_serialize(p: *const u8, n: usize) -> u64 {
    opt_text(xpub_payload(bytes(p, n)).map(|p| base58check(&p)))
}

#[no_mangle]
pub unsafe extern "C" fn bip32_derive_child(s: *const u8, n: usize, index: u64) -> u64 {
    opt_text(parse_xpub(bytes(s, n)).and_then(|p| child(&p, index)).map(|p| base58check(&p)))
}

#[no_mangle]
pub unsafe extern "C" fn bip32_derive_path(s: *const u8, n: usize, t: *const u8, tn: usize) -> u64 {
    let Some(mut p) = parse_xpub(bytes(s, n)) else { return NONE };
    let Some(indices) = path(bytes(t, tn), p[4]) else { return NONE };
    for i in indices {
        match child(&p, i) {
            Some(c) => p = c,
            None => return NONE,
        }
    }
    text(&base58check(&p))
}

#[no_mangle]
pub unsafe extern "C" fn bip32_fingerprint(k: *const u8, kn: usize) -> u64 {
    opt(sec1(bytes(k, kn)).map(|k| hash160(&compressed(&k))[..4].to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn bip32_from_public_key(k: *const u8, kn: usize, c: *const u8, cn: usize, net: *const u8, nn: usize) -> u64 {
    let net = network(bytes(net, nn), b"Bip32");
    let (k, c) = (bytes(k, kn), bytes(c, cn));
    let Some(k) = sec1(k) else { return NONE };
    if c.len() != 32 {
        return NONE;
    }
    let mut p = [0u8; 78];
    p[..4].copy_from_slice(&net.xpub);
    p[13..45].copy_from_slice(c);
    p[45..].copy_from_slice(&compressed(&k));
    text(&base58check(&p))
}

// ---- Script ----------------------------------------------------------------------------------

fn sized(b: &[u8], n: usize, f: impl FnOnce(&[u8]) -> Vec<u8>) -> u64 {
    if b.len() == n { output(&f(b)) } else { NONE }
}

#[no_mangle]
pub unsafe extern "C" fn script_p2pkh(h: *const u8, n: usize) -> u64 {
    sized(bytes(h, n), 20, |h| [&[0x76, 0xa9, 0x14][..], h, &[0x88, 0xac]].concat())
}

#[no_mangle]
pub unsafe extern "C" fn script_p2sh(h: *const u8, n: usize) -> u64 {
    sized(bytes(h, n), 20, |h| [&[0xa9, 0x14][..], h, &[0x87]].concat())
}

#[no_mangle]
pub unsafe extern "C" fn script_p2wpkh(h: *const u8, n: usize) -> u64 {
    sized(bytes(h, n), 20, |h| witness_script(0, h))
}

#[no_mangle]
pub unsafe extern "C" fn script_p2wsh(h: *const u8, n: usize) -> u64 {
    sized(bytes(h, n), 32, |h| witness_script(0, h))
}

#[no_mangle]
pub unsafe extern "C" fn script_p2tr(k: *const u8, n: usize) -> u64 {
    sized(bytes(k, n), 32, |k| witness_script(1, k))
}

/// The minimal push of `d` (BIP62): OP_0, OP_1NEGATE, OP_1..OP_16, a direct push, or
/// OP_PUSHDATA1/2/4.
#[no_mangle]
pub unsafe extern "C" fn script_push_data(p: *const u8, n: usize) -> u64 {
    let d = bytes(p, n);
    match d.len() {
        0 => return output(&[0x00]),
        1 if d[0] == 0x81 => return output(&[0x4f]),
        1 if (1..=16).contains(&d[0]) => return output(&[0x50 + d[0]]),
        _ => {}
    }
    let mut v = Vec::with_capacity(d.len() + 5);
    match d.len() {
        n if n < 0x4c => v.push(n as u8),
        n if n <= 0xff => v.extend_from_slice(&[0x4c, n as u8]),
        n if n <= 0xffff => {
            v.push(0x4d);
            v.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n => {
            v.push(0x4e);
            v.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
    v.extend_from_slice(d);
    output(&v)
}

#[no_mangle]
pub unsafe extern "C" fn script_tap_leaf_hash(p: *const u8, n: usize, version: u64) -> u64 {
    if version > 0xfe || version & 1 != 0 {
        return NONE;
    }
    let s = bytes(p, n);
    let mut m = Vec::with_capacity(s.len() + 10);
    m.push(version as u8);
    tx::put_compact(&mut m, s.len() as u64);
    m.extend_from_slice(s);
    output(&tagged(b"TapLeaf", &m))
}

#[no_mangle]
pub unsafe extern "C" fn script_tap_branch_hash(a: *const u8, an: usize, b: *const u8, bn: usize) -> u64 {
    let (a, b) = (bytes(a, an), bytes(b, bn));
    if a.len() != 32 || b.len() != 32 {
        return NONE;
    }
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    output(&tagged(b"TapBranch", &[x, y].concat()))
}

// ---- Transaction -----------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn tx_is_valid(p: *const u8, n: usize) -> u32 {
    tx::parse(bytes(p, n)).is_some() as u32
}

#[no_mangle]
pub unsafe extern "C" fn tx_strip_witness(p: *const u8, n: usize) -> u64 {
    opt(tx::parse(bytes(p, n)).map(|t| tx::serialize(&t, false)))
}

#[no_mangle]
pub unsafe extern "C" fn tx_txid(p: *const u8, n: usize) -> u64 {
    opt(tx::parse(bytes(p, n)).map(|t| tx::sha256d(&tx::serialize(&t, false)).to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn tx_wtxid(p: *const u8, n: usize) -> u64 {
    opt(tx::parse(bytes(p, n)).map(|t| tx::sha256d(&tx::serialize(&t, true)).to_vec()))
}

#[no_mangle]
pub unsafe extern "C" fn tx_sighash_legacy(p: *const u8, n: usize, index: u64, s: *const u8, sn: usize, hash_type: u64) -> u64 {
    let Some(t) = tx::parse(bytes(p, n)) else { return NONE };
    if index >= t.inputs.len() as u64 || hash_type > 0xffff_ffff {
        return NONE;
    }
    output(&tx::sighash_legacy(&t, index as usize, bytes(s, sn), hash_type as u32))
}

#[no_mangle]
pub unsafe extern "C" fn tx_sighash_segwit_v0(p: *const u8, n: usize, index: u64, s: *const u8, sn: usize, amount: u64, hash_type: u64) -> u64 {
    let Some(t) = tx::parse(bytes(p, n)) else { return NONE };
    if index >= t.inputs.len() as u64 || hash_type > 0xffff_ffff {
        return NONE;
    }
    output(&tx::sighash_segwit_v0(&t, index as usize, bytes(s, sn), amount, hash_type as u32))
}

#[no_mangle]
pub unsafe extern "C" fn tx_sighash_taproot(
    p: *const u8, n: usize, index: u64, po: *const u8, pon: usize, hash_type: u64,
    a: *const u8, an: usize, l: *const u8, ln: usize, codesep: u64,
) -> u64 {
    let Some(t) = tx::parse(bytes(p, n)) else { return NONE };
    if index >= t.inputs.len() as u64 || hash_type > 0xff || codesep > 0xffff_ffff {
        return NONE;
    }
    // The spent outputs: one serialized output per input, nothing else.
    let po = bytes(po, pon);
    let mut r = tx::Reader { b: po, pos: 0 };
    let mut prevouts = Vec::new();
    while r.pos < po.len() {
        let Some(o) = r.output() else { return NONE };
        prevouts.push(o);
    }
    if prevouts.len() != t.inputs.len() {
        return NONE;
    }
    let (a, l) = (bytes(a, an), bytes(l, ln));
    let annex = match a.len() {
        0 => None,
        _ if a[0] == 0x50 => Some(a),
        _ => return NONE,
    };
    let leaf = match l.len() {
        0 => None,
        32 => Some((l, codesep as u32)),
        _ => return NONE,
    };
    opt(tx::sighash_taproot(&t, index as usize, &prevouts, hash_type as u8, annex, leaf).map(|h| h.to_vec()))
}
