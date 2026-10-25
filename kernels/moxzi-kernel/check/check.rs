//! The kernel ABI, natively and under Miri: the SDK's helpers (../src/lib.rs) through the native
//! stand-ins for `kernel_alloc` / `kernel_trap` (native.rs), and every exported function of
//! every kernel family (rewritten into this crate by build.rs), called the way the program's glue
//! calls them (CompileEnhanced.mo, `KernelArg` / `KernelResult`):
//!  - a Blob/Text argument is its payload pointer and length (never null; empty is dangling);
//!  - a fixed-size result is a buffer of exactly `result_bytes`, passed last;
//!  - a variable result is the address of `[len: u64][bytes]` from `kernel_alloc`, 0 for null.
//! Each call checks what the glue checks (a Bool is 0 or 1, a result block lies inside its
//! allocation, Text is UTF-8, a non-optional result is never null), and what the glue trusts:
//! the kernel writes neither its inputs nor outside its result buffer, and writes all of it.
//! Natively the result buffer has guard bytes; under Miri it is an exact allocation and every
//! input is a shared borrow, so an out-of-bounds or input write is reported as UB.
#![cfg(test)]
#![allow(deprecated)]
#![cfg_attr(feature = "p256", allow(dead_code, unused_imports))]
// The kernels' `extern crate alloc;` binds `alloc` in their own module only; this puts it in
// the extern prelude, where their submodules (bitcoin's tx.rs) find it as in the real crate.
extern crate alloc;
#[path = "native.rs"]
#[allow(dead_code)]
mod native;

use native::{free_scratch, iters, run, scratch_count, take_output, Arg, OutBuf, Rng, Stop};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Blob,
    Text,
    Nat64,
    Bool,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Res {
    Bool,
    Fixed(usize),
    Blob,
    OptBlob,
    Text,
    OptText,
}
pub struct Entry {
    pub family: &'static str,
    pub name: &'static str,
    pub export: &'static str,
    pub args: &'static [Kind],
    pub result: Res,
    pub call: unsafe fn(&[Arg], *mut u8) -> u64,
}

include!(concat!(env!("OUT_DIR"), "/kernels.rs"));

mod btc {
    include!(concat!(env!("OUT_DIR"), "/bitcoin_vectors.rs"));
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// ---- calling exports as the glue does -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Bool(bool),
    Bytes(Vec<u8>),
    Null,
}

impl Value {
    fn bytes(self) -> Vec<u8> {
        match self {
            Value::Bytes(b) => b,
            v => panic!("expected bytes, got {v:?}"),
        }
    }
    fn text(self) -> String {
        String::from_utf8(self.bytes()).unwrap()
    }
}

fn entry(family: &str, export: &str) -> &'static Entry {
    ENTRIES.iter().find(|e| e.family == family && e.export == export).unwrap_or_else(|| panic!("no export {family} {export}"))
}

/// One call, with every check of the module comment.
fn call(e: &Entry, args: &[Arg]) -> Result<Value, Stop> {
    assert_eq!(args.len(), e.args.len(), "{}", e.name);
    for (a, k) in args.iter().zip(e.args) {
        match (k, a) {
            (Kind::Blob, Arg::Bytes(_)) | (Kind::Nat64, Arg::Int(_)) => {}
            (Kind::Text, Arg::Bytes(b)) => assert!(std::str::from_utf8(b).is_ok(), "Text arguments are UTF-8"),
            (Kind::Bool, Arg::Int(v)) => assert!(*v <= 1),
            _ => panic!("{}: argument {a:?} for {k:?}", e.name),
        }
    }
    let before = args.to_vec();
    let once = |fill: u8| -> Result<Value, Stop> {
        assert_eq!(scratch_count(), 0);
        let mut out = match e.result {
            Res::Fixed(n) => Some(OutBuf::filled(n, fill)),
            _ => None,
        };
        let p = out.as_mut().map_or(std::ptr::null_mut(), |o| o.ptr());
        let r = run(|| unsafe { (e.call)(args, p) });
        let v = r.map(|r| match e.result {
            Res::Bool => {
                assert!(r <= 1, "{}: Bool result {r}", e.name);
                Value::Bool(r == 1)
            }
            Res::Fixed(_) => {
                assert_eq!(r, 0);
                Value::Bytes(out.as_ref().unwrap().bytes().to_vec())
            }
            Res::Blob | Res::Text => Value::Bytes(take_output(r).unwrap_or_else(|| panic!("{}: null for a non-optional result", e.name))),
            Res::OptBlob | Res::OptText => take_output(r).map_or(Value::Null, Value::Bytes),
        });
        if let (Ok(Value::Bytes(b)), Res::Text | Res::OptText) = (&v, e.result) {
            assert!(std::str::from_utf8(b).is_ok(), "{}: a Text result that is not UTF-8", e.name);
        }
        free_scratch();
        v
    };
    let v = once(0x5a);
    // A fixed result must be written in full: natively, call again over a different fill.
    if let (Ok(Value::Bytes(b)), Res::Fixed(_), false) = (&v, e.result, cfg!(miri)) {
        assert_eq!(&once(0xa6).unwrap().bytes(), b, "{}: result buffer not fully written (or not deterministic)", e.name);
    }
    assert_eq!(args, &before[..], "{}: the kernel wrote an input", e.name);
    v
}

fn ok(family: &str, export: &str, args: &[Arg]) -> Value {
    let e = entry(family, export);
    call(e, args).unwrap_or_else(|s| panic!("{} ({family} {export}) stopped: {s:?}\n  args {args:02x?}", e.name))
}

fn b(x: impl AsRef<[u8]>) -> Arg {
    Arg::Bytes(x.as_ref().to_vec())
}
fn i(x: u64) -> Arg {
    Arg::Int(x)
}

#[test]
#[cfg_attr(miri, ignore = "checks the generated table, not kernel code: native runs check it")]
fn every_export_is_declared_and_typed() {
    // build.rs generated one typed call per declaration; every export is declared.
    let families: std::collections::BTreeSet<_> = ENTRIES.iter().map(|e| e.family).collect();
    if cfg!(feature = "p256") {
        assert_eq!(families.len(), 1, "{families:?}");
        assert_eq!(ENTRIES.len(), 8);
    } else {
        assert_eq!(families.len(), 10, "{families:?}");
        assert_eq!(ENTRIES.len(), 97);
    }
}

// ---- hostile arguments ---------------------------------------------------------------------------

const LENGTHS: &[usize] = &[0, 1, 2, 4, 19, 20, 21, 31, 32, 33, 47, 48, 49, 63, 64, 65, 66, 77, 78, 79, 95, 96, 97, 143, 144, 145, 192, 288, 383, 384, 385, 1312, 2420];
const INTS: &[u64] = &[0, 1, 2, 3, 5, 8, 16, 17, 192, 255, 256, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000, u64::MAX];
const TEXTS: &[&str] = &["", "1", "m", "m/", "m/0", "m/0/1/2", "0/2147483647", "1/2147483648", "mainnet", "testnet", "regtest", "signet", "bc", "tb", "BC", "bcrt", "a1", "bc1", " ", "  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "TapLeaf", "é", "\u{0}", "0OIl"];

fn hostile_blob(rng: &mut Rng) -> Vec<u8> {
    let n = LENGTHS[rng.next() as usize % LENGTHS.len()];
    let mut v = match rng.next() % 4 {
        0 => vec![0; n],
        1 => vec![0xff; n],
        _ => rng.bytes(n),
    };
    // Prefixes that get past the first parsing step: SEC1 tags, BLS flags, DER, 0x50 (annex).
    if n > 0 && rng.next() % 2 == 0 {
        v[0] = [0x02, 0x03, 0x04, 0x05, 0x06, 0x80, 0xa0, 0xc0, 0xe0, 0x30, 0x50, 0x00][rng.next() as usize % 12];
    }
    v
}

fn hostile_text(rng: &mut Rng) -> Vec<u8> {
    if rng.next() % 3 == 0 {
        let n = (rng.next() % 120) as usize;
        let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz/'m 1";
        (0..n).map(|_| alphabet[rng.next() as usize % alphabet.len()]).collect()
    } else {
        TEXTS[rng.next() as usize % TEXTS.len()].as_bytes().to_vec()
    }
}

fn hostile_args(kinds: &[Kind], rng: &mut Rng, case: usize) -> Vec<Arg> {
    kinds
        .iter()
        .map(|k| match (k, case) {
            (Kind::Blob | Kind::Text, 0) => Arg::Bytes(vec![]),
            (Kind::Blob, 1) => Arg::Bytes(vec![0]),
            (Kind::Text, 1) => Arg::Bytes(b"m".to_vec()),
            (Kind::Nat64, 0) | (Kind::Bool, 0) => Arg::Int(0),
            (Kind::Nat64, 1) => Arg::Int(u64::MAX),
            (Kind::Bool, _) => Arg::Int(rng.next() % 2),
            (Kind::Nat64, _) => Arg::Int(if rng.next() % 2 == 0 { INTS[rng.next() as usize % INTS.len()] } else { rng.next() }),
            (Kind::Blob, _) => Arg::Bytes(hostile_blob(rng)),
            (Kind::Text, _) => Arg::Bytes(hostile_text(rng)),
        })
        .collect()
}

/// Every export, on inputs a caller can pass but no valid one: empty, short, wrong-length,
/// random, extreme integers. It may return false/null or trap (kernel_trap, as the Motoko body
/// traps); it must not panic (the Motoko body would not trap with "native kernel panicked"),
/// and every call passes the checks of `call`. Under Miri: the empty and the one-byte case.
#[test]
fn every_export_survives_hostile_arguments() {
    let mut rng = Rng(42);
    let mut panics = Vec::new();
    let (mut returned, mut trapped) = (0, 0);
    for e in ENTRIES {
        for case in 0..iters(150, 2) {
            let args = hostile_args(e.args, &mut rng, case);
            match call(e, &args) {
                Ok(_) => returned += 1,
                Err(Stop::Trap(_)) => trapped += 1,
                Err(Stop::Panic(m)) => panics.push(format!("{} {} ({}): {m}\n    args {:02x?}", e.family, e.name, e.export, args)),
            }
        }
    }
    eprintln!("hostile arguments: {returned} returned, {trapped} trapped, {} panicked", panics.len());
    assert!(panics.is_empty(), "kernels panicked (a trap with \"native kernel panicked\" in the program):\n{}", panics.join("\n"));
}

// ---- valid arguments: every success path, which is where the results are written ------------------

#[cfg(feature = "k256")]
fn hash_family(rng: &mut Rng) {
    use sha2::Digest;
    for msg in [vec![], rng.bytes(1), rng.bytes(64), rng.bytes(iters(1000, 100))] {
        assert_eq!(ok("moxzi-hash", "sha256", &[b(&msg)]).bytes(), sha2::Sha256::digest(&msg).to_vec());
        assert_eq!(ok("moxzi-hash", "sha512", &[b(&msg)]).bytes(), sha2::Sha512::digest(&msg).to_vec());
        assert_eq!(ok("moxzi-hash", "ripemd160", &[b(&msg)]).bytes(), ripemd::Ripemd160::digest(&msg).to_vec());
        assert_eq!(ok("moxzi-hash", "blake3_hash", &[b(&msg)]).bytes(), blake3::hash(&msg).as_bytes().to_vec());
        let key32 = rng.array::<32>();
        assert_eq!(ok("moxzi-hash", "blake3_keyed", &[b(key32), b(&msg)]).bytes(), blake3::keyed_hash(&key32, &msg).as_bytes().to_vec());
        for key in [vec![], rng.bytes(32), rng.bytes(200)] {
            assert_eq!(ok("moxzi-hash", "hmac_sha256", &[b(&key), b(&msg)]).bytes().len(), 32);
            assert_eq!(ok("moxzi-hash", "hmac_sha512", &[b(&key), b(&msg)]).bytes().len(), 64);
        }
    }
}

#[cfg(feature = "k256")]
fn base58_family(rng: &mut Rng) {
    for data in [vec![], vec![0], vec![0, 0, 1], rng.bytes(25), rng.bytes(iters(200, 40))] {
        let s = ok("moxzi-base58", "base58_encode", &[b(&data)]).text();
        assert_eq!(ok("moxzi-base58", "base58_decode", &[b(format!("  {s} "))]), Value::Bytes(data.clone()));
        let c = ok("moxzi-base58", "base58check_encode", &[b(&data)]).text();
        assert_eq!(ok("moxzi-base58", "base58check_decode", &[b(&c)]), Value::Bytes(data.clone()));
    }
}

#[cfg(feature = "k256")]
fn bech32_family(rng: &mut Rng) {
    for m in [0, 1] {
        let values: Vec<u8> = (0..32).map(|_| (rng.next() % 32) as u8).collect();
        let s = ok("moxzi-bech32", "bech32_encode", &[b("bc"), b(&values), i(m)]).text();
        let packed = ok("moxzi-bech32", "bech32_decode", &[b(&s)]).bytes();
        assert_eq!(&packed[..4], &[m as u8, 2, b'b', b'c']);
        assert_eq!(&packed[4..], &values[..]);
    }
    let data = rng.bytes(20);
    let fives = ok("moxzi-bech32", "bech32_convert_bits", &[b(&data), i(8), i(5), i(1)]).bytes();
    assert_eq!(ok("moxzi-bech32", "bech32_convert_bits", &[b(&fives), i(5), i(8), i(0)]).bytes(), data);
    for (hrp, version, len) in [("bc", 0, 20), ("tb", 0, 32), ("bc", 1, 32), ("bcrt", 16, 40)] {
        let program = rng.bytes(len);
        let s = ok("moxzi-bech32", "segwit_encode", &[b(hrp), i(version), b(&program)]).text();
        let packed = ok("moxzi-bech32", "segwit_decode", &[b(&s)]).bytes();
        assert_eq!(packed[0] as u64, version);
        assert_eq!(&packed[2 + hrp.len()..], &program[..]);
    }
}

#[cfg(feature = "k256")]
/// A secp256k1 key pair through the kernel: (secret, compressed, uncompressed).
fn secp_key(rng: &mut Rng) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let mut sk = rng.array::<32>();
    sk[0] &= 0x7f; // below n
    sk[31] |= 1; // not zero
    let c = ok("moxzi-secp256k1", "derive_public_key", &[b(sk)]).bytes();
    let u = ok("moxzi-secp256k1", "public_key", &[b(sk)]).bytes();
    (sk, c, u)
}

#[cfg(feature = "k256")]
fn secp256k1_family(rng: &mut Rng) {
    let f = "moxzi-secp256k1";
    let (sk, c, u) = secp_key(rng);
    assert_eq!((c.len(), u.len()), (33, 65));
    assert_eq!(ok(f, "compress_public_key", &[b(&u)]).bytes(), c);
    assert_eq!(ok(f, "decompress_public_key", &[b(&c)]).bytes(), u);
    assert_eq!(ok(f, "convert_public_key", &[b(&c), i(0)]).bytes(), u);
    assert_eq!(ok(f, "convert_public_key", &[b(&u), i(1)]).bytes(), c);
    let x = ok(f, "x_only_public_key", &[b(&c)]).bytes();
    assert_eq!(&x[..], &c[1..]);
    let (_, c2, _) = secp_key(rng);
    assert_eq!(ok(f, "point_add", &[b(&c), b(&c2)]).bytes().len(), 33);
    let mut neg = c.clone();
    neg[0] ^= 1; // -P: P + (-P) is the point at infinity
    assert_eq!(ok(f, "point_add", &[b(&c), b(&neg)]), Value::Null);
    let t = rng.array::<32>().map(|v| v & 0x3f);
    assert_eq!(ok(f, "point_multiply", &[b(&c), b(t)]).bytes().len(), 33);
    assert_eq!(ok(f, "point_multiply", &[b(&c), b([0; 32])]), Value::Null);
    assert_eq!(ok(f, "base_multiply", &[b(sk)]).bytes(), c);
    assert_eq!(ok(f, "base_multiply", &[b([0; 32])]), Value::Null);
    assert_eq!(ok(f, "tweak_public_key", &[b(&c), b(t)]).bytes().len(), 33);
    assert_eq!(ok(f, "tweak_x_only_public_key", &[b(&x), b(t)]).bytes().len(), 33);
    assert_eq!(ok(f, "tweak_x_only_secret_key", &[b(sk), b(t)]).bytes().len(), 32);
    let h = rng.array::<32>();
    let sig = ok(f, "sign_prehash", &[b(sk), b(h)]).bytes();
    assert_eq!(ok(f, "verify_prehash", &[b(&c), b(h), b(&sig)]), Value::Bool(true));
    assert_eq!(ok(f, "normalize_signature", &[b(&sig)]).bytes(), sig, "RFC 6979 signatures here are low-S");
    let der = ok(f, "signature_to_der", &[b(&sig)]).bytes();
    assert_eq!(ok(f, "signature_from_der", &[b(&der)]).bytes(), sig);
    for msg in [rng.bytes(32), vec![], rng.bytes(100)] {
        let aux = rng.array::<32>();
        let s = ok(f, "schnorr_sign", &[b(sk), b(&msg), b(aux)]).bytes();
        assert_eq!(ok(f, "schnorr_verify", &[b(&x), b(&msg), b(&s)]), Value::Bool(true));
    }
}

#[cfg(feature = "p256")]
fn p256_family(rng: &mut Rng) {
    let f = "moxzi-p256";
    let mut sk = rng.array::<32>();
    sk[0] &= 0x7f;
    sk[31] |= 1;
    let c = ok(f, "derive_public_key", &[b(sk)]).bytes();
    let u = ok(f, "public_key", &[b(sk), i(0)]).bytes();
    assert_eq!(ok(f, "public_key", &[b(sk), i(1)]).bytes(), c);
    assert_eq!(ok(f, "convert_public_key", &[b(&c), i(0)]).bytes(), u);
    assert_eq!(ok(f, "convert_public_key", &[b(&u), i(1)]).bytes(), c);
    let h = rng.array::<32>();
    let sig = ok(f, "sign_prehash", &[b(sk), b(h)]).bytes();
    assert_eq!(ok(f, "verify_prehash", &[b(&u), b(h), b(&sig)]), Value::Bool(true));
    assert_eq!(ok(f, "normalize_signature", &[b(&sig)]).bytes().len(), 64);
    let der = ok(f, "signature_to_der", &[b(&sig)]).bytes();
    assert_eq!(ok(f, "signature_from_der", &[b(&der)]).bytes(), sig);
}

#[cfg(feature = "k256")]
fn ed25519_family(rng: &mut Rng) {
    let f = "moxzi-ed25519";
    let seed = rng.array::<32>();
    let pk = ok(f, "public_key", &[b(seed)]).bytes();
    for msg in [vec![], rng.bytes(100)] {
        let sig = ok(f, "sign", &[b(seed), b(&msg)]).bytes();
        assert_eq!(ok(f, "verify", &[b(&pk), b(&msg), b(&sig)]), Value::Bool(true));
    }
}

#[cfg(feature = "k256")]
fn ml_dsa_family(rng: &mut Rng) {
    let f = "moxzi-ml-dsa";
    let seed = rng.array::<32>();
    let pk = ok(f, "mldsa44_public_key", &[b(seed)]).bytes();
    let (msg, ctx) = (rng.bytes(50), rng.bytes(255));
    let sig = ok(f, "mldsa44_sign", &[b(seed), b(&msg), b(&ctx)]).bytes();
    assert_eq!(ok(f, "mldsa44_verify", &[b(&pk), b(&msg), b(&sig), b(&ctx)]), Value::Bool(true));
    let sig = ok(f, "mldsa44_sign_hedged", &[b(seed), b(&msg), b([]), b(rng.array::<32>())]).bytes();
    assert_eq!(ok(f, "mldsa44_verify", &[b(&pk), b(&msg), b(&sig), b([])]), Value::Bool(true));
}

#[cfg(feature = "k256")]
fn rsa_family(rng: &mut Rng) {
    let f = "moxzi-rsa";
    let der = include_bytes!("../../moxzi-rsa/check/keys/e65537.der");
    let (n, e) = rsa_public(der);
    let msg = rng.bytes(10);
    let digest = {
        use sha2::Digest;
        sha2::Sha256::digest(&msg).to_vec()
    };
    if cfg!(miri) {
        // One signature is ~20 minutes of Miri; moxzi-rsa/check signs (and verifies) under Miri
        // through the same export with an exact 384-byte buffer. Here: the early-out paths.
        let e_ = entry(f, "rsa_pss_sign");
        assert!(matches!(call(e_, &[b(der), b(&digest), b([0u8; 31])]), Err(Stop::Trap(_))));
        assert_eq!(ok(f, "rsa_pss_verify", &[b(&n), b(&e), b(&msg), b([0u8; 383])]), Value::Bool(false));
        assert_eq!(ok(f, "rsa_pss_verify_digest", &[b(&n), b(&e), b(&digest), b(&n)]), Value::Bool(false));
        return;
    }
    let sig = ok(f, "rsa_pss_sign", &[b(der), b(&digest), b(rng.array::<32>())]).bytes();
    assert_eq!(ok(f, "rsa_pss_verify", &[b(&n), b(&e), b(&msg), b(&sig)]), Value::Bool(true));
    assert_eq!(ok(f, "rsa_pss_verify_digest", &[b(&n), b(&e), b(&digest), b(&sig)]), Value::Bool(true));
}

#[cfg(feature = "k256")]
fn rsa_public(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::der::Decode;
    let info = rsa::pkcs8::PrivateKeyInfo::from_der(der).unwrap();
    let k = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
    (k.modulus.as_bytes().to_vec(), k.public_exponent.as_bytes().to_vec())
}

#[cfg(feature = "k256")]
fn bitcoin_family(rng: &mut Rng) {
    let f = "moxzi-bitcoin";
    let msg = rng.bytes(80);
    assert_eq!(ok(f, "hash_sha256d", &[b(&msg)]).bytes().len(), 32);
    assert_eq!(ok(f, "hash_hash160", &[b(&msg)]).bytes().len(), 20);
    assert_eq!(ok(f, "hash_tagged", &[b("TapLeaf"), b(&msg)]).bytes().len(), 32);
    let (_, c, u) = secp_key(rng);
    let x = c[1..].to_vec();
    let script = hex("76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac");
    for net in ["mainnet", "testnet", "regtest"] {
        let a = ok(f, "address_p2pkh", &[b(&u), b(net)]).text();
        assert_eq!(ok(f, "address_to_script", &[b(&a), b(net)]).bytes().len(), 25);
        ok(f, "address_p2wpkh", &[b(&c), b(net)]).text();
        ok(f, "address_p2sh", &[b(&script), b(net)]).text();
        ok(f, "address_p2wsh", &[b(&script), b(net)]).text();
        ok(f, "address_p2tr", &[b(&x), b([]), b(net)]).text();
        ok(f, "address_p2tr", &[b(&x), b(rng.array::<32>()), b(net)]).text();
    }
    assert_eq!(ok(f, "address_taproot_output_key", &[b(&x), b([])]).bytes().len(), 33);
    for (addr, script, chain) in btc::ADDRESSES {
        let net = match *chain {
            "main" => "mainnet",
            "regtest" => "regtest",
            _ => "testnet",
        };
        assert_eq!(ok(f, "address_to_script", &[b(addr), b(net)]).bytes(), hex(script), "{addr}");
        if !matches!(*chain, "main" | "regtest" | "test" | "testnet" | "signet" | "testnet4") {
            continue;
        }
        let back = ok(f, "address_from_script", &[b(hex(script)), b(net)]);
        assert!(matches!(back, Value::Bytes(_) | Value::Null));
    }
    let xpub = btc::BIP32_DERIVE[0].0;
    let payload = ok(f, "bip32_parse", &[b(xpub)]).bytes();
    assert_eq!(payload.len(), 78);
    assert_eq!(ok(f, "bip32_serialize", &[b(&payload)]).text(), xpub);
    for (parent, index, child) in btc::BIP32_DERIVE.iter().take(iters(3, 1)) {
        assert_eq!(ok(f, "bip32_derive_child", &[b(parent), i(*index)]).text(), *child);
    }
    ok(f, "bip32_derive_path", &[b(xpub), b("0/1")]).text();
    assert_eq!(ok(f, "bip32_fingerprint", &[b(&c)]).bytes().len(), 4);
    ok(f, "bip32_from_public_key", &[b(&c), b(rng.array::<32>()), b("mainnet")]).text();
    let (h20, h32) = (rng.bytes(20), rng.bytes(32));
    for (export, arg) in [("script_p2pkh", &h20), ("script_p2sh", &h20), ("script_p2wpkh", &h20), ("script_p2wsh", &h32), ("script_p2tr", &h32)] {
        ok(f, export, &[b(arg)]).bytes();
    }
    for n in [0usize, 1, 1, 1, 75, 76, 255, 256, 65535, 65536] {
        if cfg!(miri) && n > 300 {
            continue;
        }
        let d = match n {
            1 => vec![[0x81, 5, 0x20][rng.next() as usize % 3]],
            _ => rng.bytes(n),
        };
        ok(f, "script_push_data", &[b(&d)]).bytes();
    }
    ok(f, "script_tap_leaf_hash", &[b(&script), i(0xc0)]).bytes();
    ok(f, "script_tap_branch_hash", &[b(&h32), b(rng.array::<32>())]).bytes();
    for (tx, script, index, hash_type, want) in btc::SIGHASH_LEGACY.iter().take(iters(4, 1)) {
        let tx = hex(tx);
        assert_eq!(ok(f, "tx_is_valid", &[b(&tx)]), Value::Bool(true));
        ok(f, "tx_strip_witness", &[b(&tx)]).bytes();
        ok(f, "tx_txid", &[b(&tx)]).bytes();
        ok(f, "tx_wtxid", &[b(&tx)]).bytes();
        let mut got = ok(f, "tx_sighash_legacy", &[b(&tx), i(*index), b(hex(script)), i(*hash_type as i32 as u32 as u64)]).bytes();
        got.reverse();
        assert_eq!(got, hex(want));
    }
    for (tx, index, script, amount, hash_type, want) in btc::BIP143.iter().take(iters(3, 1)) {
        // The scriptCode as BIP143 prints it, as the PocketIC tests pass it.
        let got = ok(f, "tx_sighash_segwit_v0", &[b(hex(tx)), i(*index), b(hex(script)), i(*amount), i(*hash_type)]).bytes();
        assert_eq!(got, hex(want));
    }
    let mut prevouts = Vec::new();
    for (spk, amount) in btc::BIP341_UTXOS {
        let spk = hex(spk);
        prevouts.extend_from_slice(&amount.to_le_bytes());
        prevouts.push(spk.len() as u8);
        prevouts.extend_from_slice(&spk);
    }
    for (index, hash_type, want) in btc::BIP341_INPUTS.iter().take(iters(3, 1)) {
        let got = ok(f, "tx_sighash_taproot", &[b(hex(btc::BIP341_TX)), i(*index), b(&prevouts), i(*hash_type), b([]), b([]), i(0xffff_ffff)]).bytes();
        assert_eq!(got, hex(want));
    }
}

const ETH_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const ETH_POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[cfg(feature = "k256")]
/// BLS12-381. Pairings (every verify, pairingCheck, ic-agent's verify) cost ~10^9 Miri steps
/// each, so under Miri they get malformed points only (decoding fails before any pairing); the
/// valid calls run natively.
fn bls_family(rng: &mut Rng) {
    use bls12_381::{G1Affine, G2Affine};
    let f = "moxzi-bls12-381";
    let g1 = G1Affine::generator().to_compressed().to_vec();
    let g2 = G2Affine::generator().to_compressed().to_vec();
    let msg = rng.bytes(20);
    let h1 = ok(f, "bls_hash_to_g1", &[b(&msg), b(ETH_DST)]).bytes();
    let h2 = ok(f, "bls_hash_to_g2", &[b(&msg), b(ETH_DST)]).bytes();
    assert_eq!((h1.len(), h2.len()), (48, 96));
    let mut sk = rng.array::<32>();
    sk[0] &= 0x3f; // below r
    let pk = ok(f, "bls_g1_mul", &[b(&g1), b(sk)]).bytes();
    let sig = ok(f, "bls_g2_mul", &[b(&h2), b(sk)]).bytes();
    assert_eq!(ok(f, "bls_g1_validate", &[b(&pk)]), Value::Bool(true));
    assert_eq!(ok(f, "bls_g2_validate", &[b(&sig)]), Value::Bool(true));
    ok(f, "bls_g1_add", &[b(&pk), b(&h1)]).bytes();
    ok(f, "bls_g2_add", &[b(&sig), b(&h2)]).bytes();
    ok(f, "bls_g1_aggregate", &[b([&pk[..], &h1].concat())]).bytes();
    ok(f, "bls_g2_aggregate", &[b([&sig[..], &h2].concat())]).bytes();
    ok(f, "bls_g1_msm", &[b([&pk[..], &h1].concat()), b([sk, sk].concat())]).bytes();
    ok(f, "bls_g2_msm", &[b([&sig[..], &h2].concat()), b([sk, sk].concat())]).bytes();
    let mut u = [0u8; 96];
    u[47] = 7;
    u[95] = 9;
    ok(f, "bls_map_to_g1", &[b(&u[..48])]).bytes();
    ok(f, "bls_map_to_g2", &[b(u)]).bytes();
    ok(f, "bls_map_to_g2", &[b([0u8; 96])]).bytes(); // u = 0: the kernel's own special case
    if cfg!(miri) {
        let bad = vec![0x80u8; 96];
        assert_eq!(ok(f, "bls_eth_verify", &[b(&pk), b(&msg), b(&bad)]), Value::Bool(false));
        assert_eq!(ok(f, "bls_pairing_check", &[b([&g1[..], &bad].concat())]), Value::Bool(false));
        assert_eq!(ok("ic-agent-bls", "bls_verify", &[b(&g2), b(&g1[..47]), b(&msg), b(ETH_DST)]), Value::Bool(false));
        return;
    }
    assert_eq!(ok(f, "bls_eth_verify", &[b(&pk), b(&msg), b(&sig)]), Value::Bool(true));
    let pop = ok(f, "bls_g2_mul", &[b(ok(f, "bls_hash_to_g2", &[b(&pk), b(ETH_POP_DST)]).bytes()), b(sk)]).bytes();
    assert_eq!(ok(f, "bls_eth_pop_verify", &[b(&pk), b(&pop)]), Value::Bool(true));
    let digest = rng.array::<32>();
    let sig_d = ok(f, "bls_g2_mul", &[b(ok(f, "bls_hash_to_g2", &[b(digest), b(ETH_DST)]).bytes()), b(sk)]).bytes();
    assert_eq!(ok(f, "bls_eth_aggregate_verify", &[b(&pk), b(digest), b(&sig_d)]), Value::Bool(true));
    assert_eq!(ok(f, "bls_eth_fast_aggregate_verify", &[b(&pk), b(&msg), b(&sig)]), Value::Bool(true));
    let mut neg = g1.clone();
    neg[0] ^= 0x20; // the other y: -G1
    assert_eq!(ok(f, "bls_pairing_check", &[b([&g1[..], &g2, &neg, &g2].concat())]), Value::Bool(true));
    // ic-agent's kernel: G2 public key, G1 signature (minimal-signature-size).
    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let pk2 = ok(f, "bls_g2_mul", &[b(&g2), b(sk)]).bytes();
    let sig1 = ok(f, "bls_g1_mul", &[b(ok(f, "bls_hash_to_g1", &[b(&msg), b(dst)]).bytes()), b(sk)]).bytes();
    assert_eq!(ok("ic-agent-bls", "bls_verify", &[b(&pk2), b(&sig1), b(&msg), b(dst)]), Value::Bool(true));
}

/// BLS12-381 results checked for VALUE (bls_family only checks that the calls succeed): the
/// maps against py_ecc 8.0.0 (RFC 9380 reference, including u = 0, where bls12_381 0.8.0's own
/// G2 map is wrong), the Straus MSM against the sum of the crate's multiplications on edge
/// scalars and repeated points, and the bilinear pairing-product reduction against the product
/// of full pairings on terms built to cancel, repeat and merge.
#[cfg(feature = "k256")]
mod bls_values {
    use super::*;
    use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

    const F: &str = "moxzi-bls12-381";

    fn be(s: &Scalar) -> [u8; 32] {
        let mut b = s.to_bytes();
        b.reverse();
        b
    }

    /// py_ecc 8.0.0: compress(clear_cofactor(map_to_curve(u))), u = c0 + c1 i.
    #[test]
    #[cfg_attr(miri, ignore = "value vectors: native")]
    fn maps_match_py_ecc() {
        let g2 = [
            ((0u8, 0u8), "8a67d12118b5a35bb02d2e86b3ebfa7e23410db93de39fb06d7025fa95e96ffa428a7a27c3ae4dd4b40bd251ac658892018320896ec9eef9d5e619848dc29ce266f413d02dd31d9b9d44ec0c79cd61f18b075ddba6d7bd20b7ff27a4b324bfce"),
            ((0, 1), "a5d991fb690fdad1923ac1834188ed45d160a15ee5547a4476b836a158a9884236846408b8abd5d99217876d12f8f5d60f5ab9ab512bac0e5aa9d4be326afefbfa5db2dba6c88000f1cfeaa0cd62b2b2604935e2794933d76f9887bae7ed2851"),
            ((1, 0), "a0e12b55d801607d9760f8637ac80a4fececd3eb74045b342ee3c7dddd2037e72dedccc27e9a89491d4e57bde555fead1770d4f641225e1a1c0f7d05857299763e98e47ec6355b81dd6cdaf6db6825052f71d35ede3af8b70f046474c48d712e"),
            ((5, 0), "93ee20d424e46ed1c78ec37f89f61b3c83a6c6491df417e903139b6fd23d948bb0d19ebd87d0ac3697d69b3110e6af9501194a87cdefc974835aa52ae0c8538a90ca1dd4bd3a1623c6ab10b4d405191e4710cb668d58e8be433c6a10bc786969"),
            ((0, 5), "a9da735eda059d9bb98f03fde58f680fec29e7f6f1779448c35a34fa478a4cb7921e51d9730805c0e05053de188c18ba09e8a4936abf1b2ee876623249146e2bd5b9448e0a2f39daac15ad00b027dd3e16083e2de3b2e76c42951dc3fa6bd2f8"),
            ((1, 1), "8bb10e09bdf236cb2951bd7bcc044e1b9a6bb5fd4b2019dcc20ffde851d52d4f0d1a32382af9d7da2c5ba27e0f1c69e609bf1b857d8c15f317f649accfa7023ef21cfc03059936b83b487db476ff9d2fe64c6147140a5f0a436b875f51ffdf07"),
        ];
        for ((c0, c1), want) in g2 {
            let mut u = [0u8; 96];
            u[47] = c0;
            u[95] = c1;
            assert_eq!(ok(F, "bls_map_to_g2", &[b(u)]), Value::Bytes(hex(want)), "mapToG2({c0} + {c1} i)");
        }
        // Why the kernel special-cases u = 0: the unmodified crate maps it elsewhere.
        {
            use bls12_381::hash_to_curve::MapToCurve;
            let zero = <G2Projective as MapToCurve>::Field::default();
            let upstream = G2Affine::from(G2Projective::map_to_curve(&zero).clear_h()).to_compressed();
            assert_ne!(upstream.to_vec(), hex(g2[0].1), "bls12_381 fixed map_to_curve_g2(0): the special case can go");
        }
        let g1 = [
            (0u8, "91a9a0372b8f332d5c30de9ad14e50372a73fa4c45d5f2fa5097f2d6fb93bcac592f2e1711ac43db0519870c7d0ea415"),
            (1, "9073311196f8ef19477219ccee3a48035ff432295aa9419eed45d186027d88b90832e14c4f0e2aa4d15f54d1c3ed0f93"),
            (5, "a3a76914689fb401b446b4227e7b0d4d4872d8fc6d39e2b2b28fa19ef0eb6a0a13093e5654d4dc679d79e1a560e2d113"),
        ];
        for (c, want) in g1 {
            let mut u = [0u8; 48];
            u[47] = c;
            assert_eq!(ok(F, "bls_map_to_g1", &[b(u)]), Value::Bytes(hex(want)), "mapToG1({c})");
        }
    }

    fn edge_scalars(rng: &mut Rng) -> Vec<Scalar> {
        let mut v = vec![Scalar::zero(), Scalar::one(), -Scalar::one(), -Scalar::one().double(), Scalar::one().double()];
        let mut p = Scalar::one();
        for e in 0..255 {
            if matches!(e, 1 | 63 | 64 | 127 | 128 | 191 | 252 | 253 | 254) { v.push(p); v.push(-p); v.push(p - Scalar::one()); }
            p = p.double();
        }
        for _ in 0..6 { v.push(Scalar::from_bytes_wide(&{ let mut w = [0u8; 64]; w[..32].copy_from_slice(&rng.array::<32>()); w[32..].copy_from_slice(&rng.array::<32>()); w })) }
        v
    }

    #[test]
    #[cfg_attr(miri, ignore = "hundreds of scalar multiplications: native")]
    fn msm_is_the_sum_of_products() {
        let mut rng = Rng(0x5157);
        let ss = edge_scalars(&mut rng);
        let g = G1Projective::generator();
        let h = G2Projective::generator();
        let p1: Vec<G1Affine> = vec![G1Affine::from(g), G1Affine::from(g * ss[ss.len() - 1]), G1Affine::identity(), G1Affine::from(-g)];
        let p2: Vec<G2Affine> = vec![G2Affine::from(h), G2Affine::from(h * ss[ss.len() - 2]), G2Affine::identity(), G2Affine::from(-h)];
        let n = ss.len();
        let mut cases: Vec<Vec<(usize, Scalar)>> = Vec::new();
        for (i, s) in ss.iter().enumerate() {
            cases.push(vec![(i % 4, *s)]);
            cases.push(vec![(0, *s), (1, ss[(i * 7 + 3) % n]), (3, ss[(i * 5 + 1) % n])]);
            // The same point twice: scalars that cancel, that double, and a third repeat.
            cases.push(vec![(1, *s), (1, -*s)]);
            cases.push(vec![(1, *s), (2, ss[(i + 1) % n]), (1, *s), (1, ss[(i + 2) % n])]);
            // P and -P (different encodings).
            cases.push(vec![(0, *s), (3, *s)]);
        }
        cases.push(vec![]);
        for c in cases {
            let pts1: Vec<u8> = c.iter().flat_map(|(i, _)| p1[*i].to_compressed()).collect();
            let pts2: Vec<u8> = c.iter().flat_map(|(i, _)| p2[*i].to_compressed()).collect();
            let sc: Vec<u8> = c.iter().flat_map(|(_, s)| be(s)).collect();
            let want1 = c.iter().fold(G1Projective::identity(), |a, (i, s)| a + p1[*i] * s);
            let want2 = c.iter().fold(G2Projective::identity(), |a, (i, s)| a + p2[*i] * s);
            assert_eq!(ok(F, "bls_g1_msm", &[b(&pts1), b(&sc)]), Value::Bytes(G1Affine::from(want1).to_compressed().to_vec()), "g1Msm {c:?}");
            assert_eq!(ok(F, "bls_g2_msm", &[b(&pts2), b(&sc)]), Value::Bytes(G2Affine::from(want2).to_compressed().to_vec()), "g2Msm {c:?}");
        }
        // An invalid scalar (r) or point after a repeated valid one still refuses the whole call.
        let r_be = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        let gp = p1[0].to_compressed();
        assert_eq!(ok(F, "bls_g1_msm", &[b([gp, gp].concat()), b([be(&ss[1]).to_vec(), r_be.clone()].concat())]), Value::Null);
        let mut bad = gp;
        bad[47] ^= 1;
        assert_eq!(ok(F, "bls_g1_msm", &[b([gp, gp, bad].concat()), b([be(&ss[1]), be(&ss[2]), be(&ss[3])].concat())]), Value::Null);
    }

    #[test]
    #[cfg_attr(miri, ignore = "pairings: native")]
    fn pairing_product_reduction_keeps_the_value() {
        let mut rng = Rng(0x9a12);
        let rs = |rng: &mut Rng| Scalar::from_bytes_wide(&{ let mut w = [0u8; 64]; w[..32].copy_from_slice(&rng.array::<32>()); w });
        let g = G1Projective::generator();
        let h = G2Projective::generator();
        for round in 0..3 {
            let (a, bb, c) = (rs(&mut rng), rs(&mut rng), rs(&mut rng));
            let (pa, pb, pc) = (G1Affine::from(g * a), G1Affine::from(g * bb), G1Affine::from(g * c));
            let (qa, qb) = (G2Affine::from(h * a), G2Affine::from(h * bb));
            let (o1, o2) = (G1Affine::identity(), G2Affine::identity());
            let neg1 = |p: G1Affine| -p;
            let neg2 = |q: G2Affine| -q;
            let sets: Vec<Vec<(G1Affine, G2Affine)>> = vec![
                vec![(pa, qb), (neg1(pa), qb)],                          // cancel by Q
                vec![(pa, qb), (pa, neg2(qb))],                          // cancel by P
                vec![(pa, G2Affine::from(h)), (neg1(G1Affine::from(g)), qa)], // e(aG, H) = e(G, aH)
                vec![(pa, qb), (pb, qb), (pc, qb)],                      // three merge, no cancel
                vec![(pa, qb), (pb, qb), (neg1(G1Affine::from(g * (a + bb))), qb)], // three merge to O
                vec![(o1, qa), (pa, o2), (o1, o2)],                      // identities only
                vec![(pa, qa), (pa, qa)],                                // a repeated term
                vec![(pa, qa), (pb, qa), (pa, qb), (neg1(pa), qb)],      // merge in both stages
                vec![(pa, qa), (pb, qb), (pc, qa), (pc, qb)],            // P merge after Q merge
                vec![(pa, qa)],
                vec![],
            ];
            for (k, terms) in sets.iter().enumerate() {
                let want = terms.iter().fold(Gt::identity(), |acc, (p, q)| acc + pairing(p, q)) == Gt::identity();
                let bytes: Vec<u8> = terms.iter().flat_map(|(p, q)| [p.to_compressed().to_vec(), q.to_compressed().to_vec()].concat()).collect();
                assert_eq!(ok(F, "bls_pairing_check", &[b(&bytes)]), Value::Bool(want), "round {round} set {k}");
            }
        }
    }
}

macro_rules! family_test {
    ($name:ident, $f:ident, $native:expr) => {
        #[test]
        fn $name() {
            let mut rng = Rng(stringify!($name).len() as u64);
            for _ in 0..iters($native, 1) {
                $f(&mut rng);
            }
        }
    };
}
#[cfg(feature = "k256")]
mod every_family_but_p256 {
    use super::*;
    family_test!(valid_hash, hash_family, 5);
    family_test!(valid_base58, base58_family, 5);
    family_test!(valid_bech32, bech32_family, 5);
    family_test!(valid_secp256k1, secp256k1_family, 5);
    family_test!(valid_ed25519, ed25519_family, 5);
    family_test!(valid_ml_dsa, ml_dsa_family, 3);
    family_test!(valid_rsa, rsa_family, 2);
    family_test!(valid_bitcoin, bitcoin_family, 3);
    family_test!(valid_bls12_381, bls_family, 2);
}
#[cfg(feature = "p256")]
family_test!(valid_p256, p256_family, 5);

/// Every export appears in some valid-argument call above (so its success path, where the
/// result is written, ran) -- a new export without one fails here.
#[test]
#[cfg_attr(miri, ignore = "scans this file's text, not kernel code: native runs check it")]
fn every_export_has_a_valid_call() {
    let src = include_str!("check.rs");
    let body = &src[src.find("fn hash_family").unwrap()..src.find("macro_rules! family_test").unwrap()];
    let missing: Vec<_> = ENTRIES.iter().filter(|e| !body.contains(&format!("\"{}\"", e.export))).map(|e| format!("{} {}", e.family, e.export)).collect();
    assert!(missing.is_empty(), "exports without a valid-argument call: {missing:?}");
}
