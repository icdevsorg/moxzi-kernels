//! Instruction counts (wasmtime fuel) of the pinned moxzi-rsa kernel's `rsa_pss_sign`, see
//! Cargo.toml. usage: moxzi-rsa-fuel-probe [kernel.wasm | kernel.kernel.toml]
//!
//! Wasmtime fuel is not the IC's instruction weighting, but both count executed instructions, so a
//! secret-dependent difference here is a secret-dependent branch or loop bound in the kernel.
use anyhow::{anyhow, Result};
use num_bigint_dig::{BigUint, ModInverse, RandPrime};
use rand_chacha::rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use wasmtime::*;

const MEM_BASE: u64 = 0x10000;
const STACK_TOP: u64 = 0x100000;
const HEAP: u64 = 0x200000;
const K: usize = 384;

struct Kernel {
    engine: Engine,
    module: Module,
}

fn base64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for v in s.bytes().filter_map(val) {
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

impl Kernel {
    fn new(path: &str) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let wasm = if path.ends_with(".toml") {
            let t = String::from_utf8(bytes)?;
            let start = t.find("wasm = \"\"\"").ok_or_else(|| anyhow!("no wasm in {path}"))? + 10;
            let end = start + t[start..].find("\"\"\"").unwrap();
            base64(&t[start..end])
        } else {
            bytes
        };
        let mut cfg = Config::new();
        cfg.wasm_memory64(true);
        cfg.consume_fuel(true);
        let engine = Engine::new(&cfg).map_err(|e| anyhow!("{e}"))?;
        let module = Module::new(&engine, &wasm).map_err(|e| anyhow!("{e}"))?;
        Ok(Kernel { engine, module })
    }

    /// Calls export `name` with byte-slice arguments (each as ptr, len) and, when `out` > 0, an
    /// output buffer of `out` bytes. Returns the result (or the trap text) and the fuel used by
    /// the export call alone, in a fresh instance.
    fn call(&self, name: &str, args: &[&[u8]], out: usize) -> (std::result::Result<(i64, Vec<u8>), String>, u64) {
        let mut store = Store::new(&self.engine, HEAP);
        let mem = Memory::new(&mut store, MemoryType::new64(4096, None)).unwrap();
        let table = Table::new(&mut store, TableType::new64(RefType::FUNCREF, 17, None), Ref::Func(None)).unwrap();
        let sp = Global::new(&mut store, GlobalType::new(ValType::I64, Mutability::Var), Val::I64(STACK_TOP as i64)).unwrap();
        let mb = Global::new(&mut store, GlobalType::new(ValType::I64, Mutability::Const), Val::I64(MEM_BASE as i64)).unwrap();
        let tb = Global::new(&mut store, GlobalType::new(ValType::I64, Mutability::Const), Val::I64(0)).unwrap();
        let alloc = Func::wrap(&mut store, |mut c: Caller<'_, u64>, size: u64, align: u64| -> u64 {
            let a = align.max(1);
            let p = (*c.data() + a - 1) / a * a;
            *c.data_mut() = p + size;
            p
        });
        let trap = Func::wrap(&mut store, move |c: Caller<'_, u64>, p: u64, l: u64| -> wasmtime::Result<()> {
            let mut b = vec![0u8; l as usize];
            mem.read(&c, p as usize, &mut b).ok();
            Err(wasmtime::Error::msg(format!("trap: {}", String::from_utf8_lossy(&b))))
        });
        let mut linker = Linker::new(&self.engine);
        linker.define(&store, "env", "memory", mem).unwrap();
        linker.define(&store, "env", "__indirect_function_table", table).unwrap();
        linker.define(&store, "env", "__stack_pointer", sp).unwrap();
        linker.define(&store, "env", "__memory_base", mb).unwrap();
        linker.define(&store, "env", "__table_base", tb).unwrap();
        linker.define(&store, "env", "kernel_alloc", alloc).unwrap();
        linker.define(&store, "env", "kernel_trap", trap).unwrap();
        store.set_fuel(u64::MAX / 4).unwrap();
        let inst = linker.instantiate(&mut store, &self.module).unwrap();
        inst.get_typed_func::<(), ()>(&mut store, "__wasm_apply_data_relocs").unwrap().call(&mut store, ()).unwrap();
        let mut vals: Vec<Val> = Vec::new();
        for a in args {
            let p = *store.data();
            mem.write(&mut store, p as usize, a).unwrap();
            *store.data_mut() = (p + a.len() as u64 + 15) / 16 * 16 + 16;
            vals.push(Val::I64(p as i64));
            vals.push(Val::I64(a.len() as i64));
        }
        let outp = *store.data();
        if out > 0 {
            *store.data_mut() += out as u64 + 16;
            vals.push(Val::I64(outp as i64));
        }
        let f = inst.get_func(&mut store, name).unwrap();
        let mut res = vec![Val::I32(0); f.ty(&store).results().len()];
        let before = store.get_fuel().unwrap();
        let r = f.call(&mut store, &vals, &mut res);
        let used = before - store.get_fuel().unwrap();
        let r = match r {
            Ok(()) => {
                let mut o = vec![0u8; out];
                mem.read(&store, outp as usize, &mut o).unwrap();
                let ret = res.first().map(|v| match v { Val::I32(x) => *x as i64, Val::I64(x) => *x, _ => 0 }).unwrap_or(0);
                Ok((ret, o))
            }
            Err(e) => Err(format!("{e:#}")),
        };
        (r, used)
    }
}

fn one() -> BigUint { BigUint::from(1u32) }

fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut a, mut b) = (a.clone(), b.clone());
    while b != BigUint::from(0u32) {
        let t = &a % &b;
        a = b;
        b = t;
    }
    a
}

/// d = e^-1 mod lcm(p - 1, q - 1).
fn private_exponent(p: &BigUint, q: &BigUint, e: &BigUint) -> Option<BigUint> {
    let (p1, q1) = (p - one(), q - one());
    let lcm = &p1 * &q1 / gcd(&p1, &q1);
    e.clone().mod_inverse(&lcm)?.to_biguint()
}

/// PKCS#8 DER of the two-prime key (p, q, e), with optional replacement CRT exponents.
fn der(p: &BigUint, q: &BigUint, e: &BigUint, crt: Option<(BigUint, BigUint)>) -> Option<Vec<u8>> {
    let d = private_exponent(p, q, e)?;
    let (dp, dq) = crt.unwrap_or((&d % (p - one()), &d % (q - one())));
    let qinv = q.clone().mod_inverse(p)?.to_biguint()?;
    let parts = [p * q, e.clone(), d, p.clone(), q.clone(), dp, dq, qinv].map(|x| x.to_bytes_be());
    fn uint(b: &[u8]) -> rsa::pkcs1::UintRef<'_> { rsa::pkcs1::UintRef::new(b).unwrap() }
    let k = rsa::pkcs1::RsaPrivateKey {
        modulus: uint(&parts[0]),
        public_exponent: uint(&parts[1]),
        private_exponent: uint(&parts[2]),
        prime1: uint(&parts[3]),
        prime2: uint(&parts[4]),
        exponent1: uint(&parts[5]),
        exponent2: uint(&parts[6]),
        coefficient: uint(&parts[7]),
        other_prime_infos: None,
    };
    use rsa::pkcs8::der::Encode;
    let inner = k.to_der().unwrap();
    Some(rsa::pkcs8::PrivateKeyInfo::new(rsa::pkcs1::ALGORITHM_ID, &inner).to_der().unwrap())
}

/// The DER shape of the secret fields: byte length, `+` when the top bit is set (DER then
/// prefixes 0x00).
fn shape(p: &BigUint, q: &BigUint, e: &BigUint) -> String {
    let d = private_exponent(p, q, e).unwrap();
    let f = |x: &BigUint| {
        let b = x.to_bytes_be();
        format!("{}{}", b.len(), if b[0] >= 0x80 { "+" } else { "" })
    };
    let qinv = q.clone().mod_inverse(p).unwrap().to_biguint().unwrap();
    format!("d={} dp={} dq={} qi={}", f(&d), f(&(&d % (p - one()))), f(&(&d % (q - one()))), f(&qinv))
}

/// sign's count minus verifyDigest's count on its own signature: the private part. None when the
/// signature has a leading zero byte: sign then does less public work on s (its BigUint is
/// shorter), a difference in PUBLIC data that this subtraction does not cancel.
fn private_part(k: &Kernel, der: &[u8], n: &BigUint, e: &BigUint, digest: &[u8], salt: &[u8]) -> Option<i128> {
    let (r, fs) = k.call("rsa_pss_sign", &[der, digest, salt], K);
    let (_, sig) = r.unwrap_or_else(|t| panic!("sign trapped: {t}"));
    let mut nb = n.to_bytes_be();
    while nb.len() < K {
        nb.insert(0, 0);
    }
    let (r, fv) = k.call("rsa_pss_verify_digest", &[&nb, &e.to_bytes_be(), digest, &sig], 0);
    assert_eq!(r.unwrap().0, 1, "the kernel verifies its own signature");
    (sig[0] != 0).then_some(fs as i128 - fv as i128)
}

fn main() -> Result<()> {
    let default = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kernel/moxzi-rsa.kernel.toml");
    let path = std::env::args().nth(1).unwrap_or(default.to_string());
    let k = Kernel::new(&path)?;
    let digest = Sha256::digest(b"fuel probe").to_vec();
    let salt = [7u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x5eed);
    let f4 = BigUint::from(65537u32);
    let (p, q) = loop {
        let (a, b): (BigUint, BigUint) = (rng.gen_prime(1536), rng.gen_prime(1536));
        if (&a * &b).bits() == 3072 && a != b {
            break if a > b { (a, b) } else { (b, a) };
        }
    };
    let n = &p * &q;
    let mut findings = 0;

    // 1. The constant-time path, one key, six messages: must be one count (control).
    let dk = der(&p, &q, &f4, None).unwrap();
    let per_msg: BTreeSet<i128> = (0..6u8).filter_map(|i| private_part(&k, &dk, &n, &f4, &Sha256::digest([i]), &[i; 32])).collect();
    println!("CT path, one key, 6 messages: private parts {per_msg:?}");
    assert_eq!(per_msg.len(), 1, "control: the constant-time path varies with the message");

    // 2. The same primes (so the same n) with different 3-byte public exponents: d, dp and dq
    //    change, and so does their DER shape. The private part must not depend on the secret.
    let mut by_shape: BTreeMap<String, BTreeSet<i128>> = BTreeMap::new();
    let mut e = f4.clone();
    for _ in 0..4000 {
        e += 2u32;
        let Some(dk) = der(&p, &q, &e, None) else { continue };
        let s = shape(&p, &q, &e);
        let set = by_shape.entry(s).or_default();
        if set.len() >= 2 {
            continue;
        }
        if let Some(pp) = private_part(&k, &dk, &n, &e, &digest, &salt) {
            set.insert(pp);
        }
        if by_shape.len() >= 10 && by_shape.values().all(|v| !v.is_empty()) {
            break;
        }
    }
    let all: BTreeSet<i128> = by_shape.values().flatten().copied().collect();
    for (s, v) in &by_shape {
        println!("same n, secret shape [{s}]: private part {v:?}");
    }
    if all.len() > 1 {
        findings += 1;
        println!("FINDING: sign's private part depends on the DER shape of d/dp/dq ({} distinct counts, spread {})", all.len(), all.last().unwrap() - all.first().unwrap());
    }

    // 3. Unreduced CRT exponents (dp + 2(p - 1), dq + 2(q - 1); PKCS#1 accepts them): until
    //    2026-10-24 the BigUint fallback, variable time in the secret primes (this probe's finding,
    //    in review). Such keys are refused now: sign must trap with the shape message.
    let d = private_exponent(&p, &q, &f4).unwrap();
    let (p1, q1) = (&p - one(), &q - one());
    let dk = der(&p, &q, &f4, Some((&d % &p1 + &p1 * 2u32, &d % &q1 + &q1 * 2u32))).unwrap();
    match k.call("rsa_pss_sign", &[&dk, &digest, &salt], K).0 {
        Err(t) if t.contains("key shape not supported") => println!("unreduced dp, dq: refused ({t})"),
        other => {
            findings += 1;
            println!("FINDING: a key with unreduced CRT exponents was not refused: {other:?}");
        }
    }
    std::process::exit(if findings > 0 { 1 } else { 0 });
}
