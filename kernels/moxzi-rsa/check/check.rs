//! The RSA kernel, natively and under Miri:
//!  - ../rust/src/mont.rs (raw-pointer CIOS multiplication, the conditional subtraction,
//!    conversion to and from Montgomery form, both exponentiations) against num-bigint -- an
//!    implementation independent of rsa's num-bigint-dig -- for every modulus size the code
//!    accepts (N = 8, 16, ..., 96 limbs; the kernel uses 96 for n and 48 for the primes), on
//!    edge moduli and operands and random ones;
//!  - the kernel's exports (../rust/src/lib.rs, rewritten into this crate by build.rs), called
//!    as the glue calls them (payload pointers, a 384-byte result buffer of exactly that size),
//!    against the rsa crate's PSS verification, an RFC 8017 signature computed here without the
//!    CRT, and the Wycheproof RSA-PSS 3072 vectors.
#![cfg(test)]
#[path = "../../moxzi-kernel/check/native.rs"]
#[allow(dead_code)]
mod native;
#[path = "../rust/src/mont.rs"]
mod mont;
#[allow(dead_code)]
mod moxzi_kernel {
    include!(concat!(env!("OUT_DIR"), "/moxzi-kernel/lib.rs"));
}
#[allow(dead_code)]
mod k_rsa {
    include!(concat!(env!("OUT_DIR"), "/k_rsa/lib.rs"));
}
mod wycheproof {
    include!(concat!(env!("OUT_DIR"), "/wycheproof.rs"));
}

use mont::Modulus;
use native::{free_scratch, iters, run, OutBuf, Rng, Stop};
use num_bigint::BigUint as Big;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn one() -> Big { Big::from(1u8) }
fn pow2(k: usize) -> Big { one() << k }
fn big<const N: usize>(x: &[u32; N]) -> Big { Big::from_slice(x) }
fn limbs<const N: usize>(x: &Big) -> [u32; N] {
    let d = x.to_u32_digits();
    assert!(d.len() <= N, "{} limbs do not fit in {N}", d.len());
    let mut a = [0u32; N];
    a[..d.len()].copy_from_slice(&d);
    a
}
/// Exactly `len` big-endian bytes.
fn be(x: &Big, len: usize) -> Vec<u8> {
    let b = x.to_bytes_be();
    let b = if b == [0] { vec![] } else { b };
    assert!(b.len() <= len);
    let mut v = vec![0u8; len - b.len()];
    v.extend(b);
    v
}

// ---- mont.rs ----------------------------------------------------------------------------------

/// Moduli that stress the code (all odd, R/2 <= n < R): both ends of the range, the extremes of
/// n0 = -n^-1 mod 2^32 (n[0] = 1 gives n0 = 2^32 - 1, n[0] = 2^32 - 1 gives n0 = 1), top limbs
/// that make the quotient estimate of `to_mont_vartime` overshoot, repeating patterns; then
/// random ones.
fn moduli<const N: usize>(rng: &mut Rng, random: usize) -> Vec<Big> {
    let r = pow2(32 * N);
    let half = pow2(32 * N - 1);
    let mut v = vec![
        &r - 1u8,
        &half + 1u8,
        &half + 3u8,
        &half + pow2(32) - 1u8,
        &half + pow2(32 * N - 2) + 1u8,
        &r - pow2(32) + 1u8,
        &half + pow2(32 * (N - 1)) - 1u8,
        &half + 0xffff_ffffu32,
        &r - pow2(32 * N - 33) + 1u8,
        Big::from_slice(&[0xaaaa_aaabu32; N]),
        Big::from_slice(&[0x5555_5555u32; N]) | &half,
    ];
    for _ in 0..random {
        v.push(Big::from_bytes_le(&rng.bytes(4 * N)) | &half | one());
    }
    for n in &v {
        assert!(n.bit(0) && n.bits() == (32 * N) as u64, "bad test modulus {n:x}");
    }
    // Under Miri every shape above runs at N = 8; the kernel's sizes (48, 96 limbs: the same
    // code with every unrolled block live) get the two ends of the range, n0 = 2^32 - 1, and
    // the random ones.
    if cfg!(miri) && N > 8 {
        let random = v.split_off(11);
        v = vec![v[0].clone(), v[1].clone(), v[5].clone()];
        v.extend(random);
    }
    v
}

/// Operands below n: 0, 1, 2, n - 1, n - 2, around n/2, R mod n, R^2 mod n, R - 1 mod n,
/// numbers whose low limbs are all ones, powers of two at limb boundaries; then random ones.
fn operands<const N: usize>(n: &Big, rng: &mut Rng, random: usize) -> Vec<Big> {
    let r = pow2(32 * N);
    let mut v = vec![Big::from(0u8), one(), Big::from(2u8), n - 1u8, n - 2u8, n >> 1, (n >> 1) + 1u8, &r % n, (&r * &r) % n, (&r - 1u8) % n];
    let ks: Vec<usize> = if cfg!(miri) { vec![1, N / 2, N - 1] } else { vec![1, 2, 3, N / 2, N - 3, N - 2, N - 1] };
    for k in ks {
        v.push(pow2(32 * k) - 1u8); // k all-ones limbs
        v.push(pow2(32 * k) % n);
    }
    for k in [31, 32, 33, 32 * N - 2] {
        v.push(pow2(k) % n);
    }
    for _ in 0..random {
        v.push(Big::from_bytes_le(&rng.bytes(4 * N)) % n);
    }
    // Under Miri all of the above at N = 8; at the kernel's sizes (where num-bigint's 3072-bit
    // reference divisions cost more Miri time than the code under test) 0, 1, n - 1, R mod n,
    // R - 1 mod n, N - 1 all-ones limbs, and the random ones.
    if cfg!(miri) && N > 8 {
        let all_ones = v[10 + 2 * 2].clone(); // ks = [1, N / 2, N - 1]: 2^(32 (N - 1)) - 1
        let random = v.split_off(v.len() - random);
        v = vec![v[0].clone(), v[1].clone(), v[3].clone(), v[7].clone(), v[9].clone(), all_ones];
        v.extend(random);
    }
    v
}

fn modulus<const N: usize>(n: &Big) -> Modulus<N> {
    Modulus::<N>::from_be(&be(n, 4 * N)).expect("an odd modulus with its top bit set")
}

fn check_mul<const N: usize>() {
    let mut rng = Rng(N as u64);
    let r = pow2(32 * N);
    for n in moduli::<N>(&mut rng, iters(6, 1)) {
        let m = modulus::<N>(&n);
        let xs = operands::<N>(&n, &mut rng, iters(8, 2));
        // Natively every pair; under Miri every operand against a few partners at N = 8, and
        // squared at the kernel's sizes (Miri runs ~5,000 limb steps a second here, measured
        // 2026-10-23: one 96-limb product is ~4 s, one RSA-3072 signature ~25 min).
        let pairs: Vec<(usize, usize)> = if cfg!(miri) && N > 8 {
            (0..xs.len()).map(|i| (i, i)).collect()
        } else if cfg!(miri) {
            (0..xs.len()).flat_map(|i| [(i, i), (i, 3), (i, xs.len() - 1)]).collect()
        } else {
            (0..xs.len()).flat_map(|i| (0..xs.len()).map(move |j| (i, j))).collect()
        };
        for (i, j) in pairs {
            let (a, b) = (&xs[i], &xs[j]);
            let c = big(&m.mul(&limbs::<N>(a), &limbs::<N>(b)));
            assert!(c < n, "N={N} mul not reduced: n={n:x} a={a:x} b={b:x}");
            assert_eq!((&c * &r) % &n, (a * b) % &n, "N={N} mul: n={n:x} a={a:x} b={b:x}");
        }
    }
}

fn check_conversions<const N: usize>() {
    let mut rng = Rng(100 + N as u64);
    let r = pow2(32 * N);
    for n in moduli::<N>(&mut rng, iters(6, 1)) {
        let m = modulus::<N>(&n);
        assert_eq!(big(&m.one_mont()), &r % &n, "N={N} one_mont n={n:x}");
        for x in operands::<N>(&n, &mut rng, iters(8, 2)) {
            let xm = big(&m.to_mont_vartime(&limbs::<N>(&x)));
            assert_eq!(xm, (&x * &r) % &n, "N={N} to_mont n={n:x} x={x:x}");
            let back = big(&m.from_mont(&limbs::<N>(&x)));
            assert!(back < n);
            assert_eq!((&back * &r) % &n, x, "N={N} from_mont n={n:x} x={x:x}");
        }
    }
}

fn check_pow_public<const N: usize>() {
    let mut rng = Rng(200 + N as u64);
    let mut exps: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0, 0], vec![1], vec![2], vec![3], vec![0, 3], vec![1, 0, 1], vec![0xff; 4], vec![0x80, 0, 0, 0, 0]];
    for _ in 0..iters(10, 1) {
        let len = 1 + (rng.next() % 16) as usize;
        exps.push(rng.bytes(len));
    }
    let ms = moduli::<N>(&mut rng, iters(2, 0));
    let take = if cfg!(miri) && N > 8 { 1 } else { ms.len() };
    for n in ms.into_iter().take(take) {
        let m = modulus::<N>(&n);
        let xs = operands::<N>(&n, &mut rng, iters(4, 1));
        for (i, e) in exps.iter().enumerate() {
            // Under Miri every exponent runs at N = 8 (the bit loop is the same at every N); at
            // N = 48 e = 0 bytes, 3 and 65537 on one modulus (N = 96 runs in every Wycheproof
            // verification).
            if cfg!(miri) && N > 8 && !(e.is_empty() || e[..] == [3u8] || e[..] == [1u8, 0, 1]) {
                continue;
            }
            // Natively every operand meets the short exponents and a quarter of them the long
            // ones; under Miri 65537 meets the edge operands at N = 8, every other exponent one.
            let picks: Vec<&Big> = if (e[..] == [1u8, 0, 1] && !cfg!(miri)) || (!cfg!(miri) && e.len() <= 3) {
                xs.iter().collect()
            } else if cfg!(miri) && e[..] == [1u8, 0, 1] && N == 8 {
                xs.iter().take(6).collect()
            } else if cfg!(miri) {
                vec![&xs[i % xs.len()]]
            } else {
                xs.iter().skip(i % 4).step_by(4).collect()
            };
            for x in picks {
                let got = big(&m.pow_public(&limbs::<N>(x), e));
                assert_eq!(got, x.modpow(&Big::from_bytes_be(e), &n), "N={N} pow_public n={n:x} x={x:x} e={e:02x?}");
            }
        }
    }
}

fn check_pow_secret<const N: usize>() {
    let mut rng = Rng(300 + N as u64);
    let r = pow2(32 * N);
    let mut exps: Vec<Big> = vec![Big::from(0u8), one(), Big::from(2u8), Big::from(31u8), Big::from(32u8), Big::from(33u8), &r - 1u8, pow2(32 * N - 1), pow2(5 * (32 * N / 5)) - 1u8];
    for _ in 0..iters(4, 1) {
        exps.push(Big::from_bytes_le(&rng.bytes(4 * N)));
    }
    // pow_secret costs ~6.4 N limb-row multiplications of N^2 each: natively every edge modulus
    // up to 48 limbs (the kernel's size), the first four above; under Miri every edge modulus
    // and exponent at N = 8, and at N = 48 one modulus with the zero and all-ones exponents.
    let ms = moduli::<N>(&mut rng, iters(1, 0));
    let take = if cfg!(miri) && N > 8 { 1 } else if N <= 48 { ms.len() } else { 4 };
    for (mi, n) in ms.into_iter().take(take).enumerate() {
        let m = modulus::<N>(&n);
        let one_m = m.one_mont();
        let xs = operands::<N>(&n, &mut rng, iters(2, 0));
        for (i, e) in exps.iter().enumerate() {
            // Under Miri: every exponent on the first modulus, zero and all-ones on the others.
            if cfg!(miri) && mi > 0 && !matches!(i, 0 | 6) {
                continue;
            }
            let picks: Vec<&Big> = if cfg!(miri) { vec![&xs[i % xs.len()]] } else { vec![&xs[i % xs.len()], &xs[(i * 7 + 3) % xs.len()]] };
            for x in picks {
                let xm = limbs::<N>(&((x * &r) % &n));
                let got = big(&m.pow_secret(&xm, &limbs::<N>(e), &one_m));
                assert_eq!(got, x.modpow(e, &n), "N={N} pow_secret n={n:x} x={x:x} e={e:x}");
            }
        }
    }
}

/// The helpers `rsasp1_ct` is built from (reduce, add, sub, r2, to_mont_wide), which the sign
/// tests reach only end to end, against num-bigint directly; and `mul` with its second operand
/// in [n, R) (a key's qInv is not checked to be below p), where the result must still be
/// a b / R mod n, reduced.
fn check_crt_helpers<const N: usize>() {
    let mut rng = Rng(500 + N as u64);
    let r = pow2(32 * N);
    for n in moduli::<N>(&mut rng, iters(4, 1)) {
        let m = modulus::<N>(&n);
        assert_eq!(big(&m.r2()), (&r * &r) % &n, "N={N} r2 n={n:x}");
        let xs = operands::<N>(&n, &mut rng, iters(4, 1));
        // Numbers in [n, R): every x < R is < 2n here.
        let wide: Vec<Big> = [&r - 1u8, n.clone(), &n + 1u8, &r - 2u8].into_iter().chain(xs.iter().map(|x| (&n + x) % &r)).filter(|x| *x >= n && *x < r).collect();
        for (i, a) in xs.iter().enumerate() {
            let b = &xs[(i * 7 + 3) % xs.len()];
            assert_eq!(big(&m.add(&limbs::<N>(a), &limbs::<N>(b))), (a + b) % &n, "N={N} add");
            assert_eq!(big(&m.sub(&limbs::<N>(a), &limbs::<N>(b))), (a + &n - b) % &n, "N={N} sub");
            assert_eq!(big(&m.sub(&limbs::<N>(a), &limbs::<N>(a))), Big::from(0u8), "N={N} sub self");
            for w in &wide {
                assert_eq!(big(&m.reduce(&limbs::<N>(w))), w % &n, "N={N} reduce n={n:x} w={w:x}");
                let c = big(&m.mul(&limbs::<N>(a), &limbs::<N>(w)));
                assert!(c < n, "N={N} mul(a < n, b in [n, R)) not reduced: n={n:x} a={a:x} b={w:x}");
                assert_eq!((&c * &r) % &n, (a * w) % &n, "N={N} mul(a < n, b in [n, R))");
                let (lo, hi) = (limbs::<N>(w), limbs::<N>(a));
                let want = ((a * &r + w) * &r) % &n;
                assert_eq!(big(&m.to_mont_wide(&lo, &hi)), want, "N={N} to_mont_wide");
                assert_eq!(big(&m.to_mont_wide(&hi, &lo)), ((w * &r + a) * &r) % &n, "N={N} to_mont_wide (hi >= n)");
            }
        }
    }
}

fn check_encoding<const N: usize>() {
    let mut rng = Rng(400 + N as u64);
    for _ in 0..iters(50, 3) {
        let b = rng.bytes(4 * N);
        let x = mont::from_be::<N>(&b).unwrap();
        assert_eq!(big(&x), Big::from_bytes_be(&b));
        let mut back = vec![0u8; 4 * N];
        mont::to_be(&x, &mut back);
        assert_eq!(back, b);
    }
    assert!(mont::from_be::<N>(&vec![0u8; 4 * N - 1]).is_none());
    assert!(mont::from_be::<N>(&vec![0u8; 4 * N + 1]).is_none());
    // Modulus::from_be: odd with the top bit set, exactly 4N bytes.
    let half = pow2(32 * N - 1);
    assert!(Modulus::<N>::from_be(&be(&(&half + 1u8), 4 * N)).is_some());
    assert!(Modulus::<N>::from_be(&be(&(&half + 2u8), 4 * N)).is_none(), "even");
    assert!(Modulus::<N>::from_be(&be(&(&half - 1u8), 4 * N)).is_none(), "top bit clear");
    assert!(Modulus::<N>::from_be(&be(&(&half + 1u8), 4 * N + 1)).is_none(), "length");
    // less_than against num-bigint on neighbours.
    let n = &half + 12345u32;
    let near = [&n - 1u8, n.clone(), &n + 1u8, Big::from(0u8), pow2(32 * N) - 1u8, &n ^ pow2(32 * (N / 2))];
    for a in &near {
        for b in &near {
            assert_eq!(mont::less_than(&limbs::<N>(a), &limbs::<N>(b)), a < b);
        }
    }
}

macro_rules! for_each_n {
    ($f:ident) => {{
        // The kernel's two sizes always, the smallest for the most cases; every size natively.
        $f::<8>();
        $f::<48>();
        $f::<96>();
        if !cfg!(miri) {
            $f::<16>(); $f::<24>(); $f::<32>(); $f::<40>(); $f::<56>(); $f::<64>(); $f::<72>(); $f::<80>(); $f::<88>();
        }
    }};
}

#[test]
fn mont_mul() { for_each_n!(check_mul) }
#[test]
fn mont_conversions() { for_each_n!(check_conversions) }
#[test]
fn mont_pow_public() {
    if cfg!(miri) {
        // N = 96 under Miri: through rsa_pss_verify in wycheproof_rsa_pss_3072.
        check_pow_public::<8>();
        check_pow_public::<48>();
    } else {
        for_each_n!(check_pow_public)
    }
}
/// Found in adversarial review, 2026-10-24: a public exponent can be any length, and pow_public
/// walked its leading zero bytes bit by bit -- 2 MB of zeros before 65537 cost ~80 M instructions
/// per verification instead of ~4.6 M. It now skips them (mont::significant). The cost bound:
/// the bit loop walks exactly the significant bytes (counted by mont::POW_PUBLIC_BYTES) however
/// many zeros lead; the results are those of the minimal exponent and of num-bigint.
fn check_pow_public_leading_zeros<const N: usize>() {
    let mut rng = Rng(400 + N as u64);
    let n = moduli::<N>(&mut rng, 1).pop().unwrap();
    let m = modulus::<N>(&n);
    let xs = operands::<N>(&n, &mut rng, 1);
    let zeros = if cfg!(miri) { 4096 } else { 2 << 20 };
    let exps = [vec![], vec![0u8], vec![1], vec![3], vec![1, 0, 1], vec![0x80, 0, 0, 0, 1], rng.bytes(7)];
    for e in &exps {
        let significant = mont::significant(e);
        assert!(significant.is_empty() || significant[0] != 0, "e={e:02x?}");
        assert_eq!(Big::from_bytes_be(significant), Big::from_bytes_be(e), "e={e:02x?}");
        for lead in [0usize, 1, 7, 8, 9, 15, 16, 17, zeros] {
            let mut long = vec![0u8; lead];
            long.extend_from_slice(e);
            assert_eq!(mont::significant(&long), significant, "{lead} zeros, e={e:02x?}");
            for x in xs.iter().take(3) {
                let x = limbs::<N>(x);
                let before = mont::POW_PUBLIC_BYTES.with(|c| c.get());
                let got = m.pow_public(&x, &long);
                let walked = mont::POW_PUBLIC_BYTES.with(|c| c.get()) - before;
                assert_eq!(walked, significant.len(), "N={N} {lead} zeros, e={e:02x?}: bytes walked");
                assert_eq!(got, m.pow_public(&x, e), "N={N} {lead} zeros, e={e:02x?}");
                assert_eq!(big(&got), big(&x).modpow(&Big::from_bytes_be(e), &n), "N={N} {lead} zeros, e={e:02x?}");
            }
        }
    }
}

#[test]
fn mont_pow_public_leading_zeros() {
    check_pow_public_leading_zeros::<8>();
    if !cfg!(miri) {
        check_pow_public_leading_zeros::<96>();
    }
}

#[test]
fn mont_pow_secret() {
    // pow_secret costs ~6.4 N rows of N^2 limb products whatever the exponent (constant time),
    // and num-bigint's reference with a 1536-bit exponent costs more again: under Miri every
    // edge case at N = 8 here, and the kernel's N = 48 through sign_is_rfc8017 (two calls).
    if cfg!(miri) {
        check_pow_secret::<8>();
    } else {
        for_each_n!(check_pow_secret)
    }
}
#[test]
fn mont_encoding() { for_each_n!(check_encoding) }
#[test]
fn mont_crt_helpers() {
    if cfg!(miri) {
        check_crt_helpers::<8>();
    } else {
        for_each_n!(check_crt_helpers)
    }
}

// ---- the exports ------------------------------------------------------------------------------

const K: usize = 384;

/// A test key's parts (from keys/*.der, written by `write_keys`).
struct Key {
    der: Vec<u8>,
    n: Big,
    e: Big,
    d: Big,
}

fn load(name: &str) -> Key {
    let der = match name {
        "e65537" => include_bytes!("keys/e65537.der").to_vec(),
        "e3" => include_bytes!("keys/e3.der").to_vec(),
        "swapped" => include_bytes!("keys/swapped.der").to_vec(),
        "unbalanced" => include_bytes!("keys/unbalanced.der").to_vec(),
        "unreduced" => include_bytes!("keys/unreduced.der").to_vec(),
        "inconsistent" => include_bytes!("keys/inconsistent.der").to_vec(),
        "rsa2048" => include_bytes!("keys/rsa2048.der").to_vec(),
        _ => panic!("{name}"),
    };
    use rsa::pkcs8::der::Decode;
    let info = rsa::pkcs8::PrivateKeyInfo::from_der(&der).unwrap();
    let k = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
    let u = |x: rsa::pkcs1::UintRef<'_>| Big::from_bytes_be(x.as_bytes());
    Key { n: u(k.modulus), e: u(k.public_exponent), d: u(k.private_exponent), der }
}

/// The keys the kernel signs with: two-prime 3072-bit keys with 1536-bit primes and CRT
/// parameters below 2^1536 (e = 65537, e = 3, and p < q).
const SIGNING_KEYS: [&str; 3] = ["e65537", "e3", "swapped"];
/// Well-formed, consistent keys of the shapes the kernel refuses since 2026-10-24 (until then
/// signed by a variable-time BigUint fallback): a 1535/1537-bit prime split, and CRT exponents
/// >= 2^1536.
const REFUSED_KEYS: [&str; 2] = ["unbalanced", "unreduced"];
const UNSUPPORTED: &str = "Rsa3072.sign: key shape not supported (primes must be exactly 1536 bits and the CRT parameters reduced)";

/// EMSA-PSS-ENCODE (RFC 8017 9.1.1) for emBits = 3071, SHA-256, MGF1-SHA-256, written here from
/// the RFC (not from lib.rs).
fn emsa_pss_encode(m_hash: &[u8], salt: &[u8]) -> Vec<u8> {
    let em_len = K;
    let h_len = 32;
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let h = Sha256::digest(&m_prime).to_vec();
    let ps_len = em_len - salt.len() - h_len - 2;
    let mut db = vec![0u8; ps_len];
    db.push(1);
    db.extend_from_slice(salt);
    let mut mask = Vec::new();
    let mut counter = 0u32;
    while mask.len() < db.len() {
        mask.extend_from_slice(&Sha256::new().chain_update(&h).chain_update(counter.to_be_bytes()).finalize());
        counter += 1;
    }
    let mut masked: Vec<u8> = db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    masked[0] &= 0x7f; // 8 emLen - emBits = 1 bit
    let mut em = masked;
    em.extend_from_slice(&h);
    em.push(0xbc);
    em
}

/// RSASP1 without the CRT: em^d mod n.
fn sign_reference(key: &Key, digest: &[u8], salt: &[u8]) -> Vec<u8> {
    be(&Big::from_bytes_be(&emsa_pss_encode(digest, salt)).modpow(&key.d, &key.n), K)
}

/// The kernel's contract for verify: n exactly 384 bytes with its top bit set, a key the rsa
/// crate accepts, and RSASSA-PSS-VERIFY with a 32-byte salt.
fn verify_reference(n: &[u8], e: &[u8], digest: &[u8], sig: &[u8]) -> bool {
    if n.len() != K || n[0] & 0x80 == 0 || digest.len() != 32 {
        return false;
    }
    let Ok(key) = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(n), rsa::BigUint::from_bytes_be(e)) else { return false };
    key.verify(rsa::Pss::new_with_salt::<Sha256>(32), digest, sig).is_ok()
}

/// The exports, called as the glue calls them: payload pointers of shared borrows (under Miri a
/// write through one is reported), a result buffer of exactly 384 bytes, and the inputs
/// compared afterwards.
fn sign(der: &[u8], digest: &[u8], salt: &[u8]) -> Result<Vec<u8>, Stop> {
    let before = (der.to_vec(), digest.to_vec(), salt.to_vec());
    let mut out = OutBuf::new(K);
    let p = out.ptr();
    let r = run(|| unsafe { k_rsa::rsa_pss_sign(der.as_ptr(), der.len(), digest.as_ptr(), digest.len(), salt.as_ptr(), salt.len(), p) });
    free_scratch();
    assert!(before == (der.to_vec(), digest.to_vec(), salt.to_vec()), "sign wrote an input");
    r.map(|()| out.bytes().to_vec())
}

fn verify(n: &[u8], e: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let before = [n.to_vec(), e.to_vec(), msg.to_vec(), sig.to_vec()];
    let r = run(|| unsafe { k_rsa::rsa_pss_verify(n.as_ptr(), n.len(), e.as_ptr(), e.len(), msg.as_ptr(), msg.len(), sig.as_ptr(), sig.len()) });
    free_scratch();
    assert!(before == [n.to_vec(), e.to_vec(), msg.to_vec(), sig.to_vec()], "verify wrote an input");
    let r = r.unwrap_or_else(|s| panic!("verify stopped: {s:?}"));
    assert!(r <= 1, "Bool result {r}");
    r == 1
}

fn verify_digest(n: &[u8], e: &[u8], digest: &[u8], sig: &[u8]) -> bool {
    let before = [n.to_vec(), e.to_vec(), digest.to_vec(), sig.to_vec()];
    let r = run(|| unsafe { k_rsa::rsa_pss_verify_digest(n.as_ptr(), n.len(), e.as_ptr(), e.len(), digest.as_ptr(), digest.len(), sig.as_ptr(), sig.len()) });
    free_scratch();
    assert!(before == [n.to_vec(), e.to_vec(), digest.to_vec(), sig.to_vec()], "verifyDigest wrote an input");
    let r = r.unwrap_or_else(|s| panic!("verifyDigest stopped: {s:?}"));
    assert!(r <= 1, "Bool result {r}");
    r == 1
}

#[test]
fn wycheproof_rsa_pss_3072() {
    let mut count = 0;
    for g in wycheproof::GROUPS {
        let n = hex(g.n);
        let n = &n[n.len() - K..];
        let e = hex(g.e);
        for (i, t) in g.tests.iter().enumerate() {
            // Under Miri every sixth vector, and every invalid one up to 8.
            if cfg!(miri) && i % 6 != 0 && (t.valid || count > 8) {
                continue;
            }
            let (msg, sig) = (hex(t.msg), hex(t.sig));
            assert_eq!(verify(n, &e, &msg, &sig), t.valid, "tcId {} {}", t.id, t.comment);
            assert_eq!(verify_digest(n, &e, &Sha256::digest(&msg), &sig), t.valid, "tcId {} (digest) {}", t.id, t.comment);
            count += 1;
        }
    }
    assert!(count >= iters(108, 10), "{count} vectors");
}

#[test]
fn sign_is_rfc8017() {
    let mut rng = Rng(7);
    for (ki, name) in SIGNING_KEYS.iter().enumerate() {
        // Under Miri one signature (mont.rs; the rest is the rsa crate's safe DER code)
        // crate's safe BigUint code), ~20 minutes of Miri on its own on a loaded box.
        if cfg!(miri) && ki != 0 {
            continue;
        }
        let key = load(name);
        let n = be(&key.n, K);
        let e = key.e.to_bytes_be();
        let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![(vec![0; 32], vec![0; 32]), (vec![0xff; 32], vec![0xff; 32])]
            .into_iter()
            .chain((0..iters(12, 0)).map(|_| (rng.bytes(32), rng.bytes(32))))
            .take(iters(usize::MAX, 1))
            .collect();
        for (digest, salt) in cases {
            let got = sign(&key.der, &digest, &salt).unwrap_or_else(|s| panic!("{name}: {s:?}"));
            assert!(verify_digest(&n, &e, &digest, &got), "{name}: the kernel verifies");
            // The references (a 3072-bit-exponent modpow, the rsa crate's verify) natively only:
            // under Miri they cost several times the kernel's signature, and this exact case is
            // checked natively.
            if !cfg!(miri) {
                assert_eq!(got, sign_reference(&key, &digest, &salt), "{name}: RSASP1(EMSA-PSS-ENCODE)");
                assert!(verify_reference(&n, &e, &digest, &got), "{name}: the rsa crate verifies");
            }
        }
    }
}

/// The refused shapes trap with UNSUPPORTED (after the digest and salt checks, like every key
/// error), and so do e65537 rebuilt with one CRT parameter at 2^1536 or above; the same key with
/// dq + (q - 1) below 2^1536 (unreduced, but the fixed-window exponentiation takes it) signs, and
/// signs the same as e65537.
#[test]
fn sign_refuses_nonstandard_key_shapes() {
    let t = |der: &[u8], d: &[u8], s: &[u8]| match sign(der, d, s) {
        Err(Stop::Trap(m)) => m,
        other => panic!("expected a trap, got {other:?}"),
    };
    let (d32, s32) = ([1u8; 32], [2u8; 32]);
    for name in REFUSED_KEYS {
        let der = load(name).der;
        assert_eq!(t(&der, &d32, &s32), UNSUPPORTED, "{name}");
        assert_eq!(t(&der, &[1; 31], &s32), "Rsa3072.sign: the digest must be 32 bytes", "{name}");
        assert_eq!(t(&der, &d32, &[2; 31]), "Rsa3072.sign: the salt must be 32 bytes", "{name}");
    }
    if cfg!(miri) {
        return;
    }
    let base = load("e65537").der;
    let two1536 = pow2(1536);
    // [n, e, d, p, q, dp, dq, qinv]
    let wide: [(usize, &str); 3] = [(5, "dp"), (6, "dq"), (7, "qinv")];
    for (i, what) in wide {
        let der = rebuild(&base, |x| {
            let m = if i == 7 { x[3].clone() } else { &x[i - 2] - 1u8 };
            while x[i] < two1536 { x[i] += &m }
        });
        assert_eq!(t(&der, &d32, &s32), UNSUPPORTED, "{what} >= 2^1536");
    }
    let der = rebuild(&base, |x| { let q1 = &x[4] - 1u8; if &x[6] + &q1 < two1536 { x[6] += q1 } });
    assert!(der != base, "the test key has dq + q - 1 < 2^1536");
    assert_eq!(sign(&der, &d32, &s32).unwrap(), sign(&base, &d32, &s32).unwrap(), "dq + (q - 1)");
}

/// A PKCS#8 key with its PKCS#1 numbers [n, e, d, p, q, dp, dq, qinv] edited.
fn rebuild(der: &[u8], edit: impl FnOnce(&mut [Big; 8])) -> Vec<u8> {
    use rsa::pkcs8::der::{Decode, Encode};
    let info = rsa::pkcs8::PrivateKeyInfo::from_der(der).unwrap();
    let k = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
    let u = |x: rsa::pkcs1::UintRef<'_>| Big::from_bytes_be(x.as_bytes());
    let mut x = [u(k.modulus), u(k.public_exponent), u(k.private_exponent), u(k.prime1), u(k.prime2), u(k.exponent1), u(k.exponent2), u(k.coefficient)];
    edit(&mut x);
    let b = x.map(|v| v.to_bytes_be());
    fn uint(b: &[u8]) -> rsa::pkcs1::UintRef<'_> { rsa::pkcs1::UintRef::new(b).unwrap() }
    let k = rsa::pkcs1::RsaPrivateKey {
        modulus: uint(&b[0]),
        public_exponent: uint(&b[1]),
        private_exponent: uint(&b[2]),
        prime1: uint(&b[3]),
        prime2: uint(&b[4]),
        exponent1: uint(&b[5]),
        exponent2: uint(&b[6]),
        coefficient: uint(&b[7]),
        other_prime_infos: None,
    };
    let inner = k.to_der().unwrap();
    rsa::pkcs8::PrivateKeyInfo::new(rsa::pkcs1::ALGORITHM_ID, &inner).to_der().unwrap()
}

#[test]
fn sign_traps_in_the_motoko_order() {
    let key = load("e65537");
    let t = |der: &[u8], d: &[u8], s: &[u8]| match sign(der, d, s) {
        Err(Stop::Trap(m)) => m,
        other => panic!("expected a trap, got {other:?}"),
    };
    let (d32, s32) = ([1u8; 32], [2u8; 32]);
    assert_eq!(t(&key.der, &[1; 31], &[2; 31]), "Rsa3072.sign: the digest must be 32 bytes");
    assert_eq!(t(&key.der, &[], &s32), "Rsa3072.sign: the digest must be 32 bytes");
    assert_eq!(t(&key.der, &d32, &[2; 33]), "Rsa3072.sign: the salt must be 32 bytes");
    assert_eq!(t(&key.der, &d32, &[]), "Rsa3072.sign: the salt must be 32 bytes");
    let bad_key = "Rsa3072.sign: the key must be a 3072-bit RSA private key in PKCS#8 DER";
    assert_eq!(t(&[], &d32, &s32), bad_key);
    assert_eq!(t(&key.der[..key.der.len() - 1], &d32, &s32), bad_key);
    assert_eq!(t(&load("rsa2048").der, &d32, &s32), bad_key);
    let mut wrong_oid = key.der.clone();
    let at = wrong_oid.windows(9).position(|w| w == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]).unwrap();
    wrong_oid[at + 8] = 0x0a;
    assert_eq!(t(&wrong_oid, &d32, &s32), bad_key);
    if !cfg!(miri) {
        // CRT parts that disagree with (n, e): RSASP1 runs, and the public check refuses it.
        assert_eq!(t(&load("inconsistent").der, &d32, &s32), "Rsa3072.sign: the private key is inconsistent");
    }
}

#[test]
#[cfg_attr(miri, ignore = "the rsa crate's signing (CRT, blinding) is safe crate code and ~1 h under Miri; verify_edge_inputs covers the kernel there")]
fn verify_agrees_with_the_rsa_crate() {
    use rand_chacha::rand_core::SeedableRng;
    let mut rng = Rng(9);
    let mut crng = rand_chacha::ChaCha8Rng::seed_from_u64(9);
    for name in ["e65537", "e3"] {
        let key = load(name);
        let private = {
            use rsa::pkcs8::DecodePrivateKey;
            rsa::RsaPrivateKey::from_pkcs8_der(&key.der).unwrap()
        };
        let n = be(&key.n, K);
        let e = key.e.to_bytes_be();
        for i in 0..10 {
            let msg = rng.bytes(i * 37 % 300);
            let digest = Sha256::digest(&msg).to_vec();
            let sig = private.sign_with_rng(&mut crng, rsa::Pss::new_with_salt::<Sha256>(32), &digest).unwrap();
            assert!(verify(&n, &e, &msg, &sig), "{name}: rsa's signature");
            assert!(!verify(&n, &e, &[&msg[..], &[0]].concat(), &sig), "{name}: other message");
            let mut flipped = sig.clone();
            flipped[i * 7 % K] ^= 1 << (i % 8);
            assert!(!verify_digest(&n, &e, &digest, &flipped));
            assert!(!verify_reference(&n, &e, &digest, &flipped));
            edge_inputs(&n, &e, &msg, &sig);
        }
    }
}

/// Signatures at and around the range check s < n, wrong lengths, bad digests, and keys the
/// contract refuses: the kernel says what the reference says (rsa crate + the length rules).
#[test]
fn verify_edge_inputs() {
    let g = &wycheproof::GROUPS[0];
    let n = hex(g.n);
    let n = n[n.len() - K..].to_vec();
    let e = hex(g.e);
    let t = g.tests.iter().find(|t| t.valid).unwrap();
    let (msg, sig) = (hex(t.msg), hex(t.sig));
    assert!(verify(&n, &e, &msg, &sig));
    edge_inputs(&n, &e, &msg, &sig);
}

/// The same at the exports: a key whose e carries 2 MB of leading zeros verifies exactly as the minimal
/// e (accepts the valid signature, refuses the invalid one; refused exponents stay refused, as
/// in the Motoko body, which reads e as a Nat), walks only e's significant bytes, and costs about
/// what the minimal e costs (natively: the zero run is skipped eight bytes at a time, not
/// converted to a BigUint and walked bit by bit, which was ~100x the whole verification).
#[test]
fn verify_e_with_leading_zeros() {
    let g = &wycheproof::GROUPS[0];
    let n = hex(g.n);
    let n = n[n.len() - K..].to_vec();
    let e = hex(g.e);
    let zeros = if cfg!(miri) { 4096 } else { 2 << 20 };
    let lead = |e: &[u8]| -> Vec<u8> {
        let mut v = vec![0u8; zeros];
        v.extend_from_slice(e);
        v
    };
    let long = lead(&e);
    let valid = g.tests.iter().find(|t| t.valid).unwrap();
    let invalid = g.tests.iter().find(|t| !t.valid).unwrap();
    for t in [valid, invalid] {
        let (msg, sig) = (hex(t.msg), hex(t.sig));
        let digest = Sha256::digest(&msg);
        let before = k_rsa::mont::POW_PUBLIC_BYTES.with(|c| c.get());
        assert_eq!(verify_digest(&n, &long, &digest, &sig), t.valid, "tcId {} with {zeros} leading zeros", t.id);
        let walked = k_rsa::mont::POW_PUBLIC_BYTES.with(|c| c.get()) - before;
        assert!(walked <= mont::significant(&e).len(), "tcId {}: {walked} bytes of e walked", t.id);
        assert_eq!(verify(&n, &long, &msg, &sig), t.valid, "tcId {} (verify) with {zeros} leading zeros", t.id);
    }
    // Exponents the crate refuses (even, below 3, 2^33 and up, all zeros) stay refused.
    let (msg, sig) = (hex(valid.msg), hex(valid.sig));
    let digest = Sha256::digest(&msg);
    // (Under Miri two of them: each verification is a 96-limb exponentiation.)
    let bad = [vec![2u8], vec![2, 0, 0, 0, 1], vec![], vec![0u8], vec![1], vec![1, 0, 0], vec![0xff; 6]];
    for bad in bad.iter().take(if cfg!(miri) { 2 } else { bad.len() }) {
        assert_eq!(verify_digest(&n, &lead(&bad), &digest, &sig), verify_digest(&n, &bad, &digest, &sig), "e={bad:02x?}");
        assert!(!verify_digest(&n, &lead(&bad), &digest, &sig), "e={bad:02x?} accepted");
    }
    if !cfg!(miri) {
        // Wall time, best of five each: the 2 MB key within 20x of the minimal one. Measured
        // 2026-10-24 (release): 20.2 ms against 0.27 ms (76x) before the fix, 0.58 ms (2.2x) after.
        let best = |e: &[u8]| {
            (0..5)
                .map(|_| {
                    let t0 = std::time::Instant::now();
                    assert!(verify_digest(&n, e, &digest, &sig));
                    t0.elapsed()
                })
                .min()
                .unwrap()
        };
        let (short, long_t) = (best(&e), best(&long));
        assert!(long_t < short * 20, "verifyDigest with {zeros} leading zeros of e: {long_t:?} vs {short:?}");
    }
}

fn edge_inputs(n: &[u8], e: &[u8], msg: &[u8], sig: &[u8]) {
    let digest = Sha256::digest(msg).to_vec();
    let nb = Big::from_bytes_be(n);
    let mut sigs: Vec<Vec<u8>> = [Big::from(0u8), one(), &nb - 1u8, nb.clone(), &nb + 1u8, pow2(8 * K) - 1u8].iter().map(|s| be(s, K)).collect();
    sigs.extend([sig[1..].to_vec(), [&[0u8][..], sig].concat(), vec![]]);
    // Every case below is invalid. Natively the rsa crate confirms it for each; under Miri its
    // num-bigint-dig exponentiations would be most of this test's time, so the answer is taken
    // as known.
    let reference = |n: &[u8], e: &[u8], d: &[u8], s: &[u8]| -> bool {
        if cfg!(miri) {
            return false;
        }
        let want = verify_reference(n, e, d, s);
        assert!(!want, "an edge case the reference accepts");
        want
    };
    for s in &sigs {
        let want = reference(n, e, &digest, s);
        assert_eq!(verify_digest(n, e, &digest, s), want, "sig {:02x?}...", &s[..s.len().min(4)]);
        assert_eq!(verify(n, e, msg, s), want);
    }
    for d in [vec![], digest[..31].to_vec(), [&digest[..], &[0]].concat()] {
        assert!(!verify_digest(n, e, &d, sig));
    }
    let mut keys: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (n.to_vec(), vec![]),
        (n.to_vec(), vec![1]),
        (n.to_vec(), vec![2]),
        (n.to_vec(), vec![1, 0, 0]),
        (n.to_vec(), vec![2, 0, 0, 0, 1]), // 2^33 + 1
        (n.to_vec(), vec![1, 0, 0, 0, 1]), // 2^32 + 1
        (n.to_vec(), n.to_vec()),          // e = n
        (n[1..].to_vec(), e.to_vec()),     // 383 bytes
        ([&[0u8][..], n].concat(), e.to_vec()),
    ];
    let mut even = n.to_vec();
    even[K - 1] &= 0xfe;
    keys.push((even, e.to_vec()));
    let mut low = n.to_vec();
    low[0] &= 0x7f;
    keys.push((low, e.to_vec()));
    for (kn, ke) in keys {
        let want = reference(&kn, &ke, &digest, sig);
        assert_eq!(verify_digest(&kn, &ke, &digest, sig), want, "n {} bytes, e {:02x?}", kn.len(), ke);
    }
}

// ---- test keys ----------------------------------------------------------------------------------

/// keys/*.der: PKCS#8 DER (rsaEncryption, two-prime PKCS#1), as `openssl genpkey` writes them.
/// MOXZI_WRITE_KEYS=1 regenerates them from fixed seeds; otherwise this checks they are
/// consistent (n = p q, d e = 1 mod lcm(p - 1, q - 1), the CRT parts) except the one meant not
/// to be, and have the shapes the tests rely on.
#[test]
fn keys() {
    if std::env::var_os("MOXZI_WRITE_KEYS").is_some() {
        // The keys are compiled in (include_bytes!): check them on the next run.
        return write_keys();
    }
    if cfg!(miri) {
        return;
    }
    for name in SIGNING_KEYS.iter().chain(&REFUSED_KEYS).chain(&["inconsistent", "rsa2048"]) {
        use rsa::pkcs8::der::Decode;
        let der = load(name).der;
        let info = rsa::pkcs8::PrivateKeyInfo::from_der(&der).unwrap();
        let k = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
        let u = |x: rsa::pkcs1::UintRef<'_>| Big::from_bytes_be(x.as_bytes());
        let (n, e, d, p, q, dp, dq, qinv) = (u(k.modulus), u(k.public_exponent), u(k.private_exponent), u(k.prime1), u(k.prime2), u(k.exponent1), u(k.exponent2), u(k.coefficient));
        assert_eq!(&p * &q, n, "{name}");
        let (p1, q1) = (&p - 1u8, &q - 1u8);
        let lcm = &p1 * &q1 / gcd(&p1, &q1);
        assert_eq!((&d * &e) % &lcm, one(), "{name}");
        assert_eq!((&qinv * &q) % &p, one(), "{name}");
        let crt_ok = &dp % &p1 == &d % &p1 && &dq % &q1 == &d % &q1;
        assert_eq!(crt_ok, *name != "inconsistent", "{name}");
        let bits = if *name == "rsa2048" { 2048 } else { 3072 };
        assert_eq!(n.bits(), bits, "{name}");
        match *name {
            "unbalanced" => assert_eq!((p.bits(), q.bits()), (1535, 1537)),
            "unreduced" => assert!(dp.bits() > 1536 && dq.bits() > 1536),
            "swapped" => assert!(p < q),
            "e3" => assert_eq!(e, Big::from(3u8)),
            "rsa2048" => {}
            _ => assert_eq!((p.bits(), q.bits(), e.clone()), (1536, 1536, Big::from(65537u32)), "{name}"),
        }
    }
}

fn gcd(a: &Big, b: &Big) -> Big {
    let (mut a, mut b) = (a.clone(), b.clone());
    while b != Big::from(0u8) {
        let t = &a % &b;
        a = b;
        b = t;
    }
    a
}

fn write_keys() {
    use num_bigint_dig::RandPrime;
    use rand_chacha::rand_core::SeedableRng;
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/keys");
    std::fs::create_dir_all(dir).unwrap();
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0x6d6f787a69);
    let to = |x: &num_bigint_dig::BigUint| Big::from_bytes_be(&x.to_bytes_be());
    let prime = |rng: &mut rand_chacha::ChaCha8Rng, bits: usize| -> Big { to(&rng.gen_prime(bits)) };
    // (n, e, d, p, q, dp, dq, qinv) as DER.
    let der = |p: &Big, q: &Big, e: &Big, dp_extra: bool, swap_crt: bool| -> Vec<u8> {
        let n = p * q;
        let (p1, q1) = (p - 1u8, q - 1u8);
        let lcm = &p1 * &q1 / gcd(&p1, &q1);
        let d = e.modinv(&lcm).expect("e invertible");
        let (mut dp, mut dq) = (&d % &p1, &d % &q1);
        if dp_extra {
            dp += &p1 * 2u8;
            dq += &q1 * 2u8;
        }
        if swap_crt {
            std::mem::swap(&mut dp, &mut dq);
        }
        let qinv = q.modinv(p).unwrap();
        let parts = [n, e.clone(), d, p.clone(), q.clone(), dp, dq, qinv].map(|x| x.to_bytes_be());
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
        rsa::pkcs8::PrivateKeyInfo::new(rsa::pkcs1::ALGORITHM_ID, &inner).to_der().unwrap()
    };
    let balanced = |rng: &mut rand_chacha::ChaCha8Rng, e: &Big, bits: usize| loop {
        let (p, q) = (prime(rng, bits / 2), prime(rng, bits / 2));
        let n = &p * &q;
        let ok = n.bits() == bits as u64 && p != q && gcd(&(&p - 1u8), e) == one() && gcd(&(&q - 1u8), e) == one();
        if ok {
            break if p > q { (p, q) } else { (q, p) };
        }
    };
    let f4 = Big::from(65537u32);
    let (p, q) = balanced(&mut rng, &f4, 3072);
    std::fs::write(format!("{dir}/e65537.der"), der(&p, &q, &f4, false, false)).unwrap();
    std::fs::write(format!("{dir}/swapped.der"), der(&q, &p, &f4, false, false)).unwrap();
    std::fs::write(format!("{dir}/unreduced.der"), der(&p, &q, &f4, true, false)).unwrap();
    std::fs::write(format!("{dir}/inconsistent.der"), der(&p, &q, &f4, false, true)).unwrap();
    let three = Big::from(3u8);
    let (p3, q3) = balanced(&mut rng, &three, 3072);
    std::fs::write(format!("{dir}/e3.der"), der(&p3, &q3, &three, false, false)).unwrap();
    let (pu, qu) = loop {
        let (a, b) = (prime(&mut rng, 1535), prime(&mut rng, 1537));
        if (&a * &b).bits() == 3072 && gcd(&(&a - 1u8), &f4) == one() && gcd(&(&b - 1u8), &f4) == one() {
            break (a, b);
        }
    };
    std::fs::write(format!("{dir}/unbalanced.der"), der(&pu, &qu, &f4, false, false)).unwrap();
    let (p2, q2) = balanced(&mut rng, &f4, 2048);
    std::fs::write(format!("{dir}/rsa2048.der"), der(&p2, &q2, &f4, false, false)).unwrap();
}
