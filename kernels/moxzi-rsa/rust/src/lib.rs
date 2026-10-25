//! RSA-3072 RSASSA-PSS kernels for the `moxzi-rsa` Motoko package (ABI 1, see moxzi-kernel).
//!
//! The scheme is RSASSA-PSS (RFC 8017) with SHA-256, MGF1-SHA-256 and a 32-byte salt (JOSE's
//! PS256), for 3072-bit moduli only (signatures are 384 bytes).
//!  - verify: the public key is (n, e) as big-endian bytes; n must be exactly 384 bytes with its
//!    top bit set; e is checked as the crate checks it (odd, 2 <= e < 2^33, e < n; n odd). Any
//!    malformed input returns false; a signature >= n is rejected (RSAVP1's range check).
//!  - sign: the private key is PKCS#8 DER (as `openssl genpkey` or node's `export({ type:
//!    'pkcs8', format: 'der' })` write it); the salt is an argument (no RNG exists), so a
//!    signature is a deterministic function of (key, digest, salt). Errors trap with the Motoko
//!    body's text, checked in the same order (digest, salt, key). Only keys of the standard shape
//!    are signed with: primes of exactly 1536 bits and CRT parameters dp, dq, qInv below 2^1536
//!    (every key `openssl genpkey` or node writes); any other key traps (`UNSUPPORTED_KEY`).
//!
//! The modular exponentiations run in mont.rs (Montgomery multiplication on 32-bit limbs, which
//! wasm multiplies natively); the crate's u64-digit BigUint pays a 128-bit multiply call per limb
//! product there. Verification: 17 multiplications for e = 65537 instead of the crate's modpow
//! (48 M -> 4.6 M instructions). Signing: the whole CRT private operation (`rsasp1_ct`) on
//! fixed-size limbs, a fixed-window exponentiation per prime, so that its instruction count does
//! not depend on the private key (gated by kernel-constant-time.test.ts). No secret number is
//! ever a BigUint: the private key's p, q, dp, dq and qInv go from their DER bytes to limbs.
#![no_std]
extern crate alloc;

use moxzi_kernel::{bytes, trap};
use rsa::pkcs1;
use rsa::pkcs8::{der::asn1::Null, PrivateKeyInfo};
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

mod mont;
use mont::Modulus;

const K: usize = 384;
const H_LEN: usize = 32;
const SALT: usize = 32;
/// 32-bit limbs of a 3072-bit modulus, and of one of its 1536-bit primes.
const LIMBS: usize = K / 4;
const HALF: usize = LIMBS / 2;

fn verify_digest(n: &[u8], e: &[u8], digest: &[u8], sig: &[u8]) -> bool {
    if n.len() != K || n[0] & 0x80 == 0 || digest.len() != H_LEN || sig.len() != K {
        return false;
    }
    // e without its leading zero bytes: the same number (so the same accept/reject, here and in
    // the Motoko body, which reads e as a Nat), but a key's e can be any length, and 2 MB of
    // zeros made this conversion and pow_public's bit loop cost ~17x a whole verification on the
    // IC (found in adversarial review; check: verify_e_with_leading_zeros).
    let e = mont::significant(e);
    // The crate's public-key checks (n odd, e odd, 2 <= e < 2^33, e < n), unchanged.
    if RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)).is_err() {
        return false;
    }
    // n is odd with its top bit set (checked above), so the Montgomery path always applies.
    let Some(modulus) = Modulus::<LIMBS>::from_be(n) else { return false };
    let (Some(s), Some(nl)) = (mont::from_be::<LIMBS>(sig), mont::from_be::<LIMBS>(n)) else { return false };
    // RSAVP1 (RFC 8017 5.2.2): the signature representative must be < n.
    if !mont::less_than(&s, &nl) {
        return false;
    }
    let mut em = [0u8; K];
    mont::to_be(&modulus.pow_public(&s, e), &mut em);
    emsa_pss_verify(digest, &mut em)
}

/// EMSA-PSS-VERIFY (RFC 8017 9.1.2) for emBits = 3071 (emLen = 384), SHA-256, MGF1-SHA-256 and
/// a 32-byte salt: the steps of rsa 0.9.10's `emsa_pss_verify_digest`, in its order.
fn emsa_pss_verify(m_hash: &[u8], em: &mut [u8; K]) -> bool {
    // 4. The rightmost octet must be 0xbc.
    if em[K - 1] != 0xbc {
        return false;
    }
    // 5. maskedDB = the leftmost emLen - hLen - 1 octets, H = the next hLen.
    let (db, rest) = em.split_at_mut(K - H_LEN - 1);
    let h = &rest[..H_LEN];
    // 6. The leftmost 8 emLen - emBits = 1 bit of maskedDB must be zero.
    if db[0] & 0x80 != 0 {
        return false;
    }
    // 7-9. DB = maskedDB xor MGF1(H), then clear that bit.
    mgf1_xor(db, h);
    db[0] &= 0x7f;
    // 10. emLen - hLen - sLen - 2 zero octets, then 0x01.
    let zeros = K - H_LEN - SALT - 2;
    let salt_valid = db[..zeros].iter().all(|&b| b == 0) & (db[zeros] == 0x01);
    // 11-14. H' = Hash(0^8 || mHash || salt) must equal H.
    let salt = &db[db.len() - SALT..];
    let h0 = Sha256::new().chain_update([0u8; 8]).chain_update(m_hash).chain_update(salt).finalize();
    salt_valid & (h0.as_slice() == h)
}

/// A decoded two-prime private key: the public (n, e), and the CRT form RSASP1 uses (RFC 8017
/// 5.2.1, 2.b) as DER bytes (big-endian, minimal): primes p and q, exponents dp and dq, and
/// qInv = q^-1 mod p.
struct Key {
    /// n, exactly 384 bytes (3072 bits).
    n: [u8; K],
    e: alloc::vec::Vec<u8>,
    raw: [alloc::vec::Vec<u8>; 5],
}

/// The trap for a well-formed key that `crt` refuses. Until 2026-10-24 such keys (a 1535/1537-bit
/// prime split, or CRT exponents >= 2^1536) were signed with the rsa crate's BigUint modpow and
/// division on the secret primes, variable time in the key (found in review); no key that
/// `openssl genpkey` or node writes has that shape, so they are refused instead.
const UNSUPPORTED_KEY: &[u8] = b"Rsa3072.sign: key shape not supported (primes must be exactly 1536 bits and the CRT parameters reduced)";

/// The PKCS#8 checks of rsa 0.9.10's `TryFrom<PrivateKeyInfo> for RsaPrivateKey` (rsaEncryption
/// with NULL parameters, a two-prime PKCS#1 key), a 3072-bit modulus, and a public part the crate
/// accepts.
fn key(der: &[u8]) -> Option<Key> {
    let info = PrivateKeyInfo::try_from(der).ok()?;
    info.algorithm.assert_algorithm_oid(pkcs1::ALGORITHM_OID).ok()?;
    if info.algorithm.parameters_any().ok()? != Null.into() {
        return None;
    }
    let k = pkcs1::RsaPrivateKey::try_from(info.private_key).ok()?;
    if k.version() != pkcs1::Version::TwoPrime {
        return None;
    }
    // The public part only: n and e are BigUints for the crate's checks.
    let n = BigUint::from_bytes_be(k.modulus.as_bytes());
    let e = BigUint::from_bytes_be(k.public_exponent.as_bytes());
    if n.bits() != 3072 || RsaPublicKey::new(n.clone(), e.clone()).is_err() {
        return None;
    }
    let mut n_be = [0u8; K];
    n_be.copy_from_slice(&n.to_bytes_be());
    let raw = [k.prime1, k.prime2, k.exponent1, k.exponent2, k.coefficient].map(|x| x.as_bytes().to_vec());
    Some(Key { n: n_be, e: e.to_bytes_be(), raw })
}

/// The private key as `rsasp1_ct` takes it: Montgomery moduli for p and q, q as limbs, and dp,
/// dq, qInv as 1536-bit limb arrays.
struct Crt {
    mp: Modulus<HALF>,
    mq: Modulus<HALF>,
    q: [u32; HALF],
    dp: [u32; HALF],
    dq: [u32; HALF],
    qinv: [u32; HALF],
}

/// The standard key shape, or None (the caller traps with `UNSUPPORTED_KEY`): p and q exactly
/// 1536 bits (192 bytes, top bit set) and odd, and dp, dq, qInv below 2^1536. A reduced key with
/// such primes always qualifies (dp < p - 1, dq < q - 1, qInv < p). The fixed-window
/// exponentiation takes any 1536-bit exponent, and Montgomery multiplication by any qInv below
/// 2^1536 stays in range (d qInv < p R); the s^e == m check after signing catches a key whose
/// numbers do not belong together. The DER lengths of dp, dq and qInv (whether a top byte is
/// zero) reach the copy lengths here: the accepted minor finding in kernels/ct-scan/allow/moxzi-rsa.toml.
fn crt(key: &Key) -> Option<Crt> {
    let [p, q, dp, dq, qinv] = &key.raw;
    let pad = |x: &[u8]| -> Option<[u32; HALF]> {
        if x.len() > 4 * HALF {
            return None;
        }
        let mut be = [0u8; 4 * HALF];
        be[4 * HALF - x.len()..].copy_from_slice(x);
        mont::from_be::<HALF>(&be)
    };
    // Exactly 192 bytes, odd, top bit set (Modulus::from_be's conditions).
    let (mp, mq) = (Modulus::<HALF>::from_be(p)?, Modulus::<HALF>::from_be(q)?);
    Some(Crt { mp, mq, q: mont::from_be::<HALF>(q)?, dp: pad(dp)?, dq: pad(dq)?, qinv: pad(qinv)? })
}

/// RSASP1 with the CRT (RFC 8017 5.2.1: s = m2 + q (qInv (m1 - m2) mod p), m1 = m^dp mod p,
/// m2 = m^dq mod q), in an instruction count that does not depend on the secret key: every step
/// is mont.rs arithmetic on fixed-size limbs -- m mod p and m mod q as Montgomery forms (no
/// division), the fixed-window exponentiations, h = qInv (m1 - m2) mod p by Montgomery
/// multiplication, and s = m2 + h q by a full schoolbook product. Returns s as limbs.
///
/// Why: the constant-time gate (instruction counts on PocketIC, 2026-10-23) found
/// sign varying by up to 113,696 instructions between keys (257,454,349..257,567,726 over five
/// keys of one shape): the BigUint `pow_mod_prime` reduced m mod p and m R mod p with the
/// crate's division, and `rsasp1` recombined with BigUint `%` and `*` -- all variable time in p
/// and q. Both are gone (2026-10-24): keys this cannot sign are refused (`crt`).
///
/// Out of line so that the constant-time scan (kernels/ct-scan) checks it, with everything it
/// inlines (Modulus::sub, reduce_once), site by site: it is in the policy's `ct` list.
#[inline(never)]
fn rsasp1_ct(key: &Crt, em: &[u8; K]) -> [u32; LIMBS] {
    let Crt { mp, mq, q: ql, dp, dq, qinv } = key;
    let m = mont::from_be::<LIMBS>(em).expect("K bytes");
    let (mut lo, mut hi) = ([0u32; HALF], [0u32; HALF]);
    lo.copy_from_slice(&m[..HALF]);
    hi.copy_from_slice(&m[HALF..]);
    // m1 = m^dp mod p, m2 = m^dq mod q.
    let m1 = mp.pow_secret(&mp.to_mont_wide(&lo, &hi), dp, &mp.one_mont());
    let m2 = mq.pow_secret(&mq.to_mont_wide(&lo, &hi), dq, &mq.one_mont());
    // h = qInv (m1 - m2) mod p. m2 < q < 2p, so one reduction; mul(mul(d, qInv), R^2) = d qInv.
    let d = mp.sub(&m1, &mp.reduce(&m2));
    let h = mp.mul(&mp.mul(&d, qinv), &mp.r2());
    // s = m2 + h q (< n).
    let mut s = [0u32; LIMBS];
    for i in 0..HALF {
        let mut carry = 0u64;
        for j in 0..HALF {
            let t = s[i + j] as u64 + h[i] as u64 * ql[j] as u64 + carry;
            s[i + j] = t as u32;
            carry = t >> 32;
        }
        s[i + HALF] = carry as u32;
    }
    let mut carry = 0u64;
    for (j, limb) in s.iter_mut().enumerate() {
        let t = *limb as u64 + if j < HALF { m2[j] as u64 } else { 0 } + carry;
        *limb = t as u32;
        carry = t >> 32;
    }
    s
}

/// a < b (little-endian limbs) by the borrow of a - b, and a == b by ORing a ^ b: the post-check
/// runs on s before it is known to be the signature, so neither stops at the first differing
/// limb (a slice `!=` compiles to memcmp, which does).
fn below<const N: usize>(a: &[u32; N], b: &[u32; N]) -> bool {
    let mut borrow = 0u64;
    for i in 0..N {
        borrow = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow) >> 63;
    }
    borrow == 1
}

fn equal<const N: usize>(a: &[u32; N], b: &[u32; N]) -> bool {
    a.iter().zip(b).fold(0u32, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// MGF1 with SHA-256 (RFC 8017 B.2.1), XORed into `db`.
fn mgf1_xor(db: &mut [u8], seed: &[u8]) {
    for (counter, chunk) in db.chunks_mut(H_LEN).enumerate() {
        let mask = Sha256::new().chain_update(seed).chain_update((counter as u32).to_be_bytes()).finalize();
        for (b, m) in chunk.iter_mut().zip(mask.iter()) {
            *b ^= m;
        }
    }
}

/// EMSA-PSS-ENCODE (RFC 8017 9.1.1) for emBits = 3071, so emLen = 384.
fn emsa_pss_encode(m_hash: &[u8], salt: &[u8]) -> [u8; K] {
    let h = Sha256::new().chain_update([0u8; 8]).chain_update(m_hash).chain_update(salt).finalize();
    let mut em = [0u8; K];
    let db_len = K - H_LEN - 1;
    em[db_len - salt.len() - 1] = 0x01;
    em[db_len - salt.len()..db_len].copy_from_slice(salt);
    mgf1_xor(&mut em[..db_len], &h);
    em[0] &= 0x7f;
    em[db_len..K - 1].copy_from_slice(&h);
    em[K - 1] = 0xbc;
    em
}

#[no_mangle]
pub unsafe extern "C" fn rsa_pss_verify_digest(n: *const u8, nn: usize, e: *const u8, en: usize, d: *const u8, dn: usize, s: *const u8, sn: usize) -> u32 {
    verify_digest(bytes(n, nn), bytes(e, en), bytes(d, dn), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn rsa_pss_verify(n: *const u8, nn: usize, e: *const u8, en: usize, m: *const u8, mn: usize, s: *const u8, sn: usize) -> u32 {
    verify_digest(bytes(n, nn), bytes(e, en), &Sha256::digest(bytes(m, mn)), bytes(s, sn)) as u32
}

#[no_mangle]
pub unsafe extern "C" fn rsa_pss_sign(k: *const u8, kn: usize, d: *const u8, dn: usize, s: *const u8, sn: usize, out: *mut u8) {
    let (der, digest, salt) = (bytes(k, kn), bytes(d, dn), bytes(s, sn));
    if digest.len() != H_LEN {
        trap(b"Rsa3072.sign: the digest must be 32 bytes");
    }
    if salt.len() != SALT {
        trap(b"Rsa3072.sign: the salt must be 32 bytes");
    }
    let Some(key) = key(der) else { trap(b"Rsa3072.sign: the key must be a 3072-bit RSA private key in PKCS#8 DER") };
    let Some(crt) = crt(&key) else { trap(UNSUPPORTED_KEY) };
    let em = emsa_pss_encode(digest, salt);
    // RSASP1 (em < 2^3071 < n), then the check rsa's own signing makes, s^e mod n == m (and here
    // also s < n), so an inconsistent key cannot produce a wrong signature. n is odd with its top
    // bit set (the crate's checks in `key`), so it is a Montgomery modulus.
    let s = rsasp1_ct(&crt, &em);
    let modulus = Modulus::<LIMBS>::from_be(&key.n).expect("n: odd, 3072 bits");
    let (nl, ml) = (mont::from_be::<LIMBS>(&key.n).expect("K bytes"), mont::from_be::<LIMBS>(&em).expect("K bytes"));
    if !(below(&s, &nl) & equal(&modulus.pow_public(&s, &key.e), &ml)) {
        trap(b"Rsa3072.sign: the private key is inconsistent");
    }
    mont::to_be(&s, core::slice::from_raw_parts_mut(out, K));
}
