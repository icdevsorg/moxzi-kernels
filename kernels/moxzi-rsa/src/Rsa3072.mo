/// RSA-3072 signatures: RSASSA-PSS (RFC 8017) with SHA-256, MGF1-SHA-256 and a 32-byte salt
/// (JOSE's PS256). Signatures are 384 bytes.
///
/// With the moxzi-rsa native kernel opted in (`[kernels]` in the application's mops.toml) every
/// function runs natively (RustCrypto `rsa` 0.9.10 for keys and checks, with the modular
/// exponentiation on 32-bit limbs); otherwise, and under moc, these bodies run.
///
/// - `verify` / `verifyDigest` take the public key as (n, e), big-endian. n must be exactly 384
///   bytes with its top bit set (a 3072-bit modulus); e must be odd, at least 3 and below 2^33
///   (the `rsa` crate's limits; 65537 is usual). They return `false` for any malformed input:
///   a wrong length, a bad key, a signature >= n, or a signature that does not verify. The
///   Motoko bodies implement RSAVP1 and EMSA-PSS-VERIFY with `Nat` arithmetic and mo:sha2, and
///   agree with the kernel on every input.
/// - `sign` takes a PKCS#8 DER private key (as `openssl genpkey -algorithm RSA -pkeyopt
///   rsa_keygen_bits:3072 -outform DER` writes one), a 32-byte SHA-256 digest and a 32-byte salt.
///   The key must have the standard shape: two primes of exactly 1536 bits and CRT parameters
///   (dp, dq, qInv) below 2^1536, as every key OpenSSL or node generates has. Other keys, such as
///   a 1535/1537-bit prime split or unreduced CRT exponents, trap with "Rsa3072.sign: key shape
///   not supported (...)" rather than being signed by a slower path whose running time would
///   depend on the secret primes. No randomness exists in a canister: the caller supplies the
///   salt (for example from `raw_rand`), so a signature is a deterministic function of (key,
///   digest, salt). It has no Motoko body: without the kernel it traps after checking the digest
///   and salt lengths. (The exponentiation would be feasible in Motoko, but agreeing with the
///   kernel's strict DER and key checks on every malformed key is not.)
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Runtime "mo:core/Runtime";
import Sha256 "mo:sha2/Sha256";

module {
  let K = 384;
  let H_LEN = 32;
  let S_LEN = 32;
  let MAX_E : Nat = 8_589_934_591; // 2^33 - 1

  func toNat(b : [Nat8]) : Nat {
    var n = 0;
    for (x in b.values()) n := n * 256 + Nat8.toNat(x);
    n;
  };

  func toBytes(n : Nat, len : Nat) : [var Nat8] {
    let out = VarArray.repeat<Nat8>(0, len);
    var v = n;
    var i = len;
    while (i > 0) { i -= 1; out[i] := Nat8.fromNat(v % 256); v := v / 256 };
    out;
  };

  func modPow(b : Nat, e : Nat, m : Nat) : Nat {
    var result = 1;
    var base = b % m;
    var x = e;
    while (x > 0) {
      if (x % 2 == 1) result := (result * base) % m;
      base := (base * base) % m;
      x := x / 2;
    };
    result;
  };

  func sha256(parts : [[Nat8]]) : [Nat8] = Blob.toArray(Sha256.fromBlob(#sha256, Blob.fromArray(Array.flatten(parts))));

  /// Verify an RSASSA-PSS signature on `message` (hashed here with SHA-256).
  public func verify(n : Blob, e : Blob, message : Blob, signature : Blob) : Bool {
    verifyDigest(n, e, Sha256.fromBlob(#sha256, message), signature);
  };

  /// Verify an RSASSA-PSS signature on a 32-byte SHA-256 `digest`.
  public func verifyDigest(n : Blob, e : Blob, digest : Blob, signature : Blob) : Bool {
    let nb = Blob.toArray(n);
    if (nb.size() != K or nb[0] < 0x80 or digest.size() != H_LEN or signature.size() != K) return false;
    let modulus = toNat(nb);
    let exponent = toNat(Blob.toArray(e));
    // RsaPublicKey::new: n odd, e odd, 2 <= e <= 2^33 - 1 (and e < n, implied here).
    if (modulus % 2 == 0 or exponent % 2 == 0 or exponent < 2 or exponent > MAX_E) return false;
    // RSAVP1: the signature representative must be below n.
    let s = toNat(Blob.toArray(signature));
    if (s >= modulus) return false;
    let em = toBytes(modPow(s, exponent, modulus), K);
    // EMSA-PSS-VERIFY (RFC 8017 9.1.2) with emBits = 3071, emLen = 384.
    if (em[K - 1] != 0xbc) return false;
    let dbLen = K - H_LEN - 1;
    if (em[0] & 0x80 != 0) return false;
    let h = Array.tabulate<Nat8>(H_LEN, func i = em[dbLen + i]);
    var counter = 0;
    while (counter * H_LEN < dbLen) {
      let c = Nat8.fromNat(counter);
      let mask = sha256([h, [0, 0, 0, c]]);
      var j = 0;
      while (j < H_LEN and counter * H_LEN + j < dbLen) {
        em[counter * H_LEN + j] ^= mask[j];
        j += 1;
      };
      counter += 1;
    };
    em[0] &= 0x7f;
    let ps = dbLen - S_LEN - 1;
    var i = 0;
    while (i < ps) { if (em[i] != 0) return false; i += 1 };
    if (em[ps] != 0x01) return false;
    let salt = Array.tabulate<Nat8>(S_LEN, func k = em[ps + 1 + k]);
    sha256([Array.repeat<Nat8>(0, 8), Blob.toArray(digest), salt]) == h;
  };

  /// Sign a 32-byte SHA-256 `digest` with a 3072-bit PKCS#8 DER private key and a 32-byte salt.
  /// Traps on a wrong digest or salt length, a key that is not a valid 3072-bit RSA key, or a key
  /// whose primes are not exactly 1536 bits each or whose CRT parameters are 2^1536 or more.
  public func sign(privateKey : Blob, digest : Blob, salt : Blob) : Blob {
    ignore privateKey;
    if (digest.size() != H_LEN) Runtime.trap("Rsa3072.sign: the digest must be 32 bytes");
    if (salt.size() != S_LEN) Runtime.trap("Rsa3072.sign: the salt must be 32 bytes");
    Runtime.trap("Rsa3072.sign: needs the moxzi native kernel (no Motoko implementation)");
  };
};
