import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import Curve "mo:ecdsa/Curve";
import EcdsaPrivateKey "mo:ecdsa/PrivateKey";
import EcdsaSignature "mo:ecdsa/Signature";
import Sha256 "mo:sha2/Sha256";

/// NIST P-256 (secp256r1, prime256v1): SEC1 public keys and RFC 6979 ECDSA over 32-byte
/// digests (WebAuthn, TLS, JWT ES256).
///
/// With the `moxzi-p256` kernel opted in (`[kernels]` in the application's mops.toml), moxzi
/// runs each function natively (RustCrypto `p256` 0.13.2). Otherwise -- under moc, or without
/// the opt-in -- the Motoko bodies below run, on `mo:ecdsa` 8.0.1's P-256 curve arithmetic,
/// private key and signature code. Both paths accept, reject and trap identically.
///
/// Encodings:
/// - secret keys: 32 big-endian bytes in [1, n);
/// - public keys: canonical SEC1, compressed (33 bytes, 02/03) or uncompressed (65 bytes, 04);
///   hybrid, compact and identity encodings are refused;
/// - signatures: 64 bytes r || s, r and s in [1, n); DER is strict (minimal) DER.
///
/// Errors: bad input to a function that is not a predicate traps with
/// "P256.<function>: <reason>"; `verifyPrehash` returns false for any bad input.
///
/// Not constant-time without the kernel (Motoko `Nat` arithmetic): keep secret keys where
/// timing cannot be observed.
module {
  // mo:ecdsa's curve; a class, so built per call (a module may hold only static values).
  func mkCurve() : Curve.Curve = Curve.prime256v1();
  let P : Nat = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
  let N : Nat = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
  let HALF_N : Nat = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8; // (n-1)/2: s above it is "high"

  func beNat(a : [Nat8], from : Nat, len : Nat) : Nat {
    var n = 0;
    var i = 0;
    while (i < len) { n := n * 256 + a[from + i].toNat(); i += 1 };
    n;
  };

  func beBytes(n : Nat, len : Nat) : [Nat8] {
    let out = VarArray.repeat<Nat8>(0, len);
    var m = n;
    var i = len;
    while (i > 0) { i -= 1; out[i] := (m % 256).toNat8(); m /= 256 };
    out.toArray();
  };

  func cat(parts : [[Nat8]]) : [Nat8] = parts.flatten();

  func secretOf(b : Blob, fn : Text) : Nat {
    if (b.size() != 32) Runtime.trap("P256." # fn # ": invalid secret key");
    let d = beNat(b.toArray(), 0, 32);
    if (d == 0 or d >= N) Runtime.trap("P256." # fn # ": invalid secret key");
    d;
  };

  /// Canonical SEC1 (compressed or uncompressed) to affine coordinates.
  func parsePublic(b : Blob) : ?(Nat, Nat) {
    let curve = mkCurve();
    let a = b.toArray();
    if (a.size() == 33 and (a[0] == 2 or a[0] == 3)) {
      let x = beNat(a, 1, 32);
      if (x >= P) return null;
      switch (curve.getYfromX(#fp(x), a[0] == 2)) {
        case (?#fp(y)) ?(x, y);
        case null null;
      };
    } else if (a.size() == 65 and a[0] == 4) {
      let x = beNat(a, 1, 32);
      let y = beNat(a, 33, 32);
      if (x >= P or y >= P) return null;
      if (not curve.isValidAffine((#fp(x), #fp(y)))) return null;
      ?(x, y);
    } else null;
  };

  func encode(x : Nat, y : Nat, compressed : Bool) : Blob {
    Array.toBlob(
      if (compressed) cat([[if (y % 2 == 0) 2 else 3], beBytes(x, 32)])
      else cat([[4], beBytes(x, 32), beBytes(y, 32)])
    );
  };

  func encodeJ(j : Curve.Jacobi, compressed : Bool) : Blob {
    let curve = mkCurve();
    switch (curve.fromJacobi(j)) {
      case (#affine(#fp(x), #fp(y))) encode(x, y, compressed);
      case (#zero) Runtime.trap("P256: unexpected point at infinity");
    };
  };

  /// r || s with r, s in [1, n).
  func parseSignature(b : Blob) : ?(Nat, Nat) {
    if (b.size() != 64) return null;
    let a = b.toArray();
    let r = beNat(a, 0, 32);
    let s = beNat(a, 32, 32);
    if (r == 0 or r >= N or s == 0 or s >= N) return null;
    ?(r, s);
  };

  func signatureOf(b : Blob, fn : Text) : (Nat, Nat) {
    switch (parseSignature(b)) {
      case (?rs) rs;
      case null Runtime.trap("P256." # fn # ": invalid signature");
    };
  };

  func compact(r : Nat, s : Nat) : Blob = cat([beBytes(r, 32), beBytes(s, 32)]).toBlob();

  func sha256(data : [Nat8]) : [Nat8] = Sha256.fromArray(#sha256, data).toArray();

  /// HMAC-SHA-256 (RFC 2104) for keys of at most 64 bytes (RFC 6979's are 32).
  func hmac(key : [Nat8], data : [Nat8]) : [Nat8] {
    let k = Array.tabulate<Nat8>(64, func i = if (i < key.size()) key[i] else 0);
    let inner = sha256(cat([k.map(func(b : Nat8) : Nat8 = b ^ 0x36), data]));
    sha256(cat([k.map(func(b : Nat8) : Nat8 = b ^ 0x5c), inner]));
  };

  /// The SEC1 public key of a secret key, compressed (33 bytes) or uncompressed (65 bytes).
  public func publicKey(secret : Blob, compressed : Bool) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "publicKey");
    encodeJ(curve.mul_base(#fr(d)), compressed);
  };

  /// The 33-byte compressed public key of a secret key.
  public func derivePublicKey(secret : Blob) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "derivePublicKey");
    encodeJ(curve.mul_base(#fr(d)), true);
  };

  /// A public key compressed (33 bytes) or uncompressed (65 bytes).
  public func convertPublicKey(key : Blob, compressed : Bool) : Blob {
    switch (parsePublic(key)) {
      case (?(x, y)) encode(x, y, compressed);
      case null Runtime.trap("P256.convertPublicKey: invalid public key");
    };
  };

  /// The low-S form of a signature (s replaced by n - s when s > n/2).
  public func normalizeSignature(signature : Blob) : Blob {
    let (r, s) = signatureOf(signature, "normalizeSignature");
    // Not mo:ecdsa's Signature.s: for P-256 its threshold is (n-1)/2 with `<`, so it turns
    // the low s = (n-1)/2 into the high n - s = (n+1)/2.
    compact(r, if (s > HALF_N) (N - s : Nat) else s);
  };

  /// A strict DER signature as 64 bytes r || s; null unless `der` is the minimal DER encoding
  /// of r, s in [1, n) with nothing after it.
  public func signatureFromDer(der : Blob) : ?Blob {
    // Not mo:ecdsa's Signature.fromBytes(#der): it accepts non-minimal encodings, and it TRAPS
    // (a Nat underflow in its low-S normalisation) on a DER s above n instead of failing.
    let a = der.toArray();
    if (a.size() < 2 or a[0] != 0x30 or a[1].toNat() + 2 != a.size()) return null;
    let ?(r, i) = derInteger(a, 2) else return null;
    let ?(s, j) = derInteger(a, i) else return null;
    if (j != a.size()) return null;
    if (r == 0 or r >= N or s == 0 or s >= N) return null;
    ?compact(r, s);
  };

  /// A minimal DER INTEGER (short-form length, non-negative) at `a[i]`: its value and the index
  /// after it.
  func derInteger(a : [Nat8], i : Nat) : ?(Nat, Nat) {
    if (i + 2 > a.size() or a[i] != 0x02) return null;
    let len = a[i + 1].toNat();
    if (len == 0 or len >= 0x80 or i + 2 + len > a.size()) return null;
    let first = a[i + 2];
    if (first >= 0x80) return null; // negative
    if (len > 1 and first == 0 and a[i + 3] < 0x80) return null; // not minimal
    ?(beNat(a, i + 2, len), i + 2 + len);
  };

  /// The minimal DER encoding of a 64-byte signature.
  public func signatureToDer(signature : Blob) : Blob {
    let curve = mkCurve();
    let (r, s) = signatureOf(signature, "signatureToDer");
    EcdsaSignature.Signature(r, s, curve).toBytes(#der).toBlob();
  };

  /// RFC 6979 deterministic ECDSA (HMAC-SHA-256) over a 32-byte digest: r || s, with s as
  /// computed (RFC 6979's own signatures; `normalizeSignature` gives the low-S form).
  public func signPrehash(secret : Blob, digest : Blob) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "signPrehash");
    if (digest.size() != 32) Runtime.trap("P256.signPrehash: the digest must be 32 bytes");
    // RFC 6979 3.2: bits2octets(h1) = the digest reduced mod n.
    let x = beBytes(d, 32);
    let h1 = beBytes(beNat(digest.toArray(), 0, 32) % N, 32);
    var v = Array.repeat<Nat8>(1, 32);
    var k = Array.repeat<Nat8>(0, 32);
    k := hmac(k, cat([v, [0], x, h1]));
    v := hmac(k, v);
    k := hmac(k, cat([v, [1], x, h1]));
    v := hmac(k, v);
    var nonce = 0;
    label search loop {
      v := hmac(k, v);
      nonce := beNat(v, 0, 32);
      if (nonce >= 1 and nonce < N) break search;
      k := hmac(k, cat([v, [0]]));
      v := hmac(k, v);
    };
    // mo:ecdsa signs with the nonce it is given (its own `sign` expects fresh randomness).
    switch (EcdsaPrivateKey.PrivateKey(d, curve).signHashed(digest.values(), beBytes(nonce, 32).values())) {
      case (#ok(sig)) {
        if (sig.original_s == 0) Runtime.trap("P256.signPrehash: signing failed");
        compact(sig.original_r, sig.original_s);
      };
      case (#err(_)) Runtime.trap("P256.signPrehash: signing failed");
    };
  };

  /// ECDSA verification of a 64-byte signature over a 32-byte digest; low-S and high-S
  /// signatures are both accepted. False for any bad input.
  public func verifyPrehash(key : Blob, digest : Blob, signature : Blob) : Bool {
    let curve = mkCurve();
    let ?(x, y) = parsePublic(key) else return false;
    if (digest.size() != 32) return false;
    let ?(r, s) = parseSignature(signature) else return false;
    // The equation on mo:ecdsa's curve arithmetic, not its PublicKey.verifyHashed, which
    // rejects the valid signatures with s = (n-1)/2 or (n+1)/2 (its low-S normalisation, above).
    let z = beNat(digest.toArray(), 0, 32) % N;
    let w = curve.Fr.inv(#fr(s));
    let u1 = curve.Fr.mul(#fr(z), w);
    let u2 = curve.Fr.mul(#fr(r), w);
    switch (curve.fromJacobi(curve.add(curve.mul_base(u1), curve.mul((#fp(x), #fp(y), #fp(1)), u2)))) {
      case (#affine(#fp(rx), _)) rx % N == r;
      case (#zero) false;
    };
  };
};
