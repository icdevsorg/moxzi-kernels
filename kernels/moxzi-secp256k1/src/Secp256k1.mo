import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import VarArray "mo:core/VarArray";
import Curve "mo:ecdsa/Curve";
import EcdsaPrivateKey "mo:ecdsa/PrivateKey";
import EcdsaPublicKey "mo:ecdsa/PublicKey";
import EcdsaSignature "mo:ecdsa/Signature";
import Der "mo:bitcoin/ecdsa/Der";
import Hash "mo:bitcoin/Hash";
import Hmac "mo:bitcoin/Hmac";

/// secp256k1: SEC1 public keys, point arithmetic, RFC 6979 ECDSA over 32-byte digests, and
/// BIP340 Schnorr signatures.
///
/// With the `moxzi-secp256k1` kernel opted in (`[kernels]` in the application's mops.toml),
/// moxzi runs each function natively (RustCrypto `k256` 0.13.4 for scalars, signatures and
/// hashes; `libsecp256k1-core` 0.3.0 for the point arithmetic). Otherwise -- under moc, or
/// without the opt-in -- the Motoko bodies below run, built on `mo:ecdsa` 8.0.1's curve
/// arithmetic, private key and signature code, and `mo:bitcoin` 0.2.1's HMAC, tagged hash and
/// DER code. Neither library has RFC 6979 nonces or BIP340 signatures: those bodies follow the
/// RFC and BIP reference algorithms on the libraries' primitives. Both paths accept, reject and
/// trap identically.
///
/// Encodings:
/// - secret keys: 32 big-endian bytes in [1, n);
/// - scalars (tweaks, multipliers): 32 big-endian bytes in [0, n);
/// - public keys: canonical SEC1, compressed (33 bytes, 02/03) or uncompressed (65 bytes, 04);
///   hybrid, compact and identity encodings are refused; results are compressed unless named;
/// - ECDSA signatures: 64 bytes r || s, r and s in [1, n); DER is strict (minimal) DER;
/// - BIP340: 32-byte x-only keys, 64-byte signatures, messages of any length.
///
/// Errors: bad input to a function that is not a predicate traps with
/// "Secp256k1.<function>: <reason>"; `verifyPrehash` and `schnorrVerify` return false for any
/// bad input; a point at infinity (or a zero tweaked secret key) is `null`.
///
/// Not constant-time without the kernel (Motoko `Nat` arithmetic): keep secret keys where
/// timing cannot be observed.
module {
  // mo:ecdsa's curve; a class, so built per call (a module may hold only static values).
  func mkCurve() : Curve.Curve = Curve.secp256k1();
  let P : Nat = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
  let N : Nat = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
  let HALF_N : Nat = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0; // (n-1)/2: s above it is "high"

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
    if (b.size() != 32) Runtime.trap("Secp256k1." # fn # ": invalid secret key");
    let d = beNat(b.toArray(), 0, 32);
    if (d == 0 or d >= N) Runtime.trap("Secp256k1." # fn # ": invalid secret key");
    d;
  };

  func scalarOf(b : Blob, fn : Text) : Nat {
    if (b.size() != 32) Runtime.trap("Secp256k1." # fn # ": invalid scalar");
    let k = beNat(b.toArray(), 0, 32);
    if (k >= N) Runtime.trap("Secp256k1." # fn # ": invalid scalar");
    k;
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

  func publicOf(b : Blob, fn : Text) : Curve.Jacobi {
    switch (parsePublic(b)) {
      case (?(x, y)) (#fp(x), #fp(y), #fp(1));
      case null Runtime.trap("Secp256k1." # fn # ": invalid public key");
    };
  };

  /// BIP340 lift_x: the point with x-coordinate `b` and an even y.
  func liftX(b : Blob) : ?(Nat, Nat) {
    let curve = mkCurve();
    if (b.size() != 32) return null;
    let x = beNat(b.toArray(), 0, 32);
    if (x >= P) return null;
    switch (curve.getYfromX(#fp(x), true)) {
      case (?#fp(y)) ?(x, y);
      case null null;
    };
  };

  func encode(x : Nat, y : Nat, compressed : Bool) : Blob {
    Array.toBlob(
      if (compressed) cat([[if (y % 2 == 0) 2 else 3], beBytes(x, 32)])
      else cat([[4], beBytes(x, 32), beBytes(y, 32)])
    );
  };

  func affine(j : Curve.Jacobi) : ?(Nat, Nat) {
    let curve = mkCurve();
    switch (curve.fromJacobi(j)) {
      case (#affine(#fp(x), #fp(y))) ?(x, y);
      case (#zero) null;
    };
  };

  /// A compressed point, or null at infinity.
  func pointOrNull(j : Curve.Jacobi) : ?Blob {
    switch (affine(j)) {
      case (?(x, y)) ?encode(x, y, true);
      case null null;
    };
  };

  func encodeJ(j : Curve.Jacobi, compressed : Bool) : Blob {
    switch (affine(j)) {
      case (?(x, y)) encode(x, y, compressed);
      case null Runtime.trap("Secp256k1: unexpected point at infinity");
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
      case null Runtime.trap("Secp256k1." # fn # ": invalid signature");
    };
  };

  func compact(r : Nat, s : Nat) : Blob = cat([beBytes(r, 32), beBytes(s, 32)]).toBlob();

  func hmac(key : [Nat8], data : [Nat8]) : [Nat8] {
    let h = Hmac.sha256(key);
    h.writeArray(data);
    h.sum().toArray();
  };

  /// BIP340 tagged hash (mo:bitcoin's).
  func tagged(tag : Text, data : [Nat8]) : [Nat8] = Hash.taggedHash(data, tag);

  /// The 65-byte uncompressed public key of a secret key.
  public func publicKey(secret : Blob) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "publicKey");
    encodeJ(curve.mul_base(#fr(d)), false);
  };

  /// The 33-byte compressed public key of a secret key.
  public func derivePublicKey(secret : Blob) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "derivePublicKey");
    encodeJ(curve.mul_base(#fr(d)), true);
  };

  /// A public key in its 33-byte compressed form.
  public func compressPublicKey(key : Blob) : Blob = encodeJ(publicOf(key, "compressPublicKey"), true);

  /// A public key in its 65-byte uncompressed form.
  public func decompressPublicKey(key : Blob) : Blob = encodeJ(publicOf(key, "decompressPublicKey"), false);

  /// A public key compressed (33 bytes) or uncompressed (65 bytes).
  public func convertPublicKey(key : Blob, compressed : Bool) : Blob = encodeJ(publicOf(key, "convertPublicKey"), compressed);

  /// The 32-byte x coordinate of a public key (its BIP340 x-only form).
  public func xOnlyPublicKey(key : Blob) : Blob {
    let (#fp(x), _, _) = publicOf(key, "xOnlyPublicKey");
    beBytes(x, 32).toBlob();
  };

  /// a + b; null at infinity.
  public func pointAdd(a : Blob, b : Blob) : ?Blob {
    let curve = mkCurve();
    let p = publicOf(a, "pointAdd");
    let q = publicOf(b, "pointAdd");
    pointOrNull(curve.add(p, q));
  };

  /// scalar * key; null at infinity (a zero scalar).
  public func pointMultiply(key : Blob, scalar : Blob) : ?Blob {
    let curve = mkCurve();
    let p = publicOf(key, "pointMultiply");
    let k = scalarOf(scalar, "pointMultiply");
    pointOrNull(curve.mul(p, #fr(k)));
  };

  /// scalar * G; null for a zero scalar.
  public func baseMultiply(scalar : Blob) : ?Blob {
    let curve = mkCurve();
    let k = scalarOf(scalar, "baseMultiply");
    pointOrNull(curve.mul_base(#fr(k)));
  };

  /// key + tweak * G; null at infinity.
  public func tweakPublicKey(key : Blob, tweak : Blob) : ?Blob {
    let curve = mkCurve();
    let p = publicOf(key, "tweakPublicKey");
    let t = scalarOf(tweak, "tweakPublicKey");
    pointOrNull(curve.add(p, curve.mul_base(#fr(t))));
  };

  /// lift_x(key) + tweak * G (BIP341 taproot output key), compressed so the parity is kept;
  /// null at infinity.
  public func tweakXOnlyPublicKey(key : Blob, tweak : Blob) : ?Blob {
    let curve = mkCurve();
    let (x, y) = switch (liftX(key)) {
      case (?xy) xy;
      case null Runtime.trap("Secp256k1.tweakXOnlyPublicKey: invalid x-only public key");
    };
    let t = scalarOf(tweak, "tweakXOnlyPublicKey");
    pointOrNull(curve.add((#fp(x), #fp(y), #fp(1)), curve.mul_base(#fr(t))));
  };

  /// The BIP341 tweaked secret key: d negated if d * G has an odd y, plus tweak; null if zero.
  public func tweakXOnlySecretKey(secret : Blob, tweak : Blob) : ?Blob {
    let curve = mkCurve();
    let d0 = secretOf(secret, "tweakXOnlySecretKey");
    let t = scalarOf(tweak, "tweakXOnlySecretKey");
    let d = switch (affine(curve.mul_base(#fr(d0)))) {
      case (?(_, y)) if (y % 2 == 1) (N - d0 : Nat) else d0;
      case null d0;
    };
    let r = (d + t) % N;
    if (r == 0) null else ?beBytes(r, 32).toBlob();
  };

  /// The low-S form of a signature (s replaced by n - s when s > n/2).
  public func normalizeSignature(signature : Blob) : Blob {
    let curve = mkCurve();
    let (r, s) = signatureOf(signature, "normalizeSignature");
    // mo:ecdsa's Signature keeps min(s, n - s) in `s`.
    compact(r, EcdsaSignature.Signature(r, s, curve).s);
  };

  /// A strict DER signature as 64 bytes r || s; null unless `der` is the minimal DER encoding
  /// of r, s in [1, n) with nothing after it.
  public func signatureFromDer(der : Blob) : ?Blob {
    // mo:bitcoin's decoder accepts non-minimal integers; strict DER is exactly "re-encoding
    // the decoded values gives the input back".
    let #ok({ r; s }) = Der.decodeSignature(der) else return null;
    if (r == 0 or r >= N or s == 0 or s >= N) return null;
    let sig = compact(r, s);
    if (Der.encodeSignature(sig) != der) return null;
    ?sig;
  };

  /// The minimal DER encoding of a 64-byte signature.
  public func signatureToDer(signature : Blob) : Blob {
    ignore signatureOf(signature, "signatureToDer");
    Der.encodeSignature(signature);
  };

  /// RFC 6979 deterministic ECDSA (HMAC-SHA-256) over a 32-byte digest; the low-S signature
  /// r || s.
  public func signPrehash(secret : Blob, digest : Blob) : Blob {
    let curve = mkCurve();
    let d = secretOf(secret, "signPrehash");
    if (digest.size() != 32) Runtime.trap("Secp256k1.signPrehash: the digest must be 32 bytes");
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
    switch (EcdsaPrivateKey.PrivateKey(d, curve).signHashed(digest.values(), beBytes(nonce, 32).values())) {
      case (#ok(sig)) {
        if (sig.s == 0) Runtime.trap("Secp256k1.signPrehash: signing failed");
        compact(sig.r, sig.s); // mo:ecdsa keeps the low-S form in `s`
      };
      case (#err(_)) Runtime.trap("Secp256k1.signPrehash: signing failed");
    };
  };

  /// ECDSA verification of a 64-byte signature over a 32-byte digest. As in libsecp256k1 and
  /// k256, a high-S signature is refused (normalize it first). False for any bad input.
  public func verifyPrehash(key : Blob, digest : Blob, signature : Blob) : Bool {
    let curve = mkCurve();
    let ?(x, y) = parsePublic(key) else return false;
    if (digest.size() != 32) return false;
    let ?(r, s) = parseSignature(signature) else return false;
    if (s > HALF_N) return false;
    EcdsaPublicKey.PublicKey(x, y, curve).verifyHashed(digest.values(), EcdsaSignature.Signature(r, s, curve));
  };

  /// BIP340 signature of `message` with the 32 bytes of auxiliary randomness `aux` (the
  /// reference signing algorithm; deterministic for a given `aux`).
  public func schnorrSign(secret : Blob, message : Blob, aux : Blob) : Blob {
    let curve = mkCurve();
    let d0 = secretOf(secret, "schnorrSign");
    if (aux.size() != 32) Runtime.trap("Secp256k1.schnorrSign: the auxiliary randomness must be 32 bytes");
    let m = message.toArray();
    let ?(px, py) = affine(curve.mul_base(#fr(d0))) else Runtime.trap("Secp256k1.schnorrSign: signing failed");
    let d = if (py % 2 == 1) (N - d0 : Nat) else d0;
    let db = beBytes(d, 32);
    let a = tagged("BIP0340/aux", aux.toArray());
    let t = Array.tabulate<Nat8>(32, func i = db[i] ^ a[i]);
    let pxb = beBytes(px, 32);
    let k0 = beNat(tagged("BIP0340/nonce", cat([t, pxb, m])), 0, 32) % N;
    if (k0 == 0) Runtime.trap("Secp256k1.schnorrSign: signing failed");
    let ?(rx, ry) = affine(curve.mul_base(#fr(k0))) else Runtime.trap("Secp256k1.schnorrSign: signing failed");
    let k = if (ry % 2 == 1) (N - k0 : Nat) else k0;
    let rxb = beBytes(rx, 32);
    let e = beNat(tagged("BIP0340/challenge", cat([rxb, pxb, m])), 0, 32) % N;
    cat([rxb, beBytes((k + e * d) % N, 32)]).toBlob();
  };

  /// BIP340 verification (the reference algorithm). False for any bad input.
  public func schnorrVerify(key : Blob, message : Blob, signature : Blob) : Bool {
    let curve = mkCurve();
    if (signature.size() != 64) return false;
    let ?(px, py) = liftX(key) else return false;
    let sig = signature.toArray();
    let r = beNat(sig, 0, 32);
    if (r >= P) return false;
    let s = beNat(sig, 32, 32);
    if (s >= N) return false;
    let e = beNat(tagged("BIP0340/challenge", cat([Array.tabulate<Nat8>(32, func i = sig[i]), key.toArray(), message.toArray()])), 0, 32) % N;
    let rj = curve.add(curve.mul_base(#fr(s)), curve.mul((#fp(px), #fp(py), #fp(1)), #fr((N - e : Nat) % N)));
    switch (affine(rj)) {
      case (?(x, y)) y % 2 == 0 and x == r;
      case null false;
    };
  };
};
