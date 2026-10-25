// Verbatim copy of mo:ic-agent 0.2.0 src/Ed25519.mo (https://github.com/icdevsorg/ic-agent-mo),
// ICDevs.org, Apache-2.0. Copied, not imported: ic-agent 0.2.0 depends on sha2 0.2.5, and an application
// could then not also use mo:bitcoin 0.2.1 (sha2 0.1.x API), e.g. through moxzi-secp256k1.
/// Ed25519 (RFC 8032): verification (5.1.7) for query-response node signatures, and signing
/// (5.1.6) for `Identity.ed25519`. `verify` is total (false on any malformed input, never a
/// trap). Both are fast: field elements are `Nat` reduced mod p, the representation `mo:bls12-381` measured
/// ~80x faster than fixed-width limbs in pure Motoko.
///
/// Why not `mo:ed25519.verify` (measured 2026-09-24): it traps on malformed input; it costs over
/// 2 seconds per verification under moxzid (400 did not finish in 15 minutes), against 155
/// million instructions for a whole node-signature check here; and in one gate run of three
/// it REJECTED a genuine PocketIC node signature, in the moxzi-built client. A pre-check of
/// the inputs accepted all 400 OpenSSL signatures in a differential run, so the rejection came
/// from the library as built there (not yet isolated between the library and its compilation).
/// Its SIGNING was wrong too: a 100-message differential against OpenSSL found 3 invalid
/// signatures, every one with a nonce r < 2^248 (a zero top byte; about 1 message in 24),
/// identically under moc and moxzi -- a library bug, not a compiler one, and the same fault
/// behind the verification failure. This file replaces the package entirely.
///
/// The check is RFC 8032's: decode A and R canonically (y < p, a square root exists, no
/// "negative zero"), require s < L, k = SHA-512(R ‖ A ‖ M) mod L over the ORIGINAL bytes, and
/// accept iff [s]B = R + [k]A. That is the strict cofactorless equation, which every honest
/// signer satisfies; small-order public keys are refused. Cross-checked against RFC 8032 test
/// vector 1 and ICDevs' `ic-ed25519` (system repository) rejection cases.
import Sha512 "mo:sha2/Sha512";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";

module {
  let P : Nat = 57896044618658097711785492504343953926634992332820282019728792003956564819949; // 2^255 - 19
  let L : Nat = 7237005577332262213973186563042994240857116359379907606001950938285454250989;
  let D : Nat = 37095705934669439343138083508754565189542113879843219016388785533085940283555; // -121665/121666
  let D2 : Nat = 16295367250680780974490674513165176452449235426866156013048779062215315747161; // 2d mod p
  let SQRT_M1 : Nat = 19681161376707505956807079304988542015446066515923890162744021073123829784752;
  let BX : Nat = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
  let BY : Nat = 46316835694926478169428394003475163141307993866256225615783033603165251855960;

  /// Extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z.
  type Point = (Nat, Nat, Nat, Nat);

  func add(a : Nat, b : Nat) : Nat { let s = a + b; if (s >= P) s - P else s };
  func sub(a : Nat, b : Nat) : Nat = if (a >= b) a - b else a + P - b;
  func mul(a : Nat, b : Nat) : Nat = (a * b) % P;

  func pow(b : Nat, e : Nat) : Nat {
    var result = 1;
    var base = b % P;
    var exp = e;
    while (exp > 0) {
      if (exp % 2 == 1) result := mul(result, base);
      base := mul(base, base);
      exp /= 2;
    };
    result
  };

  /// add-2008-hwcd-3 (a = -1), complete for points of the prime-order group and its cosets.
  func padd(p : Point, q : Point) : Point {
    let (x1, y1, z1, t1) = p;
    let (x2, y2, z2, t2) = q;
    let a = mul(sub(y1, x1), sub(y2, x2));
    let b = mul(add(y1, x1), add(y2, x2));
    let c = mul(mul(t1, D2), t2);
    let d = mul(add(z1, z1), z2);
    let e = sub(b, a);
    let f = sub(d, c);
    let g = add(d, c);
    let h = add(b, a);
    (mul(e, f), mul(g, h), mul(f, g), mul(e, h))
  };

  /// dbl-2008-hwcd (a = -1).
  func pdouble(p : Point) : Point {
    let (x1, y1, z1, _) = p;
    let a = mul(x1, x1);
    let b = mul(y1, y1);
    let c = mul(2, mul(z1, z1));
    let dd = sub(0, a);                     // a·X² with a = -1
    let xy = add(x1, y1);
    let e = sub(sub(mul(xy, xy), a), b);
    let g = add(dd, b);
    let f = sub(g, c);
    let h = sub(dd, b);
    (mul(e, f), mul(g, h), mul(f, g), mul(e, h))
  };

  func neg(p : Point) : Point { let (x, y, z, t) = p; (sub(0, x), y, z, sub(0, t)) };

  let IDENTITY : Point = (0, 1, 1, 0);
  let BASE : Point = (BX, BY, 1, 46827403850823179245072216630277197565144205554125654976674165829533817101731); // T = x·y mod p

  func leNat(bytes : [Nat8], from : Nat, len : Nat) : Nat {
    var n = 0;
    var i = len;
    while (i > 0) { i -= 1; n := n * 256 + Nat8.toNat(bytes[from + i]) };
    n
  };

  /// RFC 8032 5.1.3 point decoding; null for anything that is not a canonical point encoding.
  func decode(bytes : [Nat8], from : Nat) : ?Point {
    let top = Nat8.toNat(bytes[from + 31]);
    let sign = top / 128;
    let y = leNat(bytes, from, 32) % (2 ** 255);
    if (y >= P) return null;
    let y2 = mul(y, y);
    let u = sub(y2, 1);
    let v = add(mul(D, y2), 1);
    let v3 = mul(mul(v, v), v);
    let v7 = mul(mul(v3, v3), v);
    var x = mul(mul(u, v3), pow(mul(u, v7), (P - 5) / 8));
    let vx2 = mul(v, mul(x, x));
    if (vx2 == u) {} else if (vx2 == sub(0, u)) { x := mul(x, SQRT_M1) } else return null;
    if (x == 0 and sign == 1) return null;
    if (x % 2 != sign) x := sub(0, x);
    ?(x, y, 1, mul(x, y))
  };

  func bitsOf(n : Nat) : [Bool] {
    var m = n;
    var out : [Bool] = [];
    let buf = Array.init<Bool>(256, false);
    var len = 0;
    while (m > 0 and len < 256) { buf[len] := m % 2 == 1; m /= 2; len += 1 };
    out := Array.tabulate<Bool>(len, func(i) = buf[i]);
    out
  };

  /// [a]P + [b]Q by one joint double-and-add pass (Straus/Shamir). a, b < 2^256.
  func doubleScalarMul(a : Nat, p : Point, b : Nat, q : Point) : Point {
    let pq = padd(p, q);
    let ba = bitsOf(a);
    let bb = bitsOf(b);
    var acc = IDENTITY;
    var i = if (ba.size() > bb.size()) ba.size() else bb.size();
    while (i > 0) {
      i -= 1;
      acc := pdouble(acc);
      let bitA = i < ba.size() and ba[i];
      let bitB = i < bb.size() and bb[i];
      if (bitA and bitB) acc := padd(acc, pq)
      else if (bitA) acc := padd(acc, p)
      else if (bitB) acc := padd(acc, q);
    };
    acc
  };

  func leBytes(n : Nat, len : Nat) : [Nat8] {
    var m = n;
    Array.tabulate<Nat8>(len, func(_) { let b = Nat8.fromNat(m % 256); m /= 256; b })
  };

  /// RFC 8032 5.1.2 point encoding: y little-endian, the sign of x in the top bit.
  func encode(p : Point) : [Nat8] {
    let (x, y, z, _) = p;
    let zi = pow(z, P - 2);
    let ax = mul(x, zi);
    let ay = mul(y, zi);
    let out = Array.thaw<Nat8>(leBytes(ay, 32));
    if (ax % 2 == 1) out[31] |= 0x80;
    Array.freeze(out)
  };

  func scalarMulBase(n : Nat) : Point = doubleScalarMul(n, BASE, 0, IDENTITY);

  func sha512(parts : [[Nat8]]) : [Nat8] = Blob.toArray(Sha512.fromBlob(#sha512, Blob.fromArray(Array.flatten<Nat8>(parts))));

  /// RFC 8032 5.1.5: the secret scalar (clamped) and the nonce prefix from a 32-byte seed.
  func expand(seed : Blob) : (Nat, [Nat8]) {
    let h = sha512([Blob.toArray(seed)]);
    var a = leNat(h, 0, 32);
    a := a % (2 ** 254);                 // clear bit 255 (and 254, set again below)
    a := a - (a % 8) + (2 ** 254);       // clear the low 3 bits, set bit 254
    (a, Array.tabulate<Nat8>(32, func(i) = h[32 + i]))
  };

  /// The 32-byte public key of a 32-byte seed. Traps on a seed of any other size (a caller
  /// bug, not hostile input).
  public func publicKey(seed : Blob) : Blob {
    assert seed.size() == 32;
    let (a, _) = expand(seed);
    Blob.fromArray(encode(scalarMulBase(a)))
  };

  /// RFC 8032 5.1.6 signing. Deterministic; NOT constant-time (Motoko `Nat` arithmetic), so
  /// keep secret keys where timing cannot be observed -- the same property the `mo:ed25519`
  /// package it replaces had. Replaces that package because it produced an INVALID signature
  /// whenever the nonce r had a zero top byte (r < 2^248, about 1 message in 24): measured
  /// 2026-09-24, 3 of 100 messages differed from OpenSSL, identically under moc and moxzi.
  public func sign(seed : Blob, msg : Blob) : Blob {
    assert seed.size() == 32;
    let (a, prefix) = expand(seed);
    let aBytes = encode(scalarMulBase(a));
    let m = Blob.toArray(msg);
    let r = leNat(sha512([prefix, m]), 0, 64) % L;
    let rBytes = encode(scalarMulBase(r));
    let k = leNat(sha512([rBytes, aBytes, m]), 0, 64) % L;
    let sScalar = (r + k * a) % L;
    Blob.fromArray(Array.flatten<Nat8>([rBytes, leBytes(sScalar, 32)]))
  };

  /// True iff `sig` (64 bytes, R ‖ s) is a valid Ed25519 signature of `msg` under the raw
  /// 32-byte public key `pub`. False, never a trap, for any malformed input.
  public func verify(sig : Blob, msg : Blob, pub : Blob) : Bool {
    if (sig.size() != 64 or pub.size() != 32) return false;
    let sb = Blob.toArray(sig);
    let pb = Blob.toArray(pub);
    let s = leNat(sb, 32, 32);
    if (s >= L) return false;
    let ?a = decode(pb, 0) else return false;
    // A small-order public key (the identity or another torsion point) satisfies the
    // cofactorless equation for forged signatures: [8]A = O means reject. (ICDevs' ic-ed25519
    // rejects these too, by a full [L]A torsion check; [8]A is enough to close the forgery.)
    let (a8x, a8y, a8z, _) = pdouble(pdouble(pdouble(a)));
    if (a8x == 0 and a8y == a8z) return false;
    let ?r = decode(sb, 0) else return false;
    let rBytes = Array.tabulate<Nat8>(32, func(i) = sb[i]);
    let h = Blob.toArray(Sha512.fromBlob(#sha512, Blob.fromArray(Array.flatten<Nat8>([rBytes, pb, Blob.toArray(msg)]))));
    let k = leNat(h, 0, 64) % L;
    // [s]B - [k]A must equal R.
    let (x, y, z, _) = doubleScalarMul(s, BASE, k, neg(a));
    let (rx, ry, _, _) = r;
    mul(x, 1) == mul(rx, z) and mul(y, 1) == mul(ry, z)
  };
}
