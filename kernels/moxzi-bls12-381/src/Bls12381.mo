/// BLS12-381: Ethereum BLS signatures, group arithmetic, RFC 9380 hashing and pairing checks.
///
/// With the moxzi-bls12-381 native kernel opted in (`[kernels]` in the application's mops.toml)
/// every function runs natively (zkcrypto `bls12_381` 0.8.0); otherwise, and under moc, these
/// bodies run, built on `mo:bls12-381` 0.2.0. Both agree on every input, including bad ones.
///
/// Encodings:
/// - G1 point: 48 bytes, G2 point: 96 bytes, compressed with the IETF / Zcash flags (G2: the
///   imaginary part of x first). A point must be canonical, on the curve and in the prime-order
///   subgroup. The identity (`0xc0` then zeros) is a valid group element.
/// - Scalar: 32 bytes big-endian, below the group order r.
/// - Field element (`mapToG1`): 48 bytes big-endian below p; Fp2 (`mapToG2`): 96 bytes, the real
///   part c0 first, then c1.
/// - Lists are one Blob of concatenated fixed-size items: G1 points n x 48 bytes, G2 points
///   n x 96, scalars n x 32, Ethereum aggregate messages n x 32 (signing roots), pairing terms
///   n x 144 (a G1 point, then a G2 point).
///
/// Group operations return `null` on any invalid input: a wrong length (including a list whose
/// length is not a multiple of its item size, or point and scalar lists of different counts), an
/// invalid point, a scalar >= r, a field element >= p. Verification and `pairingCheck` return
/// `false` on any invalid input.
///
/// Ethereum signatures use the proof-of-possession ciphersuite: public keys in G1, signatures in
/// G2, `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` for messages and
/// `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` for proofs. Public keys and signatures must not
/// be the identity. The aggregate functions assume every key's proof of possession has been
/// checked (`verifyEthereumProof`), as the ciphersuite requires.
///
/// Cost: without the kernel, one signature verification is about two pairings plus a hash to G2
/// in Motoko, on the order of a billion instructions; large aggregates and MSMs can exceed one
/// message's limit. The kernel is roughly two orders of magnitude cheaper.
import BLS "mo:bls12-381";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import C "internal/Codec";

module {
  let ETH_DST : Blob = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
  let ETH_POP_DST : Blob = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

  func key(b : [Nat8]) : ?BLS.G1Point {
    let ?p = C.g1(b) else return null;
    if (BLS.g1_is_inf(p)) null else ?p;
  };

  func sig(b : [Nat8]) : ?BLS.G2Point {
    let ?p = C.g2(b) else return null;
    if (BLS.g2_is_inf(p)) null else ?p;
  };

  /// e(pk, H(msg)) == e(g1, sig)
  func coreVerify(pk : BLS.G1Point, msg : [Nat8], s : BLS.G2Point, dst : Blob) : Bool {
    BLS.pairing_check([(pk, C.hashToG2(msg, Blob.toArray(dst))), (BLS.g1_neg(BLS.G1_GEN), s)]);
  };

  /// Verify an Ethereum BLS signature (96 bytes) on `message` under a public key (48 bytes).
  public func verifyEthereum(publicKey : Blob, message : Blob, signature : Blob) : Bool {
    let ?pk = key(Blob.toArray(publicKey)) else return false;
    let ?s = sig(Blob.toArray(signature)) else return false;
    coreVerify(pk, Blob.toArray(message), s, ETH_DST);
  };

  /// Verify a proof of possession (96 bytes) of the secret key behind `publicKey` (48 bytes).
  public func verifyEthereumProof(publicKey : Blob, proof : Blob) : Bool {
    let pkBytes = Blob.toArray(publicKey);
    let ?pk = key(pkBytes) else return false;
    let ?s = sig(Blob.toArray(proof)) else return false;
    coreVerify(pk, pkBytes, s, ETH_POP_DST);
  };

  /// Verify an aggregate signature over n distinct (key, message) pairs: `publicKeys` is n x 48
  /// bytes, `messages` n x 32 bytes (n >= 1).
  public func aggregateVerifyEthereum(publicKeys : Blob, messages : Blob, signature : Blob) : Bool {
    let (pks, msgs) = (Blob.toArray(publicKeys), Blob.toArray(messages));
    let n = pks.size() / 48;
    if (n == 0 or pks.size() % 48 != 0 or msgs.size() != 32 * n) return false;
    let ?s = sig(Blob.toArray(signature)) else return false;
    let terms = Array.tabulate<?(BLS.G1Point, BLS.G2Point)>(n, func i {
      let ?pk = key(C.slice(pks, 48 * i, 48)) else return null;
      ?(pk, C.hashToG2(C.slice(msgs, 32 * i, 32), Blob.toArray(ETH_DST)));
    });
    let checked = Array.filterMap<?(BLS.G1Point, BLS.G2Point), (BLS.G1Point, BLS.G2Point)>(terms, func t = t);
    if (checked.size() != n) return false;
    BLS.pairing_check(Array.concat(checked, [(BLS.g1_neg(BLS.G1_GEN), s)]));
  };

  /// Verify an aggregate signature by n keys (n x 48 bytes, n >= 1) on one message.
  public func fastAggregateVerifyEthereum(publicKeys : Blob, message : Blob, signature : Blob) : Bool {
    let pks = Blob.toArray(publicKeys);
    if (pks.size() == 0 or pks.size() % 48 != 0) return false;
    var sum = BLS.G1_INF;
    var i = 0;
    while (i < pks.size()) {
      let ?pk = key(C.slice(pks, i, 48)) else return false;
      sum := BLS.g1_add(sum, pk);
      i += 48;
    };
    let ?s = sig(Blob.toArray(signature)) else return false;
    if (BLS.g1_is_inf(sum)) return false;
    coreVerify(sum, Blob.toArray(message), s, ETH_DST);
  };

  func g1List(b : [Nat8]) : ?[BLS.G1Point] {
    if (b.size() % 48 != 0) return null;
    let n = b.size() / 48;
    let ps = Array.filterMap<Nat, BLS.G1Point>(Array.tabulate<Nat>(n, func i = i), func i = C.g1(C.slice(b, 48 * i, 48)));
    if (ps.size() == n) ?ps else null;
  };

  func g2List(b : [Nat8]) : ?[BLS.G2Point] {
    if (b.size() % 96 != 0) return null;
    let n = b.size() / 96;
    let ps = Array.filterMap<Nat, BLS.G2Point>(Array.tabulate<Nat>(n, func i = i), func i = C.g2(C.slice(b, 96 * i, 96)));
    if (ps.size() == n) ?ps else null;
  };

  func scalarList(b : [Nat8]) : ?[Nat] {
    if (b.size() % 32 != 0) return null;
    let n = b.size() / 32;
    let ss = Array.filterMap<Nat, Nat>(Array.tabulate<Nat>(n, func i = i), func i = C.scalar(C.slice(b, 32 * i, 32)));
    if (ss.size() == n) ?ss else null;
  };

  /// a + b in G1.
  public func g1Add(a : Blob, b : Blob) : ?Blob {
    let ?p = C.g1(Blob.toArray(a)) else return null;
    let ?q = C.g1(Blob.toArray(b)) else return null;
    ?C.encodeG1(BLS.g1_add(p, q));
  };

  /// The sum of n G1 points (n x 48 bytes; the empty list sums to the identity).
  public func g1Aggregate(points : Blob) : ?Blob {
    let ?ps = g1List(Blob.toArray(points)) else return null;
    var sum = BLS.G1_INF;
    for (p in ps.values()) sum := BLS.g1_add(sum, p);
    ?C.encodeG1(sum);
  };

  /// s * p in G1.
  public func g1Mul(point : Blob, scalar : Blob) : ?Blob {
    let ?p = C.g1(Blob.toArray(point)) else return null;
    let ?s = C.scalar(Blob.toArray(scalar)) else return null;
    ?C.encodeG1(BLS.g1_mul(p, s));
  };

  /// sum s_i * p_i in G1: n points (n x 48 bytes) and n scalars (n x 32 bytes).
  /// Not constant time: its cost depends on the scalars, so it is for public scalars
  /// (verification, aggregation weights). For a secret scalar use `g1Mul`, whose native
  /// kernel cost does not depend on the scalar.
  public func g1Msm(points : Blob, scalars : Blob) : ?Blob {
    let (pb, sb) = (Blob.toArray(points), Blob.toArray(scalars));
    if (pb.size() % 48 != 0 or sb.size() % 32 != 0 or pb.size() / 48 != sb.size() / 32) return null;
    let ?ps = g1List(pb) else return null;
    let ?ss = scalarList(sb) else return null;
    ?C.encodeG1(BLS.g1_msm(ps, ss));
  };

  /// a + b in G2.
  public func g2Add(a : Blob, b : Blob) : ?Blob {
    let ?p = C.g2(Blob.toArray(a)) else return null;
    let ?q = C.g2(Blob.toArray(b)) else return null;
    ?C.encodeG2(BLS.g2_add(p, q));
  };

  /// The sum of n G2 points (n x 96 bytes; the empty list sums to the identity).
  public func g2Aggregate(points : Blob) : ?Blob {
    let ?ps = g2List(Blob.toArray(points)) else return null;
    var sum = BLS.G2_INF;
    for (p in ps.values()) sum := BLS.g2_add(sum, p);
    ?C.encodeG2(sum);
  };

  /// s * p in G2.
  public func g2Mul(point : Blob, scalar : Blob) : ?Blob {
    let ?p = C.g2(Blob.toArray(point)) else return null;
    let ?s = C.scalar(Blob.toArray(scalar)) else return null;
    ?C.encodeG2(BLS.g2_mul(p, s));
  };

  /// sum s_i * p_i in G2: n points (n x 96 bytes) and n scalars (n x 32 bytes).
  /// Not constant time: its cost depends on the scalars, so it is for public scalars
  /// (verification, aggregation weights). For a secret scalar use `g2Mul`, whose native
  /// kernel cost does not depend on the scalar.
  public func g2Msm(points : Blob, scalars : Blob) : ?Blob {
    let (pb, sb) = (Blob.toArray(points), Blob.toArray(scalars));
    if (pb.size() % 96 != 0 or sb.size() % 32 != 0 or pb.size() / 96 != sb.size() / 32) return null;
    let ?ps = g2List(pb) else return null;
    let ?ss = scalarList(sb) else return null;
    ?C.encodeG2(BLS.g2_msm(ps, ss));
  };

  /// Whether `point` is a valid 48-byte G1 encoding (canonical, on the curve, in the subgroup).
  public func validateG1(point : Blob) : Bool = C.g1(Blob.toArray(point)) != null;

  /// Whether `point` is a valid 96-byte G2 encoding (canonical, on the curve, in the subgroup).
  public func validateG2(point : Blob) : Bool = C.g2(Blob.toArray(point)) != null;

  /// RFC 9380 map_to_curve then clear_cofactor for G1 (EIP-2537's MAP_FP_TO_G1), from a 48-byte
  /// field element.
  public func mapToG1(element : Blob) : ?Blob {
    let b = Blob.toArray(element);
    if (b.size() != 48) return null;
    let ?u = C.fp(b, 0) else return null;
    ?C.encodeG1(BLS.map_fp_to_g1(u));
  };

  /// RFC 9380 map_to_curve then clear_cofactor for G2 (EIP-2537's MAP_FP2_TO_G2), from a 96-byte
  /// Fp2 element (c0, then c1).
  public func mapToG2(element : Blob) : ?Blob {
    let b = Blob.toArray(element);
    if (b.size() != 96) return null;
    let ?c0 = C.fp(b, 0) else return null;
    let ?c1 = C.fp(b, 48) else return null;
    ?C.encodeG2(BLS.map_fp2_to_g2((c0, c1)));
  };

  /// RFC 9380 hash_to_curve, suite BLS12381G1_XMD:SHA-256_SSWU_RO_, with domain separation tag
  /// `dst` (a tag over 255 bytes is hashed as RFC 9380 5.3.3 says). 48 bytes.
  public func hashToG1(message : Blob, dst : Blob) : Blob = C.encodeG1(C.hashToG1(Blob.toArray(message), Blob.toArray(dst)));

  /// RFC 9380 hash_to_curve, suite BLS12381G2_XMD:SHA-256_SSWU_RO_. 96 bytes.
  public func hashToG2(message : Blob, dst : Blob) : Blob = C.encodeG2(C.hashToG2(Blob.toArray(message), Blob.toArray(dst)));

  /// Whether prod e(p_i, q_i) == 1 for n terms (n x 144 bytes: a G1 point, then a G2 point).
  /// The empty product is 1 (true).
  public func pairingCheck(terms : Blob) : Bool {
    let b = Blob.toArray(terms);
    if (b.size() % 144 != 0) return false;
    let n = b.size() / 144;
    let ts = Array.filterMap<Nat, (BLS.G1Point, BLS.G2Point)>(Array.tabulate<Nat>(n, func i = i), func i {
      let ?p = C.g1(C.slice(b, 144 * i, 48)) else return null;
      let ?q = C.g2(C.slice(b, 144 * i + 48, 96)) else return null;
      ?(p, q);
    });
    if (ts.size() != n) return false;
    BLS.pairing_check(ts);
  };
};
