/// Encodings and RFC 9380 hashing for `Bls12381.mo`, on top of `mo:bls12-381` (field, curve and
/// pairing arithmetic). Compressed points follow the IETF / Zcash convention, exactly as the
/// zkcrypto `bls12_381` crate (the native kernel) reads and writes them.
import BLS "mo:bls12-381";
import Sha256 "mo:sha2/Sha256";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import VarArray "mo:core/VarArray";

module {
  public let P : Nat = BLS.P;
  public let R : Nat = BLS.R_;
  let HALF_P : Nat = 2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279893; // (p - 1) / 2
  let POW_2_381 : Nat = 4925250774549309901534880012517951725634967408808180833493536675530715221437151326426783281860614455100828498788352;

  /// Big-endian bytes `b[from .. from + len]` as a Nat.
  public func toNat(b : [Nat8], from : Nat, len : Nat) : Nat {
    var n = 0;
    var i = from;
    while (i < from + len) { n := n * 256 + Nat8.toNat(b[i]); i += 1 };
    n;
  };

  /// `n` (< 256^len) as `len` big-endian bytes, into `out[at ..]`.
  func putNat(out : [var Nat8], at : Nat, len : Nat, n : Nat) {
    var v = n;
    var i = len;
    while (i > 0) { i -= 1; out[at + i] := Nat8.fromNat(v % 256); v := v / 256 };
  };

  public func slice(b : [Nat8], from : Nat, len : Nat) : [Nat8] = Array.tabulate<Nat8>(len, func i = b[from + i]);

  /// A 48-byte compressed G1 point: canonical, on the curve, in the subgroup (identity allowed).
  public func g1(b : [Nat8]) : ?BLS.G1Point {
    // decompress_g1 checks the flags, x < p and the curve equation (via the square root).
    let ?p = BLS.decompress_g1(b) else return null;
    if (not BLS.g1_subgroup_check(p)) return null;
    ?p;
  };

  /// A 96-byte compressed G2 point (x's imaginary part first): canonical, on the curve, in the
  /// subgroup (identity allowed). The flag rules are the crate's `G2Affine::from_compressed`.
  public func g2(b : [Nat8]) : ?BLS.G2Point {
    if (b.size() != 96) return null;
    let c = b[0] >> 7;
    let inf = (b[0] >> 6) & 1;
    let sort = (b[0] >> 5) & 1;
    if (c != 1) return null;
    let x1 = toNat(b, 0, 48) % POW_2_381;
    let x0 = toNat(b, 48, 48);
    if (inf == 1) {
      if (sort == 1 or x1 != 0 or x0 != 0) return null;
      return ?BLS.G2_INF;
    };
    if (x1 >= P or x0 >= P) return null;
    let x : BLS.Fp2 = (x0, x1);
    let rhs = BLS.fp2_add(BLS.fp2_mul(BLS.fp2_sq(x), x), (4, 4));
    let ?y0 = BLS.fp2_sqrt(rhs) else return null;
    let y = if (largest2(y0) != (sort == 1)) BLS.fp2_neg(y0) else y0;
    let ?pt = BLS.g2_from_affine(x, (BLS.fp_mod(y.0), BLS.fp_mod(y.1))) else return null;
    if (not BLS.g2_subgroup_check(pt)) return null;
    ?pt;
  };

  /// The crate's `lexicographically_largest` for Fp2: c1 > (p-1)/2, or c1 = 0 and c0 > (p-1)/2.
  func largest2(y : BLS.Fp2) : Bool {
    let (c0, c1) = (BLS.fp_mod(y.0), BLS.fp_mod(y.1));
    c1 > HALF_P or (c1 == 0 and c0 > HALF_P);
  };

  public func encodeG1(p : BLS.G1Point) : Blob {
    let out = VarArray.repeat<Nat8>(0, 48);
    if (BLS.g1_is_inf(p)) { out[0] := 0xc0; return Blob.fromVarArray(out) };
    let (x, y) = BLS.g1_to_affine(p);
    putNat(out, 0, 48, x);
    out[0] |= (if (y > HALF_P) 0xa0 else 0x80);
    Blob.fromVarArray(out);
  };

  public func encodeG2(p : BLS.G2Point) : Blob {
    let out = VarArray.repeat<Nat8>(0, 96);
    if (BLS.g2_is_inf(p)) { out[0] := 0xc0; return Blob.fromVarArray(out) };
    let (x, y) = BLS.g2_to_affine(p);
    putNat(out, 0, 48, BLS.fp_mod(x.1));
    putNat(out, 48, 48, BLS.fp_mod(x.0));
    out[0] |= (if (largest2(y)) 0xa0 else 0x80);
    Blob.fromVarArray(out);
  };

  /// A 32-byte big-endian scalar below the group order.
  public func scalar(b : [Nat8]) : ?Nat {
    if (b.size() != 32) return null;
    let s = toNat(b, 0, 32);
    if (s >= R) null else ?s;
  };

  /// A 48-byte big-endian field element below p.
  public func fp(b : [Nat8], from : Nat) : ?Nat {
    let u = toNat(b, from, 48);
    if (u >= P) null else ?u;
  };

  func sha256(parts : [[Nat8]]) : [Nat8] = Blob.toArray(Sha256.fromBlob(#sha256, Blob.fromArray(Array.flatten(parts))));

  /// expand_message_xmd with SHA-256 (RFC 9380 5.3.1), including 5.3.3's oversized-DST rule.
  public func expandMessageXmd(msg : [Nat8], dst0 : [Nat8], lenInBytes : Nat) : [Nat8] {
    let dst = if (dst0.size() > 255) sha256([Blob.toArray("H2C-OVERSIZE-DST-"), dst0]) else dst0;
    let dstPrime = Array.concat(dst, [Nat8.fromNat(dst.size())]);
    let ell = (lenInBytes + 31) / 32;
    let b0 = sha256([Array.repeat<Nat8>(0, 64), msg, [Nat8.fromNat(lenInBytes / 256), Nat8.fromNat(lenInBytes % 256), 0], dstPrime]);
    let out = VarArray.repeat<Nat8>(0, ell * 32);
    var prev = sha256([b0, [1], dstPrime]);
    var i = 1;
    while (true) {
      for (j in prev.keys()) out[(i - 1) * 32 + j] := prev[j];
      if (i == ell) return Array.tabulate<Nat8>(lenInBytes, func k = out[k]);
      i += 1;
      let p = prev;
      prev := sha256([Array.tabulate<Nat8>(32, func j = b0[j] ^ p[j]), [Nat8.fromNat(i)], dstPrime]);
    };
    [];
  };

  /// hash_to_field: `count` elements of Fp^m, L = 64 (RFC 9380 5.2).
  public func hashToField(msg : [Nat8], dst : [Nat8], count : Nat, m : Nat) : [[Nat]] {
    let prb = expandMessageXmd(msg, dst, count * m * 64);
    Array.tabulate<[Nat]>(count, func i = Array.tabulate<Nat>(m, func j = toNat(prb, 64 * (j + i * m), 64) % P));
  };

  /// hash_to_curve for G1 (BLS12381G1_XMD:SHA-256_SSWU_RO_). Clearing the cofactor of each mapped
  /// point and adding is the same as adding and clearing once (clearing is a homomorphism).
  public func hashToG1(msg : [Nat8], dst : [Nat8]) : BLS.G1Point {
    let u = hashToField(msg, dst, 2, 1);
    BLS.g1_add(BLS.map_fp_to_g1(u[0][0]), BLS.map_fp_to_g1(u[1][0]));
  };

  /// hash_to_curve for G2 (BLS12381G2_XMD:SHA-256_SSWU_RO_).
  public func hashToG2(msg : [Nat8], dst : [Nat8]) : BLS.G2Point {
    let u = hashToField(msg, dst, 2, 2);
    BLS.g2_add(BLS.map_fp2_to_g2((u[0][0], u[0][1])), BLS.map_fp2_to_g2((u[1][0], u[1][1])));
  };
};
