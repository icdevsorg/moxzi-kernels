import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import ByteUtils "mo:bitcoin/ByteUtils";
import Hash "mo:bitcoin/Hash";
import Util "internal/Util";

/// Bitcoin output scripts and pushes as raw bytes (no length prefix), and the BIP341 script-tree
/// hashes.
///
/// Native with the moxzi-bitcoin kernel opted in; otherwise Motoko (the hashes from mo:bitcoin
/// 0.2.1's Hash). mo:bitcoin's Script works on instruction lists and always prefixes the length,
/// so the byte templates here are written directly. Both paths agree on every input.
module {
  func sized(b : Blob, n : Nat, f : [Nat8] -> [Nat8]) : ?Blob =
    if (b.size() == n) ?Blob.fromArray(f(Blob.toArray(b))) else null;

  /// OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG; null unless 20 bytes.
  public func p2pkh(publicKeyHash : Blob) : ?Blob =
    sized(publicKeyHash, 20, func h = Util.concat([[0x76, 0xa9, 0x14], h, [0x88, 0xac]]));

  /// OP_HASH160 <20-byte hash> OP_EQUAL; null unless 20 bytes.
  public func p2sh(scriptHash : Blob) : ?Blob =
    sized(scriptHash, 20, func h = Util.concat([[0xa9, 0x14], h, [0x87]]));

  /// OP_0 <20-byte hash>; null unless 20 bytes.
  public func p2wpkh(publicKeyHash : Blob) : ?Blob = sized(publicKeyHash, 20, func h = Util.witnessScript(0, h));

  /// OP_0 <32-byte SHA-256 of the witness script>; null unless 32 bytes.
  public func p2wsh(scriptHash : Blob) : ?Blob = sized(scriptHash, 32, func h = Util.witnessScript(0, h));

  /// OP_1 <32-byte x-only output key> (already tweaked, see Address.taprootOutputKey); null
  /// unless 32 bytes.
  public func p2tr(outputKey : Blob) : ?Blob = sized(outputKey, 32, func k = Util.witnessScript(1, k));

  /// The minimal push of `data` (BIP62): OP_0 for empty, OP_1NEGATE for 0x81, OP_1..OP_16 for a
  /// single byte 1..16, otherwise a direct push or OP_PUSHDATA1/2/4 with the data.
  public func pushData(data : Blob) : Blob {
    let d = Blob.toArray(data);
    let n = d.size();
    if (n == 0) return "\00";
    if (n == 1 and d[0] == 0x81) return "\4f";
    if (n == 1 and d[0] >= 1 and d[0] <= 16) return Blob.fromArray([0x50 + d[0]]);
    let header : [Nat8] = if (n < 0x4c) [Nat8.fromNat(n)]
      else if (n <= 0xff) [0x4c, Nat8.fromNat(n)]
      else if (n <= 0xffff) [0x4d, Nat8.fromNat(n % 256), Nat8.fromNat(n / 256)]
      else Util.concat([[0x4e], Util.le32(n)]);
    Blob.fromArray(Util.concat([header, d]));
  };

  /// BIP341 TapLeaf hash: tagged "TapLeaf" of the leaf version, the script's CompactSize length
  /// and the script. Null unless the version is even and at most 0xfe (tapscript is 0xc0).
  public func tapLeafHash(script : Blob, leafVersion : Nat64) : ?Blob {
    if (leafVersion > 0xfe or leafVersion % 2 != 0) return null;
    let s = Blob.toArray(script);
    ?Blob.fromArray(Hash.taggedHash(Util.concat([[Nat8.fromNat(Nat64.toNat(leafVersion))], ByteUtils.writeVarint(s.size()), s]), "TapLeaf"));
  };

  /// BIP341 TapBranch hash of two 32-byte child hashes, ordered lexicographically first. Null
  /// unless both are 32 bytes.
  public func tapBranchHash(left : Blob, right : Blob) : ?Blob {
    if (left.size() != 32 or right.size() != 32) return null;
    let (a, b) = if (left <= right) (left, right) else (right, left);
    ?Blob.fromArray(Hash.taggedHash(Util.concat([Blob.toArray(a), Blob.toArray(b)]), "TapBranch"));
  };
};
