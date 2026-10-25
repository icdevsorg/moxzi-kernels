import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Text "mo:core/Text";
import Segwit "mo:bitcoin/Segwit";

/// Segregated-witness addresses (BIP173 for version 0, BIP350 / Bech32m for versions 1..16).
///
/// Native with the moxzi-bech32 kernel opted in; otherwise mo:bitcoin's Segwit. Both paths
/// agree on every input, including returning null for bad input.
///
/// The kernel interface (ABI 1) has no records, so `decodePacked` returns the parts packed in
/// one Blob; `decode` unpacks it into a record.
module {
  public type Decoded = { hrp : Text; version : Nat8; program : Blob };

  /// The address of witness `version` (0..16) and `program` under `hrp` (e.g. "bc", "tb",
  /// "bcrt"). Null if the version is above 16, the program is not 2..40 bytes (20 or 32 for
  /// version 0), `hrp` is empty or has a character outside `!`..`~` or an uppercase letter, or
  /// the address would exceed 90 characters. Version 0 uses Bech32, later versions Bech32m.
  public func encode(hrp : Text, version : Nat64, program : Blob) : ?Text {
    if (version > 16) return null;
    // Checks mo:bitcoin asserts (it would trap) rather than reports.
    let h = Text.encodeUtf8(hrp);
    if (h.size() == 0) return null;
    for (c in h.vals()) if (c < 0x21 or c > 0x7e or (c >= 0x41 and c <= 0x5a)) return null;
    if (h.size() + 1 + 1 + (program.size() * 8 + 4) / 5 + 6 > 90) return null;
    switch (Segwit.encode(hrp, { version = Nat8.fromNat(Nat64.toNat(version)); program = Blob.toArray(program) })) {
      case (#ok address) ?address;
      case (#err _) null;
    };
  };

  /// Decode a segwit address, packed as `[version][hrp length][hrp, lowercase][program]`.
  /// Null unless it is a valid Bech32 string (see `Bech32.decodePacked`) whose first value is a
  /// version 0..16, whose checksum is Bech32 for version 0 and Bech32m otherwise, whose program
  /// has valid padding and 2..40 bytes (20 or 32 for version 0). The HRP is not checked: compare
  /// it with the network you expect.
  public func decodePacked(address : Text) : ?Blob {
    switch (Segwit.decode(address)) {
      case (#err _) null;
      case (#ok(hrp, { version; program })) {
        let h = Blob.toArray(Text.encodeUtf8(hrp));
        ?Blob.fromArray(Array.flatten<Nat8>([[version, Nat8.fromNat(h.size())], h, program]));
      };
    };
  };

  /// Decode a segwit address (see `decodePacked`).
  public func decode(address : Text) : ?Decoded {
    let ?p = decodePacked(address) else return null;
    let n = Nat8.toNat(p[1]);
    let a = Blob.toArray(p);
    let ?hrp = Text.decodeUtf8(Blob.fromArray(Array.sliceToArray<Nat8>(a, 2, 2 + n))) else return null;
    ?{ hrp; version = p[0]; program = Blob.fromArray(Array.sliceToArray<Nat8>(a, 2 + n, a.size())) };
  };
};
