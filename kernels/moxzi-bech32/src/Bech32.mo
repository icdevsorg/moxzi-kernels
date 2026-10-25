import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";
import Bech32 "mo:bitcoin/Bech32";

/// Bech32 (BIP173) and Bech32m (BIP350) strings over 5-bit values.
///
/// Native with the moxzi-bech32 kernel opted in; otherwise mo:bitcoin's Bech32 (and, for
/// `convertBits`, a port of BIP173's reference `convertbits`, which mo:bitcoin keeps private).
/// Both paths agree on every input, including returning null for bad input.
///
/// The kernel interface (ABI 1) has no records or variants, so `decodePacked` returns the
/// decoded parts packed in one Blob; `decode` unpacks it into a record.
module {
  public type Encoding = { #bech32; #bech32m };
  public type Decoded = { hrp : Text; data : Blob; encoding : Encoding };

  // An HRP mo:bitcoin's encoder accepts without trapping: non-empty, '!'..'~', no uppercase.
  func encodableHrp(hrp : Text) : Bool {
    let b = Text.encodeUtf8(hrp);
    if (b.size() == 0) return false;
    for (c in b.vals()) if (c < 0x21 or c > 0x7e or (c >= 0x41 and c <= 0x5a)) return false;
    true;
  };

  /// The Bech32 (`bech32m = false`) or Bech32m string of `hrp` and the 5-bit values `data`
  /// (each byte 0..31). Null if `hrp` is empty, has a character outside `!`..`~` or an
  /// uppercase letter, a value is 32 or more, or the result would exceed 90 characters.
  /// The result is lowercase.
  public func encode(hrp : Text, data : Blob, bech32m : Bool) : ?Text {
    if (not encodableHrp(hrp)) return null;
    if (Text.encodeUtf8(hrp).size() + 1 + data.size() + 6 > 90) return null;
    for (v in data.vals()) if (v > 31) return null;
    ?Bech32.encode(hrp, Blob.toArray(data), if (bech32m) #BECH32M else #BECH32);
  };

  /// Decode a Bech32 or Bech32m string, packed as
  /// `[0 = Bech32 | 1 = Bech32m][hrp length][hrp, lowercase][5-bit values, checksum removed]`.
  /// Null unless the string is at most 90 characters, all in `!`..`~`, not mixed case, with
  /// a non-empty HRP before the last `1`, valid data characters and a valid checksum.
  public func decodePacked(text : Text) : ?Blob {
    switch (Bech32.decode(text)) {
      case (#err _) null;
      case (#ok(encoding, hrp, values)) {
        let h = Blob.toArray(Text.encodeUtf8(hrp));
        ?Blob.fromArray(Array.flatten<Nat8>([[if (encoding == #BECH32M) 1 else 0, Nat8.fromNat(h.size())], h, values]));
      };
    };
  };

  /// Decode a Bech32 or Bech32m string (see `decodePacked`): the lowercase HRP, the 5-bit
  /// values without the checksum, and which checksum it carried.
  public func decode(text : Text) : ?Decoded {
    let ?p = decodePacked(text) else return null;
    let n = Nat8.toNat(p[1]);
    let hrp = switch (Text.decodeUtf8(Blob.fromArray(Array.sliceToArray<Nat8>(Blob.toArray(p), 2, 2 + n)))) {
      case (?t) t;
      case null return null;
    };
    ?{
      hrp;
      data = Blob.fromArray(Array.sliceToArray<Nat8>(Blob.toArray(p), 2 + n, p.size()));
      encoding = if (p[0] == 1) #bech32m else #bech32;
    };
  };

  /// Regroup `data`'s `fromBits`-bit values into `toBits`-bit values, most significant bit
  /// first (BIP173's `convertbits`); both widths are 1..8. With `pad`, a final partial group
  /// is padded with zero bits; without it, leftover bits must be fewer than `fromBits` and all
  /// zero. Null if a width is out of range, a value does not fit `fromBits`, or the padding is
  /// wrong. `convertBits(bytes, 8, 5, true)` gives Bech32 data; `(values, 5, 8, false)` undoes it.
  public func convertBits(data : Blob, fromBits : Nat64, toBits : Nat64, pad : Bool) : ?Blob {
    if (fromBits < 1 or fromBits > 8 or toBits < 1 or toBits > 8) return null;
    let from = Nat32.fromNat(Nat64.toNat(fromBits));
    let to = Nat32.fromNat(Nat64.toNat(toBits));
    let maxv : Nat32 = (1 << to) - 1;
    let maxAcc : Nat32 = (1 << (from + to - 1)) - 1;
    var acc : Nat32 = 0;
    var bits : Nat32 = 0;
    let out = VarArray.repeat<Nat8>(0, data.size() * Nat32.toNat(from) / Nat32.toNat(to) + 1);
    var n = 0;
    for (b in data.vals()) {
      let v = Nat32.fromNat(Nat8.toNat(b));
      if (v >> from != 0) return null;
      acc := ((acc << from) | v) & maxAcc;
      bits += from;
      while (bits >= to) {
        bits -= to;
        out[n] := Nat8.fromNat(Nat32.toNat((acc >> bits) & maxv));
        n += 1;
      };
    };
    if (pad) {
      if (bits > 0) {
        out[n] := Nat8.fromNat(Nat32.toNat((acc << (to - bits)) & maxv));
        n += 1;
      };
    } else if (bits >= from or ((acc << (to - bits)) & maxv) != 0) {
      return null;
    };
    ?Blob.fromArray(Array.tabulate<Nat8>(n, func i = out[i]));
  };
};
