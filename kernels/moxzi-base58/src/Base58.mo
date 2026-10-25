import Blob "mo:core/Blob";
import Base58 "mo:bitcoin/Base58";

/// Base58 with the Bitcoin alphabet
/// (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).
///
/// Native with the moxzi-base58 kernel opted in; otherwise mo:bitcoin's Base58. Both behave
/// the same on every input.
module {
  /// Base58 of `data`. Each leading zero byte becomes a leading `1`; the empty Blob gives "".
  public func encode(data : Blob) : Text = Base58.encode(Blob.toArray(data));

  /// The bytes `text` encodes, or null if it is not Base58. ASCII spaces before and after the
  /// digits are ignored (as mo:bitcoin does); any other character outside the alphabet, or a
  /// space between digits, gives null. "" decodes to the empty Blob.
  public func decode(text : Text) : ?Blob = switch (Base58.decodeOpt(text)) {
    case (?bytes) ?Blob.fromArray(bytes);
    case null null;
  };
};
