import Blob "mo:core/Blob";
import Base58 "mo:bitcoin/Base58";
import Base58Check "mo:bitcoin/Base58Check";

/// Base58Check: Base58 of the payload followed by the first four bytes of its double SHA-256.
/// The payload includes any version byte; this module does not interpret it.
///
/// Native with the moxzi-base58 kernel opted in; otherwise mo:bitcoin's Base58Check. Both
/// behave the same on every input.
module {
  /// Base58Check of `payload` (any length, including empty).
  public func encode(payload : Blob) : Text = Base58Check.encode(Blob.toArray(payload));

  /// The payload of `text` with the checksum verified and removed, or null if `text` is not
  /// Base58 (see `Base58.decode`), is shorter than the four checksum bytes, or the checksum
  /// does not match.
  public func decode(text : Text) : ?Blob {
    // mo:bitcoin's Base58Check.decode traps on a character outside the alphabet.
    if (not Base58.isBase58Alphabet(text)) return null;
    switch (Base58Check.decode(text)) {
      case (?payload) ?Blob.fromArray(payload);
      case null null;
    };
  };
};
