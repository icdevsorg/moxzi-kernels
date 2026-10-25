import Blob "mo:core/Blob";
import Hash "mo:bitcoin/Hash";

/// Bitcoin's hashes. Native with the moxzi-bitcoin kernel opted in; otherwise mo:bitcoin's Hash.
module {
  /// SHA-256 of SHA-256 (32 bytes), in digest byte order (a transaction id displays reversed).
  public func sha256d(data : Blob) : Blob = Blob.fromArray(Hash.doubleSHA256(Blob.toArray(data)));

  /// RIPEMD-160 of SHA-256 (20 bytes).
  public func hash160(data : Blob) : Blob = Blob.fromArray(Hash.hash160(Blob.toArray(data)));

  /// BIP340 tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data), the tag as UTF-8.
  public func taggedHash(tag : Text, data : Blob) : Blob = Blob.fromArray(Hash.taggedHash(Blob.toArray(data), tag));
};
