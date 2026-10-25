import Blob "mo:core/Blob";
import Runtime "mo:core/Runtime";
import Blake3Ref "internal/Blake3Ref";

module {
  /// BLAKE3 of `data` (32 bytes). Native with the moxzi-hash kernel opted in; otherwise a port of
  /// the official reference implementation (mo:blake3 0.1.2 hashes inputs over 1 KiB wrongly).
  public func digest(data : Blob) : Blob =
    Blob.fromArray(Blake3Ref.hash(Blake3Ref.IV, 0, Blob.toArray(data), 32));

  /// Keyed BLAKE3 (a MAC) of `data` under a 32-byte `key`. Traps on any other key length.
  public func keyedHash(key : Blob, data : Blob) : Blob {
    if (key.size() != 32) Runtime.trap("Blake3.keyedHash: the key must be 32 bytes");
    Blob.fromArray(Blake3Ref.hash(Blake3Ref.keyWords(Blob.toArray(key)), Blake3Ref.KEYED_HASH, Blob.toArray(data), 32));
  };
};
