import Blob "mo:core/Blob";
import Hmac "mo:bitcoin/Hmac";

module {
  /// HMAC-SHA-256 (RFC 2104) of `data` under `key` (32 bytes). Native with the moxzi-hash kernel
  /// opted in; otherwise mo:bitcoin's Hmac.
  public func sha256(key : Blob, data : Blob) : Blob {
    let h = Hmac.sha256(Blob.toArray(key));
    h.writeArray(Blob.toArray(data));
    h.sum();
  };

  /// HMAC-SHA-512 of `data` under `key` (64 bytes).
  public func sha512(key : Blob, data : Blob) : Blob {
    let h = Hmac.sha512(Blob.toArray(key));
    h.writeArray(Blob.toArray(data));
    h.sum();
  };
};
