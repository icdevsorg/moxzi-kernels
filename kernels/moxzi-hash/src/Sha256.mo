import Sha256 "mo:sha2/Sha256";

module {
  /// SHA-256 of `data` (32 bytes). Native with the moxzi-hash kernel opted in; otherwise mo:sha2.
  public func digest(data : Blob) : Blob = Sha256.fromBlob(#sha256, data);
};
