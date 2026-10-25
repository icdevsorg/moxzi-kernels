import Sha512 "mo:sha2/Sha512";

module {
  /// SHA-512 of `data` (64 bytes). Native with the moxzi-hash kernel opted in; otherwise mo:sha2.
  public func digest(data : Blob) : Blob = Sha512.fromBlob(#sha512, data);
};
