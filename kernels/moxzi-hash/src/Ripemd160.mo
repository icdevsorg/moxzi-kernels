import Blob "mo:core/Blob";
import Ripemd160 "mo:bitcoin/Ripemd160";

module {
  /// RIPEMD-160 of `data` (20 bytes). Native with the moxzi-hash kernel opted in; otherwise
  /// mo:bitcoin's Ripemd160.
  public func digest(data : Blob) : Blob = Blob.fromArray(Ripemd160.hash(Blob.toArray(data)));
};
