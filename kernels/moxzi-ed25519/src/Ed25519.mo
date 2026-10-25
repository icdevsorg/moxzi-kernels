import Runtime "mo:core/Runtime";
import Ref "internal/Ed25519Ref";

/// Ed25519 (RFC 8032, pure Ed25519): public keys from 32-byte seeds, deterministic signing,
/// and verification.
///
/// With the `moxzi-ed25519` kernel opted in (`[kernels]` in the application's mops.toml),
/// moxzi runs each function natively (`ed25519-dalek` 2.2.0 / `curve25519-dalek` 4.1.3).
/// Otherwise -- under moc, or without the opt-in -- the Motoko bodies below run: `mo:ic-agent`
/// 0.2.0's RFC 8032 implementation, copied verbatim into internal/Ed25519Ref.mo (not the
/// `ed25519` 0.1.0 package, which signs wrongly whenever the nonce has a zero top byte, about
/// 1 message in 24). Both paths accept, reject and trap identically.
///
/// Verification is RFC 8032 5.1.7, strict: A and R must be canonical encodings (y < p, no
/// "negative zero" x), s < L, a small-order public key is refused, and the equation is the
/// cofactorless [s]B = R + [k]A. It is NOT ZIP 215, which accepts non-canonical encodings and
/// small-order keys and checks the cofactored equation; a signature valid under ZIP 215 only
/// is refused here. A small-order R is not refused (RFC 8032 does not ask it).
///
/// Signing takes the message itself (not Ed25519ph). Without the kernel it is not
/// constant-time (Motoko `Nat` arithmetic): keep seeds where timing cannot be observed.
module {
  /// The 32-byte public key of a 32-byte secret seed. Traps on a seed of any other size.
  public func publicKey(seed : Blob) : Blob {
    if (seed.size() != 32) Runtime.trap("Ed25519.publicKey: the seed must be 32 bytes");
    Ref.publicKey(seed);
  };

  /// The 64-byte RFC 8032 signature (R || s) of `message` under a 32-byte secret seed. Traps
  /// on a seed of any other size.
  public func sign(seed : Blob, message : Blob) : Blob {
    if (seed.size() != 32) Runtime.trap("Ed25519.sign: the seed must be 32 bytes");
    Ref.sign(seed, message);
  };

  /// True iff `signature` is a valid signature of `message` under the 32-byte public key
  /// `key` (see the module documentation for the rules). False, never a trap, for any bad
  /// input.
  public func verify(key : Blob, message : Blob, signature : Blob) : Bool = Ref.verify(signature, message, key);
};
