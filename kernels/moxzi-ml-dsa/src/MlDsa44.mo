/// ML-DSA-44 (FIPS 204, the final standard): key generation from a seed, signing and
/// verification, with a context string of at most 255 bytes. Public keys are 1312 bytes,
/// signatures 2420 bytes.
///
/// The private key is the 32-byte seed xi of ML-DSA.KeyGen (FIPS 204 Algorithm 6). Supply it from
/// a secure source (for example `raw_rand`) and keep it secret; no expanded secret key is
/// imported, so a key can never be inconsistent. `sign` is the deterministic variant of
/// ML-DSA.Sign (rnd = 32 zero bytes); `signHedged` takes rnd as an argument, since a canister has
/// no randomness of its own. Both sign the message itself (pure ML-DSA, not HashML-DSA).
///
/// With the moxzi-ml-dsa native kernel opted in (`[kernels]` in the application's mops.toml)
/// every function runs natively (Cryspen `libcrux-ml-dsa` 0.0.11); otherwise, and under moc, these
/// bodies run: `internal/MlDsa44Ref.mo`, a port of FIPS 204 written for this package (no mops
/// library implements ML-DSA). Both give the same bytes and verdicts on every input, and fail the
/// same way on bad input. The Motoko bodies cost far more instructions than the kernel, but all
/// fit in one message.
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";
import Ref "internal/MlDsa44Ref";

module {
  func checkSeed(f : Text, seed : Blob) {
    if (seed.size() != 32) Runtime.trap("MlDsa44." # f # ": the seed must be 32 bytes");
  };

  func checkContext(f : Text, context : Blob) {
    if (context.size() > 255) Runtime.trap("MlDsa44." # f # ": the context must be at most 255 bytes");
  };

  /// The 1312-byte public key of the 32-byte seed (ML-DSA.KeyGen_internal). Traps on another
  /// seed length.
  public func publicKey(seed : Blob) : Blob {
    checkSeed("publicKey", seed);
    Blob.fromArray(Ref.publicKey(Blob.toArray(seed)));
  };

  /// A deterministic 2420-byte signature of `message` with context `context`. Traps on a seed
  /// that is not 32 bytes or a context over 255 bytes.
  public func sign(seed : Blob, message : Blob, context : Blob) : Blob {
    checkSeed("sign", seed);
    checkContext("sign", context);
    Blob.fromArray(Ref.sign(Blob.toArray(seed), Blob.toArray(message), Blob.toArray(context), Array.repeat<Nat8>(0, 32)));
  };

  /// A hedged 2420-byte signature with the caller's 32 bytes of `randomness` (FIPS 204's rnd).
  /// Traps on a seed or randomness that is not 32 bytes, or a context over 255 bytes.
  public func signHedged(seed : Blob, message : Blob, context : Blob, randomness : Blob) : Blob {
    checkSeed("signHedged", seed);
    checkContext("signHedged", context);
    if (randomness.size() != 32) Runtime.trap("MlDsa44.signHedged: the randomness must be 32 bytes");
    Blob.fromArray(Ref.sign(Blob.toArray(seed), Blob.toArray(message), Blob.toArray(context), Blob.toArray(randomness)));
  };

  /// Whether `signature` is a valid signature of `message` with `context` under `publicKey`.
  /// False for a key or signature of the wrong length, a context over 255 bytes, a malformed
  /// signature, or one that does not verify.
  public func verify(publicKey : Blob, message : Blob, signature : Blob, context : Blob) : Bool {
    Ref.verify(Blob.toArray(publicKey), Blob.toArray(message), Blob.toArray(signature), Blob.toArray(context));
  };
};
