import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Nat8 "mo:core/Nat8";
import Text "mo:core/Text";
import Bip32 "mo:bitcoin/Bip32";
import Common "mo:bitcoin/Common";
import Util "internal/Util";

/// BIP32 extended public keys (xpub for mainnet, tpub for testnet and regtest): parsing,
/// serialization, and non-hardened public derivation (CKDpub). Private keys and hardened
/// derivation are not covered.
///
/// An extended key is valid when its Base58Check payload is 78 bytes with the xpub
/// (0x0488B21E) or tpub (0x043587CF) version, a depth-0 key has a zero parent fingerprint and
/// child number, and the key is a compressed SEC1 point on secp256k1.
///
/// Native with the moxzi-bitcoin kernel opted in; otherwise Motoko built on mo:bitcoin 0.2.1:
/// its ExtendedPublicKey.deriveChild for CKDpub, and its Base58Check, Hash and curve code.
/// mo:bitcoin's own `Bip32.parse` is not used: it does not check the payload length (a short
/// one traps, a long one is accepted), it accepts only xpub, and it rejects every non-master key
/// unless the caller passes the parent. Both paths agree on every input.
module {
  let XPUB : [Nat8] = [0x04, 0x88, 0xb2, 0x1e];
  let TPUB : [Nat8] = [0x04, 0x35, 0x87, 0xcf];

  func valid(p : [Nat8]) : Bool {
    if (p.size() != 78) return false;
    let v = Util.slice(p, 0, 4);
    if (v != XPUB and v != TPUB) return false;
    if (p[4] == 0 and (Util.slice(p, 5, 13) != [0, 0, 0, 0, 0, 0, 0, 0])) return false;
    if (p[45] != 2 and p[45] != 3) return false;
    Util.validKey(Util.slice(p, 45, 78));
  };

  func payloadOf(key : Text) : ?[Nat8] {
    let ?p = Util.unbase58check(key) else return null;
    if (valid(p)) ?p else null;
  };

  func child(p : [Nat8], index : Nat64) : ?[Nat8] {
    if (index >= 0x8000_0000 or p[4] == 255) return null;
    let key = Util.slice(p, 45, 78);
    let parent = Bip32.ExtendedPublicKey(key, Util.slice(p, 13, 45), p[4], Common.readBE32(p, 9), null);
    let ?c = parent.deriveChild(Nat32.fromNat(Nat64.toNat(index))) else return null;
    ?Util.concat([Util.slice(p, 0, 4), [c.depth], Util.slice(Util.hash160(key), 0, 4), Util.be32(Nat64.toNat(index)), c.chaincode, c.key]);
  };

  // "m" or "m/…" (depth 0 only), or relative indices; decimal, below 2^31, '/'-separated.
  func path(t : Text, depth : Nat8) : ?[Nat64] {
    let s = Util.textBytes(t);
    if (s == [0x6d : Nat8]) return if (depth == 0) ?[] else null;
    var i = 0;
    if (s.size() >= 2 and s[0] == 0x6d and s[1] == 0x2f) {
      if (depth != 0) return null;
      i := 2;
    };
    let out = List.empty<Nat64>();
    var n : Nat64 = 0;
    var digits = 0;
    while (i <= s.size()) {
      if (i == s.size() or s[i] == 0x2f) {
        if (digits == 0) return null;
        List.add(out, n);
        n := 0;
        digits := 0;
      } else {
        let c = s[i];
        if (c < 0x30 or c > 0x39) return null;
        n := n * 10 + Nat64.fromNat(Nat8.toNat(c - 0x30));
        if (n >= 0x8000_0000) return null;
        digits += 1;
      };
      i += 1;
    };
    ?List.toArray(out);
  };

  /// The 78-byte payload of a valid extended public key (version, depth, parent fingerprint,
  /// child number, chain code, key), or null.
  public func parse(key : Text) : ?Blob {
    switch (payloadOf(key)) { case (?p) ?Blob.fromArray(p); case null null };
  };

  /// The extended key of a valid 78-byte payload (see `parse`), or null.
  public func serialize(payload : Blob) : ?Text {
    let p = Blob.toArray(payload);
    if (valid(p)) ?Util.base58check(p) else null;
  };

  /// The child at a non-hardened `index` (below 2^31). Null if the key is invalid, the index is
  /// hardened, the key is at depth 255, or (probability below 2^-127) the child is invalid; per
  /// BIP32 the caller then tries the next index.
  public func deriveChild(key : Text, index : Nat64) : ?Text {
    let ?p = payloadOf(key) else return null;
    switch (child(p, index)) { case (?c) ?Util.base58check(c); case null null };
  };

  /// The key at `path` below `key`: "0/1/2" relative to it, or "m", "m/0/1" when `key` is a
  /// master key (depth 0). Indices are decimal and non-hardened. Null if the key or path is
  /// invalid or any derivation step fails.
  public func derivePath(key : Text, path_ : Text) : ?Text {
    let ?p0 = payloadOf(key) else return null;
    var p = p0;
    let ?indices = path(path_, p[4]) else return null;
    for (i in indices.vals()) {
      let ?c = child(p, i) else return null;
      p := c;
    };
    ?Util.base58check(p);
  };

  /// The BIP32 fingerprint of a SEC1 public key: the first 4 bytes of HASH160 of its compressed
  /// form. Null if the key is not a valid point.
  public func fingerprint(publicKey : Blob) : ?Blob {
    let ?k = Util.sec1(Blob.toArray(publicKey)) else return null;
    ?Blob.fromArray(Util.slice(Util.hash160(Util.compressed(k)), 0, 4));
  };

  /// A master (depth 0) extended public key from a SEC1 public key (compressed in the result)
  /// and a 32-byte chain code: xpub on "mainnet", tpub on "testnet" and "regtest" (any other
  /// network traps with `Bip32: network must be …`). Null if the key or chain code is invalid.
  public func fromPublicKey(publicKey : Blob, chainCode : Blob, network : Text) : ?Text {
    let net = Util.network(network, "Bip32");
    let ?k = Util.sec1(Blob.toArray(publicKey)) else return null;
    if (chainCode.size() != 32) return null;
    ?Util.base58check(Util.concat([net.xpub, [0, 0, 0, 0, 0, 0, 0, 0, 0], Blob.toArray(chainCode), Util.compressed(k)]));
  };
};
