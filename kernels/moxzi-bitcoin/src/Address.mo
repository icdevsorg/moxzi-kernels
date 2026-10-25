import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import Common "mo:bitcoin/Common";
import Hash "mo:bitcoin/Hash";
import Segwit "mo:bitcoin/Segwit";
import P2tr "mo:bitcoin/bitcoin/P2tr";
import Sha256 "mo:sha2/Sha256";
import Util "internal/Util";

/// Bitcoin addresses: P2PKH, P2SH (Base58Check), P2WPKH, P2WSH (Bech32, BIP173) and P2TR
/// (Bech32m, BIP341/BIP350), and the conversion between addresses and output scripts.
///
/// `network` is "mainnet", "testnet" or "regtest"; any other value traps with
/// `Address: network must be "mainnet", "testnet" or "regtest"`. Testnet and regtest share the
/// Base58 version bytes (0x6f, 0xc4) and differ in the segwit HRP ("tb", "bcrt"); signet uses
/// testnet's.
///
/// Native with the moxzi-bitcoin kernel opted in; otherwise Motoko built on mo:bitcoin 0.2.1's
/// Base58Check, Segwit, Hash, curve arithmetic and P2tr. Both paths agree on every input. Two
/// corrections to mo:bitcoin are applied: public keys with a coordinate >= p are rejected
/// (mo:bitcoin's SEC1 parser reduces them modulo p and accepts them), and the Taproot tweak is
/// rejected when >= the group order n (BIP341; mo:bitcoin compares it with p).
module {
  /// The P2PKH address of a SEC1 public key (33 bytes compressed or 65 uncompressed; the key is
  /// hashed as given). Null if the key is not a valid point.
  public func p2pkh(publicKey : Blob, network : Text) : ?Text {
    let net = Util.network(network, "Address");
    let k = Blob.toArray(publicKey);
    if (not Util.validKey(k)) return null;
    ?Util.base58check(Util.concat([[net.p2pkh], Util.hash160(k)]));
  };

  /// The P2SH address of a redeem script.
  public func p2sh(redeemScript : Blob, network : Text) : Text {
    let net = Util.network(network, "Address");
    Util.base58check(Util.concat([[net.p2sh], Util.hash160(Blob.toArray(redeemScript))]));
  };

  /// The P2WPKH address of a compressed (33-byte) SEC1 public key. Null if the key is not
  /// compressed or not a valid point.
  public func p2wpkh(publicKey : Blob, network : Text) : ?Text {
    let net = Util.network(network, "Address");
    let k = Blob.toArray(publicKey);
    if (k.size() != 33 or not Util.validKey(k)) return null;
    Util.segwit(net.hrp, 0, Util.hash160(k));
  };

  /// The P2WSH address of a witness script.
  public func p2wsh(witnessScript : Blob, network : Text) : Text {
    let net = Util.network(network, "Address");
    switch (Util.segwit(net.hrp, 0, Blob.toArray(Sha256.fromBlob(#sha256, witnessScript)))) {
      case (?a) a;
      case null Runtime.trap("Address.p2wsh: unreachable");
    };
  };

  func taprootOutput(p : [Nat8], root : [Nat8]) : ?[Nat8] {
    if (p.size() != 32 or (root.size() != 0 and root.size() != 32)) return null;
    // lift_x(p): an x-coordinate below p with a point on the curve.
    if (not Util.validKey(Util.concat([[2], p]))) return null;
    let t = Common.readBE256(Hash.taggedHash(Util.concat([p, root]), "TapTweak"), 0);
    if (t >= Util.curve.r) return null;
    switch (P2tr.tweakPublicKey(p, Util.curve.Fp(t))) {
      case (#ok k) ?Util.concat([[if (k.is_even) 2 else 3], k.bip340_public_key]);
      case (#err _) null;
    };
  };

  /// BIP341's output key Q = lift_x(P) + int(TapTweak(P || merkleRoot))·G for a 32-byte x-only
  /// internal key P, as 33-byte compressed SEC1 (the prefix gives Q's parity). An empty
  /// `merkleRoot` means no script tree (BIP86); otherwise it is 32 bytes. Null if P is not on
  /// the curve, the root has another length, the tweak is >= n, or Q is the point at infinity.
  public func taprootOutputKey(internalKey : Blob, merkleRoot : Blob) : ?Blob {
    switch (taprootOutput(Blob.toArray(internalKey), Blob.toArray(merkleRoot))) {
      case (?q) ?Blob.fromArray(q);
      case null null;
    };
  };

  /// The P2TR address for an internal key and script-tree root (see `taprootOutputKey`).
  public func p2tr(internalKey : Blob, merkleRoot : Blob, network : Text) : ?Text {
    let net = Util.network(network, "Address");
    let ?q = taprootOutput(Blob.toArray(internalKey), Blob.toArray(merkleRoot)) else return null;
    Util.segwit(net.hrp, 1, Util.slice(q, 1, 33));
  };

  /// The output script (scriptPubKey) an address pays to on `network`, or null if it is not a
  /// valid address of that network. Segwit addresses of any version 0..16 (BIP350) and
  /// Base58Check P2PKH/P2SH addresses are accepted; segwit HRPs must match the network.
  public func toScript(address : Text, network : Text) : ?Blob {
    let net = Util.network(network, "Address");
    switch (Segwit.decode(address)) {
      case (#ok(hrp, { version; program })) {
        return if (hrp == net.hrp) ?Blob.fromArray(Util.witnessScript(version, program)) else null;
      };
      case (#err _) {};
    };
    let ?p = Util.unbase58check(address) else return null;
    if (p.size() != 21) return null;
    let h = Util.slice(p, 1, 21);
    if (p[0] == net.p2pkh) ?Blob.fromArray(Util.concat([[0x76, 0xa9, 0x14], h, [0x88, 0xac]]))
    else if (p[0] == net.p2sh) ?Blob.fromArray(Util.concat([[0xa9, 0x14], h, [0x87]]))
    else null;
  };

  /// The address of a standard output script on `network`: P2PKH, P2SH, or a witness program
  /// (version 0 with 20 or 32 bytes, versions 1..16 with 2..40 bytes). Null for anything else.
  public func fromScript(script : Blob, network : Text) : ?Text {
    let net = Util.network(network, "Address");
    let s = Blob.toArray(script);
    let n = s.size();
    if (n == 25 and s[0] == 0x76 and s[1] == 0xa9 and s[2] == 0x14 and s[23] == 0x88 and s[24] == 0xac) {
      return ?Util.base58check(Util.concat([[net.p2pkh], Util.slice(s, 3, 23)]));
    };
    if (n == 23 and s[0] == 0xa9 and s[1] == 0x14 and s[22] == 0x87) {
      return ?Util.base58check(Util.concat([[net.p2sh], Util.slice(s, 2, 22)]));
    };
    if (n >= 4 and n <= 42 and (s[0] == 0 or (s[0] >= 0x51 and s[0] <= 0x60)) and Nat8.toNat(s[1]) + 2 == n) {
      return Util.segwit(net.hrp, if (s[0] == 0) 0 else s[0] - 0x50, Util.slice(s, 2, n));
    };
    null;
  };
};
