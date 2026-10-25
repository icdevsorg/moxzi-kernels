import Array "mo:core/Array";
import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import VarArray "mo:core/VarArray";
import Base58 "mo:bitcoin/Base58";
import Base58Check "mo:bitcoin/Base58Check";
import Common "mo:bitcoin/Common";
import Hash "mo:bitcoin/Hash";
import Segwit "mo:bitcoin/Segwit";
import Affine "mo:bitcoin/ec/Affine";
import Curves "mo:bitcoin/ec/Curves";

/// Helpers shared by the Motoko bodies of moxzi-bitcoin, built on mo:bitcoin 0.2.1.
module {
  public type Net = { p2pkh : Nat8; p2sh : Nat8; hrp : Text; xpub : [Nat8] };

  public let curve = Curves.secp256k1;

  /// The network named `name`; traps with `<moduleName>: network must be …` otherwise.
  public func network(name : Text, moduleName : Text) : Net {
    switch name {
      case "mainnet" ({ p2pkh = 0x00; p2sh = 0x05; hrp = "bc"; xpub = [0x04, 0x88, 0xb2, 0x1e] });
      case "testnet" ({ p2pkh = 0x6f; p2sh = 0xc4; hrp = "tb"; xpub = [0x04, 0x35, 0x87, 0xcf] });
      case "regtest" ({ p2pkh = 0x6f; p2sh = 0xc4; hrp = "bcrt"; xpub = [0x04, 0x35, 0x87, 0xcf] });
      case _ Runtime.trap(moduleName # ": network must be \"mainnet\", \"testnet\" or \"regtest\"");
    };
  };

  public func slice(a : [Nat8], from : Nat, to : Nat) : [Nat8] = Array.sliceToArray<Nat8>(a, from, to);

  public func concat(parts : [[Nat8]]) : [Nat8] = Array.flatten<Nat8>(parts);

  /// A SEC1 public key, compressed (33 bytes) or uncompressed (65), as a point. mo:bitcoin's
  /// Affine.fromBytes reduces coordinates modulo p, so it also accepts encodings with x >= p (or
  /// y >= p), which SEC1 and libsecp256k1 reject; those are refused here first.
  public func sec1(key : [Nat8]) : ?Affine.Point {
    let n = key.size();
    if (not ((n == 33 and (key[0] == 2 or key[0] == 3)) or (n == 65 and key[0] == 4))) return null;
    if (Common.readBE256(key, 1) >= curve.p) return null;
    if (n == 65 and Common.readBE256(key, 33) >= curve.p) return null;
    Affine.fromBytes(key, curve);
  };

  public func validKey(key : [Nat8]) : Bool = switch (sec1(key)) { case (?_) true; case null false };

  public func compressed(p : Affine.Point) : [Nat8] = Affine.toBytes(p, true);

  public func hash160(data : [Nat8]) : [Nat8] = Hash.hash160(data);

  public func base58check(payload : [Nat8]) : Text = Base58Check.encode(payload);

  /// The payload of a Base58Check string, or null. Unlike mo:bitcoin's decoder, surrounding
  /// spaces are not accepted (addresses and extended keys have none), and nothing traps.
  public func unbase58check(t : Text) : ?[Nat8] {
    for (c in t.chars()) if (c == ' ') return null;
    if (not Base58.isBase58Alphabet(t)) return null;
    Base58Check.decode(t);
  };

  /// The segwit address of `program` (mo:bitcoin's Segwit), or null.
  public func segwit(hrp : Text, version : Nat8, program : [Nat8]) : ?Text {
    switch (Segwit.encode(hrp, { version; program })) {
      case (#ok a) ?a;
      case (#err _) null;
    };
  };

  /// `[OP_n][push length][program]`.
  public func witnessScript(version : Nat8, program : [Nat8]) : [Nat8] =
    concat([[if (version == 0) 0 else 0x50 + version, Nat8.fromNat(program.size())], program]);

  public func le32(n : Nat) : [Nat8] {
    let b = VarArray.repeat<Nat8>(0, 4);
    var v = n;
    for (i in b.keys()) { b[i] := Nat8.fromNat(v % 256); v /= 256 };
    Array.fromVarArray(b);
  };

  public func be32(n : Nat) : [Nat8] = Array.reverse(le32(n));

  public func textBytes(t : Text) : [Nat8] = Blob.toArray(Text.encodeUtf8(t));
};
