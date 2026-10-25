import Array "mo:core/Array";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";
import Hash "mo:bitcoin/Hash";
import Sha256 "mo:sha2/Sha256";
import Util "internal/Util";

/// Raw Bitcoin transactions: validation, txid/wtxid, and the signature hashes of legacy inputs
/// (Bitcoin Core's SignatureHash), segwit v0 (BIP143) and Taproot (BIP341).
///
/// A transaction is valid when it deserializes as in Bitcoin Core (witness serialization
/// allowed, canonical CompactSizes no larger than 0x02000000, no "superfluous witness record",
/// no unknown flags) with no bytes left over. Every function returns null for an invalid
/// transaction or an input index out of range.
///
/// Native with the moxzi-bitcoin kernel opted in; otherwise this Motoko port of Bitcoin Core's
/// serialization and of the BIPs (hashes from mo:bitcoin 0.2.1 and mo:sha2). mo:bitcoin's own
/// Transaction is not used: it parses every scriptSig as a list of known opcodes (so it rejects
/// valid transactions), signs legacy inputs with SIGHASH_ALL only, has no BIP143 hash, and its
/// Taproot hash assumes every input spends the same scriptPubKey and has no annex. Both paths
/// agree on every input.
module {
  type TxIn = { outpoint : [Nat8]; script : [Nat8]; sequence : [Nat8]; witness : [[Nat8]] };
  type Tx = { version : [Nat8]; inputs : [TxIn]; outputs : [[Nat8]]; lockTime : [Nat8] };

  let MAX_SIZE = 0x0200_0000;

  class Reader(b : [Nat8]) {
    public var pos = 0;
    public func atEnd() : Bool = pos == b.size();
    public func take(n : Nat) : ?[Nat8] {
      if (b.size() - pos < n) return null;
      let s = Array.sliceToArray<Nat8>(b, pos, pos + n);
      pos += n;
      ?s;
    };
    func le(s : [Nat8]) : Nat {
      var v = 0;
      var i = s.size();
      while (i > 0) { i -= 1; v := v * 256 + Nat8.toNat(s[i]) };
      v;
    };
    public func compact() : ?Nat {
      let ?f = take(1) else return null;
      let n = switch (f[0]) {
        case 0xfd { let ?s = take(2) else return null; let n = le(s); if (n < 0xfd) return null; n };
        case 0xfe { let ?s = take(4) else return null; let n = le(s); if (n < 0x1_0000) return null; n };
        case 0xff { let ?s = take(8) else return null; let n = le(s); if (n < 0x1_0000_0000) return null; n };
        case x Nat8.toNat(x);
      };
      if (n > MAX_SIZE) null else ?n;
    };
    public func field() : ?[Nat8] {
      let ?n = compact() else return null;
      take(n);
    };
    public func output() : ?[Nat8] {
      let start = pos;
      let ?_ = take(8) else return null;
      let ?_ = field() else return null;
      ?Array.sliceToArray<Nat8>(b, start, pos);
    };
  };

  func readInputs(r : Reader, n : Nat) : ?[TxIn] {
    let v = List.empty<TxIn>();
    var i = 0;
    while (i < n) {
      let ?outpoint = r.take(36) else return null;
      let ?script = r.field() else return null;
      let ?sequence = r.take(4) else return null;
      List.add(v, { outpoint; script; sequence; witness = [] });
      i += 1;
    };
    ?List.toArray(v);
  };

  func readOutputs(r : Reader) : ?[[Nat8]] {
    let ?n = r.compact() else return null;
    let v = List.empty<[Nat8]>();
    var i = 0;
    while (i < n) {
      let ?o = r.output() else return null;
      List.add(v, o);
      i += 1;
    };
    ?List.toArray(v);
  };

  func parse(b : [Nat8]) : ?Tx {
    let r = Reader(b);
    let ?version = r.take(4) else return null;
    var flags : Nat8 = 0;
    let ?n = r.compact() else return null;
    var ins = switch (readInputs(r, n)) { case (?v) v; case null return null };
    var outs : [[Nat8]] = [];
    if (ins.size() == 0) {
      let ?f = r.take(1) else return null;
      flags := f[0];
      if (flags != 0) {
        let ?m = r.compact() else return null;
        ins := switch (readInputs(r, m)) { case (?v) v; case null return null };
        outs := switch (readOutputs(r)) { case (?v) v; case null return null };
      };
    } else {
      outs := switch (readOutputs(r)) { case (?v) v; case null return null };
    };
    if (flags & 1 != 0) {
      flags ^= 1;
      let withWitness = VarArray.repeat<TxIn>({ outpoint = []; script = []; sequence = []; witness = [] }, ins.size());
      var any = false;
      for (k in ins.keys()) {
        let ?count = r.compact() else return null;
        let items = List.empty<[Nat8]>();
        var j = 0;
        while (j < count) {
          let ?item = r.field() else return null;
          List.add(items, item);
          j += 1;
        };
        if (count > 0) any := true;
        withWitness[k] := { ins[k] with witness = List.toArray(items) };
      };
      if (not any) return null; // superfluous witness record
      ins := Array.fromVarArray(withWitness);
    };
    if (flags != 0) return null; // unknown optional data
    let ?lockTime = r.take(4) else return null;
    if (not r.atEnd()) return null;
    ?{ version; inputs = ins; outputs = outs; lockTime };
  };

  func compactSize(n : Nat) : [Nat8] {
    if (n < 0xfd) [Nat8.fromNat(n)]
    else if (n <= 0xffff) [0xfd, Nat8.fromNat(n % 256), Nat8.fromNat(n / 256)]
    else if (n <= 0xffff_ffff) Util.concat([[0xfe], Util.le32(n)])
    else Util.concat([[0xff], Util.le32(n % 0x1_0000_0000), Util.le32(n / 0x1_0000_0000)]);
  };

  func field(b : [Nat8]) : [Nat8] = Util.concat([compactSize(b.size()), b]);

  func le64(n : Nat64) : [Nat8] {
    let v = Nat64.toNat(n);
    Util.concat([Util.le32(v % 0x1_0000_0000), Util.le32(v / 0x1_0000_0000)]);
  };

  func serialize(tx : Tx, witness : Bool) : [Nat8] {
    let w = witness and Array.any<TxIn>(tx.inputs, func i = i.witness.size() > 0);
    let out = List.empty<[Nat8]>();
    List.add(out, tx.version);
    if (w) List.add<[Nat8]>(out, [0, 1]);
    List.add(out, compactSize(tx.inputs.size()));
    for (i in tx.inputs.vals()) { List.add(out, i.outpoint); List.add(out, field(i.script)); List.add(out, i.sequence) };
    List.add(out, compactSize(tx.outputs.size()));
    for (o in tx.outputs.vals()) List.add(out, o);
    if (w) for (i in tx.inputs.vals()) {
      List.add(out, compactSize(i.witness.size()));
      for (item in i.witness.vals()) List.add(out, field(item));
    };
    List.add(out, tx.lockTime);
    Util.concat(List.toArray(out));
  };

  func sha256(b : [Nat8]) : [Nat8] = Blob.toArray(Sha256.fromArray(#sha256, b));

  // Bitcoin Core's GetScriptOp: the opcode at pc and the position after it and its push data;
  // on failure, the position where Core leaves pc.
  func getOp(s : [Nat8], pc : Nat) : (?Nat8, Nat) {
    let len = s.size();
    if (pc >= len) return (null, pc);
    let op = s[pc];
    var p = pc + 1;
    if (op <= 0x4e) {
      var n = 0;
      if (op < 0x4c) {
        n := Nat8.toNat(op);
      } else if (op == 0x4c) {
        if (len - p < 1) return (null, p);
        n := Nat8.toNat(s[p]);
        p += 1;
      } else if (op == 0x4d) {
        if (len - p < 2) return (null, p);
        n := Nat8.toNat(s[p]) + 256 * Nat8.toNat(s[p + 1]);
        p += 2;
      } else {
        if (len - p < 4) return (null, p);
        n := Nat8.toNat(s[p]) + 256 * Nat8.toNat(s[p + 1]) + 65536 * Nat8.toNat(s[p + 2]) + 16777216 * Nat8.toNat(s[p + 3]);
        p += 4;
      };
      if (len - p < n) return (null, p);
      p += n;
    };
    (?op, p);
  };

  // Core's SerializeScriptCode: without OP_CODESEPARATORs; like Core, bytes after a push that
  // runs past the end are not written (the length still counts them).
  func scriptCode(s : [Nat8]) : [Nat8] {
    var it = 0;
    var seps = 0;
    label count loop {
      switch (getOp(s, it)) {
        case ((?op, p)) { it := p; if (op == 0xab) seps += 1 };
        case ((null, _)) break count;
      };
    };
    let out = List.empty<[Nat8]>();
    List.add(out, compactSize(s.size() - seps));
    it := 0;
    var begin = 0;
    label write loop {
      switch (getOp(s, it)) {
        case ((?op, p)) {
          it := p;
          if (op == 0xab) { List.add(out, Util.slice(s, begin, it - 1)); begin := it };
        };
        case ((null, p)) { it := p; break write };
      };
    };
    if (begin != s.size()) List.add(out, Util.slice(s, begin, it));
    Util.concat(List.toArray(out));
  };

  func legacy(tx : Tx, index : Nat, script : [Nat8], hashType : Nat) : [Nat8] {
    let anyone = hashType / 0x80 % 2 == 1;
    let single = hashType % 0x20 == 3;
    let none = hashType % 0x20 == 2;
    if (single and index >= tx.outputs.size()) return Util.concat([[1], Array.repeat<Nat8>(0, 31)]);
    let out = List.empty<[Nat8]>();
    List.add(out, tx.version);
    let nIn = if (anyone) 1 else tx.inputs.size();
    List.add(out, compactSize(nIn));
    for (j in Nat.range(0, nIn)) {
      let k = if (anyone) index else j;
      let i = tx.inputs[k];
      List.add(out, i.outpoint);
      List.add<[Nat8]>(out, if (k != index) [0] else scriptCode(script));
      List.add<[Nat8]>(out, if (k != index and (single or none)) [0, 0, 0, 0] else i.sequence);
    };
    let nOut = if (none) 0 else if (single) index + 1 else tx.outputs.size();
    List.add(out, compactSize(nOut));
    for (k in Nat.range(0, nOut)) {
      List.add<[Nat8]>(out, if (single and k != index) [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0] else tx.outputs[k]);
    };
    List.add(out, tx.lockTime);
    List.add(out, Util.le32(hashType));
    Hash.doubleSHA256(Util.concat(List.toArray(out)));
  };

  func segwitV0(tx : Tx, index : Nat, script : [Nat8], amount : Nat64, hashType : Nat) : [Nat8] {
    let anyone = hashType / 0x80 % 2 == 1;
    let base = hashType % 0x20;
    let zero = Array.repeat<Nat8>(0, 32);
    let prevouts = if (anyone) zero else Hash.doubleSHA256(Util.concat(Array.map<TxIn, [Nat8]>(tx.inputs, func i = i.outpoint)));
    let sequences = if (anyone or base == 3 or base == 2) zero else Hash.doubleSHA256(Util.concat(Array.map<TxIn, [Nat8]>(tx.inputs, func i = i.sequence)));
    let outputs = if (base != 3 and base != 2) Hash.doubleSHA256(Util.concat(tx.outputs))
      else if (base == 3 and index < tx.outputs.size()) Hash.doubleSHA256(tx.outputs[index])
      else zero;
    let i = tx.inputs[index];
    Hash.doubleSHA256(Util.concat([tx.version, prevouts, sequences, i.outpoint, field(script), le64(amount), i.sequence, outputs, tx.lockTime, Util.le32(hashType)]));
  };

  func taproot(tx : Tx, index : Nat, prevouts : [[Nat8]], hashType : Nat8, annex : ?[Nat8], leaf : ?([Nat8], Nat)) : ?[Nat8] {
    switch hashType { case (0x00 or 0x01 or 0x02 or 0x03 or 0x81 or 0x82 or 0x83) {}; case _ return null };
    let anyone = hashType & 0x80 != 0;
    let outType = hashType & 3;
    if (outType == 3 and index >= tx.outputs.size()) return null;
    let m = List.empty<[Nat8]>();
    List.add<[Nat8]>(m, [0x00, hashType]);
    List.add(m, tx.version);
    List.add(m, tx.lockTime);
    if (not anyone) {
      List.add(m, sha256(Util.concat(Array.map<TxIn, [Nat8]>(tx.inputs, func i = i.outpoint))));
      List.add(m, sha256(Util.concat(Array.map<[Nat8], [Nat8]>(prevouts, func p = Util.slice(p, 0, 8)))));
      List.add(m, sha256(Util.concat(Array.map<[Nat8], [Nat8]>(prevouts, func p = Util.slice(p, 8, p.size())))));
      List.add(m, sha256(Util.concat(Array.map<TxIn, [Nat8]>(tx.inputs, func i = i.sequence))));
    };
    if (outType != 2 and outType != 3) List.add(m, sha256(Util.concat(tx.outputs)));
    List.add<[Nat8]>(m, [(if (leaf != null) 2 else 0) + (if (annex != null) 1 else 0) : Nat8]);
    if (anyone) {
      let i = tx.inputs[index];
      List.add(m, i.outpoint);
      List.add(m, prevouts[index]);
      List.add(m, i.sequence);
    } else {
      List.add(m, Util.le32(index));
    };
    switch annex { case (?a) List.add(m, sha256(field(a))); case null {} };
    if (outType == 3) List.add(m, sha256(tx.outputs[index]));
    switch leaf { case (?(h, pos)) { List.add(m, h); List.add<[Nat8]>(m, [0x00]); List.add(m, Util.le32(pos)) }; case null {} };
    ?Hash.taggedHash(Util.concat(List.toArray(m)), "TapSighash");
  };

  func blob(b : [Nat8]) : Blob = Blob.fromArray(b);

  /// True if `tx` is a valid serialized transaction (see the module doc).
  public func isValid(tx : Blob) : Bool = parse(Blob.toArray(tx)) != null;

  /// The transaction serialized without witnesses (what the txid commits to).
  public func stripWitness(tx : Blob) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    ?blob(serialize(t, false));
  };

  /// The txid: double SHA-256 of the serialization without witnesses, in digest byte order
  /// (as in outpoints; block explorers display it reversed).
  public func txid(tx : Blob) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    ?blob(Hash.doubleSHA256(serialize(t, false)));
  };

  /// The wtxid (BIP141): double SHA-256 of the serialization with witnesses; equal to the txid
  /// when no input has a witness. Digest byte order.
  public func wtxid(tx : Blob) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    ?blob(Hash.doubleSHA256(serialize(t, true)));
  };

  /// The legacy (pre-segwit) signature hash of input `index` (Bitcoin Core's SignatureHash):
  /// `scriptCode` is the script being executed (OP_CODESEPARATORs are removed here) and
  /// `hashType` the 32-bit hash type appended to the signature. SIGHASH_SINGLE without a
  /// matching output gives Core's value 1 (0x01 then 31 zero bytes). Null if the transaction is
  /// invalid, `index` is not an input, or `hashType` exceeds 32 bits.
  public func signatureHashLegacy(tx : Blob, index : Nat64, scriptCode : Blob, hashType : Nat64) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    if (index >= Nat64.fromNat(t.inputs.size()) or hashType > 0xffff_ffff) return null;
    ?blob(legacy(t, Nat64.toNat(index), Blob.toArray(scriptCode), Nat64.toNat(hashType)));
  };

  /// The BIP143 (segwit v0) signature hash of input `index`, which spends `amount` satoshis;
  /// `scriptCode` is used as given. Null as for `signatureHashLegacy`.
  public func signatureHashSegwitV0(tx : Blob, index : Nat64, scriptCode : Blob, amount : Nat64, hashType : Nat64) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    if (index >= Nat64.fromNat(t.inputs.size()) or hashType > 0xffff_ffff) return null;
    ?blob(segwitV0(t, Nat64.toNat(index), Blob.toArray(scriptCode), amount, Nat64.toNat(hashType)));
  };

  /// The BIP341 (Taproot) signature hash of input `index`. `prevouts` is every spent output in
  /// input order, each serialized as in a transaction (8-byte value, CompactSize, scriptPubKey).
  /// `annex` is empty for none, otherwise it starts with 0x50. `leafHash` is empty for a key-path
  /// spend, otherwise the 32-byte TapLeaf hash of a script-path spend with
  /// `codeSeparatorPosition` (0xffffffff when none was executed). Null if the transaction is
  /// invalid, `index` is not an input, the prevouts do not match the inputs, the hash type is not
  /// one of 0x00..0x03, 0x81..0x83, SIGHASH_SINGLE has no matching output, or an argument has a
  /// wrong form.
  public func signatureHashTaproot(tx : Blob, index : Nat64, prevouts : Blob, hashType : Nat64, annex : Blob, leafHash : Blob, codeSeparatorPosition : Nat64) : ?Blob {
    let ?t = parse(Blob.toArray(tx)) else return null;
    if (index >= Nat64.fromNat(t.inputs.size()) or hashType > 0xff or codeSeparatorPosition > 0xffff_ffff) return null;
    let p = Blob.toArray(prevouts);
    let r = Reader(p);
    let outs = List.empty<[Nat8]>();
    while (not r.atEnd()) {
      let ?o = r.output() else return null;
      List.add(outs, o);
    };
    if (List.size(outs) != t.inputs.size()) return null;
    let a = Blob.toArray(annex);
    let an : ?[Nat8] = if (a.size() == 0) null else if (a[0] == 0x50) ?a else return null;
    let l = Blob.toArray(leafHash);
    let leaf : ?([Nat8], Nat) = if (l.size() == 0) null else if (l.size() == 32) ?(l, Nat64.toNat(codeSeparatorPosition)) else return null;
    switch (taproot(t, Nat64.toNat(index), List.toArray(outs), Nat8.fromNat(Nat64.toNat(hashType)), an, leaf)) {
      case (?h) ?blob(h);
      case null null;
    };
  };
};
