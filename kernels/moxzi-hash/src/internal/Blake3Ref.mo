/// BLAKE3, a direct port of the official reference implementation
/// (https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs, CC0 /
/// Apache-2.0). The Motoko fallback of moxzi-hash's Blake3 module, and its test oracle against the
/// native kernel. Written because mo:blake3 0.1.2 never merges chunk chaining values into parent
/// nodes, so every input longer than one 1 KiB chunk hashes wrongly.
import Array "mo:core/Array";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";
import Nat "mo:core/Nat";

module {
  let BLOCK_LEN = 64;
  let CHUNK_LEN = 1024;
  let CHUNK_START : Nat32 = 1;
  let CHUNK_END : Nat32 = 2;
  let PARENT : Nat32 = 4;
  let ROOT : Nat32 = 8;
  public let KEYED_HASH : Nat32 = 16;
  public let IV : [Nat32] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
  let PERM : [Nat] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

  func g(s : [var Nat32], a : Nat, b : Nat, c : Nat, d : Nat, mx : Nat32, my : Nat32) {
    s[a] := s[a] +% s[b] +% mx; s[d] := (s[d] ^ s[a]) <>> 16; s[c] := s[c] +% s[d]; s[b] := (s[b] ^ s[c]) <>> 12;
    s[a] := s[a] +% s[b] +% my; s[d] := (s[d] ^ s[a]) <>> 8; s[c] := s[c] +% s[d]; s[b] := (s[b] ^ s[c]) <>> 7;
  };

  func compress(cv : [Nat32], m0 : [Nat32], counter : Nat64, blockLen : Nat, flags : Nat32) : [Nat32] {
    let s = VarArray.repeat<Nat32>(0, 16);
    var i = 0;
    while (i < 8) { s[i] := cv[i]; i += 1 };
    s[8] := IV[0]; s[9] := IV[1]; s[10] := IV[2]; s[11] := IV[3];
    s[12] := Nat32.fromNat(Nat64.toNat(counter & 0xFFFFFFFF)); s[13] := Nat32.fromNat(Nat64.toNat(counter >> 32));
    s[14] := Nat32.fromNat(blockLen); s[15] := flags;
    var m = m0;
    var r = 0;
    while (r < 7) {
      g(s, 0, 4, 8, 12, m[0], m[1]); g(s, 1, 5, 9, 13, m[2], m[3]); g(s, 2, 6, 10, 14, m[4], m[5]); g(s, 3, 7, 11, 15, m[6], m[7]);
      g(s, 0, 5, 10, 15, m[8], m[9]); g(s, 1, 6, 11, 12, m[10], m[11]); g(s, 2, 7, 8, 13, m[12], m[13]); g(s, 3, 4, 9, 14, m[14], m[15]);
      let prev = m;
      m := Array.tabulate<Nat32>(16, func k = prev[PERM[k]]);
      r += 1;
    };
    i := 0;
    while (i < 8) { s[i] := s[i] ^ s[i + 8]; s[i + 8] := s[i + 8] ^ cv[i]; i += 1 };
    Array.fromVarArray(s);
  };

  func words(b : [var Nat8]) : [Nat32] = Array.tabulate<Nat32>(16, func k =
    Nat32.fromNat(Nat8.toNat(b[4 * k])) | (Nat32.fromNat(Nat8.toNat(b[4 * k + 1])) << 8)
    | (Nat32.fromNat(Nat8.toNat(b[4 * k + 2])) << 16) | (Nat32.fromNat(Nat8.toNat(b[4 * k + 3])) << 24));

  /// The 8 little-endian words of a 32-byte key.
  public func keyWords(key : [Nat8]) : [Nat32] = Array.tabulate<Nat32>(8, func k =
    Nat32.fromNat(Nat8.toNat(key[4 * k])) | (Nat32.fromNat(Nat8.toNat(key[4 * k + 1])) << 8)
    | (Nat32.fromNat(Nat8.toNat(key[4 * k + 2])) << 16) | (Nat32.fromNat(Nat8.toNat(key[4 * k + 3])) << 24));

  type Output = { cv : [Nat32]; block : [Nat32]; counter : Nat64; blockLen : Nat; flags : Nat32 };

  func chainingValue(o : Output) : [Nat32] = Array.sliceToArray(compress(o.cv, o.block, o.counter, o.blockLen, o.flags), 0, 8);

  func rootBytes(o : Output, outLen : Nat) : [Nat8] {
    let out = VarArray.repeat<Nat8>(0, outLen);
    var pos = 0;
    var counter : Nat64 = 0;
    while (pos < outLen) {
      let w = compress(o.cv, o.block, counter, o.blockLen, o.flags | ROOT);
      var k = 0;
      while (k < 64 and pos < outLen) {
        out[pos] := Nat8.fromNat(Nat32.toNat((w[k / 4] >> Nat32.fromNat(8 * (k % 4))) & 0xFF));
        pos += 1; k += 1;
      };
      counter += 1;
    };
    Array.fromVarArray(out);
  };

  func parentOutput(left : [Nat32], right : [Nat32], key : [Nat32], flags : Nat32) : Output =
    { cv = key; block = Array.concat(left, right); counter = 0; blockLen = BLOCK_LEN; flags = PARENT | flags };

  /// BLAKE3 of `input` under `key` words (IV for plain hashing) and `flags` (0, or KEYED_HASH).
  public func hash(key : [Nat32], flags : Nat32, input : [Nat8], outLen : Nat) : [Nat8] {
    // Chunk state.
    var cv : [Nat32] = key;
    var chunkCounter : Nat64 = 0;
    let block = VarArray.repeat<Nat8>(0, BLOCK_LEN);
    var blockLen = 0;
    var blocksCompressed = 0;
    func startFlag() : Nat32 = if (blocksCompressed == 0) CHUNK_START else 0;
    func chunkLen() : Nat = BLOCK_LEN * blocksCompressed + blockLen;
    func chunkOutput() : Output =
      { cv; block = words(block); counter = chunkCounter; blockLen; flags = flags | startFlag() | CHUNK_END };
    // The chaining-value stack.
    var stack : [[Nat32]] = [];
    var i = 0;
    let n = input.size();
    while (i < n) {
      if (chunkLen() == CHUNK_LEN) {
        var newCv = chainingValue(chunkOutput());
        var total = chunkCounter + 1;
        while (total & 1 == 0) {
          let left = stack[stack.size() - 1];
          stack := Array.sliceToArray(stack, 0, stack.size() - 1);
          newCv := chainingValue(parentOutput(left, newCv, key, flags));
          total >>= 1;
        };
        stack := Array.concat(stack, [newCv]);
        cv := key; chunkCounter += 1; blockLen := 0; blocksCompressed := 0;
        var z = 0; while (z < BLOCK_LEN) { block[z] := 0; z += 1 };
      };
      // Within a chunk: compress a FULL block only when more input follows it.
      if (blockLen == BLOCK_LEN) {
        cv := Array.sliceToArray(compress(cv, words(block), chunkCounter, BLOCK_LEN, flags | startFlag()), 0, 8);
        blocksCompressed += 1; blockLen := 0;
        var z = 0; while (z < BLOCK_LEN) { block[z] := 0; z += 1 };
      };
      let room = Nat.min(BLOCK_LEN - blockLen, CHUNK_LEN - chunkLen());
      let take = Nat.min(room, n - i);
      var k = 0;
      while (k < take) { block[blockLen + k] := input[i + k]; k += 1 };
      blockLen += take; i += take;
    };
    var out = chunkOutput();
    var remaining = stack.size();
    while (remaining > 0) {
      remaining -= 1;
      out := parentOutput(stack[remaining], chainingValue(out), key, flags);
    };
    rootBytes(out, outLen);
  };
};
