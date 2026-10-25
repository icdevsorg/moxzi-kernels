/// ML-DSA-44 in Motoko: a direct port of FIPS 204 (August 2024) -- key generation from the seed,
/// external (pure) signing and verification. It is the Motoko body behind `MlDsa44.mo` and must
/// agree with the native kernel (libcrux-ml-dsa 0.0.11) on every input; the NIST ACVP known
/// answers and the kernel itself are its tests (moxzi's PocketIC suite for this package).
/// Algorithm numbers below are FIPS 204's. SHAKE128/SHAKE256 (FIPS 202) are implemented here
/// on a Keccak-f[1600] permutation; polynomials are [var Nat] with coefficients in [0, q).
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import Int "mo:core/Int";
import Prim "mo:⛔";

module {
  let Q : Nat = 8380417;
  let K = 4;
  let L = 4;
  let TAU = 39;
  let BETA : Nat = 78;
  let GAMMA1 : Nat = 131072; // 2^17
  let GAMMA2 : Nat = 95232; // (q - 1) / 88
  let OMEGA = 80;
  let N_INV : Nat = 8347681; // 256^-1 mod q
  public let PK_LEN = 1312;
  public let SIG_LEN = 2420;

  // ---------------------------------------------------------------------------------------------
  // Keccak-f[1600] and SHAKE (FIPS 202)

  let RC : [Nat64] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
  ];
  // Rotation offsets r[x + 5y].
  let ROT : [Nat64] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

  func keccakF(a : [var Nat64]) {
    let c = VarArray.repeat<Nat64>(0, 5);
    let b = VarArray.repeat<Nat64>(0, 25);
    var round = 0;
    while (round < 24) {
      var x = 0;
      while (x < 5) { c[x] := a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]; x += 1 };
      x := 0;
      while (x < 5) {
        let d = c[(x + 4) % 5] ^ (c[(x + 1) % 5] <<> 1);
        var y = 0;
        while (y < 25) { a[x + y] ^= d; y += 5 };
        x += 1;
      };
      x := 0;
      while (x < 5) {
        var y = 0;
        while (y < 5) { b[y + 5 * ((2 * x + 3 * y) % 5)] := a[x + 5 * y] <<> ROT[x + 5 * y]; y += 1 };
        x += 1;
      };
      var y = 0;
      while (y < 25) {
        x := 0;
        while (x < 5) { a[x + y] := b[x + y] ^ ((^ b[(x + 1) % 5 + y]) & b[(x + 2) % 5 + y]); x += 1 };
        y += 5;
      };
      a[0] ^= RC[round];
      round += 1;
    };
  };

  /// A SHAKE instance (rate 168: SHAKE128, rate 136: SHAKE256) over `input`, squeezed bytewise.
  class Xof(rate : Nat, input : [Nat8]) {
    let s = VarArray.repeat<Nat64>(0, 25);
    func xorByte(i : Nat, v : Nat8) {
      s[i / 8] ^= Nat64.fromNat(Nat8.toNat(v)) << Nat64.fromNat(8 * (i % 8));
    };
    var off = 0;
    while (input.size() - off >= rate) {
      var i = 0;
      while (i < rate) { xorByte(i, input[off + i]); i += 1 };
      keccakF(s);
      off += rate;
    };
    var i = 0;
    while (off + i < input.size()) { xorByte(i, input[off + i]); i += 1 };
    xorByte(i, 0x1f);
    xorByte(rate - 1, 0x80);
    keccakF(s);
    var pos = 0;

    public func next() : Nat8 {
      if (pos == rate) { keccakF(s); pos := 0 };
      let v = Nat8.fromNat(Nat64.toNat((s[pos / 8] >> Nat64.fromNat(8 * (pos % 8))) & 0xff));
      pos += 1;
      v;
    };

    public func bytes(n : Nat) : [Nat8] = Array.tabulate<Nat8>(n, func _ = next());
  };

  func shake256(input : [Nat8], n : Nat) : [Nat8] = Xof(136, input).bytes(n);

  // ---------------------------------------------------------------------------------------------
  // NTT (Algorithms 41, 42); ZETAS[k] = 1753^brv8(k) mod q

  let ZETAS : [Nat] = [
    1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975,
    7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639,
    2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148, 928749,
    1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881, 4805951,
    3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338, 1853806,
    3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066, 482649,
    1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814, 5183169,
    1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206, 4197502,
    7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812, 8052569,
    1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527, 2660408,
    6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264, 4969849,
    2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938, 6653329,
    2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676, 2642980,
    1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950, 7921677,
    6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063, 2105286, 6006015,
    6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325, 6987258, 507927, 7192532,
    7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144, 3994671, 8368538,
    7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144,
    3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054,
    7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
  ];

  func ntt(w : [var Nat]) {
    var m = 0;
    var len = 128;
    while (len >= 1) {
      var start = 0;
      while (start < 256) {
        m += 1;
        let z = ZETAS[m];
        var j = start;
        while (j < start + len) {
          let t = (z * w[j + len]) % Q;
          w[j + len] := (w[j] + Q - t) % Q;
          w[j] := (w[j] + t) % Q;
          j += 1;
        };
        start += 2 * len;
      };
      len /= 2;
    };
  };

  func invNtt(w : [var Nat]) {
    var m = 256;
    var len = 1;
    while (len < 256) {
      var start = 0;
      while (start < 256) {
        m -= 1;
        let z = Q - ZETAS[m];
        var j = start;
        while (j < start + len) {
          let t = w[j];
          w[j] := (t + w[j + len]) % Q;
          w[j + len] := (z * ((t + Q - w[j + len]) % Q)) % Q;
          j += 1;
        };
        start += 2 * len;
      };
      len *= 2;
    };
    var j = 0;
    while (j < 256) { w[j] := (w[j] * N_INV) % Q; j += 1 };
  };

  func copy(a : [var Nat]) : [var Nat] = Prim.Array_tabulateVar<Nat>(256, func i = a[i]);
  func nttOf(a : [var Nat]) : [var Nat] { let b = copy(a); ntt(b); b };
  func add(a : [var Nat], b : [var Nat]) : [var Nat] = Prim.Array_tabulateVar<Nat>(256, func i = (a[i] + b[i]) % Q);
  func sub(a : [var Nat], b : [var Nat]) : [var Nat] = Prim.Array_tabulateVar<Nat>(256, func i = (a[i] + Q - b[i]) % Q);
  func neg(a : [var Nat]) : [var Nat] = Prim.Array_tabulateVar<Nat>(256, func i = (Q - a[i]) % Q);
  /// sum_s a[s] o b[s] in the NTT domain, then back.
  func dotInv(a : [[var Nat]], b : [[var Nat]]) : [var Nat] {
    let acc = VarArray.repeat<Nat>(0, 256);
    for (s in a.keys()) {
      let (x, y) = (a[s], b[s]);
      var i = 0;
      while (i < 256) { acc[i] := (acc[i] + x[i] * y[i]) % Q; i += 1 };
    };
    invNtt(acc);
    acc;
  };
  func mulInv(a : [var Nat], b : [var Nat]) : [var Nat] {
    let r = Prim.Array_tabulateVar<Nat>(256, func i = (a[i] * b[i]) % Q);
    invNtt(r);
    r;
  };

  /// |x| for x mod q in centered form.
  func abs(x : Nat) : Nat = if (x > (Q - 1) / 2) Q - x else x;
  func normBelow(polys : [[var Nat]], bound : Nat) : Bool {
    for (p in polys.values()) for (x in p.values()) if (abs(x) >= bound) return false;
    true;
  };

  // ---------------------------------------------------------------------------------------------
  // Sampling (Algorithms 29-34)

  /// RejNTTPoly over SHAKE128(seed).
  func rejNtt(seed : [Nat8]) : [var Nat] {
    let x = Xof(168, seed);
    let a = VarArray.repeat<Nat>(0, 256);
    var j = 0;
    while (j < 256) {
      let b0 = Nat8.toNat(x.next());
      let b1 = Nat8.toNat(x.next());
      let b2 = Nat8.toNat(x.next()) % 128;
      let c = b0 + 256 * b1 + 65536 * b2;
      if (c < Q) { a[j] := c; j += 1 };
    };
    a;
  };

  /// RejBoundedPoly over SHAKE256(seed) for eta = 2.
  func rejBounded(seed : [Nat8]) : [var Nat] {
    let x = Xof(136, seed);
    let a = VarArray.repeat<Nat>(0, 256);
    var j = 0;
    func half(b : Nat) : ?Nat = if (b < 15) ?((Q + 2 - b % 5) % Q) else null;
    while (j < 256) {
      let z = Nat8.toNat(x.next());
      switch (half(z % 16)) { case (?c) { a[j] := c; j += 1 }; case null {} };
      if (j < 256) switch (half(z / 16)) { case (?c) { a[j] := c; j += 1 }; case null {} };
    };
    a;
  };

  /// ExpandA: A[r][s] = RejNTTPoly(rho || s || r).
  func expandA(rho : [Nat8]) : [[[var Nat]]] =
    Array.tabulate<[[var Nat]]>(K, func r = Array.tabulate<[var Nat]>(L, func s = rejNtt(Array.concat<Nat8>(rho, [Nat8.fromNat(s), Nat8.fromNat(r)]))));

  /// SampleInBall(c_tilde): tau coefficients of +-1.
  func sampleInBall(rho : [Nat8]) : [var Nat] {
    let x = Xof(136, rho);
    let sb = x.bytes(8);
    var h : Nat = 0;
    var i = 8;
    while (i > 0) { i -= 1; h := h * 256 + Nat8.toNat(sb[i]) };
    let c = VarArray.repeat<Nat>(0, 256);
    var k = 256 - TAU;
    while (k < 256) {
      var j = Nat8.toNat(x.next());
      while (j > k) j := Nat8.toNat(x.next());
      c[k] := c[j];
      c[j] := if ((h / (2 ** (k + TAU - 256))) % 2 == 1) Q - 1 else 1;
      k += 1;
    };
    c;
  };

  /// ExpandMask(rho'', kappa): y[r] = BitUnpack(SHAKE256(rho'' || kappa + r, 576), gamma1 - 1, gamma1).
  func expandMask(rho : [Nat8], kappa : Nat) : [[var Nat]] =
    Array.tabulate<[var Nat]>(L, func r {
      let n = kappa + r;
      let v = shake256(Array.concat<Nat8>(rho, [Nat8.fromNat(n % 256), Nat8.fromNat(n / 256)]), 576);
      VarArray.map<Nat, Nat>(unpack(v, 0, 256, 18), func b = (Q + GAMMA1 - b) % Q);
    });

  // ---------------------------------------------------------------------------------------------
  // Bit packing (Algorithms 16-21), little-endian bit order

  func pack(out : [var Nat8], at : Nat, values : [var Nat], bits : Nat) {
    var acc = 0;
    var nbits = 0;
    var o = at;
    var scale = 1;
    for (v in values.values()) {
      acc += v * scale;
      scale *= 2 ** bits;
      nbits += bits;
      while (nbits >= 8) { out[o] := Nat8.fromNat(acc % 256); acc /= 256; scale /= 256; nbits -= 8; o += 1 };
    };
  };

  func unpack(b : [Nat8], at : Nat, count : Nat, bits : Nat) : [var Nat] {
    let out = VarArray.repeat<Nat>(0, count);
    let mask = 2 ** bits;
    var acc = 0;
    var nbits = 0;
    var scale = 1;
    var i = at;
    var k = 0;
    while (k < count) {
      while (nbits < bits) { acc += Nat8.toNat(b[i]) * scale; scale *= 256; nbits += 8; i += 1 };
      out[k] := acc % mask;
      acc /= mask;
      scale /= mask;
      nbits -= bits;
      k += 1;
    };
    out;
  };

  // ---------------------------------------------------------------------------------------------
  // Rounding (Algorithms 35-40)

  /// Decompose(r): (r1, r0) with r0 signed, as an Int.
  func decompose(r : Nat) : (Nat, Int) {
    var r0 : Int = r % (2 * GAMMA2);
    if (r0 > GAMMA2) r0 -= 2 * GAMMA2;
    if (r - r0 == Q - 1) (0, r0 - 1) else (Int.abs(r - r0) / (2 * GAMMA2), r0);
  };
  func highBits(r : Nat) : Nat = decompose(r).0;
  func useHint(h : Bool, r : Nat) : Nat {
    let (r1, r0) = decompose(r);
    if (not h) r1 else if (r0 > 0) (r1 + 1) % 44 else (r1 + 43) % 44;
  };

  /// w1Encode: 6 bits per coefficient.
  func w1Encode(w1 : [[var Nat]]) : [Nat8] {
    let out = VarArray.repeat<Nat8>(0, 192 * K);
    for (r in w1.keys()) pack(out, 192 * r, w1[r], 6);
    Array.fromVarArray(out);
  };

  // ---------------------------------------------------------------------------------------------
  // Keys (Algorithm 6)

  type Key = { rho : [Nat8]; key : [Nat8]; tr : [Nat8]; a : [[[var Nat]]]; s1 : [[var Nat]]; s2 : [[var Nat]]; t0 : [[var Nat]]; pk : [Nat8] };

  func keyGen(xi : [Nat8]) : Key {
    let seeds = shake256(Array.concat<Nat8>(xi, [Nat8.fromNat(K), Nat8.fromNat(L)]), 128);
    let rho = Array.sliceToArray(seeds, 0, 32);
    let rhoPrime = Array.sliceToArray(seeds, 32, 96);
    let key = Array.sliceToArray(seeds, 96, 128);
    let a = expandA(rho);
    let s = Array.tabulate<[var Nat]>(K + L, func r = rejBounded(Array.concat<Nat8>(rhoPrime, [Nat8.fromNat(r), 0])));
    let s1 = Array.sliceToArray(s, 0, L);
    let s2 = Array.sliceToArray(s, L, K + L);
    let s1Hat = Array.map<[var Nat], [var Nat]>(s1, nttOf);
    let t = Array.tabulate<[var Nat]>(K, func r = add(dotInv(a[r], s1Hat), s2[r]));
    // Power2Round: t = t1 * 2^13 + t0, t0 in (-2^12, 2^12].
    let t1 = Array.tabulate<[var Nat]>(K, func _ = VarArray.repeat<Nat>(0, 256));
    let t0 = Array.tabulate<[var Nat]>(K, func _ = VarArray.repeat<Nat>(0, 256));
    for (r in t.keys()) {
      for (i in t[r].keys()) {
        let v = t[r][i];
        var low = v % 8192;
        if (low > 4096) low += Q - 8192; // negative: as a field element
        let lowSigned : Int = if (low > 4096) low - Q else low;
        t1[r][i] := Int.abs(v - lowSigned) / 8192;
        t0[r][i] := low % Q;
      };
    };
    let pkv = VarArray.repeat<Nat8>(0, PK_LEN);
    for (i in rho.keys()) pkv[i] := rho[i];
    for (r in t1.keys()) pack(pkv, 32 + 320 * r, t1[r], 10);
    let pk = Array.fromVarArray(pkv);
    { rho; key; tr = shake256(pk, 64); a; s1; s2; t0; pk };
  };

  public func publicKey(xi : [Nat8]) : [Nat8] = keyGen(xi).pk;

  // ---------------------------------------------------------------------------------------------
  // Signing (Algorithm 7, with Algorithm 2's M' = 0 || |ctx| || ctx || M)

  func mPrime(ctx : [Nat8], m : [Nat8]) : [Nat8] = Array.flatten<Nat8>([[0, Nat8.fromNat(ctx.size())], ctx, m]);

  public func sign(xi : [Nat8], m : [Nat8], ctx : [Nat8], rnd : [Nat8]) : [Nat8] {
    let k = keyGen(xi);
    let s1Hat = Array.map<[var Nat], [var Nat]>(k.s1, nttOf);
    let s2Hat = Array.map<[var Nat], [var Nat]>(k.s2, nttOf);
    let t0Hat = Array.map<[var Nat], [var Nat]>(k.t0, nttOf);
    let mu = shake256(Array.concat(k.tr, mPrime(ctx, m)), 64);
    let rhoPP = shake256(Array.flatten<Nat8>([k.key, rnd, mu]), 64);
    var kappa = 0;
    loop {
      let y = expandMask(rhoPP, kappa);
      kappa += L;
      let yHat = Array.map<[var Nat], [var Nat]>(y, nttOf);
      let w = Array.tabulate<[var Nat]>(K, func r = dotInv(k.a[r], yHat));
      let w1 = Array.map<[var Nat], [var Nat]>(w, func p = VarArray.map<Nat, Nat>(p, highBits));
      let cTilde = shake256(Array.concat(mu, w1Encode(w1)), 32);
      let cHat = nttOf(sampleInBall(cTilde));
      let z = Array.tabulate<[var Nat]>(L, func s = add(y[s], mulInv(cHat, s1Hat[s])));
      let wcs2 = Array.tabulate<[var Nat]>(K, func r = sub(w[r], mulInv(cHat, s2Hat[r])));
      let r0ok = do {
        var ok = true;
        for (p in wcs2.values()) for (x in p.values()) if (Int.abs(decompose(x).1) >= GAMMA2 - BETA) ok := false;
        ok;
      };
      if (normBelow(z, GAMMA1 - BETA) and r0ok) {
        let ct0 = Array.tabulate<[var Nat]>(K, func r = mulInv(cHat, t0Hat[r]));
        // MakeHint(-ct0, w - cs2 + ct0): whether adding -ct0 changes the high bits.
        var ones = 0;
        let h = Array.tabulate<[var Bool]>(K, func r {
          let hr = VarArray.repeat<Bool>(false, 256);
          for (i in hr.keys()) {
            let rr = (wcs2[r][i] + ct0[r][i]) % Q;
            if (highBits(rr) != highBits(wcs2[r][i])) { hr[i] := true; ones += 1 };
          };
          hr;
        });
        if (normBelow(ct0, GAMMA2) and ones <= OMEGA) {
          let out = VarArray.repeat<Nat8>(0, SIG_LEN);
          for (i in cTilde.keys()) out[i] := cTilde[i];
          for (s in z.keys()) pack(out, 32 + 576 * s, VarArray.map<Nat, Nat>(z[s], func c = (GAMMA1 + Q - c) % Q), 18);
          var index = 0;
          for (r in h.keys()) {
            for (i in h[r].keys()) if (h[r][i]) { out[2336 + index] := Nat8.fromNat(i); index += 1 };
            out[2336 + OMEGA + r] := Nat8.fromNat(index);
          };
          return Array.fromVarArray(out);
        };
      };
    };
  };

  // ---------------------------------------------------------------------------------------------
  // Verification (Algorithm 8, with Algorithm 3's M')

  public func verify(pk : [Nat8], m : [Nat8], sig : [Nat8], ctx : [Nat8]) : Bool {
    if (pk.size() != PK_LEN or sig.size() != SIG_LEN or ctx.size() > 255) return false;
    let rho = Array.sliceToArray(pk, 0, 32);
    let t1 = Array.tabulate<[var Nat]>(K, func r = unpack(pk, 32 + 320 * r, 256, 10));
    let cTilde = Array.sliceToArray(sig, 0, 32);
    let z = Array.tabulate<[var Nat]>(L, func s = VarArray.map<Nat, Nat>(unpack(sig, 32 + 576 * s, 256, 18), func b = (Q + GAMMA1 - b) % Q));
    // HintBitUnpack (Algorithm 21).
    let h = Array.tabulate<[var Bool]>(K, func _ = VarArray.repeat<Bool>(false, 256));
    let y = Array.sliceToArray(sig, 2336, 2420);
    var index = 0;
    for (r in h.keys()) {
      let cut = Nat8.toNat(y[OMEGA + r]);
      if (cut < index or cut > OMEGA) return false;
      let first = index;
      while (index < cut) {
        if (index > first and y[index - 1] >= y[index]) return false;
        h[r][Nat8.toNat(y[index])] := true;
        index += 1;
      };
    };
    while (index < OMEGA) { if (y[index] != 0) return false; index += 1 };
    if (not normBelow(z, GAMMA1 - BETA)) return false;
    let a = expandA(rho);
    let tr = shake256(pk, 64);
    let mu = shake256(Array.concat(tr, mPrime(ctx, m)), 64);
    let cHat = nttOf(sampleInBall(cTilde));
    let zHat = Array.map<[var Nat], [var Nat]>(z, nttOf);
    let w1 = Array.tabulate<[var Nat]>(K, func r {
      let t1Hat = nttOf(VarArray.map<Nat, Nat>(t1[r], func c = (c * 8192) % Q));
      let az = VarArray.repeat<Nat>(0, 256);
      for (s in zHat.keys()) for (i in az.keys()) az[i] := (az[i] + a[r][s][i] * zHat[s][i]) % Q;
      for (i in az.keys()) az[i] := (az[i] + Q - (cHat[i] * t1Hat[i]) % Q) % Q;
      invNtt(az);
      Prim.Array_tabulateVar<Nat>(256, func i = useHint(h[r][i], az[i]));
    });
    shake256(Array.concat(mu, w1Encode(w1)), 32) == cTilde;
  };
};
