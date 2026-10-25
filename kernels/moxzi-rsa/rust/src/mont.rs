//! Montgomery arithmetic modulo an odd N-limb modulus, on 32-bit limbs.
//!
//! Why this exists: wasm has a 64 x 64 -> 64 multiply but no 64 x 64 -> 128 one, so the u64-digit
//! BigUint of `rsa` pays a `__multi3` call (about 60 instructions) for every limb product. On
//! 32-bit limbs a limb product is one native `i64.mul`. This module is the modular
//! exponentiation only; keys, encodings and the PSS rules stay with `rsa`/`sha2` and lib.rs.
//!
//! Numbers are `[u32; N]`, little-endian limbs. R = 2^(32 N). A modulus is accepted only when it
//! is odd and its top bit (bit 32 N - 1) is set, so R/2 <= n < R; callers fall back otherwise.

/// A modulus n with its Montgomery constant n0 = -n^-1 mod 2^32.
pub struct Modulus<const N: usize> {
    n: [u32; N],
    n0: u32,
}

impl<const N: usize> Modulus<N> {
    /// `n` as big-endian bytes (exactly 4 N of them); None unless odd with the top bit set.
    pub fn from_be(bytes: &[u8]) -> Option<Self> {
        let n = from_be::<N>(bytes)?;
        if n[0] & 1 == 0 || n[N - 1] >> 31 == 0 {
            return None;
        }
        // Newton's iteration for n^-1 mod 2^32: each step doubles the number of correct bits.
        let mut inv: u32 = 1;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        Some(Modulus { n, n0: inv.wrapping_neg() })
    }

    /// a * b / R mod n, for a, b < n. Constant time: the same instructions for every input.
    ///
    /// CIOS (Koc, Acar, Kaliski 1996): for each limb a_i, t = (t + a_i b + m n) / 2^32 with m
    /// chosen so the division is exact, as two carry chains (a_i b and m n) that each stay below
    /// 2^64; t < 2n throughout. The division is not a shift: row i works on the window buf[i..],
    /// so the word that becomes zero is simply left behind. The row is unrolled (N is a multiple
    /// of 8, at most 96) so every limb access is a constant offset from one pointer -- on wasm64
    /// that is about half the instructions of an indexed loop.
    pub fn mul(&self, a: &[u32; N], b: &[u32; N]) -> [u32; N] {
        const MAX: usize = 2 * 96 + 2;
        const { assert!(N % 8 == 0 && N <= 96) };
        let mut buf = [0u32; MAX];
        unsafe {
            let bp = b.as_ptr();
            let np = self.n.as_ptr();
            for (i, &ai) in a.iter().enumerate() {
                let ai = ai as u64;
                // (black_box keeps the row's accesses as offsets from w; without it the loop
                // optimizer rewrites them into separately computed addresses.)
                let w = core::hint::black_box(buf.as_mut_ptr().add(i));
                let m = ((*w).wrapping_add((ai as u32).wrapping_mul(*bp))).wrapping_mul(self.n0) as u64;
                let mut c1 = 0u64;
                let mut c2 = 0u64;
                macro_rules! step {
                    ($k:expr) => {
                        let s = *w.add($k) as u64 + ai * *bp.add($k) as u64 + c1;
                        c1 = s >> 32;
                        let s2 = (s as u32) as u64 + m * *np.add($k) as u64 + c2;
                        c2 = s2 >> 32;
                        *w.add($k) = s2 as u32;
                    };
                }
                macro_rules! step8 {
                    ($($b:expr),*) => { $( if $b < N {
                        step!($b); step!($b + 1); step!($b + 2); step!($b + 3);
                        step!($b + 4); step!($b + 5); step!($b + 6); step!($b + 7);
                    } )* };
                }
                step8!(0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88);
                let s = *w.add(N) as u64 + c1 + c2;
                *w.add(N) = s as u32;
                *w.add(N + 1) = (s >> 32) as u32;
            }
            let mut t = [0u32; N];
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(N), t.as_mut_ptr(), N);
            self.reduce_once(t, buf[2 * N])
        }
    }

    /// (hi R + t) mod n for hi R + t < 2n: subtract n when the value is >= n, without branching.
    fn reduce_once(&self, t: [u32; N], hi: u32) -> [u32; N] {
        let mut d = [0u32; N];
        let mut borrow = 0u64;
        for j in 0..N {
            let s = (t[j] as u64).wrapping_sub(self.n[j] as u64).wrapping_sub(borrow);
            d[j] = s as u32;
            borrow = (s >> 63) & 1;
        }
        // Keep d when hi = 1 (the value is >= R > n) or when there was no borrow (t >= n).
        let keep_d = ((hi as u64) | (borrow ^ 1)) & 1;
        // black_box: knowing mask is 0 or all ones, LLVM turns the merge below into a select of
        // which array to copy -- an address that depends on whether the extra reduction happened.
        let mask = core::hint::black_box((keep_d as u32).wrapping_neg());
        let mut r = [0u32; N];
        for j in 0..N {
            r[j] = (d[j] & mask) | (t[j] & !mask);
        }
        r
    }

    /// x R mod n for x < n (the Montgomery form), by N steps of "times 2^32 mod n" (variable
    /// time: for public values only).
    pub fn to_mont_vartime(&self, x: &[u32; N]) -> [u32; N] {
        let mut r = *x;
        for _ in 0..N {
            r = self.shift_word_vartime(&r);
        }
        r
    }

    /// r 2^32 mod n for r < n. Quotient digit estimated from the top limbs (Knuth's algorithm D;
    /// n is normalized, so the estimate exceeds the quotient by at most 2), then corrected.
    fn shift_word_vartime(&self, r: &[u32; N]) -> [u32; N] {
        // y = r 2^32 has N + 1 limbs: y[0] = 0, y[i + 1] = r[i].
        let top = ((r[N - 1] as u64) << 32) | r[N - 2] as u64;
        let q = core::cmp::min(top / self.n[N - 1] as u64, u32::MAX as u64);
        // y - q n, as N limbs plus a signed top word.
        let mut out = [0u32; N];
        let mut carry = 0u64; // q n's carry
        let mut borrow = 0u64;
        unsafe {
            let (np, rp, op) = (self.n.as_ptr(), r.as_ptr(), out.as_mut_ptr());
            macro_rules! step {
                ($j:expr) => {
                    let p = q * *np.add($j) as u64 + carry;
                    carry = p >> 32;
                    let yj = if $j == 0 { 0 } else { *rp.add(if $j == 0 { 0 } else { $j - 1 }) as u64 };
                    let s = yj.wrapping_sub(p & 0xffff_ffff).wrapping_sub(borrow);
                    *op.add($j) = s as u32;
                    borrow = (s >> 63) & 1;
                };
            }
            macro_rules! step8 {
                ($($b:expr),*) => { $( if $b < N {
                    step!($b); step!($b + 1); step!($b + 2); step!($b + 3);
                    step!($b + 4); step!($b + 5); step!($b + 6); step!($b + 7);
                } )* };
            }
            step8!(0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88);
        }
        let mut top_word = (r[N - 1] as i64) - (carry as i64) - (borrow as i64);
        while top_word < 0 {
            // Add n back (at most twice).
            let mut c = 0u64;
            for j in 0..N {
                let s = out[j] as u64 + self.n[j] as u64 + c;
                out[j] = s as u32;
                c = s >> 32;
            }
            top_word += c as i64;
        }
        out
    }

    /// x^e mod n for x < n and a public exponent e (big-endian bytes), left to right.
    ///
    /// Leading zero bytes of e are skipped first (they leave acc at None, so the result is the
    /// same): e comes from the caller's key, of any length, and was walked bit by bit -- a key
    /// whose e is 2 MB of zeros then 65537 made verification ~80 M instructions instead of
    /// ~4.6 M (found in adversarial review; natively 20.2 ms against 0.27 ms, 0.58 ms with the skip).
    pub fn pow_public(&self, x: &[u32; N], e: &[u8]) -> [u32; N] {
        let xm = self.to_mont_vartime(x);
        let mut acc: Option<[u32; N]> = None;
        for &byte in significant(e) {
            #[cfg(test)]
            POW_PUBLIC_BYTES.with(|c| c.set(c.get() + 1));
            for bit in (0..8).rev() {
                if let Some(a) = acc {
                    acc = Some(self.mul(&a, &a));
                }
                if (byte >> bit) & 1 == 1 {
                    acc = Some(match acc {
                        Some(a) => self.mul(&a, &xm),
                        None => xm,
                    });
                }
            }
        }
        match acc {
            Some(a) => self.from_mont(&a),
            None => {
                // e = 0: x^0 = 1 (mod n > 1).
                let mut one = [0u32; N];
                one[0] = 1;
                one
            }
        }
    }

    /// x / R mod n: leave the Montgomery form.
    pub fn from_mont(&self, x: &[u32; N]) -> [u32; N] {
        let mut one = [0u32; N];
        one[0] = 1;
        self.mul(x, &one)
    }

    /// x^e mod n for a secret exponent e < 2^(32 N) given as N limbs, x < n given in Montgomery
    /// form, with a fixed 5-bit window: every exponent of N limbs costs the same squarings and
    /// multiplications, and the table entry is selected by scanning the whole table. Returns
    /// the result out of Montgomery form.
    pub fn pow_secret(&self, xm: &[u32; N], e: &[u32; N], one_m: &[u32; N]) -> [u32; N] {
        const W: usize = 5;
        // table[i] = x^i R mod n, i < 32.
        let mut table = [[0u32; N]; 1 << W];
        table[0] = *one_m;
        table[1] = *xm;
        for i in 2..(1 << W) {
            table[i] = self.mul(&table[i - 1], xm);
        }
        let bits = 32 * N;
        let windows = bits.div_ceil(W);
        let mut acc = *one_m;
        for w in (0..windows).rev() {
            for _ in 0..W {
                acc = self.mul(&acc, &acc);
            }
            // The W-bit digit at bit w W (bits past the top read as zero).
            let mut digit = 0u32;
            for k in 0..W {
                let b = w * W + k;
                if b < bits {
                    digit |= ((e[b / 32] >> (b % 32)) & 1) << k;
                }
            }
            let mut sel = [0u32; N];
            for (i, entry) in table.iter().enumerate() {
                // mask = all ones when i == digit, without a branch on the digit.
                let diff = (i as u32) ^ digit;
                // black_box: knowing mask is 0 or all ones, LLVM compiles this scan into `if i ==
                // digit { copy entry }` -- a branch on the secret digit that loads only the
                // selected entry (the alpha-10 pinned wasm; check/wasm_ct_scan.py). Opaque, every
                // entry is loaded and masked.
                let mask = core::hint::black_box(((diff | diff.wrapping_neg()) >> 31).wrapping_sub(1));
                for j in 0..N {
                    sel[j] |= entry[j] & mask;
                }
            }
            acc = self.mul(&acc, &sel);
        }
        self.from_mont(&acc)
    }

    /// x mod n for any x < R (so x < 2n): one subtraction, without a branch.
    pub fn reduce(&self, x: &[u32; N]) -> [u32; N] {
        self.reduce_once(*x, 0)
    }

    /// a + b mod n for a, b < n, without a branch.
    pub fn add(&self, a: &[u32; N], b: &[u32; N]) -> [u32; N] {
        let mut t = [0u32; N];
        let mut carry = 0u64;
        for j in 0..N {
            let s = a[j] as u64 + b[j] as u64 + carry;
            t[j] = s as u32;
            carry = s >> 32;
        }
        self.reduce_once(t, carry as u32)
    }

    /// a - b mod n for a, b < n, without a branch (n is added back under a mask).
    pub fn sub(&self, a: &[u32; N], b: &[u32; N]) -> [u32; N] {
        let mut d = [0u32; N];
        let mut borrow = 0u64;
        for j in 0..N {
            let s = (a[j] as u64).wrapping_sub(b[j] as u64).wrapping_sub(borrow);
            d[j] = s as u32;
            borrow = (s >> 63) & 1;
        }
        let mask = (borrow as u32).wrapping_neg();
        let mut carry = 0u64;
        for j in 0..N {
            let s = d[j] as u64 + (self.n[j] & mask) as u64 + carry;
            d[j] = s as u32;
            carry = s >> 32;
        }
        d
    }

    /// R^2 mod n, the constant that takes a number into Montgomery form, computed without a
    /// division: 2 R mod n is R mod n doubled, and (2 R)^(32 N) in Montgomery arithmetic is
    /// 2^(32 N) R = R^2. The exponent 32 N is public; the steps do not depend on n's value.
    pub fn r2(&self) -> [u32; N] {
        let one = self.one_mont();
        let two = self.add(&one, &one);
        let e = 32 * N;
        let mut acc = one;
        for bit in (0..usize::BITS - e.leading_zeros()).rev() {
            acc = self.mul(&acc, &acc);
            if (e >> bit) & 1 == 1 {
                acc = self.mul(&acc, &two);
            }
        }
        acc
    }

    /// The Montgomery form (x R mod n) of x = hi R + lo, for any lo, hi < R (a number of 2 N
    /// limbs), without a division: lo R = mul(lo mod n, R^2) and hi R^2 = mul(hi mod n, R^3).
    pub fn to_mont_wide(&self, lo: &[u32; N], hi: &[u32; N]) -> [u32; N] {
        let r2 = self.r2();
        let r3 = self.mul(&r2, &r2);
        self.add(&self.mul(&self.reduce(lo), &r2), &self.mul(&self.reduce(hi), &r3))
    }

    /// R mod n = R - n (since n > R/2), in Montgomery form the number 1.
    pub fn one_mont(&self) -> [u32; N] {
        let mut r = [0u32; N];
        let mut borrow = 0u64;
        for j in 0..N {
            let s = 0u64.wrapping_sub(self.n[j] as u64).wrapping_sub(borrow);
            r[j] = s as u32;
            borrow = (s >> 63) & 1;
        }
        r
    }
}

/// Big-endian bytes (exactly 4 N) to little-endian limbs.
pub fn from_be<const N: usize>(bytes: &[u8]) -> Option<[u32; N]> {
    if bytes.len() != 4 * N {
        return None;
    }
    let mut x = [0u32; N];
    for (i, c) in bytes.rchunks_exact(4).enumerate() {
        x[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    Some(x)
}

/// Little-endian limbs to big-endian bytes.
pub fn to_be<const N: usize>(x: &[u32; N], out: &mut [u8]) {
    for (i, c) in out.rchunks_exact_mut(4).enumerate() {
        c.copy_from_slice(&x[i].to_be_bytes());
    }
}

/// a < b for equal-length limb arrays (variable time).
pub fn less_than<const N: usize>(a: &[u32; N], b: &[u32; N]) -> bool {
    for j in (0..N).rev() {
        if a[j] != b[j] {
            return a[j] < b[j];
        }
    }
    false
}

/// Big-endian bytes without their leading zero bytes: the same number, in at most as many bytes.
/// Eight bytes per step over the zeros (a public exponent can be any length; see pow_public).
pub fn significant(bytes: &[u8]) -> &[u8] {
    let zero_words = bytes.chunks_exact(8).take_while(|w| u64::from_ne_bytes((*w).try_into().unwrap()) == 0).count();
    let rest = &bytes[8 * zero_words..];
    &rest[rest.iter().take_while(|&&b| b == 0).count()..]
}

// The bytes of e that pow_public walks bit by bit, counted per thread (only in ../../check).
#[cfg(test)]
std::thread_local! {
    pub static POW_PUBLIC_BYTES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}
