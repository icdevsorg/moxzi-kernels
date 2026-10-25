# Native kernels: sources, pins and checks

This directory holds the native kernels published for moxzi, the reproducible build recipe's
inputs, and the checks run on them. The top-level [README](../README.md) is the short version;
this file has the details.

| Path | What it is |
|---|---|
| `moxzi-kernel/` | The kernel SDK (ABI 1): scratch allocation, traps with a message, result helpers, the panic handler. Every kernel crate depends on it by path. |
| `moxzi-kernel/check/` | Native and Miri checks of the SDK and of every exported function of every kernel. |
| `moxzi-<family>/` | A Motoko package (`src/`, `mops.toml`) with its kernel: `rust/` is the crate, `kernel/<package>.kernel.toml` the pinned build, `check/` (some families) the native checks of its arithmetic. |
| `ic-agent-bls/` | The BLS signature kernel of `mo:ic-agent`. Its Motoko side (`Bls12381.verify`) ships in that package; `kernel/` holds the pinned file it ships and `kernel/declarations.toml`, a copy of its `[kernel]` declarations. |
| `wasm64-none-shared.json` | The target spec, identical to the Motoko runtime system's (`rts/motoko-rts/wasm64-none-shared.json` in the Motoko compiler repository). |
| `repro/` | The Linux container that rebuilds every kernel (`verify.sh`, `Dockerfile`) and the list of kernels (`kernels.list`). |
| `ct-scan/` | The constant-time scanner for compiled kernels, its reviewed per-kernel policies (`allow/`) and the two superseded pins it must reject (`teeth/`). |

## Building a kernel

```sh
rustup toolchain install nightly-2026-07-25 --profile minimal --component rust-src
scripts/build-kernel.sh kernels/moxzi-hash/rust out/moxzi-hash.kernel.toml
```

This is the Motoko runtime system's recipe: the pinned nightly, `-Zbuild-std=core,alloc`, the
target spec in this directory, and `rust-lld --shared --experimental-pic`. The script checks the
toolchain by commit (rustc `da86f4d07`, its rust-lld at LLD 22.1.8) and refuses any other.
`moxzi kernel build <crate> -o <out.kernel.toml>` runs the same recipe, with the target spec, the
SDK and the rustc wrapper compiled into the CLI, and writes the same file byte for byte.

**Where the build runs.** Cargo hashes a path dependency outside the crate's workspace by its
absolute path, and those hashes order the kernel's functions and constants, so the SDK must sit
at the same absolute path on every machine. The script copies `kernels/` to
`/tmp/moxzi-kernel-build/kernels` and builds the crate at the same relative place inside it
(`kernels/moxzi-p256/rust` builds at `/tmp/moxzi-kernel-build/kernels/moxzi-p256/rust`). One
build runs at a time (the lock is `/tmp/moxzi-kernel-build.lock`). Building anywhere else
(`MOXZI_KERNEL_WORKDIR`) works, but the bytes will not match the pins.

**What else the script controls.** Every crate has a committed `Cargo.lock`, used `--locked`.
`scripts/kernel-rustc-wrapper.sh` keeps the host triple out of cargo's crate hashes. Every
machine-specific path prefix (the work directory under both of its spellings, the cargo home,
the toolchain sysroot) is remapped. `RUSTFLAGS` and the other cargo/rustc settings of the
caller's environment are dropped, and each one dropped is named. A crate may select a
dependency's documented `--cfg` in its own `Cargo.toml` (`[package.metadata.moxzi-kernel] cfg`),
as `moxzi-ed25519` does for curve25519-dalek's 32-bit backend.

The output is a `.kernel.toml`: a header naming the toolchain, then `abi`, `sha256`, `size` and
the wasm in base64. Applications pin the `sha256`.

## Reproducing the pins

```sh
scripts/kernel_repro_gate.sh                    # every kernel, 5-11 minutes on an M-series Mac
scripts/kernel_repro_gate.sh moxzi-p256         # one kernel (names as in repro/kernels.list)
kernels/repro/verify.sh                         # the same on Linux, in Docker
```

The gate rebuilds every kernel listed in `repro/kernels.list` and fails if any byte differs from
the committed pin. It also fails if a `.kernel.toml` in the tree is missing from the list, or if a
package names a kernel file the gate does not rebuild. `KERNEL_REPRO_OUT=<dir>` keeps the rebuilt
files; `KERNEL_REPRO_UPDATE=1` writes them over the committed ones (re-pinning).

`repro/verify.sh` builds a Debian image pinned by digest, installs the pinned nightly with
rustup, mounts the checkout read-only and runs the gate inside. macOS arm64 and Linux arm64
produce byte-identical files. `PLATFORM=linux/amd64` runs another architecture (emulated, slower).

## The tier-1 list

The moxzi CLI ships with a list of (package, sha256) pairs for the kernels in this repository:
the "tier-1" kernels. A build that links one of them at a listed pin says `[tier-1]` and links it.
Any other kernel, including one that uses a published package name with other bytes, is
third-party: the first build that links it prints what a kernel can do and stops until the
user accepts those exact bytes. The bytes decide, not the package name. When a kernel here is
re-pinned, the CLI's list gains the new pin in its next release; released pins stay listed.

## Native checks and Miri

A kernel writes straight into the canister's memory, and inside one wasm memory a write past a
buffer is just a write, so tests of the compiled wasm cannot see one. The kernels' sources also
run natively, in check crates that are not part of any kernel build:

| Crate | What it checks |
|---|---|
| `moxzi-kernel/check` | The SDK (`bytes`, `output`, `text`, `trap`, the allocator) and every exported function of every family, called as the glue calls them: payload pointers, a result buffer of exactly `result_bytes`, the result read back and validated (Bool 0/1, the result block inside its `kernel_alloc` block, UTF-8 Text, no null for a non-optional result, inputs unwritten, the whole buffer written). The calls are generated from each package's `[kernel.functions]`, so a declaration that disagrees with the Rust signature does not compile. Valid inputs reach every success path; hostile ones (empty, wrong lengths, random, extreme integers) must return or trap, never panic. P-256 builds alone (`--no-default-features --features p256`): with both p256 and k256 in one build, the `ORDER.encode_field_bytes()` calls in the P-256 and secp256k1 `ops.rs` become ambiguous. |
| `moxzi-rsa/check` | `mont.rs` against num-bigint for every modulus size the code accepts (8 to 96 limbs), on edge and random moduli and operands; sign and verify against an RFC 8017 reference, the rsa crate, and the Wycheproof RSA-PSS 3072 vectors; test keys of the shape sign accepts and of the shapes it refuses (a 1535/1537-bit prime split, CRT exponents >= 2^1536). The keys in `keys/` are TEST KEYS, generated deterministically from fixed seeds in `check.rs` (`MOXZI_WRITE_KEYS=1` regenerates them); they protect nothing. `fuel-probe/` measures the pinned kernel's instruction counts under wasmtime for keys whose secrets differ in shape. |
| `moxzi-{ed25519,p256,secp256k1}/check` | Each family's `ops.rs` against the reference crate it replaced, and the static tables against the crate's own arithmetic (`MOXZI_WRITE_TABLES=1` regenerates them). |

The kernel sources are compiled into the check crates by `moxzi-kernel/check/transform.rs`, a
line-for-line rewrite that changes only what a std test crate needs (no `#[no_mangle]`,
`extern "C-unwind"` so a native `kernel_trap` can unwind, no lang items, module paths); it
refuses any other change. `moxzi-kernel/check/native.rs` holds the native `kernel_alloc` (the
program's limits, one exact-size allocation per request) and `kernel_trap`. The test vectors the
checks read are in each crate's `vectors/` directory (sources in [NOTICE](../NOTICE)).

```sh
bash scripts/kernel_native_checks.sh          # natively: release, debug, and the 32-bit dalek backend
MIRI=1 bash scripts/kernel_native_checks.sh   # the same crates under Miri (about 30 minutes)
```

Miri runs on the pinned nightly (`rustup component add --toolchain nightly-2026-07-25 miri`)
with `-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check` and Stacked Borrows. Under
`cfg(miri)` the crates run fewer cases and keep every class of edge case; a few tests that check
generated data rather than kernel code are ignored there. A missing toolchain is a failure, not
a skip. Measured 2026-10-23: native about 70 s warm; Miri about 27 minutes in four parallel
lanes. No undefined behaviour was found.

## Constant-time scan of the compiled wasm

Instruction-count tests on the Internet Computer (or PocketIC) compare the cost of operations on
different secrets, and equal counts can hide a branch on a secret whose two arms cost the same.
An off-chain host (wasmtime, a browser) compiles the wasm to native code, where such a branch,
or a load from an address chosen by a secret, is a branch-predictor or cache timing leak. LLVM
made exactly that out of constant-time Rust twice in earlier pins: the secp256k1 comb select
(via libsecp's `AffineStorage::cmov`), and RSA's `pow_secret` table scan and `reduce_once`.

`ct-scan/scan.py` scans the pinned wasm itself: it disassembles it (`wasm-tools print`; the
name section carries the Rust symbols) and runs a flow-sensitive, interprocedural taint
analysis from the exports that take secret input. It reports every branch (`br_if`, `if`,
`br_table`), address `select`, select-chosen pointer handed to a callee, and data-indexed table
access whose condition or index depends on data (anything loaded, returned by a call, or derived
from a secret parameter's bytes); loop counters, constants, public lengths and static tables stay
public. The scanner's docstring gives the exact rules and their known imprecisions.

Each kernel has a reviewed policy, `ct-scan/allow/<kernel>.toml`:

- `[roots]`: the exports that take secrets, with the parameter indices of the secret buffers
  (the secret key, a scalar, a seed, an HMAC key...); `[public]`: every other export, with the
  reason it sees no secret. An unclassified export fails.
- The scanned functions are the roots and everything they reach by direct calls, minus the
  `[exclude]` panic paths (`common.toml`). Most secret arithmetic is inlined into the exports, so
  the export bodies are scanned too, and a function that a rebuild stops inlining is picked up
  automatically. `ct` names the constant-time core (the comb and its selection, inversion,
  Montgomery exponentiation, field multiplication, the hash compressions): it must be among the
  scanned functions, and it can only be allowed site by site.
- `[[allow]]`: per function, the exact sites (`kind op condition` = count) or, for variable-time
  library code accepted as a whole (RSA's DER and BigUint), an exact total, each with its reason.
  A new site, a changed count or a stale entry fails.

```sh
bash scripts/kernel_ct_scan_gate.sh                                     # every kernel + the teeth
python3 -I kernels/ct-scan/scan.py kernels/moxzi-rsa/kernel/moxzi-rsa.kernel.toml --list
python3 -I kernels/ct-scan/scan.py scratch.wasm --root probe=0          # a scratch build, ad hoc
```

The gate needs `wasm-tools` (`cargo install wasm-tools`) and Python 3.11 or later; a missing one
is a failure. It also scans the two superseded pins in `ct-scan/teeth/` (moxzi-secp256k1 and
moxzi-rsa as they were before the two fixes) with today's policies, and requires the scan to
FAIL on them in `ops::mul_g` and in `Modulus<48>::{pow_secret, to_mont_wide}` (271 and 102
unallowed sites: the leaks, plus the sites of code those pins still had, libsecp's `add_ge` and
RSA's BigUint fallback). A scan that cannot fail on a known leak proves nothing. After a rebuild
that changes a pin, re-run with `--list`, review what changed, and update the counts
(`--suggest` prints fresh entries).

What the scan found in the current pins (details in each policy):

- **secp256k1, upstream (fixed in our code)**: libsecp256k1-core 0.3.0's `Jacobian::add_ge`
  (the comb's addition) is not branch-free: its Rust port writes `normalizes_to_zero` and
  `degenerate` with short-circuit `||`/`&&` and `Field::cmov` as `if flag {..} else {..}` (9
  branches, 7 address selects). They only differed for degenerate additions and on `a.infinity`
  (the first addition), so they were not exploitable; `ops::add_ge` now computes the same formula
  with masks (equal to the crate's limb for limb, check `add_ge_is_the_crates`) and the k*G path
  has no site left from it.
- **crypto-bigint (RUSTSEC-2026-0387 pattern)**: `Uint::neg_mod`'s masked zero case compiles to a
  branch on the scalar being zero (k256 `Scalar` negation in BIP340 signing, the low-S
  normalisation and `tweakXOnlySecretKey`). Every scalar negated there is nonzero, so the branch
  never varies. `inv_odd_mod`'s loop (1/k in both ECDSA kernels) is branch-free in these builds;
  only its final `ok` check branches, always the same way for a nonzero k.
- **RSA, accepted**: DER parsing of the private key is variable time in the key's encoding
  shape, and the DER-minimal byte lengths of dp, dq and qInv reach copy lengths in `crt`. The
  Montgomery core (`rsasp1_ct`, `mont.rs`) has no site. Keys of other shapes than 1536-bit primes
  with CRT values below 2^1536 used to be signed by a variable-time BigUint fallback; sign now
  refuses them, and no secret number is a BigUint.
- Everything else is public by construction: validity checks that trap, SEC1 tags of public
  outputs, hash block-buffer positions, RFC 6979 and ML-DSA rejection loops (FIPS 204's
  rejected candidates, SampleInBall on the public `c~`, the public matrix A).

## Verifying with the moxzi CLI

`moxzi kernel verify <package dir | .kernel.toml | app dir>` rebuilds a kernel from the
package's declared `[kernel] source` (and `commit`, once set): the local checkout when the
package sits in a checkout of that repository, otherwise a fetch into a scratch directory
(`--crate DIR` overrides). It compares the result with the package's kernel file and, for an
application, its `[kernels]` pin, and exits non-zero on any difference.
