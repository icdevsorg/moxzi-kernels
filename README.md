# moxzi-kernels

Native kernels for Motoko: hashing, signatures, curve arithmetic and encodings, compiled from
Rust and reproducible from this repository's source.

A native kernel is a small wasm library, built from an existing Rust crate such as `sha2` or
`k256`, that backs functions in a Motoko package. When an application opts in (a `[kernels]`
entry in its `mops.toml`, pinned by the kernel's sha256), the
[moxzi](https://doe5l-siaaa-aaaak-qzcuq-cai.icp0.io/) toolchain links the kernel into the
canister and calls it in place of those functions' Motoko bodies, at a fraction of the
instructions. Without the opt-in, or under `moc`, the same package compiles its Motoko bodies
and gives the same results. The user guide is
[Native kernels](https://doe5l-siaaa-aaaak-qzcuq-cai.icp0.io/docs/cli/kernels/).

This repository holds the kernels' source, the exact bytes each package ships (its pinned
`.kernel.toml`), and everything needed to check that those bytes come from that source: the
build recipe, a Docker verifier, native and Miri checks of the Rust, and a constant-time scan of
the compiled wasm with its reviewed allow lists. You don't need moxzi for any of it.

## Packages

| Package | Provides |
|---|---|
| `moxzi-hash` | SHA-256, SHA-512, HMAC-SHA-256, HMAC-SHA-512, RIPEMD-160, BLAKE3 (plain and keyed) |
| `moxzi-secp256k1` | Keys, point arithmetic, ECDSA with RFC 6979 nonces, BIP340 Schnorr signatures, key tweaks, DER signatures |
| `moxzi-p256` | NIST P-256 keys, ECDSA with RFC 6979 nonces, DER signatures |
| `moxzi-ed25519` | Ed25519 keys, signing and strict verification (RFC 8032) |
| `moxzi-bls12-381` | Ethereum BLS signatures (verify, proof of possession, aggregates), G1 and G2 arithmetic and multi-scalar multiplication, RFC 9380 hash-to-curve, pairing checks |
| `moxzi-ml-dsa` | ML-DSA-44 (FIPS 204) keys, signing and verification |
| `moxzi-rsa` | RSA-3072 PSS signatures with SHA-256. `Rsa3072.sign` has no Motoko body: without the kernel it traps |
| `moxzi-base58` | Base58 and Base58Check |
| `moxzi-bech32` | Bech32 and Bech32m, bit regrouping, segwit addresses |
| `moxzi-bitcoin` | Bitcoin hashes, addresses, BIP32 public derivation, scripts, transaction signature hashes |
| `ic-agent-bls` | The BLS signature check behind certificate verification in [`mo:ic-agent`](https://github.com/icdevsorg/ic-agent-mo) |

Each `kernels/moxzi-<name>/` directory is a mops package: the Motoko modules in `src/`, its
`mops.toml` (which declares the kernel's functions under `[kernel.functions]`), the Rust crate
in `rust/`, and the pinned build in `kernel/moxzi-<name>.kernel.toml`. The Motoko side of
`ic-agent-bls` ships in `mo:ic-agent`; this repository has its crate and a copy of the pinned
file that package ships. `kernels/moxzi-kernel/` is the kernel SDK every crate builds on.
[kernels/README.md](kernels/README.md) has the details of everything below.

## Rebuild and verify a kernel

Every kernel builds from locked dependencies with one Rust nightly and its linker, in one fixed
directory (`/tmp/moxzi-kernel-build`), so the bytes don't depend on the machine: macOS arm64 and
Linux arm64 produce identical files. Install the toolchain once:

```sh
rustup toolchain install nightly-2026-07-25 --profile minimal --component rust-src
```

Build one kernel (needs `python3` 3.11+ and `rsync`) and compare its `sha256` line with the
committed file:

```sh
scripts/build-kernel.sh kernels/moxzi-hash/rust /tmp/moxzi-hash.kernel.toml
grep sha256 /tmp/moxzi-hash.kernel.toml kernels/moxzi-hash/kernel/moxzi-hash.kernel.toml
```

Rebuild every kernel and check each against its pin (5 to 11 minutes):

```sh
scripts/kernel_repro_gate.sh                  # all kernels
scripts/kernel_repro_gate.sh moxzi-p256       # one
```

Or, with nothing installed but Docker, the same on Linux:

```sh
kernels/repro/verify.sh
```

Both print `MATCH` per kernel and exit non-zero if any rebuilt kernel differs from its pin. If
you use moxzi, `moxzi kernel verify <package directory>` does the same for one package.

## Run the checks

**Native and Miri checks.** The kernels' Rust also runs natively, in check crates that call
every exported function the way the program's glue does (on valid and hostile inputs) and
compare each family's arithmetic with reference crates and official test vectors (Wycheproof,
the RFCs and BIPs):

```sh
bash scripts/kernel_native_checks.sh          # about 1 minute warm, 6 cold
rustup component add --toolchain nightly-2026-07-25 miri
MIRI=1 bash scripts/kernel_native_checks.sh   # the same under Miri, about 30 minutes
```

**Constant-time scan.** A branch or memory address that depends on a secret is a timing leak
on hosts that compile wasm to native code, and LLVM can turn constant-time Rust into one. The
scanner disassembles each pinned kernel and traces secret data through it; every
data-dependent branch it finds must be in that kernel's reviewed allow list
(`kernels/ct-scan/allow/<kernel>.toml`), with an exact count and a reason. The gate also
requires the scan to fail on two earlier pins that had real leaks (`kernels/ct-scan/teeth/`):

```sh
cargo install wasm-tools
bash scripts/kernel_ct_scan_gate.sh
```

## Security status

Most of the cryptography in the kernels comes from published Rust crates, used unmodified
(RustCrypto, dalek, zkcrypto, Cryspen libcrux). Some was written for these kernels: the
Montgomery arithmetic and CRT signing in `moxzi-rsa`, the fixed-base tables and point addition
used for keys and signatures in `moxzi-secp256k1` and `moxzi-p256`, and P-256 verification.

That code has had automated adversarial review, the constant-time scan of the compiled wasm
above, instruction-count comparisons across secrets, native and Miri checks, and differential
tests against reference implementations and official test vectors. **It has not had an
independent audit by cryptography experts. Until it has, don't use `moxzi-rsa`,
`moxzi-secp256k1` or `moxzi-p256` to protect significant value.**

Known limitations:

| Limitation | Detail |
|---|---|
| ML-DSA signing time varies | FIPS 204 signing retries until a candidate signature passes its checks, so the time depends on the key and message. The standard is designed this way; the rejected candidates don't reveal the key |
| RSA signing accepts only standard 3072-bit keys | The key needs two primes of exactly 1,536 bits and reduced CRT parameters, as every 3072-bit key from OpenSSL or Node has. Other keys trap with `Rsa3072.sign: key shape not supported`. DER parsing of the private key is variable time in the key's encoding shape |
| RUSTSEC-2026-0387 (crypto-bigint) | `moxzi-secp256k1` and `moxzi-p256` use a crypto-bigint version with this advisory: compiled code can branch on secret values. The compiled kernels are checked instead. The one such branch they contain never sees a zero scalar, so its timing doesn't vary. The kernels don't use a fixed crypto-bigint yet |
| Young and unmaintained crates | `moxzi-ml-dsa` uses `libcrux-ml-dsa`, which hasn't reached 1.0. `moxzi-secp256k1` uses the field arithmetic of `libsecp256k1-core`, which is no longer maintained |
| Secrets stay in memory | Kernel scratch memory is reclaimed by the garbage collector, not erased, so copies of a secret key remain until the memory is reused. On the Internet Computer, node providers can read canister memory in any case |

A kernel shares its canister's memory: it can read and write anything in the heap. The pin
guarantees which bytes run, not that they are correct. Review the source at the commit a
package names before you pin a new version, and take a canister snapshot before deploying one.

The RSA check crate commits test keys (`kernels/moxzi-rsa/check/keys/*.der`). They are
generated deterministically from fixed seeds for the tests and protect nothing.

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please report privately.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Third-party code and data in this repository, and the third-party crates
compiled into the kernels, are listed with their licenses in [NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this repository by you, as defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
