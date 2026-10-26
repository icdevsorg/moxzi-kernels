# moxzi-ml-dsa

ML-DSA-44 (FIPS 204) key generation, signing and verification, with a native moxzi kernel; the Motoko bodies (a FIPS 204 port) run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-ml-dsa
moxzi kernel add moxzi-ml-dsa
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-ml-dsa/MlDsa44`

## Functions with a native kernel (4)

- `MlDsa44.publicKey`
- `MlDsa44.sign`
- `MlDsa44.signHedged`
- `MlDsa44.verify`

## Security

The kernel uses published Rust crates. It has had differential tests against the Motoko bodies, reference implementations and official test vectors, but no independent audit.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-ml-dsa/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
