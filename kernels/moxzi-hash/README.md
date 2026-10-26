# moxzi-hash

SHA-256, SHA-512, HMAC, RIPEMD-160 and BLAKE3, with a native moxzi kernel; the Motoko bodies run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-hash
moxzi kernel add moxzi-hash
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-hash/Blake3`, `mo:moxzi-hash/Hmac`, `mo:moxzi-hash/Ripemd160`, `mo:moxzi-hash/Sha256`, `mo:moxzi-hash/Sha512`

## Functions with a native kernel (7)

- `Blake3.digest`
- `Blake3.keyedHash`
- `Hmac.sha256`
- `Hmac.sha512`
- `Ripemd160.digest`
- `Sha256.digest`
- `Sha512.digest`

## Security

The kernel uses published Rust crates. It has had differential tests against the Motoko bodies, reference implementations and official test vectors, but no independent audit.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-hash/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
