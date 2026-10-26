# moxzi-p256

NIST P-256 (secp256r1) keys and RFC 6979 ECDSA, with a native moxzi kernel; the Motoko bodies run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-p256
moxzi kernel add moxzi-p256
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-p256/P256`

## Functions with a native kernel (8)

- `P256.convertPublicKey`
- `P256.derivePublicKey`
- `P256.normalizeSignature`
- `P256.publicKey`
- `P256.signPrehash`
- `P256.signatureFromDer`
- `P256.signatureToDer`
- `P256.verifyPrehash`

## Security

The cryptography in this kernel includes code written for it. That code has had automated adversarial review, checks of the compiled wasm for secret-dependent branches and memory accesses, and differential tests against reference implementations and official test vectors, but no independent audit by cryptography experts. Until it has one, don't use this package to protect significant value.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-p256/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
