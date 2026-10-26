# moxzi-secp256k1

secp256k1 keys, point arithmetic, RFC 6979 ECDSA and BIP340 Schnorr, with a native moxzi kernel; the Motoko bodies run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-secp256k1
moxzi kernel add moxzi-secp256k1
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-secp256k1/Secp256k1`

## Functions with a native kernel (19)

- `Secp256k1.baseMultiply`
- `Secp256k1.compressPublicKey`
- `Secp256k1.convertPublicKey`
- `Secp256k1.decompressPublicKey`
- `Secp256k1.derivePublicKey`
- `Secp256k1.normalizeSignature`
- `Secp256k1.pointAdd`
- `Secp256k1.pointMultiply`
- `Secp256k1.publicKey`
- `Secp256k1.schnorrSign`
- `Secp256k1.schnorrVerify`
- `Secp256k1.signPrehash`
- `Secp256k1.signatureFromDer`
- `Secp256k1.signatureToDer`
- `Secp256k1.tweakPublicKey`
- `Secp256k1.tweakXOnlyPublicKey`
- `Secp256k1.tweakXOnlySecretKey`
- `Secp256k1.verifyPrehash`
- `Secp256k1.xOnlyPublicKey`

## Security

The cryptography in this kernel includes code written for it. That code has had automated adversarial review, checks of the compiled wasm for secret-dependent branches and memory accesses, and differential tests against reference implementations and official test vectors, but no independent audit by cryptography experts. Until it has one, don't use this package to protect significant value.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-secp256k1/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
