# moxzi-rsa

RSA-3072 RSASSA-PSS (SHA-256, PS256) for Motoko with a native moxzi kernel: verify in Motoko or natively, sign natively.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-rsa
moxzi kernel add moxzi-rsa
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results. `Rsa3072.sign` is the exception: it has no Motoko body and traps without the kernel.

## Modules

`mo:moxzi-rsa/Rsa3072`

## Functions with a native kernel (3)

- `Rsa3072.sign`
- `Rsa3072.verify`
- `Rsa3072.verifyDigest`

## Security

The cryptography in this kernel includes code written for it. That code has had automated adversarial review, checks of the compiled wasm for secret-dependent branches and memory accesses, and differential tests against reference implementations and official test vectors, but no independent audit by cryptography experts. Until it has one, don't use this package to protect significant value.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-rsa/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
