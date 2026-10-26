# moxzi-bls12-381

BLS12-381 for Motoko: Ethereum BLS signatures, G1/G2 arithmetic and MSM, hash-to-curve and pairings, with a native moxzi kernel; the Motoko bodies run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-bls12-381
moxzi kernel add moxzi-bls12-381
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-bls12-381/Bls12381`

## Functions with a native kernel (19)

- `Bls12381.aggregateVerifyEthereum`
- `Bls12381.fastAggregateVerifyEthereum`
- `Bls12381.g1Add`
- `Bls12381.g1Aggregate`
- `Bls12381.g1Msm`
- `Bls12381.g1Mul`
- `Bls12381.g2Add`
- `Bls12381.g2Aggregate`
- `Bls12381.g2Msm`
- `Bls12381.g2Mul`
- `Bls12381.hashToG1`
- `Bls12381.hashToG2`
- `Bls12381.mapToG1`
- `Bls12381.mapToG2`
- `Bls12381.pairingCheck`
- `Bls12381.validateG1`
- `Bls12381.validateG2`
- `Bls12381.verifyEthereum`
- `Bls12381.verifyEthereumProof`

## Security

The kernel uses published Rust crates. It has had differential tests against the Motoko bodies, reference implementations and official test vectors, but no independent audit.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-bls12-381/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
