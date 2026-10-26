# moxzi-bitcoin

Bitcoin hashes, addresses, BIP32 public derivation, scripts and transaction signature hashes, with a native moxzi kernel; the Motoko bodies (on mo:bitcoin) run under moc or without the opt-in.

## Install

Add the package, then opt into its native kernel in your application's `mops.toml`:

```sh
mops add moxzi-bitcoin
moxzi kernel add moxzi-bitcoin
```

`moxzi kernel add` checks the kernel file against its recorded hash and writes the pin under `[kernels]`. Build with [moxzi](https://moxzi.ai) 0.1.0-alpha.10 or later; the build names each kernel it links.

Without the opt-in, or under `moc`, the same program builds with the Motoko bodies and gives the same results.

## Modules

`mo:moxzi-bitcoin/Address`, `mo:moxzi-bitcoin/Bip32`, `mo:moxzi-bitcoin/Hash`, `mo:moxzi-bitcoin/Script`, `mo:moxzi-bitcoin/Transaction`

## Functions with a native kernel (32)

- `Address.fromScript`
- `Address.p2pkh`
- `Address.p2sh`
- `Address.p2tr`
- `Address.p2wpkh`
- `Address.p2wsh`
- `Address.taprootOutputKey`
- `Address.toScript`
- `Bip32.deriveChild`
- `Bip32.derivePath`
- `Bip32.fingerprint`
- `Bip32.fromPublicKey`
- `Bip32.parse`
- `Bip32.serialize`
- `Hash.hash160`
- `Hash.sha256d`
- `Hash.taggedHash`
- `Script.p2pkh`
- `Script.p2sh`
- `Script.p2tr`
- `Script.p2wpkh`
- `Script.p2wsh`
- `Script.pushData`
- `Script.tapBranchHash`
- `Script.tapLeafHash`
- `Transaction.isValid`
- `Transaction.signatureHashLegacy`
- `Transaction.signatureHashSegwitV0`
- `Transaction.signatureHashTaproot`
- `Transaction.stripWitness`
- `Transaction.txid`
- `Transaction.wtxid`

## Security

The kernel uses published Rust crates. It has had differential tests against the Motoko bodies, reference implementations and official test vectors, but no independent audit.

A kernel runs inside your canister and shares its memory. Read [Using kernels](https://moxzi.ai/docs/kernels/using/) and [Published kernels](https://moxzi.ai/docs/kernels/packages/) before you opt in.

## Source and license

The kernel is built from [icdevsorg/moxzi-kernels](https://github.com/icdevsorg/moxzi-kernels/tree/main/kernels/moxzi-bitcoin/rust) at commit `445b558869a5`; `moxzi kernel verify` rebuilds it and compares the bytes. Maintained by [ICDevs.org](https://icdevs.org). License: MIT OR Apache-2.0 (the registry lists Apache-2.0).
