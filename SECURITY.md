# Security policy

A native kernel runs inside the canisters that link it and shares their memory, so a bug in one
can expose or corrupt canister state. We take reports seriously.

## Reporting a vulnerability

Please report security issues **privately** through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability** (https://github.com/icdevsorg/moxzi-kernels/security/advisories/new).
Do not open a public issue or pull request for a suspected vulnerability.

Include what you can of:

- the kernel package and version, and the `sha256` of the `.kernel.toml` you looked at;
- the function, the inputs that trigger the problem, and what happens;
- for a timing issue, how you measured it (instruction counts, a native host, the
  constant-time scan) and on which build.

We will acknowledge the report, keep you informed while we investigate, and credit you in the
fix unless you ask us not to. A fix is a new pin: applications pick it up when they update the
package and its pin, so we will coordinate disclosure with the time users need to do that.

## Scope

In scope: the kernel sources in `kernels/`, the pinned `.kernel.toml` files, the build and
verification scripts, and the Motoko fallback bodies in each package's `src/`.

Out of scope here (report them to their maintainers): the moxzi CLI and runtime, the Motoko
compiler, and the upstream Rust crates the kernels use. If you are unsure, report it to us and
we will route it.

## Current status

The kernels have had automated adversarial review, constant-time checks of the compiled wasm,
native and Miri checks, and differential tests against reference implementations and official
test vectors. They have **not** had an independent audit by cryptography experts. See
"Security status" in the [README](README.md) before using `moxzi-rsa`, `moxzi-secp256k1` or
`moxzi-p256` to protect significant value.
