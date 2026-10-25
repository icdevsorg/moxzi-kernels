#!/usr/bin/env bash
# Build a native kernel crate into a `.kernel.toml`.
#
#   scripts/build-kernel.sh kernels/moxzi-hash/rust out/moxzi-hash.kernel.toml
#
# The recipe of the Motoko runtime system: the pinned nightly, -Zbuild-std=core,alloc, the RTS
# target spec (kernels/wasm64-none-shared.json), and rust-lld --shared --experimental-pic. Built
# in ONE fixed directory (MOXZI_KERNEL_WORKDIR, default /tmp/moxzi-kernel-build): cargo's crate
# hashes include the source path and set the order of functions and constants, so the same crate
# built elsewhere gives other bytes. Every exported function is a `#[no_mangle] pub extern "C" fn`
# in src/lib.rs.
#
# REPRODUCIBLE ACROSS MACHINES. Applications pin the kernel BYTES, so anyone must be able to
# rebuild them from source: `scripts/kernel_repro_gate.sh` rebuilds every kernel and compares with
# the pins; `kernels/repro/verify.sh` does the same in a Linux container. macOS arm64 and Linux
# arm64 write byte-identical .kernel.toml files for every kernel. Four things used to make the
# bytes differ between machines, each handled here:
#   - CRATE VERSIONS FLOATED. Without a Cargo.lock every build re-resolved transitive versions
#     from crates.io (a smallvec release once moved the RSA pin with no source change). Every
#     crate has a committed lock, used --locked.
#   - THE HOST TRIPLE reached cargo's crate hashes (via build scripts), which order the constants:
#     scripts/kernel-rustc-wrapper.sh.
#   - THE WORK DIRECTORY'S SPELLING reached them too (/private/tmp vs /tmp): see BASE_REAL below.
#   - TWO LINKERS. A missing libLLVM on macOS once made a fallback pick another nightly's rust-lld.
#     Now there is ONE linker, the pinned nightly's, run with $SYSROOT/lib on the library path and
#     checked by commit; a missing or broken one is an error, never a fallback.
# Plus: one toolchain checked by commit, the canonical work directory, path remapping, and no
# inherited cargo/rustc settings.
#
# The moxzi CLI carries the same recipe (`moxzi kernel build <crate> -o <out>`, with the target
# spec, the SDK and the wrapper compiled in) and writes the SAME .kernel.toml byte for byte; this
# script needs nothing but rustup, python3 and rsync.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$(cd "$1" && pwd)"; OUT="$2"
TC=nightly-2026-07-25
TC_RUSTC_COMMIT=da86f4d0726be475afbbffe40cb2f65741c51ad3   # rustc 1.99.0-nightly (da86f4d07 2026-07-24)
TC_LLD_COMMIT=52ed14fcd56afc30f9cccd8ca8ce237c2eef7e04      # its rust-lld: LLD 22.1.8
die() { echo "build-kernel: $*" >&2; exit 1; }

# --- the toolchain: exactly the pinned one, or nothing --------------------------------------------
RUSTC_VV="$(rustc "+$TC" -vV 2>&1)" \
  || die "toolchain $TC is not installed: rustup toolchain install $TC --profile minimal --component rust-src"
[ "$(sed -n 's/^commit-hash: //p' <<<"$RUSTC_VV")" = "$TC_RUSTC_COMMIT" ] \
  || die "$TC's rustc is not commit $TC_RUSTC_COMMIT:"$'\n'"$RUSTC_VV"
SYSROOT="$(rustc "+$TC" --print sysroot)"
HOST="$(sed -n 's/^host: //p' <<<"$RUSTC_VV")"
[ -d "$SYSROOT/lib/rustlib/src/rust/library/core" ] \
  || die "$TC has no rust-src (needed by -Zbuild-std): rustup component add rust-src --toolchain $TC"
LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"
[ -x "$LLD" ] || die "no rust-lld in $TC at $LLD (it ships in the rustc component)"
# libLLVM is in $SYSROOT/lib. On macOS rust-lld's rpath does not reach it ("Library not loaded:
# @rpath/libLLVM.dylib"); on Linux its RUNPATH does, and the variable is harmless.
run_lld() { DYLD_LIBRARY_PATH="$SYSROOT/lib" LD_LIBRARY_PATH="$SYSROOT/lib" "$LLD" "$@"; }
LLD_V="$(run_lld -flavor wasm --version 2>&1)" || die "$LLD cannot run:"$'\n'"$LLD_V"
case "$LLD_V" in *" $TC_LLD_COMMIT)"*) ;; *) die "$LLD is not LLD at commit $TC_LLD_COMMIT: $LLD_V" ;; esac
CARGO_V="$(cargo "+$TC" -V)"
RUSTC_V="$(head -1 <<<"$RUSTC_VV")"
# The version line names the checkout it was built in (a URL on macOS, /checkout/... on Linux);
# keep only what identifies the linker, so the recorded line is the same on every host.
LLD_ID="$(sed -E 's/^(LLD [0-9.]+) \(.* ([0-9a-f]{40})\)$/\1 (llvm-project \2)/' <<<"$LLD_V")"
echo "toolchain: $RUSTC_V; $CARGO_V; host $HOST"
echo "linker:    $LLD_ID at $LLD"

# --- nothing from the caller's environment reaches the bytes --------------------------------------
# The pins must follow from the sources alone, so cargo/rustc settings are not inherited (each
# one dropped is named). Cargo config FILES cannot be switched off; they are named below.
# CARGO_BUILD_JOBS stays: parallelism does not change the bytes (one codegen unit, fat LTO).
for v in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC_BOOTSTRAP \
         $(env | sed -nE 's/^(CARGO_(BUILD|PROFILE|TARGET)_[A-Za-z0-9_]*)=.*/\1/p' | grep -vx CARGO_BUILD_JOBS); do
  if [ -n "${!v+x}" ]; then echo "note: ignoring $v=${!v} (kernel bytes follow from the sources alone)"; unset "$v"; fi
done
# Cargo's crate hashes must not depend on the host triple; see the wrapper for why and how.
export RUSTC_WRAPPER="$ROOT/scripts/kernel-rustc-wrapper.sh"

# The whole kernels/ tree is copied, so a crate's path dependencies (the moxzi-kernel SDK)
# resolve, and the crate is built at the same place inside it every time.
case "$CRATE/" in "$ROOT/kernels/"*) REL="${CRATE#$ROOT/kernels/}" ;; *) die "$CRATE is not under kernels/" ;; esac
[ -f "$CRATE/Cargo.lock" ] || die "$CRATE has no Cargo.lock: commit one (cargo +$TC generate-lockfile, then review it)"
BASE="${MOXZI_KERNEL_WORKDIR:-/tmp/moxzi-kernel-build}"
case "$BASE" in /*) ;; *) die "MOXZI_KERNEL_WORKDIR must be an absolute path" ;; esac
[ "$BASE" = /tmp/moxzi-kernel-build ] || echo "note: MOXZI_KERNEL_WORKDIR=$BASE -- not the canonical directory, so the bytes will not match the pins"
# One build at a time: the directory is wiped below, and every build must use the same one.
LOCK="$BASE.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  pid="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then die "another kernel build (pid $pid) is using $BASE"; fi
  echo "note: removing the stale lock $LOCK (pid ${pid:-?} is gone)"; rm -rf "$LOCK"; mkdir "$LOCK"
fi
echo $$ >"$LOCK/pid"; trap 'rm -rf "$LOCK"' EXIT
rm -rf "$BASE"; mkdir -p "$BASE"
# TWO SPELLINGS OF ONE DIRECTORY. On macOS /tmp is a symlink to /private/tmp; on Linux it is not.
#   - Cargo hashes a path dependency outside the crate's workspace (the moxzi-kernel SDK) by its
#     ABSOLUTE path, as it spells it, into the crate hashes that order the constants. So cargo must
#     see the literal $BASE on every host: it is driven by --manifest-path under $BASE, which cargo
#     normalises lexically and never resolves. (It used to run from the resolved directory, so the
#     Mac hashed /private/tmp/... and Linux /tmp/...: p256, bitcoin, rsa and bls12-381 differed.)
#   - rustc sees the RESOLVED path wherever it reads the working directory, and a symlinked prefix
#     escapes a remap of the other spelling (that made a default build 8 bytes different from one in
#     a non-symlinked directory). So both spellings are remapped below.
BASE_REAL="$(cd "$BASE" && pwd -P)"
rsync -a --exclude target --exclude '*.kernel.toml' "$ROOT/kernels/" "$BASE/kernels/"
WORK="$BASE/kernels/$REL"
cp "$ROOT/kernels/wasm64-none-shared.json" "$WORK/"
cd "$WORK"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
d="$WORK"; while :; do
  for f in "$d/.cargo/config.toml" "$d/.cargo/config"; do [ -f "$f" ] && echo "note: cargo config $f applies to this build"; done
  [ "$d" = / ] && break; d="$(dirname "$d")"
done
for f in "$CARGO_HOME_DIR/config.toml" "$CARGO_HOME_DIR/config"; do [ -f "$f" ] && echo "note: cargo config $f applies to this build"; done
# Paths reach the binary (panic locations name source files). Remap every machine-specific prefix
# -- this work directory, the cargo home, the toolchain sysroot (build-std sources) -- so the
# bytes depend on the sources alone and anyone can rebuild a kernel and get its pinned hash.
export RUSTFLAGS="--remap-path-prefix=$BASE=/moxzi-kernel-build --remap-path-prefix=$BASE_REAL=/moxzi-kernel-build --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$SYSROOT=/rust"
# A crate may select a dependency's documented build configuration -- curve25519-dalek's
# `curve25519_dalek_bits="32"`, its 32-bit-limb backend, which suits wasm64 (no native 64x64->128
# multiply) better than the 64-bit default -- in its Cargo.toml:
#   [package.metadata.moxzi-kernel]
#   cfg = ['curve25519_dalek_bits="32"']
# Only `--cfg` values (no spaces), never other rustc flags; they are part of the crate's sources,
# so the pinned bytes still follow from the sources alone.
KCFG=$(python3 - "$CRATE/Cargo.toml" <<'PY'
import re, sys, tomllib
cfg = tomllib.load(open(sys.argv[1], 'rb')).get('package', {}).get('metadata', {}).get('moxzi-kernel', {}).get('cfg', [])
for c in cfg:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(="[A-Za-z0-9_.-]*")?', c): sys.exit(f"bad kernel cfg {c!r}")
    print(f"--cfg {c}")
PY
)
[ -z "$KCFG" ] || { echo "kernel cfg: $(echo $KCFG)"; export RUSTFLAGS="$RUSTFLAGS $(echo $KCFG)"; }
# --locked: the committed Cargo.lock decides every crate version; a stale lock is an error.
cargo "+$TC" build --manifest-path "$WORK/Cargo.toml" --release --locked --target wasm64-none-shared.json -Zjson-target-spec \
  -Zbuild-std=core,alloc -Zbuild-std-features=optimize_for_size >"$WORK/build.log" 2>&1 \
  || { tail -30 "$WORK/build.log"; exit 1; }
LIB="$(ls target/wasm64-none-shared/release/*.a | head -1)"
EXPORTS=$(grep -oE 'pub (unsafe )?extern "C" fn [a-zA-Z0-9_]+' "$CRATE/src/lib.rs" | awk '{print $NF}')
[ -n "$EXPORTS" ] || die "no exported functions in $CRATE/src/lib.rs"
run_lld -flavor wasm -mwasm64 --import-memory --shared --no-entry --gc-sections --import-undefined \
  --whole-archive --experimental-pic $(for e in $EXPORTS; do printf -- '--export=%s ' "$e"; done) \
  "$LIB" -o "$WORK/kernel.wasm"
cd "$ROOT"; mkdir -p "$(dirname "$OUT")"
# The toolchain lines are comments: the pin is over the wasm bytes, and moxzi reads only
# abi/sha256/wasm. They are host-independent, so the whole file is identical on every host.
python3 - "$WORK/kernel.wasm" "$OUT" "$RUSTC_V" "$CARGO_V" "$LLD_ID" <<'PY'
import base64, hashlib, sys, textwrap
b = open(sys.argv[1], 'rb').read()
h = hashlib.sha256(b).hexdigest()
wasm = "\n".join(textwrap.wrap(base64.b64encode(b).decode(), 76))
open(sys.argv[2], 'w').write(
    "# A moxzi native kernel (ABI 1), from the reproducible kernel build (`moxzi kernel build`). Generated; do not edit.\n"
    f"# Built with {sys.argv[3]}; {sys.argv[4]}; linked by {sys.argv[5]}.\n"
    "# Rebuild it from source and compare: moxzi kernel verify <its package directory>.\n"
    f'abi = 1\nsha256 = "{h}"\nsize = {len(b)}\nwasm = """\n{wasm}\n"""\n')
print(f"{sys.argv[2]}: {len(b)} B, sha256:{h}")
PY
