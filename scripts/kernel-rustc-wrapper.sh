#!/usr/bin/env bash
# RUSTC_WRAPPER for scripts/build-kernel.sh: makes cargo's crate hashes independent of the build
# machine. Every other rustc call passes through unchanged. `moxzi kernel build` does the same
# (the moxzi binary is its own wrapper).
#
# WHY. Cargo gives each crate a `-C metadata` hash, which becomes the crate's
# StableCrateId: it is in every mangled symbol, and fat LTO orders the merged constants by it. For
# units built FOR THE HOST -- build scripts, which libc, compiler_builtins, typenum and others have --
# cargo mixes in the host triple from `rustc -vV` (cargo's compute_metadata/hash_rustc_version), and
# every crate that depends on one inherits the difference. So macOS arm64 and Linux arm64 built
# five of the kernels with the same functions but constants in another order (p256: 99
# bytes, two .rodata blobs swapped). Cargo reads the host triple through the wrapper, so the
# wrapper reports one fixed name and the hashes agree everywhere. Cargo uses the name only for
# hashing, for config lookup ([target.<triple>], none here), and as $HOST for build scripts; host
# code is still compiled for the real host, because cargo passes no --target for host units.
CANONICAL_HOST=moxzi-kernel-build-host
if [ "$#" -eq 2 ] && [ "$2" = -vV ]; then
  out="$("$1" -vV)" || exit $?
  printf '%s\n' "$out" | sed "s/^host: .*/host: $CANONICAL_HOST/"
  exit 0
fi
exec "$@"
