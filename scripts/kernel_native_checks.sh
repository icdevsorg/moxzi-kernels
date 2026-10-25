#!/usr/bin/env bash
# THE KERNELS' RUST, CHECKED WHERE IT IS NOT WASM. A native kernel writes straight into the
# canister's memory: undefined behaviour or a write past its buffer corrupts canister state
# (under enhanced orthogonal persistence, state that survives upgrades), and no test of the wasm
# can see that -- wasm has no bounds inside one linear memory. So the kernels' sources also run
# here, natively and under Miri, in the check crates under kernels/:
#  - kernels/moxzi-kernel/check: the SDK (bytes/output/text/trap/allocator) and EVERY exported
#    function of every family, called as the program's glue calls them (exact-size result
#    buffers, payload pointers, results read back and validated), on valid and hostile inputs;
#  - kernels/moxzi-rsa/check: mont.rs (raw-pointer Montgomery arithmetic) against num-bigint
#    for every modulus size, sign/verify against the rsa crate, RFC 8017 and Wycheproof;
#  - kernels/moxzi-{ed25519,p256,secp256k1}/check: each family's ops.rs against the reference
#    crate it replaced.
#
#   bash scripts/kernel_native_checks.sh           # natively, release (+ debug / cfg variants)
#   MIRI=1 bash scripts/kernel_native_checks.sh    # the same crates under Miri (slow: ~30 min)
#   ONLY=RSA bash scripts/kernel_native_checks.sh  # just the runs whose label contains RSA
#
# Miri runs on the pinned nightly with -Zmiri-strict-provenance -Zmiri-symbolic-alignment-check
# (override with MIRIFLAGS); the crates cut their case counts under cfg(miri) and keep every
# class of edge case. MIRI_PAR (default 4) Miri processes run at once; CARGO_JOBS (default 4)
# bounds each build.
#
# Measured 2026-10-23 on a busy 10-core machine: native 70 s warm (~6 min from cold); Miri
# 1,604 s wall in 4 lanes, 8 runs, no UB -- the longest P-256 ops (26 min), then secp256k1 (18),
# the kernel ABI (14), RSA mont.rs (9), one RSA-3072 signature (7, ~20 under heavy load).
#
# A missing toolchain is a FAIL, never a skip: a check that did not run proved nothing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIRI_TC=nightly-2026-07-25
JOBS="${CARGO_JOBS:-4}"
PAR="${MIRI_PAR:-4}"
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-symbolic-alignment-check}"
LOG_DIR="${LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/kernel-native-checks.XXXXXX")}"
mkdir -p "$LOG_DIR"
DALEK32='RUSTFLAGS=--cfg curve25519_dalek_bits="32"'
T0=$SECONDS
# cargo-miri reads MIRI as the path of the miri binary: take our switch out of the environment.
WANT_MIRI="${MIRI:-}"
unset MIRI

if [ -n "$WANT_MIRI" ]; then
  if ! cargo "+$MIRI_TC" miri --version >/dev/null 2>&1; then
    echo "FAIL: Miri is not installed for $MIRI_TC (rustup component add --toolchain $MIRI_TC miri)"
    exit 1
  fi
  echo "Miri: $(cargo "+$MIRI_TC" miri --version 2>/dev/null); MIRIFLAGS=$MIRIFLAGS"
  # Build Miri's sysroot once, before the parallel runs.
  cargo "+$MIRI_TC" miri setup >"$LOG_DIR/miri-setup.log" 2>&1 || { echo "FAIL: cargo miri setup (log: $LOG_DIR/miri-setup.log)"; exit 1; }
else
  cargo --version >/dev/null 2>&1 || { echo "FAIL: no cargo on PATH"; exit 1; }
  echo "$(cargo --version)"
fi
echo "logs: $LOG_DIR"

# check <label> <crate dir under kernels/> <words...>: run cargo in that crate. A word NAME=value
# goes to the environment; the rest are cargo's arguments. Writes <slug>.verdict.
check() {
  local label=$1 dir=$2; shift 2
  local slug=${label//[^A-Za-z0-9]/_}
  local log="$LOG_DIR/$slug.log" t0=$SECONDS envs=() args=() w
  for w in "$@"; do
    case "$w" in [A-Z]*=*) envs+=("$w") ;; *) args+=("$w") ;; esac
  done
  if (cd "$ROOT/kernels/$dir" && env ${envs[@]+"${envs[@]}"} cargo "${args[@]}") >"$log" 2>&1; then
    local n ign
    n=$(grep -E '^test result: ok' "$log" | awk '{s += $4} END {print s + 0}')
    ign=$(grep -E '^test result: ok' "$log" | awk '{s += $8} END {print s + 0}')
    if [ "$n" -gt 0 ]; then
      printf "  ok   %-52s %5ds  %3d tests%s\n" "$label" $((SECONDS - t0)) "$n" "$([ "$ign" -gt 0 ] && echo ", $ign ignored")" >"$LOG_DIR/$slug.verdict"
    else
      printf "  FAIL %-52s %5ds  no tests ran (log: %s)\n" "$label" $((SECONDS - t0)) "$log" >"$LOG_DIR/$slug.verdict"
    fi
  else
    {
      printf "  FAIL %-52s %5ds  (log: %s)\n" "$label" $((SECONDS - t0)) "$log"
      grep -E "Undefined Behavior|^error|panicked|FAILED|failures:" "$log" | head -12 | sed 's/^/       /'
    } >"$LOG_DIR/$slug.verdict"
  fi
  cat "$LOG_DIR/$slug.verdict"
}

RUNS=()
if [ -z "$WANT_MIRI" ]; then
  RUNS+=("kernel ABI: SDK + every export, all but P-256|moxzi-kernel/check|$DALEK32|CARGO_TARGET_DIR=target/bits32|test|--release|-j$JOBS")
  RUNS+=("kernel ABI: P-256 exports|moxzi-kernel/check|$DALEK32|CARGO_TARGET_DIR=target/bits32|test|--release|-j$JOBS|--no-default-features|--features|p256")
  RUNS+=("kernel ABI: debug (overflow checks)|moxzi-kernel/check|test|-j$JOBS")
  RUNS+=("RSA: Montgomery arithmetic, sign, verify|moxzi-rsa/check|test|--release|-j$JOBS")
  RUNS+=("Ed25519 ops, 64-bit backend|moxzi-ed25519/check|test|--release|-j$JOBS")
  RUNS+=("Ed25519 ops, 32-bit backend (as built)|moxzi-ed25519/check|$DALEK32|CARGO_TARGET_DIR=target/bits32|test|--release|-j$JOBS")
  RUNS+=("P-256 ops|moxzi-p256/check|test|--release|-j$JOBS")
  RUNS+=("secp256k1 ops|moxzi-secp256k1/check|test|--release|-j$JOBS")
  RUNS+=("secp256k1 ops, debug (field magnitude asserts)|moxzi-secp256k1/check|test|-j$JOBS")
  PAR=1
else
  # PAR lanes take runs i, i + PAR, ...; with 4 lanes the order below balances them by the
  # times measured 2026-10-23 (one RSA-3072 signature alone is ~25 min of Miri, so it gets a
  # lane). The two kernel-ABI builds share target/miri and the same RUSTFLAGS, so neither
  # rebuilds the other's dependencies.
  RUNS+=("Miri: RSA signing (mont.rs at 48 limbs, the 384-byte result)|moxzi-rsa/check|+$MIRI_TC|miri|test|-j$JOBS|--|--exact|sign_is_rfc8017")
  RUNS+=("Miri: P-256 ops|moxzi-p256/check|+$MIRI_TC|miri|test|-j$JOBS")
  RUNS+=("Miri: kernel ABI, all but P-256|moxzi-kernel/check|$DALEK32|+$MIRI_TC|miri|test|-j$JOBS")
  RUNS+=("Miri: secp256k1 ops|moxzi-secp256k1/check|+$MIRI_TC|miri|test|-j$JOBS")
  RUNS+=("Miri: RSA verify, Wycheproof, traps, keys|moxzi-rsa/check|+$MIRI_TC|miri|test|-j$JOBS|--|wycheproof|verify_|sign_traps|sign_refuses|keys")
  RUNS+=("Miri: kernel ABI, P-256 exports|moxzi-kernel/check|$DALEK32|+$MIRI_TC|miri|test|-j$JOBS|--no-default-features|--features|p256")
  RUNS+=("Miri: RSA mont.rs|moxzi-rsa/check|+$MIRI_TC|miri|test|-j$JOBS|--|mont_")
  RUNS+=("Miri: Ed25519 ops, 32-bit backend (as built)|moxzi-ed25519/check|$DALEK32|+$MIRI_TC|miri|test|-j$JOBS")
fi

# PAR lanes, each running its share of RUNS in order (run i goes to lane i mod PAR; the list
# is longest first, so the longest run gets a lane of its own).
labels=()
selected=()
for r in "${RUNS[@]}"; do
  label=${r%%|*}
  case "$label" in *"${ONLY:-}"*) ;; *) continue ;; esac
  labels+=("$label")
  selected+=("$r")
done
lane() {
  local i=0 r parts
  for r in ${selected[@]+"${selected[@]}"}; do
    if [ $((i % PAR)) -eq "$1" ]; then
      IFS='|' read -r -a parts <<<"$r"
      check "${parts[@]}"
    fi
    i=$((i + 1))
  done
}
if [ "$PAR" -le 1 ]; then
  lane 0
else
  for ((l = 0; l < PAR; l++)); do lane "$l" & done
  wait
fi

[ "${#labels[@]}" -gt 0 ] || { echo "FAIL: no run matches ONLY=${ONLY:-}"; exit 1; }
fails=0
for label in "${labels[@]}"; do
  v="$LOG_DIR/${label//[^A-Za-z0-9]/_}.verdict"
  if [ ! -f "$v" ] || ! grep -q '^  ok ' "$v"; then fails=$((fails + 1)); fi
done
mode=native; [ -n "$WANT_MIRI" ] && mode="Miri ($MIRIFLAGS)"
if [ "$fails" -gt 0 ]; then
  echo "*** kernel native checks ($mode): $fails of ${#labels[@]} runs FAILED, $((SECONDS - T0))s ***"
  exit 1
fi
echo "*** kernel native checks ($mode): ${#labels[@]} runs ok, $((SECONDS - T0))s wall ***"
