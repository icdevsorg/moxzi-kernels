#!/usr/bin/env bash
# Scan the kernels' compiled wasm for secret-dependent branches and memory addresses.
# The kernels' Rust is written constant-time where it touches secrets, but LLVM may prove a mask
# is 0 or all ones and turn it back into a branch or an address select. Instruction counts can
# stay equal (both arms the same length), so a test that compares instruction counts cannot see
# it; an off-chain host compiles the wasm to native code, where a branch on a secret or a load
# from a secret-chosen address is a branch-predictor / cache timing leak. It happened twice (found
# in review, 2026-10-24): the secp256k1 comb select (libsecp's AffineStorage::cmov: 64
# digit-dependent br_if and 189 address selects) and RSA's pow_secret table scan + reduce_once.
#
# For EVERY shipped kernel (kernels/*/kernel/*.kernel.toml) kernels/ct-scan/scan.py decodes the
# pinned wasm, disassembles it with wasm-tools, and runs a flow-sensitive taint analysis over the
# functions the secret-handling exports reach; every DATA-dependent branch, address select or
# DATA-indexed access must be in the kernel's reviewed policy kernels/ct-scan/allow/<kernel>.toml
# with an exact count and a reason. A kernel without a policy, a new site, a changed count, or a
# stale entry fails.
#
# Teeth: the same scan, with the CURRENT policies, must FAIL on the two superseded pins that had
# those leaks (kernels/ct-scan/teeth/), in the functions that leaked. A gate that cannot fail
# proves nothing.
#
#   bash scripts/kernel_ct_scan_gate.sh
#   ONLY=moxzi-rsa bash scripts/kernel_ct_scan_gate.sh    # one kernel (skips the teeth)
#
# Needs python3 >= 3.11 and wasm-tools (cargo install wasm-tools). A missing one is a FAIL, never
# a skip. About 35 s for all eleven kernels plus the teeth.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$ROOT/kernels/ct-scan/scan.py"
T0=$SECONDS
fail=0

command -v wasm-tools >/dev/null 2>&1 || { echo "FAIL: wasm-tools is not on PATH (cargo install wasm-tools)"; exit 1; }
python3 -c 'import sys, tomllib; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null \
  || { echo "FAIL: python3 >= 3.11 (tomllib) is required"; exit 1; }
echo "$(wasm-tools --version); $(python3 --version)"


shopt -s nullglob
pins=("$ROOT"/kernels/*/kernel/*.kernel.toml)
shopt -u nullglob
[ ${#pins[@]} -gt 0 ] || { echo "FAIL: no shipped kernels found"; exit 1; }

names=()
for pin in "${pins[@]}"; do
  name=$(basename "$pin" .kernel.toml)
  names+=("$name")
  [ -n "${ONLY:-}" ] && [ "$name" != "$ONLY" ] && continue
  t0=$SECONDS
  if out=$(python3 -I "$SCAN" "$pin" 2>&1); then
    printf "  ok   %-18s %3ds  %s\n" "$name" $((SECONDS - t0)) "$(echo "$out" | head -1 | sed "s/^$name: //")"
  else
    printf "  FAIL %-18s %3ds\n" "$name" $((SECONDS - t0))
    echo "$out" | head -60 | sed 's/^/       /'
    fail=1
  fi
done

# Every policy belongs to a shipped kernel (a renamed kernel must take its policy along).
for pol in "$ROOT"/kernels/ct-scan/allow/*.toml; do
  n=$(basename "$pol" .toml)
  printf '%s\n' "${names[@]}" | grep -qx "$n" || { echo "  FAIL policy $n.toml has no shipped kernel"; fail=1; }
done

# Teeth: the pre-fix pins must fail, in the functions that leaked. kernels/ct-scan/teeth/ holds
# them as they were committed before the fixes: moxzi-secp256k1 before the comb entry was selected
# with masks, moxzi-rsa before pow_secret's table scan and reduce_once were made branch-free.
teeth() {  # teeth <pin> <function glob>...
  local f=$1; shift
  local label; label=$(basename "$f" .kernel.toml)
  if [ ! -f "$f" ]; then
    echo "  FAIL teeth: $f is missing"; fail=1; return
  fi
  local out
  if out=$(python3 -I "$SCAN" "$f" --expect-fail "$@" 2>&1); then
    printf "  ok   teeth %-16s %s\n" "$label" "$(echo "$out" | grep TEETH | sed 's/^ *TEETH: //')"
  else
    echo "  FAIL teeth $label: the scan passes the pre-fix pin $f"
    echo "$out" | tail -5 | sed 's/^/       /'
    fail=1
  fi
}
if [ -z "${ONLY:-}" ]; then
  TEETH="$ROOT/kernels/ct-scan/teeth"
  teeth "$TEETH/moxzi-secp256k1.kernel.toml" 'moxzi_secp256k1_kernel::ops::mul_g'
  teeth "$TEETH/moxzi-rsa.kernel.toml" \
    '<moxzi_rsa_kernel::mont::Modulus<48>>::pow_secret' '<moxzi_rsa_kernel::mont::Modulus<48>>::to_mont_wide'
fi

if [ $fail -eq 0 ]; then
  echo "PASS: ${#pins[@]} kernels scanned against their policies; the pre-fix pins fail ($((SECONDS - T0))s)"
  exit 0
fi
echo "FAIL: see above ($((SECONDS - T0))s). Review every reported site: fix a real secret-dependent branch;"
echo "      allow a public one in kernels/ct-scan/allow/<kernel>.toml with its reason."
exit 1
