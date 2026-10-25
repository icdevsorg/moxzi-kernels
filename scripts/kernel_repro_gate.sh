#!/usr/bin/env bash
# Rebuild every kernel from source and compare with its pinned bytes.
# An application pins each native kernel by the sha256 of its exact bytes, so those bytes must
# follow from the sources alone. This rebuilds every kernel with scripts/build-kernel.sh (pinned
# nightly, canonical work directory, one at a time) and fails if any byte differs from the
# committed pin. On Linux, with only Docker: kernels/repro/verify.sh.
#
#   scripts/kernel_repro_gate.sh                       # every kernel (5-11 min on an M-series Mac)
#   scripts/kernel_repro_gate.sh moxzi-p256 moxzi-rsa  # some (names as in kernels/repro/kernels.list)
#   KERNEL_REPRO_OUT=dir ...                           # keep the rebuilt .kernel.toml files there
#   KERNEL_REPRO_UPDATE=1 ...                          # RE-PIN: write the rebuilt files over the
#                                                      #   committed ones
#
# Also checked, without building: every .kernel.toml in the tree is listed (a new kernel cannot go
# unchecked), and every package's [kernel] file is one of them.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TC=nightly-2026-07-25   # keep in step with scripts/build-kernel.sh

# crate directory -> the committed .kernel.toml it produces
KERNELS="$(grep -v '^#' kernels/repro/kernels.list)"
pin_of() { sed -n 's/^sha256 = "\([0-9a-f]*\)"$/\1/p' "$1"; }

# --- static checks: the list is complete, every package names a listed kernel file ---------------
fail=0
listed=$(echo "$KERNELS" | awk 'NF {print $2}' | sort)
# kernels/ct-scan/teeth holds two superseded pins kept as evidence for the constant-time scan.
found=$(find kernels -name '*.kernel.toml' -not -path '*/target/*' -not -path 'kernels/ct-scan/*' | sort)
for f in $(comm -13 <(echo "$listed") <(echo "$found")); do echo "FAIL: $f is not in this gate's kernel list"; fail=1; done
for f in $(comm -23 <(echo "$listed") <(echo "$found")); do echo "FAIL: listed $f does not exist"; fail=1; done
python3 - "$listed" <<'PY2' || fail=1
# Each kernel package's mops.toml (and ic-agent-bls's declarations.toml) names its kernel file
# under [kernel] file; that file must be one this gate rebuilds.
import glob, os, sys, tomllib
listed = set(sys.argv[1].split())
bad = 0; n = 0
for m in sorted(glob.glob('kernels/*/mops.toml') + glob.glob('kernels/*/kernel/declarations.toml')):
    t = tomllib.load(open(m, 'rb'))
    if 'kernel' not in t or 'file' not in t['kernel']: continue
    n += 1
    base = os.path.dirname(m)
    if base.endswith('/kernel'): base = os.path.dirname(base)
    f = os.path.normpath(os.path.join(base, t['kernel']['file']))
    if f not in listed: print(f"FAIL: {m}: [kernel] file {f} is not a listed kernel"); bad = 1
print(f"packages: {n} name a listed kernel file")
sys.exit(bad)
PY2
[ "$fail" = 0 ] || { echo "*** kernel repro: FAIL (the pins are inconsistent before building anything) ***"; exit 1; }

if ! rustc "+$TC" -V >/dev/null 2>&1; then
  echo "FAIL: $TC is not installed (rustup toolchain install $TC --profile minimal --component rust-src)"
  exit 1
fi

# --- rebuild ---------------------------------------------------------------------------------------
tmp="${TMPDIR:-/tmp}"; OUT="${KERNEL_REPRO_OUT:-$(mktemp -d "${tmp%/}/kernel-repro.XXXXXX")}"; mkdir -p "$OUT"
echo "rebuilt kernels: $OUT"
printf '%-16s %-16s %-16s %6s  %s\n' kernel pinned rebuilt time verdict
match=0; total=0; t_all=$SECONDS
while read -r crate toml; do
  [ -n "$crate" ] || continue
  name=$(basename "$toml" .kernel.toml)
  if [ "$#" -gt 0 ]; then case " $* " in *" $name "*) ;; *) continue ;; esac; fi
  total=$((total+1)); t0=$SECONDS
  pinned=$(pin_of "$toml")
  if bash scripts/build-kernel.sh "$crate" "$OUT/$name.kernel.toml" >"$OUT/$name.log" 2>&1; then
    got=$(pin_of "$OUT/$name.kernel.toml")
    grep '^note:' "$OUT/$name.log" | sed 's/^/    /'   # ignored settings, stray cargo config
  else
    got=BUILD-FAILED; sed 's/^/    /' "$OUT/$name.log" | tail -15
  fi
  v=DIFF; [ "$got" = "$pinned" ] && { v=MATCH; match=$((match+1)); }
  # Same bytes, other file (the toolchain header): refresh it; it moves no pin.
  if [ -n "${KERNEL_REPRO_UPDATE:-}" ] && [ "$v" = MATCH ] && ! cmp -s "$OUT/$name.kernel.toml" "$toml"; then
    cp "$OUT/$name.kernel.toml" "$toml"; v="MATCH (header refreshed)"
  fi
  if [ -n "${KERNEL_REPRO_UPDATE:-}" ] && [ "$v" = DIFF ] && [ "$got" != BUILD-FAILED ]; then
    cp "$OUT/$name.kernel.toml" "$toml"
    v=REPINNED
  fi
  printf '%-16s %-16s %-16s %5ss  %s\n' "$name" "${pinned:0:12}…" "${got:0:12}…" $((SECONDS-t0)) "$v"
done <<<"$KERNELS"
[ "$total" -gt 0 ] || { echo "FAIL: no kernel matched: $*"; exit 1; }
toolchain=$(grep -m1 '^# Built with' "$OUT"/*.kernel.toml 2>/dev/null | head -1 | sed 's/^[^#]*# Built with //; s/\.$//')
echo "host: $(uname -sm); ${toolchain:-toolchain unknown}"
if [ "$match" = "$total" ]; then
  echo "*** kernel repro: $match/$total kernels rebuild to their pinned bytes ($((SECONDS-t_all))s) ***"
  exit 0
fi
if [ -n "${KERNEL_REPRO_UPDATE:-}" ]; then
  echo "*** kernel repro: re-pinned $((total-match)) of $total kernels -- review the diff, rerun the kernel suites ***"
  exit 0
fi
echo "*** kernel repro: FAIL -- $((total-match)) of $total kernels do not rebuild to their pins (rebuilt files: $OUT) ***"
exit 1
