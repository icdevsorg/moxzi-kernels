#!/usr/bin/env python3
"""The constant-time scan of this kernel's compiled wasm. It began here as a one-off scan of the
comb (ops::mul_g) that found LLVM's branches and address selects keyed on the secret digit in the
alpha-10 pin (64 br_if, 189 selects); it is now kernels/ct-scan/scan.py, which scans every kernel
against a reviewed policy (kernels/ct-scan/allow/moxzi-secp256k1.toml), and the gate
scripts/kernel_ct_scan_gate.sh, which also proves the scan fails on that pre-fix pin.

    python3 -I kernels/moxzi-secp256k1/check/wasm_ct_scan.py [kernel.toml | x.wasm] [scan.py options]

Default: the pinned kernel. For a scratch build with mul_g inlined into a probe export, pass
`--root <probe>=<secret parameter index>` (an ad-hoc root, no policy). Needs wasm-tools.
"""
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
src = args.pop(0) if args and not args[0].startswith('--') else os.path.join(here, '..', 'kernel', 'moxzi-secp256k1.kernel.toml')
scan = os.path.join(here, '..', '..', 'ct-scan', 'scan.py')
sys.exit(subprocess.call([sys.executable, '-I', scan, src, '--name', 'moxzi-secp256k1', *args]))
