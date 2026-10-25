#!/usr/bin/env python3
"""The constant-time scan of this kernel's compiled wasm. It began here as a one-off scan of the
secret-key arithmetic (Modulus::{pow_secret, mul, sub, to_mont_wide, r2}) that found LLVM's
`if i == digit` table scan in pow_secret and an address select in reduce_once in the alpha-10
pin; it is now kernels/ct-scan/scan.py, which scans every kernel against a reviewed policy
(kernels/ct-scan/allow/moxzi-rsa.toml: the mont.rs functions are its `ct` core, with no allowed
site), and the gate scripts/kernel_ct_scan_gate.sh, which also proves the scan fails on that
pre-fix pin.

    python3 -I kernels/moxzi-rsa/check/wasm_ct_scan.py [kernel.toml | x.wasm] [scan.py options]

Default: the pinned kernel. For a scratch build of mont.rs with a probe export, pass
`--root <probe>=<secret parameter indices>` (an ad-hoc root, no policy). Needs wasm-tools.
"""
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
src = args.pop(0) if args and not args[0].startswith('--') else os.path.join(here, '..', 'kernel', 'moxzi-rsa.kernel.toml')
scan = os.path.join(here, '..', '..', 'ct-scan', 'scan.py')
sys.exit(subprocess.call([sys.executable, '-I', scan, src, '--name', 'moxzi-rsa', *args]))
