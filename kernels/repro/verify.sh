#!/usr/bin/env bash
# Check, on Linux, that every moxzi native kernel rebuilds from source to its pinned bytes.
# Needs only Docker and this checkout:
#
#   kernels/repro/verify.sh                          # all kernels, the host's architecture
#   kernels/repro/verify.sh moxzi-p256 moxzi-rsa     # some kernels
#   PLATFORM=linux/amd64 kernels/repro/verify.sh     # another architecture (emulated: slower)
#   CPUS=2 kernels/repro/verify.sh                   # CPUs for the container (default 4)
#   KERNEL_REPRO_OUT=/abs/dir kernels/repro/verify.sh   # keep the rebuilt .kernel.toml files
#
# It builds the image in this directory (Debian, rustup, the pinned nightly with rust-src), mounts
# the checkout read-only, and runs scripts/kernel_repro_gate.sh inside, which builds each kernel at
# the canonical /tmp/moxzi-kernel-build with scripts/build-kernel.sh and compares sha256s. Exit 0
# means every rebuilt kernel is byte-identical to the one applications pin.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM="${PLATFORM:-}"
TAG="moxzi-kernel-repro:${PLATFORM:-native}"; TAG="${TAG//\//-}"
docker build ${PLATFORM:+--platform "$PLATFORM"} -t "$TAG" "$ROOT/kernels/repro"
MOUNT_OUT=(); ENV_OUT=()
if [ -n "${KERNEL_REPRO_OUT:-}" ]; then
  mkdir -p "$KERNEL_REPRO_OUT"
  MOUNT_OUT=(-v "$(cd "$KERNEL_REPRO_OUT" && pwd):/out"); ENV_OUT=(-e KERNEL_REPRO_OUT=/out)
fi
exec docker run --rm ${PLATFORM:+--platform "$PLATFORM"} --cpus "${CPUS:-4}" \
  -v "$ROOT:/repo:ro" ${MOUNT_OUT[@]+"${MOUNT_OUT[@]}"} ${ENV_OUT[@]+"${ENV_OUT[@]}"} \
  "$TAG" bash /repo/scripts/kernel_repro_gate.sh "$@"
