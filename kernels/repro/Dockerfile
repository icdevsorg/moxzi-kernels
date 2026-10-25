# A Linux machine for rebuilding moxzi's native kernels from source.
#
#   kernels/repro/verify.sh            # builds this image, rebuilds every kernel, compares pins
#
# Nothing here reaches the kernel bytes except the pinned nightly (its rustc, its rust-src for
# -Zbuild-std, its rust-lld) and the crates in each kernel's committed Cargo.lock: the base image,
# rustup, gcc (host build scripts only) and python only drive the build. The image is pinned by
# digest anyway, so the build is the same tomorrow.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc libc6-dev python3 rsync git \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
# Keep in step with TC in scripts/build-kernel.sh.
ARG KERNEL_TOOLCHAIN=nightly-2026-07-25
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none \
 && rustup toolchain install "$KERNEL_TOOLCHAIN" --profile minimal --component rust-src \
 && rustc "+$KERNEL_TOOLCHAIN" -vV && cargo "+$KERNEL_TOOLCHAIN" -V

WORKDIR /repo
