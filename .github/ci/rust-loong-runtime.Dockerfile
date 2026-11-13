# This sysroot is crosstool-ng's new-world LP64D glibc 2.36, not Ubuntu's libc.
FROM ghcr.io/cross-rs/loongarch64-unknown-linux-gnu@sha256:2a47f65508a27636f726ebd9e79cd37ed14981f86ab894e08210f5fc02c03031 AS toolchain
FROM scratch
COPY --from=toolchain /x-tools/loongarch64-unknown-linux-gnu/loongarch64-unknown-linux-gnu/sysroot/ /
COPY --from=toolchain /usr/local/bin/qemu-loongarch64 /qemu-loongarch64
ENTRYPOINT ["/qemu-loongarch64", "-L", "/"]
