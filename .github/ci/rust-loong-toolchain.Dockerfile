# The pinned cross image has no Python, which the build/ELF guards require.
# Reuse a portable interpreter from the already pinned x86 floor image; no
# package installation or target-sysroot changes happen in the CI job.
FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:e0adf18521ad35192df733a6c62d35df7801957d24e0470238aacecfab2188a3 AS python
RUN cp -aL /opt/python/cp311-cp311 /floor-python
FROM ghcr.io/cross-rs/loongarch64-unknown-linux-gnu@sha256:2a47f65508a27636f726ebd9e79cd37ed14981f86ab894e08210f5fc02c03031
COPY --from=python /floor-python /opt/floor-python
ENV PATH="/opt/floor-python/bin:${PATH}"
RUN python3 -c 'import argparse, json, pathlib, re, subprocess'
