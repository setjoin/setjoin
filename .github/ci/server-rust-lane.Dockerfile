# The server-rust lane image: the pinned CI toolchain image plus the pinned lane tools
# (cargo-nextest, cargo-deny, pebble; scripts/server-rust-lane-tools.sh verifies their sha256).
# Built by .github/workflows/ci-images.yml with BASE = the pinned setjoin-ci-linux-tc digest.
ARG BASE
FROM ${BASE}
COPY scripts/server-rust-lane-tools.sh /tmp/server-rust-lane-tools.sh
RUN LANE_BIN_DIR=/usr/local/bin bash /tmp/server-rust-lane-tools.sh \
  && rm /tmp/server-rust-lane-tools.sh && go clean -modcache \
  && cargo nextest --version && cargo deny --version && test -x /usr/local/bin/pebble
