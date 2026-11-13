# Linux CI toolchain for the Xinchuang unit-test lanes, built and cached on the
# Mac runner by .github/workflows/xinchuang-ci.yml (build-once, reuse). The
# unit-tests and tagged-lane jobs run INSIDE this image: ubuntu 24.04 + Go
# 1.26.6 + Node 26 + PostgreSQL 17 (server, pgtap, pg_prove) + Rust stable +
# libopus + python3. No docker inside — postgres runs locally in
# the container; the throwaway container itself is the isolation boundary.
#
# arm64 (Apple Silicon) or amd64 (Go tarball follows the image architecture). Rebuild with:
#   docker build -t setjoin-ci-linux-tc:1 -f .github/ci/linux-toolchain.Dockerfile .github/ci
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates curl git build-essential pkg-config jq xz-utils \
       sudo gnupg libopus0 python3 python3-pip iproute2 ripgrep \
  && rm -rf /var/lib/apt/lists/*

# Node 26 (webmail build + the node-based structural guards)
RUN curl -fsSL https://deb.nodesource.com/setup_26.x | bash - \
  && apt-get install -y --no-install-recommends nodejs \
  && rm -rf /var/lib/apt/lists/*

# PostgreSQL 17 + pgtap + pg_prove (PGDG; noble ships 16, the schema pins 17)
RUN install -d /usr/share/postgresql-common/pgdg \
  && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
       postgresql-17 postgresql-client-17 postgresql-17-pgtap \
       libtap-parser-sourcehandler-pgtap-perl libdbd-pg-perl \
  && rm -rf /var/lib/apt/lists/*
ENV PATH="/usr/lib/postgresql/17/bin:${PATH}"

# Go 1.26.6 (go.work pins 1.26.6; GOTOOLCHAIN=local in the CI go-setup step)
ARG GO_VERSION=1.26.6
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
      -o /tmp/go.tgz \
  && tar -C /usr/local -xzf /tmp/go.tgz \
  && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Rust stable (tauri-bridge cargo test, R2 native lane, server-rust via
# scripts/check-server-rust.sh). rustup installs the image-architecture
# toolchain (amd64 and arm64). Floor: server-rust/tools/schema-simulation pins
# rust-version 1.99 (the server-rust workspace and pilot need >= 1.97.1), so
# the build fails here rather than in the guard if stable is ever older.
# The build context is .github/ci (no source), so the image cannot test the
# workspace at build time: scripts/verify-server-rust-image.sh runs
# check-server-rust.sh (+ --self-test) inside the built image. Executed on
# amd64 only (RP07 review-fix pass, 2026-10-29); arm64 is NOT_RUN until that
# script is run on an arm64 host.
ARG RUST_MIN_VERSION=1.99.0
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add llvm-tools
RUN have="$(rustc --version | awk '{print $2}')" \
  && if [ "$(printf '%s\n%s\n' "$RUST_MIN_VERSION" "$have" | sort -V | head -1)" != "$RUST_MIN_VERSION" ]; then \
       echo "rustc $have is older than the server-rust floor $RUST_MIN_VERSION" >&2; exit 1; \
     fi

# Pinned supply-chain policy checker for the server Rust workspace.
RUN cargo install cargo-deny --locked --version 0.19.0

# Native-lane system libraries the bare-metal Linux runner is provisioned with:
# Tauri/GTK/WebKit for the R2 native lane (glib-sys et al.) and libopus headers
# for the asrbot cgo build.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       libglib2.0-dev libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev \
       libjavascriptcoregtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
       libssl-dev libopus-dev \
  && rm -rf /var/lib/apt/lists/*

# pg_prove must find DBD::Pg for the pgTAP suite; the perl packages above land
# in the system perl, which is the one pg_prove runs under.
RUN pg_prove --version 2>&1 | head -1 || true

CMD ["/bin/bash"]
