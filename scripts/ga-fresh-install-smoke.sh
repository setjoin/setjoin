#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# ga-fresh-install-smoke.sh — GA gap G0-002: fully-automated fresh-install
# smoke (retired-docs:superpowers/plans/archive/2026-07-04-ga-readiness-program-index.md, G1).
#
# WHAT THIS IS. From a completely clean throwaway Docker container, drives
# the REAL operator path with no human in the loop: build → provision DB →
# mailserver/deploy/scripts/install.sh → assert /ready → rebuild →
# mailserver/deploy/scripts/upgrade.sh → assert /ready → a genuine rollback
# exercise (a broken binary forces upgrade.sh's rollback path, then health is
# re-asserted). It does NOT reimplement install/upgrade logic — it drives the
# real scripts, same as an operator would (ponytail: the installer already
# exists; this just proves it works end to end by machine).
#
# SYSTEMD-VS-DIRECT (read this before changing the container setup). The
# installer registers a systemd unit (`setjoin.service`) and G1's manual
# fresh-container run already found THREE systemd-unit-file bugs that a
# direct-daemon smoke would never have caught (missing
# `Environment=CONFIG_PATH`, wrong `ReadWritePaths`, a MinIO-only
# `ExecStartPre` that blocked forever under SeaweedFS — see
# mailserver/deploy/mailserver.service history). So this script uses a
# SYSTEMD-CAPABLE base image (`ubuntu:24.04` + `systemd`/`systemd-sysv`,
# `CMD ["/sbin/init"]`) run `--privileged` with the host cgroup mounted —
# proven to boot systemd cleanly on this box (cgroup v2, Docker 29). That is
# the ONLY way to exercise the actual `systemctl start/stop setjoin` path the
# installer and upgrade script use. If your Docker host can't run privileged/
# systemd containers (rootless Docker, gVisor sandboxes, some hosted CI), this
# script will NOT work as-is — install.sh itself has a documented direct-
# daemon fallback (its "systemd" step prints the manual `mailserverd` command
# when `systemctl` is absent), but this script's health/rollback assertions
# are written against the systemd-managed service, so a direct-daemon mode is
# NOT implemented here. Add one only if a real CI runner needs it (YAGNI).
#
# COVERAGE — what this DOES prove:
#   - The whole SINGLE_NODE_SETUP.md path actually runs on a byte-for-byte
#     fresh install target: schema create + baseline + forward migrations +
#     reducers + native-RLS role provisioning (constrained three-role runtime
#     DSN shape — the install default), public Guest-invite origin seeding,
#     config.env generation, BOTH systemd units (setjoin-auth + setjoin),
#     governed first-admin creation, and a REAL /ready
#     probe (the real HTTPS listener with a :80 fallback — never trusting a
#     bare :80 301, the exact false-green class the G1 upgrade.sh fix closed).
#   - A REAL admin login round-trip through the gateway (POST /auth/login →
#     verified-credential response: access_token, or the fresh-install default
#     MFA policy's mfa_enrollment_required — both only exist after password
#     verification inside authserverd): proves the auth unit is up, the
#     gateway's AUTHSERVER_URL points at it, and the constrained setjoin_app
#     credential can actually serve auth — the 2026-07-06 real deploy 502'd
#     every login while this smoke's ancestor (/ready-only) stayed green;
#     this assertion closes that mask for good.
#   - upgrade.sh's binary-swap + schema-check/apply + health re-probe.
#   - upgrade.sh's ROLLBACK path for real: a deliberately broken "new binary"
#     is fed to upgrade.sh, which must fail health, roll back, and leave the
#     service healthy again on the previous binary — this script asserts all
#     three, not just that rollback files exist on disk.
#
# COVERAGE CEILING — what this does NOT prove (say so, don't fake green):
#   - No genuine CROSS-VERSION schema migration: there is only one checked-out
#     commit here, so the "upgrade" rebuilds the SAME commit's binary. A real
#     forward-migration apply between two different schema versions is not
#     exercised (same honest scope as the earlier manual G1 upgrade smoke).
#   - A privileged Docker container is not a real VM/bare-metal host: it
#     shares the host kernel, and Docker's systemd support (cgroup delegation,
#     etc.) can behave subtly differently from a real machine. This is the
#     closest thing achievable in CI, not a substitute for the periodic real-
#     VM smoke SINGLE_NODE_SETUP.md's own doc still recommends.
#   - Single distro (Ubuntu 24.04, host arch) — not the full OS support
#     matrix. No TLS/public-DNS, no HA/multi-node, no backup.sh, no SCIM/
#     mailctl user provisioning, no browser/webmail UI interaction beyond the
#     webmail build succeeding. Login is asserted via the JSON API, not a
#     browser session (no MFA/SSO flows).
#
# USAGE.
#   Local (on a Linux host with Docker, e.g. the self-hosted CI runner):
#     bash scripts/ga-fresh-install-smoke.sh
#   From a Mac (no local Docker) via the self-hosted Linux box:
#     rsync -a --exclude .git "$PWD"/ <host>:~/ga-smoke-src/ && \
#       ssh <host> 'cd ~/ga-smoke-src && bash scripts/ga-fresh-install-smoke.sh'
#   Env overrides:
#     REBUILD_BASE=1     force-rebuild the cached base image (Dockerfile changed)
#     PRELOAD_HOST_EGRESS=0 disable exact-digest Egress cache import from the
#                         Docker host into the nested Podman store (default: 1)
#     KEEP_ON_FAIL=1     leave the containers running on failure for `docker exec -it`
#     KEEP_ON_SUCCESS=1  retain a passing stack for a later integration phase
#     SMOKE_PREFIX=name  isolate container names (default: ga-fresh-install-smoke)
#     SMOKE_NETWORK=name attach the systemd container to an existing Docker network
#     SMOKE_IPV4=address request a stable address on SMOKE_NETWORK
#     SMOKE_DNS=address  use an isolated DNS resolver inside the systemd container
#     SMOKE_HOSTNAME=fqdn set the systemd container hostname
#     REPLACE_EXISTING=1 remove exact-name stale containers before starting
#     RESUME_PREINSTALL=1 reuse exact-name running containers only when the
#                         installer has not installed Setjoin yet
#     RESUME_INSTALL=1    reuse exact-name running containers after a failed
#                         idempotent install/start probe; reruns the real
#                         installer and every subsequent assertion
#
# EXIT CODE IS THE GATE: 0 only if install + upgrade + rollback all assert
# healthy; any failure prints "FAIL at step: <name>" and exits non-zero.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG_TAG="setjoin-ga-smoke-base:v9" # bump the tag whenever the Dockerfile below changes
SMOKE_PREFIX="${SMOKE_PREFIX:-ga-fresh-install-smoke}"
C="$SMOKE_PREFIX"
C_MINIO="${SMOKE_PREFIX}-minio"
KEEP_ON_FAIL="${KEEP_ON_FAIL:-0}"
KEEP_ON_SUCCESS="${KEEP_ON_SUCCESS:-0}"
REBUILD_BASE="${REBUILD_BASE:-0}"
PRELOAD_HOST_EGRESS="${PRELOAD_HOST_EGRESS:-1}"
REPLACE_EXISTING="${REPLACE_EXISTING:-0}"
RESUME_PREINSTALL="${RESUME_PREINSTALL:-0}"
RESUME_INSTALL="${RESUME_INSTALL:-0}"
SMOKE_NETWORK="${SMOKE_NETWORK:-}"
SMOKE_IPV4="${SMOKE_IPV4:-}"
SMOKE_DNS="${SMOKE_DNS:-}"
SMOKE_HOSTNAME="${SMOKE_HOSTNAME:-}"
SMOKE_FAILED=0

say() { printf '\n=== %s ===\n' "$1"; }
die() {
  printf '\nFAIL at step: %s\n' "$1" >&2
  printf 'RESULT: FAIL\n'
  SMOKE_FAILED=1
  exit 1
}

# Per-run S3 credentials for the disposable MinIO sidecar. Generated, never the
# vendor defaults: install.sh's well-known-default-credential guard refuses any
# pair containing minioadmin/changeme/..., so the previous literal
# minioadmin/minioadmin12345 failed the install step on every run. The sidecar
# env, the in-container config.env and the installer env must all carry the
# SAME pair (one mismatch and /ready hides an unusable object store).
command -v openssl >/dev/null 2>&1 || die "openssl is required to generate the smoke S3 credentials"
if [ "$RESUME_PREINSTALL" = "1" ] || [ "$RESUME_INSTALL" = "1" ]; then
  # A kept sidecar still runs with the original run's pair — recover it so a
  # resumed install pins the same credentials the surviving containers use.
  SMOKE_S3_USER="$(docker exec "$C_MINIO" printenv MINIO_ROOT_USER)" || die "resume: cannot read sidecar S3 user"
  SMOKE_S3_PASS="$(docker exec "$C_MINIO" printenv MINIO_ROOT_PASSWORD)" || die "resume: cannot read sidecar S3 password"
else
  SMOKE_S3_USER="smoke-$(openssl rand -hex 8)"
  SMOKE_S3_PASS="smoke-$(openssl rand -hex 16)"
fi

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  if [ "$SMOKE_FAILED" = "1" ] && [ "$KEEP_ON_FAIL" = "1" ]; then
    echo "KEEP_ON_FAIL=1 — leaving $C / $C_MINIO running (docker exec -it $C bash)."
    return
  fi
  if [ "$SMOKE_FAILED" = "0" ] && [ "$KEEP_ON_SUCCESS" = "1" ]; then
    echo "KEEP_ON_SUCCESS=1 — leaving $C / $C_MINIO running for later integration phases."
    return
  fi
  docker rm -f "$C_MINIO" "$C" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── 0. Preconditions ────────────────────────────────────────────────────────
say "Preconditions"
case "$SMOKE_PREFIX" in
  *[!a-z0-9_.-]* | '') die "SMOKE_PREFIX must contain only lowercase a-z, 0-9, dot, underscore, or hyphen" ;;
esac
[ "${#SMOKE_PREFIX}" -le 48 ] || die "SMOKE_PREFIX must be at most 48 characters"
case "$KEEP_ON_FAIL:$KEEP_ON_SUCCESS:$REBUILD_BASE:$PRELOAD_HOST_EGRESS:$REPLACE_EXISTING:$RESUME_PREINSTALL:$RESUME_INSTALL" in
  *[!01:]* | *::* | :* | *:) die "boolean overrides must be exactly 0 or 1" ;;
esac
[ "$RESUME_PREINSTALL:$RESUME_INSTALL" != "1:1" ] ||
  die "choose only one resume mode"
if [ -n "$SMOKE_IPV4" ] && [ -z "$SMOKE_NETWORK" ]; then
  die "SMOKE_IPV4 requires SMOKE_NETWORK"
fi
command -v docker >/dev/null 2>&1 || die "docker not found on this host"
docker info >/dev/null 2>&1 || die "docker daemon unreachable (add your user to the 'docker' group, no sudo needed for this script)"
container_exists=0
minio_exists=0
docker container inspect "$C" >/dev/null 2>&1 && container_exists=1
docker container inspect "$C_MINIO" >/dev/null 2>&1 && minio_exists=1
if [ "$container_exists" = "1" ] || [ "$minio_exists" = "1" ]; then
  if [ "$RESUME_PREINSTALL" = "1" ] || [ "$RESUME_INSTALL" = "1" ]; then
    [ "$container_exists:$minio_exists" = "1:1" ] ||
      die "resume requires both exact-name containers"
    [ "$(docker inspect -f '{{.State.Running}}' "$C")" = "true" ] ||
      die "resume requires a running $C"
    [ "$(docker inspect -f '{{.State.Running}}' "$C_MINIO")" = "true" ] ||
      die "resume requires a running $C_MINIO"
    if [ "$RESUME_PREINSTALL" = "1" ]; then
      if docker exec "$C" sh -c \
        'test -e /opt/setjoin/mailserverd || test -e /etc/systemd/system/setjoin.service'; then
        die "RESUME_PREINSTALL refuses a partially or fully installed environment"
      fi
    elif ! docker exec "$C" sh -c \
      'test -f /etc/setjoin/config.env && test -L /opt/setjoin/current && test -e /etc/systemd/system/setjoin.service'; then
      die "RESUME_INSTALL requires the exact install/config/unit boundary"
    fi
  elif [ "$REPLACE_EXISTING" != "1" ]; then
    die "container collision for $C or $C_MINIO (set REPLACE_EXISTING=1 only for these exact names)"
  else
    docker rm -f "$C_MINIO" "$C" >/dev/null 2>&1 || die "remove exact-name stale containers"
    container_exists=0
    minio_exists=0
  fi
fi
if [ -n "$SMOKE_NETWORK" ]; then
  docker network inspect "$SMOKE_NETWORK" >/dev/null 2>&1 ||
    die "SMOKE_NETWORK does not exist: $SMOKE_NETWORK"
fi

# ── 1. Base: systemd + Postgres 18 (+pgtap) + Valkey + Podman + Go + Node ──
# No COPY/ADD in this Dockerfile — the repo is bind-mounted at container-run
# time (below), so the base image build has no repo dependency and is cached
# across runs (only rebuilt when this script's embedded Dockerfile changes).
say "Base image ($IMG_TAG)"
if [ "$REBUILD_BASE" = "1" ] || ! docker image inspect "$IMG_TAG" >/dev/null 2>&1; then
  docker build -t "$IMG_TAG" - <<'DOCKERFILE' || die "base image build"
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv \
    curl ca-certificates gnupg lsb-release \
    build-essential git openssl \
  && rm -rf /var/lib/apt/lists/*
# PostgreSQL 18 via the PGDG apt repo (Ubuntu 24.04 "noble" default apt only
# ships PG16). postgresql-18 itself bundles pg_stat_statements/pg_trgm/
# pgcrypto (confirmed: no separate -contrib package needed for PG18 on PGDG —
# the generic "postgresql-contrib" meta-package actually pulls in PG16, which
# would be wrong here). pgtap is its own package: V001__baseline.sql does
# CREATE EXTENSION pgtap and fails without it.
RUN install -d /usr/share/postgresql-common/pgdg \
  && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" \
     > /etc/apt/sources.list.d/pgdg.list \
  && apt-get update && apt-get install -y --no-install-recommends \
       postgresql-18 postgresql-18-pgtap \
  && rm -rf /var/lib/apt/lists/*
# The real single-node installer requires both valkey-server and valkey-cli,
# plus a container runtime for the digest-pinned Egress sidecar. Podman is the
# documented daemonless preference for this privileged systemd container.
# Ubuntu 24.04 ships valkey-cli through valkey-tools, pulled by the
# valkey-server package (there is no package named merely "valkey").
# Keep both in the throwaway image so the smoke exercises the installer instead
# of stopping at missing host prerequisites.
RUN apt-get update && apt-get install -y --no-install-recommends valkey-server podman \
  && rm -rf /var/lib/apt/lists/*
# Nested-container storage pin (GA smoke only — real deployments are native
# hosts). Docker Desktop's containerd-snapshotter layout makes the container
# root itself a kernel overlayfs, so an overlayfs upperdir CANNOT be stacked
# inside ("filesystem on upperdir not supported"); podman silently falls back
# to fuse-overlayfs, and the linuxkit 7.x FUSE path returns EINVAL on execve
# of any binary on it — every nested container dies at entrypoint exec. Pin
# podman's store to vfs BEFORE it ever initializes (a fuse-initialized store
# then refuses driver changes). vfs copies layers (slower) but the smoke runs
# three small containers.
RUN mkdir -p /etc/containers \
  && printf '[storage]\ndriver = "vfs"\nrunroot = "/run/containers/storage"\ngraphroot = "/var/lib/containers/storage"\n' > /etc/containers/storage.conf
# Go (matches the retired .github/workflows/xinchuang-ci.yml (removed; see webmail.yml, rust-floor.yml)'s go-version). Arch-detected
# so the smoke also runs on arm64 Docker hosts (Apple-silicon dev boxes), not
# just the amd64 CI runner (dpkg arch names == Go tarball arch names here).
RUN curl -fsSL "https://go.dev/dl/go1.26.6.linux-$(dpkg --print-architecture).tar.gz" -o /tmp/go.tgz \
  && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
# Node (webmail build): 26.x matches the xinchuang-ci.yml webmail steps
# (actions/setup-node node-version: '26'). Older npm re-resolves transitive
# ranges (e.g. picomatch ^3 || ^4) differently and fails `npm ci` against the
# committed lock — keep the container's node in lockstep with CI.
RUN curl -fsSL https://deb.nodesource.com/setup_26.x | bash - \
  && apt-get install -y --no-install-recommends nodejs \
  && rm -rf /var/lib/apt/lists/*
# Nested Podman runs on Docker's overlayfs-backed filesystem in this smoke.
# fuse-overlayfs is the supported mount program for that overlay-on-overlay
# case; /dev/fuse is exposed by the privileged container. Podman's systemd
# cgroup manager also talks to the system bus, so this deliberately minimal
# systemd image must install dbus before it can launch the Egress container.
RUN apt-get update && apt-get install -y --no-install-recommends dbus fuse-overlayfs \
  && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE
else
  echo "reusing cached $IMG_TAG (set REBUILD_BASE=1 to force a rebuild)"
fi

# ── 2. Start the throwaway container (systemd, privileged) + blob store ────
say "Starting fresh throwaway container"
if [ "$RESUME_PREINSTALL" = "1" ] || [ "$RESUME_INSTALL" = "1" ]; then
  if [ "$RESUME_INSTALL" = "1" ]; then
    echo "RESUME_INSTALL=1 — reusing $C / $C_MINIO after an install/start-probe failure."
  else
    echo "RESUME_PREINSTALL=1 — reusing $C / $C_MINIO after a pre-install failure."
  fi
else
  run_args=(
    -d --name "$C"
    --privileged --cgroupns=host
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw
    --tmpfs /run --tmpfs /run/lock
    -v "$ROOT":/mnt/repo-src:ro
    -v ga-smoke-gomodcache:/root/go/pkg/mod
    -v ga-smoke-gobuildcache:/root/.cache/go-build
    -v ga-smoke-npmcache:/root/.npm
  )
  [ -n "$SMOKE_NETWORK" ] && run_args+=(--network "$SMOKE_NETWORK")
  [ -n "$SMOKE_IPV4" ] && run_args+=(--ip "$SMOKE_IPV4")
  [ -n "$SMOKE_DNS" ] && run_args+=(--dns "$SMOKE_DNS")
  [ -n "$SMOKE_HOSTNAME" ] && run_args+=(--hostname "$SMOKE_HOSTNAME")
  run_args+=("$IMG_TAG")
  docker run "${run_args[@]}" >/dev/null || die "container start"

  # Blob store: MinIO sharing the smoke container's network namespace, so it's
  # reachable at the installer's default S3_ENDPOINT (127.0.0.1:9000) with zero
  # config-file surgery. The gateway treats S3 as non-fatal at boot (G1 fix), so
  # this isn't required for /ready to pass — provided anyway per the task's
  # "provide the deps the installer needs".
  # Pinned by digest: MinIO's Docker Hub publishing now requires
  # authentication (2026-10-01), and the digest is the last multi-arch
  # manifest a CI host cached before that. Pull once per host and keep it; unpinned `latest` would
  # break every fresh runner the same way.
  #   minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e
  docker run -d --name "$C_MINIO" --network "container:$C" \
    -e MINIO_ROOT_USER="$SMOKE_S3_USER" -e MINIO_ROOT_PASSWORD="$SMOKE_S3_PASS" \
    minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e \
    server /data --console-address :9001 >/dev/null || die "minio sidecar start"
fi

say "Waiting for systemd to come up inside the container"
ok=0
for _ in $(seq 1 30); do
  docker exec "$C" test -d /run/systemd/system >/dev/null 2>&1 && {
    ok=1
    break
  }
  sleep 1
done
[ "$ok" = "1" ] || die "systemd did not come up in the container within 30s"

# ── 3. Stage an isolated copy of the repo INSIDE the container ─────────────
# Bind mount is read-only on purpose: everything the installer writes (build
# artifacts, /etc/setjoin, /opt/setjoin) stays inside the throwaway container,
# never leaking root-owned files back onto the host checkout.
say "Staging repo into the container"
# Drop .git from the in-container copy: Go 1.24+ stamps VCS info by default, and
# a repo whose .git is owned by the host runner user (CI checkout) but built as
# container-root trips git's dubious-ownership guard → `go build` fails with
# "error obtaining VCS status: exit status 128". A throwaway build copy needs no
# git history; removing it makes buildvcs=auto skip stamping. (Matches the manual
# rsync --exclude .git path that already passed.)
docker exec "$C" bash -c 'rm -rf /root/setjoin && cp -a /mnt/repo-src /root/setjoin && rm -rf /root/setjoin/.git' ||
  die "repo stage"

# The 4+ GB Egress image is reconstructible but expensive to pull repeatedly.
# When the Docker host already has the exact manifest-list digest selected for
# its architecture, stream that verified image into the nested Podman store.
# The installer still addresses it by digest and performs its normal presence
# check; a missing host cache simply falls back to the registry. This cache
# contains no configuration, credentials, or customer data.
if [ "$PRELOAD_HOST_EGRESS" = "1" ]; then
  EGRESS_IMAGE="$(
    # shellcheck disable=SC1091 # ROOT is resolved from this checked-out script.
    source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
    printf '%s' "$EGRESS_IMAGE"
  )"
  if docker image inspect "$EGRESS_IMAGE" >/dev/null 2>&1; then
    if docker exec "$C" podman image inspect "$EGRESS_IMAGE" >/dev/null 2>&1; then
      echo "exact-digest Egress image already present in nested Podman store."
    else
      say "Preloading exact-digest Egress image from Docker host cache"
      # podman >=5 loads a digest-saved archive UNNAMED (<none>:<none>), so the
      # by-digest inspect below would never resolve. Capture the loaded ID and
      # re-tag it to the Egress repository first.
      LOAD_OUT="$(docker save "$EGRESS_IMAGE" | docker exec -i "$C" podman load 2>&1 || true)"
      LOADED_ID="$(printf '%s' "$LOAD_OUT" | sed -n 's/^Loaded image: sha256://p' | tail -1)"
      [ -n "$LOADED_ID" ] || die "exact-digest Egress cache import (load output: $(printf '%s' "$LOAD_OUT" | tail -2))"
      EGRESS_REPO="${EGRESS_IMAGE%%@*}"
      docker exec "$C" podman tag "$LOADED_ID" "$EGRESS_REPO" ||
        die "exact-digest Egress cache import"
      if ! docker exec "$C" podman image inspect "$EGRESS_IMAGE" >/dev/null 2>&1; then
        die "imported Egress digest is not addressable in nested Podman (tagged $LOADED_ID as $EGRESS_REPO; nested store: $(docker exec "$C" podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | tr '\n' ' '))"
      fi
      echo "exact-digest Egress host cache imported."
    fi
  else
    echo "exact-digest Egress image is not cached on the Docker host; installer will pull it normally."
  fi
fi

# ── 4. INSTALL smoke: build → provision DB → install.sh → assert /ready ────
say "Install smoke"
docker exec -e RESUME_INSTALL="$RESUME_INSTALL" \
  -e SMOKE_S3_USER="$SMOKE_S3_USER" -e SMOKE_S3_PASS="$SMOKE_S3_PASS" \
  -i "$C" bash -s <<'INNER'
set -euo pipefail
cd /root/setjoin

echo ">> build mailserverd + authserverd"
bash scripts/build.sh

echo ">> build webmail"
( cd mailserver/webmail && npm ci --no-audit --no-fund && npm run build )

echo ">> start postgres, provision the password-authenticated 'mail' superuser role"
service postgresql start
su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='mail'\"" | grep -q 1 \
  || su postgres -c "createuser -s mail"
DB_OWNER_PASSWORD='Sm0keDbPassw0rd2026'
su postgres -c "psql -v ON_ERROR_STOP=1 -c \"ALTER ROLE mail PASSWORD '$DB_OWNER_PASSWORD'\"" >/dev/null
install -d -m 0755 /etc/setjoin
if [ "$RESUME_INSTALL" != "1" ]; then
  cat > /etc/setjoin/config.env <<EOF
DB_OWNER_DSN=postgres://mail:${DB_OWNER_PASSWORD}@127.0.0.1:5432/mailserver?sslmode=disable
DB_DIRECT_OWNER_DSN=postgres://mail:${DB_OWNER_PASSWORD}@127.0.0.1:5432/mailserver?sslmode=disable
S3_ACCESS_KEY=$SMOKE_S3_USER
S3_SECRET_KEY=$SMOKE_S3_PASS
EOF
  chmod 0600 /etc/setjoin/config.env
else
  # A resumed idempotent install must preserve every generated encryption and
  # signing secret. Replacing config.env with the two bootstrap DSNs here used
  # to rotate DB_ENCRYPTION_KEY underneath existing encrypted signing_keys.
  # Post-dsn-split, config.env no longer carries the privileged tiers: the
  # owner DSN lives in the credential file.
  grep -q '^DB_ENCRYPTION_KEY=' /etc/setjoin/config.env
  grep -q '^DB_DIRECT_OWNER_DSN=' /etc/setjoin/db-credentials.d/db-credentials.env
  echo ">> preserve existing config.env for install resume"
fi

echo ">> verify stock SCRAM loopback authentication as 'mail'"
PGPASSWORD="$DB_OWNER_PASSWORD" psql -h 127.0.0.1 -p 5432 -U mail -d postgres -tAc 'SELECT 1' >/dev/null

echo ">> run install.sh (NONINTERACTIVE, all defaults)"
export NONINTERACTIVE=1
export ADMIN_PASSWORD='Sm0ke-Test-Passw0rd!1'
# The disposable MinIO sidecar was started with the per-run generated
# credentials passed in via docker exec -e. config.env is the operative pin:
# the installer's gen_or_keep always overwrites these two keys from it (the
# ambient environment is not read), so the exports below are inert today —
# they document the three-site agreement and pin the values should install.sh
# ever honor ambient env.
export S3_ACCESS_KEY="$SMOKE_S3_USER"
export S3_SECRET_KEY="$SMOKE_S3_PASS"
bash mailserver/deploy/scripts/install.sh

echo ">> assert /ready — real HTTPS listener first, :80 fallback (never trust"
echo "   a bare :80 301 as healthy — the exact class the G1 upgrade.sh fix closed)"
ready=0
for _ in $(seq 1 15); do
  if curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null; then ready=1; echo "READY via https:443"; break; fi
  if curl -sf --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:80/ready 2>/dev/null | grep -q "^200$"; then ready=1; echo "READY via http:80 fallback"; break; fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "READY probe FAILED"
  systemctl status setjoin --no-pager || true
  journalctl -u setjoin --no-pager -n 100 || true
  exit 1
fi

echo ">> assert the constrained native-RLS DSN shape shipped (install default)"
# dsn-split contract (install.sh header): config.env carries only the
# app-tier surface; the privileged tiers live in db-credentials.d/ (0600,
# root only) and must not leak back into the runtime-account-readable file.
grep -q '^DB_DSN=postgres://setjoin_app:' /etc/setjoin/config.env
grep -q '^USE_EXTERNAL_IP=true$'          /etc/setjoin/config.env
! grep -qE '^DB_(WORKER|OWNER|DIRECT_OWNER)_DSN=' /etc/setjoin/config.env
CRED_ENV=/etc/setjoin/db-credentials.d/db-credentials.env
[ -f "$CRED_ENV" ]
grep -q '^DB_WORKER_DSN=postgres://setjoin_worker:' "$CRED_ENV"
grep -q '^DB_OWNER_DSN='                            "$CRED_ENV"
grep -q '^DB_DIRECT_OWNER_DSN='                     "$CRED_ENV"
echo "constrained DSN shape: OK"

echo ">> assert first-boot authority + Guest invitation public origin"
source /etc/setjoin/config.env
source "$CRED_ENV"
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "
  SELECT count(*) = 1
    FROM admin_role_assignments ara
    JOIN admin_role_groups arg ON arg.id=ara.role_group_id
    JOIN users u ON u.id=ara.user_id
   WHERE u.email='admin@example.com'
     AND arg.name='Super Admin'
     AND 'system.config'=ANY(arg.permissions)
" | grep -qx t
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "
  SELECT value #>> '{}'
    FROM system_config
   WHERE key='authserver.public_url'
" | grep -qx 'https://mail.example.com'
echo "bootstrap authority + Guest public origin: OK"

echo ">> assert setjoin-auth is running + a REAL login round-trip through the"
echo "   gateway (POST /auth/login with the installer-seeded admin). This is the"
echo "   assertion that was missing when the 2026-07-06 real deploy shipped with"
echo "   a dead login path and a green /ready-only smoke."
systemctl is-active setjoin-auth
# Success = the auth round-trip completed with VERIFIED credentials: either a
# token was issued, or the fresh-install default MFA policy answered
# mfa_enrollment_required (feature.require_mfa=true + mfa_enforcement_mode=
# required in the baseline; authserver only emits that status AFTER the
# password verified — a wrong password is a plain 401, a dead auth upstream
# is a 502, and neither matches).
login_ok=0
for _ in $(seq 1 10); do
  login_resp="$(curl -sk --max-time 10 -X POST https://127.0.0.1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@example.com","password":"Sm0ke-Test-Passw0rd!1"}')" || true
  if printf '%s' "$login_resp" | grep -Eq '"access_token":"|"status":"mfa_enrollment_required"'; then login_ok=1; break; fi
  sleep 2
done
if [ "$login_ok" != "1" ]; then
  echo "LOGIN round-trip FAILED — last response: ${login_resp:-<empty>}"
  systemctl status setjoin-auth --no-pager || true
  journalctl -u setjoin-auth --no-pager -n 100 || true
  journalctl -u setjoin --no-pager -n 50 || true
  exit 1
fi
echo "LOGIN round-trip: OK — credentials verified through gateway → authserver"
echo "   (token issued, or default MFA policy demanded enrollment: $(printf '%s' "$login_resp" | head -c 120))"
echo "INSTALL_SMOKE_PASS"
INNER
rc=$?
[ "$rc" -eq 0 ] || die "install smoke (build / DB provision / install.sh / ready-probe / auth login round-trip)"

# ── 5. UPGRADE smoke: rebuild → upgrade.sh → assert /ready ──────────────────
say "Upgrade smoke"
docker exec -i "$C" bash -s <<'INNER'
set -euo pipefail
cd /root/setjoin

echo ">> build a fresh mailserverd + mailctl (same commit — see header's honest scope note)"
( cd mailserver && CGO_ENABLED=0 go build -o /tmp/mailserverd.new -ldflags="-s -w" ./cmd/mailserverd )
( cd mailctl && CGO_ENABLED=0 go build -o /tmp/mailctl.new . )

echo ">> run upgrade.sh"
if [ -L /opt/setjoin/current ]; then
  before="$(readlink /opt/setjoin/current)"
  if output="$(bash mailserver/deploy/scripts/upgrade.sh /tmp/mailserverd.new /tmp/mailctl.new \
      /root/setjoin/mailserver/webmail/build 2>&1)"; then
    echo "IMMUTABLE_LAYOUT_FAIL — retired positional upgrade unexpectedly succeeded"
    exit 1
  fi
  printf '%s\n' "$output" | grep -Fq 'transactional immutable layout' || {
    echo "IMMUTABLE_LAYOUT_FAIL — refusal did not name the transactional immutable layout"
    exit 1
  }
  [ "$(readlink /opt/setjoin/current)" = "$before" ] || {
    echo "IMMUTABLE_LAYOUT_FAIL — rejected legacy upgrade changed current"
    exit 1
  }
  printf '%s\n' "$before" > /tmp/setjoin-immutable-current
  echo "Retired positional upgrade refused without changing current: OK"
else
bash mailserver/deploy/scripts/upgrade.sh /tmp/mailserverd.new /tmp/mailctl.new \
  /root/setjoin/mailserver/webmail/build
fi

echo ">> assert /ready after upgrade"
ready=0
for _ in $(seq 1 15); do
  if curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null; then ready=1; echo "READY via https:443"; break; fi
  if curl -sf --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:80/ready 2>/dev/null | grep -q "^200$"; then ready=1; echo "READY via http:80 fallback"; break; fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "READY probe FAILED after upgrade"
  systemctl status setjoin --no-pager || true
  journalctl -u setjoin --no-pager -n 100 || true
  exit 1
fi
echo "UPGRADE_SMOKE_PASS"
INNER
rc=$?
[ "$rc" -eq 0 ] || die "upgrade smoke (rebuild / upgrade.sh / ready-probe)"

# ── 6. ROLLBACK exercise: force upgrade.sh's failure path for real ─────────
say "Rollback exercise"
if docker exec "$C" test -L /opt/setjoin/current; then
  docker exec -i "$C" bash -s <<'INNER'
set -euo pipefail
test "$(readlink /opt/setjoin/current)" = "$(cat /tmp/setjoin-immutable-current)"
systemctl is-active setjoin-auth setjoin
curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null
echo "IMMUTABLE_ROLLBACK_DEFERRED_PASS — legacy mutation is fenced; signed success/rollback is exercised by transactional-updater-rehearsal.sh"
INNER
  rc=$?
  [ "$rc" -eq 0 ] || die "immutable-layout legacy fence / ready-probe"
else
  docker exec -i "$C" bash -s <<'INNER'
set -euo pipefail
cd /root/setjoin

echo ">> install a deliberately broken 'new binary' (exits 1 immediately)"
printf '#!/bin/sh\nexit 1\n' > /tmp/mailserverd.broken
chmod +x /tmp/mailserverd.broken
rm -rf /tmp/webmail.broken
cp -a /root/setjoin/mailserver/webmail/build /tmp/webmail.broken
printf 'must-be-rolled-back\n' > /tmp/webmail.broken/rollback-probe.txt

echo ">> run upgrade.sh with the broken binary — it MUST fail and roll back"
if bash mailserver/deploy/scripts/upgrade.sh /tmp/mailserverd.broken "" /tmp/webmail.broken; then
  echo "ROLLBACK_EXERCISE_FAIL — upgrade.sh reported success with a broken binary (should have failed + rolled back)"
  exit 1
fi
echo "upgrade.sh correctly reported failure (non-zero exit) on the broken binary."

echo ">> assert the service is healthy again on the ROLLED-BACK (previous, working) binary"
ready=0
for _ in $(seq 1 15); do
  if curl -skf --max-time 3 https://127.0.0.1/ready >/dev/null; then ready=1; echo "READY via https:443 (post-rollback)"; break; fi
  if curl -sf --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:80/ready 2>/dev/null | grep -q "^200$"; then ready=1; echo "READY via http:80 fallback (post-rollback)"; break; fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "READY probe FAILED after rollback — service did not recover"
  systemctl status setjoin --no-pager || true
  journalctl -u setjoin --no-pager -n 100 || true
  exit 1
fi
[ -f /opt/setjoin/mailserverd.prev ] && echo "rollback artifact present: /opt/setjoin/mailserverd.prev"
[ ! -e /opt/setjoin/webmail/rollback-probe.txt ] ||
  { echo "ROLLBACK_EXERCISE_FAIL — broken Webmail build survived rollback"; exit 1; }
echo "webmail rollback: OK"
echo "ROLLBACK_SMOKE_PASS"
INNER
  rc=$?
  [ "$rc" -eq 0 ] || die "rollback exercise (broken-binary upgrade / rollback / post-rollback ready-probe)"
fi

say "RESULT: PASS"
echo "Install (incl. a real admin login through the gateway → authserver, on the"
echo "constrained native-RLS DSN shape) and the applicable upgrade boundary asserted healthy."
echo "Immutable installs prove the retired positional path is fenced here; the signed"
echo "success and rollback mutations run in transactional-updater-rehearsal.sh."
echo "Coverage ceiling: same-commit upgrade only (no cross-schema-version migration"
echo "exercised); privileged container, not a real VM — see this script's header."
exit 0
