#!/usr/bin/env bash
# lib-livekit.sh — Meet B1 Task 14: provisions the setjoin-sfu (LiveKit)
# sidecar. Sourced by install.sh; also sourced standalone by
# test-livekit-render.sh so the render logic gets a real test without
# invoking the whole (root-only) installer.
#
# Two functions:
#   install_livekit_binary DEST  — download+checksum-verify+chmod the pinned
#     livekit-server v1.13.5 release binary (spike §6.1/§6.2). Re-run safe.
#   render_livekit_yaml TEMPLATE OUTFILE — substitute the {{NAME}}/
#     {{NAME|default}} tokens in livekit.yaml.template, gating turn.enabled
#     on the TURN cert pair's presence on disk (eng BLOCKER #1: LiveKit
#     refuses to start TURN/TLS without both PEMs — a missing pair must
#     degrade to no-TURN, never no-SFU).
#
# Callers set HOSTNAME / LIVEKIT_API_SECRET / VALKEY_PASSWORD (required) and
# may set RTC_PORT_START / RTC_PORT_END / USE_EXTERNAL_IP / TURN_CERT /
# TURN_KEY (all optional, template-defaulted) as plain shell variables
# before calling render_livekit_yaml.
#
# Meet B2 adds three more functions (Task 9, D7/§3.3):
#   detect_container_runtime — podman first, docker fallback; called ONCE at
#     install time and baked into the setjoin-egress unit — no runtime
#     autodetect at service start.
#   render_egress_yaml TEMPLATE OUTFILE — same {{NAME}} substitution genre
#     for egress.yaml.template.
#   render_egress_unit TEMPLATE OUTFILE — same genre for
#     setjoin-egress.service.template (a rendered unit, not sed-rewritten
#     like the Go units — the container binary path + image ref are
#     install-time facts).
#   provision_valkey_conf OUTFILE — writes the loopback-only, no-persistence
#     Valkey config (law 3: same password as livekit.yaml/egress.yaml).
#
# Meet B3 (Task 16) adds four more functions for the OPTIONAL captions
# sidecar pair (setjoin-asr-bot + setjoin-funasr — unlike the SFU/Valkey/
# Egress trio above, gated behind install.sh's MEET_CAPTIONS_ENABLED
# prompt, not installed unconditionally):
#   render_asrbot_unit / render_funasr_unit — the render_egress_unit genre
#     for the two new units.
#   render_asrbot_env TEMPLATE OUTFILE — the render_egress_yaml genre for
#     asrbot.env.template; requires ASR_TOKEN (the control-API bearer
#     secret, B3 Task 18 pipeline-review finding 1) and additionally refuses
#     a non-loopback ASR_LISTEN.
#   install_funasr_models DEST — download+sha256-verify the pinned FunASR
#     streaming-model weight files, the install_livekit_binary discipline.
# See each function's own comment for the honesty-ledger scope note (only
# ONE model is pinned by this task — the plan's own naming).
#
# Arch review #A11 (2026-07-16): converges the remaining 4 native/static
# units (mailserver, authserver, setjoin-sfu, setjoin-valkey) onto this SAME
# tested {{TOKEN}} seam, replacing install.sh's bespoke `sed` rewrites (0
# tests, fail-OPEN on a stale pattern — a sed that stops matching silently
# installs a wrong-user/wrong-path unit) — plus the asr-bot two-pass hybrid
# (render, THEN a separate User/Group sed pass), now a single render call
# like every other unit:
#   render_mailserver_unit / render_authserver_unit / render_sfu_unit /
#     render_valkey_unit — the render_egress_unit genre for
#     mailserver.service.template / authserver.service.template /
#     setjoin-sfu.service.template / setjoin-valkey.service.template.
# This file is no longer LiveKit-specific — it is the general deploy-unit
# render library (kept as lib-livekit.sh; renaming would be a large-blast-
# radius change for a comment-only motivation).

LIVEKIT_VERSION="1.13.5"
# Hard-coded SHA-256 digests published for the official v1.13.5 GitHub release
# assets (verified through the release API on 2026-08-04). Never trust a
# runtime-fetched checksums
# file for this — that would just move the trust root to whatever served it.
LIVEKIT_SHA256_AMD64="c020fac437b7cc9b776eef1ad5ea8af77be9acfa07602eca20a3a44930dfbc70"
LIVEKIT_SHA256_ARM64="332015305518765fe05bad74fc3a9d9583e635e7dd130de3c4fc563d69c550f3"

# _lk_say — falls back to plain echo if the caller (install.sh) hasn't
# defined its own `info`/`die` helpers (e.g. when this file is sourced
# standalone by the test script).
if ! declare -F info >/dev/null 2>&1; then info() { printf '    %s\n' "$1"; }; fi
if ! command -v die  >/dev/null 2>&1; then die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }; fi

# install_livekit_binary DEST — download the pinned linux amd64/arm64
# livekit-server release binary to DEST, sha256-verifying the archive before
# extraction, chmod 0755. Skips the download entirely on a re-run once a
# version stamp file (DEST's dir + .livekit-server-version) already matches
# — the published checksum covers the release TARBALL, not the extracted
# binary, so re-hashing the installed binary against it would never match;
# the stamp is the correct (and simpler) idempotency check.
install_livekit_binary() {
  local dest="$1" stamp
  stamp="$(dirname "$dest")/.livekit-server-version"
  if [ -x "$dest" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$LIVEKIT_VERSION" ]; then
    info "livekit-server $LIVEKIT_VERSION already installed at $dest — skipping download."
    return 0
  fi

  local arch sha256
  case "$(uname -m)" in
    x86_64|amd64)   arch="amd64"; sha256="$LIVEKIT_SHA256_AMD64" ;;
    aarch64|arm64)  arch="arm64"; sha256="$LIVEKIT_SHA256_ARM64" ;;
    *) die "unsupported CPU architecture for the LiveKit SFU binary: $(uname -m) (supported: x86_64/amd64, aarch64/arm64)" ;;
  esac

  local tarball="livekit_${LIVEKIT_VERSION}_linux_${arch}.tar.gz"
  local url="https://github.com/livekit/livekit/releases/download/v${LIVEKIT_VERSION}/${tarball}"
  local tmp; tmp="$(mktemp -d)"
  info "Downloading livekit-server $LIVEKIT_VERSION ($arch)…"
  if ! curl -fsSL -o "$tmp/$tarball" "$url"; then
    rm -rf "$tmp"
    die "failed to download $url — check network access, or pre-place the binary at $dest and its version at $stamp."
  fi

  local got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$tarball" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$tmp/$tarball" | cut -d' ' -f1)"
  fi
  if [ "$got" != "$sha256" ]; then
    rm -rf "$tmp"
    die "livekit-server checksum mismatch: expected $sha256, got $got — refusing to install a tampered or corrupt binary. Re-download and retry."
  fi

  tar -xzf "$tmp/$tarball" -C "$tmp" livekit-server
  mkdir -p "$(dirname "$dest")"
  install -m 0755 "$tmp/livekit-server" "$dest"
  echo "$LIVEKIT_VERSION" > "$stamp"
  rm -rf "$tmp"
  info "Installed livekit-server $LIVEKIT_VERSION to $dest (sha256 verified)."
}

# render_livekit_yaml TEMPLATE OUTFILE — substitute placeholders and write
# OUTFILE. Reads HOSTNAME / LIVEKIT_API_SECRET (required — fails loud if
# either is unset) and RTC_PORT_START / RTC_PORT_END / USE_EXTERNAL_IP /
# TURN_CERT / TURN_KEY (optional) from the environment.
render_livekit_yaml() {
  local template="$1" outfile="$2"
  [ -n "${HOSTNAME:-}" ] || { echo "render_livekit_yaml: HOSTNAME is required" >&2; return 1; }
  [ -n "${LIVEKIT_API_SECRET:-}" ] || { echo "render_livekit_yaml: LIVEKIT_API_SECRET is required" >&2; return 1; }
  # Meet B2 (Task 9): the SFU joins the Valkey bus unconditionally (the redis:
  # block ships in the template from birth — D7/§3.3) so VALKEY_PASSWORD is a
  # required var here too, same fail-loud posture as LIVEKIT_API_SECRET.
  [ -n "${VALKEY_PASSWORD:-}" ] || { echo "render_livekit_yaml: VALKEY_PASSWORD is required" >&2; return 1; }

  local rtc_start="${RTC_PORT_START:-50000}"
  local rtc_end="${RTC_PORT_END:-60000}"
  local ext_ip="${USE_EXTERNAL_IP:-true}"
  local turn_cert="${TURN_CERT:-/etc/setjoin/certs/fullchain.pem}"
  local turn_key="${TURN_KEY:-/etc/setjoin/certs/privkey.pem}"

  # TURN is enabled ONLY when both PEMs already exist on disk — never
  # hand-set. LiveKit hard-crashes on turn.enabled:true with a missing/bad
  # cert (eng BLOCKER #1); this degrades to no-TURN instead of no-SFU.
  local turn_enabled="false"
  if [ -f "$turn_cert" ] && [ -f "$turn_key" ]; then
    turn_enabled="true"
  else
    info "TURN disabled — no cert at $turn_cert (or key at $turn_key). NAT'd remote guests lose the TURN fallback rung; direct UDP and ICE/TCP still work. Provision a cert for turn.$HOSTNAME to enable it (docs/guides/SINGLE_NODE_SETUP.md)."
  fi

  sed \
    -e "s#{{RTC_PORT_START|50000}}#${rtc_start}#" \
    -e "s#{{RTC_PORT_END|60000}}#${rtc_end}#" \
    -e "s#{{USE_EXTERNAL_IP|true}}#${ext_ip}#" \
    -e "s#{{LIVEKIT_API_SECRET}}#${LIVEKIT_API_SECRET}#" \
    -e "s#{{VALKEY_PASSWORD}}#${VALKEY_PASSWORD}#" \
    -e "s#{{HOSTNAME}}#${HOSTNAME}#g" \
    -e "s#{{TURN_ENABLED}}#${turn_enabled}#" \
    -e "s#{{TURN_CERT|/etc/setjoin/certs/fullchain.pem}}#${turn_cert}#" \
    -e "s#{{TURN_KEY|/etc/setjoin/certs/privkey.pem}}#${turn_key}#" \
    "$template" > "$outfile"

  # A stale/renamed placeholder must fail the install loudly, not ship a
  # broken config with a literal "{{...}}" baked in (sed silently no-ops on
  # a non-matching pattern — this is the backstop).
  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_livekit_yaml: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# Meet B2: the pinned egress container (pairs with server v1.13.5). The
# manifest-list digest was fetched from Docker Hub 2026-07-15 and is the
# trust root — the tag alone is mutable, the digest is not (the SFU-binary
# checksum posture, container edition).
EGRESS_IMAGE="docker.io/livekit/egress:v1.13.0@sha256:980ff439431df2c773573721ab6da19e15bdc1f049ab7cb80e87470bf174c12f"

# detect_container_runtime — podman first (packaged in every 信创/EL distro we
# target, daemonless), docker fallback; echoes the binary path or fails loud.
# Detected ONCE at install time and baked into the unit — no runtime
# autodetect at service start (spec §3.3).
detect_container_runtime() {
  if command -v podman >/dev/null 2>&1; then command -v podman; return 0; fi
  if command -v docker >/dev/null 2>&1; then command -v docker; return 0; fi
  die "no container runtime found (podman or docker) — required for the Meet Egress recording sidecar. Install podman, or re-run after 'dnf/apt install podman'."
}

# render_egress_yaml TEMPLATE OUTFILE — substitute placeholders in
# egress.yaml.template. Reads LIVEKIT_API_SECRET / VALKEY_PASSWORD (required
# — fails loud if either is unset) and EGRESS_ROOM_COMPOSITE_CPU_COST
# (optional) from the environment.
render_egress_yaml() {
  local template="$1" outfile="$2"
  [ -n "${LIVEKIT_API_SECRET:-}" ] || { echo "render_egress_yaml: LIVEKIT_API_SECRET is required" >&2; return 1; }
  [ -n "${VALKEY_PASSWORD:-}" ] || { echo "render_egress_yaml: VALKEY_PASSWORD is required" >&2; return 1; }

  local cpu_cost="${EGRESS_ROOM_COMPOSITE_CPU_COST:-3}"

  sed \
    -e "s#{{VALKEY_PASSWORD}}#${VALKEY_PASSWORD}#" \
    -e "s#{{LIVEKIT_API_SECRET}}#${LIVEKIT_API_SECRET}#" \
    -e "s#{{EGRESS_ROOM_COMPOSITE_CPU_COST|3}}#${cpu_cost}#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_egress_yaml: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_egress_unit TEMPLATE OUTFILE — substitute placeholders in
# setjoin-egress.service.template. Reads CONTAINER_BIN (required) and
# EGRESS_CPUQUOTA (optional) from the environment. EGRESS_IMAGE is this
# file's own pinned constant, never overridable from the environment.
render_egress_unit() {
  local template="$1" outfile="$2"
  [ -n "${CONTAINER_BIN:-}" ] || { echo "render_egress_unit: CONTAINER_BIN is required" >&2; return 1; }

  local cpuquota="${EGRESS_CPUQUOTA:-400%}"

  sed \
    -e "s#{{CONTAINER_BIN}}#${CONTAINER_BIN}#g" \
    -e "s#{{EGRESS_IMAGE}}#${EGRESS_IMAGE}#" \
    -e "s#{{EGRESS_CPUQUOTA|400%}}#${cpuquota}#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_egress_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# Arch review #A11: the four remaining native/static units, converged onto
# this same render seam. All four run as the fixed "setjoin" runtime
# account — no install-time knob has ever existed to change it (the old sed
# blocks hardcoded `User=setjoin`/`Group=setjoin` too) — so USER/GROUP are
# NOT read from the environment here (a bare `${USER:-setjoin}` would
# silently pick up the ambient shell USER var, e.g. "root" under sudo — a
# real footgun avoided by never reading it). The {{USER|setjoin}}/
# {{GROUP|setjoin}} tokens exist in the templates so a future override is a
# one-line sed change, not a template rewrite.

# render_mailserver_unit TEMPLATE OUTFILE — substitute placeholders in
# mailserver.service.template. Reads INSTALL_DIR / DATA_DIR / CONFIG_ENV /
# DB_CREDENTIALS_FILE (the privileged-DB-tier EnvironmentFile, DEPLOY-004);
# RUNTIME_DIR defaults to INSTALL_DIR/current.
# (all required — fail loud if unset, same posture as every other render_*
# function here).
render_mailserver_unit() {
  local template="$1" outfile="$2"
  [ -n "${INSTALL_DIR:-}" ] || { echo "render_mailserver_unit: INSTALL_DIR is required" >&2; return 1; }
  [ -n "${DATA_DIR:-}" ] || { echo "render_mailserver_unit: DATA_DIR is required" >&2; return 1; }
  [ -n "${CONFIG_ENV:-}" ] || { echo "render_mailserver_unit: CONFIG_ENV is required" >&2; return 1; }
  # Privileged DB credential file (DEPLOY-004 split) — required: an empty
  # substitution would render "EnvironmentFile=" (a systemd parse error at
  # boot) instead of failing the render loud.
  [ -n "${DB_CREDENTIALS_FILE:-}" ] || { echo "render_mailserver_unit: DB_CREDENTIALS_FILE is required" >&2; return 1; }

  local runtime_dir="${RUNTIME_DIR:-${INSTALL_DIR}/current}"

  sed \
    -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" \
    -e "s#{{DATA_DIR}}#${DATA_DIR}#g" \
    -e "s#{{CONFIG_ENV}}#${CONFIG_ENV}#g" \
    -e "s#{{DB_CREDENTIALS_FILE}}#${DB_CREDENTIALS_FILE}#g" \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_mailserver_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_gateway_unit TEMPLATE OUTFILE — the Rust front door (#264, ARCH-027).
# Renders setjoin-gateway.service.template to OUTFILE and its sibling
# setjoin-gateway.socket.template beside it (same directory, .socket), so the
# compiled catalog keeps one row per service. Reads INSTALL_DIR and
# GATEWAY_ENV (required); GATEWAY_LISTEN defaults to 127.0.0.1:8090 and must
# be loopback: the gateway is plaintext and sits behind the TLS terminator.
render_gateway_unit() {
  local template="$1" outfile="$2"
  [ -n "${INSTALL_DIR:-}" ] || { echo "render_gateway_unit: INSTALL_DIR is required" >&2; return 1; }
  [ -n "${GATEWAY_ENV:-}" ] || { echo "render_gateway_unit: GATEWAY_ENV is required" >&2; return 1; }
  local runtime_dir="${RUNTIME_DIR:-${INSTALL_DIR}/current}"
  local listen="${GATEWAY_LISTEN:-127.0.0.1:8090}"
  case "$listen" in
    127.*:[0-9]*|\[::1\]:[0-9]*) ;;
    *) echo "render_gateway_unit: GATEWAY_LISTEN must be a loopback host:port (got '$listen') — the plaintext front door sits behind the TLS terminator" >&2; return 1 ;;
  esac
  local socket_template="${template%.service.template}.socket.template"
  local socket_outfile="${outfile%.service}.socket"
  [ -f "$socket_template" ] || { echo "render_gateway_unit: missing $socket_template" >&2; return 1; }
  local pair
  for pair in "$template:$outfile" "$socket_template:$socket_outfile"; do
    sed \
      -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" \
      -e "s#{{GATEWAY_ENV}}#${GATEWAY_ENV}#g" \
      -e "s#{{TLS_ENV}}#${TLS_ENV:-${GATEWAY_ENV%/*}/tls.env}#g" \
      -e "s#{{FEDERATION_ENV}}#${FEDERATION_ENV:-${GATEWAY_ENV%/*}/federation.env}#g" \
      -e "s#{{SMTP_ENV}}#${SMTP_ENV:-${GATEWAY_ENV%/*}/smtp.env}#g" \
      -e "s#{{GATEWAY_LISTEN}}#${listen}#g" \
      -e "s#{{USER|setjoin}}#setjoin#" \
      -e "s#{{GROUP|setjoin}}#setjoin#" \
      "${pair%%:*}" > "${pair#*:}"
    if grep -q '{{' "${pair#*:}"; then
      rm -f "$outfile" "$socket_outfile"
      echo "render_gateway_unit: unresolved {{...}} placeholder(s) remain in ${pair#*:} — template/render drift, refusing to write a broken config" >&2
      return 1
    fi
  done
  if tls_front_enabled "${CONFIG_ENV:-}" && [[ ",$(tls_front_value "$CONFIG_ENV" RUST_WORKERS_ON)," == *,http-tls,* ]]; then
    local https_listen="${GATEWAY_HTTPS_LISTEN:-$(tls_front_value "$CONFIG_ENV" GATEWAY_HTTPS_LISTEN)}"
    https_listen="${https_listen:-443}"
    https_listen="${https_listen#:}"
    case "$https_listen" in *[!a-zA-Z0-9.:\[\]-]*|'') echo 'invalid HTTPS listen address' >&2; return 1;; esac
    sed -e "s#{{HTTPS_LISTEN}}#${https_listen}#g" "${template%/*}/setjoin-https.socket.template" > "${outfile%/*}/setjoin-https.socket"
    cat >> "$outfile" <<'TLS'

[Unit]
Wants=setjoin-https.socket
After=setjoin-https.socket

[Install]
Also=setjoin-https.socket
TLS
    if [ -n "$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_DOMAINS)" ]; then
      local cache key_file
      cache=$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_CACHE_DIR)
      cache="${cache:-/var/cache/mailserver/autocert}"
      key_file=$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_KEY_FILE)
      case "$cache" in /*) ;; *) echo 'ACME cache must be absolute' >&2; return 1;; esac
      case "$cache" in *[[:space:]#\&]*) echo 'invalid ACME cache path' >&2; return 1;; esac
      printf '\n[Service]\nReadWritePaths=-%s\n' "$cache" >> "$outfile"
      if [ -n "$key_file" ]; then
        case "$key_file" in /*) ;; *) echo 'ACME account key must be absolute' >&2; return 1;; esac
        case "$key_file" in *[[:space:]#\&]*) echo 'invalid ACME account key path' >&2; return 1;; esac
        printf 'ReadWritePaths=-%s\n' "${key_file%/*}" >> "$outfile"
      fi
      if [ "$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_CHALLENGE)" = http-01 ]; then
        case "$(tls_front_value "$CONFIG_ENV" HTTP_MODE)" in ''|redirect)
          cp "${template%/*}/setjoin-acme.socket.template" "${outfile%/*}/setjoin-acme.socket"
          cat >> "$outfile" <<'ACME'

[Unit]
Wants=setjoin-acme.socket
After=setjoin-acme.socket

[Install]
Also=setjoin-acme.socket
ACME
        esac
      fi
    fi
  fi
  # The shared threat gate qualifies the complete IMAP listener (#420).
  if imap_front_enabled "${CONFIG_ENV:-}"; then
    local imap_kind imap_key imap_default imap_listen
    for imap_kind in imap imaps; do
      imap_key=IMAP_ADDR; imap_default=:143
      if [ "$imap_kind" = imaps ]; then imap_key=IMAP_TLS_ADDR; imap_default=:993; fi
      imap_listen=$(imap_front_listen "$CONFIG_ENV" "$imap_key" "$imap_default")
      [ -n "$imap_listen" ] || continue
      imap_listen="${imap_listen#:}"
      case "$imap_listen" in *[!a-zA-Z0-9.:\[\]-]*|'') echo 'invalid IMAP listen address' >&2; return 1;; esac
      sed -e "s#{{IMAP_LISTEN}}#${imap_listen}#g" "${template%/*}/setjoin-$imap_kind.socket.template" > "${outfile%/*}/setjoin-$imap_kind.socket"
      printf '\n[Unit]\nWants=setjoin-%s.socket\nAfter=setjoin-%s.socket\n\n[Install]\nAlso=setjoin-%s.socket\n' "$imap_kind" "$imap_kind" "$imap_kind" >> "$outfile"
    done
  fi
  # SMTP moves whole (#501): inbound :25, the implicit-TLS variant and
  # submission, each a named systemd socket. The gateway only Wants= them, so an
  # SMTP socket problem can never take the HTTPS front door down.
  if smtp_front_enabled "${CONFIG_ENV:-}"; then
    local smtp_kind smtp_key smtp_default smtp_listen
    for smtp_kind in smtp smtps submission; do
      case "$smtp_kind" in
        smtp) smtp_key=SMTP_INBOUND_ADDR; smtp_default=:25 ;;
        smtps) smtp_key=SMTP_INBOUND_TLS_ADDR; smtp_default= ;;
        submission) smtp_key=SMTP_SUBMISSION_ADDR; smtp_default=:587 ;;
      esac
      smtp_listen=$(smtp_front_listen "$CONFIG_ENV" "$smtp_key" "$smtp_default")
      [ -n "$smtp_listen" ] || continue
      smtp_listen="${smtp_listen#:}"
      case "$smtp_listen" in *[!a-zA-Z0-9.:\[\]-]*|'') echo 'invalid SMTP listen address' >&2; return 1;; esac
      sed -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" -e "s#{{SMTP_LISTEN}}#${smtp_listen}#g" "${template%/*}/setjoin-$smtp_kind.socket.template" > "${outfile%/*}/setjoin-$smtp_kind.socket"
      printf '\n[Unit]\nWants=setjoin-%s.socket\nAfter=setjoin-%s.socket\n\n[Install]\nAlso=setjoin-%s.socket\n' "$smtp_kind" "$smtp_kind" "$smtp_kind" >> "$outfile"
    done
  fi
  # A configured federation leg moves whole, using an additional named socket.
  if [ "${FEDERATION_ENABLED:-false}" = true ]; then
    local fed_template="${template%/*}/setjoin-federation.socket.template"
    local fed_out="${outfile%/*}/setjoin-federation.socket"
    local fed_listen="${FEDERATION_LISTEN_ADDR:-:7443}"
    fed_listen="${fed_listen#:}"
    case "$fed_listen" in *$'\n'*|*'#'*|*'&'*) echo 'invalid federation listen address' >&2; return 1;; esac
    sed -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" -e "s#{{FEDERATION_LISTEN}}#${fed_listen}#g" "$fed_template" > "$fed_out"
    cat >> "$outfile" <<'FED'

[Unit]
Wants=setjoin-federation.socket
After=setjoin-federation.socket

[Install]
Also=setjoin-federation.socket
FED
  fi
}

# render_federation_env OUTFILE CONFIG_ENV DB_CRED_FILE — a strict allowlist.
# Copy literal EnvironmentFile assignments, never source the broad secret files.
# Owner DSNs and unrelated worker switches must never reach the front door.
render_federation_env() {
  local outfile="$1" config="$2" credentials="$3" tmp key names allowed
  tmp="$(mktemp "${outfile}.XXXXXX")" || return 1
  (
    umask 027
    if [ -f "$config" ]; then
      grep -E '^(DB_DSN|DB_DIRECT_DSN|FEDERATION_LOCAL_DOMAIN|FEDERATION_CERT|FEDERATION_KEY|FEDERATION_LISTEN_ADDR)=' "$config" || true
    fi
    if [ -f "$credentials" ]; then
      grep -E '^DB_WORKER_DSN=' "$credentials" || true
    elif [ -f "$config" ]; then
      # Pre-split installations still carry the worker tier in config.env.
      grep -E '^DB_WORKER_DSN=' "$config" || true
    fi
    for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
      allowed='^(federation-residue-reap|cert-monitor|tls-ticket-keys|http-tls|http-h2c|acme-renewal)$'
      if [ "$key" = GO_WORKERS_OFF ]; then allowed='^(federation-(service|residue-reap)|cert-monitor|tls-ticket-keys|http-tls|http-h2c|acme-renewal|http-port80)$'; fi
      names="$(sed -n "s/^$key=//p" "$config" | tail -1 | tr ',' '\n' |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
        grep -E "$allowed" | paste -sd, - || true)"
      printf '%s=%s\n' "$key" "$names"
    done
  ) > "$tmp"
  chmod 0640 "$tmp"
  mv -f "$tmp" "$outfile"
}

# config_env_value FILE KEY — the last KEY=value line, unquoted like systemd's
# EnvironmentFile (one pair of matching quotes, trailing blanks of an unquoted value).
config_env_value() {
  [ -f "$1" ] || return 0
  grep -E "^$2=" "$1" | tail -1 | sed -e "s/^$2=//" -e 's/[[:space:]]*$//' \
    -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# link_protect_key SECRET VERSION — Go linkprotect.tokenKeyN, byte for byte:
# hex(HMAC-SHA256(secret, "link-protect-v<VERSION>: link-protect token hmac key")).
link_protect_key() {
  printf '%s' "link-protect-v$2: link-protect token hmac key" \
    | openssl dgst -sha256 -hmac "$1" -r | sed 's/ .*//'
}

# smtp_link_protect_keys CONFIG_ENV — print the SMTP link-protect settings: the
# ALREADY-DERIVED current key (Config.LinkProtectTokenKeys) and, only while the
# rotation overlap is open (previous secret set, version > 1), the retiring key at
# version-1. The master JWT_SECRET itself never reaches smtp.env.
smtp_link_protect_keys() {
  local secret previous version key
  secret="$(config_env_value "$1" JWT_SECRET)"
  [ -n "$secret" ] || return 0
  version="$(config_env_value "$1" JWT_LINK_PROTECT_TOKEN_VERSION)"
  case "${version:-1}" in ''|*[!0-9]*) echo "smtp.env: JWT_LINK_PROTECT_TOKEN_VERSION must be a positive integer" >&2; return 1;; esac
  version="${version:-1}"
  [ "$version" -ge 1 ] || { echo "smtp.env: JWT_LINK_PROTECT_TOKEN_VERSION must be >= 1" >&2; return 1; }
  key="$(link_protect_key "$secret" "$version")"
  [[ "$key" =~ ^[0-9a-f]{64}$ ]] || { echo "smtp.env: could not derive the link-protect key (openssl)" >&2; return 1; }
  printf 'SMTP_LINK_PROTECT_KEY=%s\nSMTP_LINK_PROTECT_VERSION=%s\n' "$key" "$version"
  previous="$(config_env_value "$1" JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET)"
  if [ -n "$previous" ] && [ "$version" -gt 1 ]; then
    key="$(link_protect_key "$previous" "$((version - 1))")"
    [[ "$key" =~ ^[0-9a-f]{64}$ ]] || { echo "smtp.env: could not derive the previous link-protect key" >&2; return 1; }
    printf 'SMTP_LINK_PROTECT_KEY_PREVIOUS=%s\n' "$key"
  fi
}

# render_smtp_env OUTFILE CONFIG_ENV DB_CRED_FILE — SMTP's own allow-listed
# environment (#501), loaded by the gateway unit beside federation.env. Literal
# assignments only, never sourced: no owner/direct-owner DSN, no updater or
# unrelated credential ever reaches the internet-facing SMTP listeners. The
# worker DSN comes from the split credential file (or a pre-split config.env).
render_smtp_env() {
  local outfile="$1" config="$2" credentials="$3" tmp
  tmp="$(mktemp "${outfile}.XXXXXX")" || return 1
  # With SMTP off the file is EMPTY: the internet-facing gateway never receives the
  # encryption/audit/S3 secrets or the worker tier on behalf of a listener that
  # is not served.
  if ! smtp_front_enabled "$config"; then
    : > "$tmp"
    chmod 0640 "$tmp"
    mv -f "$tmp" "$outfile"
    return 0
  fi
  (
    umask 027
    if [ -f "$config" ]; then
      grep -E '^(CLAMAV_ADDR|SANDBOX_(ENABLED|CAPE_URL|CAPE_API_KEY|TIMEOUT|FAIL_MODE)|INTERNAL_DOMAINS|PROTECTED_DOMAINS|ANTIPHISH_(NAME_THRESHOLD|USER_CACHE_TTL)|CRYPTO_ALGORITHM_PROFILE|DB_DSN|DB_DIRECT_DSN|DB_ENCRYPTION_KEY|AUDIT_HMAC_KEY|TLS_CERT|TLS_KEY|SMTP_(INBOUND_(ADDR|TLS_ADDR|TLS_ENFORCE|MAX_CONNS)|SUBMISSION_(ADDR|MAX_CONNS)|PER_USER_MAX_CONNS|TLS_CERT_FILE|TLS_KEY_FILE)|S3_(ENDPOINT|SECURE|BUCKET|ACCESS_KEY|SECRET_KEY)|MINIO_(ENDPOINT|SECURE|BUCKET|ACCESS_KEY|SECRET_KEY)|THREAT_(FEED_ENABLED|SPRAY_WINDOW_SECS|SPRAY_MAX_USERS|SPRAY_LOCKOUT_MINS|CAPTCHA_WINDOW_MINS|CAPTCHA_THRESHOLD|TARPIT_WINDOW_MINS|TARPIT_THRESHOLD|RATE_LIMIT_PER_MIN)|GEO_BLOCK_(ENABLED|COUNTRIES)|GEOIP_DB_(PATH|SHA256)|SPRAY_DETECT_ENABLED|CAPTCHA_ENABLED|TARPIT_ENABLED)=' "$config" || true
    fi
    smtp_link_protect_keys "$config" || exit 1
    if [ -f "$credentials" ]; then
      grep -E '^DB_WORKER_DSN=' "$credentials" || true
    elif [ -f "$config" ]; then
      grep -E '^DB_WORKER_DSN=' "$config" || true
    fi
  ) > "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 0640 "$tmp"
  mv -f "$tmp" "$outfile"
}

# render_gateway_env OUTFILE — the front door's own environment (no secrets).
# GATEWAY_UPSTREAM is Go's internal plain listener (HTTP_MODE=proxy serves the
# app on :80; default http://127.0.0.1:80) and must be loopback;
# GATEWAY_RUST_AUTH_UPSTREAM is AUTHSERVER_URL (setjoin-auth, required) and
# GATEWAY_AUTH_UPSTREAM is the transitional Go authserverd AUTHSERVERD_URL
# (default http://127.0.0.1:8444; go-auth rows reach Go directly, #359b). Both
# must be the literal http://127.0.0.1:<port>: each hop trusts its peer only as
# exactly 127.0.0.1 (TRUSTED_PROXY_IP). GATEWAY_TRUSTED_PROXIES
# is the local TLS terminator's address (default 127.0.0.1).
render_gateway_env() {
  local outfile="$1"
  [ -n "${AUTHSERVER_URL:-}" ] || { echo "render_gateway_env: AUTHSERVER_URL is required" >&2; return 1; }
  local upstream="${GATEWAY_UPSTREAM:-http://127.0.0.1:80}"
  case "$upstream" in
    http://127.*|http://\[::1\]*|http://localhost:*) ;;
    *) echo "render_gateway_env: GATEWAY_UPSTREAM must be Go's loopback plain listener (got '$upstream')" >&2; return 1 ;;
  esac
  [[ "$AUTHSERVER_URL" =~ ^http://127\.0\.0\.1:[0-9]{1,5}$ ]] || { echo "render_gateway_env: AUTHSERVER_URL must be http://127.0.0.1:<port> (got '$AUTHSERVER_URL')" >&2; return 1; }
  local go_auth="${AUTHSERVERD_URL:-http://127.0.0.1:8444}"
  [[ "$go_auth" =~ ^http://127\.0\.0\.1:[0-9]{1,5}$ ]] || { echo "render_gateway_env: AUTHSERVERD_URL must be http://127.0.0.1:<port> (got '$go_auth')" >&2; return 1; }
  local trusted="${GATEWAY_TRUSTED_PROXIES:-127.0.0.1}"
  ( umask 022; cat > "$outfile" <<ENV
# setjoin Rust front door (setjoin-gateway) — generated by deploy/scripts/install.sh.
# ARCH-027: the TLS terminator forwards client traffic to the gateway socket
# (setjoin-gateway.socket, ${GATEWAY_LISTEN:-127.0.0.1:8090}); the gateway forwards every
# route it does not serve to Go's internal plain listener. Rollback reinstalls
# the previous release with its matching units, sockets and configuration.
GATEWAY_ENABLED=true
GATEWAY_LISTEN=${GATEWAY_LISTEN:-127.0.0.1:8090}
GATEWAY_UPSTREAM=$upstream
GATEWAY_AUTH_UPSTREAM=$go_auth
GATEWAY_RUST_AUTH_UPSTREAM=$AUTHSERVER_URL
GATEWAY_TRUSTED_PROXIES=$trusted
ENV
  )
  local off_names=""
  if imap_front_enabled "${CONFIG_ENV:-}"; then off_names=imap; fi
  if smtp_front_enabled "${CONFIG_ENV:-}"; then
    if [ -n "$(smtp_front_listen "$CONFIG_ENV" SMTP_INBOUND_ADDR :25)$(smtp_front_listen "$CONFIG_ENV" SMTP_INBOUND_TLS_ADDR '')" ]; then off_names="${off_names:+$off_names,}smtp"; fi
    if [ -n "$(smtp_front_listen "$CONFIG_ENV" SMTP_SUBMISSION_ADDR :587)" ]; then off_names="${off_names:+$off_names,}submission"; fi
  fi
  if [ -n "$off_names" ]; then
    printf 'GO_LISTENERS_OFF=%s\n' "$off_names" >> "$outfile"
    # Protocol-only settings; no broad config.env or owner credential exposure.
    grep -E '^(THREAT_(FEED_ENABLED|SPRAY_WINDOW_SECS|SPRAY_MAX_USERS|SPRAY_LOCKOUT_MINS|CAPTCHA_WINDOW_MINS|CAPTCHA_THRESHOLD|TARPIT_WINDOW_MINS|TARPIT_THRESHOLD|RATE_LIMIT_PER_MIN)|GEO_BLOCK_(ENABLED|COUNTRIES)|GEOIP_DB_PATH|GEOIP_DB_SHA256|SPRAY_DETECT_ENABLED|CAPTCHA_ENABLED|TARPIT_ENABLED|IMAP_(MAX_CONNS|PER_USER_MAX_CONNS|TLS_CERT_FILE|TLS_KEY_FILE))=' "$CONFIG_ENV" >> "$outfile" || true
  fi
}

# render_updater_unit TEMPLATE OUTFILE — renders the root-owned transactional
# updater. execution.json defaults disabled, preserving observer-only startup.
# Credential values remain in root-owned 0600 files below a 0700 directory;
# argv contains only their fixed paths, never secret material. Direct paths
# work on both a normal host and systemd inside the supported deployment
# rehearsal container, where LoadCredential can be silently unavailable.
render_updater_unit() {
  local template="$1" outfile="$2"
  [ -n "${UPDATER_DATA_DIR:-}" ] || { echo "render_updater_unit: UPDATER_DATA_DIR is required" >&2; return 1; }
  [ -n "${UPDATER_DSN_FILE:-}" ] || { echo "render_updater_unit: UPDATER_DSN_FILE is required" >&2; return 1; }
	[ -n "${INSTALL_DIR:-}" ] || { echo "render_updater_unit: INSTALL_DIR is required" >&2; return 1; }
	[ -n "${UPDATER_EXECUTION_CONFIG:-}" ] || { echo "render_updater_unit: UPDATER_EXECUTION_CONFIG is required" >&2; return 1; }
	[ -n "${UPDATER_OWNER_DSN_FILE:-}" ] || { echo "render_updater_unit: UPDATER_OWNER_DSN_FILE is required" >&2; return 1; }
	[ -n "${UPDATER_RECOVERY_ACCESS_FILE:-}" ] || { echo "render_updater_unit: UPDATER_RECOVERY_ACCESS_FILE is required" >&2; return 1; }
	[ -n "${UPDATER_RECOVERY_SECRET_FILE:-}" ] || { echo "render_updater_unit: UPDATER_RECOVERY_SECRET_FILE is required" >&2; return 1; }
	[ -n "${UPDATER_RECOVERY_HMAC_FILE:-}" ] || { echo "render_updater_unit: UPDATER_RECOVERY_HMAC_FILE is required" >&2; return 1; }
	[ -n "${UPDATER_PROBE_CREDENTIAL_FILE:-}" ] || { echo "render_updater_unit: UPDATER_PROBE_CREDENTIAL_FILE is required" >&2; return 1; }
	[ -n "${UPDATER_APP_WORKER_DSN_FILE:-}" ] || { echo "render_updater_unit: UPDATER_APP_WORKER_DSN_FILE is required" >&2; return 1; }
	[ -n "${OFFICE_APP_MANIFEST:-}" ] || { echo "render_updater_unit: OFFICE_APP_MANIFEST is required" >&2; return 1; }
	[ -n "${OFFICE_APP_STATE_DIR:-}" ] || { echo "render_updater_unit: OFFICE_APP_STATE_DIR is required" >&2; return 1; }

  sed \
    -e "s#{{UPDATER_DATA_DIR}}#${UPDATER_DATA_DIR}#g" \
    -e "s#{{UPDATER_DSN_FILE}}#${UPDATER_DSN_FILE}#g" \
		-e "s#{{INSTALL_DIR}}#${INSTALL_DIR}#g" \
		-e "s#{{UPDATER_EXECUTION_CONFIG}}#${UPDATER_EXECUTION_CONFIG}#g" \
		-e "s#{{UPDATER_OWNER_DSN_FILE}}#${UPDATER_OWNER_DSN_FILE}#g" \
		-e "s#{{UPDATER_RECOVERY_ACCESS_FILE}}#${UPDATER_RECOVERY_ACCESS_FILE}#g" \
		-e "s#{{UPDATER_RECOVERY_SECRET_FILE}}#${UPDATER_RECOVERY_SECRET_FILE}#g" \
		-e "s#{{UPDATER_RECOVERY_HMAC_FILE}}#${UPDATER_RECOVERY_HMAC_FILE}#g" \
		-e "s#{{UPDATER_PROBE_CREDENTIAL_FILE}}#${UPDATER_PROBE_CREDENTIAL_FILE}#g" \
		-e "s#{{UPDATER_APP_WORKER_DSN_FILE}}#${UPDATER_APP_WORKER_DSN_FILE}#g" \
		-e "s#{{OFFICE_APP_MANIFEST}}#${OFFICE_APP_MANIFEST}#g" \
		-e "s#{{OFFICE_APP_STATE_DIR}}#${OFFICE_APP_STATE_DIR}#g" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_updater_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_authserver_unit TEMPLATE OUTFILE — substitute placeholders in
# authserver.service.template (Rust setjoin-auth, #359b). Reads INSTALL_DIR /
# CONFIG_ENV / AUTH_ENV; the privileged credential file is deliberately not an
# input (least privilege: auth.env carries only DB_WORKER_DSN);
# RUNTIME_DIR defaults to INSTALL_DIR/current.
# (all required). The two EnvironmentFile lines are order-sensitive in the
# TEMPLATE itself (config.env's token appears first, auth.env's second) —
# this function substitutes each token in place and never reorders lines,
# so the precedence (later EnvironmentFile wins) is preserved by
# construction, not by a fragile line-anchored sed pattern.
render_authserver_unit() {
  local template="$1" outfile="$2"
  [ -n "${INSTALL_DIR:-}" ] || { echo "render_authserver_unit: INSTALL_DIR is required" >&2; return 1; }
  [ -n "${CONFIG_ENV:-}" ] || { echo "render_authserver_unit: CONFIG_ENV is required" >&2; return 1; }
  [ -n "${AUTH_ENV:-}" ] || { echo "render_authserver_unit: AUTH_ENV is required" >&2; return 1; }

  local runtime_dir="${RUNTIME_DIR:-${INSTALL_DIR}/current}"

  sed \
    -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" \
    -e "s#{{CONFIG_ENV}}#${CONFIG_ENV}#g" \
    -e "s#{{AUTH_ENV}}#${AUTH_ENV}#g" \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_authserver_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_authserverd_unit TEMPLATE OUTFILE — the transitional Go authserverd
# behind setjoin-auth (#359b). Inputs: INSTALL_DIR, CONFIG_ENV,
# DB_CREDENTIALS_FILE, AUTHSERVERD_ENV (all required); RUNTIME_DIR defaults to
# INSTALL_DIR/current. Deleted with Go (#359).
render_authserverd_unit() {
  local template="$1" outfile="$2"
  [ -n "${INSTALL_DIR:-}" ] || { echo "render_authserverd_unit: INSTALL_DIR is required" >&2; return 1; }
  [ -n "${CONFIG_ENV:-}" ] || { echo "render_authserverd_unit: CONFIG_ENV is required" >&2; return 1; }
  [ -n "${DB_CREDENTIALS_FILE:-}" ] || { echo "render_authserverd_unit: DB_CREDENTIALS_FILE is required" >&2; return 1; }
  [ -n "${AUTHSERVERD_ENV:-}" ] || { echo "render_authserverd_unit: AUTHSERVERD_ENV is required" >&2; return 1; }
  local runtime_dir="${RUNTIME_DIR:-${INSTALL_DIR}/current}"
  sed \
    -e "s#{{RUNTIME_DIR}}#${runtime_dir}#g" \
    -e "s#{{CONFIG_ENV}}#${CONFIG_ENV}#g" \
    -e "s#{{DB_CREDENTIALS_FILE}}#${DB_CREDENTIALS_FILE}#g" \
    -e "s#{{AUTHSERVERD_ENV}}#${AUTHSERVERD_ENV}#g" \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"
  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_authserverd_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_sfu_unit TEMPLATE OUTFILE — substitute placeholders in
# setjoin-sfu.service.template. Reads INSTALL_DIR (required) and
# LIVEKIT_YAML (optional, defaults to /etc/setjoin/livekit.yaml — the
# render_livekit_yaml default) from the environment.
render_sfu_unit() {
  local template="$1" outfile="$2"
  [ -n "${INSTALL_DIR:-}" ] || { echo "render_sfu_unit: INSTALL_DIR is required" >&2; return 1; }

  local livekit_yaml="${LIVEKIT_YAML:-/etc/setjoin/livekit.yaml}"

  sed \
    -e "s#{{INSTALL_DIR}}#${INSTALL_DIR}#g" \
    -e "s#{{LIVEKIT_YAML|/etc/setjoin/livekit.yaml}}#${livekit_yaml}#" \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_sfu_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_valkey_unit TEMPLATE OUTFILE — substitute placeholders in
# setjoin-valkey.service.template. No required vars: this unit deliberately
# carries no path token at all (ExecStart hardcodes /etc/setjoin/valkey.conf
# — the "valkey no-path-rewrite" fact preserved verbatim from the pre-render
# sed era; unlike the SFU/egress genre, this unit's config path has never
# been install-time-configurable and this refactor does not add that).
render_valkey_unit() {
  local template="$1" outfile="$2"

  sed \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_valkey_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# Meet B3 (Task 16) adds four more functions for the optional captions
# sidecar pair (setjoin-asr-bot + setjoin-funasr, both gated behind
# install.sh's MEET_CAPTIONS_ENABLED prompt — unlike the SFU/Valkey/Egress
# trio, which install unconditionally):
#   render_asrbot_unit / render_funasr_unit — the render_egress_unit genre
#     for the two new units.
#   render_asrbot_env — the render_egress_yaml genre for asrbot.env.template.
#   install_funasr_models — download+sha256-verify the pinned FunASR model
#     weight files, the install_livekit_binary discipline, model edition.

# Meet B3 (Task 16): the pinned FunASR streaming ASR runtime container —
# the upstream `funasr-runtime-sdk-online-cpu` C++ WebSocket server (NOT the
# Python toolkit; D3's zero-Python-in-product decision, asrbot/AGENTS.md).
# The manifest-list digest was fetched from the Aliyun registry 2026-07-16
# (`curl` against the registry v2 API — a real docker-distribution
# manifest-list digest, re-derivable via
# `crane digest registry.cn-hangzhou.aliyuncs.com/funasr_repo/funasr:funasr-runtime-sdk-online-cpu-0.1.13`)
# and is the trust root (the tag alone is mutable) — the EGRESS_IMAGE
# pinning discipline, container edition.
FUNASR_IMAGE="registry.cn-hangzhou.aliyuncs.com/funasr_repo/funasr:funasr-runtime-sdk-online-cpu-0.1.13@sha256:2a54c20f6b9e2fd253b24abd5c083545751485bcc26e038ed12eab3380c86d51"

# render_asrbot_unit TEMPLATE OUTFILE — substitute placeholders in
# setjoin-asr-bot.service.template. Reads INSTALL_DIR (optional, defaults
# to /opt/mailserver — the setjoin-sfu.service convention) from the
# environment. Arch review #A11: the {{USER|setjoin}}/{{GROUP|setjoin}}
# tokens are substituted HERE now, in the same single render call — this
# used to be a two-pass hybrid (render, THEN a separate install.sh sed pass
# for User/Group), the exact seam #A11 called out as where the next deploy
# bug would hide (the render seam not owning the runtime-account fact).
render_asrbot_unit() {
  local template="$1" outfile="$2"
  local install_dir="${INSTALL_DIR:-/opt/mailserver}"

  sed \
    -e "s#{{INSTALL_DIR|/opt/mailserver}}#${install_dir}#g" \
    -e "s#{{USER|setjoin}}#setjoin#" \
    -e "s#{{GROUP|setjoin}}#setjoin#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_asrbot_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_funasr_unit TEMPLATE OUTFILE — substitute placeholders in
# setjoin-funasr.service.template. Reads CONTAINER_BIN (required) and
# FUNASR_GPU_ARGS (optional — e.g. "--device nvidia.com/gpu=all" for the
# CUDA runtime-image variant, spec §2 GPU sizing) from the environment.
# FUNASR_IMAGE is this file's own pinned constant, never overridable from
# the environment (the EGRESS_IMAGE posture) — but IS guarded here: a
# CHANGEME-pin-at-deploy sentinel (the honesty-ledger fallback Task 16's own
# plan allows when a real digest can't be fetched) must never be rendered
# into a unit that would then pull an unpinned image.
render_funasr_unit() {
  local template="$1" outfile="$2"
  [ -n "${CONTAINER_BIN:-}" ] || { echo "render_funasr_unit: CONTAINER_BIN is required" >&2; return 1; }
  case "$FUNASR_IMAGE" in
    ""|*CHANGEME*)
      echo "render_funasr_unit: FUNASR_IMAGE is unpinned (empty or a CHANGEME-pin-at-deploy sentinel) — refusing to render a unit that would pull an unpinned image. Pin FUNASR_IMAGE in lib-livekit.sh first." >&2
      return 1
      ;;
  esac

  local gpu_args="${FUNASR_GPU_ARGS:-}"

  sed \
    -e "s#{{CONTAINER_BIN}}#${CONTAINER_BIN}#g" \
    -e "s#{{FUNASR_IMAGE}}#${FUNASR_IMAGE}#g" \
    -e "s#{{FUNASR_GPU_ARGS|}}#${gpu_args}#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_funasr_unit: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# render_asrbot_env TEMPLATE OUTFILE — substitute placeholders in
# asrbot.env.template. Reads LIVEKIT_URL and ASR_TOKEN (both required —
# fail loud if unset, the render_livekit_yaml posture) and FUNASR_URL /
# ASR_LISTEN / ASR_MAX_MEETINGS / ASR_MAX_ACTIVE_TRACKS (all optional,
# template-defaulted — asrbot/AGENTS.md's own defaults) from the
# environment. ASR_LISTEN is ADDITIONALLY refused here if it is not
# loopback — the SAME check asrbot's own bot.ValidateLoopback runs at
# startup (asrbot/internal/bot/server.go), caught a layer earlier so a
# misconfigured install fails at `install.sh` time, not at the first
# `systemctl start` (the eng BLOCKER #1 "fail loud before the service, not
# after" posture). ASR_TOKEN (B3 Task 18 pipeline-review finding 1) is the
# control-API bearer secret asrbot's own bot.ValidateToken also refuses to
# start without — install.sh generates it ONCE and passes the SAME value
# here and into config.env's ASR_TOKEN (law 3).
render_asrbot_env() {
  local template="$1" outfile="$2"
  [ -n "${LIVEKIT_URL:-}" ] || { echo "render_asrbot_env: LIVEKIT_URL is required" >&2; return 1; }
  [ -n "${ASR_TOKEN:-}" ] || { echo "render_asrbot_env: ASR_TOKEN is required (the control-API bearer secret — asrbot's own bot.ValidateToken refuses to start without it)" >&2; return 1; }

  local listen="${ASR_LISTEN:-127.0.0.1:7890}"
  local host="${listen%:*}"
  case "$host" in
    127.*|::1|localhost) : ;;
    *)
      echo "render_asrbot_env: ASR_LISTEN host '$host' is not loopback (127.0.0.0/8, ::1, localhost) — refusing. The asrbot control API requires the ASR_TOKEN bearer secret (asrbot/AGENTS.md), but a non-loopback bind would still let any host-network peer reach it and brute-force / relay that secret." >&2
      return 1
      ;;
  esac

  local funasr_url="${FUNASR_URL:-ws://127.0.0.1:10096}"
  local max_meetings="${ASR_MAX_MEETINGS:-2}"
  local max_tracks="${ASR_MAX_ACTIVE_TRACKS:-4}"

  sed \
    -e "s#{{LIVEKIT_URL}}#${LIVEKIT_URL}#" \
    -e "s#{{FUNASR_URL|ws://127.0.0.1:10096}}#${funasr_url}#" \
    -e "s#{{ASR_LISTEN|127.0.0.1:7890}}#${listen}#" \
    -e "s#{{ASR_TOKEN}}#${ASR_TOKEN}#" \
    -e "s#{{ASR_MAX_MEETINGS|2}}#${max_meetings}#" \
    -e "s#{{ASR_MAX_ACTIVE_TRACKS|4}}#${max_tracks}#" \
    "$template" > "$outfile"

  if grep -q '{{' "$outfile"; then
    rm -f "$outfile"
    echo "render_asrbot_env: unresolved {{...}} placeholder(s) remain in $outfile — template/render drift, refusing to write a broken config" >&2
    return 1
  fi
}

# Meet B3 (Task 16, completed by the 2026-07-16 live gate): ALL FIVE models
# the pinned image's own run_server_2pass.sh defaults to — read out of the
# real container at gate time, not asserted from docs — are pinned here and
# named explicitly in setjoin-funasr.service.template's ExecStart, so an
# upstream default bump inside a future image can never silently change
# which models transcribe. License: Apache License 2.0 for the damo/*
# models (re-verified against the ModelScope model cards at pin time —
# permissive/commercial-ok, spec §2); thuduj12/fst_itn_zh carries the same
# posture per its card. Every SHA-256 below was fetched from ModelScope's
# own repo/files API (`GET .../repo/files?Revision=master`, the `Sha256`
# field per file — a canonical, first-party source) and independently
# re-verified by downloading each file and re-hashing it — the
# install_livekit_binary discipline, model-weight edition. The
# `/workspace/models` mount is deliberately `:ro` (never a runtime
# auto-download target: the container must not silently fetch its own
# trust root) — the gate proved the server loads every model from the
# pre-placed :ro dir and serves the full 2pass round-trip (partials +
# punctuated finals) with zero writable model state.
#
# The wrapper's sixth default, --lm-dir
# (damo/speech_ngram_lm_zh-cn-ai-wesp-fst, a ~960MB WFST rescoring FST), is
# deliberately DISABLED (--lm-dir '' in the unit) rather than pinned: it
# would crowd the unit's 4G MemoryMax and the live gate proved
# recognizably-correct transcription without it. Pin it HERE and enable it
# in the unit together if a real deploy demands LM rescoring.
FUNASR_ONLINE_MODEL_ID="damo/speech_paraformer-large_asr_nat-zh-cn-16k-common-vocab8404-online-onnx"
# "<relative path>:<sha256>" — one entry per line (ModelScope repo/files'
# Sha256 field, fetched 2026-07-16). Deliberately excludes each repo's
# non-runtime files (.gitattributes, quickstart.md, README.md).
FUNASR_ONLINE_MODEL_FILES="am.mvn:29b3c740a2c0cfc6b308126d31d7f265fa2be74f3bb095cd2f143ea970896ae5
config.yaml:35e6bf41f8c7eaf9a0f787af7fdc8fc5ed75fa8009ade7d3c2f3ef5bce20c648
configuration.json:cbf1c4e973cbb914d5c3aa24dcb30468bccc3abef60c1b9f9bb28b1f75c81255
decoder_quant.onnx:873d21ee80c7345bfc27944b843699fe16bba021fd020747d38aef2dfc103681
model_quant.onnx:dd4121cf45102018c26f9256f0b862df416edfcd06b0863ef4ce378a63c7d5e2
tokens.json:2b20c2b12572d682afff84ce1c8d560f67b8b32a4c1f21567411d141ed352127"

# The four companion models (the ledgered Task 16 gap, closed by the
# 2026-07-16 live gate): server-side VAD, the offline/2pass rescoring AM,
# streaming punctuation, and inverse text normalization.
FUNASR_VAD_MODEL_ID="damo/speech_fsmn_vad_zh-cn-16k-common-onnx"
FUNASR_VAD_MODEL_FILES="am.mvn:6820fef9687708c4fc3fab2530179c8fcea6262daa25514380056cd8f6eb1754
config.yaml:2ef334f2d7776edd86ed696296774f87550206c256bfabc597872ad861831589
configuration.json:f62fcbcebbaade798714b34c521cad87d869ee6a327ceed948e01ff2336bbfc0
model_quant.onnx:5289eb2aa3c9af2d7a4284bcfa7c3ceb81d360814ed4203239b6c5d0569da8a1"

FUNASR_OFFLINE_MODEL_ID="damo/speech_paraformer-large-vad-punc_asr_nat-zh-cn-16k-common-vocab8404-onnx"
FUNASR_OFFLINE_MODEL_FILES="am.mvn:29b3c740a2c0cfc6b308126d31d7f265fa2be74f3bb095cd2f143ea970896ae5
config.yaml:4f35265cc3c6dd906a2668b62847183e441310d82df6438bace9b8f6dab3bf7d
configuration.json:6e4e5234d4f657eb5530fbda198915b9f219aedbaa13a7b59b62819f43022af3
model_quant.onnx:80fa5c8a87f5ae77ea2dc233ad220b9415343c8681d538e59f019f2acc837694
tokens.json:2b20c2b12572d682afff84ce1c8d560f67b8b32a4c1f21567411d141ed352127"

FUNASR_PUNC_MODEL_ID="damo/punc_ct-transformer_zh-cn-common-vad_realtime-vocab272727-onnx"
FUNASR_PUNC_MODEL_FILES="config.yaml:4b57cf5d7a3310937ac2d73aa0ea89770e022d62c99dcf3e247f7dbeb0b0260d
configuration.json:7c7884ea9e28c103034672afc1f8d37e8758af6d1eeeaf3a40396ef89975b9cd
model_quant.onnx:a167b716ac5ade229b45c0e5c8fafc935cf65abda8b37597c781332ec2970a89
tokens.json:c960ab87bccea4aa15cf49a59f71973c2c330b46668048cd8da253749ec71ee3"

FUNASR_ITN_MODEL_ID="thuduj12/fst_itn_zh"
FUNASR_ITN_MODEL_FILES="configuration.json:52f2864a0245fd59162431fb54fcda8a083729183c86532037d6bcaa6df9d7e6
zh_itn_tagger.fst:b6e7f892c1fd1b313ea94215d529160c237b2d575b2b98969ed5ca0c10ff7300
zh_itn_verbalizer.fst:de9d39002de8d73e97e3740d98d037c4aa8f421881a62baa3f0e022add994a34"

# install_one_funasr_model DEST MODEL_ID FILES — download+sha256-verify each
# pinned weight file for MODEL_ID into DEST/MODEL_ID/ — the exact
# relative-path convention the server's --download-model-dir/--*-dir flag
# pairs resolve LOCALLY, without touching the network, when a model ID is
# already present under download-model-dir (the reason the model-ID string
# doubles as a directory path here; proven against the real pinned image by
# the 2026-07-16 live gate, :ro mount included). Re-run safe: each file is
# independently content-addressed by its own pinned sha256, so re-verifying
# an existing file on every call is cheap and self-heals a partial prior
# download — unlike install_livekit_binary's single version-stamp file, no
# separate stamp is needed.
install_one_funasr_model() {
  local dest="$1" model_id="$2" files="$3"
  local model_dir="$dest/$model_id"
  mkdir -p "$model_dir"

  local line name want got dst url
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name="${line%%:*}"; want="${line#*:}"
    dst="$model_dir/$name"
    if [ -f "$dst" ]; then
      if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$dst" | cut -d' ' -f1)"
      else got="$(shasum -a 256 "$dst" | cut -d' ' -f1)"; fi
      if [ "$got" = "$want" ]; then
        info "FunASR model file $model_id/$name already present + verified — skipping."
        continue
      fi
      info "FunASR model file $model_id/$name present but checksum mismatch — re-downloading."
    fi
    url="https://modelscope.cn/api/v1/models/${model_id}/repo?Revision=master&FilePath=${name}"
    info "Downloading FunASR model file $model_id/$name…"
    if ! curl -fsSL -o "$dst.tmp" "$url"; then
      rm -f "$dst.tmp"
      die "failed to download $url — check network access, or pre-place the pinned FunASR model files under $model_dir."
    fi
    if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$dst.tmp" | cut -d' ' -f1)"
    else got="$(shasum -a 256 "$dst.tmp" | cut -d' ' -f1)"; fi
    if [ "$got" != "$want" ]; then
      rm -f "$dst.tmp"
      die "FunASR model file $model_id/$name checksum mismatch: expected $want, got $got — refusing to install a tampered or corrupt model weight. Re-download and retry."
    fi
    mv "$dst.tmp" "$dst"
    chmod 0644 "$dst"
  done <<EOF
$files
EOF
  info "FunASR model $model_id installed to $model_dir (sha256 verified)."
}

# install_funasr_models DEST — all five models setjoin-funasr.service's
# ExecStart names explicitly (online + the four companions the 2026-07-16
# live gate pinned; ~750MB total on first run, re-verify-only afterwards).
install_funasr_models() {
  local dest="$1"
  install_one_funasr_model "$dest" "$FUNASR_ONLINE_MODEL_ID"  "$FUNASR_ONLINE_MODEL_FILES"
  install_one_funasr_model "$dest" "$FUNASR_VAD_MODEL_ID"     "$FUNASR_VAD_MODEL_FILES"
  install_one_funasr_model "$dest" "$FUNASR_OFFLINE_MODEL_ID" "$FUNASR_OFFLINE_MODEL_FILES"
  install_one_funasr_model "$dest" "$FUNASR_PUNC_MODEL_ID"    "$FUNASR_PUNC_MODEL_FILES"
  install_one_funasr_model "$dest" "$FUNASR_ITN_MODEL_ID"     "$FUNASR_ITN_MODEL_FILES"
}

# provision_valkey_conf OUTFILE — writes the loopback-only, no-persistence
# Valkey config (bus-only — the setjoin-valkey.service unit needs no
# writable state dir). Reads VALKEY_PASSWORD (required) from the
# environment; law 3: this is the SAME value rendered into livekit.yaml and
# egress.yaml in the same install run.
provision_valkey_conf() {
  local outfile="$1"
  [ -n "${VALKEY_PASSWORD:-}" ] || { echo "provision_valkey_conf: VALKEY_PASSWORD is required" >&2; return 1; }

  cat > "$outfile" <<CONF
# setjoin Valkey config — generated by mailserver/deploy/scripts/install.sh
# (provision_valkey_conf). Bus only for the SFU<->Egress message plane
# (D7/§3.3) — no persistence, so a lost Valkey never loses durable state.
bind 127.0.0.1
port 6390
requirepass ${VALKEY_PASSWORD}
save ""
appendonly no
protected-mode yes
CONF
  chmod 600 "$outfile"
}

# Native TLS front door (#413). Read literal EnvironmentFile assignments; never source secrets.
tls_front_value() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1 || true; }
tls_front_enabled() {
  [ -f "$1" ] && { [ -n "$(tls_front_value "$1" TLS_CERT)" ] || [ -n "$(tls_front_value "$1" TLS_AUTOCERT_DOMAINS)" ]; }
}
tls_front_set() {
  local config="$1" key="$2" value="$3" tmp
  tmp=$(mktemp "${config}.XXXXXX") || return 1
  grep -v "^$key=" "$config" > "$tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  cat "$tmp" > "$config"
  rm -f "$tmp"
}
configure_tls_front() {
  local config="$1" key names worker mode http_mode additions
  tls_front_enabled "$config" || return 0
  # Overseer binds before launchWorker checks its switches. It must reserve only
  # an unused loopback socket; systemd owns the public TLS descriptor.
  tls_front_set "$config" LISTEN_ADDR 127.0.0.1:0 || return 1
  mode=$(tls_front_value "$config" TLS_AUTOCERT_CHALLENGE)
  http_mode=$(tls_front_value "$config" HTTP_MODE)
  for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
    names=$(tls_front_value "$config" "$key")
    additions='cert-monitor tls-ticket-keys http-tls http-h2c'
    if [ -n "$(tls_front_value "$config" TLS_AUTOCERT_DOMAINS)" ]; then
      case "$mode" in
        ''|tls-alpn-01|dns-01) additions="$additions acme-renewal" ;;
        http-01)
          # #305's native :80 responder implements redirect mode. Proxy/serve
          # still host legacy API shapes on Go :80; retain that named owner.
          case "$http_mode" in ''|redirect)
            additions="$additions acme-renewal"
            if [ "$key" = GO_WORKERS_OFF ]; then additions="$additions http-port80"; fi ;;
          esac ;;
      esac
    fi
    for worker in $additions; do
      case ",$names," in *,$worker,*) ;; *) names="${names:+$names,}$worker" ;; esac
    done
    tls_front_set "$config" "$key" "$names" || return 1
  done
}
render_tls_front_env() {
  local outfile="$1" config="$2" tmp
  tmp=$(mktemp "${outfile}.XXXXXX") || return 1
  # Paths/credentials needed by TLS/ACME only. DB tiers/worker ownership are in
  # the existing least-privilege federation.env, loaded before this file.
  grep -E '^(HOSTNAME|TLS_CERT|TLS_KEY|TLS_AUTOCERT_(DOMAINS|EMAIL|CACHE_DIR|KEY_FILE|CHALLENGE)|TLS_DNS_(PROVIDER|CONFIG|RESOLVERS)|TLS_SESSION_TICKET_KEY_ROTATE_SECS|AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|PROFILE|SHARED_CREDENTIALS_FILE|CONFIG_FILE|ROLE_ARN|WEB_IDENTITY_TOKEN_FILE|ROLE_SESSION_NAME|CONTAINER_CREDENTIALS_RELATIVE_URI|CONTAINER_CREDENTIALS_FULL_URI|CONTAINER_AUTHORIZATION_TOKEN|CONTAINER_AUTHORIZATION_TOKEN_FILE|EC2_METADATA_DISABLED|EC2_METADATA_SERVICE_ENDPOINT|ENDPOINT_URL|ENDPOINT_URL_ROUTE_53))=' "$config" > "$tmp" || true
  chmod 0640 "$tmp"
  mv -f "$tmp" "$outfile"
}

# Local TLS readiness accepts the installation's self-signed leaf, while still
# requiring a TLS handshake and the native front-door health response.
tls_front_probe_url() {
  local address
  address=$(tls_front_value "$1" GATEWAY_HTTPS_LISTEN)
  address="${address:-443}"
  case "$address" in
    :*) address="127.0.0.1$address" ;;
    *:*) address="${address/#0.0.0.0:/127.0.0.1:}"; address="${address/#\[::\]:/[::1]:}" ;;
    *) address="127.0.0.1:$address" ;;
  esac
  printf 'https://%s/_gateway/healthz\n' "$address"
}

# Preserve the managed TLS settings across install's config.env regeneration,
# honoring explicit environment assignments without evaluating any value.
tls_front_preserve_settings() {
  local config="$1" key value
  for key in SMTP_FRONT_ENABLED SMTP_INBOUND_ADDR SMTP_INBOUND_TLS_ADDR SMTP_SUBMISSION_ADDR SMTP_INBOUND_TLS_ENFORCE SMTP_INBOUND_MAX_CONNS SMTP_SUBMISSION_MAX_CONNS SMTP_PER_USER_MAX_CONNS SMTP_TLS_CERT_FILE SMTP_TLS_KEY_FILE IMAP_ADDR IMAP_TLS_ADDR IMAP_MAX_CONNS IMAP_PER_USER_MAX_CONNS IMAP_TLS_CERT_FILE IMAP_TLS_KEY_FILE TLS_AUTOCERT_DOMAINS TLS_AUTOCERT_EMAIL TLS_AUTOCERT_CACHE_DIR TLS_AUTOCERT_KEY_FILE TLS_AUTOCERT_CHALLENGE TLS_DNS_PROVIDER TLS_DNS_CONFIG TLS_DNS_RESOLVERS TLS_SESSION_TICKET_KEY_ROTATE_SECS GATEWAY_HTTPS_LISTEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_SHARED_CREDENTIALS_FILE AWS_CONFIG_FILE AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_SESSION_NAME AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE AWS_EC2_METADATA_DISABLED AWS_EC2_METADATA_SERVICE_ENDPOINT AWS_ENDPOINT_URL AWS_ENDPOINT_URL_ROUTE_53; do
    if [ "${!key+x}" = x ]; then value="${!key}"; else value=$(tls_front_value "$config" "$key"); fi
    case "$value" in *$'\n'*|*$'\r'*) echo "TLS setting $key must be one EnvironmentFile line (use a config file for JSON)" >&2; return 1;; esac
    if [ -n "$value" ]; then
      printf '%s=%s\n' "$key" "$value"
    elif [ "$key" = IMAP_ADDR ] || [ "$key" = IMAP_TLS_ADDR ] || [ "$key" = SMTP_INBOUND_ADDR ] || [ "$key" = SMTP_INBOUND_TLS_ADDR ] || [ "$key" = SMTP_SUBMISSION_ADDR ]; then
      # Empty is the explicit listener-disable value, distinct from omission.
      if [ "${!key+x}" = x ] || { [ -f "$config" ] && grep -q "^$key=" "$config"; }; then
        printf '%s=\n' "$key"
      fi
    fi
  done
}

# IMAP's listener transfer is whole, with systemd owning both configured sockets.
imap_front_listen() {
  local config="$1" key="$2" fallback="$3"
  if [ "${!key+x}" = x ]; then printf '%s' "${!key}"
  elif [ -f "$config" ] && grep -q "^$key=" "$config"; then sed -n "s/^$key=//p" "$config" | tail -1
  else printf '%s' "$fallback"; fi
}
imap_front_enabled() {
  local config="$1"
  [ -n "$config" ] && [ -f "$config" ] || return 1
  [ -n "$(tls_front_value "$config" TLS_CERT)" ] && [ -n "$(tls_front_value "$config" TLS_KEY)" ] || return 1
  [ -n "$(imap_front_listen "$config" IMAP_ADDR :143)$(imap_front_listen "$config" IMAP_TLS_ADDR :993)" ]
}
configure_imap_front() {
  local config="$1" names
  imap_front_enabled "$config" || return 0
  names=$(tls_front_value "$config" GO_LISTENERS_OFF)
  case ",$names," in *,imap,*) ;; *) names="${names:+$names,}imap";; esac
  tls_front_set "$config" GO_LISTENERS_OFF "$names"
}

# SMTP's whole-listener transfer (#501). Rust owns inbound :25, the implicit-TLS
# variant and submission by default (#526); Go's
# listeners are then off. There is no runtime switch back: rollback reinstalls
# the previous release with its matching units, sockets and configuration.
smtp_front_listen() {
  local config="$1" key="$2" fallback="$3"
  if [ "${!key+x}" = x ]; then printf '%s' "${!key}"
  elif [ -f "$config" ] && grep -q "^$key=" "$config"; then sed -n "s/^$key=//p" "$config" | tail -1
  else printf '%s' "$fallback"; fi
}
smtp_front_enabled() {
  local config="$1"
  [ -n "$config" ] && [ -f "$config" ] || return 1
  # The old opt-in marker is retired. Explicit empty addresses disable a
  # listener; an old false marker must not strand upgrades on Go.
  [ -n "$(smtp_front_listen "$config" SMTP_INBOUND_ADDR :25)$(smtp_front_listen "$config" SMTP_INBOUND_TLS_ADDR '')$(smtp_front_listen "$config" SMTP_SUBMISSION_ADDR :587)" ]
}
configure_smtp_front() {
  local config="$1" names
  tls_front_set "$config" SMTP_FRONT_ENABLED true
  smtp_front_enabled "$config" || return 0
  names=$(tls_front_value "$config" GO_LISTENERS_OFF)
  if [ -n "$(smtp_front_listen "$config" SMTP_INBOUND_ADDR :25)$(smtp_front_listen "$config" SMTP_INBOUND_TLS_ADDR '')" ]; then
    case ",$names," in *,smtp,*) ;; *) names="${names:+$names,}smtp";; esac
  fi
  if [ -n "$(smtp_front_listen "$config" SMTP_SUBMISSION_ADDR :587)" ]; then
    case ",$names," in *,submission,*) ;; *) names="${names:+$names,}submission";; esac
  fi
  tls_front_set "$config" GO_LISTENERS_OFF "$names"
}
