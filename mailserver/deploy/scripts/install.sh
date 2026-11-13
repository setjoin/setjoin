#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# install.sh — first-class SINGLE-NODE production installer for setjoin.
#
# Scope: a single host serving <100 users. For 100+ users or HA (zero SPOF,
# automatic failover) use the 3-node guide: docs/guides/HA_OVERVIEW.md.
#
# Adapted from scripts/setup-test-env.sh (the working dev reference). Unlike
# that script this targets a REAL config dir (/etc/setjoin), generates and
# PERSISTS production secrets, installs the systemd units (gateway + auth
# server), provisions the first admin, and health-checks — and it is IDEMPOTENT: re-running never overwrites
# an existing secret or config without an explicit --force confirmation.
#
# What it does (the 10 steps mirrored in SINGLE_NODE_SETUP.md):
#   1. Preconditions: root, required tools, a reachable Postgres.
#   2. Build mailserverd + authserverd + the gated setjoin-updater observer if
#      the binaries are missing; download +
#      checksum-verify the pinned livekit-server v1.13.5 SFU binary (Meet B1
#      Task 14 — mailserver/deploy/scripts/lib-livekit.sh); verify valkey-server
#      is installed, detect the container runtime (podman/docker), and pull the
#      digest-pinned Egress image (Meet B2 Task 9 — recording sidecar). Prompts
#      for the OPTIONAL Meet captions leg (MEET_CAPTIONS_ENABLED, default
#      false — Meet B3 Task 16): if enabled, pulls the digest-pinned FunASR
#      image and downloads + sha256-verifies the pinned streaming ASR model.
#   3. Prompt for the 5-8 core settings (hostname/domain, admin email+password,
#      listen addr, DB DSN, S3 endpoint) — skipped for any already in config.env.
#   4. GENERATE + persist secrets: DB_ENCRYPTION_KEY, JWT_SECRET,
#      INTERNAL_API_KEY, S3 access/secret keys, LIVEKIT_API_SECRET, VALKEY_PASSWORD.
#   5. Generate a self-signed TLS cert (with an ACME / real-cert note).
#   6. Verify/install the pgtap extension package for the target Postgres
#      (V001__baseline.sql does CREATE EXTENSION pgtap — fail loud, not at
#      schema-load time, if it can't be installed), then create the database
#      and load V001__baseline.sql + forward migrations + reducers (all as the
#      OWNER identity), and give the constrained runtime roles (setjoin_app /
#      setjoin_worker) generated LOGIN passwords.
#   7. Write /etc/setjoin/config.env (mode 0600) — the runtime APP-role DSN
#      (DB_DSN; docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md), an explicit
#      AUTHSERVER_URL, and LIVEKIT_API_KEY/LIVEKIT_API_SECRET/LIVEKIT_URL/
#      MEET_EGRESS_ENABLED/VALKEY_PASSWORD (the SAME LIVEKIT_API_SECRET +
#      VALKEY_PASSWORD rendered into /etc/setjoin/livekit.yaml, valkey.conf,
#      and egress.yaml in this same step — one secret, one generation step,
#      never two prompts) — plus auth.env; install binaries + webmail. The
#      updater DSN is isolated in a separate root-only 0600 credential file,
#      never config.env. The PRIVILEGED DB tiers (DB_WORKER_DSN /
#      DB_OWNER_DSN / DB_DIRECT_OWNER_DSN) are likewise split OUT of
#      config.env into /etc/setjoin/db-credentials.d/db-credentials.env
#      (0600 root:root below the root-owned config dir; DEPLOY-004): config.env
#      is chown'ed to — and EnvironmentFile-injected into — the account running
#      BOTH internet-facing services, so it must never carry the owner or
#      BYPASSRLS-worker credentials. One-way exactly-once migration with a
#      timestamped config.env backup handles installs rendered by older
#      installers.
#   8. Install + enable the five runtime services plus the no-listener U1
#      updater observer. Start valkey/SFU/egress/auth/gateway in dependency
#      order, then the updater; host mutation remains gated until U2.
#   9. Provision the first admin through the local mailctl/database authority.
#  10. Health-check (GET /health + the SFU signal port + Valkey PING + the
#      Egress container) and print next steps, including firewall/TURN
#      guidance for the SFU (Meet B1 Task 14) and recording sizing (Meet B2
#      Task 9, docs/guides/SINGLE_NODE_SETUP.md).
#
# Optional (Pillar C1 Task 9): FEDERATION_ENABLED=1 (or answer "yes" to the
# interactive prompt) generates an org CA + s2s leaf cert under
# /etc/setjoin/federation/ and wires FEDERATION_LOCAL_DOMAIN/_LISTEN_ADDR/
# _CERT/_KEY into config.env — no systemd unit, no sidecar: federation.Service
# runs INSIDE mailserverd (cmd/mailserverd/main.go), gated only on all three
# of those being set. feature.federation (DB toggle, seeded OFF) and the
# admin allow-list console (federation.manage) separately gate actual
# cross-org peering — this leg only wires the box to be ABLE to federate.
#
# Usage:
#   sudo bash install.sh                 # interactive, idempotent
#   sudo bash install.sh --force         # re-prompt + rotate secrets (asks first)
#   sudo NONINTERACTIVE=1 bash install.sh  # use env vars / existing config, no prompts
#   sudo bash install.sh --permissive-dsn  # escape hatch: single owner DSN for the
#                                          # runtime too (no constrained roles);
#                                          # also honors PERMISSIVE_DSN=1
#
# Re-run safety: an existing /etc/setjoin/config.env is the source of truth;
# its secrets and settings are preserved unless --force is given (and even then
# you are asked before any secret is rotated). The privileged-DSN split is a
# ONE-WAY migration: a pre-split config.env is backed up once and its
# DB_WORKER_DSN/DB_OWNER_DSN/DB_DIRECT_OWNER_DSN values are carried verbatim
# into the credential file — never regenerated, never re-merged.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Repo root: this script lives at mailserver/deploy/scripts/install.sh.
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

# Meet B1 Task 14: install_livekit_binary + render_livekit_yaml. It defines
# its own info()/die() fallbacks (for standalone use by
# test-livekit-render.sh), but bash resolves a function name at CALL time —
# this script's say()/info()/die(), defined below, are the last definition
# in the shell by the time anything actually calls them, so they win.
# shellcheck source=lib-livekit.sh
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"

# S3 admin-identity admission: whole-weak-value, repeated-pattern and length
# rules. Sourced (not inlined) so test-install-provision-render.sh can exercise
# the real predicate behaviourally instead of grepping its source text.
# shellcheck source=lib-s3-identity.sh
source "$ROOT/mailserver/deploy/scripts/lib-s3-identity.sh"

# Release trust roots for adopting a managed `current` (#507).
# shellcheck source=lib-release-roots.sh
source "$ROOT/mailserver/deploy/scripts/lib-release-roots.sh"

# The compiled unit catalog (pure readonly definitions — safe to source early).
# It lives here, not in the systemd step, because the privileged-DSN migration
# below re-renders the units via render_runtime_units BEFORE the systemd step
# runs; the step itself only adds daemon-reload/enable/start on top.
# shellcheck source=../generated/unit-catalog.sh
source "$ROOT/mailserver/deploy/generated/unit-catalog.sh"

CONFIG_DIR="${SETJOIN_CONFIG_DIR:-/etc/setjoin}"
CONFIG_ENV="$CONFIG_DIR/config.env"
# Privileged DB credential namespace (DEPLOY-004, r3): the credential file
# lives in a dedicated directory directly below CONFIG_DIR, and CONFIG_DIR
# itself is the root-controlled ANCESTOR of that namespace (it defaults to
# /etc/setjoin). Because CONFIG_DIR was historically chown'ed setjoin:setjoin,
# directory write permission there would let the runtime account rename the
# credential directory aside and plant a substitute — so the installer owns
# CONFIG_DIR root:root (0755, traverse-only for the runtime account) and the
# credential directory 0750 root:setjoin (traverse/list, no write). The
# conversion happens at ENTRY (prepare_credential_migration — a legacy
# pre-split install's setjoin-owned CONFIG_DIR is the migration input and is
# accepted there, then converted BEFORE anything is written below it); the
# posture block near the end of this script re-asserts the final posture.
DB_CRED_DIR="$CONFIG_DIR/db-credentials.d"
DB_CRED_FILE="$DB_CRED_DIR/db-credentials.env"
# The unit renderers substitute this token (lib-livekit.sh); keep the shell
# variable in lockstep with DB_CRED_FILE.
# shellcheck disable=SC2034  # consumed by render_mailserver_unit/render_authserver_unit in lib-livekit.sh
DB_CREDENTIALS_FILE="$DB_CRED_FILE"
BACKUP_SIGNING_KEY_FILE="$CONFIG_DIR/backup-signing-key"
INSTALL_DIR="${INSTALL_DIR:-/opt/setjoin}"
RUNTIME_DIR="$INSTALL_DIR/current"
DATA_DIR="${DATA_DIR:-/var/lib/setjoin}"
UPDATER_DATA_DIR="${UPDATER_DATA_DIR:-/var/lib/setjoin-updater}"
UPDATER_CONFIG_DIR="${UPDATER_CONFIG_DIR:-/etc/setjoin-updater}"
UPDATER_DSN_FILE="$UPDATER_CONFIG_DIR/updater-dsn"
UPDATER_OWNER_DSN_FILE="$UPDATER_CONFIG_DIR/owner-dsn"
UPDATER_EXECUTION_CONFIG="$UPDATER_CONFIG_DIR/execution.json"
UPDATER_RECOVERY_ACCESS_FILE="$UPDATER_CONFIG_DIR/recovery-access-key"
UPDATER_RECOVERY_SECRET_FILE="$UPDATER_CONFIG_DIR/recovery-secret-key"
UPDATER_RECOVERY_HMAC_FILE="$UPDATER_CONFIG_DIR/recovery-hmac-key"
UPDATER_PROBE_CREDENTIAL_FILE="$UPDATER_CONFIG_DIR/probe-credential.json"
UPDATER_APP_WORKER_DSN_FILE="$UPDATER_CONFIG_DIR/app-worker-dsn"
OFFICE_APP_MANIFEST="$CONFIG_DIR/office-managed-app-v1.json"
# Lives under UPDATER_DATA_DIR, not DATA_DIR: the updater unit runs as an
# unprivileged root (empty capability bounding set), so it cannot traverse the
# setjoin-owned 0700 DATA_DIR tree; its own tree is chowned root:root below.
OFFICE_APP_STATE_DIR="$UPDATER_DATA_DIR/appmarket/collabora-code"
CERT_DIR="$CONFIG_DIR/tls"

FORCE=false
NONINTERACTIVE="${NONINTERACTIVE:-0}"
PERMISSIVE_DSN="${PERMISSIVE_DSN:-0}"
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    --non-interactive|--noninteractive) NONINTERACTIVE=1 ;;
    --permissive-dsn) PERMISSIVE_DSN=1 ;;
  esac
done

say()  { printf '==> %s\n' "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

# ask <var> <prompt> <default> [redact-default]
#   4th arg "1" marks the default as a RECOVERED SECRET (e.g. the owner DSN on
#   a re-run): the default is never echoed — the prompt shows no value and only
#   hints "(configured — Enter to keep)". An empty answer keeps the configured
#   value; typing a new one replaces it. Without the marker (or with an empty
#   default) ask behaves exactly as before — non-secret defaults (hostname,
#   listen addr, S3 endpoint) stay visible.
ask() {
  local __var="$1" __prompt="$2" __default="${3:-}" __ans="" __redact="${4:-0}"
  if [ "$NONINTERACTIVE" = "1" ]; then
    printf -v "$__var" '%s' "$__default"
    return
  fi
  if [ -n "$__default" ] && [ "$__redact" != "1" ]; then
    read -r -p "  $__prompt [$__default]: " __ans
    printf -v "$__var" '%s' "${__ans:-$__default}"
  elif [ -n "$__default" ]; then
    read -r -p "  $__prompt (configured — Enter to keep): " __ans
    printf -v "$__var" '%s' "${__ans:-$__default}"
  else
    read -r -p "  $__prompt: " __ans
    printf -v "$__var" '%s' "$__ans"
  fi
}

ask_secret() { # ask_secret <var> <prompt> — no echo, no default
  local __var="$1" __prompt="$2" __ans=""
  if [ "$NONINTERACTIVE" = "1" ]; then
    printf -v "$__var" '%s' "${!__var:-}"
    return
  fi
  read -r -s -p "  $__prompt: " __ans; echo
  printf -v "$__var" '%s' "$__ans"
}

# ── Privileged-DB-credential namespace guard (DEPLOY-004, r2-1/r3-1) ──────────
# The credential file's OWN mode/owner cannot defend it: write permission on a
# directory permits rename and unlink of its entries regardless of each entry's
# owner or mode, so the whole chain (ancestor → credential directory →
# credential file) is validated, and a renamed-aside real directory can be
# restored from the documented `$cred_dir.old` repair convention. These
# functions are sourced/tested: test-install-provision-render.sh extracts them
# (the validate_known_hosts_file pattern) and drives them over sandboxed
# fixture trees, passing ITS OWN identity as the expected owner/group; the
# production literals (root/root/setjoin) live at this installer's call sites,
# where the lane pins them by pattern.
#
# verify_db_credentials_namespace ANCESTOR CRED_DIR CRED_FILE ROOT_OWNER ROOT_GROUP RUNTIME_GROUP
#   Validates every EXISTING member of the chain (existence, type, no symlinks,
#   exact ownership, exact mode: ancestor 0755 root:root with no group/other
#   write; directory 0750 root:"runtime group"; file 0600 root:"root group") —
#   a fully-absent chain (fresh/old-layout install) validates as 0. On any
#   posture failure it prints a reason naming whole-directory replacement and
#   returns 1.
verify_db_credentials_namespace() {
  local ancestor="$1" cred_dir="$2" cred_file="$3"
  local root_owner="$4" root_group="$5" runtime_group="$6"
  local p want st
  for p in "$ancestor" "$cred_dir" "$cred_file"; do
    if [ -L "$p" ]; then
      echo "privileged-credential namespace broken: $p is a symlink — symlink plants are never trusted" >&2
      return 1
    fi
  done
  # Full-chain existence: anything below implies everything above.
  if [ -e "$cred_file" ] && [ ! -d "$cred_dir" ]; then
    echo "privileged-credential namespace broken: $cred_file exists but $cred_dir is not a directory" >&2
    return 1
  fi
  if [ -e "$cred_dir" ] && [ ! -d "$ancestor" ]; then
    echo "privileged-credential namespace broken: $cred_dir exists but ancestor $ancestor is missing or not a directory" >&2
    return 1
  fi
  # Ancestor: root-owned, 0755 — writable by root only; the runtime account may
  # traverse, never write/rename/replace. This is the property that closes the
  # whole-directory-replacement vector by construction.
  if [ -e "$ancestor" ]; then
    want="$root_owner $root_group 755"
    st="$(stat -c '%U %G %a' "$ancestor" 2>/dev/null)" \
      || st="$(stat -f '%Su %Sg %Lp' "$ancestor" 2>/dev/null)" \
      || { echo "privileged-credential namespace broken: cannot stat ancestor $ancestor" >&2; return 1; }
    if [ ! -d "$ancestor" ] || [ "$st" != "$want" ]; then
      echo "privileged-credential namespace broken: ancestor $ancestor is '$st', want '$want' — a runtime-account-writable ancestor permits whole-directory replacement of the credential store" >&2
      return 1
    fi
  fi
  if [ -e "$cred_dir" ]; then
    want="$root_owner $runtime_group 750"
    st="$(stat -c '%U %G %a' "$cred_dir" 2>/dev/null)" \
      || st="$(stat -f '%Su %Sg %Lp' "$cred_dir" 2>/dev/null)" \
      || { echo "privileged-credential namespace broken: cannot stat $cred_dir" >&2; return 1; }
    if [ ! -d "$cred_dir" ] || [ "$st" != "$want" ]; then
      echo "privileged-credential namespace broken: credential directory $cred_dir is '$st', want '$want' — its posture does not match the installed store, which names a possible whole-directory replacement (the real directory was renamed aside and a substitute planted); refuse the substitute and restore the real directory" >&2
      return 1
    fi
  fi
  if [ -e "$cred_file" ]; then
    want="$root_owner $root_group 600"
    st="$(stat -c '%U %G %a' "$cred_file" 2>/dev/null)" \
      || st="$(stat -f '%Su %Sg %Lp' "$cred_file" 2>/dev/null)" \
      || { echo "privileged-credential namespace broken: cannot stat $cred_file" >&2; return 1; }
    if [ ! -f "$cred_file" ] || [ "$st" != "$want" ]; then
      echo "privileged-credential namespace broken: credential file $cred_file is '$st', want '$want' — refusing to trust it" >&2
      return 1
    fi
  fi
  return 0
}

# restore_db_credentials_namespace ANCESTOR CRED_DIR CRED_FILE ROOT_OWNER ROOT_GROUP RUNTIME_GROUP
#   Whole-directory-replacement recovery: when the credential directory at the
#   installed pathname fails validation, a real directory moved aside to
#   `$cred_dir.old` by the disruption (or by a root repair following the
#   printed guidance) is restored: the substitute at the live pathname is
#   quarantined (never trusted, never silently deleted), the real directory is
#   moved back, and the chain is re-validated. Returns 1 when no restorable
#   `.old` exists — the caller must refuse loud.
restore_db_credentials_namespace() {
  local ancestor="$1" cred_dir="$2" cred_file="$3"
  local root_owner="$4" root_group="$5" runtime_group="$6"
  local old="$cred_dir.old" quarantine
  if [ -L "$old" ] || [ ! -d "$old" ]; then
    echo "no restorable $old directory found — cannot undo the replacement" >&2
    return 1
  fi
  verify_db_credentials_namespace "$ancestor" "$old" "$old/db-credentials.env" \
    "$root_owner" "$root_group" "$runtime_group" || {
      echo "$old exists but does not carry the installed credential-store posture — refusing to restore it" >&2
      return 1
    }
  quarantine="${cred_dir}.planted.$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$cred_dir" "$quarantine" || {
    echo "could not quarantine the substitute at $cred_dir — refusing to overwrite it in place" >&2
    return 1
  }
  mv "$old" "$cred_dir" || {
    echo "restore failed mid-recovery: the real directory is at $quarantine — repair by hand" >&2
    return 1
  }
  verify_db_credentials_namespace "$ancestor" "$cred_dir" "$cred_file" \
    "$root_owner" "$root_group" "$runtime_group"
}

# ensure_db_credentials_namespace ANCESTOR CRED_DIR CRED_FILE ROOT_OWNER ROOT_GROUP RUNTIME_GROUP
#   Installer entry posture: accept an absent chain or a fully valid one;
#   on a broken one, attempt the documented restore and re-validate.
#   Returns 1 (reason already printed) when the caller must refuse.
ensure_db_credentials_namespace() {
  verify_db_credentials_namespace "$@" && return 0
  echo "attempting whole-directory-replacement restore from $2.old…" >&2
  restore_db_credentials_namespace "$@"
}

# migrate_privileged_dsn_split CONFIG_ENV CRED_DIR CRED_FILE RERENDER_FN
#   One-way, exactly-once migration of the privileged DB tiers out of a
#   pre-split config.env (DEPLOY-004 WP-1.5):
#     - credential file exists AND keys still in config.env → partial state:
#       refuse loud with the named repair (returns 1; caller dies);
#     - no keys in config.env → nothing to do (fresh or already split);
#     - otherwise: timestamped 0600 backup of config.env INSIDE the
#       root-controlled credential directory, credential file written from the
#       SAME values (never regenerated — rotation stays gen_or_keep and
#       --force-asked), the three lines stripped from config.env (other bytes
#       untouched), and RERENDER_FN invoked so the units immediately address
#       the new file. No automatic re-merge exists; rollback is runbook §4.6.
#   Ownership of the NAMESPACE ANCESTOR is converted to root-controlled by
#   prepare_credential_migration BEFORE this function runs, and the final
#   root:root / root:setjoin pins are re-asserted by the installer's posture
#   block: this function only asserts modes, so it stays executable by the
#   unprivileged hermetic lane.
migrate_privileged_dsn_split() {
  local config_env="$1" cred_dir="$2" cred_file="$3" rerender="$4"
  local key have_cfg=0 tmp stripped backup
  if [ -f "$config_env" ]; then
    for key in DB_WORKER_DSN DB_OWNER_DSN DB_DIRECT_OWNER_DSN; do
      if grep -Eq "^$key=" "$config_env" 2>/dev/null; then have_cfg=1; fi
    done
  fi
  if [ -e "$cred_file" ] && [ "$have_cfg" = "1" ]; then
    echo "partial privileged-DSN split state: $cred_file exists AND one of DB_WORKER_DSN/DB_OWNER_DSN/DB_DIRECT_OWNER_DSN is still present in $config_env" >&2
    echo "repair (pick one):" >&2
    echo "  (a) confirm $cred_file carries the values from the newest $cred_dir/config.env.pre-dsn-split.* backup, then strip the three lines: sed '/^DB_WORKER_DSN=/d;/^DB_OWNER_DSN=/d;/^DB_DIRECT_OWNER_DSN=/d' $config_env > ${config_env}.repaired && cat ${config_env}.repaired > $config_env && rm ${config_env}.repaired" >&2
    echo "  (b) or restore $config_env from that backup, remove $cred_file, and re-run install.sh to redo the migration" >&2
    return 1
  fi
  [ "$have_cfg" = "1" ] || return 0
  mkdir -p "$cred_dir"
  chmod 0750 "$cred_dir"
  backup="$cred_dir/config.env.pre-dsn-split.$(date -u +%Y%m%dT%H%M%SZ)"
  ( umask 077; cat "$config_env" > "$backup" )
  chmod 0600 "$backup"
  tmp="$(mktemp "${TMPDIR:-/tmp}/setjoin-dsn-split.XXXXXX")"
  {
    printf '# setjoin privileged DB credential tier — migrated verbatim from %s by deploy/scripts/install.sh.\n' "$config_env"
    printf '# 0600 root:root below the root-owned credential directory; never merged back into config.env.\n'
    grep -E '^DB_WORKER_DSN=|^DB_OWNER_DSN=|^DB_DIRECT_OWNER_DSN=' "$config_env"
  } > "$tmp"
  chmod 0600 "$tmp"
  ( umask 077; cat "$tmp" > "$cred_file" )
  rm -f "$tmp"
  chmod 0600 "$cred_file"
  # Strip exactly the three lines; every other byte of config.env is preserved.
  stripped="$(mktemp "${TMPDIR:-/tmp}/setjoin-dsn-strip.XXXXXX")"
  grep -vE '^DB_WORKER_DSN=|^DB_OWNER_DSN=|^DB_DIRECT_OWNER_DSN=' "$config_env" > "$stripped" || true
  cat "$stripped" > "$config_env"
  rm -f "$stripped"
  # Re-render the units so consumers address the new file immediately (the
  # systemd step re-renders again with the final prompt state).
  "$rerender"
  if command -v info >/dev/null 2>&1; then
    info "Migrated privileged DB tiers to $cred_file (0600); config.env backed up to $backup."
  fi
  return 0
}

# render_runtime_units — render every enabled unit from its template through
# the compiled catalog's typed renderer (arch review #A11 seam). Called by the
# systemd step on every install AND by migrate_privileged_dsn_split right after
# it strips config.env, so a migrated install never keeps unit files that point
# consumers at config.env alone. MEET_CAPTIONS_ENABLED may be unset at
# migration time (the prompts have not run yet) — it defaults to false there;
# the systemd step always re-renders with the final value.
render_runtime_units() {
  local unit feature template destination renderer
  for unit in "${SETJOIN_ALL_UNITS[@]}"; do
    feature="${SETJOIN_UNIT_FEATURE[$unit]}"
    if [ "$feature" = "captions" ] && [ "${MEET_CAPTIONS_ENABLED:-false}" != "true" ]; then
      continue
    fi
    template="$ROOT/mailserver/deploy/${SETJOIN_UNIT_TEMPLATE[$unit]}"
    destination="${SETJOIN_UNIT_DESTINATION[$unit]}"
    renderer="${SETJOIN_UNIT_RENDERER[$unit]}"
    [ -f "$template" ] || die "required fixed unit template is missing: $template"
    "$renderer" "$template" "$destination" \
      || die "failed to render $destination — see the error above."
  done
}

# prepare_credential_migration ANCESTOR CRED_DIR CRED_FILE CONFIG_ENV RERENDER_FN ROOT_OWNER ROOT_GROUP RUNTIME_GROUP
#   The REAL legacy-migration ordering (DEPLOY-004; Astra L2-C8 impl HOLD fix).
#   The old ordering could never migrate a real legacy install: entry
#   validation demanded a root-owned ANCESTOR before the migration that
#   CREATES the credential chain, the ownership conversion only ran in the
#   late posture block, and the migration's unit re-render fired while
#   renderer inputs (AUTH_ENV) were still unassigned — the real renderer
#   refuses that state. The ordering here is:
#     1. Entry validation. A credential chain that ALREADY exists must carry
#        the full root-controlled posture (validate-or-restore). A chain that
#        does NOT exist beneath a not-yet-root-controlled ancestor is the
#        PRE-SPLIT legacy state — that state IS the migration input — and is
#        accepted here (only the symlink sanity applies); the conversion in
#        step 2 re-owns the ancestor before anything is written below it.
#     2. Privileged-dir conversion FIRST: ANCESTOR → root-controlled posture,
#        so the credential file is born inside a directory the runtime
#        account cannot rename/replace.
#     3. Only then the one-way credential migration; its $rerender hook fires
#        with every renderer input already assigned by the caller (AUTH_ENV
#        included — see the entry block).
#   The production literals (root/root/setjoin) live at the call sites; like
#   the guard functions above, the parameters keep this executable by the
#   unprivileged hermetic lane, which passes its own identity.
prepare_credential_migration() {
  local ancestor="$1" cred_dir="$2" cred_file="$3" config_env="$4" rerender="$5"
  local root_owner="$6" root_group="$7" runtime_group="$8" st
  if [ -e "$cred_dir" ] || [ -e "$cred_file" ]; then
    ensure_db_credentials_namespace "$ancestor" "$cred_dir" "$cred_file" \
      "$root_owner" "$root_group" "$runtime_group" || return 1
  else
    if [ -L "$ancestor" ]; then
      echo "privileged-credential namespace broken: $ancestor is a symlink — symlink plants are never trusted" >&2
      return 1
    fi
    st="$(stat -c '%U' "$ancestor" 2>/dev/null || stat -f '%Su' "$ancestor" 2>/dev/null || true)"
    if [ -d "$ancestor" ] && [ "$st" != "$root_owner" ]; then
      echo "legacy pre-split install: $ancestor is '$st'-owned — that state IS the migration input; converting it to the root-controlled credential-ancestor posture before the migration writes anything below it" >&2
    fi
  fi
  # Privileged-dir conversion — idempotent: also pins the fresh-install path
  # and re-asserts the posture the final block checks at the end of the run.
  if [ -d "$ancestor" ]; then
    chown "$root_owner:$root_group" "$ancestor" || return 1
    chmod 0755 "$ancestor" || return 1
  fi
  migrate_privileged_dsn_split "$config_env" "$cred_dir" "$cred_file" "$rerender" || return 1
}

# get_env_from FILE KEY — read a value from an arbitrary env file (empty if
# absent). get_env stays the config.env reader; get_cred_env reads the
# privileged DB credential file the same way.
get_env_from() {
  local file="$1"
  [ -f "$file" ] || { echo ""; return; }
  grep -E "^$2=" "$file" 2>/dev/null | tail -1 | cut -d= -f2- || echo ""
}
get_env() { get_env_from "$CONFIG_ENV" "$1"; }

# get_cred_env KEY — read a privileged DB tier from the credential file.
# Used ONLY for re-run recovery (owner/worker DSN defaults, worker password
# reuse); first-install generation renders the file directly, and rotation
# stays gen_or_keep/--force-asked. The namespace posture is validated at
# installer entry before any of these reads trust the file.
get_cred_env() { get_env_from "$DB_CRED_FILE" "$1"; }

# ── 0. Preconditions ────────────────────────────────────────────────────────
say "setjoin single-node install (scope: <100 users; 100+/HA → docs/guides/HA_OVERVIEW.md)"

[ "$(id -u)" = "0" ] || die "must run as root (sudo). It installs to $INSTALL_DIR and writes a systemd unit."

for tool in psql openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' not found — install it first (see docs/guides/SINGLE_NODE_SETUP.md prereqs)."
done

# Source an existing config so re-runs preserve settings/secrets.
if [ -f "$CONFIG_ENV" ]; then
  info "Found existing $CONFIG_ENV — preserving its settings and secrets (use --force to change)."
fi

# ── Privileged-DSN namespace + one-way split migration (DEPLOY-004) ──────────
# The REAL legacy-migration ordering (Astra L2-C8 HOLD fix): a PRE-SPLIT
# install owns CONFIG_DIR setjoin:setjoin — that state IS the migration input,
# so entry validation accepts it, the privileged-dir conversion runs FIRST,
# and only then does the migration write the credential file, inside an
# already root-controlled ancestor. The migration's unit re-render fires with
# every renderer input assigned: AUTH_ENV (a pure path constant, assigned
# here) and CONTAINER_BIN (detected here — the egress sidecar is
# unconditional, so every install needs it) both exist BEFORE
# render_runtime_units runs; the old ordering re-rendered while AUTH_ENV was
# still unassigned and the real renderer refused that state. Everything here
# still runs before ANY consumer read (prompt defaults, worker-password
# recovery) can trust the credential file, and before the fresh-install render
# below. The production posture literals live here and at the posture block.
AUTH_ENV="$CONFIG_DIR/auth.env"
# The Rust front door's own env file (#264) — a render_gateway_unit input, so
# it is assigned before the entry migration re-renders the units.
GATEWAY_ENV="$CONFIG_DIR/gateway.env"
FEDERATION_ENV="$CONFIG_DIR/federation.env"
TLS_ENV="$CONFIG_DIR/tls.env"
SMTP_ENV="$CONFIG_DIR/smtp.env"
CONTAINER_BIN="$(detect_container_runtime)"
if ! prepare_credential_migration "$CONFIG_DIR" "$DB_CRED_DIR" "$DB_CRED_FILE" "$CONFIG_ENV" render_runtime_units root root setjoin; then
  die "privileged-credential entry posture/migration failed — refusing to continue (reason above). Restore the real $DB_CRED_DIR (see the .old repair convention printed above) or apply the printed split repair, then re-run."
fi

# ── 1. Core settings (prompt; default to existing config when present) ───────
say "Core settings"
DEF_HOSTNAME="$(get_env HOSTNAME)"; DEF_HOSTNAME="${DEF_HOSTNAME:-mail.example.com}"
DEF_LISTEN="$(get_env LISTEN_ADDR)"; DEF_LISTEN="${DEF_LISTEN:-:443}"
# The DSN prompted here is the OWNER/ADMIN credential: it creates the database,
# loads the schema + reducers, and is persisted as DB_OWNER_DSN in the
# privileged credential file (NOT config.env — DEPLOY-004 split; the same
# migration above carries pre-split values over) as the DDL/partition identity.
# The RUNTIME connects as the constrained setjoin_app /
# setjoin_worker roles derived below (native-RLS credential shape, the default
# since 2026-07-03 — docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md) unless
# --permissive-dsn / PERMISSIVE_DSN=1 opts back into the single permissive DSN.
# On a re-run, prefer the persisted owner DSN (credential file first, then a
# pre-split config.env) over DB_DSN (which is the app role's DSN in the
# constrained shape).
# A recovered default IS a secret (the persisted owner DSNs carry passwords):
# DEF_*_RECOVERED marks it so the ask below redacts the default-value prompt
# (it must never echo the DSN back). A first install recovers nothing and
# shows its non-secret stock suggestion plainly.
DEF_DBDSN_RECOVERED=0
DEF_DBDSN="$(get_cred_env DB_OWNER_DSN)"
[ -n "$DEF_DBDSN" ] || DEF_DBDSN="$(get_env DB_OWNER_DSN)"
[ -n "$DEF_DBDSN" ] || DEF_DBDSN="$(get_env DB_DSN)"
if [ -n "$DEF_DBDSN" ]; then
  DEF_DBDSN_RECOVERED=1
else
  DEF_DBDSN="postgres://mail@127.0.0.1:5432/mailserver?sslmode=disable"
fi
DEF_DIRECT_RECOVERED=0
DEF_DIRECT="$(get_cred_env DB_DIRECT_OWNER_DSN)"
[ -n "$DEF_DIRECT" ] || DEF_DIRECT="$(get_env DB_DIRECT_OWNER_DSN)"
# Legacy (pre-flip) config compat: its DB_DIRECT_DSN is the owner's direct DSN
# (in the constrained shape that key holds the app role's, so skip it there).
if [ -z "$DEF_DIRECT" ]; then
  case "$(get_env DB_DIRECT_DSN)" in
    postgres://setjoin_app:*|postgres://setjoin_worker:*) : ;;
    *) DEF_DIRECT="$(get_env DB_DIRECT_DSN)" ;;
  esac
fi
if [ -n "$DEF_DIRECT" ]; then
  DEF_DIRECT_RECOVERED=1
else
  DEF_DIRECT="$DEF_DBDSN"
  DEF_DIRECT_RECOVERED="$DEF_DBDSN_RECOVERED"
fi
DEF_S3="$(get_env S3_ENDPOINT)"; DEF_S3="${DEF_S3:-127.0.0.1:9000}"

ask HOSTNAME      "Public hostname / mail domain" "$DEF_HOSTNAME"
ask LISTEN_ADDR   "HTTPS listen address"          "$DEF_LISTEN"
ask DB_DSN        "Owner/admin DB DSN (schema owner; loads + migrates the schema)" "$DEF_DBDSN" "$DEF_DBDSN_RECOVERED"
ask DB_DIRECT_DSN "Direct owner DB DSN (non-pooled; LISTEN/NOTIFY host)" "$DEF_DIRECT" "$DEF_DIRECT_RECOVERED"
ask S3_ENDPOINT   "S3 / SeaweedFS endpoint"       "$DEF_S3"

# Until the constrained runtime DSNs are derived below, DB_DIRECT_DSN is the
# operator-supplied direct owner connection. Keep an explicit shell identity
# for every later owner-only consumer. In particular, the root-owned updater
# credential renderer runs before config.env is rewritten and must not depend
# on a variable that exists only as text inside DSN_BLOCK.
DB_DIRECT_OWNER_DSN="$DB_DIRECT_DSN"

# Auth server upstream: loopback-only, standardized on authserverd's stock
# port 8443 (also the gateway's compiled default — but written EXPLICITLY into
# config.env below: explicit beats compiled default, and the 2026-07-06 real
# :443 deploy 502'd on every /auth/login exactly because nothing pinned the
# gateway upstream and the auth listen port together). The dev reference
# (scripts/deploy-and-test.sh) runs auth on 8444 only because ITS gateway
# squats 8443 — do not copy that port here.
AUTHSERVER_URL="$(get_env AUTHSERVER_URL)"; AUTHSERVER_URL="${AUTHSERVER_URL:-http://127.0.0.1:8443}"
AUTH_LISTEN="${AUTHSERVER_URL#http://}"; AUTH_LISTEN="${AUTH_LISTEN#https://}"; AUTH_LISTEN="${AUTH_LISTEN%%/*}"
# AUTH_ENV itself is assigned at the entry block above (a pure path constant
# and a required renderer input — the migration's unit re-render fires before
# this point and render_authserver_unit refuses an unassigned AUTH_ENV).

ADMIN_EMAIL="$(get_env SETJOIN_ADMIN_EMAIL)"
if [ -z "$ADMIN_EMAIL" ]; then
  ask ADMIN_EMAIL "Initial admin email" "admin@${HOSTNAME#mail.}"
  ask_secret ADMIN_PASSWORD "Initial admin password (min 12 chars)"
fi

# Parse the DB name/host/port/user out of the direct DSN for the load steps.
# Strip scheme + query; tolerate user[:pass]@host[:port]/db.
_dsn="${DB_DIRECT_DSN#postgres://}"; _dsn="${_dsn#postgresql://}"; _dsn="${_dsn%%\?*}"
DB_USERHOST="${_dsn%/*}"; DB_NAME="${_dsn##*/}"
DB_USER="${DB_USERHOST%@*}"; DB_HOSTPORT="${DB_USERHOST##*@}"
DB_USER="${DB_USER%%:*}"; [ "$DB_USER" = "$DB_HOSTPORT" ] && DB_USER="mail"
DB_HOST="${DB_HOSTPORT%%:*}"; DB_PORT="${DB_HOSTPORT##*:}"
[ "$DB_PORT" = "$DB_HOST" ] && DB_PORT="5432"
DB_HOST="${DB_HOST:-127.0.0.1}"; DB_NAME="${DB_NAME:-mailserver}"

# ── Runtime credential shape (native-RLS three-role model) ───────────────────
# Default: the gateway/authserver RUNTIME connects as setjoin_app (constrained
# by FORCE'd RLS), cross-tenant background jobs as setjoin_worker (BYPASSRLS),
# and only migrations/partition DDL as the owner DSN prompted above — the same
# shape the e2e harness runs permanently (start-test-stack.sh; runbook:
# docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md). ROLLBACK (runbook §4.6): point
# DB_DSN/DB_DIRECT_DSN in config.env back at the DB_OWNER_DSN value and
# restart — no migration to undo. --permissive-dsn keeps the old single-DSN
# shape end to end.
# dsn_password <dsn> — extract the password from a user:pw@host DSN (empty if none).
dsn_password() {
  local d="${1#postgres://}"; d="${d#postgresql://}"
  case "$d" in
    *@*) d="${d%%@*}"; case "$d" in *:*) printf '%s' "${d#*:}";; esac ;;
  esac
}

# Stock Debian/Ubuntu loopback TCP uses SCRAM. When the owner DSN carries a
# password, make it available to every explicit -h/-U psql call below. Keep
# an operator-supplied PGPASSWORD when the DSN is intentionally passwordless
# (for example, a local environment that manages credentials externally).
OWNER_DB_PASSWORD="$(dsn_password "$DB_DIRECT_DSN")"
if [ -n "$OWNER_DB_PASSWORD" ]; then
  export PGPASSWORD="$OWNER_DB_PASSWORD"
fi
if [ "$PERMISSIVE_DSN" != "1" ]; then
  # Re-run idempotency: reuse the app/worker passwords already persisted in the
  # existing DSNs (app-role DB_DSN in config.env; the privileged worker tier in
  # the credential file, preferring it over any pre-split config.env copy);
  # generate fresh ones only on first install.
  APP_PW=""; WORKER_PW=""
  case "$(get_env DB_DSN)" in postgres://setjoin_app:*) APP_PW="$(dsn_password "$(get_env DB_DSN)")" ;; esac
  _worker_dsn="$(get_cred_env DB_WORKER_DSN)"
  [ -n "$_worker_dsn" ] || _worker_dsn="$(get_env DB_WORKER_DSN)"
  case "$_worker_dsn" in postgres://setjoin_worker:*) WORKER_PW="$(dsn_password "$_worker_dsn")" ;; esac
  [ -n "$APP_PW" ]    || { APP_PW="$(openssl rand -hex 24)";    info "setjoin_app password: generated"; }
  [ -n "$WORKER_PW" ] || { WORKER_PW="$(openssl rand -hex 24)"; info "setjoin_worker password: generated"; }
  # Rebuild host[:port]/db[?query] from the owner DSNs, swapping in role creds.
  _pq=""; case "$DB_DSN" in *\?*) _pq="?${DB_DSN#*\?}";; esac
  _ph="${DB_DSN#postgres://}"; _ph="${_ph#postgresql://}"; _ph="${_ph%%\?*}"
  case "$_ph" in *@*) _ph="${_ph#*@}";; esac
  _dq=""; case "$DB_DIRECT_DSN" in *\?*) _dq="?${DB_DIRECT_DSN#*\?}";; esac
  RUNTIME_DB_DSN="postgres://setjoin_app:${APP_PW}@${_ph}${_pq}"
  RUNTIME_WORKER_DSN="postgres://setjoin_worker:${WORKER_PW}@${_ph}${_pq}"
  RUNTIME_DIRECT_DSN="postgres://setjoin_app:${APP_PW}@${DB_HOST}:${DB_PORT}/${DB_NAME}${_dq}"
fi

# ── 2. Build binaries if missing ─────────────────────────────────────────────
say "Binaries"
if [ ! -x "$ROOT/mailserver/mailserverd" ] ||
   [ ! -x "$ROOT/mailserver/setjoin-updater" ] ||
   [ ! -x "$ROOT/authserver/authserverd" ]; then
  command -v go >/dev/null 2>&1 || die "binaries missing and 'go' not found — install Go or pre-build with: bash scripts/build.sh"
  info "Building (bash scripts/build.sh)…"
  ( cd "$ROOT" && bash scripts/build.sh )
else
  info "Reusing existing build artifacts."
fi
# Use the Rust artifact's canonical path: an old Go mailctl in a source tree
# cannot satisfy this check. Release archives provide this executable directly.
if [ ! -x "$ROOT/server-rust/mailctl" ]; then
  command -v cargo >/dev/null 2>&1 || die "Rust mailctl missing and 'cargo' not found — use a release archive or install the Rust toolchain."
  ( cd "$ROOT/server-rust" && cargo build --release --locked -p setjoin-mailctl )
  install -m 0755 "${CARGO_TARGET_DIR:-$ROOT/server-rust/target}/release/mailctl" "$ROOT/server-rust/mailctl"
fi
# One native updater/recovery process; frozen Go is only the Office companion (#300).
UPDATER_SOURCE="$ROOT/server-rust/setjoin-updater"
if [ ! -x "$UPDATER_SOURCE" ]; then
  command -v cargo >/dev/null 2>&1 || die "Rust updater/recovery missing — use a release archive or install cargo."
  ( cd "$ROOT/server-rust" && cargo build --release --locked -p setjoin-updater )
  install -m 0755 "${CARGO_TARGET_DIR:-$ROOT/server-rust/target}/release/setjoin-updater" "$UPDATER_SOURCE"
fi
# Refuse before schema/runtime changes. Final install repeats this under both locks.
"$UPDATER_SOURCE" check-swap --state-dir "$UPDATER_DATA_DIR/journal" --dsn-file "$UPDATER_DSN_FILE" \
  || die "updater swap refused: finish or recover the in-progress update with the installed updater first."
# The Rust front door (#264, ARCH-027) ships beside the Go binaries: a release
# archive stages it at server-rust/setjoin-gateway; a source checkout builds it.
GATEWAY_SOURCE="$ROOT/server-rust/setjoin-gateway"
if [ ! -x "$GATEWAY_SOURCE" ]; then
  command -v cargo >/dev/null 2>&1 || die "setjoin-gateway missing ($GATEWAY_SOURCE) and 'cargo' not found — use a release archive or install the Rust toolchain."
  info "Building setjoin-gateway (cargo build --release)…"
  ( cd "$ROOT/server-rust" && CARGO_TARGET_DIR="$ROOT/server-rust/target" cargo build --release --locked -p setjoin-gateway )
  install -m 0755 "$ROOT/server-rust/target/release/setjoin-gateway" "$GATEWAY_SOURCE"
fi

# setjoin-sfu (LiveKit) — pinned v1.13.5 release binary, sha256-verified
# against the hard-coded checksums in lib-livekit.sh (Meet B1 Task 14 / spike
# §6.1-§6.2). Re-run safe: skipped once the version stamp matches.
command -v curl >/dev/null 2>&1 || die "'curl' not found — needed to download the LiveKit SFU binary."
install_livekit_binary "$INSTALL_DIR/bin/livekit-server"

# Meet B2 (Task 9): Valkey (the SFU<->Egress message bus, D7) + the pinned
# Egress container. Provisioned unconditionally, same posture as the SFU
# itself — feature.meet_recording (DB toggle, seeded OFF) gates actual use,
# never deploy-time provisioning.
command -v valkey-server >/dev/null 2>&1 || die "valkey-server not found — install the distro package (apt install valkey-server / dnf install valkey) and re-run."
command -v valkey-cli >/dev/null 2>&1 || die "valkey-cli not found — install the distro package (apt install valkey-server / dnf install valkey) and re-run (needed for the post-start PING health probe)."
# CONTAINER_BIN was detected once at the entry block (the migration's unit
# re-render needs it for the egress unit) — reported here, where the SFU/Egress
# provisioning that depends on it begins.
info "Container runtime: $CONTAINER_BIN"
# Digest-pinned = content-addressed: an image already present locally IS the
# pinned image, so a re-run must not depend on registry availability (on-prem
# re-runs behind flaky/offline egress — a live aliyuncs manifest 404 killed a
# re-run on the 2026-07-16 fresh-VM gate while the image sat locally).
if "$CONTAINER_BIN" image inspect "$EGRESS_IMAGE" >/dev/null 2>&1; then
  info "Pinned Egress image already present locally (digest-addressed) — skipping pull."
else
  info "Pulling pinned Egress image $EGRESS_IMAGE (digest-verified — a MITM'd registry cannot satisfy the digest)…"
  "$CONTAINER_BIN" pull "$EGRESS_IMAGE" >/dev/null || die "failed to pull $EGRESS_IMAGE — check network access / registry credentials."
fi

# Meet B3 (Task 16): live captions (setjoin-asr-bot + setjoin-funasr) —
# UNLIKE the SFU/Valkey/Egress trio above, this leg is OPTIONAL and NOT
# provisioned by default: it downloads a ~840MB pinned model + pulls a
# ~1GB pinned container image, for a feature that (like recording) ships
# behind feature.meet_captions seeded OFF. --force does not re-prompt this
# (it is not a secret); re-run with a different answer to change it.
# Hardcoded to match setjoin-funasr.service.template's own mount source
# EXACTLY (that template does not parameterize it — the plan's own file
# spec hardcodes it too) — deliberately NOT "$DATA_DIR/funasr-models": a
# customized DATA_DIR would otherwise silently diverge from the unit's own
# unparameterized bind mount, downloading models to one path while the
# container reads from another.
FUNASR_MODELS_DIR="/var/lib/setjoin/funasr-models"
MEET_CAPTIONS_ENABLED="$(get_env MEET_CAPTIONS_ENABLED)"; MEET_CAPTIONS_ENABLED="${MEET_CAPTIONS_ENABLED:-false}"
ask MEET_CAPTIONS_ENABLED "Enable Meet live captions (setjoin-asr-bot + setjoin-funasr — downloads a pinned ASR model + container image; feature.meet_captions still separately gates actual use)?" "$MEET_CAPTIONS_ENABLED"
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  case "$FUNASR_IMAGE" in
    ""|*CHANGEME*) die "FUNASR_IMAGE is unpinned (CHANGEME-pin-at-deploy sentinel) in lib-livekit.sh — refusing to enable Meet captions. Pin it first, or re-run and answer 'false' to this prompt (MEET_CAPTIONS_ENABLED=false)." ;;
  esac
  # The Rust captions bot (#356; pure Rust, no libopus): staged by the release archive at
  # server-rust/asrbotd, built from a source checkout otherwise.
  if [ ! -x "$ROOT/server-rust/asrbotd" ]; then
    command -v cargo >/dev/null 2>&1 || die "MEET_CAPTIONS_ENABLED=true but $ROOT/server-rust/asrbotd is missing and 'cargo' not found — use a release archive or install the Rust toolchain."
    info "Building asrbotd (cargo build --release)…"
    ( cd "$ROOT/server-rust" && CARGO_TARGET_DIR="$ROOT/server-rust/target" cargo build --release --locked -p setjoin-asrbot )
    install -m 0755 "$ROOT/server-rust/target/release/asrbotd" "$ROOT/server-rust/asrbotd"
  fi
  if "$CONTAINER_BIN" image inspect "$FUNASR_IMAGE" >/dev/null 2>&1; then
    info "Pinned FunASR image already present locally (digest-addressed) — skipping pull."
  else
    info "Pulling pinned FunASR image $FUNASR_IMAGE (digest-verified)…"
    "$CONTAINER_BIN" pull "$FUNASR_IMAGE" >/dev/null || die "failed to pull $FUNASR_IMAGE — check network access / registry credentials."
  fi
  info "Installing the pinned FunASR streaming model (see lib-livekit.sh's honesty-ledger note — companion models are NOT pinned by this leg)…"
  install_funasr_models "$FUNASR_MODELS_DIR"
fi

# ── 3. Generate + persist secrets (idempotent: never clobber without --force) ─
say "Secrets"
gen_or_keep() { # gen_or_keep VAR generator-cmd
  local var="$1" gen="$2" existing
  existing="$(get_env "$var")"
  if [ -n "$existing" ] && ! $FORCE; then
    printf -v "$var" '%s' "$existing"
    info "$var: kept existing"
  elif [ -n "$existing" ] && $FORCE; then
    if [ "$NONINTERACTIVE" = "1" ]; then
      printf -v "$var" '%s' "$existing"; info "$var: kept (non-interactive --force won't rotate silently)"
    else
      read -r -p "  Rotate $var? Existing data may become unreadable. (yes/no) [no]: " yn
      if [ "$yn" = "yes" ]; then printf -v "$var" '%s' "$(eval "$gen")"; info "$var: ROTATED"
      else printf -v "$var" '%s' "$existing"; info "$var: kept"; fi
    fi
  else
    printf -v "$var" '%s' "$(eval "$gen")"; info "$var: generated"
  fi
}
gen_or_keep DB_ENCRYPTION_KEY "openssl rand -hex 16"     # 32 hex = 16 bytes (standard profile)
gen_or_keep JWT_SECRET        "openssl rand -hex 32"
gen_or_keep AUDIT_HMAC_KEY     "openssl rand -hex 32"
gen_or_keep INTERNAL_API_KEY  "openssl rand -hex 32"
# One-time setup token (owner decision A3): required by the setup calls on the
# local control socket (X-Setup-Token on /setup/preflight, /setup/restore) and
# PRINTED in the end-of-install summary below. Effectively one-time: both
# endpoints refuse once the system is initialized, and the completion-state
# endpoint 404s after that. gen_or_keep keys re-run recovery off the SAME
# config.env name (SETJOIN_SETUP_TOKEN), so a re-run keeps the existing token —
# no silent rotation.
gen_or_keep SETJOIN_SETUP_TOKEN "openssl rand -hex 32"
gen_or_keep S3_ACCESS_KEY     "openssl rand -hex 16"
gen_or_keep S3_SECRET_KEY     "openssl rand -hex 24"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$BACKUP_SIGNING_KEY_FILE" ]; then
  umask 077
  openssl rand -hex 32 > "$BACKUP_SIGNING_KEY_FILE"
  info "backup signing key: generated"
else
  info "backup signing key: kept existing"
fi
chmod 600 "$BACKUP_SIGNING_KEY_FILE"

# Privileged DB credential tier (DEPLOY-004 split, law 3): rendered
# UNCONDITIONALLY in both postures (Astra L2-C8 HOLD fix) — the units' second
# EnvironmentFile= and the ownership block below are unconditional, so a fresh
# --permissive-dsn install must also produce the file; the postures differ
# only in CONTENT:
#   - constrained (default): the three privileged tiers, generated in the
#     SAME single step as the DSNs they derive from (the constrained-shape
#     block in step 1);
#   - permissive: no constrained roles exist, so the file carries the two
#     owner tiers only — the same single owner credential config.env's
#     DB_DSN/DB_DIRECT_DSN hold — keeping one authoritative location for
#     upgrade.sh's owner-tier probe and this installer's re-run recovery.
# Never into config.env, which is chown'ed to and injected into the account
# running both internet-facing services. A re-run lands here only after the
# entry migration has already carried any pre-split values over; the rebuild
# uses the recovered passwords, so the file's values are byte-stable across
# re-runs and --force never rotates them silently (rotation stays
# prompt-gated).
if [ -L "$DB_CRED_DIR" ] || [ -L "$DB_CRED_FILE" ]; then
  die "$DB_CRED_DIR or $DB_CRED_FILE is a symlink — refusing to write through it."
fi
if [ "$PERMISSIVE_DSN" != "1" ]; then
  [ -n "${RUNTIME_WORKER_DSN:-}" ] || die "RUNTIME_WORKER_DSN missing — refusing to render the privileged DB credential file."
  ( umask 077
    mkdir -p "$DB_CRED_DIR"
    cat > "$DB_CRED_FILE" <<ENV
# setjoin privileged DB credential tier — generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by deploy/scripts/install.sh.
# Mode 0600 root:root below the root-owned $DB_CRED_DIR — NEVER merged back
# into config.env (the runtime-account-readable config surface). Consumers:
#   - EnvironmentFile= of setjoin.service and setjoin-auth.service (systemd
#     parses EnvironmentFile manager-side, as root)
#   - upgrade.sh's schema-apply DSN probe (owner keys preferred)
#   - install.sh re-runs (owner/worker DSN + password recovery)
DB_WORKER_DSN=$RUNTIME_WORKER_DSN
DB_OWNER_DSN=$DB_DSN
DB_DIRECT_OWNER_DSN=$DB_DIRECT_DSN
ENV
  )
else
  ( umask 077
    mkdir -p "$DB_CRED_DIR"
    cat > "$DB_CRED_FILE" <<ENV
# setjoin privileged DB credential tier — generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by deploy/scripts/install.sh.
# --permissive-dsn posture: no constrained roles exist on this install, so the
# owner tiers below are the only privileged DB credentials (the same values
# config.env's DB_DSN/DB_DIRECT_DSN carry). Mode 0600 root:root below the
# root-owned $DB_CRED_DIR — NEVER merged back into config.env.
DB_OWNER_DSN=$DB_DSN
DB_DIRECT_OWNER_DSN=$DB_DIRECT_DSN
ENV
  )
fi
chmod 600 "$DB_CRED_FILE"
chmod 0750 "$DB_CRED_DIR"
info "Privileged DB tiers written to $DB_CRED_FILE (0600 root:root) — config.env no longer carries them."

# S3 admin identity — INSTALL-TIME GENERATION (med-deploy-s3-credentials-b1r2-001,
# D-MAILSERVER-DEPLOY-001). The SAME S3_ACCESS_KEY/S3_SECRET_KEY generated above
# (law 3: one secret, one generation step) are rendered into the server-side S3
# identity config the SeaweedFS deployment loads via -s3.config:
#   - single-node: $CONFIG_DIR/seaweedfs-s3.json, bind-mounted read-only into
#     the pinned container (SINGLE_NODE_SETUP.md step 3 previously made the
#     operator hand-write this file pointing at the installer keys — the
#     installer now renders it itself);
#   - HA: the deploy wizard seeds the same generated-identity contract into
#     each node's /etc/mail/seaweedfs-s3.json (internal/deploy).
# Deployment-time rejection runs BEFORE the file a deployment loads can exist:
# a well-known pair (minioadmin/minioadmin — the vendor default, which a
# pre-seeded config.env could carry in) or empty credential material refuses
# the install loud instead of booting an authenticatable-as-anyone S3 gateway.
# ROTATION: --force rotating S3_ACCESS_KEY/S3_SECRET_KEY (each asked
# individually above) rewrites this file with the new pair in the same run;
# restart the SeaweedFS container/service afterwards.
# Whole-weak-value, repeated-pattern and length admission (lib-s3-identity.sh;
# see its header for why each rule exists and how to rotate).
_s3_reason="$(s3_identity_admit "$S3_ACCESS_KEY" "$S3_SECRET_KEY")" \
  || die "$_s3_reason"
S3_IAM_FILE="$CONFIG_DIR/seaweedfs-s3.json"
( umask 077
  cat > "$S3_IAM_FILE" <<JSON
{
  "identities": [
    {
      "name": "admin",
      "credentials": [
        {"accessKey": "$S3_ACCESS_KEY", "secretKey": "$S3_SECRET_KEY"}
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
JSON
)
chmod 600 "$S3_IAM_FILE"
info "S3 identity config: $S3_IAM_FILE (0600) — point the SeaweedFS container's -s3.config at it (SINGLE_NODE_SETUP.md step 3)."
# Meet B1 (Task 14): the ONE secret, ONE generation step (spike §2 finding
# 3) — this SAME value is rendered into BOTH config.env's LIVEKIT_API_SECRET
# (below) and /etc/setjoin/livekit.yaml's keys.setjoin (render_livekit_yaml,
# further down) in this single install run. Never prompted, never generated
# twice. LIVEKIT_API_KEY is a constant key ID ("setjoin"), not a secret.
gen_or_keep LIVEKIT_API_SECRET "openssl rand -hex 32"
LIVEKIT_API_KEY="setjoin"
LIVEKIT_URL="ws://127.0.0.1:7880"
# Meet B2 (Task 9, law 3): ONE Valkey password, generated once, written into
# valkey.conf, livekit.yaml's redis: block, AND egress.yaml in this same run.
gen_or_keep VALKEY_PASSWORD "openssl rand -hex 32"
# Meet B3 (Task 18 pipeline-review finding 1, law 3): the asrbot control-API
# bearer secret — ONE value, generated once, written into BOTH config.env's
# ASR_TOKEN (below) and asrbot.env's ASR_TOKEN (render_asrbot_env, further
# down) in this same install run. Only generated when the optional captions
# leg is actually enabled (MEET_CAPTIONS_ENABLED, prompted in step 2 above,
# already known by this point) — an unused secret for a sidecar that was
# never installed would just be dead config.env clutter.
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  gen_or_keep ASR_TOKEN "openssl rand -hex 32"
fi

# ── 4. TLS: self-signed unless a cert is already present ─────────────────────
say "TLS certificate"
mkdir -p "$CERT_DIR"
TLS_CERT="$CERT_DIR/server.pem"
TLS_KEY="$CERT_DIR/server-key.pem"
if [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] && ! $FORCE; then
  info "Existing cert kept ($TLS_CERT)."
else
  info "Generating self-signed cert for $HOSTNAME (valid 825 days)."
  # CA:FALSE is load-bearing security, not cosmetic: `openssl req -x509` defaults
  # to CA:TRUE, and this cert gets anchored in the SYSTEM trust store below (so
  # the on-box SFU can verify the gateway's webhook TLS). A CA:TRUE anchor is a
  # box-wide sign-anything CA — a leaked $TLS_KEY (the serving key of the
  # internet-facing gateway, the most-exposed key on the host) would then be a
  # working CA trusted by every system-root verifier on the box (outbound SMTP
  # STARTTLS, LDAP/AD sync, curl/apt, egress registry pulls), turning a gateway
  # key-read into full TLS-MITM of all egress. A CA:FALSE self-signed LEAF still
  # validates when trusted directly (chain length 1; the anchor itself is not
  # subject to the CA:TRUE basic-constraints check) — the webhook plane is
  # unaffected, but a leaked key can no longer mint certs for other hosts.
  openssl req -x509 -newkey rsa:2048 -keyout "$TLS_KEY" -out "$TLS_CERT" \
    -days 825 -nodes -subj "/CN=$HOSTNAME" \
    -addext "subjectAltName=DNS:$HOSTNAME" \
    -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
  chmod 600 "$TLS_KEY"
fi
info "For a PUBLICLY-TRUSTED cert: enable ACME (set TLS_AUTOCERT_DOMAINS=$HOSTNAME and"
info "open :80 for the HTTP-01 challenge), or drop a real cert at $TLS_CERT / $TLS_KEY."

# Self-signed trust for ON-BOX sidecars (Meet B1/B2): livekit-server delivers
# every webhook to https://$HOSTNAME/api/meet/webhook and verifies the cert
# against the SYSTEM trust store — an untrusted self-signed gateway cert
# silently kills the whole webhook plane (meetings never flip 'live',
# room_finished is lost to the GC belt, recording start 409s BZ200). Found
# live by the 2026-07-16 fresh-VM gate; every earlier live run was plain
# HTTP. Only a SELF-SIGNED cert (issuer == subject) is anchored — a real/
# private-CA cert must be trusted via its own CA, not pinned here. Runs
# BEFORE the systemd step so the SFU process starts with the anchor visible.
_iss="$(openssl x509 -in "$TLS_CERT" -noout -issuer 2>/dev/null)"
_sub="$(openssl x509 -in "$TLS_CERT" -noout -subject 2>/dev/null)"
if [ -n "$_sub" ] && [ "${_iss#issuer=}" = "${_sub#subject=}" ]; then
  if command -v update-ca-certificates >/dev/null 2>&1; then
    install -m 0644 "$TLS_CERT" /usr/local/share/ca-certificates/setjoin-gateway.crt
    update-ca-certificates >/dev/null 2>&1 || true
    info "Self-signed gateway cert anchored in the system trust store (the SFU's webhook sender verifies against it)."
  elif command -v update-ca-trust >/dev/null 2>&1; then
    install -m 0644 "$TLS_CERT" /etc/pki/ca-trust/source/anchors/setjoin-gateway.crt
    update-ca-trust extract >/dev/null 2>&1 || true
    info "Self-signed gateway cert anchored in the system trust store (the SFU's webhook sender verifies against it)."
  else
    info "WARN: no update-ca-certificates/update-ca-trust found — the SFU cannot verify the self-signed cert and Meet webhooks WILL fail (meetings never flip live) until the cert is trusted system-wide."
  fi
fi

# ── Federation (optional, Pillar C1 Task 9 — DM federation) ─────────────────
# UNLIKE every sidecar above, cross-org s2s federation is a Go SERVICE INSIDE
# mailserverd (federation.Service, cmd/mailserverd/main.go) — no systemd
# unit, no container, no binary download. This leg's only job is optional
# s2s cert material + config.env wiring. FEDERATION_ENABLED is NOT a runtime
# config key (mailserverd's static gate is FEDERATION_LOCAL_DOMAIN/_CERT/
# _KEY all non-empty, the meetCfg.Configured() precedent) — it is purely
# this installer's own prompt-once/re-run-memory flag, the
# MEET_CAPTIONS_ENABLED pattern. Off by default: a fresh install never grows
# an s2s attack surface nobody asked for.
say "Federation (Pillar C1 DM federation, optional)"
FEDERATION_ENABLED="$(get_env FEDERATION_ENABLED)"; FEDERATION_ENABLED="${FEDERATION_ENABLED:-false}"
ask FEDERATION_ENABLED "Enable Pillar C1 DM federation (generates s2s cert material + wires config.env — feature.federation and the admin allow-list console still separately gate actual peering)?" "$FEDERATION_ENABLED"
FEDERATION_DIR="$CONFIG_DIR/federation"
if [ "$FEDERATION_ENABLED" = "true" ]; then
  FEDERATION_LOCAL_DOMAIN="$(get_env FEDERATION_LOCAL_DOMAIN)"; FEDERATION_LOCAL_DOMAIN="${FEDERATION_LOCAL_DOMAIN:-$HOSTNAME}"
  ask FEDERATION_LOCAL_DOMAIN "Federation local domain (this org's s2s identity — the name peers dial via DNS SRV)" "$FEDERATION_LOCAL_DOMAIN"
  [ -n "$FEDERATION_LOCAL_DOMAIN" ] || die "FEDERATION_ENABLED=true requires a non-empty FEDERATION_LOCAL_DOMAIN."
  FEDERATION_LISTEN_ADDR="$(get_env FEDERATION_LISTEN_ADDR)"; FEDERATION_LISTEN_ADDR="${FEDERATION_LISTEN_ADDR:-:7443}"

  # Accept pre-supplied paths (env, or persisted from a prior run) — an
  # admin with their own CA/leaf need never touch our generator.
  FEDERATION_CERT="${FEDERATION_CERT:-$(get_env FEDERATION_CERT)}"
  FEDERATION_KEY="${FEDERATION_KEY:-$(get_env FEDERATION_KEY)}"
  if [ -n "$FEDERATION_CERT" ] && [ -n "$FEDERATION_KEY" ]; then
    info "FEDERATION_CERT/FEDERATION_KEY already set — using them as-is, skipping CA/leaf generation."
  else
    mkdir -p "$FEDERATION_DIR"
    FED_CA_CERT="$FEDERATION_DIR/ca.crt"; FED_CA_KEY="$FEDERATION_DIR/ca.key"
    FED_LEAF_CERT="$FEDERATION_DIR/leaf.crt"; FED_LEAF_KEY="$FEDERATION_DIR/leaf.key"
    if [ -f "$FED_CA_CERT" ] && [ -f "$FED_CA_KEY" ] && [ -f "$FED_LEAF_CERT" ] && [ -f "$FED_LEAF_KEY" ] && ! $FORCE; then
      info "Existing federation CA + leaf cert kept ($FEDERATION_DIR)."
    else
      # ONE step (law 3): a long-lived org CA (3650 days, CA:TRUE, never
      # leaves this host) signs an 825-day leaf for FEDERATION_LOCAL_DOMAIN.
      # The leaf is what a peer's Dial/Listen actually validates on the
      # wire; the CA cert alone (ca.crt — public, no key material) is the
      # ONLY thing ever handed to a peer org, pasted into ITS admin
      # Federation console as this org's federation_allowlist.peer_anchor
      # (Task 8) — never ca.key, never leaf.key.
      info "Generating federation CA + leaf cert for $FEDERATION_LOCAL_DOMAIN (CA 3650 days, leaf 825 days)."
      openssl req -x509 -newkey rsa:2048 -keyout "$FED_CA_KEY" -out "$FED_CA_CERT" \
        -days 3650 -nodes -subj "/CN=setjoin-federation-ca-$FEDERATION_LOCAL_DOMAIN" \
        -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
      chmod 600 "$FED_CA_KEY"
      openssl req -newkey rsa:2048 -keyout "$FED_LEAF_KEY" -out "$FEDERATION_DIR/leaf.csr" \
        -nodes -subj "/CN=$FEDERATION_LOCAL_DOMAIN" 2>/dev/null
      openssl x509 -req -in "$FEDERATION_DIR/leaf.csr" -CA "$FED_CA_CERT" -CAkey "$FED_CA_KEY" -CAcreateserial \
        -out "$FED_LEAF_CERT" -days 825 \
        -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE' "$FEDERATION_LOCAL_DOMAIN") 2>/dev/null
      rm -f "$FEDERATION_DIR/leaf.csr" "$FEDERATION_DIR/ca.srl"
      chmod 600 "$FED_LEAF_KEY"
    fi
    FEDERATION_CERT="$FED_LEAF_CERT"
    FEDERATION_KEY="$FED_LEAF_KEY"
  fi

  info "Anchor for peer orgs: $FEDERATION_DIR/ca.crt — paste its contents into the PEER org's admin Federation console (federation_allowlist.peer_anchor). Never share ca.key or leaf.key."
  info "Publish DNS SRV _setjoin-im._tcp.$FEDERATION_LOCAL_DOMAIN -> this host on port ${FEDERATION_LISTEN_ADDR#:} (peers discover you this way; no central directory)."
  info "Air-gapped / no-DNS peers: federation discovery is DNS SRV ONLY today (no per-peer endpoint override exists) — an air-gapped pair needs a private DNS zone (or /etc/hosts + a stub resolver) serving that SRV record for each peer."
  info "Open ${FEDERATION_LISTEN_ADDR#:}/tcp on this host's firewall for inbound s2s (peer-to-peer only — never expose it the way :443 is exposed)."
  info "feature.federation ships seeded OFF and the allow-list starts empty — nothing federates until an admin flips the toggle AND allow-lists a peer (admin Federation console, federation.manage permission)."
fi

# ── Pgpool-II failover leg (optional — the 3-node HA track) ─────────────────
# UNLIKE the single-node services above, remote PostgreSQL failover belongs to
# the HA track: pgpool's failover_command delegates to /etc/pgpool2/failover.sh
# (deploy/failover.sh.template — reviewed, strict host-identity policy: pinned
# known_hosts, no interactive prompts) and that script's SSH client trusts ONLY
# peer host keys pre-provisioned in /etc/pgpool2/known_hosts. This installer
# has NO HA node inventory (it is the single-node installer; the wizard's
# DeploymentState.Nodes is the HA inventory and provisions the same files from
# its pinned host key), so the trust anchor is built ONLY from operator-verified
# input, and everything fails closed:
#   - peer keys supplied as a pre-verified known_hosts file (PGPOOL_KNOWN_HOSTS)
#     are validated strictly (line shape, key type, no wildcards/markers, and a
#     whole-file ssh-keygen parse) before anything is installed;
#   - peer hostnames (PGPOOL_PEERS / interactive) are ssh-keyscan'd, their
#     fingerprints DISPLAYED for out-of-band verification, and installed only
#     after an explicit interactive confirmation — NONINTERACTIVE runs refuse
#     to install scan output no human verified;
#   - no verified input → no known_hosts → remote failover fails closed (by
#     the script's own StrictHostKeyChecking=yes policy) until it exists.
# Install-contract decision that stays open: scanning is provisioning-time
# trust establishment with operator verification; TOFU at FAILOVER time remains
# deliberately rejected.
say "Pgpool-II failover (HA, optional)"
HA_FAILOVER_ENABLED="$(get_env HA_FAILOVER_ENABLED)"; HA_FAILOVER_ENABLED="${HA_FAILOVER_ENABLED:-false}"
ask HA_FAILOVER_ENABLED "Provision the Pgpool-II failover leg (installs /etc/pgpool2/failover.sh 0700 + /etc/pgpool2/known_hosts from operator-verified peer host keys; for the 3-node HA track)?" "$HA_FAILOVER_ENABLED"
PGPOOL_DIR="/etc/pgpool2"

# validate_known_hosts_file <candidate-file> — fail-closed gate for candidate
# known_hosts content. Rejects (loudly, naming the reason): empty input,
# @cert-authority/@revoked marker lines, wildcard/negated host patterns, host
# fields with empty comma-elements, unsupported key types, malformed key
# blobs, and any input ssh-keygen cannot fully parse. Only strict
# host-pattern public-key entries survive.
validate_known_hosts_file() {
  local f="$1" line host rest keytype blob elem
  [ -s "$f" ] || { echo "candidate known_hosts is empty" >&2; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    case "$line" in \#*) continue ;; esac
    case "$line" in
      @*) echo "marker lines (@cert-authority/@revoked) are not accepted: $line" >&2; return 1 ;;
    esac
    host="${line%% *}"; rest="${line#* }"; blob="${rest#* }"
    keytype="${rest%% *}"
    [ -n "$rest" ] && [ "$rest" != "$line" ] || { echo "entry is not a 'host keytype blob' line: $line" >&2; return 1; }
    case "$host" in
      *\**|*\?*) echo "wildcard host patterns are not accepted: $host" >&2; return 1 ;;
      !*|*,!*) echo "negated host patterns are not accepted: $host" >&2; return 1 ;;
    esac
    IFS=',' read -r -a _kh_hosts <<< "$host"
    for elem in "${_kh_hosts[@]}"; do
      case "$elem" in
        ""|*\**|*\?*|!*) echo "wildcard/empty host pattern element is not accepted: $elem (in $host)" >&2; return 1 ;;
      esac
    done
    case "$keytype" in
      ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ;;
      *) echo "unsupported key type: $keytype" >&2; return 1 ;;
    esac
    blob="${blob%% *}"
    case "$blob" in
      ""|*[!A-Za-z0-9+/=]*) echo "malformed key blob for host $host" >&2; return 1 ;;
    esac
  done < "$f"
  # Whole-file parse: ssh-keygen must validate EVERY entry (bit lengths out)
  # or the candidate is not known_hosts content.
  ssh-keygen -lf "$f" >/dev/null 2>&1 || { echo "ssh-keygen cannot validate the candidate known_hosts content" >&2; return 1; }
  return 0
}

if [ "$HA_FAILOVER_ENABLED" = "true" ]; then
  # 1. The reviewed failover script itself — installed from the repository
  #    template (0700, root-owned), never a hand-edit. It is static (no
  #    {{ PLACEHOLDER }} render), but a syntax-broken template must refuse
  #    the install instead of shipping a failover path that cannot run.
  FAILOVER_TEMPLATE="$ROOT/mailserver/deploy/failover.sh.template"
  [ -f "$FAILOVER_TEMPLATE" ] || die "failover.sh template missing: $FAILOVER_TEMPLATE"
  bash -n "$FAILOVER_TEMPLATE" || die "$FAILOVER_TEMPLATE is not bash-clean — refusing to install it."
  install -d -o root -g root -m 0755 "$PGPOOL_DIR"
  install -o root -g root -m 0700 "$FAILOVER_TEMPLATE" "$PGPOOL_DIR/failover.sh"
  info "Installed $PGPOOL_DIR/failover.sh (0700 root:root) from the reviewed template."

  # 2. The trust anchor — ONLY from operator-verified input (fail closed).
  PGPOOL_KNOWN_HOSTS_INPUT="${PGPOOL_KNOWN_HOSTS:-}"
  if [ -n "$PGPOOL_KNOWN_HOSTS_INPUT" ]; then
    [ -f "$PGPOOL_KNOWN_HOSTS_INPUT" ] || die "PGPOOL_KNOWN_HOSTS=$PGPOOL_KNOWN_HOSTS_INPUT does not exist."
    validate_known_hosts_file "$PGPOOL_KNOWN_HOSTS_INPUT" \
      || die "PGPOOL_KNOWN_HOSTS failed strict validation — refusing to write $PGPOOL_DIR/known_hosts from unverified input (fix the file and re-run)."
    install -o root -g root -m 0644 "$PGPOOL_KNOWN_HOSTS_INPUT" "$PGPOOL_DIR/known_hosts"
    info "Installed $PGPOOL_DIR/known_hosts (0644 root:root) from operator-verified input."
  else
    PGPOOL_PEERS="${PGPOOL_PEERS:-$(get_env PGPOOL_PEERS)}"
    ask PGPOOL_PEERS "HA peer node hostnames (comma/space separated; keys are scanned and their fingerprints shown for YOUR out-of-band verification)" "$PGPOOL_PEERS"
    if [ -n "$PGPOOL_PEERS" ]; then
      command -v ssh-keyscan >/dev/null 2>&1 || die "ssh-keyscan not found — install the openssh-client tools, or pre-verify keys and re-run with PGPOOL_KNOWN_HOSTS=<file>."
      _kh_scan="$(mktemp "${TMPDIR:-/tmp}/setjoin-pgpool-kh.XXXXXX")"
      for _peer in $(printf '%s' "$PGPOOL_PEERS" | tr ',' ' '); do
        [ -n "$_peer" ] || continue
        case "$_peer" in
          -*|*[!A-Za-z0-9._-]*)
            rm -f "$_kh_scan"
            die "peer token '$_peer' is not a hostname/address — refusing to scan (fail closed)." ;;
        esac
        ssh-keyscan -t ed25519,ecdsa,rsa "$_peer" >> "$_kh_scan" 2>/dev/null \
          || die "ssh-keyscan failed for $_peer — verify the hostname, or pre-verify keys and re-run with PGPOOL_KNOWN_HOSTS=<file>."
      done
      validate_known_hosts_file "$_kh_scan" \
        || { rm -f "$_kh_scan"; die "scanned peer keys failed strict validation — refusing to write $PGPOOL_DIR/known_hosts from unverified input."; }
      if [ "$NONINTERACTIVE" = "1" ]; then
        rm -f "$_kh_scan"
        die "NONINTERACTIVE runs cannot verify scanned host keys — no human saw these fingerprints. Pre-verify the keys out-of-band and re-run with PGPOOL_KNOWN_HOSTS=<file> (fail closed)."
      fi
      info "Scanned peer host key fingerprints (verify these out-of-band — phone/video/panic-channel — before confirming):"
      ssh-keygen -lf "$_kh_scan" || true
      read -r -p "  Are ALL of these fingerprints verified as the real peers' keys? Type 'verified': " _kh_confirm
      if [ "$_kh_confirm" != "verified" ]; then
        rm -f "$_kh_scan"
        die "host keys not verified — refusing to write $PGPOOL_DIR/known_hosts (fail closed). Re-run after verifying, or pass PGPOOL_KNOWN_HOSTS=<file>."
      fi
      install -o root -g root -m 0644 "$_kh_scan" "$PGPOOL_DIR/known_hosts"
      rm -f "$_kh_scan"
      info "Installed $PGPOOL_DIR/known_hosts (0644 root:root) from fingerprint-verified scan input."
    else
      info "No peer host keys supplied — $PGPOOL_DIR/known_hosts NOT written."
      info "Remote failover FAILS CLOSED (the script pins StrictHostKeyChecking=yes to that anchor) until it exists."
      info "Provide it: re-run and answer with peers, or PGPOOL_KNOWN_HOSTS=<verified known_hosts file> sudo bash $0."
    fi
  fi
  info "The failover script logs to /var/log/pgpool/failover.log; pgpool invokes it via failover_command = '/etc/pgpool2/failover.sh %d %P %H %R'."
else
  info "Pgpool-II failover leg not enabled (re-run and answer yes to the HA_FAILOVER_ENABLED prompt, HA guide: docs/guides/HA_OVERVIEW.md)."
fi

# ── 5. Database: create + load baseline + forward migrations + reducers ──────
say "Database ($DB_NAME on $DB_HOST:$DB_PORT as $DB_USER)"
export PGCONNECT_TIMEOUT=5
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -tAc 'SELECT 1' >/dev/null 2>&1 \
  || die "cannot reach Postgres at $DB_HOST:$DB_PORT as $DB_USER. Start it and create the role first. (Stock Debian/Ubuntu pg_hba.conf uses scram-sha-256 on 127.0.0.1 — a passwordless role/DSN cannot authenticate; see SINGLE_NODE_SETUP.md step 2 for the password or loopback-trust options.)"

if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d'|' -f1 | grep -qw "$DB_NAME"; then
  info "Database '$DB_NAME' already exists — preserving it."
else
  info "Creating database '$DB_NAME'."
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
    -c "CREATE DATABASE $DB_NAME OWNER $DB_USER TEMPLATE template0;"
fi

# Native-RLS roles (setjoin_app/worker/owner) — cluster-global, idempotent,
# and referenced by forward migrations (e.g. V017 GRANTs), so they must exist
# BEFORE the migration loop; re-run again after load so the per-DB GRANTs land
# on the created tables (mirrors scripts/load-test-schema.sh's two calls).
# Missing pre-pass = fresh install dies at V017 "role setjoin_app does not
# exist" (found by the G1 fresh-container install smoke, 2026-07-04).
info "Provisioning native-RLS roles (scripts/provision-roles.sql, idempotent)."
( cd "$ROOT/scripts" && psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 -f provision-roles.sql >/dev/null )

# Load V001 baseline only if the schema is not already at version ≥ 1.
# `|| true` is load-bearing: on a FRESH database schema_migrations doesn't
# exist yet, psql exits 1, and under `set -euo pipefail` a failed command
# substitution in an assignment would kill the installer silently right here
# (found by the G1 fresh-container install smoke, 2026-07-04). Empty → 0 below.
SCHEMA_VER="$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
  "SELECT COALESCE(MAX(version),0) FROM schema_migrations" 2>/dev/null | tr -d '[:space:]' || true)"
if [ "${SCHEMA_VER:-0}" -ge 1 ] 2>/dev/null; then
  info "Schema already loaded (schema_migrations MAX = $SCHEMA_VER) — skipping baseline."
else
  # pgtap preflight: V001__baseline.sql does CREATE EXTENSION pgtap (frozen
  # baseline — guarded by check-schema-determinism.sh, so the fix lives HERE,
  # not in the SQL). Fail loud and actionable BEFORE the baseline load, and
  # auto-install the version-matched package where apt is available (the
  # 2026-07-06 real deploy hit this as a mid-load psql error).
  if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
       "SELECT 1 FROM pg_available_extensions WHERE name='pgtap'" | grep -q 1; then
    PG_MAJOR="$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc 'SHOW server_version_num' | tr -d '[:space:]')"
    PG_MAJOR=$((PG_MAJOR / 10000))
    if command -v apt-get >/dev/null 2>&1; then
      info "pgtap extension not available — installing postgresql-$PG_MAJOR-pgtap via apt."
      DEBIAN_FRONTEND=noninteractive apt-get install -y "postgresql-$PG_MAJOR-pgtap" \
        || die "could not install postgresql-$PG_MAJOR-pgtap. Install the pgTAP package for PostgreSQL $PG_MAJOR on this host, then re-run (the schema baseline does CREATE EXTENSION pgtap)."
      psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT 1 FROM pg_available_extensions WHERE name='pgtap'" | grep -q 1 \
        || die "postgresql-$PG_MAJOR-pgtap installed but the 'pgtap' extension is still not visible to the server — is the DSN pointing at a different Postgres host than this machine?"
    else
      die "the 'pgtap' extension is not available on the PostgreSQL server (needed by V001__baseline.sql). Install the pgTAP package for PostgreSQL $PG_MAJOR (Debian/Ubuntu: postgresql-$PG_MAJOR-pgtap; RHEL: pgtap_$PG_MAJOR; or from source: https://pgtap.org), then re-run."
    fi
  fi
  info "Loading V001__baseline.sql"
  ( cd "$ROOT/mailserver/sql/dbschema" && \
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -f V001__baseline.sql >/dev/null )
fi

# Bring both fresh and existing databases to the schema embedded in this build
# BEFORE loading current reducers. Keeping this outside the baseline branch is
# load-bearing: a re-run against an older installed schema (for example V149)
# otherwise tried to create V177-era reducer functions before their tables
# existed. mailctl applies only pending migrations, one transaction each, using
# the owner DSN; it is the same migration authority as upgrade.sh.
info "Applying pending schema migrations with the matching mailctl."
DB_DIRECT_OWNER_DSN="$DB_DIRECT_DSN" DB_OWNER_DSN="$DB_DSN" \
  "$ROOT/server-rust/mailctl" schema apply --yes \
  || die "schema migration failed — database remains at its last committed version; fix the named migration and re-run."

# One call: the loader iterates to a fixed point internally, so forward refs
# resolve without a second invocation. (The old double-run also happened to
# resolve a mailserver→authserver cross-set forward ref; none exist, and one
# would now fail loudly here instead — the loud failure is the intent.)
info "Loading PL/pgSQL reducers (fixed-point iteration resolves forward refs)."
DB_NAME="$DB_NAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/reload-reducers.sh" >/dev/null 2>&1 \
  || die "reducer load failed — run 'DB_NAME=$DB_NAME bash scripts/reload-reducers.sh' to see the named failure."

# Post-load pass: the per-DB GRANTs in provision-roles.sql need the tables to
# exist (the pre-pass above only guaranteed the roles for the migration loop).
( cd "$ROOT/scripts" && psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 -f provision-roles.sql >/dev/null )

if [ "$PERMISSIVE_DSN" != "1" ]; then
  # Give the constrained runtime roles their LOGIN passwords (provision-roles.sql
  # creates them password-less; re-asserted every run, same as the e2e harness).
  # Passwords are hex-only, so no SQL-quoting hazard. stdin-fed SQL: a password
  # in psql argv is visible to any local user via /proc/<pid>/cmdline for the
  # process's whole lifetime — the exact leak class this script fixed for
  # valkey-cli via REDISCLI_AUTH (B3 Task 18 finding 4). -v/--set would be argv
  # too; stdin only. -v ON_ERROR_STOP=1 semantics preserved.
  info "Setting runtime-role passwords (setjoin_app / setjoin_worker)."
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null <<SQL
ALTER ROLE setjoin_app WITH LOGIN PASSWORD '$APP_PW';
ALTER ROLE setjoin_worker WITH LOGIN PASSWORD '$WORKER_PW';
SQL
fi

# The root-owned updater gets its own NOBYPASSRLS credential. It is never
# written to config.env (which mailserverd reads); the updater receives only
# its fixed root-only credential-file path. Re-runs preserve the password.
UPDATER_PW=""
mkdir -p "$UPDATER_CONFIG_DIR"
chown root:root "$UPDATER_CONFIG_DIR"
chmod 0700 "$UPDATER_CONFIG_DIR"
if [ -f "$UPDATER_DSN_FILE" ]; then
  UPDATER_PW="$(dsn_password "$(tr -d '\r\n' < "$UPDATER_DSN_FILE")")"
fi
[ -n "$UPDATER_PW" ] || { UPDATER_PW="$(openssl rand -hex 24)"; info "setjoin_updater password: generated"; }
info "Setting transactional-updater role password."
# stdin-fed SQL (never argv — see the setjoin_app/worker note above).
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null <<SQL
ALTER ROLE setjoin_updater WITH LOGIN PASSWORD '$UPDATER_PW';
SQL
_upq=""; case "$DB_DSN" in *\?*) _upq="?${DB_DSN#*\?}";; esac
_uphost="${DB_DSN#postgres://}"; _uphost="${_uphost#postgresql://}"; _uphost="${_uphost%%\?*}"
case "$_uphost" in *@*) _uphost="${_uphost#*@}";; esac
( umask 077
  printf '%s\n' "postgres://setjoin_updater:${UPDATER_PW}@${_uphost}${_upq}" > "$UPDATER_DSN_FILE"
)
chmod 0600 "$UPDATER_DSN_FILE"
# The updater's managed-app worker credential follows the posture (Astra
# L2-C8 HOLD fix: the file must exist in BOTH postures — the unit always
# receives its path and the managed-app runner exits when it is missing):
# constrained installs give it the BYPASSRLS worker DSN; a --permissive-dsn
# install has no constrained roles, so the file carries the single owner
# credential the posture has.
if [ "$PERMISSIVE_DSN" != "1" ]; then
  ( umask 077
    printf '%s\n' "$RUNTIME_WORKER_DSN" > "$UPDATER_APP_WORKER_DSN_FILE"
  )
else
  ( umask 077
    printf '%s\n' "$DB_DSN" > "$UPDATER_APP_WORKER_DSN_FILE"
  )
fi
chmod 0600 "$UPDATER_APP_WORKER_DSN_FILE"

# The mutation catalog is doubly gated. A fresh install always writes an
# explicit disabled non-secret config, while the owner/recovery/probe secrets
# live in distinct root-owned 0600 files below a 0700 directory. The unit
# receives only their fixed paths; no credential value enters argv or env.
# Re-runs preserve operator-populated recovery/probe credentials and an
# explicitly enabled config; they do refresh the owner DSN alongside the
# installer's authoritative migration connection.
# Creation-time umask hygiene (same rule class as every sibling write): a plain
# `>` under root's default umask exists briefly 0644 before the batch chmod
# below — the 0700 updater directory limits exposure, but creation-time privacy
# is free and removes the race entirely.
( umask 077
  printf '%s\n' "$DB_DIRECT_OWNER_DSN" > "$UPDATER_OWNER_DSN_FILE"
)
if [ ! -e "$UPDATER_EXECUTION_CONFIG" ]; then
  printf '%s\n' '{"version":1,"enabled":false}' > "$UPDATER_EXECUTION_CONFIG"
fi
if [ ! -e "$UPDATER_RECOVERY_ACCESS_FILE" ]; then
  printf '%s\n' 'unconfigured' > "$UPDATER_RECOVERY_ACCESS_FILE"
fi
if [ ! -e "$UPDATER_RECOVERY_SECRET_FILE" ]; then
  printf '%s\n' 'unconfigured' > "$UPDATER_RECOVERY_SECRET_FILE"
fi
if [ ! -e "$UPDATER_RECOVERY_HMAC_FILE" ]; then
  # A real openssl secret: created under the private umask like its siblings.
  ( umask 077
    openssl rand -hex 32 > "$UPDATER_RECOVERY_HMAC_FILE"
  )
fi
if [ ! -e "$UPDATER_PROBE_CREDENTIAL_FILE" ]; then
  printf '%s\n' '{"disabled":true}' > "$UPDATER_PROBE_CREDENTIAL_FILE"
fi
chmod 0600 "$UPDATER_OWNER_DSN_FILE" "$UPDATER_EXECUTION_CONFIG" \
  "$UPDATER_RECOVERY_ACCESS_FILE" "$UPDATER_RECOVERY_SECRET_FILE" \
  "$UPDATER_RECOVERY_HMAC_FILE" "$UPDATER_PROBE_CREDENTIAL_FILE"

# Dedicated Ed25519 continuity key. It is deliberately separate from JWT,
# release, entitlement, organization, and recovery-set keys. Re-runs preserve
# it so native rollback witnesses remain verifiable across ordinary upgrades.
# Create the runtime identity before the first file is assigned to its group.
# Keep the group explicit: relying on distro-specific user-private-group
# defaults made clean Ubuntu installs fail at the chown below.
getent group setjoin >/dev/null 2>&1 || groupadd -r setjoin
id -u setjoin >/dev/null 2>&1 || useradd -r -g setjoin -s /bin/false -d "$INSTALL_DIR" setjoin
CONTINUITY_SIGNING_KEY_FILE="${CONTINUITY_SIGNING_KEY_FILE:-$CONFIG_DIR/continuity-signing-key.pem}"
if [ ! -e "$CONTINUITY_SIGNING_KEY_FILE" ]; then
  ( umask 077; openssl genpkey -algorithm ED25519 -out "$CONTINUITY_SIGNING_KEY_FILE" )
fi
chown root:setjoin "$CONTINUITY_SIGNING_KEY_FILE"
chmod 0640 "$CONTINUITY_SIGNING_KEY_FILE"

# Guest invitation links must use the externally reachable gateway origin, not
# AUTHSERVER_URL (which is deliberately loopback-only). Seed the known public
# hostname on first install and preserve any explicit operator override on
# re-runs. Without this row Guest provisioning commits nothing and returns 500
# at the invite-preparation boundary.
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -v ON_ERROR_STOP=1 -v public_url="https://$HOSTNAME" <<'SQL' >/dev/null
INSERT INTO public.system_config (key, value, encrypted, updated_at)
VALUES ('authserver.public_url', to_jsonb(:'public_url'::text), FALSE, now())
ON CONFLICT (key) DO NOTHING;
SQL
info "Database ready."

# ── 6. Write config.env + install binaries/webmail ───────────────────────────
say "Config + install"
mkdir -p "$INSTALL_DIR" "$DATA_DIR/backups" "$DATA_DIR/updates" \
  "$UPDATER_DATA_DIR/journal" "$UPDATER_DATA_DIR/releases" "$OFFICE_APP_STATE_DIR" /usr/libexec

install_rust_updater() {
  local staged_unit
  staged_unit="$(mktemp "$UPDATER_DATA_DIR/.updater-unit.XXXXXXXX")"
  if ! render_updater_unit "$ROOT/mailserver/deploy/setjoin-updater.service.template" "$staged_unit" ||
     ! "$UPDATER_SOURCE" install --binary "$UPDATER_SOURCE" \
       --office-runner "$ROOT/mailserver/setjoin-updater" \
       --state-dir "$UPDATER_DATA_DIR/journal" --dsn-file "$UPDATER_DSN_FILE" \
       --unit-source "$staged_unit"; then
    rm -f -- "$staged_unit"
    return 1
  fi
  rm -f -- "$staged_unit"
}
install_rust_updater || die "Rust updater installation refused; existing update/journal must be inactive and reconciled."
install -m 0755 "$ROOT/mailserver/mailserverd"  "$INSTALL_DIR/mailserverd"
install -o root -g root -m 0644 "$ROOT/config/office-managed-app-v1.json" "$OFFICE_APP_MANIFEST"
install -d -o root -g root -m 0755 /usr/local/sbin /usr/local/lib/setjoin
install -o root -g root -m 0755 \
  "$ROOT/mailserver/deploy/scripts/setjoin-lifecycle.sh" /usr/local/sbin/setjoinctl
install -o root -g root -m 0644 \
  "$ROOT/mailserver/deploy/generated/unit-catalog.sh" /usr/local/lib/setjoin/unit-catalog.sh
install -m 0755 "$ROOT/authserver/authserverd"  "$INSTALL_DIR/authserverd"
install -m 0755 "$ROOT/server-rust/mailctl"          "$INSTALL_DIR/mailctl"
install -m 0755 "$GATEWAY_SOURCE" "$INSTALL_DIR/setjoin-gateway"
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  mkdir -p "$INSTALL_DIR/bin"
  install -m 0755 "$ROOT/server-rust/asrbotd" "$INSTALL_DIR/bin/asrbotd"
fi
if [ -d "$ROOT/mailserver/webmail/build" ]; then
  rm -rf "$INSTALL_DIR/webmail"; cp -r "$ROOT/mailserver/webmail/build" "$INSTALL_DIR/webmail"
else
  info "WARN: webmail build not found ($ROOT/mailserver/webmail/build) — build it with 'cd mailserver/webmail && npm run build'."
fi

# ASR block for config.env: ASR_URL is written ONLY when the (optional)
# captions leg was actually provisioned — an unconditional ASR_URL would
# point the gateway's CaptionsController/health probe at a sidecar pair
# that was never installed, misreporting "asr" as persistently down instead
# of correctly absent (config.go's Configured()-by-non-empty-string gate).
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  ASR_BLOCK="
# setjoin Meet B3 (captions — setjoin-asr-bot + setjoin-funasr, Task 16).
# feature.meet_captions (DB toggle, seeded OFF) still separately gates the
# start route; this just wires the sidecar the same way LIVEKIT_URL does
# for the SFU. ASR_TOKEN is the SAME value rendered into asrbot.env below
# (law 3) — the gateway sends it as an Authorization: Bearer header on
# every /start, /stop and /status call (mailserver/internal/meet/
# captions.go's newRequest, the B3 Task 18 pipeline-review finding-1
# follow-up, landed).
ASR_URL=http://127.0.0.1:7890
ASR_TOKEN=$ASR_TOKEN"
else
  ASR_BLOCK=""
fi

# Federation block for config.env (Pillar C1 Task 9): written ONLY when the
# optional leg was actually enabled — an unconditional (empty) block would
# be harmless to the static gate (all three must be non-empty to construct
# federation.Service) but would clutter every install's config.env with
# dead FEDERATION_* lines for a feature almost nobody turns on.
if [ "$FEDERATION_ENABLED" = "true" ]; then
  FEDERATION_BLOCK="
# setjoin Pillar C1 DM federation (feature.federation DB toggle, seeded OFF,
# gates actual peering; the admin allow-list console gates per-peer — this
# just wires the box to be ABLE to federate). FEDERATION_LOCAL_DOMAIN/_CERT/
# _KEY are cmd/mailserverd/main.go's static gate: all three non-empty
# constructs+starts federation.Service, absent means no Service at all.
FEDERATION_LOCAL_DOMAIN=$FEDERATION_LOCAL_DOMAIN
FEDERATION_LISTEN_ADDR=$FEDERATION_LISTEN_ADDR
FEDERATION_CERT=$FEDERATION_CERT
FEDERATION_KEY=$FEDERATION_KEY"
else
  FEDERATION_BLOCK=""
fi

# DSN block for config.env: constrained three-role shape by default,
# single permissive DSN with --permissive-dsn. The PRIVILEGED tiers are NOT
# rendered here in either branch: they live only in the root-owned credential
# file (DEPLOY-004) and reach the units through their own EnvironmentFile=.
if [ "$PERMISSIVE_DSN" = "1" ]; then
  DSN_BLOCK="# PERMISSIVE single-DSN mode (--permissive-dsn): runtime = owner credential.
# To adopt the constrained native-RLS shape later, re-run install.sh without
# the flag (docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md).
DB_DSN=$DB_DSN
DB_DIRECT_DSN=$DB_DIRECT_DSN"
else
  DSN_BLOCK="# Native-RLS constrained runtime (docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md):
# app role for tenant traffic; worker (BYPASSRLS) for cross-tenant jobs and
# owner for migrations/partition DDL — but ONLY the app-role DSN is rendered
# here: DB_WORKER_DSN / DB_OWNER_DSN / DB_DIRECT_OWNER_DSN live exclusively in
# $DB_CRED_FILE (0600 root:root, below the root-owned $DB_CRED_DIR) and reach
# the units through their own EnvironmentFile= line. ROLLBACK: point DB_DSN
# and DB_DIRECT_DSN back at the DB_OWNER_DSN value from that file and restart
# (runbook §4.6) — no migration to undo.
DB_DSN=$RUNTIME_DB_DSN
DB_DIRECT_DSN=$RUNTIME_DIRECT_DSN"
fi

# Persist SFU network-discovery choices so an idempotent re-run does not
# silently revert a private/LAN deployment from use_external_ip=false back to
# the internet-facing default. Environment values win on an intentional
# change; otherwise reuse config.env, then fall back to documented defaults.
RTC_PORT_START="${RTC_PORT_START:-$(get_env RTC_PORT_START)}"
RTC_PORT_START="${RTC_PORT_START:-50000}"
RTC_PORT_END="${RTC_PORT_END:-$(get_env RTC_PORT_END)}"
RTC_PORT_END="${RTC_PORT_END:-60000}"
USE_EXTERNAL_IP="${USE_EXTERNAL_IP:-$(get_env USE_EXTERNAL_IP)}"
USE_EXTERNAL_IP="${USE_EXTERNAL_IP:-true}"
case "$USE_EXTERNAL_IP" in
  true|false) ;;
  *) die "USE_EXTERNAL_IP must be true or false (got '$USE_EXTERNAL_IP')." ;;
esac

# Transfer shared backup effects to Rust; preserve every other worker switch.
GO_WORKERS_OFF="${GO_WORKERS_OFF:-$(get_env GO_WORKERS_OFF)}"
case ",$GO_WORKERS_OFF," in
  *,backup-engine,*) ;;
  *) GO_WORKERS_OFF="${GO_WORKERS_OFF:+$GO_WORKERS_OFF,}backup-engine" ;;
esac

# Federation listener/dialers swap whole; residue reaps independently of the product gate.
for _fed_worker in federation-service federation-residue-reap; do
  case ",$GO_WORKERS_OFF," in
    *,"$_fed_worker",*) ;;
    *) GO_WORKERS_OFF="${GO_WORKERS_OFF:+$GO_WORKERS_OFF,}$_fed_worker" ;;
  esac
done
RUST_WORKERS_ON="${RUST_WORKERS_ON:-$(get_env RUST_WORKERS_ON)}"
case ",$RUST_WORKERS_ON," in
  *,federation-residue-reap,*) ;;
  *) RUST_WORKERS_ON="${RUST_WORKERS_ON:+$RUST_WORKERS_ON,}federation-residue-reap" ;;
esac

_TLS_PRESERVED=$(tls_front_preserve_settings "$CONFIG_ENV") || die "invalid managed TLS setting"
_INSTALL_UMASK="$(umask)"
umask 077
cat > "$CONFIG_ENV" <<ENV
# setjoin single-node config — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Managed by deploy/scripts/install.sh. Secrets are persisted here (mode 0600);
# the privileged DB tiers live separately in $DB_CRED_FILE (0600 root:root).
HOSTNAME=$HOSTNAME
LISTEN_ADDR=$LISTEN_ADDR
TLS_CERT=$TLS_CERT
TLS_KEY=$TLS_KEY
# Rust front door (#264, ARCH-027 shape): clients reach setjoin-gateway through
# native HTTPS socket; Go retains the existing plain upstream on :80 for
# unported shapes (restrict tcp/80 to this host) and trusts the gateway's
# address for X-Forwarded-*. Rollback restores the complete previous release.
HTTP_MODE=proxy
TRUSTED_PROXY_IP=127.0.0.1
SETJOIN_CONTROL_SOCKET=/run/setjoin/control.sock
GO_WORKERS_OFF=$GO_WORKERS_OFF
RUST_WORKERS_ON=$RUST_WORKERS_ON

$DSN_BLOCK
DB_MAX_CONNS=10
DB_ENCRYPTION_KEY=$DB_ENCRYPTION_KEY
CRYPTO_ALGORITHM_PROFILE=standard

# Gateway → auth server upstream (explicit: must match setjoin-auth's listen
# address in $AUTH_ENV — the compiled default happens to agree today, but a
# fresh install must never depend on that).
AUTHSERVER_URL=$AUTHSERVER_URL

S3_ENDPOINT=$S3_ENDPOINT
S3_ACCESS_KEY=$S3_ACCESS_KEY
S3_SECRET_KEY=$S3_SECRET_KEY
S3_BUCKET=mailblobs
S3_SECURE=false

JWT_SECRET=$JWT_SECRET
AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY
BACKUP_SIGNING_KEY_FILE=$BACKUP_SIGNING_KEY_FILE
JWT_ISSUER=mailserver
JWT_EXPIRY=1h
INTERNAL_API_KEY=$INTERNAL_API_KEY

# One-time setup token (owner decision A3) — mailserverd requires it (as the
# X-Setup-Token header) on every setup call to the local control socket.
SETJOIN_SETUP_TOKEN=$SETJOIN_SETUP_TOKEN

WEBAUTHN_RP_ID=$HOSTNAME
WEBAUTHN_RP_NAME=setjoin
WEBAUTHN_RP_ORIGIN=https://$HOSTNAME

# setjoin Meet B1 (feature.meet ships seeded OFF — this just wires the
# sidecar; flip the toggle per-org when ready). The SAME LIVEKIT_API_SECRET
# is rendered into /etc/setjoin/livekit.yaml's keys.setjoin in this same
# install run (Meet B1 Task 14, spike §2 finding 3 — never two prompts).
LIVEKIT_API_KEY=$LIVEKIT_API_KEY
LIVEKIT_API_SECRET=$LIVEKIT_API_SECRET
LIVEKIT_URL=$LIVEKIT_URL
RTC_PORT_START=$RTC_PORT_START
RTC_PORT_END=$RTC_PORT_END
USE_EXTERNAL_IP=$USE_EXTERNAL_IP

# setjoin Meet B2 (recording — Egress + the Valkey message bus). Provisioned
# unconditionally alongside the SFU (feature.meet_recording itself ships
# seeded OFF, gating only the start route). VALKEY_PASSWORD is the SAME
# value law 3 also writes into /etc/setjoin/valkey.conf and
# /etc/setjoin/egress.yaml, and into livekit.yaml's redis: block, in this
# same run.
MEET_EGRESS_ENABLED=true
VALKEY_PASSWORD=$VALKEY_PASSWORD
$ASR_BLOCK
$FEDERATION_BLOCK

# Re-run memory only (not read by mailserverd/authserverd) — lets a re-run's
# \`ask MEET_CAPTIONS_ENABLED\`/\`ask FEDERATION_ENABLED\` default to the
# prior answer instead of re-prompting "false" every time.
MEET_CAPTIONS_ENABLED=$MEET_CAPTIONS_ENABLED
FEDERATION_ENABLED=$FEDERATION_ENABLED
HA_FAILOVER_ENABLED=$HA_FAILOVER_ENABLED

LOG_LEVEL=info
SETJOIN_DEV=false
# Stash the admin email so a re-run knows setup was attempted.
SETJOIN_ADMIN_EMAIL=$ADMIN_EMAIL
ENV
chmod 600 "$CONFIG_ENV"

# auth.env — read by setjoin-auth.service AFTER config.env, so these values
# win there. Overrides the shared LISTEN_ADDR (the gateway's :443) to bind
# authserverd loopback-only; must stay in sync with AUTHSERVER_URL above.
cat > "$AUTH_ENV" <<ENV
# setjoin auth-server overrides — generated by deploy/scripts/install.sh.
# Read by setjoin-auth.service after config.env (later file wins).
LISTEN_ADDR=$AUTH_LISTEN
# Plain HTTP on loopback: the gateway terminates TLS and proxies
# AUTHSERVER_URL over http — auth must NOT inherit the gateway's cert.
TLS_CERT=
TLS_KEY=
ENV
chmod 600 "$AUTH_ENV"

# gateway.env — the Rust front door's own settings (no secrets): Go's internal
# plain listener as its upstream, authserverd for /auth/*, and the local TLS
# terminator as its only trusted proxy. Re-runs keep an operator's listener
# and trusted-proxy choices.
GATEWAY_LISTEN="${GATEWAY_LISTEN:-$(get_env_from "$GATEWAY_ENV" GATEWAY_LISTEN)}"
GATEWAY_LISTEN="${GATEWAY_LISTEN:-127.0.0.1:8090}"
GATEWAY_TRUSTED_PROXIES="${GATEWAY_TRUSTED_PROXIES:-$(get_env_from "$GATEWAY_ENV" GATEWAY_TRUSTED_PROXIES)}"
GATEWAY_TRUSTED_PROXIES="${GATEWAY_TRUSTED_PROXIES:-127.0.0.1}"
printf '%s\n' "$_TLS_PRESERVED" >> "$CONFIG_ENV"
unset _TLS_PRESERVED
configure_tls_front "$CONFIG_ENV" || die "failed to transfer native TLS ownership"
configure_imap_front "$CONFIG_ENV" || die "failed to transfer native IMAP ownership"
configure_smtp_front "$CONFIG_ENV" || die "failed to transfer native SMTP ownership"
render_tls_front_env "$TLS_ENV" "$CONFIG_ENV" || die "failed to render TLS settings"
chown root:setjoin "$TLS_ENV"
if [ -n "$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_DOMAINS)" ]; then
  _tls_cache=$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_CACHE_DIR)
  _tls_cache="${_tls_cache:-/var/cache/mailserver/autocert}"
  [ -d "$_tls_cache" ] || install -d -m 0700 -o setjoin -g setjoin "$_tls_cache"
  _tls_account=$(tls_front_value "$CONFIG_ENV" TLS_AUTOCERT_KEY_FILE)
  if [ -n "$_tls_account" ] && [ ! -d "${_tls_account%/*}" ]; then
    install -d -m 0700 -o setjoin -g setjoin "${_tls_account%/*}"
  fi
fi
render_gateway_env "$GATEWAY_ENV" || die "failed to render $GATEWAY_ENV — see the error above."
render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" \
  || die "failed to render $FEDERATION_ENV — see the error above."
chown root:setjoin "$FEDERATION_ENV"
render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" \
  || die "failed to render $SMTP_ENV — see the error above."
chown root:setjoin "$SMTP_ENV"

# livekit.yaml — the SFU's own config file (Meet B1 Task 14). Rendered from
# the same LIVEKIT_API_SECRET just written into $CONFIG_ENV above; TURN is
# enabled only if a cert pair already exists at TURN_CERT/TURN_KEY (defaults
# below — a fresh install's self-signed mail cert does NOT satisfy this, so
# TURN starts disabled until an admin provisions a turn.$HOSTNAME cert; see
# docs/guides/SINGLE_NODE_SETUP.md). RTC_PORT_START/END/USE_EXTERNAL_IP are
# environment-overridable and persisted in config.env above so re-runs retain
# the deployment choice; TURN_CERT/TURN_KEY remain environment overrides.
LIVEKIT_YAML="$CONFIG_DIR/livekit.yaml"
mkdir -p "$CONFIG_DIR/certs"
TURN_CERT="${TURN_CERT:-$CONFIG_DIR/certs/fullchain.pem}"
TURN_KEY="${TURN_KEY:-$CONFIG_DIR/certs/privkey.pem}"
render_livekit_yaml "$ROOT/mailserver/deploy/livekit.yaml.template" "$LIVEKIT_YAML" \
  || die "failed to render $LIVEKIT_YAML — see the error above."
chmod 600 "$LIVEKIT_YAML"

# valkey.conf + egress.yaml — Meet B2 (Task 9). Same VALKEY_PASSWORD just
# rendered into $LIVEKIT_YAML's redis: block above (law 3).
VALKEY_CONF="$CONFIG_DIR/valkey.conf"
provision_valkey_conf "$VALKEY_CONF" \
  || die "failed to write $VALKEY_CONF — see the error above."
EGRESS_YAML="$CONFIG_DIR/egress.yaml"
render_egress_yaml "$ROOT/mailserver/deploy/egress.yaml.template" "$EGRESS_YAML" \
  || die "failed to render $EGRESS_YAML — see the error above."
chmod 600 "$EGRESS_YAML"

# asrbot.env — Meet B3 (Task 16), OPTIONAL leg only. LIVEKIT_URL is the SAME
# value just written into $CONFIG_ENV above (the SFU URL every sidecar
# shares); ASR_LISTEN/FUNASR_URL/ASR_MAX_MEETINGS/ASR_MAX_ACTIVE_TRACKS are
# all overridable via the environment before running this installer, the
# template defaults otherwise (asrbot/AGENTS.md).
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  ASRBOT_ENV="$CONFIG_DIR/asrbot.env"
  render_asrbot_env "$ROOT/mailserver/deploy/asrbot.env.template" "$ASRBOT_ENV" \
    || die "failed to render $ASRBOT_ENV — see the error above."
  chmod 600 "$ASRBOT_ENV"
  info "Wrote $ASRBOT_ENV (0600)."
fi

# Secret/config outputs above are explicitly mode-pinned. Restore the caller's
# umask before creating the immutable runtime namespace: the unprivileged
# gateway and auth services must be able to traverse its root-owned releases
# directory while remaining unable to mutate it.
umask "$_INSTALL_UMASK"

# Own only installer-managed paths. CONFIG_DIR may also contain operator-
# managed sidecar credentials (for example SeaweedFS S3 identities); a blanket
# recursive chown silently breaks their deliberately narrow container-readable
# group and only surfaces after that sidecar restarts.
# Keep the immutable releases/current/previous namespace root-controlled. Only
# the legacy flat cohort (used as adoption input), sidecar binaries, webmail,
# and mutable data belong to the runtime account. The install namespace is
# root-owned because the capability-empty updater must atomically replace its
# fixed current/previous symlinks while the gateway must never be able to do so.
chown root:root "$INSTALL_DIR"
chown setjoin:setjoin "$DATA_DIR"
chown -R setjoin:setjoin "$DATA_DIR"
install -d -o setjoin -g setjoin -m 0750 /run/setjoin
for managed_path in mailserverd authserverd mailctl setjoin-gateway webmail bin; do
  [ ! -e "$INSTALL_DIR/$managed_path" ] || chown -R setjoin:setjoin "$INSTALL_DIR/$managed_path"
done
# CONFIG_DIR itself is the root-controlled ANCESTOR of the privileged DB
# credential namespace (it defaults to /etc/setjoin — r3 binding). The
# historical runtime-account ownership of this directory is deliberately GONE:
# directory write permission would let the runtime account rename
# $DB_CRED_DIR aside and plant a substitute at the live pathname, and every
# consumer (systemd EnvironmentFile=, upgrade.sh's schema probe, this
# installer's re-run reads) would then read attacker-chosen DSNs from a path
# that looks installed. The conversion happens at ENTRY (inside
# prepare_credential_migration, before the migration writes anything below
# the ancestor); this re-assertion pins the posture at the end of the run and
# covers the fresh-install mkdir path. Residual honesty: root, as the file's
# owner, can still edit the credential file in place — what root-ownership of
# the ancestor and the directory closes is the runtime account's
# whole-directory-replacement vector. The runtime account keeps traverse
# (0755/0750) and nothing more.
chown root:root "$CONFIG_DIR"
chmod 0755 "$CONFIG_DIR"
# config.env and the other runtime-readable secret files stay with the runtime
# account — only their containing directory changed hands.
chown setjoin:setjoin "$CONFIG_ENV" "$AUTH_ENV" "$LIVEKIT_YAML" "$VALKEY_CONF" "$BACKUP_SIGNING_KEY_FILE"
# The privileged credential namespace: directory 0750 root:setjoin (traverse/
# list for the runtime group, no write — mirroring the updater credential
# tree's root-only reasoning), file 0600 root:root (systemd parses
# EnvironmentFile= manager-side; install.sh/upgrade.sh read as root).
chown root:root "$DB_CRED_DIR" "$DB_CRED_FILE"
chgrp setjoin "$DB_CRED_DIR"
chmod 0750 "$DB_CRED_DIR"
chmod 0600 "$DB_CRED_FILE"
# Migration backups landed in the same root-controlled directory (0600).
for _backup in "$DB_CRED_DIR"/config.env.pre-dsn-split.*; do
  [ -e "$_backup" ] || continue
  chown root:root "$_backup"
  chmod 0600 "$_backup"
done
# Live-tree ancestor assertion: the FULL chain must hold before the install
# can report success — this is what makes the posture above load-bearing even
# on hosts where something else has been tampering with /etc/setjoin.
verify_db_credentials_namespace "$CONFIG_DIR" "$DB_CRED_DIR" "$DB_CRED_FILE" root root setjoin \
  || die "privileged-credential namespace failed its final posture check — refusing to complete the install (reason above)."
# The gateway account must not be able to replace the updater executable,
# journal, release store, or updater DB credential.
chown -R root:root "$UPDATER_DATA_DIR"
chmod 0700 "$UPDATER_DATA_DIR" "$UPDATER_DATA_DIR/journal"
chmod 0755 "$UPDATER_DATA_DIR/releases"
chown root:root /usr/libexec/setjoin-updater /usr/libexec/setjoin-recovery \
  "$UPDATER_DSN_FILE" "$UPDATER_OWNER_DSN_FILE" "$UPDATER_EXECUTION_CONFIG" \
  "$UPDATER_RECOVERY_ACCESS_FILE" "$UPDATER_RECOVERY_SECRET_FILE" \
  "$UPDATER_RECOVERY_HMAC_FILE" "$UPDATER_PROBE_CREDENTIAL_FILE" \
  "$UPDATER_APP_WORKER_DSN_FILE" "$OFFICE_APP_MANIFEST"
chmod 0755 /usr/libexec/setjoin-updater /usr/libexec/setjoin-recovery
chmod 0600 "$UPDATER_DSN_FILE" "$UPDATER_OWNER_DSN_FILE" "$UPDATER_EXECUTION_CONFIG" \
  "$UPDATER_RECOVERY_ACCESS_FILE" "$UPDATER_RECOVERY_SECRET_FILE" \
  "$UPDATER_RECOVERY_HMAC_FILE" "$UPDATER_PROBE_CREDENTIAL_FILE" \
  "$UPDATER_APP_WORKER_DSN_FILE"
chmod 0644 "$OFFICE_APP_MANIFEST"
# Capture a complete first release before the service units move to `current`.
# The compiled command is idempotent and stores only a digest of config.env,
# never its secrets. Incomplete flat installs fail closed instead of gaining a
# false rollback claim.
# An existing managed `current` must verify against the vendor release trust roots
# (#507); install them first, on first install and on upgrade.
install_release_roots "$ROOT/server-rust/release-roots.json" "$CONFIG_DIR/release-roots.json" "$INSTALL_DIR"
/usr/libexec/setjoin-updater adopt-current-layout \
  --trust-roots "$CONFIG_DIR/release-roots.json" \
  --install-root "$INSTALL_DIR" \
  --config-file "$CONFIG_ENV" \
  --quarantine-dir "$UPDATER_DATA_DIR/legacy-prev" >/dev/null \
  || die "could not adopt the immutable release layout; a complete mailserverd/authserverd/mailctl/setjoin-gateway/webmail cohort is required."
# Repair installations created by the short-lived U2 preview whose restrictive
# config umask made this root 0700. Release cohorts remain immutable 0555; only
# the namespace root is traversable by the setjoin runtime account.
chmod 0755 "$INSTALL_DIR/releases"
info "Immutable runtime layout ready at $RUNTIME_DIR."
chown -R setjoin:setjoin "$CERT_DIR" "$CONFIG_DIR/certs"
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  chown setjoin:setjoin "$ASRBOT_ENV"
fi
if [ "$FEDERATION_ENABLED" = "true" ]; then
  chown -R setjoin:setjoin "$FEDERATION_DIR"
fi
# egress.yaml is read INSIDE the pinned egress container, which runs as
# uid 1001 gid 0 (USER egress) — setjoin:setjoin 0600 is unreadable there and
# the unit exits at boot ("open /etc/egress.yaml: permission denied"; running
# the container as root instead is NOT a fix — its entrypoint's pulseaudio
# dies as root). root:0 0640 keeps the Valkey password host-private (root +
# gid 0 only) while the container user reads via its gid-0 membership.
# Live-proven on the B2 linux-ci-host gate run (2026-07-16).
chown root:0 "$EGRESS_YAML"
chmod 640 "$EGRESS_YAML"
info "Wrote $CONFIG_ENV + $AUTH_ENV + $LIVEKIT_YAML + $VALKEY_CONF (0600) + $EGRESS_YAML (0640 root:0 — container-readable) and installed binaries to $INSTALL_DIR."

# ── 7. systemd units (valkey + sfu + egress + auth + gateway + updater) ─────
# Six base services: setjoin-valkey (the bus) and setjoin-sfu (the LiveKit SFU)
# come up first, then setjoin-egress (recording, Wants=setjoin-valkey), then
# setjoin-auth (authserverd), then setjoin — the gateway proxies every
# /auth/* route to authserverd (the 2026-07-06 real deploy 502'd every login
# without that ordering) and /rtc to the SFU (Meet B1 Task 14).
say "systemd"
# Arch review #A11: all seven units now render off the SAME tested
# {{TOKEN}} seam (mailserver/deploy/scripts/lib-livekit.sh) — the bespoke
# `sed` rewrites this block used to run against the 4 static units (0
# tests, fail-OPEN on a stale pattern) and the asr-bot render-then-sed
# two-pass hybrid are both gone. The compiled unit catalog is sourced near the
# top of this script (the privileged-DSN migration re-renders units before
# this step); render_runtime_units owns the loop, and this step adds the
# daemon-reload/enable/start actions on top of a fresh render.
if command -v systemctl >/dev/null 2>&1; then
  render_runtime_units
  systemctl daemon-reload
  if [ "$FEDERATION_ENABLED" = true ]; then
    systemctl enable setjoin-federation.socket
  fi
  for _tls_socket in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
    if [ -f "/etc/systemd/system/$_tls_socket" ]; then systemctl enable "$_tls_socket"; fi
  done
  systemctl enable "${SETJOIN_DEFAULT_ENABLE[@]}" >/dev/null 2>&1 || true
  /usr/local/sbin/setjoinctl restart
  info "Services 'setjoin-valkey', 'setjoin-sfu', 'setjoin-egress', 'setjoin-auth', 'setjoin', the 'setjoin-gateway' front door, and the gated 'setjoin-updater' observer enabled and (re)started."
  if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
    systemctl enable "${SETJOIN_OPTIONAL_START_ORDER[@]}" >/dev/null 2>&1 || true
    info "Services 'setjoin-funasr' and 'setjoin-asr-bot' enabled and (re)started."
  fi
  # A mis-keyed/dead SFU must fail the INSTALL, not the first meeting (spike
  # §6.8) — checked before the gateway's own health check further down.
  sfu_ok=0
  for _ in $(seq 1 15); do
    curl -sf --max-time 3 "http://127.0.0.1:7880/" >/dev/null 2>&1 && { sfu_ok=1; break; }
    sleep 2
  done
  [ "$sfu_ok" = "1" ] || die "setjoin-sfu did not answer http://127.0.0.1:7880/ — check: journalctl -u setjoin-sfu -n 50"
  info "LiveKit SFU healthy at http://127.0.0.1:7880/ (signal port, loopback-only)."
  # Valkey must answer PONG before recording can ever work — fail the
  # INSTALL loud, not the first recording attempt (Meet B2 Task 9).
  valkey_ok=0
  for _ in $(seq 1 15); do
    # REDISCLI_AUTH (env), not -a: a command-line -a flag is visible to any
    # local user via `ps`/`/proc/<pid>/cmdline` for the process's whole
    # lifetime — REDISCLI_AUTH is read once at valkey-cli startup and never
    # appears in argv (B3 Task 18 pipeline-review finding 4).
    [ "$(REDISCLI_AUTH="$VALKEY_PASSWORD" valkey-cli -p 6390 --no-auth-warning ping 2>/dev/null)" = "PONG" ] && { valkey_ok=1; break; }
    sleep 2
  done
  [ "$valkey_ok" = "1" ] || die "setjoin-valkey did not answer PING on 127.0.0.1:6390 — check: journalctl -u setjoin-valkey -n 50"
  info "Valkey healthy at 127.0.0.1:6390 (loopback-only, SFU<->Egress bus)."
  # Egress runs as a detached container, not a plain process — confirm the
  # container runtime actually has it up (the systemd unit can report
  # 'active' immediately after a container start races the pull).
  egress_ok=0
  for _ in $(seq 1 15); do
    "$CONTAINER_BIN" ps --filter "name=setjoin-egress" --filter "status=running" --format '{{.Names}}' 2>/dev/null \
      | grep -q '^setjoin-egress$' && { egress_ok=1; break; }
    sleep 2
  done
  [ "$egress_ok" = "1" ] || die "setjoin-egress container is not running — check: journalctl -u setjoin-egress -n 50 && $CONTAINER_BIN ps -a"
  info "Meet Egress container healthy ($CONTAINER_BIN ps: setjoin-egress running)."
  # A transient `systemctl restart` success is not evidence that the no-listener
  # updater observer survived startup. Require one stable PID across a bounded
  # interval; this catches credential/path and sandbox failures before install
  # can report success.
  updater_ok=0
  for _ in $(seq 1 10); do
    updater_pid="$(systemctl show setjoin-updater -p MainPID --value 2>/dev/null || true)"
    if [[ "$updater_pid" =~ ^[1-9][0-9]*$ ]] && systemctl is-active --quiet setjoin-updater; then
      sleep 1
      [ "$(systemctl show setjoin-updater -p MainPID --value 2>/dev/null || true)" = "$updater_pid" ] &&
        systemctl is-active --quiet setjoin-updater && { updater_ok=1; break; }
    fi
    sleep 1
  done
  [ "$updater_ok" = "1" ] || die "setjoin-updater observer did not remain active — check: journalctl -u setjoin-updater -n 50"
  info "Transactional updater observer healthy (stable no-listener systemd process)."
  # Meet B3 (Task 16): a mis-keyed/dead ASR sidecar pair must fail the
  # INSTALL, not the first captioned meeting (the spike §6.8 posture,
  # extended to the third sidecar pair).
  if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
    # funasr's ONNX model load is a slower cold start than the SFU/Egress
    # containers — a TCP-connect probe (no HTTP health endpoint on the raw
    # WS server) with a longer budget than the other probes here.
    funasr_ok=0
    for _ in $(seq 1 60); do
      (exec 3<>/dev/tcp/127.0.0.1/10096) 2>/dev/null && { exec 3<&- 3>&-; funasr_ok=1; break; }
      sleep 2
    done
    [ "$funasr_ok" = "1" ] || die "setjoin-funasr did not open a TCP listener on 127.0.0.1:10096 — check: journalctl -u setjoin-funasr -n 50 && $CONTAINER_BIN ps -a"
    info "FunASR runtime healthy (TCP listener at 127.0.0.1:10096)."
    asrbot_ok=0
    for _ in $(seq 1 15); do
      curl -sf --max-time 3 "http://127.0.0.1:7890/healthz" >/dev/null 2>&1 && { asrbot_ok=1; break; }
      sleep 2
    done
    [ "$asrbot_ok" = "1" ] || die "setjoin-asr-bot did not answer http://127.0.0.1:7890/healthz — check: journalctl -u setjoin-asr-bot -n 50"
    info "Captions bot healthy at http://127.0.0.1:7890/healthz (loopback-only)."
  fi
  # Auth answers /health on loopback before we let the gateway steps proceed —
  # a dead auth process here means every login will 502, so fail LOUD now.
  auth_ok=0
  for _ in $(seq 1 15); do
    curl -sf --max-time 3 "http://$AUTH_LISTEN/health" >/dev/null 2>&1 && { auth_ok=1; break; }
    sleep 2
  done
  [ "$auth_ok" = "1" ] || die "auth server did not answer http://$AUTH_LISTEN/health — check: journalctl -u setjoin-auth -n 50"
  info "Auth server healthy at http://$AUTH_LISTEN/health"
  # Front door ON (#264): the socket-activated gateway must answer its own
  # liveness probe before the install reports success.
  gateway_ok=0
  for _ in $(seq 1 15); do
    [ "$(curl -sf --max-time 3 "http://$GATEWAY_LISTEN/_gateway/healthz" 2>/dev/null)" = ok ] && { gateway_ok=1; break; }
    sleep 2
  done
  [ "$gateway_ok" = "1" ] || die "setjoin-gateway did not answer http://$GATEWAY_LISTEN/_gateway/healthz — check: journalctl -u setjoin-gateway -n 50"
  if tls_front_enabled "$CONFIG_ENV"; then
    _tls_probe=$(tls_front_probe_url "$CONFIG_ENV")
    curl -skf --max-time 5 "$_tls_probe" >/dev/null || die "native HTTPS front door did not answer $_tls_probe"
  fi
  info "Rust front door healthy (native HTTPS and loopback HTTP)."
else
  info "systemd not available — start manually (valkey + SFU + egress + auth first):"
  info "  sudo -u setjoin valkey-server $CONFIG_DIR/valkey.conf"
  info "  sudo -u setjoin $INSTALL_DIR/bin/livekit-server --config $LIVEKIT_YAML"
  info "  sudo $CONTAINER_BIN run --rm --name setjoin-egress --network=host --cap-add=SYS_ADMIN -v $EGRESS_YAML:/etc/egress.yaml:ro -e EGRESS_CONFIG_FILE=/etc/egress.yaml $EGRESS_IMAGE"
  if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
    # Direct-exec, NOT `bash run_server_2pass.sh` — the wrapper backgrounds
    # the server and exits, killing the container (B3 live gate 2026-07-16);
    # keep this in lockstep with setjoin-funasr.service.template's ExecStart.
    info "  sudo $CONTAINER_BIN run --rm --name setjoin-funasr -p 127.0.0.1:10096:10095 -v $FUNASR_MODELS_DIR:/workspace/models:ro -e GLOG_minloglevel=2 $FUNASR_IMAGE bash -c 'exec /workspace/FunASR/runtime/websocket/build/bin/funasr-wss-server-2pass --download-model-dir /workspace/models --model-dir damo/speech_paraformer-large-vad-punc_asr_nat-zh-cn-16k-common-vocab8404-onnx --online-model-dir damo/speech_paraformer-large_asr_nat-zh-cn-16k-common-vocab8404-online-onnx --vad-dir damo/speech_fsmn_vad_zh-cn-16k-common-vocab8404-onnx --punc-dir damo/punc_ct-transformer_zh-cn-common-vocab272727-onnx --itn-dir thuduj12/fst_itn_zh --lm-dir \"\" --decoder-thread-num \$(nproc) --io-thread-num 1 --model-thread-num 1 --port 10095 --certfile \"\" --keyfile \"\" --hotword /workspace/FunASR/runtime/websocket/hotwords.txt'"
    info "  sudo -u setjoin bash -c 'set -a; . $CONFIG_DIR/asrbot.env; exec $INSTALL_DIR/bin/asrbotd'"
  fi
  # Secrets stay OUT of argv: `env $(grep -v '^#' file | xargs)` would put every
  # config.env value into /proc/<pid>/cmdline — world-readable for the process
  # lifetime, the exact exposure the argv-secrets rule (see the systemd section
  # above, B3 Task 18 / REDISCLI_AUTH precedent) forbids. Sourcing the file with
  # `set -a` passes the values through the environment, which the kernel scopes
  # to the process owner (same as a systemd EnvironmentFile).
  info "  sudo -u setjoin bash -c 'set -a; . $CONFIG_ENV; . $DB_CRED_FILE; export LISTEN_ADDR=$AUTH_LISTEN TLS_CERT= TLS_KEY=; exec $INSTALL_DIR/authserverd'"
  info "  sudo -u setjoin bash -c 'set -a; . $CONFIG_ENV; . $DB_CRED_FILE; exec $INSTALL_DIR/mailserverd'"
  info "  sudo -u setjoin bash -c 'set -a; . $GATEWAY_ENV; exec $INSTALL_DIR/setjoin-gateway'"
fi

# ── Firewall + TURN guidance (Meet B1 Task 14, spike §6.5-§6.7) ─────────────
# 7880 (signal) is loopback-only by design and must never be opened. The rest
# is a fallback ladder: direct UDP is best; ICE/TCP 7881 and TURN/UDP 3478
# are progressively worse; TURN/TLS 5349 is last-resort (TCP head-of-line
# blocking degrades video) and needs the cert pair at TURN_CERT/TURN_KEY.
say "Firewall + TURN"
info "Open on this host's firewall: 7881/tcp, ${RTC_PORT_START:-50000}-${RTC_PORT_END:-60000}/udp, 3478/udp, 5349/tcp."
info "Do NOT expose 7880/tcp (the SFU signal port) — the gateway reverse-proxies it via /rtc."
info "NAT fallback ladder: direct UDP -> ICE/TCP 7881 -> TURN/UDP 3478 -> TURN/TLS 5349."
info "A 443-only-egress firewall on the GUEST side is not served in v1 (roadmap: TURN/TLS on 443)."
if grep -q '^  enabled: true' "$LIVEKIT_YAML" 2>/dev/null; then
  info "TURN is ENABLED (cert pair found at $TURN_CERT / $TURN_KEY)."
else
  info "TURN is DISABLED — no cert pair at $TURN_CERT / $TURN_KEY yet."
  info "For TURN, point DNS turn.$HOSTNAME at this host and drop a cert there (the gateway cert works if its SAN covers turn.$HOSTNAME), then re-run this installer."
fi

# ── 8. Provision the first admin through the local database authority ───────
say "First admin"
if [ -n "${ADMIN_PASSWORD:-}" ]; then
  bootstrap_output="$(printf '%s\n' "$ADMIN_PASSWORD" | \
      DB_DIRECT_OWNER_DSN="$DB_DIRECT_DSN" DB_OWNER_DSN="$DB_DSN" \
      CRYPTO_PROFILE="${CRYPTO_PROFILE:-standard}" \
      "$ROOT/server-rust/mailctl" bootstrap-admin --email "$ADMIN_EMAIL" --password-stdin 2>&1)" && bootstrap_status=0 || bootstrap_status=$?
  if [ "$bootstrap_status" -eq 0 ]; then
    info "Admin $ADMIN_EMAIL created through the local database authority."
  elif printf '%s' "$bootstrap_output" | grep -Fq 'bootstrap refused: setup already completed'; then
    info "Admin bootstrap skipped because this installation is already initialized."
  else
    die "Admin bootstrap failed: $bootstrap_output"
  fi
else
  info "No admin password supplied — run mailctl bootstrap-admin locally before first login."
fi

# ── 9. Health check + summary ────────────────────────────────────────────────
say "Health check"
# Loopback base URL the installer probes (LISTEN_ADDR is like ":443").
LOCAL_BASE="https://127.0.0.1${LISTEN_ADDR}"
health_body="$(curl -sk --max-time 5 "$LOCAL_BASE/health" || true)"
if printf '%s' "$health_body" | grep -q .; then
  info "Gateway healthy at $LOCAL_BASE/health"
else
  info "WARN: health check did not respond yet — check: journalctl -u setjoin -f"
fi
# Confirm the gateway actually picked up the LIVEKIT_* env (a wiring check,
# not a feature-toggle check — feature.meet ships seeded OFF, so this only
# proves the sidecar config took, not that it's in active use). Meet B1 Task
# 14, spike §6.8: a mis-keyed/dead SFU must be loud at install time.
if printf '%s' "$health_body" | grep -q '"sfu"'; then
  info "Gateway /health reports the sfu component — LIVEKIT_* config was picked up."
else
  info "WARN: gateway /health has no 'sfu' component — restart if this persists: systemctl restart setjoin"
fi
# Meet B2: same wiring check for the egress component (registered only when
# meetCfg.Configured() && meetCfg.EgressEnabled — main.go).
if printf '%s' "$health_body" | grep -q '"egress"'; then
  info "Gateway /health reports the egress component — MEET_EGRESS_ENABLED config was picked up."
else
  info "WARN: gateway /health has no 'egress' component — restart if this persists: systemctl restart setjoin"
fi
# Meet B3 (Task 16): same wiring check for the asr component (registered
# only when meetCfg.ASRURL != "" — main.go), and ONLY when this OPTIONAL
# leg was actually enabled — an unconditional check here would WARN on
# every install that correctly never wired ASR_URL at all.
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  if printf '%s' "$health_body" | grep -q '"asr"'; then
    info "Gateway /health reports the asr component — ASR_URL config was picked up."
  else
    info "WARN: gateway /health has no 'asr' component — restart if this persists: systemctl restart setjoin"
  fi
fi

# Meet B3 (Task 16): the two captions summary lines, computed once here
# (rather than an inline conditional command substitution inside the
# heredoc below — plainer to read, same result either way).
CAPTIONS_SUMMARY_LINE="  Meet Captions: not enabled (re-run and answer yes to the MEET_CAPTIONS_ENABLED prompt to add it)"
CAPTIONS_LOG_LINES=""
if [ "$MEET_CAPTIONS_ENABLED" = "true" ]; then
  CAPTIONS_SUMMARY_LINE="  Meet Captions: $CONFIG_DIR/asrbot.env (mode 0600); systemctl status setjoin-asr-bot setjoin-funasr"
  CAPTIONS_LOG_LINES="             journalctl -u setjoin-asr-bot -f  (Meet Captions — room-bot)
             journalctl -u setjoin-funasr -f   (Meet Captions — ASR runtime)"
fi

# Pillar C1 Task 9: same one-line summary genre, no unit/log line — federation
# runs inside the 'setjoin' gateway process itself (journalctl -u setjoin
# already covers it).
FEDERATION_SUMMARY_LINE="  Federation:  not enabled (re-run and answer yes to the FEDERATION_ENABLED prompt to add it)"
if [ "$FEDERATION_ENABLED" = "true" ]; then
  FEDERATION_SUMMARY_LINE="  Federation:  $FEDERATION_DIR/ca.crt is this org's anchor for peers; feature.federation + the admin allow-list still gate actual peering"
fi

PGPOOL_SUMMARY_LINE="  Pgpool HA:   not enabled (re-run and answer yes to the HA_FAILOVER_ENABLED prompt to add it)"
if [ "$HA_FAILOVER_ENABLED" = "true" ]; then
  if [ -f "$PGPOOL_DIR/known_hosts" ]; then
    PGPOOL_SUMMARY_LINE="  Pgpool HA:   $PGPOOL_DIR/failover.sh (0700) + $PGPOOL_DIR/known_hosts (0644) installed; remote failover is armed"
  else
    PGPOOL_SUMMARY_LINE="  Pgpool HA:   $PGPOOL_DIR/failover.sh (0700) installed; known_hosts NOT provisioned — remote failover fails closed until peer keys are installed"
  fi
fi

cat <<DONE

═══════════════════════════════════════════════════════════════
  setjoin single-node install complete.

  Web UI:    https://$HOSTNAME/
  Setup:     local only — mailctl bootstrap-admin --email <address>
  Setup token: $SETJOIN_SETUP_TOKEN
             (one-time setup API token — stored in $CONFIG_ENV as
              SETJOIN_SETUP_TOKEN; pass it as the X-Setup-Token header on
              control-socket setup calls, e.g.:
              curl --unix-socket /run/setjoin/control.sock \\
                -H "X-Setup-Token: <token>" http://setjoin-control/setup/preflight …)
  Health:    https://$HOSTNAME/health
  Front door: setjoin-gateway terminates HTTPS on :443; loopback HTTP is $GATEWAY_LISTEN.
             Unported shapes use the existing Go upstream http://127.0.0.1:80.
             Settings: $GATEWAY_ENV and $TLS_ENV. Recovery restores a complete release.
  Config:    $CONFIG_ENV   (mode 0600 — back this up; it holds your app-tier secrets)
  DB creds:  $DB_CRED_FILE (mode 0600 root:root — privileged DB tiers; back this up too)
  S3 IAM:    $S3_IAM_FILE (mode 0600 — the SeaweedFS -s3.config admin identity)
  Meet SFU:  $LIVEKIT_YAML (mode 0600); systemctl status setjoin-sfu
  Meet Bus:  $VALKEY_CONF (mode 0600); systemctl status setjoin-valkey
  Meet Egress: $EGRESS_YAML (mode 0640 root:0 — the egress container reads it as uid 1001/gid 0); systemctl status setjoin-egress
$CAPTIONS_SUMMARY_LINE
$FEDERATION_SUMMARY_LINE
$PGPOOL_SUMMARY_LINE
  Logs:      journalctl -u setjoin -f          (gateway)
             journalctl -u setjoin-gateway -f  (Rust front door)
             journalctl -u setjoin-auth -f     (auth server — login/MFA/SSO)
             journalctl -u setjoin-sfu -f      (Meet SFU — LiveKit)
             journalctl -u setjoin-valkey -f   (Meet bus — SFU<->Egress)
             journalctl -u setjoin-egress -f   (Meet Egress — recording)
$CAPTIONS_LOG_LINES
  Users:     mailctl login https://$HOSTNAME  →  mailctl user create ...

  Scope: single-node, <100 users. For 100+ users or HA: docs/guides/HA_OVERVIEW.md
═══════════════════════════════════════════════════════════════
DONE
