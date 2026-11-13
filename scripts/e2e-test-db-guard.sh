#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# e2e-test-db-guard.sh — always-on, fail-closed target validation for the
# destructive e2e database lane (L2-C9; triage R-DESTRUCTIVE-OP-GUARD /
# E2E-DESTRUCTIVE-DB-OP-NO-GUARD).
#
# Source-and-call pattern mirrors scripts/architecture-r2-test-db.sh, but
# there is deliberately NO opt-in kill switch: that lane's opt-in test-mode
# variable being unsatisfiable from the e2e lane (its name regex is
# arch-r2-lane-specific and cannot admit e2e names) IS the triage defect, so
# this guard is unconditional for every caller that can DROP/CREATE a
# database, provision cluster-global roles (provision-roles.sql), or reset
# role passwords.
#
# Layers, ordered — cluster identity gates FIRST (r3); the DB-level
# disposable marker stays additive (r2): neither marker alone admits a run.
#   1. e2e_validate_test_db             pure, zero DB contact: target-DB name
#                                       allowlist (byte-identical to the
#                                       in-repo e2e convention,
#                                       e2e-browser-complete.sh), loopback
#                                       host assertion, and a constructed-DSN
#                                       path cross-check for every DSN
#                                       variable that is set. Must run before
#                                       INSTANCE_DIR derivation and before
#                                       any filesystem or network effect.
#   2. e2e_validate_test_db_cluster     connected gate. FIRST validates the
#                                       registry namespace at read time (r4,
#                                       C9 HOLD): the registry dir, endpoint
#                                       dir and marker file must match the
#                                       bootstrap-writer posture — regular
#                                       non-symlink, invoking-user owner,
#                                       not group/world-writable dirs, 0600
#                                       marker — strictly observationally, so
#                                       a planted or foreign-owned registry
#                                       is refused before its contents can
#                                       satisfy anything. Then reads the
#                                       endpoint-keyed ownership marker, then
#                                       the CONNECTED cluster's
#                                       system_identifier
#                                       (pg_control_system(); fixed at initdb,
#                                       unique per cluster — the repo's
#                                       cluster-identity notion, cf.
#                                       check-upgrade-contracts.sh) and
#                                       requires an exact match, so a
#                                       REPLACED cluster at a known endpoint
#                                       is refused; then, only if the target
#                                       DB exists, requires the
#                                       'setjoin-disposable-test-db' comment.
#                                       Must run after pg_isready and BEFORE
#                                       role provisioning, the cluster-global
#                                       ALTER ROLE password resets, and the
#                                       destructive load.
#   3. e2e_bootstrap_test_db_cluster    the EXPLICIT bootstrap that records the
#                                       connected cluster's identity into the
#                                       marker (direct invocation only:
#                                       `bash scripts/e2e-test-db-guard.sh
#                                       --bootstrap`). There is no silent
#                                       first-run admission: an absent marker
#                                       refuses even when the target DB is
#                                       absent.
#
# SQL interpolation (r2-2): the repository rule forbids concatenating input
# into SQL, and an upstream shell allowlist does NOT satisfy that rule by
# itself — the allowlist is defense in depth. Every SQL-text site (the
# loader's DROP/CREATE and the marker stamp in load-test-schema.sh, and this
# guard's probes) therefore passes values AND identifiers as quoted psql
# variables (:'db_name' literal / :"db_name" identifier); the identity probe
# takes no interpolated input at all. The marker-probe SQL below is the
# shipped form the self-test asserts against a PATH-shimmed psql.
#
# Marker layout: ${E2E_CLUSTER_REGISTRY:-${TMPDIR:-/tmp}/
#   setjoin-e2e-cluster-registry}/<normalized-endpoint>/marker
#   (0600, invoking user; content binds endpoint + system_identifier).
#   That posture is re-validated at READ time (r4): bootstrap-only file
#   checks would let a planted or foreign-owned registry satisfy
#   verification without an authorized bootstrap.
# Keyed by ENDPOINT, never by DB_NAME, so a second conforming DB name on the
# same cluster finds the same evidence and a fresh INSTANCE_DIR never
# silently re-bootstraps. The endpoint is an address, not an identity — the
# identity is the system_identifier INSIDE the marker, re-read from the
# connected instance on every run.
#
# Effective-target resolution (both lanes that source this guard):
#   host: E2E_PGHOST → DB_HOST → PGHOST → 127.0.0.1
#   port: E2E_PGPORT → DB_PORT → PGPORT → 5432
#   user: E2E_PGUSER → DB_USER → PGUSER → mail
# A stale exported (remote) PGHOST therefore fails closed until unset or
# overridden by E2E_PGHOST — the poisoned-environment actor the triage names.
# ──────────────────────────────────────────────────────────────────────────

# Guard-owned globals (defaults keep sourcing safe under `set -u`).
_E2E_GUARD_DISPOSABLE_MARKER='setjoin-disposable-test-db'
_E2E_GUARD_HOST=''
_E2E_GUARD_PORT=''
_E2E_GUARD_USER=''

_e2e_guard_refuse() {
  # Fail-closed refusal, E_ARCH_R2_UNSAFE_DB line shape. Echoes only;
  # every caller returns 2 explicitly right after.
  echo "E_SEC_E2E_DB_TARGET problem=$1 cause=$2 value=$3 fix=$4" >&2
}

_e2e_guard_effective_host() {
  printf '%s' "${E2E_PGHOST:-${DB_HOST:-${PGHOST:-127.0.0.1}}}"
}

_e2e_guard_effective_port() {
  printf '%s' "${E2E_PGPORT:-${DB_PORT:-${PGPORT:-5432}}}"
}

_e2e_guard_effective_user() {
  printf '%s' "${E2E_PGUSER:-${DB_USER:-${PGUSER:-mail}}}"
}

_e2e_guard_host_is_loopback() {
  # The architecture-r2-test-db.sh:15-21 shape: exact loopback addresses or
  # an absolute Unix-socket directory path. This is the grounded form of the
  # plan's "refuse production-shaped DSNs": the lane constructs its DSNs
  # from these same vars.
  case "$1" in
    127.0.0.1 | localhost | ::1 | \[::1\] | /*) return 0 ;;
    *) return 1 ;;
  esac
}

_e2e_guard_identity_is_wellformed() {
  # system_identifier is a bigint; anything else is "unreadable" (r3-1.2).
  case "$1" in
    '' | *[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

_e2e_guard_dsn_db_name() {
  # Pure-shell path-component extraction from a constructed postgres://
  # DSN. Anything unparseable yields a string that cannot equal the
  # allowlisted DB_NAME, i.e. it fails closed.
  local rest="$1"
  rest="${rest#postgresql://}"
  rest="${rest#postgres://}"
  rest="${rest##*@}"  # drop userinfo through the LAST @
  rest="${rest%%\?*}" # drop query
  rest="${rest%%#*}"  # drop fragment
  rest="${rest#*/}"   # keep the path component (db name)
  printf '%s' "$rest"
}

_e2e_guard_registry_dir() {
  printf '%s' "${E2E_CLUSTER_REGISTRY:-${TMPDIR:-/tmp}/setjoin-e2e-cluster-registry}"
}

_e2e_guard_endpoint_key() {
  # Filesystem-safe key for the endpoint ADDRESS only. Identity lives
  # inside the marker, not in the key (r3-1).
  local endpoint
  endpoint="$(_e2e_guard_effective_host):$(_e2e_guard_effective_port)"
  printf '%s' "${endpoint//[^A-Za-z0-9._-]/_}"
}

_e2e_guard_marker_path() {
  printf '%s/%s/marker' "$(_e2e_guard_registry_dir)" "$(_e2e_guard_endpoint_key)"
}

# ── Layer 1: pure validation (no DB contact) ───────────────────────────────
e2e_validate_test_db() {
  local db_name="${DB_NAME:-${E2E_DB_NAME:-}}"
  local db_host dsn_name dsn parsed

  if [ -z "$db_name" ]; then
    _e2e_guard_refuse invalid_test_database no_database_selected unset \
      "select a disposable target via E2E_DB_NAME (or DB_NAME)"
    return 2
  fi
  # Byte-identical to the in-repo convention (e2e-browser-complete.sh):
  # anchored ^[A-Za-z0-9_]+$ AND a _e2e/_test suffix. Refuses postgres,
  # template0/1, mailserver, and every other shape by construction.
  if [[ ! "$db_name" =~ ^[A-Za-z0-9_]+$ ]] || [[ ! "$db_name" =~ _(e2e|test)$ ]]; then
    _e2e_guard_refuse invalid_test_database name_not_disposable_convention "$db_name" \
      "use a database name matching ^[A-Za-z0-9_]+\$_ with a _e2e or _test suffix (repo e2e convention)"
    return 2
  fi

  db_host="$(_e2e_guard_effective_host)"
  if ! _e2e_guard_host_is_loopback "$db_host"; then
    _e2e_guard_refuse remote_database_host e2e_lane_is_local_only "$db_host" \
      "set E2E_PGHOST to 127.0.0.1, localhost, ::1, or an absolute Unix-socket path; unset a stale exported PGHOST"
    return 2
  fi

  # Constructed-DSN cross-check: every DSN variable that is set (all four
  # are constructed by start-test-stack.sh from the validated vars) must
  # point at the allowlisted DB_NAME. Unset here means the caller has not
  # constructed DSNs yet; the connected gate re-runs this check.
  for dsn_name in DB_DSN APP_DSN WORKER_DSN OWNER_DSN; do
    dsn="${!dsn_name:-}"
    [ -n "$dsn" ] || continue
    parsed="$(_e2e_guard_dsn_db_name "$dsn")"
    if [ "$parsed" != "$db_name" ]; then
      _e2e_guard_refuse dsn_mismatch constructed_dsn_points_at_another_database "${dsn_name}=${parsed}" \
        "rebuild ${dsn_name} from the validated PG* vars so its path component is ${db_name}"
      return 2
    fi
  done

  echo "e2e-db-guard: validated local disposable database ${db_name}"
  return 0
}

# ── Layer 2 support: connected probes ──────────────────────────────────────
_e2e_guard_psql() {
  # All probes go to the always-present `postgres` database of the
  # connected cluster, so the gate works identically before the target DB
  # is ever created.
  psql -X -h "$_E2E_GUARD_HOST" -p "$_E2E_GUARD_PORT" -U "$_E2E_GUARD_USER" \
    -d postgres -At -v ON_ERROR_STOP=1 "$@"
}

_e2e_guard_read_cluster_identity() {
  # Cluster identity from the CONNECTED instance. Fixed catalog function,
  # zero interpolated inputs (r3-1.1). Heredoc (not -c) so nothing ever
  # blocks on a tty stdin when shimmed in tests.
  _e2e_guard_psql <<'SQL'
SELECT system_identifier FROM pg_control_system();
SQL
}

_e2e_guard_read_db_state() {
  # Distinguishes "target DB absent" from "present but unmarked" (the r1
  # matrix refuses the latter, protects an operator DB coincidentally named
  # like the target). The value AND identifier pass as quoted psql
  # variables (r2-2) — this is the shipped SQL form the self-test pins.
  _e2e_guard_psql -v db_name="$DB_NAME" <<'SQL'
SELECT CASE
         WHEN NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name') THEN 'db-absent'
         ELSE coalesce((SELECT shobj_description(oid, 'pg_database')
                          FROM pg_database WHERE datname = :'db_name'), '')
       END;
SQL
}

# ── Layer 2 support: READ-TIME registry namespace validation (r4) ──────────
# The C9 HOLD item: marker CONTENT is trusted only when the namespace around
# it carries the bootstrap writer's provenance. These are the read-time twins
# of the bootstrap-only hostility checks (symlink / regular-file type /
# owner / mode / registry-directory posture). Both are STRICTLY
# OBSERVATIONAL — the verification path never creates, adopts, tightens or
# deletes anything; a missing path returns 0 and falls through to the
# absent-marker refusal, which stays the only first-run answer.
_e2e_guard_check_registry_dir_ro() {
  local dir="$1"
  if [ -L "$dir" ]; then
    _e2e_guard_refuse registry_dir_hostile registry_path_is_symlink "$dir" \
      "remove ${dir} and retry the bootstrap"
    return 2
  fi
  [ -e "$dir" ] || return 0
  if [ ! -d "$dir" ]; then
    _e2e_guard_refuse registry_dir_hostile registry_path_not_a_directory "$dir" \
      "remove ${dir} and retry the bootstrap"
    return 2
  fi
  if [ -z "$(find "$dir" -maxdepth 0 -type d -user "$(id -u)" ! -perm -0020 ! -perm -0002 2>/dev/null)" ]; then
    _e2e_guard_refuse registry_dir_hostile registry_path_foreign_or_group_writable "$dir" \
      "remove ${dir} and retry the bootstrap"
    return 2
  fi
  return 0
}

_e2e_guard_check_marker_ro() {
  # The bootstrap writer leaves a regular (never symlinked) 0600 marker
  # owned by the invoking user; verification accepts no other shape, so a
  # planted or foreign-owned marker cannot satisfy this gate.
  local marker="$1"
  if [ -L "$marker" ]; then
    _e2e_guard_refuse marker_hostile marker_path_is_symlink "$marker" \
      "remove ${marker} and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  [ -e "$marker" ] || return 0
  if [ ! -f "$marker" ]; then
    _e2e_guard_refuse marker_hostile marker_not_a_regular_file "$marker" \
      "remove ${marker} and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  if [ -z "$(find "$marker" -maxdepth 0 -type f -user "$(id -u)" 2>/dev/null)" ]; then
    _e2e_guard_refuse marker_hostile marker_not_owned_by_invoking_user "$marker" \
      "the ownership marker must be owned by the invoking user; remove ${marker} and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  if [ -z "$(find "$marker" -maxdepth 0 -type f -user "$(id -u)" -perm 0600 2>/dev/null)" ]; then
    _e2e_guard_refuse marker_hostile marker_not_mode_0600 "$marker" \
      "the ownership marker must be mode 0600; remove ${marker} and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  return 0
}

# ── Layer 2: connected gate (identity first, DB marker additive) ───────────
e2e_validate_test_db_cluster() {
  e2e_validate_test_db || return $?

  local endpoint registry marker expected observed marker_endpoint db_state
  _E2E_GUARD_HOST="$(_e2e_guard_effective_host)"
  _E2E_GUARD_PORT="$(_e2e_guard_effective_port)"
  _E2E_GUARD_USER="$(_e2e_guard_effective_user)"
  endpoint="${_E2E_GUARD_HOST}:${_E2E_GUARD_PORT}"
  marker="$(_e2e_guard_marker_path)"

  # (0) READ-TIME namespace validation (r4, C9 HOLD): marker contents are
  # trusted only when the registry namespace proves the same provenance the
  # bootstrap writer leaves — regular non-symlink directories owned by the
  # invoking user and not group/world-writable, plus a regular non-symlink
  # 0600 invoking-user-owned marker. Strictly observational (no creation,
  # adoption or tightening here); a planted or foreign-owned registry is
  # refused BEFORE its contents can satisfy the identity match, and before
  # any database probe. Missing paths fall through to (1), which stays the
  # only answer for a first run.
  registry="$(_e2e_guard_registry_dir)"
  _e2e_guard_check_registry_dir_ro "$registry" || return 2
  _e2e_guard_check_registry_dir_ro "${registry}/$(_e2e_guard_endpoint_key)" || return 2
  _e2e_guard_check_marker_ro "$marker" || return 2

  # (1) Ownership marker must exist — no silent first-run admission, even
  # when the target DB is absent (r2-1.3).
  expected="$(sed -n 's/^system_identifier=//p' "$marker" 2>/dev/null | head -1)"
  if [ -z "$expected" ]; then
    _e2e_guard_refuse unowned_cluster no_disposable_cluster_marker "$endpoint" \
      "no ownership marker for ${endpoint}; verify this cluster holds nothing you care about, then run: bash scripts/e2e-test-db-guard.sh --bootstrap (E2E_PGHOST/E2E_PGPORT select it)"
    return 2
  fi
  marker_endpoint="$(sed -n 's/^endpoint=//p' "$marker" 2>/dev/null | head -1)"
  if [ "$marker_endpoint" != "$endpoint" ]; then
    _e2e_guard_refuse unowned_cluster marker_belongs_to_another_endpoint "${marker_endpoint:-unreadable}" \
      "the marker under ${endpoint} records another endpoint; remove the stale registry entry or re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  if ! _e2e_guard_identity_is_wellformed "$expected"; then
    _e2e_guard_refuse cluster_identity_unreadable marker_identity_malformed "expected=${expected}" \
      "the ownership marker for ${endpoint} is malformed; re-verify the cluster is disposable and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi

  # (2) Identity re-read from the CONNECTED cluster must match exactly.
  observed="$(_e2e_guard_read_cluster_identity 2>/dev/null)"
  if ! _e2e_guard_identity_is_wellformed "$observed"; then
    _e2e_guard_refuse cluster_identity_unreadable cluster_did_not_report_identifier "expected=${expected} observed=<unreadable>" \
      "the cluster at ${endpoint} did not report a readable system_identifier; verify it is disposable and re-run: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi
  if [ "$observed" != "$expected" ]; then
    _e2e_guard_refuse cluster_identity_mismatch marker_records_a_different_cluster "expected=${expected} observed=${observed}" \
      "the cluster answering at ${endpoint} is NOT the bootstrapped one (replaced container/volume?); verify the new cluster is disposable and re-bootstrap: bash scripts/e2e-test-db-guard.sh --bootstrap"
    return 2
  fi

  # (3) Additive DB-level marker — only reachable on an identity-verified
  # cluster; alone it never admits a run.
  if ! db_state="$(_e2e_guard_read_db_state 2>/dev/null)"; then
    _e2e_guard_refuse cluster_probe_failed db_state_probe_failed "$DB_NAME" \
      "could not read pg_database state from ${endpoint} after a verified identity; investigate the cluster before retrying"
    return 2
  fi
  case "$db_state" in
    'db-absent') ;; # first run of this name on an OWNED disposable cluster
    "$_E2E_GUARD_DISPOSABLE_MARKER") ;;
    *)
      _e2e_guard_refuse missing_disposable_marker target_db_lacks_the_disposable_comment "$DB_NAME" \
        "database ${DB_NAME} exists on ${endpoint} without the '${_E2E_GUARD_DISPOSABLE_MARKER}' comment; manually verify it holds nothing you need, then drop or rename it before rerunning"
      return 2
      ;;
  esac

  echo "e2e-db-guard: verified disposable cluster ${endpoint} (system_identifier=${observed}) and database ${DB_NAME}"
  return 0
}

# ── Layer 3: explicit bootstrap (direct invocation only) ───────────────────
_e2e_guard_ensure_private_dir() {
  # Same posture as the landed INSTANCE_DIR hardening: atomic-exclusive
  # mkdir(2) WITHOUT -p; on EEXIST the full hostility re-check runs and the
  # path is adopted only if provably ours.
  local dir="$1"
  if ! mkdir -m 0700 "$dir" 2>/dev/null; then
    if [ -L "$dir" ]; then
      _e2e_guard_refuse registry_dir_hostile registry_path_is_symlink "$dir" \
        "remove ${dir} and retry the bootstrap"
      return 2
    fi
    if [ ! -d "$dir" ]; then
      _e2e_guard_refuse registry_dir_hostile registry_path_not_a_directory "$dir" \
        "remove ${dir} and retry the bootstrap"
      return 2
    fi
    if [ -z "$(find "$dir" -maxdepth 0 -type d -user "$(id -u)" ! -perm -0020 ! -perm -0002 2>/dev/null)" ]; then
      _e2e_guard_refuse registry_dir_hostile registry_path_foreign_or_group_writable "$dir" \
        "remove ${dir} and retry the bootstrap"
      return 2
    fi
    chmod 0700 "$dir"
  fi
  return 0
}

e2e_bootstrap_test_db_cluster() {
  local db_host db_port endpoint dir marker tmp observed
  db_host="$(_e2e_guard_effective_host)"
  db_port="$(_e2e_guard_effective_port)"
  if ! _e2e_guard_host_is_loopback "$db_host"; then
    _e2e_guard_refuse remote_database_host bootstrap_is_local_only "$db_host" \
      "set E2E_PGHOST to 127.0.0.1, localhost, ::1, or an absolute Unix-socket path"
    return 2
  fi
  _E2E_GUARD_HOST="$db_host"
  _E2E_GUARD_PORT="$db_port"
  _E2E_GUARD_USER="$(_e2e_guard_effective_user)"
  endpoint="${db_host}:${db_port}"

  observed="$(_e2e_guard_read_cluster_identity 2>/dev/null)"
  if ! _e2e_guard_identity_is_wellformed "$observed"; then
    _e2e_guard_refuse cluster_identity_unreadable cluster_did_not_report_identifier "$endpoint" \
      "cannot record ownership: the cluster at ${endpoint} did not report a readable system_identifier"
    return 2
  fi

  dir="$(_e2e_guard_registry_dir)/$(_e2e_guard_endpoint_key)"
  marker="${dir}/marker"
  _e2e_guard_ensure_private_dir "$(_e2e_guard_registry_dir)" || return 2
  _e2e_guard_ensure_private_dir "$dir" || return 2
  tmp="$(mktemp "${dir}/.marker.XXXXXX")" || {
    _e2e_guard_refuse marker_write_failed mktemp_failed "$dir" "check permissions on ${dir} and retry"
    return 2
  }
  {
    echo "# setjoin e2e disposable-cluster ownership marker (L2-C9 r3)."
    echo "# Binds the endpoint ADDRESS to the CLUSTER IDENTITY that answered"
    echo "# at bootstrap time. Manual edits are self-defeating: every run"
    echo "# re-reads system_identifier from the connected instance."
    echo "endpoint=${endpoint}"
    echo "system_identifier=${observed}"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$tmp" || {
    rm -f "$tmp"
    _e2e_guard_refuse marker_write_failed write_failed "$tmp" "retry the bootstrap"
    return 2
  }
  chmod 0600 "$tmp"
  if ! mv -f "$tmp" "$marker"; then
    rm -f "$tmp"
    _e2e_guard_refuse marker_write_failed mv_failed "$marker" "retry the bootstrap"
    return 2
  fi

  echo "e2e-db-guard: bootstrapped disposable-cluster ownership for ${endpoint} (system_identifier=${observed})"
  return 0
}

# ── Direct-invocation entry: EXPLICIT bootstrap only ───────────────────────
# Sourcing this file runs nothing; the verification gate is never satisfied
# by sourcing. The gate lives in the consumers (start-test-stack.sh).
if [ "${BASH_SOURCE[0]:-}" = "$0" ]; then
  case "${1:-}" in
    --bootstrap)
      e2e_bootstrap_test_db_cluster
      exit $?
      ;;
    *)
      echo "usage: bash scripts/e2e-test-db-guard.sh --bootstrap" >&2
      echo "  Records the CONNECTED cluster's system_identifier into the" >&2
      echo "  endpoint-keyed ownership marker after you verified the cluster" >&2
      echo "  is disposable. E2E_PGHOST/E2E_PGPORT/E2E_PGUSER (or DB_HOST/" >&2
      echo "  DB_PORT/DB_USER) select the target. Verification gates run" >&2
      echo "  automatically inside start-test-stack.sh; this entry only bootstraps." >&2
      exit 2
      ;;
  esac
fi
