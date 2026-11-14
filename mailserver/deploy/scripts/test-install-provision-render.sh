#!/usr/bin/env bash
set -euo pipefail

# Render/posture check for the install.sh provisioning legs added by the
# deploy-lane r2 integration (med-deploy-s3-credentials-b1r2-001,
# med-deploy-ssh-host-identity-b1r2-002):
#   1. install.sh + upgrade.sh stay bash-syntax-clean (shellcheck -S warning
#      when available, loud explicit skip when not);
#   2. S3 admin identity — INSTALL-TIME GENERATION: the installer renders the
#      server-side S3 identity config to a 0600 path from the generated
#      S3_ACCESS_KEY/S3_SECRET_KEY, refuses empty material, and rejects
#      well-known default credentials LOUD before the file a deployment loads
#      can exist (deployment-time rejection);
#   3. Pgpool-II failover leg — the reviewed failover.sh is installed 0700
#      root-owned, and /etc/pgpool2/known_hosts is built ONLY from
#      operator-verified input: the strict validator function is exercised
#      FUNCTIONALLY below (real keys, and every rejected shape), a scanned-key
#      install is impossible without interactive verification (NONINTERACTIVE
#      refuses), and no known_hosts is written from unverified input.
#   4. Privileged-DB-credential split (DEPLOY-004, L2-C8 packet r1+r2+r3 +
#      Astra impl-HOLD fixes):
#      DB_WORKER_DSN/DB_OWNER_DSN/DB_DIRECT_OWNER_DSN live ONLY in
#      $CONFIG_DIR/db-credentials.d/db-credentials.env (0600 root:root below
#      the root:root 0755 config dir — the r3 root-controlled ANCESTOR), both
#      units receive it as a second order-documented EnvironmentFile=, the
#      one-way exactly-once migration and the whole-directory-replacement
#      namespace guard are EXECUTED over sandboxed fixture trees (hermetic —
#      no live PostgreSQL), upgrade.sh's schema-apply selection is executed
#      against the split layout, and every secret-write/redaction posture pin
#      is proven load-bearing by planted-regression mutants the lane must
#      FIRE on. The Astra HOLD fixes are pinned here as behavior, not
#      comments:
#        - the REAL legacy ordering: entry validation accepts the
#          setjoin-owned pre-split ancestor (that state IS the migration
#          input), the privileged-dir conversion runs FIRST, and the
#          migration re-renders the units through the REAL render_runtime_units
#          (real renderers, real templates, sandboxed destinations) with
#          AUTH_ENV assigned — no success stub;
#        - the credential file is UNCONDITIONAL across postures: a fresh
#          --permissive-dsn install renders it too (content differs: owner
#          tiers only, never a worker key);
#        - a recovered owner DSN is never echoed through ask's default-value
#          prompt (the asks carry the redact marker).
# See D-MAILSERVER-DEPLOY-001 / D-MAILSERVER-DEPLOY-002 / D-MAILSERVER-DEPLOY-004.

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
INSTALL="$ROOT/mailserver/deploy/scripts/install.sh"
S3_LIB="$ROOT/mailserver/deploy/scripts/lib-s3-identity.sh"
UPGRADE="$ROOT/mailserver/deploy/scripts/upgrade.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1. Syntax gate (manifest lane: bash -n install.sh upgrade.sh).
bash -n "$INSTALL"
bash -n "$UPGRADE"

# shellcheck source=lib-s3-identity.sh
source "$S3_LIB"

require() {
  local desc="$1" pattern="$2" file="${3:-$INSTALL}"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "install provision render: missing required pattern ($desc): $pattern" >&2
    exit 1
  fi
}

forbid() {
  local desc="$1" pattern="$2"
  if grep -Fq -- "$pattern" "$INSTALL"; then
    echo "install provision render: forbidden pattern present ($desc): $pattern" >&2
    grep -n -- "$pattern" "$INSTALL" >&2 || true
    exit 1
  fi
}

# 2. S3 admin identity: install-time generation into a 0600 secrets path,
#    rendered from the same generated keys config.env carries (law 3), with
#    loud deployment-time rejection of well-known/empty material.
# shellcheck disable=SC2016  # literal $-pattern grep
require 'S3 identity file target' 'S3_IAM_FILE="$CONFIG_DIR/seaweedfs-s3.json"'
require 'S3 identity written under private umask' '( umask 077'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'S3 identity heredoc target' 'cat > "$S3_IAM_FILE" <<JSON'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'S3 identity mode pinned 0600' 'chmod 600 "$S3_IAM_FILE"'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'S3 identity rendered from generated access key' '{"accessKey": "$S3_ACCESS_KEY", "secretKey": "$S3_SECRET_KEY"}'
require 'S3 identity carries the admin action set' '"actions": ["Admin", "Read", "Write", "List", "Tagging"]'
require 'empty credential material refused' 'S3_ACCESS_KEY/S3_SECRET_KEY missing — refusing to render the S3 identity config.' "$S3_LIB"
# The install.sh wiring must delegate to the shared predicate, and the
# substring-wildcard regression must stay absent from both files.
# shellcheck disable=SC2016  # literal $-pattern grep
require 'S3 admission delegated to the shared predicate' 's3_identity_admit "$S3_ACCESS_KEY" "$S3_SECRET_KEY"'
require 'S3 predicate library sourced' 'source "$ROOT/mailserver/deploy/scripts/lib-s3-identity.sh"'
for f in "$INSTALL" "$S3_LIB"; do
  if grep -Eq '\*minioadmin\*|\*changeme\*|\*change-me\*|\*replace_me\*|\*replace-me\*' "$f"; then
    echo "install provision render: S3 known-weak rejection regressed to substring matching in $f" >&2
    exit 1
  fi
done

# Behavioural arm: exercise the REAL predicate, not its source text. Covers
# vendor defaults, placeholders, mixed case, repeated-pattern values (which
# clear both the whole-value lists and any length floor), the length
# boundaries, and a strong random secret that merely CONTAINS a marker
# substring (which must be admitted — a substring guard would refuse it).
admit_case() { # label user pass expect
  if (s3_identity_admit "$2" "$3") >/dev/null 2>&1; then got=ADMIT; else got=REFUSE; fi
  if [ "$got" = "$4" ]; then
    printf '  ok: s3 admit %s\n' "$1"
  else
    printf '  FAIL: s3 admit %s (want %s, got %s)\n' "$1" "$4" "$got" >&2
    exit 1
  fi
}
admit_case 'vendor default pair' minioadmin minioadmin12345 REFUSE
admit_case 'vendor default, short secret' minioadmin minioadmin REFUSE
admit_case 'changeme placeholder' changeme changeme REFUSE
admit_case 'mixed-case placeholder' CHANGE-ME Change-Me REFUSE
admit_case 'replace_me placeholder' replace_me replace_me REFUSE
admit_case 'admin/admin12345 pair' admin admin12345 REFUSE
admit_case 'root/rootroot pair' root rootroot REFUSE
admit_case 'placeholder-prefixed user' replace_me_Xk9pQm2RtLwZ Lp4ZsRa8Nd3fGh7YwVb2CxMq REFUSE
admit_case 'placeholder-prefixed secret' svc-account-01 changeme-the-real-one-9fK2 REFUSE
admit_case 'decorated replace_me placeholder' replace_me_with_your_key aaaaaaaaaaaaaaaaaaaaaaaa REFUSE
admit_case 'decorated changeme placeholder' changeme_with_a_real_secret_x b7Qw2Rt9Lp4Zs REFUSE
admit_case 'marker-wrapped both fields' prefix-changeme-suffix suffix-changeme-value REFUSE
admit_case 'vendor default secret as USER' minioadmin12345 aXb7changemeQ2wErTyUiOp9aSdF REFUSE
admit_case 'long random base62 pair' Ab3xY9zQ1mK7pL2nR8tV Nq4wE8rT2yU6iO9pA1sD5fG3hJ7kL0zXcVb ADMIT
admit_case 'single-char repetition (period 1)' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa someSecretValueLongEnough123 REFUSE
admit_case 'two-char repetition (period 2)' ababababababababababababababab someSecretValueLongEnough123 REFUSE
admit_case 'repeated placeholder' changemechangemechangemechangeme aXb7changemeQ2wErTyUiOp9aSdF REFUSE
admit_case 'repeated vendor default' minioadminminioadmin aXb7changemeQ2wErTyUiOp9aSdF REFUSE
admit_case 'repeated arbitrary token' abcdefabcdefabcdef aXb7changemeQ2wErTyUiOp9aSdF REFUSE
# The installer's own generators produce `openssl rand -hex 16` (32 chars) and
# `openssl rand -hex 24` (48 chars); mirror those lengths with real hex material
# so the case cannot pass or fail merely on repetition.
admit_case 'installer-generated pair' "$(openssl rand -hex 16)" "$(openssl rand -hex 24)" ADMIT
admit_case 'strong secret containing marker' svc-account-01 aXb7changemeQ2wErTyUiOp9aSdF ADMIT
admit_case 'secret below length floor' validlengthuser tooshortsecret REFUSE
admit_case 'user below length floor' shortusr adequatelylongsecretvalue123 REFUSE
admit_case 'just over both floors' userboundary12 boundarysecretvalue12345 ADMIT
admit_case 'empty access identity' '' adequatelylongsecretvalue123 REFUSE
admit_case 'empty secret identity' validlengthuser '' REFUSE
# The vendor-default marker may appear ONLY in the rejection pattern/comment —
# never as a rendered credential value.
if grep -Eq 'accessKey.*minioadmin|minioadmin.*[Ss]ecretKey": "minioadmin' "$INSTALL"; then
  echo "install provision render: a vendor-default credential literal is rendered as a credential value" >&2
  exit 1
fi

# 3. Pgpool-II failover leg: reviewed script installation + verified-input
#    trust anchor, fail closed.
# shellcheck disable=SC2016  # literal $-pattern grep
require 'failover leg is opt-in' 'HA_FAILOVER_ENABLED="$(get_env HA_FAILOVER_ENABLED)"'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'failover script installed from reviewed template' 'install -o root -g root -m 0700 "$FAILOVER_TEMPLATE" "$PGPOOL_DIR/failover.sh"'
require 'template refused if not bash-clean' 'is not bash-clean — refusing to install it.'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'known_hosts installed from verified input' 'install -o root -g root -m 0644 "$PGPOOL_KNOWN_HOSTS_INPUT" "$PGPOOL_DIR/known_hosts"'
require 'unverified scan input refused (noninteractive)' 'NONINTERACTIVE runs cannot verify scanned host keys'
require 'unconfirmed fingerprints refused' 'host keys not verified — refusing to write'
require 'absent anchor fails closed with notice' 'known_hosts NOT written'
require 'candidate validation gate enforced' 'failed strict validation — refusing to write'

# 4. FUNCTIONAL check of validate_known_hosts_file: extract the function from
#    install.sh and drive it against real key material and every rejected
#    shape. This is what keeps "refuse to write known_hosts from unverified
#    input" a behavior rather than a comment.
sed -n '/^validate_known_hosts_file() {/,/^}$/p' "$INSTALL" >"$tmp/vkh.sh"
grep -q '^validate_known_hosts_file() {' "$tmp/vkh.sh" ||
  {
    echo "install provision render: could not extract validate_known_hosts_file" >&2
    exit 1
  }
cat >"$tmp/harness.sh" <<'HB'
set -euo pipefail
HB
cat "$tmp/vkh.sh" >>"$tmp/harness.sh"
cat >>"$tmp/harness.sh" <<'HB'
"$1" "$2"
HB
bash "$tmp/harness.sh" true /dev/null >/dev/null 2>&1 ||
  {
    echo "install provision render: extracted validator does not execute" >&2
    exit 1
  }

# Real key material (freshly generated in the sandbox).
ssh-keygen -q -t ed25519 -N '' -f "$tmp/peer_ed" 2>/dev/null
ssh-keygen -q -t rsa -b 2048 -N '' -f "$tmp/peer_rsa" 2>/dev/null
PUB_ED="$(awk '{print $1, $2}' "$tmp/peer_ed.pub")"
PUB_RSA="$(awk '{print $1, $2}' "$tmp/peer_rsa.pub")"

accept() { # the candidate must PASS strict validation
  local name="$1" file="$2"
  if ! bash "$tmp/harness.sh" validate_known_hosts_file "$file" >/dev/null 2>&1; then
    echo "install provision render: validator rejected an acceptable known_hosts candidate ($name)" >&2
    exit 1
  fi
}
reject() { # the candidate must FAIL strict validation
  local name="$1" file="$2"
  if bash "$tmp/harness.sh" validate_known_hosts_file "$file" >/dev/null 2>&1; then
    echo "install provision render: validator accepted an UNVERIFIED-input shape ($name)" >&2
    exit 1
  fi
}

printf 'node1.example.com %s\nnode2.example.com %s\nnode1.example.com,10.0.0.11 %s\n' \
  "$PUB_ED" "$PUB_RSA" "$PUB_ED" >"$tmp/valid"
accept 'multi-host real keys + comma host list' "$tmp/valid"

printf '# a comment line\nnode1.example.com %s\n' "$PUB_ED" >"$tmp/comments"
accept 'comment lines tolerated' "$tmp/comments"

printf 'node1.example.com %s\n' "$PUB_ED" | awk '{ $1 = "*"; print }' >"$tmp/wildcard"
reject 'wildcard host pattern' "$tmp/wildcard"

printf 'node1.example.com %s\n' "$PUB_ED" | awk '{ $1 = "!node1.example.com"; print }' >"$tmp/negated"
reject 'negated host pattern' "$tmp/negated"

printf '@cert-authority *.example.com %s\n' "$PUB_ED" >"$tmp/marker"
reject '@cert-authority marker line' "$tmp/marker"

printf 'node1.example.com ssh-dss %s\n' "$(cut -d' ' -f2 "$tmp/peer_ed.pub")" >"$tmp/dss"
reject 'unsupported key type' "$tmp/dss"

printf 'node1.example.com ssh-ed25519 not@base64!!\n' >"$tmp/badblob"
reject 'malformed key blob' "$tmp/badblob"

printf 'node1.example.com\n' >"$tmp/shortline"
reject 'missing key fields' "$tmp/shortline"

: >"$tmp/empty"
reject 'empty candidate' "$tmp/empty"

# Valid-shape base64 that decodes to a non-key: only the whole-file
# ssh-keygen parse catches this (the line-shape checks above all pass).
printf 'node1.example.com ssh-ed25519 AAAA\n' >"$tmp/fakekey"
reject 'decodable-but-not-a-key blob fails ssh-keygen parse' "$tmp/fakekey"

# ── 5. shellcheck (loud explicit skip when absent — matches script lanes) ────
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$INSTALL" "$UPGRADE" "$ROOT/mailserver/deploy/scripts/lib-livekit.sh" ||
    {
      echo "install provision render: shellcheck reported findings" >&2
      exit 1
    }
  echo "install provision render: shellcheck -S warning clean (install.sh, upgrade.sh, lib-livekit.sh)"
else
  echo "install provision render: SKIP shellcheck — shellcheck not available on PATH (explicit skip, not a pass)" >&2
fi

# ── 6. Privileged-DB-credential split (DEPLOY-004) — posture pins ────────────
# require_in/forbid_in target an arbitrary file so the same arms that check
# install.sh can be re-run against planted-regression mutants in section 9
# (non-vacuity: every pin below is proven able to FIRE).
require_in() {
  local file="$1" desc="$2" pattern="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "install provision render: missing required pattern ($desc): $pattern" >&2
    exit 1
  fi
}
forbid_in() {
  local file="$1" desc="$2" pattern="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "install provision render: forbidden pattern present ($desc): $pattern" >&2
    grep -n -- "$pattern" "$file" >&2 || true
    exit 1
  fi
}

config_env_heredoc() { # the runtime-account-readable config.env render body
  sed -n '/^cat > "\$CONFIG_ENV" <<ENV$/,/^ENV$/p' "$1"
}
cred_file_heredoc() { # the root-owned privileged-credential render body
  sed -n '/cat > "\$DB_CRED_FILE" <<ENV/,/^ENV$/p' "$1"
}
summary_heredoc() { # the end-of-install summary (paths/modes only, no values)
  sed -n '/^cat <<DONE$/,/^DONE$/p' "$1"
}

# arm_dsn_split_posture <install-sh> — WP-1 placement/ownership pins (r2-1/r3-1).
arm_dsn_split_posture() {
  local target="$1"
  require_in "$target" 'credential directory constant' 'DB_CRED_DIR="$CONFIG_DIR/db-credentials.d"'
  require_in "$target" 'credential file constant' 'DB_CRED_FILE="$DB_CRED_DIR/db-credentials.env"'
  require_in "$target" 'credential render under private umask' '( umask 077'
  require_in "$target" 'credential file heredoc target' 'cat > "$DB_CRED_FILE" <<ENV'
  require_in "$target" 'credential file mode pinned 0600' 'chmod 600 "$DB_CRED_FILE"'
  require_in "$target" 'credential directory mode pinned 0750' 'chmod 0750 "$DB_CRED_DIR"'
  require_in "$target" 'config dir owned root (r3 ancestor — the old setjoin chown is REPLACED)' 'chown root:root "$CONFIG_DIR"'
  require_in "$target" 'config dir mode pinned 0755' 'chmod 0755 "$CONFIG_DIR"'
  require_in "$target" 'credential chain chowned root' 'chown root:root "$DB_CRED_DIR" "$DB_CRED_FILE"'
  require_in "$target" 'credential dir group setjoin' 'chgrp setjoin "$DB_CRED_DIR"'
  require_in "$target" 'entry migration through the real ordering (production root literals)' 'prepare_credential_migration "$CONFIG_DIR" "$DB_CRED_DIR" "$DB_CRED_FILE" "$CONFIG_ENV" render_runtime_units root root setjoin'
  require_in "$target" 'final live-tree namespace assertion' 'verify_db_credentials_namespace "$CONFIG_DIR" "$DB_CRED_DIR" "$DB_CRED_FILE" root root setjoin'
  require_in "$target" 'one-way migration invoked with the rerender hook' 'migrate_privileged_dsn_split "$config_env" "$cred_dir" "$cred_file" "$rerender"'
  require_in "$target" 'entry privileged-dir conversion pins the root-controlled ancestor' 'chown "$root_owner:$root_group" "$ancestor"'
  require_in "$target" 'entry privileged-dir conversion pins 0755' 'chmod 0755 "$ancestor"'
  forbid_in "$target" 'r2-1 withdrawn 0640 form rejected' 'chmod 0640 "$DB_CRED_FILE"'
  forbid_in "$target" 'config dir must never be chowned to the runtime account (whole-directory replacement vector)' 'chown setjoin:setjoin "$CONFIG_DIR"'
  forbid_in "$target" 'credential file must never join the runtime-account chown cohort' 'chown setjoin:setjoin "$CONFIG_DIR" "$CONFIG_ENV"'
  forbid_in "$target" 'privileged keys never rotated via gen_or_keep (rotation stays prompt-gated)' 'gen_or_keep DB_WORKER_DSN'
  forbid_in "$target" 'privileged keys never rotated via gen_or_keep' 'gen_or_keep DB_OWNER_DSN'
  forbid_in "$target" 'privileged keys never rotated via gen_or_keep' 'gen_or_keep DB_DIRECT_OWNER_DSN'
  # The runtime-account-readable config.env heredoc must not carry the keys…
  if config_env_heredoc "$target" | grep -Eq '^DB_WORKER_DSN=|^DB_OWNER_DSN=|^DB_DIRECT_OWNER_DSN='; then
    echo "install provision render: a privileged DSN key is rendered into the runtime-account-readable config.env heredoc — it must live only in \$DB_CRED_FILE" >&2
    exit 1
  fi
  # …and the credential heredoc must carry all three (non-vacuous split).
  local key missing=0
  for key in DB_WORKER_DSN DB_OWNER_DSN DB_DIRECT_OWNER_DSN; do
    cred_file_heredoc "$target" | grep -Eq "^$key=" || missing=1
  done
  if [ "$missing" = "1" ]; then
    echo "install provision render: the privileged credential heredoc does not carry all three of DB_WORKER_DSN/DB_OWNER_DSN/DB_DIRECT_OWNER_DSN" >&2
    exit 1
  fi
  # Consumer sync: templates + upgrade.sh + get_env re-run reads address the
  # new path (r3-2: ALL consumers follow the relocation).
  require_in "$ROOT/mailserver/deploy/mailserver.service.template" 'gateway unit gains the credential EnvironmentFile' 'EnvironmentFile={{DB_CREDENTIALS_FILE}}'
  require_in "$ROOT/mailserver/deploy/setjoin-authserverd.service.template" 'Go authserverd keeps the credential EnvironmentFile (worker tier, r2-2)' 'EnvironmentFile={{DB_CREDENTIALS_FILE}}'
  if grep -q 'DB_CREDENTIALS_FILE' "$ROOT/mailserver/deploy/authserver.service.template"; then
    echo "install provision render: the Rust auth unit must not load the privileged credential file (#359b F6)" >&2
    exit 1
  fi
  require_in "$UPGRADE" 'upgrade.sh consumes the relocated credential file' 'DB_CRED_FILE="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/db-credentials.d/db-credentials.env"'
  require_in "$UPGRADE" 'upgrade.sh selection consults the credential file' 'resolve_schema_dsn "$CONFIG_ENV" "$DB_CRED_FILE"'
  require_in "$UPGRADE" 'selection posture defaults pinned to production root literals' 'want_owner="${3:-root}"'
  require_in "$UPGRADE" 'selection runtime group default pinned to setjoin' 'runtime_group="${5:-setjoin}"'
  require_in "$target" 're-run owner-DSN recovery reads the credential file' 'get_cred_env DB_OWNER_DSN'
  require_in "$target" 're-run worker-DSN recovery reads the credential file' 'get_cred_env DB_WORKER_DSN'
  local tpl cfg cred auth
  for tpl in "$ROOT/mailserver/deploy/mailserver.service.template" "$ROOT/mailserver/deploy/setjoin-authserverd.service.template"; do
    cfg="$(grep -n '^EnvironmentFile={{CONFIG_ENV}}$' "$tpl" | cut -d: -f1)"
    cred="$(grep -n '^EnvironmentFile={{DB_CREDENTIALS_FILE}}$' "$tpl" | cut -d: -f1)"
    if [ -z "$cfg" ] || [ -z "$cred" ] || [ "$cfg" -ge "$cred" ]; then
      echo "install provision render: $tpl — the credential EnvironmentFile must follow config.env's (EnvironmentFile order is precedence order)" >&2
      exit 1
    fi
  done
  auth="$(grep -n '^EnvironmentFile={{AUTHSERVERD_ENV}}$' "$ROOT/mailserver/deploy/setjoin-authserverd.service.template" | cut -d: -f1)"
  cred="$(grep -n '^EnvironmentFile={{DB_CREDENTIALS_FILE}}$' "$ROOT/mailserver/deploy/setjoin-authserverd.service.template" | cut -d: -f1)"
  if [ -z "$auth" ] || [ -z "$cred" ] || [ "$cred" -ge "$auth" ]; then
    echo "install provision render: setjoin-authserverd.service.template — the credential EnvironmentFile must precede authserverd.env's (its override stays last)" >&2
    exit 1
  fi
  # The REAL legacy ordering (Astra L2-C8 HOLD): every renderer input the
  # migration's unit re-render needs — AUTH_ENV (render_authserver_unit
  # refuses it unassigned) and the egress unit's CONTAINER_BIN — must be
  # assigned BEFORE the entry migration call.
  line_of() { grep -nF -- "$1" "$target" | head -1 | cut -d: -f1; }
  local auth_env_line container_line prepare_line
  auth_env_line="$(line_of 'AUTH_ENV="$CONFIG_DIR/auth.env"')"
  container_line="$(line_of 'CONTAINER_BIN="$(detect_container_runtime)"')"
  prepare_line="$(line_of 'prepare_credential_migration "$CONFIG_DIR"')"
  if [ -z "$auth_env_line" ] || [ -z "$container_line" ] || [ -z "$prepare_line" ] ||
    [ "$auth_env_line" -ge "$prepare_line" ] || [ "$container_line" -ge "$prepare_line" ]; then
    echo "install provision render: the entry migration must run AFTER its renderer inputs are assigned (AUTH_ENV, CONTAINER_BIN) — the real unit renderer refuses a migration-time re-render without them" >&2
    exit 1
  fi
  # Permissive posture (Astra L2-C8 HOLD): the credential file is
  # UNCONDITIONAL — a fresh --permissive-dsn install must also produce it
  # (the units' second EnvironmentFile= and the ownership block are
  # unconditional); the postures differ only in CONTENT. The permissive
  # heredoc carries the two owner tiers and never a worker key (no
  # constrained worker role exists in that posture).
  local permissive_heredoc
  permissive_heredoc="$(sed -n '/permissive-dsn posture: no constrained roles/,/^ENV$/p' "$target")"
  if [ -z "$permissive_heredoc" ]; then
    echo "install provision render: the permissive-posture credential render is missing — a fresh --permissive-dsn install would chown a nonexistent credential file and boot units referencing a missing EnvironmentFile" >&2
    exit 1
  fi
  for key in DB_OWNER_DSN DB_DIRECT_OWNER_DSN; do
    printf '%s\n' "$permissive_heredoc" | grep -Eq "^$key=" ||
      {
        echo "install provision render: the permissive credential heredoc does not carry $key" >&2
        exit 1
      }
  done
  if printf '%s\n' "$permissive_heredoc" | grep -Eq '^DB_WORKER_DSN='; then
    echo "install provision render: the permissive credential file must not carry DB_WORKER_DSN (no constrained worker role exists in that posture)" >&2
    exit 1
  fi
  require_in "$target" 'permissive updater worker credential carries the posture DSN' "printf '%s\\n' \"\$DB_DSN\" > \"\$UPDATER_APP_WORKER_DSN_FILE\""
}

# arm_wp2_write_posture <install-sh> — WP-2 write-hygiene pins.
arm_wp2_write_posture() {
  local target="$1" write
  # Every inventory-row secret write into the updater tree must sit inside a
  # creation-time ( umask 077 … ) subshell — the 0644 creation race is closed,
  # not laundered by the later chmod batch.
  for write in \
    '"$DB_DIRECT_OWNER_DSN" > "$UPDATER_OWNER_DSN_FILE"' \
    'openssl rand -hex 32 > "$UPDATER_RECOVERY_HMAC_FILE"' \
    '> "$UPDATER_DSN_FILE"' \
    '> "$UPDATER_APP_WORKER_DSN_FILE"'; do
    if ! grep -B2 -F -- "$write" "$target" | grep -Fq '( umask 077'; then
      echo "install provision render: secret write outside the creation-time umask-077 pattern: $write" >&2
      exit 1
    fi
  done
  # ALTER ROLE passwords are stdin-fed only: no argv form anywhere (the
  # /proc/<pid>/cmdline leak class), and the stdin heredoc form exists for
  # all three roles with ON_ERROR_STOP preserved.
  forbid_in "$target" 'ALTER ROLE must never travel in psql -c argv' '-c "ALTER ROLE'
  forbid_in "$target" 'ALTER ROLE must never travel in psql --set argv' '--set" "ALTER ROLE'
  require_in "$target" 'stdin-fed role SQL present' 'psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null <<SQL'
  for role in setjoin_app setjoin_worker setjoin_updater; do
    require_in "$target" "$role password set via stdin SQL" "ALTER ROLE $role WITH LOGIN PASSWORD"
  done
}

# arm_redaction <install-sh> <upgrade-sh> — no secret value may reach
# stdout/stderr/argv from either script (regression-pin: already true at
# HEAD; this keeps it true).
arm_redaction() {
  local target="$1" upgrade_target="$2"
  local forbid_re='\$(\{)?(JWT_SECRET|DB_ENCRYPTION_KEY|AUDIT_HMAC_KEY|INTERNAL_API_KEY|S3_SECRET_KEY|LIVEKIT_API_SECRET|VALKEY_PASSWORD|ASR_TOKEN|APP_PW|WORKER_PW|UPDATER_PW|DB_WORKER_DSN|DB_OWNER_DSN|DB_DIRECT_OWNER_DSN|RUNTIME_WORKER_DSN|RUNTIME_DB_DSN|RUNTIME_DIRECT_DSN|DEF_DBDSN|DEF_DIRECT)(\})?\b'
  local script out
  for script in "$target" "$upgrade_target"; do
    {
      sed -n -E '/^[[:space:]]*(info|say|die|echo)[[:space:]]/p' "$script"
      summary_heredoc "$script"
    } >"$tmp/redact-surface.txt"
    out="$(grep -E "$forbid_re" "$tmp/redact-surface.txt" || true)"
    if [ -n "$out" ]; then
      echo "install provision render: a secret variable is expanded into a stdout/stderr-writing context:" >&2
      printf '%s\n' "$out" >&2
      exit 1
    fi
  done
  # The summary block names paths/modes only — pin its shape.
  require_in "$target" 'summary names the credential file path' 'DB_CRED_FILE (mode 0600 root:root'
  # Astra L2-C8 redaction fix: a RECOVERED owner DSN must never be echoed
  # through ask's default-value prompt on an interactive re-run — the two
  # owner-DSN asks pass the recovered-secret marker so the prompt shows only
  # "(configured — Enter to keep)".
  require_in "$target" 'owner DSN prompt default redacted' 'ask DB_DSN        "Owner/admin DB DSN (schema owner; loads + migrates the schema)" "$DEF_DBDSN" "$DEF_DBDSN_RECOVERED"'
  require_in "$target" 'direct owner DSN prompt default redacted' 'ask DB_DIRECT_DSN "Direct owner DB DSN (non-pooled; LISTEN/NOTIFY host)" "$DEF_DIRECT" "$DEF_DIRECT_RECOVERED"'
}

arm_dsn_split_posture "$INSTALL"
arm_wp2_write_posture "$INSTALL"
arm_redaction "$INSTALL" "$UPGRADE"

# ── 7. FUNCTIONAL: namespace guard + one-way migration + upgrade selection ───
# The r2-3/r3-3 contract: the migration and the namespace guard are EXECUTED,
# not inspected (no live PostgreSQL — the migration is pure file surgery).
# The extracted functions run with the LANE'S OWN identity as the expected
# owner/group so the whole guard/migration logic executes unprivileged; the
# production literals (root/root/setjoin) are pinned at the call sites by
# arm_dsn_split_posture above.
fn_harness="$tmp/l2c8-functions.sh"
FX="$tmp/fx"
MG="$FX/mig"
# Sandboxed unit catalog: the REAL compiled catalog with its destinations
# pointed into the sandbox, so the REAL render_runtime_units (real renderers,
# real templates) can execute unprivileged in the lane — no success stub.
sed "s#/etc/systemd/system#$FX/units#g" "$ROOT/mailserver/deploy/generated/unit-catalog.sh" \
  >"$tmp/catalog-sandbox.sh"
grep -q 'SETJOIN_ALL_UNITS' "$tmp/catalog-sandbox.sh" ||
  {
    echo "install provision render: sandboxed unit catalog is empty" >&2
    exit 1
  }
{
  echo 'set -euo pipefail'
  echo 'OWNER="$(id -un)"'
  echo 'GROUP="$(id -gn)"'
  echo "ROOT='$ROOT'"
  cat <<'HELPERS'
# install.sh's die/info are not extracted; the lane provides the same shapes
# (lib-livekit.sh's own fallbacks yield to these via their command -v guard).
die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
info() { printf '    %s\n' "$1"; }
port_stat() { # FILE -> "owner group mode" (GNU first, BSD fallback)
  stat -c '%U %G %a' "$1" 2>/dev/null || stat -f '%Su %Sg %Lp' "$1" 2>/dev/null
}
fn_assert() { # fn_assert <desc> <cmd…> — the command must succeed
  local desc="$1"; shift
  if ! "$@"; then echo "assert failed: $desc" >&2; exit 1; fi
}
fn_assert_not() { # fn_assert_not <desc> <cmd…> — the command must fail
  local desc="$1"; shift
  if "$@"; then echo "assert failed (unexpectedly true): $desc" >&2; exit 1; fi
}
build_ok_chain() { # a well-postured fixture chain for the current identity
  mkdir -p "$1/anc/db-credentials.d"
  : > "$1/anc/db-credentials.d/db-credentials.env"
  # chgrp to the login group explicitly: default group inheritance differs
  # between /tmp (wheel) and /var/folders (staff) on macOS.
  chgrp "$GROUP" "$1/anc" "$1/anc/db-credentials.d" "$1/anc/db-credentials.d/db-credentials.env"
  chmod 755 "$1/anc"
  chmod 750 "$1/anc/db-credentials.d"
  chmod 600 "$1/anc/db-credentials.d/db-credentials.env"
}
HELPERS
  echo 'source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"'
  echo "source '$tmp/catalog-sandbox.sh'"
  for fn in verify_db_credentials_namespace restore_db_credentials_namespace \
    ensure_db_credentials_namespace migrate_privileged_dsn_split \
    prepare_credential_migration render_runtime_units; do
    sed -n "/^$fn() {/,/^}$/p" "$INSTALL"
  done
  sed -n '/^resolve_schema_dsn() {/,/^}$/p' "$UPGRADE"
} >"$fn_harness"
for fn in verify_db_credentials_namespace restore_db_credentials_namespace \
  ensure_db_credentials_namespace migrate_privileged_dsn_split \
  prepare_credential_migration render_runtime_units; do
  grep -q "^$fn() {" "$fn_harness" ||
    {
      echo "install provision render: could not extract $fn" >&2
      exit 1
    }
done
grep -q '^resolve_schema_dsn() {' "$fn_harness" ||
  {
    echo "install provision render: could not extract resolve_schema_dsn" >&2
    exit 1
  }
# Each extracted function must be complete (balanced): the harness must parse.
bash -n "$fn_harness" || {
  echo "install provision render: extracted function harness is not bash-clean" >&2
  exit 1
}

fn_case() { # fn_case <name> <body-file> — run a scenario with the harness
  local name="$1" body="$2"
  {
    echo "source '$fn_harness'"
    cat "$body"
  } >"$tmp/fn-case.sh"
  if ! FX="$FX" MG="$MG" bash "$tmp/fn-case.sh" >"$tmp/fn-out.txt" 2>"$tmp/fn-err.txt"; then
    echo "install provision render: functional case FAILED: $name" >&2
    sed 's/^/    /' "$tmp/fn-err.txt" >&2
    exit 1
  fi
}

# Case A — the namespace guard (r3-3): full-chain validation, rename-and-plant,
# restore, refusal without a restorable .old, writable ancestor, widened file,
# symlink plant.
: >"$tmp/case.sh"
cat >>"$tmp/case.sh" <<CASE
guard_accepts_well_postured_chain() {
  build_ok_chain "\$FX/g-ok"
  verify_db_credentials_namespace "\$FX/g-ok/anc" "\$FX/g-ok/anc/db-credentials.d" "\$FX/g-ok/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP"
}
guard_rejects_rename_and_plant() {
  # r3-3 rename-and-plant: the real directory renamed aside, a substitute
  # planted at the live pathname carrying foreign credentials.
  build_ok_chain "\$FX/g-plant"
  mv "\$FX/g-plant/anc/db-credentials.d" "\$FX/g-plant/anc/db-credentials.d.old"
  mkdir -p "\$FX/g-plant/anc/db-credentials.d"
  chmod 755 "\$FX/g-plant/anc/db-credentials.d"
  printf 'DB_OWNER_DSN=postgres://attacker@evil\n' > "\$FX/g-plant/anc/db-credentials.d/db-credentials.env"
  chmod 644 "\$FX/g-plant/anc/db-credentials.d/db-credentials.env"
  local out
  out="\$(verify_db_credentials_namespace "\$FX/g-plant/anc" "\$FX/g-plant/anc/db-credentials.d" "\$FX/g-plant/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" 2>&1)" && return 1
  case "\$out" in *whole-directory*) return 0 ;; *) printf '%s\n' "\$out" >&2; return 1 ;; esac
}
restore_recovers_real_directory() {
  # .old carries the real store; the live pathname carries the plant. The
  # ancestor starts EMPTY apart from them (no pre-built live directory — mv
  # into an existing directory would nest the plant inside it).
  mkdir -p "\$FX/g-restore/anc"
  chgrp "\$GROUP" "\$FX/g-restore/anc"
  chmod 755 "\$FX/g-restore/anc"
  mv "\$FX/g-plant/anc/db-credentials.d.old" "\$FX/g-restore/anc/db-credentials.d.old"
  mv "\$FX/g-plant/anc/db-credentials.d" "\$FX/g-restore/anc/db-credentials.d"
  ensure_db_credentials_namespace "\$FX/g-restore/anc" "\$FX/g-restore/anc/db-credentials.d" "\$FX/g-restore/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" || return 1
  verify_db_credentials_namespace "\$FX/g-restore/anc" "\$FX/g-restore/anc/db-credentials.d" "\$FX/g-restore/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" || return 1
  fn_assert "restored credential file present" test -f "\$FX/g-restore/anc/db-credentials.d/db-credentials.env"
  fn_assert "planted substitute quarantined, not deleted" \
    test "\$(ls "\$FX/g-restore/anc" | grep -c '^db-credentials.d.planted\.')" -ge 1
}
restore_refuses_without_old() {
  build_ok_chain "\$FX/g-noold"
  mv "\$FX/g-noold/anc/db-credentials.d" "\$FX/g-noold/anc/elsewhere"
  mkdir -p "\$FX/g-noold/anc/db-credentials.d"
  chmod 700 "\$FX/g-noold/anc/db-credentials.d"
  ensure_db_credentials_namespace "\$FX/g-noold/anc" "\$FX/g-noold/anc/db-credentials.d" "\$FX/g-noold/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" && return 1
  return 0
}
guard_rejects_writable_ancestor() {
  # r3-3 ancestor arm: a privileged-credential directory beneath a
  # runtime-account-WRITABLE ancestor is rejected at the DIRECTORY level —
  # perfect file posture cannot save it.
  build_ok_chain "\$FX/g-wanc"
  chmod 775 "\$FX/g-wanc/anc"
  local out
  out="\$(verify_db_credentials_namespace "\$FX/g-wanc/anc" "\$FX/g-wanc/anc/db-credentials.d" "\$FX/g-wanc/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" 2>&1)" && return 1
  case "\$out" in *whole-directory*) return 0 ;; *) printf '%s\n' "\$out" >&2; return 1 ;; esac
}
guard_rejects_widened_file() {
  build_ok_chain "\$FX/g-wide"
  chmod 644 "\$FX/g-wide/anc/db-credentials.d/db-credentials.env"
  verify_db_credentials_namespace "\$FX/g-wide/anc" "\$FX/g-wide/anc/db-credentials.d" "\$FX/g-wide/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" && return 1
  return 0
}
guard_rejects_symlink_file() {
  build_ok_chain "\$FX/g-slink"
  mv "\$FX/g-slink/anc/db-credentials.d/db-credentials.env" "\$FX/g-slink/anc/real.env"
  ln -s "\$FX/g-slink/anc/real.env" "\$FX/g-slink/anc/db-credentials.d/db-credentials.env"
  verify_db_credentials_namespace "\$FX/g-slink/anc" "\$FX/g-slink/anc/db-credentials.d" "\$FX/g-slink/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" && return 1
  return 0
}
guard_accepts_well_postured_chain
guard_rejects_rename_and_plant
restore_recovers_real_directory
restore_refuses_without_old
guard_rejects_writable_ancestor
guard_rejects_widened_file
guard_rejects_symlink_file
CASE
fn_case "namespace guard: accept / rename-and-plant / restore / no-.old / writable-ancestor / widened-file / symlink" "$tmp/case.sh"

echo "install provision render: namespace guard functional arms PASS"

# Case B — the REAL legacy-migration ordering (r2-3 + Astra impl-HOLD): the
# migration runs through prepare_credential_migration — entry validation,
# privileged-dir conversion FIRST, then the exactly-once split — and its unit
# re-render is the REAL render_runtime_units over the REAL templates (only
# the catalog destinations are sandboxed): no success stub. The renderer
# inputs the installer assigns before the entry migration call are assigned
# here FIRST; the no-AUTH_ENV arm proves the real renderer refuses the state
# the old ordering produced.
: >"$tmp/case.sh"
cat >>"$tmp/case.sh" <<CASE
# Renderer inputs — assigned BEFORE any migrate call, exactly as the
# installer's entry block does (AUTH_ENV and CONTAINER_BIN included).
INSTALL_DIR="\$MG/opt"
DATA_DIR="\$MG/var"
CONFIG_ENV="\$MG/config.env"
AUTH_ENV="\$MG/auth.env"
AUTHSERVERD_ENV="\$MG/authserverd.env"
GATEWAY_ENV="\$MG/gateway.env"
DB_CREDENTIALS_FILE="\$MG/cred.d/db-credentials.env"
UPDATER_DATA_DIR="\$MG/updater-data"
UPDATER_DSN_FILE="\$MG/updater-dsn"
UPDATER_EXECUTION_CONFIG="\$MG/execution.json"
UPDATER_OWNER_DSN_FILE="\$MG/owner-dsn"
UPDATER_RECOVERY_ACCESS_FILE="\$MG/recovery-access"
UPDATER_RECOVERY_SECRET_FILE="\$MG/recovery-secret"
UPDATER_RECOVERY_HMAC_FILE="\$MG/recovery-hmac"
UPDATER_PROBE_CREDENTIAL_FILE="\$MG/probe.json"
UPDATER_APP_WORKER_DSN_FILE="\$MG/app-worker-dsn"
OFFICE_APP_MANIFEST="\$MG/office-manifest.json"
OFFICE_APP_STATE_DIR="\$MG/office-state"
CONTAINER_BIN="/bin/echo"
mkdir -p "\$FX/units"

build_old_layout() {
  rm -rf "\$MG"
  mkdir -p "\$MG"
  # A LEGACY pre-split install has NO credential chain yet — the migration
  # creates it inside the converted (root-controlled) ancestor. The old
  # fixture pre-created the directory and used a success rerender stub,
  # masking both entry-ordering bugs this case now executes.
  cat > "\$MG/config.env" <<CFG
# setjoin single-node config — pre-split layout fixture
HOSTNAME=mail.example.com
DB_DSN=postgres://setjoin_app:apppw@10.0.0.5:5432/mailserver?sslmode=disable
DB_DIRECT_DSN=postgres://setjoin_app:apppw@10.0.0.9:5432/mailserver
DB_WORKER_DSN=postgres://setjoin_worker:workerpw@10.0.0.5:5432/mailserver?sslmode=disable
DB_OWNER_DSN=postgres://mail:ownerpw@10.0.0.5:5432/mailserver?sslmode=disable
DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@10.0.0.9:5432/mailserver
JWT_SECRET=jwtvalue
KEEP_ME=untouched
CFG
}
build_old_layout
cp "\$MG/config.env" "\$MG/config.env.original"
prepare_credential_migration "\$MG" "\$MG/cred.d" "\$DB_CREDENTIALS_FILE" "\$CONFIG_ENV" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" \\
  || { echo "migration returned non-zero on the old-layout fixture" >&2; exit 1; }
cred="\$MG/cred.d/db-credentials.env"
# The REAL renderer ran: every base unit exists at the sandboxed destination.
for u in setjoin-valkey setjoin-sfu setjoin-egress setjoin-auth setjoin-authserverd setjoin setjoin-updater; do
  fn_assert "real render_runtime_units produced \$u.service" test -f "\$FX/units/\$u.service"
done
# The rendered gateway unit addresses config.env FIRST, the credential file
# second (EnvironmentFile order is precedence order).
gw="\$FX/units/setjoin.service"
cfg_line="\$(grep -n '^EnvironmentFile=' "\$gw" | grep -F "\$CONFIG_ENV" | cut -d: -f1)"
cred_line="\$(grep -n '^EnvironmentFile=' "\$gw" | grep -F "\$DB_CREDENTIALS_FILE" | cut -d: -f1)"
if [ -z "\$cfg_line" ] || [ -z "\$cred_line" ]; then
  echo "rendered gateway unit does not reference both env files" >&2; exit 1
fi
fn_assert "rendered gateway unit keeps config.env before the credential file" test "\$cfg_line" -lt "\$cred_line"
au="\$FX/units/setjoin-authserverd.service"
cred_line="\$(grep -n '^EnvironmentFile=' "\$au" | grep -F "\$DB_CREDENTIALS_FILE" | cut -d: -f1)"
auth_line="\$(grep -n '^EnvironmentFile=' "\$au" | grep -F "\$AUTHSERVERD_ENV" | cut -d: -f1)"
if [ -z "\$cred_line" ] || [ -z "\$auth_line" ]; then
  echo "rendered authserverd unit does not reference both env files" >&2; exit 1
fi
fn_assert "rendered authserverd unit keeps the credential file before authserverd.env" test "\$cred_line" -lt "\$auth_line"
fn_assert "rendered Rust auth unit carries no privileged credential file" test -z "\$(grep -F "\$DB_CREDENTIALS_FILE" "\$FX/units/setjoin-auth.service" || true)"
# The privileged-dir conversion ran FIRST: the ancestor is at the
# root-controlled posture, and only then was the credential file born in it.
fn_assert "entry conversion pinned the ancestor 0755" test "\$(port_stat "\$MG" | awk '{print \$3}')" = "755"
fn_assert "entry conversion pinned the ancestor to the root identity" test "\$(port_stat "\$MG" | awk '{print \$1}')" = "\$OWNER"
fn_assert "exactly one timestamped backup inside the root-controlled dir" \\
  test "\$(find "\$MG/cred.d" -maxdepth 1 -name 'config.env.pre-dsn-split.*' | wc -l | tr -d ' ')" = "1"
backup="\$(find "\$MG/cred.d" -maxdepth 1 -name 'config.env.pre-dsn-split.*')"
fn_assert "backup is a byte-identical copy of the pre-split config.env" cmp -s "\$MG/config.env.original" "\$backup"
fn_assert "backup mode 0600" test "\$(port_stat "\$backup" | awk '{print \$3}')" = "600"
fn_assert "credential file mode 0600" test "\$(port_stat "\$cred" | awk '{print \$3}')" = "600"
for kv in \\
  'DB_WORKER_DSN=postgres://setjoin_worker:workerpw@10.0.0.5:5432/mailserver?sslmode=disable' \\
  'DB_OWNER_DSN=postgres://mail:ownerpw@10.0.0.5:5432/mailserver?sslmode=disable' \\
  'DB_DIRECT_OWNER_DSN=postgres://mail:ownerpw@10.0.0.9:5432/mailserver'; do
  fn_assert "credential file carries the migrated value byte-identical: \${kv%%=*}" grep -Fqx -- "\$kv" "\$cred"
done
fn_assert_not "config.env no longer carries DB_WORKER_DSN" grep -q '^DB_WORKER_DSN=' "\$MG/config.env"
fn_assert_not "config.env no longer carries DB_OWNER_DSN" grep -q '^DB_OWNER_DSN=' "\$MG/config.env"
fn_assert_not "config.env no longer carries DB_DIRECT_OWNER_DSN" grep -q '^DB_DIRECT_OWNER_DSN=' "\$MG/config.env"
fn_assert "config.env keeps the app-role DSN" grep -Fq 'DB_DSN=postgres://setjoin_app:apppw@10.0.0.5' "\$MG/config.env"
fn_assert "config.env keeps unrelated lines byte-intact" grep -Fqx 'KEEP_ME=untouched' "\$MG/config.env"
fn_assert "config.env keeps its comment lines" grep -Fq 'pre-split layout fixture' "\$MG/config.env"
fn_assert "app-tier secret stays in config.env" grep -Fqx 'JWT_SECRET=jwtvalue' "\$MG/config.env"

# Second run through the FULL entry ordering — exactly-once: the chain now
# exists and strict validation must accept it. (Production pins the final
# ownership root:root / root:setjoin at the posture block; the lane fixture
# pins its own identity equivalently before the strict re-check.)
chgrp "\$GROUP" "\$MG" "\$MG/cred.d" "\$cred" "\$backup" 2>/dev/null
before_md5="\$(md5 -q "\$cred" 2>/dev/null || md5sum "\$cred" | awk '{print \$1}')"
prepare_credential_migration "\$MG" "\$MG/cred.d" "\$cred" "\$CONFIG_ENV" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" \\
  || { echo "second migration run returned non-zero" >&2; exit 1; }
fn_assert "still exactly one backup after the second run" \\
  test "\$(find "\$MG/cred.d" -maxdepth 1 -name 'config.env.pre-dsn-split.*' | wc -l | tr -d ' ')" = "1"
after_md5="\$(md5 -q "\$cred" 2>/dev/null || md5sum "\$cred" | awk '{print \$1}')"
fn_assert "credential values byte-identical after the second run" test "\$before_md5" = "\$after_md5"

# Partial state — credential file exists AND keys still in config.env: dies
# loud with the named repair command (never silently reconciles).
printf 'DB_OWNER_DSN=postgres://mail:different@10.9.9.9/db\n' > "\$cred"
printf 'DB_OWNER_DSN=postgres://mail:ownerpw@10.0.0.5:5432/mailserver\n' >> "\$MG/config.env"
out="\$(prepare_credential_migration "\$MG" "\$MG/cred.d" "\$cred" "\$CONFIG_ENV" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" 2>&1)" && {
  echo "partial-state migration did NOT refuse" >&2
  exit 1
}
case "\$out" in
  *pre-dsn-split*repair*|*repair*pre-dsn-split*) : ;;
  *) printf '%s\n' "\$out" >&2; echo "partial-state refusal does not name the repair" >&2; exit 1 ;;
esac

# The regression the old success stub masked: a migration-time re-render
# WITHOUT AUTH_ENV assigned must fail loud in the REAL renderer — which is
# why the installer assigns AUTH_ENV (and CONTAINER_BIN) before it invokes
# the migration.
renderer_rejects_unassigned_auth_env() {
  local mg2="\$FX/noauth"
  rm -rf "\$mg2"; mkdir -p "\$mg2"
  INSTALL_DIR="\$mg2/opt"
  DATA_DIR="\$mg2/var"
  CONFIG_ENV="\$mg2/config.env"
  AUTH_ENV=""
  DB_CREDENTIALS_FILE="\$mg2/cred.d/db-credentials.env"
  UPDATER_DATA_DIR="\$mg2/ud"; UPDATER_DSN_FILE="\$mg2/dsn"
  UPDATER_EXECUTION_CONFIG="\$mg2/exec"; UPDATER_OWNER_DSN_FILE="\$mg2/odsn"
  UPDATER_RECOVERY_ACCESS_FILE="\$mg2/ra"; UPDATER_RECOVERY_SECRET_FILE="\$mg2/rs"
  UPDATER_RECOVERY_HMAC_FILE="\$mg2/rh"; UPDATER_PROBE_CREDENTIAL_FILE="\$mg2/pc"
  UPDATER_APP_WORKER_DSN_FILE="\$mg2/aw"; OFFICE_APP_MANIFEST="\$mg2/m.json"
  OFFICE_APP_STATE_DIR="\$mg2/os"
  CONTAINER_BIN="/bin/echo"
  printf 'DB_OWNER_DSN=postgres://mail:ownerpw@h/db\n' > "\$CONFIG_ENV"
  local out
  out="\$(prepare_credential_migration "\$mg2" "\$mg2/cred.d" "\$DB_CREDENTIALS_FILE" "\$CONFIG_ENV" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" 2>&1)" && return 1
  case "\$out" in
    *AUTH_ENV*) : ;;
    *) printf '%s\n' "\$out" >&2; return 1 ;;
  esac
}
renderer_rejects_unassigned_auth_env

# Entry validation accepts the setjoin-owned pre-split ancestor (that state
# IS the migration input), converts it FIRST, and fabricates no chain.
entry_accepts_legacy_pre_split_state() {
  local anc="\$FX/legacy-anc"
  rm -rf "\$anc"; mkdir -p "\$anc"
  chgrp "\$GROUP" "\$anc"; chmod 700 "\$anc"
  printf 'DB_DSN=postgres://setjoin_app:app@h/db\n' > "\$anc/config.env"
  CONFIG_ENV="\$anc/config.env"
  DB_CREDENTIALS_FILE="\$anc/db-credentials.d/db-credentials.env"
  prepare_credential_migration "\$anc" "\$anc/db-credentials.d" "\$DB_CREDENTIALS_FILE" "\$CONFIG_ENV" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" || return 1
  fn_assert "entry converted the legacy ancestor to 0755" test "\$(port_stat "\$anc" | awk '{print \$3}')" = "755"
  fn_assert "entry converted the legacy ancestor to the root identity" test "\$(port_stat "\$anc" | awk '{print \$1}')" = "\$OWNER"
  fn_assert "no credential chain was fabricated for a key-less legacy config" test ! -e "\$anc/db-credentials.d"
}
entry_accepts_legacy_pre_split_state

# …but legacy tolerance does NOT extend to a credential chain that already
# exists under a non-root-controlled ancestor: that is the
# whole-directory-replacement shape, and the strict validation must refuse.
entry_refuses_chain_under_unconverted_ancestor() {
  build_ok_chain "\$FX/lc"
  chmod 775 "\$FX/lc/anc"
  local out
  out="\$(prepare_credential_migration "\$FX/lc/anc" "\$FX/lc/anc/db-credentials.d" "\$FX/lc/anc/db-credentials.d/db-credentials.env" "\$FX/lc/anc/config.env" render_runtime_units "\$OWNER" "\$GROUP" "\$GROUP" 2>&1)" && return 1
  case "\$out" in
    *whole-directory*) : ;;
    *) printf '%s\n' "\$out" >&2; return 1 ;;
  esac
}
entry_refuses_chain_under_unconverted_ancestor

# r2-3.5: upgrade credential selection EXECUTED against the split layout —
# the credential file's owner tier wins over the stale config.env copy.
resolve_schema_dsn "\$MG/config.env" "\$cred" "\$OWNER" "\$GROUP" "\$GROUP" > "\$FX/schema-dsn.txt" \\
  || { echo "resolve_schema_dsn refused a valid split layout" >&2; exit 1; }
fn_assert "schema DSN resolves to the owner credential from the new file (cred preferred over config)" \\
  grep -Fx 'postgres://mail:different@10.9.9.9/db' "\$FX/schema-dsn.txt"

# Consumer-refuse arm: a widened credential file and a planted substitute
# directory are refused, never used (whole-directory replacement named).
build_ok_chain "\$FX/split-ok"
printf 'DB_WORKER_DSN=w\nDB_OWNER_DSN=postgres://mail:ownerpw@10.0.0.5:5432/mailserver\n' > "\$FX/split-ok/anc/db-credentials.d/db-credentials.env"
resolve_schema_dsn /nonexistent/config.env "\$FX/split-ok/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" > "\$FX/schema-dsn2.txt" \\
  || { echo "resolve_schema_dsn refused a valid split layout (preference probe)" >&2; exit 1; }
fn_assert "owner tier preferred from the credential file" \\
  grep -Fx 'postgres://mail:ownerpw@10.0.0.5:5432/mailserver' "\$FX/schema-dsn2.txt"
chmod 644 "\$FX/split-ok/anc/db-credentials.d/db-credentials.env"
resolve_schema_dsn /nonexistent/config.env "\$FX/split-ok/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" >/dev/null 2>&1 && {
  echo "resolve_schema_dsn trusted a widened (0644) credential file" >&2
  exit 1
}
chmod 600 "\$FX/split-ok/anc/db-credentials.d/db-credentials.env"
chmod 770 "\$FX/split-ok/anc/db-credentials.d"
out="\$(resolve_schema_dsn /nonexistent/config.env "\$FX/split-ok/anc/db-credentials.d/db-credentials.env" "\$OWNER" "\$GROUP" "\$GROUP" 2>&1 >/dev/null)" && {
  echo "resolve_schema_dsn trusted a substituted credential directory" >&2
  exit 1
}
case "\$out" in *whole-directory*) : ;; *) printf '%s\n' "\$out" >&2; echo "substitute refusal does not name whole-directory replacement" >&2; exit 1 ;; esac

# Pre-split/legacy selection still resolves owner keys from config.env, and
# the permissive/pre-flip fallback (DB_DSN IS the owner) is unchanged.
mkdir -p "\$FX/legacy"
printf 'DB_DSN=postgres://mail:owner@h/db\n' > "\$FX/legacy/config.env"
resolve_schema_dsn "\$FX/legacy/config.env" "\$FX/legacy/absent-cred" "\$OWNER" "\$GROUP" "\$GROUP" > "\$FX/schema-dsn3.txt" \\
  || { echo "resolve_schema_dsn refused a legacy layout" >&2; exit 1; }
fn_assert "legacy fallback resolves DB_DSN (pre-flip owner)" grep -Fx 'postgres://mail:owner@h/db' "\$FX/schema-dsn3.txt"
CASE
fn_case "real-ordering migration: legacy accept + convert-first + real render / second run / partial state / no-AUTH_ENV refuse / upgrade selection / consumer-refuse / legacy fallback" "$tmp/case.sh"

echo "install provision render: migration + selection functional arms PASS"

# ── 8. Non-vacuity (r1 WP-3 / r3-3): planted regressions must FIRE ───────────
# expect_fire DESC ARM MUST-NAME AWK-PROG — apply a planted regression to a
# copy of install.sh and require the named arm to FIRE (non-zero exit) with a
# message containing MUST-NAME. A planted regression the lane does not flag is
# a lane failure.
expect_fire() {
  local desc="$1" arm="$2" must_name="$3" prog="$4" out
  awk "$prog" "$INSTALL" >"$tmp/mutant.sh"
  out="$("$arm" "$tmp/mutant.sh" "$tmp/mutant.sh" 2>&1)" && {
    echo "install provision render: NON-VACUITY FAILURE — arm $arm did NOT fire on the planted regression: $desc" >&2
    exit 1
  }
  case "$out" in
    *"$must_name"*) : ;;
    *)
      echo "install provision render: arm $arm fired on '$desc' but did not name it (wanted: $must_name); got: $out" >&2
      exit 1
      ;;
  esac
  echo "install provision render: mutant fired as required ($desc)"
}

# Plant 1 (WP-2): every creation-time umask removed → the write-posture arm
# fires naming the umask pattern. (sub+print explicit: default printing is
# not portable across awks when rules carry actions.)
expect_fire 'secret writes outside the umask-077 pattern' arm_wp2_write_posture 'umask-077' \
  '{ sub(/\( umask 077/, "            :"); print }'

# Plant 2 (WP-2): an ALTER ROLE password moved back into psql argv → the arm
# fires naming the argv form.
expect_fire 'ALTER ROLE password in psql -c argv' arm_wp2_write_posture 'argv' \
  '{ print } /^ALTER ROLE setjoin_app/ { print "psql -c \"ALTER ROLE x\" >/dev/null" }'

# Plant 3 (WP-1): a privileged key rendered back into the config.env heredoc →
# the posture arm fires naming the heredoc.
expect_fire 'privileged DSN key rendered back into config.env' arm_dsn_split_posture 'config.env heredoc' \
  '{ print } /^DB_MAX_CONNS=10$/ { print "DB_OWNER_DSN=$DB_DSN" }'

# Plant 4 (WP-1/r3): the ancestor chown reverted to the runtime account → the
# posture arm fires naming the whole-directory-replacement vector.
expect_fire 'config dir chown reverted to setjoin:setjoin' arm_dsn_split_posture 'whole-directory' \
  '{ print } /chown root:root "\$CONFIG_DIR"$/ { print "chown setjoin:setjoin \"$CONFIG_DIR\"" }'

# Plant 5 (WP-1): the credential file mode pin removed → the arm fires naming
# the missing pattern.
expect_fire 'credential file mode pin removed' arm_dsn_split_posture 'missing required pattern' \
  '/^[[:space:]]*chmod 600 "\$DB_CRED_FILE"$/ { next } { print }'

# Plant 6 (redaction): a secret value echoed to the operator → the redaction
# arm fires naming the variable.
expect_fire 'secret value expanded into an info line' arm_redaction 'JWT_SECRET' \
  '/^say "Secrets"$/ { print "info \"your jwt secret is $JWT_SECRET\"" }'

# Plant 7 (Astra L2-C8 redaction): the recovered-secret marker dropped from
# the owner-DSN ask → the recovered DSN would echo through ask's
# default-value prompt again.
expect_fire 'recovered-DSN prompt default un-redacted' arm_redaction 'prompt default redacted' \
  '/^ask DB_DSN/ { sub(/ "\$DEF_DBDSN_RECOVERED"$/, ""); print; next } { print }'

# Plant 8 (Astra L2-C8 permissive posture): a worker key planted into the
# permissive credential heredoc → the arm fires — no constrained worker role
# exists in that posture.
expect_fire 'worker key planted into the permissive credential file' arm_dsn_split_posture 'permissive credential file must not carry DB_WORKER_DSN' \
  '{ print } /permissive-dsn posture: no constrained roles/ { print "DB_WORKER_DSN=\$RUNTIME_WORKER_DSN" }'

echo "install provision render: PASS"
