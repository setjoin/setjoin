#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-deploy-doc-currency.sh — packaging/install doc-vs-code currency guard
# (GA-readiness G1, retired-docs:superpowers/plans/archive/2026-07-04-ga-readiness-program-index.md).
#
# WHY. The G0 readiness sweep found upgrade.sh pointing `systemctl stop
# mailserver` at a unit install.sh never creates (it creates `setjoin.service`)
# — every real upgrade would have failed at step 1. The same G1 pass then
# found upgrade.sh/backup.sh hardcoding `/opt/mailserver` + `chown
# mailserver:mailserver` while install.sh actually installs to `/opt/setjoin`
# under a `setjoin` system user, and DNSSEC_DANE_SETUP.md linking a doc path
# (`docs/specs/SECURITY.md`) that was renamed to `docs/ref/SECURITY.md`. Three
# instances of one class of bug: an operator-facing doc or script names an env
# var, config key, script path, or systemd unit that no longer resolves
# against the actual installer/config contract. This guard mechanizes that
# class so it fails at commit time instead of at a customer's 3am upgrade.
#
# WHAT IT SCANS. `docs/guides/*.md` (auto-globbed — a new guide is covered for
# free) + the operator-facing install surface under `mailserver/deploy/`:
# `deploy/scripts/*.sh`, `deploy/mailserver.service`, `deploy/config.env.sample`.
# Deliberately OUT of scope: `deploy/docker/**` (dev/test fixtures),
# `deploy/grafana/*.json` + `deploy/zabbix/*` (monitoring dashboards, not the
# install/upgrade doc flow), `deploy/*.template` (HA templates the operator
# edits by hand — placeholders are the point, not a drift bug). Narrower than
# "all of deploy/**" on purpose: those trees are noise-prone (arbitrary JSON/
# XML keys, docker-compose service names) relative to the install/upgrade
# surface this phase is auditing — ponytail: widen if a real bug is ever
# found living in one of them.
#
# THREE CHECKS, each failing loudly and naming the offending file:line:
#
#   1. Env vars / config keys — every backtick-wrapped SCREAMING_SNAKE_CASE
#      token (with at least one underscore, so bare acronyms like `TLS`/`API`
#      don't false-positive) must resolve to EITHER a `KEY=` line in
#      config.env.sample, OR a `koanf:"<key>"` struct tag in one of the three
#      config-loading Go files, where `<key>` is the token run through the
#      SAME transform `shared/config/koanf.go applyEnvOverrides` uses
#      (lowercase, `__`→`.`, first remaining `_`→`.`) — e.g. `TLS_DNS_PROVIDER`
#      → `tls.dns_provider`, matched against config.go's
#      `TLSDNSProvider string \`koanf:"tls.dns_provider"\`` tag. A small
#      allowlist covers install.sh's own bash-only variables (never a koanf
#      Config field) and the lego/Cloudflare DNS-01 JSON credential key
#      (consumed by the third-party lego library, not our Go code).
#
#   2. Script/doc paths — every backtick-or-bare repo-relative path (contains
#      `/`, ends in a recognized extension, does NOT start with `/` — leading
#      `/` means a deployment-target path like `/opt/setjoin/...` or an API
#      route like `/api/openapi.json`, neither of which is a repo file to
#      check) must exist at `$ROOT/<path>` or `$ROOT/mailserver/<path>` (docs
#      commonly write paths shorthand relative to `mailserver/`).
#
#   3. Systemd units — every `systemctl <verb> <unit>` / `journalctl -u <unit>`
#      must name either `setjoin` (the actual unit install.sh installs) or a
#      known third-party dependency the box also runs (postgresql, minio,
#      clamav@scan, pgpool, pgbouncer) — anything else is a dead unit
#      reference (this is the exact G0-001 bug class).
#
# Usage: scripts/check-deploy-doc-currency.sh
#   DOCS_DIR=<dir>            override docs/guides/*.md glob root (selftest)
#   DEPLOY_SCRIPTS_DIR=<dir>  override mailserver/deploy/scripts (selftest)
#   CONFIG_ENV_SAMPLE=<file>  override config.env.sample (selftest)
#   SERVICE_FILE=<file>       override mailserver.service (selftest)
# Self-test: scripts/check-deploy-doc-currency-selftest.sh — plants a dangling
# env var, a dangling script path, and a dead systemd unit; asserts each FIRES
# naming the offending line, then asserts the real repo passes clean.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"
set +e  # every fallible step below is checked explicitly

DOCS_DIR="${DOCS_DIR:-$ROOT/docs/guides}"
DEPLOY_SCRIPTS_DIR="${DEPLOY_SCRIPTS_DIR:-$ROOT/mailserver/deploy/scripts}"
CONFIG_ENV_SAMPLE="${CONFIG_ENV_SAMPLE:-$ROOT/mailserver/deploy/config.env.sample}"
# Arch review #A11 (2026-07-16): mailserver.service converged onto the
# {{TOKEN}} render seam and was renamed mailserver.service.template
# alongside authserver/setjoin-sfu/setjoin-valkey — this constant follows it
# so check 2 (script/doc paths) keeps scanning its content, not silently
# losing coverage because the old filename stopped resolving.
SERVICE_FILE="${SERVICE_FILE:-$ROOT/mailserver/deploy/mailserver.service.template}"
CONFIG_GO_FILES=(
  "$ROOT/mailserver/internal/config/config.go"
  "$ROOT/authserver/internal/config/config.go"
  "$ROOT/shared/config/base.go"
)

echo "==> Deploy-doc currency guard"
echo "    docs: $DOCS_DIR/*.md"
echo "    deploy scripts: $DEPLOY_SCRIPTS_DIR/*.sh"

shopt -s nullglob
DOC_FILES=("$DOCS_DIR"/*.md)
SCRIPT_FILES=("$DEPLOY_SCRIPTS_DIR"/*.sh)
shopt -u nullglob

if [ "${#DOC_FILES[@]}" -eq 0 ]; then
  echo "  [DEPLOY-DOC] no *.md files found under $DOCS_DIR" >&2
  exit 1
fi

fail=0

# ── install.sh-only bash variables (never a koanf Config field) + the
#    lego/Cloudflare DNS-01 JSON credential key + its go-test-only siblings.
# DB_DIRECT_OWNER_DSN: the owner's direct (non-pooled) DSN install.sh itself
# computes and persists for its OWN re-run use (native-RLS three-role shape)
# — never read by mailserverd/authserverd, so it has no koanf tag and was
# never meant to be a config.env.sample key (pre-existing guard gap, found
# and fixed alongside the Meet B1 Task 14 systemd-unit fix below — same
# stale-allowlist bug class, same script).
# RTC_PORT_START/RTC_PORT_END/USE_EXTERNAL_IP/TURN_CERT/TURN_KEY: Meet B1
# Task 14 install-time knobs for rendering livekit.yaml (lib-livekit.sh) —
# consumed by livekit-server via its config file, never by mailserverd/
# authserverd's own env, so they belong here, not in config.env.sample.
# EGRESS_ROOM_COMPOSITE_CPU_COST/EGRESS_CPUQUOTA: Meet B2 Task 9 install-time
# knobs for rendering egress.yaml / setjoin-egress.service.template — same
# shape, consumed by the Egress container / systemd unit, never by our Go.
# FEDERATION_ENABLED: Pillar C1 Task 9 — install.sh's own prompt-once/
# re-run-memory flag (the MEET_CAPTIONS_ENABLED genre), not a koanf Config
# field; mailserverd's actual static gate is FEDERATION_LOCAL_DOMAIN/_CERT/
# _KEY (all real koanf fields, resolve automatically below).
# RUN_PREFIX/REWIND_ATTEMPT/RUN_ID: disposable verification/rehearsal identities.
# They isolate repeated harness runs and are never daemon config.
declare -A NON_KOANF_ALLOW=(
  [SETJOIN_CONFIG_DIR]=1 [SETJOIN_ADMIN_EMAIL]=1 [NONINTERACTIVE]=1
  [INSTALL_DIR]=1 [DATA_DIR]=1 [ADMIN_PASSWORD]=1
  [CF_API_TOKEN]=1 [TEST_CF_API_TOKEN]=1 [TEST_ACME_DOMAIN]=1 [TEST_ACME_EMAIL]=1
  [TEST_EWS_CONFIG]=1 [DB_DIRECT_OWNER_DSN]=1
  [RTC_PORT_START]=1 [RTC_PORT_END]=1 [USE_EXTERNAL_IP]=1 [TURN_CERT]=1 [TURN_KEY]=1
  [EGRESS_ROOM_COMPOSITE_CPU_COST]=1 [EGRESS_CPUQUOTA]=1
  [FEDERATION_ENABLED]=1
  [RUN_PREFIX]=1 [REWIND_ATTEMPT]=1 [RUN_ID]=1
)

# Backticked uppercase identifiers in operator guides are not always
# configuration. Keep the exception narrow and self-verifying: each symbol is
# accepted only while its canonical implementation source still contains it.
declare -A DOCUMENTED_SYMBOL_SOURCE=(
  [REWIND_ATTEMPT]="$ROOT/scripts/transactional-upgrade-rehearsal.sh"
  [RUN_PREFIX]="$ROOT/scripts/unified-deployment-readiness.sh"
  [E_ROUTE_UNDOCUMENTED]="$ROOT/scripts/check-route-inventory.sh"
  [RAIL_APPS]="$ROOT/mailserver/webmail/src/lib/nav/navConfig.ts"
  [E_TOGGLE_REGISTRY_DRIFT]="$ROOT/scripts/check-toggle-registry.sh"
  [E_ARCH_R2_METRICS]="$ROOT/scripts/check-architecture-r2-dx-metrics.sh"
  # TRUSTED_PROXY_IP (TRUSTED_PROXY_DEPLOYMENT.md) is deliberately NOT a
  # koanf Config field or config.env.sample key: clientip.go reads it once at
  # process init via os.Getenv (shared/clientip — the single XFF trust
  # boundary). Accepted only while that canonical implementation source still
  # contains the symbol, like every entry above.
  [TRUSTED_PROXY_IP]="$ROOT/shared/clientip/clientip.go"
  # E2E_GATEWAY_FLIP_DIR (WEBMAIL_PERFORMANCE_VERIFICATION.md): the opt-in
  # webmail rehearsal seam — restarts ONLY the gateway against a validated
  # web root (start-test-stack.sh), keeping DB/SeaweedFS/authserver sessions
  # alive. Test-harness-only variable, never daemon config; accepted only
  # while its canonical implementation source still contains it.
  [E2E_GATEWAY_FLIP_DIR]="$ROOT/mailserver/webmail/e2e/scripts/start-test-stack.sh"
)

# ── third-party systemd units the box also runs, not ours + OUR OWN units
#    (install.sh has installed setjoin-auth.service since the auth split,
#    setjoin-sfu.service since Meet B1 Task 14, setjoin-valkey.service /
#    setjoin-egress.service since Meet B2 Task 9 (recording), and
#    setjoin-funasr.service / setjoin-asr-bot.service since Meet B3 Task 16
#    (captions, MEET_CAPTIONS_ENABLED-conditional); the exact-match-only-
#    "setjoin" check below predates all six and was silently failing on
#    every setjoin-auth reference already in the repo — a pre-existing gap,
#    not something any of these builds introduced, fixed here alongside the
#    first one to trip it).
# shellcheck source=../mailserver/deploy/generated/unit-catalog.sh
source "$ROOT/mailserver/deploy/generated/unit-catalog.sh"
declare -A OUR_UNIT_ALLOW=()
for unit in "${SETJOIN_ALL_UNITS[@]}"; do
  OUR_UNIT_ALLOW["$unit"]=1
done
declare -A INFRA_UNIT_ALLOW=(
  [postgresql]=1 [minio]=1 ["clamav@scan"]=1 [pgpool]=1 [pgbouncer]=1
)

# env_to_koanf_key NAME — mirrors shared/config/koanf.go's makeEnvTransform:
# lowercase, __ → ., then the FIRST remaining _ → . (one level of nesting).
env_to_koanf_key() {
  local k="${1,,}"
  k="${k//__/.}"
  if [[ "$k" == *_* ]]; then
    local head="${k%%_*}" tail="${k#*_}"
    k="$head.$tail"
  fi
  printf '%s' "$k"
}

# NOTE: all three checks below feed `IFS=: read -r file line ...`, so grep MUST
# print the filename. `-H` forces it: GNU grep OMITS the filename when given a
# single file (BSD grep always prints it), which shifted the fields and silently
# skipped every match on Linux for a lone doc file. Do not drop -H.
#
# ── Check 1: env vars / config keys ─────────────────────────────────────────
echo "-- env vars / config keys --"
n1=0
while IFS=: read -r file line rawtok; do
  [ -z "$rawtok" ] && continue
  var="${rawtok//\`/}"
  n1=$((n1 + 1))
  [ -n "${NON_KOANF_ALLOW[$var]:-}" ] && continue
  symbol_source="${DOCUMENTED_SYMBOL_SOURCE[$var]:-}"
  if [ -n "$symbol_source" ] && [ -f "$symbol_source" ] && grep -qF "$var" "$symbol_source"; then continue; fi
  if [ -f "$CONFIG_ENV_SAMPLE" ] && grep -qE "^$var=" "$CONFIG_ENV_SAMPLE"; then continue; fi
  key="$(env_to_koanf_key "$var")"
  if grep -q "koanf:\"$key\"" "${CONFIG_GO_FILES[@]}" 2>/dev/null; then continue; fi
  echo "  [DEPLOY-DOC] $file:$line: \`$var\` resolves to neither a config.env.sample key nor a koanf:\"$key\" tag" >&2
  fail=1
done < <(grep -rHnoE '`[A-Z][A-Z0-9]*(_[A-Z0-9]+)+`' "${DOC_FILES[@]}")
echo "   $n1 token(s) checked."

# ── Check 2: script/doc paths ───────────────────────────────────────────────
# Known repo top-level dirs (+ "deploy" as the mailserver/deploy shorthand
# docs commonly write) a real reference's first path segment must start
# with — this rejects noise picked up by the character class below (e.g. a
# `$ROOT/mailserver/...` bash-variable expansion in install.sh: since `$` is
# not a path char, the leftmost match starts at `ROOT/mailserver/...`, whose
# first segment `ROOT` isn't a real top-level dir, so it's correctly ignored
# rather than reported as a dangling path).
TOP_LEVEL_ALLOW=(mailserver authserver shared mailctl clients docs scripts examples deploy)
is_top_level_allowed() {
  local seg="$1" t
  for t in "${TOP_LEVEL_ALLOW[@]}"; do [ "$seg" = "$t" ] && return 0; done
  return 1
}

# `template` is a recognized path extension (check 2) even though `deploy/*.template`
# files stay OUT of the scan-input glob (header note above still holds: their
# placeholders are the point). Deploy scripts and docs reference rendered-source
# templates by repo path — e.g. install.sh's HA leg pins
# `deploy/failover.sh.template` and the render tests pin `mailserver.service.template`
# — and without `template` in the alternation the greedy regex truncated those
# references at the inner `.sh`/`.service` dot, manufacturing dangling paths
# (`deploy/failover.sh`) out of references that actually resolve. Recognizing the
# extension makes the guard check the WHOLE referenced path instead.

echo "-- script/doc paths --"
n2=0
while IFS=: read -r file line rawpath; do
  [ -z "$rawpath" ] && continue
  p="${rawpath//\`/}"
  [[ "$p" == /* ]] && continue  # deployment-target path or API route, not a repo file
  while [[ "$p" == ../* ]]; do p="${p#../}"; done
  seg="${p%%/*}"
  is_top_level_allowed "$seg" || continue  # not a repo-relative reference (e.g. a $VAR expansion)
  n2=$((n2 + 1))
  if [ -e "$ROOT/$p" ] || [ -e "$ROOT/mailserver/$p" ]; then continue; fi
  # Evidence guides intentionally name atomically published, ignored runtime
  # manifests. Accept only paths under a real test-results parent that Git
  # confirms is ignored; a typo outside that evidence boundary still fails.
  if [[ "$p" == */test-results/* ]]; then
    candidate="$ROOT/$p"
    [[ "$p" == mailserver/* ]] || candidate="$ROOT/mailserver/$p"
    parent="$candidate"
    while [ ! -d "$parent" ] && [ "$parent" != "$ROOT" ]; do parent="$(dirname "$parent")"; done
    if [ -d "$parent" ] && git -C "$ROOT" check-ignore -q "$candidate"; then continue; fi
  fi
  echo "  [DEPLOY-DOC] $file:$line: path '$p' does not resolve at \$ROOT/$p or \$ROOT/mailserver/$p" >&2
  fail=1
done < <(grep -rHnoE '`?[A-Za-z0-9_./-]*/[A-Za-z0-9_./-]+\.(sh|md|go|service|sql|yml|yaml|json|template)`?' \
           "${DOC_FILES[@]}" "${SCRIPT_FILES[@]}" "$SERVICE_FILE" 2>/dev/null | sort -u)
echo "   $n2 path(s) checked."

# ── Check 3: systemd units ──────────────────────────────────────────────────
echo "-- systemd units --"
n3=0
while IFS=: read -r file line match; do
  [ -z "$match" ] && continue
  unit="$(printf '%s' "$match" | awk '{print $NF}')"
  n3=$((n3 + 1))
  [ -n "${OUR_UNIT_ALLOW[$unit]:-}" ] && continue
  [ -n "${INFRA_UNIT_ALLOW[$unit]:-}" ] && continue
  echo "  [DEPLOY-DOC] $file:$line: systemd reference names unit '$unit' — it is not in the generated Setjoin unit catalog or the known infrastructure list" >&2
  fail=1
done < <(grep -rHnoE '(^|[[:space:];|&(!])systemctl [a-z-]+( --?[A-Za-z0-9@._=-]+)* [A-Za-z0-9@._-]+|(^|[[:space:];|&(!])journalctl -u [A-Za-z0-9@._-]+' "${DOC_FILES[@]}" "${SCRIPT_FILES[@]}" 2>/dev/null)
echo "   $n3 systemd reference(s) checked."

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Deploy-doc currency guard FAILED (see above)." >&2
  exit 1
fi

echo ""
echo "Deploy-doc currency guard: clean."
