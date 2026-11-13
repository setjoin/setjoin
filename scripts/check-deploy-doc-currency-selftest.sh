#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-deploy-doc-currency-selftest.sh — proves check-deploy-doc-currency.sh
# actually FIRES (red-first proof, GA-readiness G1).
#
# Plants a synthetic docs/guides + deploy/scripts pair with three planted
# defects (one per check: a dangling env var, a dangling script path, a dead
# systemd unit name) and asserts the guard fails each, naming the offending
# line. Then asserts the guard passes clean against the REAL repo (no false
# positives on the doc set it just protected). Never mutates real files.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-deploy-doc-currency.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# ── Case A: dangling env var must FIRE ──────────────────────────────────────
DOCS_A="$TMP/docs_a"; mkdir -p "$DOCS_A"
cat > "$DOCS_A/fake.md" <<'EOF'
# Fake guide
Set `TOTALLY_MADE_UP_ENV_VAR_XYZ` before starting the gateway.
EOF
out_a="$(DOCS_DIR="$DOCS_A" DEPLOY_SCRIPTS_DIR="$TMP/empty_scripts" bash "$GUARD" 2>&1)"; rc_a=$?
mkdir -p "$TMP/empty_scripts"
out_a="$(DOCS_DIR="$DOCS_A" DEPLOY_SCRIPTS_DIR="$TMP/empty_scripts" bash "$GUARD" 2>&1)"; rc_a=$?
if [ "$rc_a" -eq 0 ]; then bad "(A) dangling env var did NOT fire (rc=0)"; else ok "(A) dangling env var fails the guard (rc=$rc_a)"; fi
if printf '%s' "$out_a" | grep -q 'TOTALLY_MADE_UP_ENV_VAR_XYZ'; then ok "(A) names the offending token"; else bad "(A) did not name the token:"$'\n'"$out_a"; fi

# ── Case B: dangling script path must FIRE ──────────────────────────────────
DOCS_B="$TMP/docs_b"; mkdir -p "$DOCS_B"
cat > "$DOCS_B/fake.md" <<'EOF'
# Fake guide
Run `mailserver/deploy/scripts/this-script-does-not-exist.sh` on the server.
EOF
out_b="$(DOCS_DIR="$DOCS_B" DEPLOY_SCRIPTS_DIR="$TMP/empty_scripts" bash "$GUARD" 2>&1)"; rc_b=$?
if [ "$rc_b" -eq 0 ]; then bad "(B) dangling script path did NOT fire (rc=0)"; else ok "(B) dangling script path fails the guard (rc=$rc_b)"; fi
if printf '%s' "$out_b" | grep -q 'this-script-does-not-exist.sh'; then ok "(B) names the offending path"; else bad "(B) did not name the path:"$'\n'"$out_b"; fi

# ── Case C: dead systemd unit name must FIRE (the exact G0-001 bug class) ──
SCRIPTS_C="$TMP/scripts_c"; mkdir -p "$SCRIPTS_C"
cat > "$SCRIPTS_C/upgrade-fake.sh" <<'EOF'
#!/usr/bin/env bash
systemctl stop mailserver
EOF
DOCS_EMPTY="$TMP/docs_empty"; mkdir -p "$DOCS_EMPTY"
cat > "$DOCS_EMPTY/fake.md" <<'EOF'
# placeholder (no candidate tokens)
EOF
out_c="$(DOCS_DIR="$DOCS_EMPTY" DEPLOY_SCRIPTS_DIR="$SCRIPTS_C" bash "$GUARD" 2>&1)"; rc_c=$?
if [ "$rc_c" -eq 0 ]; then bad "(C) dead systemd unit did NOT fire (rc=0)"; else ok "(C) dead systemd unit fails the guard (rc=$rc_c)"; fi
if printf '%s' "$out_c" | grep -q "names unit 'mailserver'"; then ok "(C) names the offending unit"; else bad "(C) did not name the unit:"$'\n'"$out_c"; fi

# ── Case D: flags between the verb and unit must not become the unit ───────
SCRIPTS_D="$TMP/scripts_d"; mkdir -p "$SCRIPTS_D"
cat > "$SCRIPTS_D/upgrade-valid.sh" <<'EOF'
#!/usr/bin/env bash
systemctl is-active --quiet setjoin-auth
EOF
out_d="$(DOCS_DIR="$DOCS_EMPTY" DEPLOY_SCRIPTS_DIR="$SCRIPTS_D" bash "$GUARD" 2>&1)"; rc_d=$?
if [ "$rc_d" -eq 0 ]; then
  ok "(D) a systemctl option is consumed before the valid unit name"
else
  bad "(D) a valid systemctl option was treated as the unit:"$'\n'"$out_d"
fi

# ── Case E: prose mentioning systemctl must not become a unit reference ────
SCRIPTS_E="$TMP/scripts_e"; mkdir -p "$SCRIPTS_E"
cat > "$SCRIPTS_E/prose-valid.sh" <<'EOF'
#!/usr/bin/env bash
command -v systemctl >/dev/null 2>&1 || echo "systemctl is unavailable"
EOF
out_e="$(DOCS_DIR="$DOCS_EMPTY" DEPLOY_SCRIPTS_DIR="$SCRIPTS_E" bash "$GUARD" 2>&1)"; rc_e=$?
if [ "$rc_e" -eq 0 ]; then
  ok "(E) quoted systemctl prose is not parsed as a command"
else
  bad "(E) quoted systemctl prose was treated as a unit:"$'\n'"$out_e"
fi

# ── Case F: the REAL repo doc set must PASS (no false positives) ──────────
out_f="$(bash "$GUARD" 2>&1)"; rc_f=$?
if [ "$rc_f" -eq 0 ]; then
  ok "(F) the real repo docs/deploy scripts pass the guard clean"
else
  bad "(F) the REAL repo fails the guard right now:"$'\n'"$out_f"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-deploy-doc-currency selftest FAILED ($fail/$((pass+fail)) checks failed)."
  exit 1
fi
echo "check-deploy-doc-currency selftest: all $pass checks passed (guard fires + is precise)."
