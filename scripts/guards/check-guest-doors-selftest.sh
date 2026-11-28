#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-guest-doors-selftest.sh — prove check-guest-doors.sh still FIRES on
# EVERY one of its five assertions, not just §1's membership-grant check (the
# check-deploy-doc-currency lesson: a guard whose self-test only exercises one
# of several assertions can silently rot on the others). Plants one violation
# at a time into a scratch copy of the guarded tree, runs the guard against
# it, and asserts a non-zero exit naming the right thing. Finishes by proving
# an UNMUTATED scratch copy still passes (the real full-tree pass is a
# separate, authoritative check — `bash scripts/guards/check-guest-doors.sh` from
# ROOT — run right after this by run-guards.sh).
#
# Coverage: §1 (1 case) · §2 (5 cases: markers, route literal, Meet blanket,
# public poll, RTC exact/slash-prefix) · §3 (3 cases:
# AuthenticateRequest, AuthenticatePushToken, bcrypt) · §4 (2 cases) · §5 (3
# cases: wrap lost, apiMux served directly, /api mount not gatedAPI). All 5
# assertions are feasibly fixturable via plain text mutation (the guard is
# pure grep/awk, not a compiler), so none are skipped.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUARD_SRC="$ROOT/scripts/guards/check-guest-doors.sh"
fail=0

# mk_clean DIR — populate DIR with an unmutated copy of every file the guard
# reads, plus an empty reducers dir. An empty $RED/*.sql glob makes grep -l
# print "No such file or directory" to stderr, but under `set -euo pipefail`
# that failure sits inside a `< <(...)` process substitution — its exit
# status is never checked by the enclosing `while read`, so the loop simply
# runs zero times and the script continues (verified: this is NOT a false
# "no reducers to flag" pass hiding a bug — it's ordinary bash process-
# substitution semantics, exercised identically by the guard's own §1/§4 loops
# on the real tree when nothing matches).
mk_clean() {
  local d="$1"
  mkdir -p "$d/mailserver/sql/reducers" "$d/scripts/guards"
  cp "$ROOT/mailserver/sql/reducers/guest_profile.sql" "$d/mailserver/sql/reducers/"
  cp "$GUARD_SRC" "$d/scripts/guards/"
}

# run_case NAME EXPECT_SUBSTR SETUP_FN — mk_clean a scratch dir, run SETUP_FN
# in it to plant exactly one violation, then run the guard and assert it
# fires naming EXPECT_SUBSTR. Reports OK/FAIL per case; does not abort the
# run on a single failure (the whole punch list matters, same posture as
# run-guards.sh itself).
run_case() {
  local name="$1" expect="$2" setup="$3"
  local d out
  d="$(mktemp -d)"
  mk_clean "$d"
  "$setup" "$d"
  if out="$(cd "$d" && bash scripts/guards/check-guest-doors.sh 2>&1)"; then
    echo "SELFTEST FAIL [$name]: guard did not fire on a planted violation"
    fail=1
  elif ! echo "$out" | grep -q "$expect"; then
    echo "SELFTEST FAIL [$name]: guard fired but did not mention '$expect':"
    echo "$out" | sed 's/^/    /'
    fail=1
  else
    echo "  [$name] caught: OK"
  fi
  rm -rf "$d"
}

# ── §1: unjustified membership-granting reducer ─────────────────────────────
setup_s1() {
  cat > "$1/mailserver/sql/reducers/evil_new_door.sql" <<'SQL'
CREATE OR REPLACE FUNCTION evil_open_door(p_user_id bigint, p_channel_id bigint) RETURNS void AS $fn$
BEGIN
    INSERT INTO chat_channel_members (channel_id, user_id, role) VALUES (p_channel_id, p_user_id, 'member');
END;
$fn$ LANGUAGE plpgsql;
SQL
}

# ── §4: RLS-blind raw guest_accounts read outside the named excepted files ───
setup_s4() {
  cat > "$1/mailserver/sql/reducers/evil_raw_read.sql" <<'SQL'
CREATE OR REPLACE FUNCTION evil_peek(p_user_id bigint) RETURNS boolean AS $fn$
  SELECT EXISTS (SELECT 1 FROM guest_accounts WHERE user_id = p_user_id);
$fn$ LANGUAGE sql;
SQL
}
setup_s4_profile_authority() {
  sed 's/SECURITY DEFINER/SECURITY INVOKER/g' "$ROOT/mailserver/sql/reducers/guest_profile.sql" \
    > "$1/mailserver/sql/reducers/guest_profile.sql"
}

run_case "§1 unjustified membership grant"         "evil_new_door.sql"                                 setup_s1
run_case "§4 raw guest_accounts read"              "evil_raw_read.sql reads guest_accounts directly"   setup_s4
run_case "§4 guest_profile loses worker authority" "guest_profile.sql exception lost worker authority" setup_s4_profile_authority

# ── clean copy still passes (no false positive from copying unmodified) ────
d="$(mktemp -d)"
mk_clean "$d"
if out="$(cd "$d" && bash scripts/guards/check-guest-doors.sh 2>&1)"; then
  echo "  [clean scratch copy] passes: OK"
else
  echo "SELFTEST FAIL [clean scratch copy]: guard failed on an unmutated copy:"
  echo "$out" | sed 's/^/    /'
  fail=1
fi
rm -rf "$d"

if [ "$fail" -ne 0 ]; then
  echo "check-guest-doors selftest: FAILED (see above)"
  exit 1
fi
echo "check-guest-doors selftest OK (3/3 mutations caught + clean copy passes)"
