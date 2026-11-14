#!/usr/bin/env bash
# test-livekit-render.sh — the one runnable check for lib-livekit.sh's
# render logic (ponytail: no framework, an assert-based script). Covers the
# livekit.yaml properties Task 14 must prove at render time, not just narrate:
#   (a) the SAME LIVEKIT_API_SECRET value lands in both the rendered yaml and
#       a config.env-shaped snippet (the drift-killer, spike §2 finding 3).
#   (b) with the TURN cert pair ABSENT, the rendered yaml carries
#       `enabled: false` (no-TURN, never no-SFU — eng BLOCKER #1); with the
#       pair PRESENT, `enabled: true`.
#   (c) no {{...}} placeholder ever survives into the rendered file.
# Plus the Meet B2 (Task 9) properties for the Valkey/Egress render legs:
#   (d) livekit.yaml's redis: block carries the SAME VALKEY_PASSWORD as
#       egress.yaml and valkey.conf (law 3, container edition).
#   (e) egress.yaml's cpu_cost defaults to 3 and honors an override.
#   (f) setjoin-egress.service renders CONTAINER_BIN + the pinned
#       EGRESS_IMAGE, and both new units carry StartLimit* in [Unit] (the
#       25bef473 lesson, structurally checked, not narrated).
#   (g) a missing required var (VALKEY_PASSWORD / LIVEKIT_API_SECRET /
#       CONTAINER_BIN) fails loud on every affected render function.
# Plus the Meet B3 (Task 16) properties for the OPTIONAL captions sidecar
# pair (setjoin-asr-bot + setjoin-funasr):
#   (h) both new units render with no surviving {{...}}, and both carry
#       StartLimit* in [Unit] (the 25bef473 lesson, extended).
#   (i) render_asrbot_env substitutes LIVEKIT_URL/FUNASR_URL/ASR_LISTEN/
#       ASR_MAX_MEETINGS/ASR_MAX_ACTIVE_TRACKS, defaults them correctly, and
#       REFUSES a non-loopback ASR_LISTEN (the bot.ValidateLoopback check,
#       caught a layer earlier).
#   (j) render_funasr_unit refuses both a missing CONTAINER_BIN and an
#       unpinned (CHANGEME/empty) FUNASR_IMAGE — the fail-loud-never-a-
#       silent-unpinned-pull posture the plan requires.
# Plus the B3 Task 18 pipeline-review properties:
#   (k) render_asrbot_env requires ASR_TOKEN (finding 1) and renders it.
#   (l) setjoin-funasr.service.template never binds --network=host, always
#       loopback-publishes -p 127.0.0.1:10096:10095, and never persists
#       stdout to journald (findings 2 + 3).
#
# Usage: bash mailserver/deploy/scripts/test-livekit-render.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib-livekit.sh
source "$SCRIPT_DIR/lib-livekit.sh"

TMPL="$SCRIPT_DIR/../livekit.yaml.template"
EGRESS_TMPL="$SCRIPT_DIR/../egress.yaml.template"
EGRESS_UNIT_TMPL="$SCRIPT_DIR/../setjoin-egress.service.template"
ASRBOT_UNIT_TMPL="$SCRIPT_DIR/../setjoin-asr-bot.service.template"
FUNASR_UNIT_TMPL="$SCRIPT_DIR/../setjoin-funasr.service.template"
ASRBOT_ENV_TMPL="$SCRIPT_DIR/../asrbot.env.template"
# Arch review #A11: the 4 units that used to be bespoke-sed-rewritten by
# install.sh, now on the same render seam as everything else above.
MAILSERVER_UNIT_TMPL="$SCRIPT_DIR/../mailserver.service.template"
AUTHSERVER_UNIT_TMPL="$SCRIPT_DIR/../authserver.service.template"
SFU_UNIT_TMPL="$SCRIPT_DIR/../setjoin-sfu.service.template"
VALKEY_UNIT_TMPL="$SCRIPT_DIR/../setjoin-valkey.service.template"
INSTALL_SCRIPT="$SCRIPT_DIR/install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
assert_contains() { # assert_contains <file> <needle> <label>
  if grep -qF -- "$2" "$1"; then
    printf 'ok   - %s\n' "$3"
  else
    printf 'FAIL - %s (expected to find %q in %s)\n' "$3" "$2" "$1"
    fail=1
  fi
}
assert_not_contains() { # assert_not_contains <file> <needle> <label>
  if grep -qF -- "$2" "$1"; then
    printf 'FAIL - %s (did NOT expect %q in %s)\n' "$3" "$2" "$1"
    fail=1
  else
    printf 'ok   - %s\n' "$3"
  fi
}

# ── Case 1: no TURN cert pair on disk → TURN disabled, secret carried through ──
export HOSTNAME="test.example.com"
export LIVEKIT_API_SECRET="deadbeefcafef00d0123456789abcdef0123456789abcdef0123456789abcd"
export VALKEY_PASSWORD="valkeypw0123456789abcdef0123456789abcdef0123456789abcdef012345"
unset RTC_PORT_START RTC_PORT_END USE_EXTERNAL_IP TURN_CERT TURN_KEY 2>/dev/null || true
export TURN_CERT="$WORK/no-such-cert.pem"
export TURN_KEY="$WORK/no-such-key.pem"

render_livekit_yaml "$TMPL" "$WORK/no-turn.yaml"
assert_directive() { # assert_directive <file> <anchored-regex> <label>
  if grep -q -- "$2" "$1"; then
    printf 'ok   - %s\n' "$3"
  else
    printf 'FAIL - %s (expected to find /%s/ in %s)\n' "$3" "$2" "$1"
    fail=1
  fi
}
# Anchored to the `  enabled: false` DIRECTIVE (^  enabled: false), not a loose
# substring match — the template's own comment at livekit.yaml.template:44
# ("Missing cert => enabled: false") contains that substring unconditionally,
# so an unanchored assert_contains here passes even if the renderer always
# emits `enabled: true` (verified false-positive: forcing turn_enabled="true"
# unconditionally in lib-livekit.sh keeps this test green without this fix).
# Mirrors the already-anchored form at install.sh:582.
assert_directive "$WORK/no-turn.yaml" '^  enabled: false' "no cert pair -> turn.enabled: false"
assert_contains "$WORK/no-turn.yaml" "$LIVEKIT_API_SECRET" "secret substituted into livekit.yaml"
assert_not_contains "$WORK/no-turn.yaml" "{{" "no leftover {{...}} placeholders (no-turn case)"

# The drift-killer proof: a config.env-shaped snippet built from the SAME
# shell variable must carry the identical secret string.
printf 'LIVEKIT_API_KEY=setjoin\nLIVEKIT_API_SECRET=%s\nLIVEKIT_URL=ws://127.0.0.1:7880\n' \
  "$LIVEKIT_API_SECRET" > "$WORK/config.env.snippet"
YAML_SECRET="$(grep -A0 '^  setjoin:' "$WORK/no-turn.yaml" | awk '{print $2}')"
ENV_SECRET="$(grep '^LIVEKIT_API_SECRET=' "$WORK/config.env.snippet" | cut -d= -f2)"
if [ "$YAML_SECRET" = "$ENV_SECRET" ] && [ -n "$YAML_SECRET" ]; then
  printf 'ok   - %s\n' "same secret in livekit.yaml and config.env"
else
  printf 'FAIL - %s (yaml=%q env=%q)\n' "same secret in livekit.yaml and config.env" "$YAML_SECRET" "$ENV_SECRET"
  fail=1
fi

# ── Case 2: TURN cert pair PRESENT on disk → TURN enabled ──────────────────────
printf 'dummy-cert' > "$WORK/fullchain.pem"
printf 'dummy-key'  > "$WORK/privkey.pem"
export TURN_CERT="$WORK/fullchain.pem"
export TURN_KEY="$WORK/privkey.pem"
render_livekit_yaml "$TMPL" "$WORK/with-turn.yaml"
assert_directive "$WORK/with-turn.yaml" '^  enabled: true' "cert pair present -> turn.enabled: true"
assert_contains "$WORK/with-turn.yaml" "cert_file: $WORK/fullchain.pem" "cert_file path rendered"
assert_not_contains "$WORK/with-turn.yaml" "{{" "no leftover {{...}} placeholders (with-turn case)"

# ── Case 3: a required placeholder left unset must fail loud, not render garbage ──
unset LIVEKIT_API_SECRET
if render_livekit_yaml "$TMPL" "$WORK/should-not-exist.yaml" 2>"$WORK/err.txt"; then
  printf 'FAIL - %s\n' "render_livekit_yaml must fail when LIVEKIT_API_SECRET is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_livekit_yaml fails loud on missing required var"
fi
export LIVEKIT_API_SECRET="deadbeefcafef00d0123456789abcdef0123456789abcdef0123456789abcd"

# Case 3b: same, but VALKEY_PASSWORD unset (Meet B2 — livekit.yaml's redis:
# block is required from birth, not optional).
unset VALKEY_PASSWORD
if render_livekit_yaml "$TMPL" "$WORK/should-not-exist-2.yaml" 2>"$WORK/err2.txt"; then
  printf 'FAIL - %s\n' "render_livekit_yaml must fail when VALKEY_PASSWORD is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_livekit_yaml fails loud on missing VALKEY_PASSWORD"
fi
export VALKEY_PASSWORD="valkeypw0123456789abcdef0123456789abcdef0123456789abcdef012345"

# ── Case 4: livekit.yaml's redis: block carries VALKEY_PASSWORD (law 3) ────────
assert_contains "$WORK/no-turn.yaml" "$VALKEY_PASSWORD" "VALKEY_PASSWORD substituted into livekit.yaml's redis: block"
assert_directive "$WORK/no-turn.yaml" '^  address: 127.0.0.1:6390' "livekit.yaml redis.address is the loopback Valkey"

# ── Case 5: egress.yaml renders the bus block + cpu_cost (plan delta 4) ────────
render_egress_yaml "$EGRESS_TMPL" "$WORK/egress.yaml"
assert_contains "$WORK/egress.yaml" "address: 127.0.0.1:6390" "egress.yaml redis.address is the loopback Valkey"
assert_contains "$WORK/egress.yaml" "password: $VALKEY_PASSWORD" "egress.yaml carries the SAME VALKEY_PASSWORD as livekit.yaml"
assert_contains "$WORK/egress.yaml" "api_secret: $LIVEKIT_API_SECRET" "egress.yaml carries the SAME LIVEKIT_API_SECRET"
assert_directive "$WORK/egress.yaml" '^  room_composite_cpu_cost: 3' "egress.yaml cpu_cost defaults to 3"
assert_not_contains "$WORK/egress.yaml" "{{" "no leftover {{...}} placeholders (egress.yaml)"

EGRESS_ROOM_COMPOSITE_CPU_COST=6 render_egress_yaml "$EGRESS_TMPL" "$WORK/egress-override.yaml"
assert_directive "$WORK/egress-override.yaml" '^  room_composite_cpu_cost: 6' "egress.yaml cpu_cost honors an override"

# missing required var (VALKEY_PASSWORD) fails loud, not a broken render
unset VALKEY_PASSWORD
if render_egress_yaml "$EGRESS_TMPL" "$WORK/should-not-exist-3.yaml" 2>"$WORK/err3.txt"; then
  printf 'FAIL - %s\n' "render_egress_yaml must fail when VALKEY_PASSWORD is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_egress_yaml fails loud on missing VALKEY_PASSWORD"
fi
export VALKEY_PASSWORD="valkeypw0123456789abcdef0123456789abcdef0123456789abcdef012345"

# ── Case 6: setjoin-egress.service.template renders CONTAINER_BIN + the
#    pinned EGRESS_IMAGE, honors an EGRESS_CPUQUOTA override, and never
#    lets a caller override the pinned image (no such placeholder exists) ──
export CONTAINER_BIN="/usr/bin/podman"
render_egress_unit "$EGRESS_UNIT_TMPL" "$WORK/setjoin-egress.service"
assert_contains "$WORK/setjoin-egress.service" "ExecStart=/usr/bin/podman run" "egress unit substitutes CONTAINER_BIN"
assert_contains "$WORK/setjoin-egress.service" "$EGRESS_IMAGE" "egress unit carries the pinned EGRESS_IMAGE digest"
assert_directive "$WORK/setjoin-egress.service" '^CPUQuota=400%' "egress unit CPUQuota defaults to 400%"
assert_not_contains "$WORK/setjoin-egress.service" "{{" "no leftover {{...}} placeholders (setjoin-egress.service)"

EGRESS_CPUQUOTA=800% render_egress_unit "$EGRESS_UNIT_TMPL" "$WORK/setjoin-egress-override.service"
assert_directive "$WORK/setjoin-egress-override.service" '^CPUQuota=800%' "egress unit CPUQuota honors an override"

unset CONTAINER_BIN
if render_egress_unit "$EGRESS_UNIT_TMPL" "$WORK/should-not-exist-4.service" 2>"$WORK/err4.txt"; then
  printf 'FAIL - %s\n' "render_egress_unit must fail when CONTAINER_BIN is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_egress_unit fails loud on missing CONTAINER_BIN"
fi

# ── Case 7: provision_valkey_conf writes a loopback-only, no-persistence,
#    password-protected config (law 3: same password as the yaml renders) ──
provision_valkey_conf "$WORK/valkey.conf"
assert_contains "$WORK/valkey.conf" "bind 127.0.0.1" "valkey.conf binds loopback-only"
assert_contains "$WORK/valkey.conf" "port 6390" "valkey.conf listens on 6390 (never the default 6379)"
assert_contains "$WORK/valkey.conf" "requirepass $VALKEY_PASSWORD" "valkey.conf carries the SAME VALKEY_PASSWORD"
assert_contains "$WORK/valkey.conf" 'save ""' "valkey.conf disables RDB persistence (bus only)"
assert_contains "$WORK/valkey.conf" "appendonly no" "valkey.conf disables AOF persistence (bus only)"
mode="$(stat -c '%a' "$WORK/valkey.conf" 2>/dev/null || stat -f '%Lp' "$WORK/valkey.conf" 2>/dev/null)"
if [ "$mode" = "600" ]; then
  printf 'ok   - %s\n' "valkey.conf written mode 0600"
else
  printf 'FAIL - %s (mode=%s)\n' "valkey.conf written mode 0600" "$mode"
  fail=1
fi

unset VALKEY_PASSWORD
if provision_valkey_conf "$WORK/should-not-exist-5.conf" 2>"$WORK/err5.txt"; then
  printf 'FAIL - %s\n' "provision_valkey_conf must fail when VALKEY_PASSWORD is unset"
  fail=1
else
  printf 'ok   - %s\n' "provision_valkey_conf fails loud on missing VALKEY_PASSWORD"
fi
export VALKEY_PASSWORD="valkeypw0123456789abcdef0123456789abcdef0123456789abcdef012345"

# ── Case 8: the 25bef473 lesson, structurally checked on BOTH new units —
#    StartLimit* must live in [Unit] (systemd silently ignores them under
#    [Service]), not just asserted in prose ──
# unit_section FILE HEADER — prints from HEADER (e.g. '[Unit]') up to (and
# including) the next '[...]' section marker. A fixed grep -A<N> window
# (the original form of this helper) silently under-covers a unit whose
# [Unit] block has a long comment preamble before StartLimitBurst — found
# by extending this script to mailserver.service.template/
# authserver.service.template/setjoin-sfu.service.template (arch review
# #A11), which all have longer [Unit] comment blocks than the -A10 window
# covered; this section-bounded form is correct for any block length.
unit_section() { # <file> <header>
  sed -n "/^\\${2}/,/^\\[/p" "$1"
}
assert_unit_section_has_startlimit() { # <file> <label>
  if unit_section "$1" '[Unit]' | grep -q '^StartLimitBurst='; then
    printf 'ok   - %s\n' "$2"
  else
    printf 'FAIL - %s ([Unit] section missing StartLimitBurst in %s)\n' "$2" "$1"
    fail=1
  fi
}
assert_unit_section_has_startlimit "$VALKEY_UNIT_TMPL" "setjoin-valkey.service.template: StartLimit* lives in [Unit]"
assert_unit_section_has_startlimit "$WORK/setjoin-egress.service" "setjoin-egress.service: StartLimit* lives in [Unit] (rendered)"
# The [Service] section of each unit must NOT also carry it (systemd ignores
# it there — a duplicate would be dead config, not a second safety net).
if unit_section "$VALKEY_UNIT_TMPL" '[Service]' | grep -q '^StartLimitBurst='; then
  printf 'FAIL - %s\n' "setjoin-valkey.service: StartLimitBurst must not also appear under [Service]"
  fail=1
else
  printf 'ok   - %s\n' "setjoin-valkey.service: no dead StartLimitBurst under [Service]"
fi

# ── Case 9: setjoin-asr-bot.service.template renders INSTALL_DIR (default +
#    override), no leftover {{...}}, and carries StartLimit* in [Unit] ──────
# Arch review #A11: User/Group now render in this SAME call (the two-pass
# render-then-sed hybrid #A11 called out as the next-bug seam is gone) —
# asserted here, not just in install.sh's own removed second pass.
render_asrbot_unit "$ASRBOT_UNIT_TMPL" "$WORK/setjoin-asr-bot.service"
assert_contains "$WORK/setjoin-asr-bot.service" "ExecStart=/opt/mailserver/bin/asrbotd" "asrbot unit defaults INSTALL_DIR to /opt/mailserver"
assert_contains "$WORK/setjoin-asr-bot.service" "EnvironmentFile=/etc/setjoin/asrbot.env" "asrbot unit reads asrbot.env (never config.env — D4, no DB/S3 credential)"
assert_contains "$WORK/setjoin-asr-bot.service" "User=setjoin" "asrbot unit renders User=setjoin in the SAME call (no more two-pass hybrid)"
assert_contains "$WORK/setjoin-asr-bot.service" "Group=setjoin" "asrbot unit renders Group=setjoin in the SAME call (no more two-pass hybrid)"
assert_not_contains "$WORK/setjoin-asr-bot.service" "{{" "no leftover {{...}} placeholders (setjoin-asr-bot.service)"

INSTALL_DIR=/srv/setjoin render_asrbot_unit "$ASRBOT_UNIT_TMPL" "$WORK/setjoin-asr-bot-override.service"
assert_contains "$WORK/setjoin-asr-bot-override.service" "ExecStart=/srv/setjoin/bin/asrbotd" "asrbot unit INSTALL_DIR honors an override"

# ── Case 10: setjoin-funasr.service.template renders CONTAINER_BIN + the
#    pinned FUNASR_IMAGE, honors an optional FUNASR_GPU_ARGS, and refuses
#    both a missing CONTAINER_BIN and an unpinned FUNASR_IMAGE ───────────────
export CONTAINER_BIN="/usr/bin/podman"
render_funasr_unit "$FUNASR_UNIT_TMPL" "$WORK/setjoin-funasr.service"
assert_contains "$WORK/setjoin-funasr.service" "ExecStart=/usr/bin/podman run" "funasr unit substitutes CONTAINER_BIN"
assert_contains "$WORK/setjoin-funasr.service" "$FUNASR_IMAGE" "funasr unit carries the pinned FUNASR_IMAGE digest"
assert_contains "$WORK/setjoin-funasr.service" "/workspace/models:ro" "funasr unit mounts the model volume read-only"
assert_not_contains "$WORK/setjoin-funasr.service" "{{" "no leftover {{...}} placeholders (setjoin-funasr.service)"

# Findings 2 + 3 (B3 Task 18 pipeline review): no host-networking (network-
# wide exposure of an unauthenticated plaintext-WS server), an explicit
# loopback-only port publish matching FUNASR_URL's default, and stdout
# never journald-persisted (spoken transcript retention, D4).
assert_not_contains "$WORK/setjoin-funasr.service" "--network=host" "funasr unit does not use --network=host (finding 2: network-wide exposure)"
assert_contains "$WORK/setjoin-funasr.service" "-p 127.0.0.1:10096:10095" "funasr unit loopback-publishes 10096->10095 (finding 2: matches FUNASR_URL's default)"
assert_contains "$WORK/setjoin-funasr.service" "--port 10095" "funasr unit pins the container's own listen port explicitly (finding 2)"
assert_contains "$WORK/setjoin-funasr.service" "StandardOutput=null" "funasr unit does not journald-persist stdout (finding 3: spoken-transcript retention)"
assert_contains "$WORK/setjoin-funasr.service" "StandardError=journal" "funasr unit still journals stderr (crash diagnostics)"

FUNASR_GPU_ARGS="--device nvidia.com/gpu=all" render_funasr_unit "$FUNASR_UNIT_TMPL" "$WORK/setjoin-funasr-gpu.service"
assert_contains "$WORK/setjoin-funasr-gpu.service" "--device nvidia.com/gpu=all" "funasr unit FUNASR_GPU_ARGS honors an override"

unset CONTAINER_BIN
if render_funasr_unit "$FUNASR_UNIT_TMPL" "$WORK/should-not-exist-6.service" 2>"$WORK/err6.txt"; then
  printf 'FAIL - %s\n' "render_funasr_unit must fail when CONTAINER_BIN is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_funasr_unit fails loud on missing CONTAINER_BIN"
fi
export CONTAINER_BIN="/usr/bin/podman"

# A CHANGEME-pin-at-deploy sentinel (the honest fallback the plan allows
# when a real digest can't be fetched) must never be rendered into a unit
# that would pull an unpinned image — the never-a-silent-unpinned-pull
# posture, machine-checked, not just asserted in the honesty ledger prose.
_FUNASR_IMAGE_REAL="$FUNASR_IMAGE"
FUNASR_IMAGE="CHANGEME-pin-at-deploy"
if render_funasr_unit "$FUNASR_UNIT_TMPL" "$WORK/should-not-exist-7.service" 2>"$WORK/err7.txt"; then
  printf 'FAIL - %s\n' "render_funasr_unit must fail when FUNASR_IMAGE is a CHANGEME sentinel"
  fail=1
else
  printf 'ok   - %s\n' "render_funasr_unit fails loud on an unpinned (CHANGEME) FUNASR_IMAGE"
fi
FUNASR_IMAGE="$_FUNASR_IMAGE_REAL"

# ── Case 11: asrbot.env.template renders LIVEKIT_URL/FUNASR_URL/ASR_LISTEN/
#    ASR_TOKEN/ASR_MAX_MEETINGS/ASR_MAX_ACTIVE_TRACKS, defaults correctly,
#    honors an override, and REFUSES a non-loopback ASR_LISTEN (asrbot's own
#    bot.ValidateLoopback check, caught a layer earlier at install time) and
#    a missing ASR_TOKEN (finding 1, asrbot's own bot.ValidateToken check,
#    caught a layer earlier too) ─────────────────────────────────────────
export LIVEKIT_URL="ws://127.0.0.1:7880"
export ASR_TOKEN="test-asr-token"
unset FUNASR_URL ASR_LISTEN ASR_MAX_MEETINGS ASR_MAX_ACTIVE_TRACKS 2>/dev/null || true
render_asrbot_env "$ASRBOT_ENV_TMPL" "$WORK/asrbot.env"
assert_contains "$WORK/asrbot.env" "LIVEKIT_URL=ws://127.0.0.1:7880" "asrbot.env substitutes LIVEKIT_URL"
assert_contains "$WORK/asrbot.env" "FUNASR_URL=ws://127.0.0.1:10096" "asrbot.env defaults FUNASR_URL"
assert_contains "$WORK/asrbot.env" "ASR_LISTEN=127.0.0.1:7890" "asrbot.env defaults ASR_LISTEN to loopback"
assert_contains "$WORK/asrbot.env" "ASR_TOKEN=test-asr-token" "asrbot.env substitutes ASR_TOKEN (finding 1)"
assert_contains "$WORK/asrbot.env" "ASR_MAX_MEETINGS=2" "asrbot.env defaults ASR_MAX_MEETINGS"
assert_contains "$WORK/asrbot.env" "ASR_MAX_ACTIVE_TRACKS=4" "asrbot.env defaults ASR_MAX_ACTIVE_TRACKS"
assert_not_contains "$WORK/asrbot.env" "{{" "no leftover {{...}} placeholders (asrbot.env)"

ASR_MAX_MEETINGS=5 ASR_MAX_ACTIVE_TRACKS=8 LIVEKIT_URL="ws://127.0.0.1:7880" ASR_TOKEN="test-asr-token" \
  render_asrbot_env "$ASRBOT_ENV_TMPL" "$WORK/asrbot-override.env"
assert_contains "$WORK/asrbot-override.env" "ASR_MAX_MEETINGS=5" "asrbot.env ASR_MAX_MEETINGS honors an override"
assert_contains "$WORK/asrbot-override.env" "ASR_MAX_ACTIVE_TRACKS=8" "asrbot.env ASR_MAX_ACTIVE_TRACKS honors an override"

unset LIVEKIT_URL
if render_asrbot_env "$ASRBOT_ENV_TMPL" "$WORK/should-not-exist-8.env" 2>"$WORK/err8.txt"; then
  printf 'FAIL - %s\n' "render_asrbot_env must fail when LIVEKIT_URL is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_asrbot_env fails loud on missing LIVEKIT_URL"
fi
export LIVEKIT_URL="ws://127.0.0.1:7880"

if ASR_LISTEN="0.0.0.0:7890" render_asrbot_env "$ASRBOT_ENV_TMPL" "$WORK/should-not-exist-9.env" 2>"$WORK/err9.txt"; then
  printf 'FAIL - %s\n' "render_asrbot_env must refuse a non-loopback ASR_LISTEN"
  fail=1
else
  printf 'ok   - %s\n' "render_asrbot_env refuses a non-loopback ASR_LISTEN (0.0.0.0)"
fi

unset ASR_TOKEN
if render_asrbot_env "$ASRBOT_ENV_TMPL" "$WORK/should-not-exist-10.env" 2>"$WORK/err10.txt"; then
  printf 'FAIL - %s\n' "render_asrbot_env must fail when ASR_TOKEN is unset (finding 1)"
  fail=1
else
  printf 'ok   - %s\n' "render_asrbot_env fails loud on missing ASR_TOKEN (finding 1)"
fi
export ASR_TOKEN="test-asr-token"

# ── Case 12: the 25bef473 lesson, extended to the two Task 16 units ────────
assert_unit_section_has_startlimit "$WORK/setjoin-asr-bot.service" "setjoin-asr-bot.service: StartLimit* lives in [Unit] (rendered)"
assert_unit_section_has_startlimit "$WORK/setjoin-funasr.service" "setjoin-funasr.service: StartLimit* lives in [Unit] (rendered)"
if unit_section "$WORK/setjoin-asr-bot.service" '[Service]' | grep -q '^StartLimitBurst='; then
  printf 'FAIL - %s\n' "setjoin-asr-bot.service: StartLimitBurst must not also appear under [Service]"
  fail=1
else
  printf 'ok   - %s\n' "setjoin-asr-bot.service: no dead StartLimitBurst under [Service]"
fi

# ── Case 13: render_mailserver_unit (arch review #A11 — converges the
#    bespoke sed-rewritten mailserver.service onto this seam) ──────────────
export INSTALL_DIR="/opt/setjoin"
export DATA_DIR="/var/lib/setjoin"
export CONFIG_ENV="/etc/setjoin/config.env"
# Privileged DB credential file (DEPLOY-004 split) — required renderer input.
export DB_CREDENTIALS_FILE="/etc/setjoin/db-credentials.d/db-credentials.env"
render_mailserver_unit "$MAILSERVER_UNIT_TMPL" "$WORK/mailserver.service"
assert_contains "$WORK/mailserver.service" "WorkingDirectory=/opt/setjoin/current" "mailserver unit points at immutable current (WorkingDirectory)"
assert_contains "$WORK/mailserver.service" "ExecStart=/opt/setjoin/current/mailserverd" "mailserver unit points at immutable current (ExecStart)"
assert_contains "$WORK/mailserver.service" "ReadWritePaths=/var/lib/setjoin /tmp" "mailserver unit exposes only mutable data paths"
assert_contains "$WORK/mailserver.service" "EnvironmentFile=/etc/setjoin/config.env" "mailserver unit substitutes CONFIG_ENV (EnvironmentFile)"
assert_contains "$WORK/mailserver.service" "EnvironmentFile=/etc/setjoin/db-credentials.d/db-credentials.env" "mailserver unit substitutes DB_CREDENTIALS_FILE (privileged-DSN split)"
assert_contains "$WORK/mailserver.service" "Environment=CONFIG_PATH=/etc/setjoin/config.env" "mailserver unit substitutes CONFIG_ENV (CONFIG_PATH)"
assert_contains "$WORK/mailserver.service" "Environment=WEBSITE_DIR=/opt/setjoin/current/webmail" "mailserver unit points webmail at immutable current"
assert_contains "$WORK/mailserver.service" "User=setjoin" "mailserver unit defaults USER to setjoin"
assert_contains "$WORK/mailserver.service" "Group=setjoin" "mailserver unit defaults GROUP to setjoin"
assert_not_contains "$WORK/mailserver.service" "{{" "no leftover {{...}} placeholders (mailserver.service)"
assert_unit_section_has_startlimit "$WORK/mailserver.service" "mailserver.service: StartLimit* lives in [Unit] (rendered)"
# Order-sensitivity (DEPLOY-004): the credential file is read AFTER config.env.
_ms_cfg_line="$(grep -n '^EnvironmentFile=/etc/setjoin/config.env$' "$WORK/mailserver.service" | cut -d: -f1)"
_ms_cred_line="$(grep -n '^EnvironmentFile=/etc/setjoin/db-credentials.d/db-credentials.env$' "$WORK/mailserver.service" | cut -d: -f1)"
if [ -n "$_ms_cfg_line" ] && [ -n "$_ms_cred_line" ] && [ "$_ms_cfg_line" -lt "$_ms_cred_line" ]; then
  printf 'ok   - %s\n' "mailserver unit: credential file's EnvironmentFile follows config.env's (later wins)"
else
  printf 'FAIL - %s (cfg_line=%s cred_line=%s)\n' "mailserver unit: credential file's EnvironmentFile follows config.env's" "$_ms_cfg_line" "$_ms_cred_line"
  fail=1
fi

for _var in INSTALL_DIR DATA_DIR CONFIG_ENV DB_CREDENTIALS_FILE; do
  _saved="$(eval "echo \${$_var}")"
  unset "$_var"
  if render_mailserver_unit "$MAILSERVER_UNIT_TMPL" "$WORK/should-not-exist-11-$_var.service" 2>"$WORK/err11-$_var.txt"; then
    printf 'FAIL - %s\n' "render_mailserver_unit must fail when $_var is unset"
    fail=1
  else
    printf 'ok   - %s\n' "render_mailserver_unit fails loud on missing $_var"
  fi
  export "$_var=$_saved"
done

# ── Case 14: render_authserver_unit — Rust setjoin-auth (#359b) ──
export AUTH_ENV="/etc/setjoin/auth.env"
render_authserver_unit "$AUTHSERVER_UNIT_TMPL" "$WORK/authserver.service"
assert_contains "$WORK/authserver.service" "WorkingDirectory=/opt/setjoin/current" "auth unit points at immutable current (WorkingDirectory)"
assert_contains "$WORK/authserver.service" "ExecStart=/opt/setjoin/current/setjoin-auth" "auth unit runs the Rust setjoin-auth from immutable current"
assert_contains "$WORK/authserver.service" "ReadWritePaths=/tmp" "auth unit cannot write the immutable release"
assert_contains "$WORK/authserver.service" "EnvironmentFile=/etc/setjoin/config.env" "auth unit substitutes CONFIG_ENV"
assert_contains "$WORK/authserver.service" "EnvironmentFile=/etc/setjoin/auth.env" "auth unit substitutes AUTH_ENV"
assert_not_contains "$WORK/authserver.service" "db-credentials" "Rust auth unit never loads the privileged credential file (F6)"
assert_contains "$WORK/authserver.service" "Wants=postgresql.service setjoin-authserverd.service" "setjoin-auth pulls authserverd"
assert_not_contains "$WORK/authserver.service" "After=network.target postgresql.service setjoin-authserverd" "no ordering against authserverd (F3)"
assert_not_contains "$WORK/authserver.service" "systemctl stop setjoin-authserverd" "no explicit stop of authserverd: it would replace the restart job (N8)"
assert_contains "$WORK/authserver.service" "ExecStopPost=+/bin/sh -c 'i=0; while" "ExecStopPost holds the deactivation (F3)"
assert_contains "$WORK/authserver.service" 'ActiveState --value setjoin-authserverd.service)" = deactivating' "while authserverd is still deactivating"
assert_contains "$WORK/authserver.service" '${AUTHSERVER_GO_UPSTREAM}/health' "readiness reaches authserverd (F7)"
assert_contains "$WORK/authserver.service" '/_setjoin/readiness")" = 404 ]' "readiness requires Go's 404 through setjoin-auth (N1)"
assert_not_contains "$WORK/authserver.service" "auth/login" "readiness sends no credential request (N1)"
assert_contains "$WORK/authserver.service" "User=setjoin" "auth unit defaults USER to setjoin"
assert_contains "$WORK/authserver.service" "Group=setjoin" "auth unit defaults GROUP to setjoin"
assert_not_contains "$WORK/authserver.service" "{{" "no leftover {{...}} placeholders (authserver.service)"
assert_unit_section_has_startlimit "$WORK/authserver.service" "authserver.service: StartLimit* lives in [Unit] (rendered)"
_cfg_line="$(grep -n '^EnvironmentFile=/etc/setjoin/config.env$' "$WORK/authserver.service" | cut -d: -f1)"
_auth_line="$(grep -n '^EnvironmentFile=/etc/setjoin/auth.env$' "$WORK/authserver.service" | cut -d: -f1)"
if [ -n "$_cfg_line" ] && [ -n "$_auth_line" ] && [ "$_cfg_line" -lt "$_auth_line" ]; then
  printf 'ok   - %s\n' "auth unit: config.env < auth.env (later wins)"
else
  printf 'FAIL - %s (cfg_line=%s auth_line=%s)\n' "auth unit: config.env < auth.env" "$_cfg_line" "$_auth_line"
  fail=1
fi
for _var in INSTALL_DIR CONFIG_ENV AUTH_ENV; do
  _saved="$(eval "echo \${$_var}")"
  unset "$_var"
  if render_authserver_unit "$AUTHSERVER_UNIT_TMPL" "$WORK/should-not-exist-12-$_var.service" 2>"$WORK/err12-$_var.txt"; then
    printf 'FAIL - %s\n' "render_authserver_unit must fail when $_var is unset"
    fail=1
  else
    printf 'ok   - %s\n' "render_authserver_unit fails loud on missing $_var"
  fi
  export "$_var=$_saved"
done

# ── Case 14b: render_authserverd_unit — transitional Go authserverd (#359b) ──
export AUTHSERVERD_ENV="/etc/setjoin/authserverd.env"
render_authserverd_unit "$SCRIPT_DIR/../setjoin-authserverd.service.template" "$WORK/setjoin-authserverd.service"
assert_contains "$WORK/setjoin-authserverd.service" "ExecStart=/opt/setjoin/current/authserverd" "authserverd unit runs immutable current"
assert_contains "$WORK/setjoin-authserverd.service" "PartOf=setjoin-auth.service" "authserverd follows setjoin-auth's stop/restart"
assert_contains "$WORK/setjoin-authserverd.service" "BindsTo=setjoin-auth.service" "authserverd never runs without setjoin-auth (N2)"
assert_not_contains "$WORK/setjoin-authserverd.service" "Before=setjoin-auth" "no ordering against setjoin-auth (F3)"
assert_not_contains "$WORK/setjoin-authserverd.service" "After=network.target postgresql.service setjoin-auth" "no ordering against setjoin-auth (F3)"
assert_contains "$WORK/setjoin-authserverd.service" "EnvironmentFile=/etc/setjoin/db-credentials.d/db-credentials.env" "authserverd keeps the worker tier (identity_links)"
assert_contains "$WORK/setjoin-authserverd.service" "EnvironmentFile=/etc/setjoin/authserverd.env" "authserverd unit substitutes AUTHSERVERD_ENV"
assert_not_contains "$WORK/setjoin-authserverd.service" "[Install]" "authserverd is pulled by setjoin-auth, never enabled alone"
assert_not_contains "$WORK/setjoin-authserverd.service" "{{" "no leftover {{...}} placeholders (setjoin-authserverd.service)"
assert_unit_section_has_startlimit "$WORK/setjoin-authserverd.service" "setjoin-authserverd.service: StartLimit* lives in [Unit] (rendered)"
_cfg_line="$(grep -n '^EnvironmentFile=/etc/setjoin/config.env$' "$WORK/setjoin-authserverd.service" | cut -d: -f1)"
_cred_line="$(grep -n '^EnvironmentFile=/etc/setjoin/db-credentials.d/db-credentials.env$' "$WORK/setjoin-authserverd.service" | cut -d: -f1)"
_own_line="$(grep -n '^EnvironmentFile=/etc/setjoin/authserverd.env$' "$WORK/setjoin-authserverd.service" | cut -d: -f1)"
if [ -n "$_cfg_line" ] && [ -n "$_cred_line" ] && [ -n "$_own_line" ] \
   && [ "$_cfg_line" -lt "$_cred_line" ] && [ "$_cred_line" -lt "$_own_line" ]; then
  printf 'ok   - %s\n' "authserverd unit: config.env < db-credentials < authserverd.env"
else
  printf 'FAIL - %s\n' "authserverd unit: config.env < db-credentials < authserverd.env"; fail=1
fi
for _var in INSTALL_DIR CONFIG_ENV AUTHSERVERD_ENV DB_CREDENTIALS_FILE; do
  _saved="$(eval "echo \${$_var}")"
  unset "$_var"
  if render_authserverd_unit "$SCRIPT_DIR/../setjoin-authserverd.service.template" "$WORK/should-not-exist-14b-$_var.service" 2>/dev/null; then
    printf 'FAIL - %s\n' "render_authserverd_unit must fail when $_var is unset"; fail=1
  else
    printf 'ok   - %s\n' "render_authserverd_unit fails loud on missing $_var"
  fi
  export "$_var=$_saved"
done

# ── Case 15: render_sfu_unit — INSTALL_DIR + LIVEKIT_YAML (default + override) ──
render_sfu_unit "$SFU_UNIT_TMPL" "$WORK/setjoin-sfu.service"
assert_contains "$WORK/setjoin-sfu.service" "WorkingDirectory=/opt/setjoin" "sfu unit substitutes INSTALL_DIR (WorkingDirectory)"
assert_contains "$WORK/setjoin-sfu.service" "ExecStart=/opt/setjoin/bin/livekit-server --config /etc/setjoin/livekit.yaml" "sfu unit substitutes INSTALL_DIR + defaults LIVEKIT_YAML"
assert_contains "$WORK/setjoin-sfu.service" "User=setjoin" "sfu unit defaults USER to setjoin"
assert_contains "$WORK/setjoin-sfu.service" "Group=setjoin" "sfu unit defaults GROUP to setjoin"
assert_contains "$WORK/setjoin-sfu.service" "AF_NETLINK" "sfu unit preserves the AF_NETLINK fix (netlink RIB, 2026-07-16 fresh-VM gate)"
assert_not_contains "$WORK/setjoin-sfu.service" "{{" "no leftover {{...}} placeholders (setjoin-sfu.service)"
assert_unit_section_has_startlimit "$WORK/setjoin-sfu.service" "setjoin-sfu.service: StartLimit* lives in [Unit] (rendered)"

LIVEKIT_YAML="/custom/path/livekit.yaml" render_sfu_unit "$SFU_UNIT_TMPL" "$WORK/setjoin-sfu-override.service"
assert_contains "$WORK/setjoin-sfu-override.service" "--config /custom/path/livekit.yaml" "sfu unit LIVEKIT_YAML honors an override"

_saved="$INSTALL_DIR"; unset INSTALL_DIR
if render_sfu_unit "$SFU_UNIT_TMPL" "$WORK/should-not-exist-13.service" 2>"$WORK/err13.txt"; then
  printf 'FAIL - %s\n' "render_sfu_unit must fail when INSTALL_DIR is unset"
  fail=1
else
  printf 'ok   - %s\n' "render_sfu_unit fails loud on missing INSTALL_DIR"
fi
export INSTALL_DIR="$_saved"

# ── Case 16: render_valkey_unit — User/Group only; the config path is
#    DELIBERATELY never a token (the "valkey no-path-rewrite" fact) ────────
render_valkey_unit "$VALKEY_UNIT_TMPL" "$WORK/setjoin-valkey.service"
assert_contains "$WORK/setjoin-valkey.service" "User=setjoin" "valkey unit defaults USER to setjoin"
assert_contains "$WORK/setjoin-valkey.service" "Group=setjoin" "valkey unit defaults GROUP to setjoin"
assert_contains "$WORK/setjoin-valkey.service" "ExecStart=/usr/bin/valkey-server /etc/setjoin/valkey.conf" "valkey unit's config path stays hardcoded (no-path-rewrite fact preserved)"
assert_not_contains "$WORK/setjoin-valkey.service" "{{" "no leftover {{...}} placeholders (setjoin-valkey.service)"
assert_unit_section_has_startlimit "$WORK/setjoin-valkey.service" "setjoin-valkey.service: StartLimit* lives in [Unit] (rendered)"

# Installer ownership boundary: operator-managed files may coexist under
# /etc/setjoin. Recursively chowning CONFIG_DIR broke SeaweedFS credentials on
# the real Ubuntu deployment only after the container restarted.
if grep -qF 'chown -R setjoin:setjoin "$INSTALL_DIR" "$DATA_DIR" "$CONFIG_DIR"' "$INSTALL_SCRIPT"; then
  printf 'FAIL - %s\n' "installer must not recursively chown CONFIG_DIR"
  fail=1
else
  printf 'ok   - %s\n' "installer preserves operator-managed CONFIG_DIR file ownership"
fi

if [ "$fail" = "0" ]; then
  echo "PASS: test-livekit-render.sh"
else
  echo "FAIL: test-livekit-render.sh (see above)" >&2
  exit 1
fi
