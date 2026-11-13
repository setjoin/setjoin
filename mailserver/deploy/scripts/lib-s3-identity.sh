#!/usr/bin/env bash
# S3 admin-identity credential admission (sourced by install.sh; exercised
# behaviourally by mailserver/deploy/scripts/test-install-provision-render.sh).
#
# WHY THIS EXISTS. install.sh renders /etc/setjoin/seaweedfs-s3.json — the
# SeaweedFS -s3.config admin identity the deployment loads. Booting an
# authenticatable-as-anyone S3 gateway is a real incident, so the installer
# refuses known-weak material BEFORE the file a deployment loads can exist.
#
# WHAT IT REFUSES, and why each rule is here:
#   1. empty material — nothing to render.
#   2. whole known-weak VALUES (vendor default minioadmin/minioadmin12345 and
#      the usual placeholders). Matched as whole values, NOT substrings: a
#      generated 32-char secret that happens to contain "changeme" is
#      unguessable and must install.
#   3. REPEATED-PATTERN values (changemechangeme..., minioadminminioadmin...).
#      These clear the whole-value lists and any length floor while being no
#      more random than the placeholder they repeat — the case rule 2 alone
#      cannot see.
#   4. a length floor (user >= 12, secret >= 24). MinIO's bare minimums (3/8)
#      are far too weak to be the only bound. Length alone is not entropy; it
#      is the backstop for rule 3.
#
# ROTATION. `install.sh --force` re-asks S3_ACCESS_KEY/S3_SECRET_KEY and
# rewrites seaweedfs-s3.json with the new pair in the same run; restart the
# SeaweedFS container/service afterwards. In NONINTERACTIVE mode --force keeps
# the existing values (it will not silently rotate), so a non-interactive
# operator must rotate the values themselves before re-running.

# True when $1 is a short token repeated to fill the whole string (e.g.
# "changemechangeme", "minioadminminioadmin"). Bash-only; no subprocess.
s3_identity_is_repetitive() {
  local v="${1:-}" i j base piece n
  v="${v,,}"
  n=${#v}
  # Periods 1 and 2 included: "aaaa..." and "ababab..." clear every whole-value
  # list and the length floor while being fully predictable.
  # Every period up to n/2: a period cap is a blind spot (period-12 repeats
  # of an 11+ char token clear any cap and every length floor).
  for ((i = 1; i * 2 <= n; i++)); do
    ((n % i == 0)) || continue
    base="${v:0:i}"
    piece="$base"
    for ((j = 1; j < n / i; j++)); do
      piece+="$base"
    done
    [ "$piece" = "$v" ] && return 0
  done
  return 1
}

# s3_identity_admit <access_key> <secret_key>
# Echoes a refusal reason and returns 1 to refuse; returns 0 silently to admit.
s3_identity_admit() {
  local user="${1:-}" pass="${2:-}" user_l pass_l
  user_l="${user,,}"
  pass_l="${pass,,}"

  if [ -z "$user" ] || [ -z "$pass" ]; then
    printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY missing — refusing to render the S3 identity config."
    return 1
  fi

  case "$user_l" in
    minioadmin | minio | minioadmin12345 | admin | root | changeme | change-me | replace_me | replace-me | password | secret | access-key | accesskey | s3)
      printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY is a well-known default credential — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
      return 1
      ;;
  esac
  case "$pass_l" in
    minioadmin | minioadmin12345 | minio | admin | root | changeme | change-me | replace_me | replace-me | password | secret | admin123 | admin1234 | admin12345 | rootroot | 123456 | password123 | secret123 | access-key | accesskey | s3)
      printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY is a well-known default credential — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
      return 1
      ;;
  esac

  # Decorated placeholders: a value that STARTS WITH a known marker
  # ("replace_me_Xk9p...", "changeme-the-real-one", "minioadmin-prod") is a
  # template nobody filled in, not a generated credential. Prefix matching
  # catches that shape exactly, without the character-count heuristic that
  # both mis-fires on real secrets and misses decorated ones.
  # Trim first: leading whitespace defeats prefix anchoring (" changeme…").
  user_l="$(printf '%s' "$user_l" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  pass_l="$(printf '%s' "$pass_l" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$user_l" in
    changeme* | change-me* | replace_me* | replace-me* | minioadmin* | minio-* | password* | secret* | admin* | root* | placeholder* | example* | your-secret* | my-secret* | default*)
      printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY begins with a known placeholder marker — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
      return 1
      ;;
  esac
  case "$pass_l" in
    changeme* | change-me* | replace_me* | replace-me* | minioadmin* | minio-* | password* | secret* | admin* | root* | placeholder* | example* | your-secret* | my-secret* | default*)
      printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY begins with a known placeholder marker — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
      return 1
      ;;
  esac

  # Character-set floor: generated material is hex, so anything carrying
  # quotes/backslashes/control bytes is operator error AND would corrupt the
  # rendered seaweedfs-s3.json (or the config.env round-trip). Fail closed.
  local _re='^[A-Za-z0-9._/@:+=-]+$'
  if [[ ! "$user_l" =~ $_re ]] || [[ ! "$pass_l" =~ $_re ]]; then
    printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY contains characters outside the allowed set ([A-Za-z0-9._/@:+=-]) — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
    return 1
  fi

  if s3_identity_is_repetitive "$user_l" || s3_identity_is_repetitive "$pass_l"; then
    printf '%s\n' "S3_ACCESS_KEY/S3_SECRET_KEY repeats a short pattern (predictable) — refusing to render the S3 identity config. Rotate them (sudo bash install.sh --force) first."
    return 1
  fi

  if [ "${#user}" -lt 12 ]; then
    printf '%s\n' "S3_ACCESS_KEY shorter than 12 characters — refusing to render the S3 identity config. Rotate it: edit S3_ACCESS_KEY in /etc/setjoin/config.env to a >=12-character value, or remove the key so the installer generates one (openssl rand -hex 16). NOTE: --force alone will NOT help in NONINTERACTIVE mode, which keeps existing values."
    return 1
  fi
  if [ "${#pass}" -lt 24 ]; then
    printf '%s\n' "S3_SECRET_KEY shorter than 24 characters — refusing to render the S3 identity config. Rotate it: edit S3_SECRET_KEY in /etc/setjoin/config.env to a >=24-character value, or remove the key so the installer generates one (openssl rand -hex 24). NOTE: --force alone will NOT help in NONINTERACTIVE mode, which keeps existing values."
    return 1
  fi
  return 0
}
