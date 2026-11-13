#!/usr/bin/env bash
set -euo pipefail

# Render/posture check for mailserver/deploy/failover.sh.template.
#
# The template is what gets INSTALLED as /etc/pgpool2/failover.sh — the wizard
# deploys an embedded byte-identical copy during configurePgpool (pinned by
# TestWizardFailoverScript_MatchesShippedTemplate), and install.sh's opt-in HA
# leg installs the template file itself — so this test owns what a template
# regression could silently break:
#   1. the script stays bash-syntax-clean and shellcheck-clean;
#   2. it is static — no unrendered {{ PLACEHOLDER }} markers;
#   3. the failover SSH runs fail-closed toward the pgpool-supplied %H host:
#      StrictHostKeyChecking=yes with BOTH known-hosts stores pinned to the
#      pre-provisioned /etc/pgpool2/known_hosts, BatchMode=yes so no prompt
#      can hang the unattended failover, ConnectTimeout retained, and both
#      promote branches log failure and exit nonzero;
#   4. the wizard-embedded pgpool config delegates failover to the same strict
#      /etc/pgpool2/failover.sh and never inlines its own ssh command.
# See D-MAILSERVER-DEPLOY-002 (med-deploy-ssh-host-identity-b1r2-002).

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TEMPLATE="$ROOT/mailserver/deploy/failover.sh.template"
WIZARD="$ROOT/mailserver/internal/deploy/wizard.go"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1a. Syntax gate.
bash -n "$TEMPLATE"

# 1b. Lint gate: required where shellcheck exists, skipped with a notice
#     otherwise (the lane convention "shellcheck clean" is owned by the
#     developer/CI environment, like the optional deep-parse checks in the
#     other render tests).
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$TEMPLATE"
else
  echo "failover template render: shellcheck unavailable; syntax checks only"
fi

# Executable lines only, so a policy mentioned in a comment cannot satisfy
# the posture checks below.
executable="$tmp/executable-lines.txt"
grep -v '^[[:space:]]*#' "$TEMPLATE" >"$executable"

require() {
  local desc="$1" pattern="$2"
  if ! grep -Fq -- "$pattern" "$executable"; then
    echo "failover template render: missing required pattern ($desc): $pattern" >&2
    exit 1
  fi
}

forbid() {
  local desc="$1" pattern="$2"
  if grep -Fq -- "$pattern" "$executable"; then
    echo "failover template render: forbidden pattern present ($desc): $pattern" >&2
    grep -n -- "$pattern" "$TEMPLATE" >&2 || true
    exit 1
  fi
}

# 2. Static script: no template placeholders.
if grep -q '{{' "$TEMPLATE"; then
  echo "failover template render: unresolved {{ PLACEHOLDER }} in static script" >&2
  exit 1
fi

# 3. Fail-closed host-identity policy on the pgpool-supplied %H host.
require 'strict host key checking' 'StrictHostKeyChecking=yes'
forbid 'host key checking disabled' 'StrictHostKeyChecking=no'
forbid 'TOFU/accept-new policy' 'accept-new'
require 'pre-provisioned trust anchor' 'KNOWN_HOSTS="/etc/pgpool2/known_hosts"'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'user known_hosts pinned to anchor' 'UserKnownHostsFile="$KNOWN_HOSTS"'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'global known_hosts pinned to anchor' 'GlobalKnownHostsFile="$KNOWN_HOSTS"'
require 'non-interactive ssh' 'BatchMode=yes'
require 'connect timeout retained' 'ConnectTimeout=5'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'remote promote target' '"root@$NEW_HOST"'
# shellcheck disable=SC2016  # literal $-pattern grep
require 'remote promote command' '"$PGCTL promote -D $PGDATA"'

# Both promote branches must log failure and exit nonzero, so a refused host
# key is recorded and pgpool does not treat the failover as done.
require 'local failure logged' 'Promote FAILED'
require 'remote failure logged' 'Remote promote FAILED'
if [ "$(grep -c 'exit 1' "$executable")" -lt 2 ]; then
  echo "failover template render: both promote branches must exit nonzero" >&2
  exit 1
fi

# 4. Wizard-embedded pgpool config stays on the identical policy: it delegates
#    failover to the strict script and inlines no ssh command of its own. The
#    check is scoped to the pgpoolConfigTemplate variable: the wizard also
#    embeds the failover script itself (wizardFailoverScript — the strict
#    policy owner it installs, pinned byte-identical to this template by
#    TestWizardFailoverScript_MatchesShippedTemplate), which legitimately
#    contains the ssh invocation.
if ! grep -Fq "failover_command = '/etc/pgpool2/failover.sh %d %P %H %R'" "$WIZARD"; then
  echo "failover template render: wizard.go failover_command no longer delegates to /etc/pgpool2/failover.sh" >&2
  exit 1
fi
sed -n '/^var pgpoolConfigTemplate = /,/^`$/p' "$WIZARD" >"$tmp/wizard-pgpool-template.txt"
if ! grep -q '^var pgpoolConfigTemplate' "$tmp/wizard-pgpool-template.txt"; then
  echo "failover template render: could not extract pgpoolConfigTemplate from $WIZARD" >&2
  exit 1
fi
if grep -Eq 'ssh |StrictHostKeyChecking' "$tmp/wizard-pgpool-template.txt"; then
  echo "failover template render: pgpoolConfigTemplate embeds an ssh command or host-key override; policy must live in /etc/pgpool2/failover.sh" >&2
  grep -nE 'ssh |StrictHostKeyChecking' "$tmp/wizard-pgpool-template.txt" >&2 || true
  exit 1
fi

echo "failover template render: PASS"
