#!/bin/bash
set -euo pipefail
# Setjoin gateway/auth upgrade.
# Usage: ./upgrade.sh /path/to/new/mailserverd [/path/to/new/mailctl] [/path/to/webmail-build] [/path/to/new/authserverd]
#
# The new gateway REFUSES TO START if the database schema is behind the version
# it ships (mailserverd embeds the V<NNN>__*.sql forward migrations). So this
# script applies any pending DB schema migrations BEFORE starting the new binary.
# It applies them with a MATCHING mailctl (same build) — pass the new mailctl as
# arg 2, or have a matching `mailctl` on PATH — so the applied set equals what the
# new gateway expects (a stale mailctl would apply the wrong set). If no matching
# mailctl is available it only CHECKS and warns; the gateway's refuse-to-start +
# the health-check rollback below are the backstop.

INSTALL_DIR="${INSTALL_DIR:-/opt/setjoin}"
if [ -L "$INSTALL_DIR/current" ]; then
    case "${1:-}" in
        status|evidence|activate-previous)
            action="$1"; shift
            exec /usr/libexec/setjoin-recovery "$action" "$@"
            ;;
        *)
            echo "This installation uses the transactional immutable layout; positional artifact-copy upgrades are disabled." >&2
            echo "Use the signed Updates workflow. For recovery only: sudo $0 status | evidence | activate-previous --reason TEXT" >&2
            exit 2
            ;;
    esac
fi

NEW_BIN="${1:-}"
NEW_MAILCTL="${2:-}"
NEW_WEBMAIL="${3:-}"
NEW_AUTH="${4:-}"
# The Rust front door (#264): replaced, backed up as setjoin-gateway.prev and
# restored on rollback exactly like the Go binaries.
NEW_GATEWAY="${5:-}"
if [ ! -f "$NEW_BIN" ]; then
    echo "Usage: $0 /path/to/new/mailserverd [/path/to/new/mailctl] [/path/to/webmail-build] [/path/to/new/authserverd] [/path/to/new/setjoin-gateway]"
    echo "  1. Build: cd mailserver && go build -o mailserverd ./cmd/mailserverd"
    echo "           cd authserver && go build -o authserverd ./cmd/authserverd"
    echo "           cd server-rust && cargo build --release --locked -p setjoin-mailctl   — Rust schema CLI"
    echo "  2. Deploy: scp mailserverd authserverd mailctl user@host:/tmp/ && \\"
    echo "             ssh user@host 'sudo /opt/setjoin/deploy/scripts/upgrade.sh /tmp/mailserverd /tmp/mailctl /tmp/webmail-build /tmp/authserverd'"
    exit 1
fi
if [ -n "$NEW_WEBMAIL" ] && [ ! -f "$NEW_WEBMAIL/index.html" ]; then
    echo "Webmail build must be a directory containing index.html: $NEW_WEBMAIL"
    exit 1
fi
if [ -n "$NEW_AUTH" ] && [ ! -f "$NEW_AUTH" ]; then
    echo "Authserver binary does not exist: $NEW_AUTH"
    exit 1
fi
if [ -n "$NEW_GATEWAY" ] && [ ! -f "$NEW_GATEWAY" ]; then
    echo "Gateway binary does not exist: $NEW_GATEWAY"
    exit 1
fi

CONFIG_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/config.env"
AUTH_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/auth.env"
# Privileged DB credential tier (DEPLOY-004 split): the owner keys moved out of
# config.env into this root-owned 0600 file below the root-owned config dir.
DB_CRED_FILE="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/db-credentials.d/db-credentials.env"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
GATEWAY_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/gateway.env"
FEDERATION_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/federation.env"
TLS_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/tls.env"
SMTP_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/smtp.env"
source "$(dirname "${BASH_SOURCE[0]}")/lib-livekit.sh"
DEPLOYMENT_PREV="$INSTALL_DIR/federation-deploy.prev"
HAD_WEBMAIL=0
AUTH_WAS_ACTIVE=0

# The descriptor set is part of the release: older gateways cannot consume
# the federation FD. Keep absence as well as bytes/modes for whole-release rollback.
backup_gateway_deployment() {
    local file
    [ ! -L "$DEPLOYMENT_PREV" ] || return 1
    rm -rf "$DEPLOYMENT_PREV"
    ( umask 077; mkdir -p "$DEPLOYMENT_PREV/units" "$DEPLOYMENT_PREV/config" )
    for file in setjoin-gateway.service setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -e "$SYSTEMD_DIR/$file" ] || [ -L "$SYSTEMD_DIR/$file" ]; then
            cp -a "$SYSTEMD_DIR/$file" "$DEPLOYMENT_PREV/units/"
        fi
    done
    for file in config.env gateway.env federation.env tls.env smtp.env; do
        if [ -e "${CONFIG_ENV%/*}/$file" ]; then
            cp -a "${CONFIG_ENV%/*}/$file" "$DEPLOYMENT_PREV/config/"
        fi
    done
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -e "$SYSTEMD_DIR/$file" ]; then
            systemctl is-active --quiet "$file" && touch "$DEPLOYMENT_PREV/$file-active" || true
            systemctl is-enabled --quiet "$file" && touch "$DEPLOYMENT_PREV/$file-enabled" || true
        fi
    done
    if [ -e "$SYSTEMD_DIR/setjoin-federation.socket" ]; then
        systemctl is-active --quiet setjoin-federation.socket && touch "$DEPLOYMENT_PREV/socket-active" || true
        systemctl is-enabled --quiet setjoin-federation.socket && touch "$DEPLOYMENT_PREV/socket-enabled" || true
    fi
}
restore_gateway_deployment() {
    local file
    # Close the new socket before the previous executable can receive its FD.
    systemctl stop setjoin-gateway || true
    systemctl stop setjoin-federation.socket || true
    systemctl disable setjoin-federation.socket || true
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        systemctl stop "$file" || true
        systemctl disable "$file" || true
    done
    for file in setjoin-gateway.service setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        rm -f "$SYSTEMD_DIR/$file"
        if [ -e "$DEPLOYMENT_PREV/units/$file" ] || [ -L "$DEPLOYMENT_PREV/units/$file" ]; then
            cp -a "$DEPLOYMENT_PREV/units/$file" "$SYSTEMD_DIR/"
        fi
    done
    for file in config.env gateway.env federation.env tls.env smtp.env; do
        rm -f "${CONFIG_ENV%/*}/$file"
        if [ -e "$DEPLOYMENT_PREV/config/$file" ]; then
            cp -a "$DEPLOYMENT_PREV/config/$file" "${CONFIG_ENV%/*}/"
        fi
    done
    systemctl daemon-reload
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -f "$DEPLOYMENT_PREV/$file-enabled" ]; then systemctl enable "$file"; fi
        if [ -f "$DEPLOYMENT_PREV/$file-active" ]; then systemctl start "$file"; fi
    done
    if [ -f "$DEPLOYMENT_PREV/socket-enabled" ]; then systemctl enable setjoin-federation.socket; fi
    if [ -f "$DEPLOYMENT_PREV/socket-active" ]; then systemctl start setjoin-federation.socket; fi
}

# Read literal installer EnvironmentFile assignments, without evaluating secrets.
config_value() {
    sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1 || true
}
render_gateway_deployment() (
    local root key names file tmp
    root="$(cd "$(dirname "$0")/../../.." && pwd)"
    source "$root/mailserver/deploy/scripts/lib-livekit.sh" || return 1
    # This is the legacy flat layout. Immutable installations use signed Updates.
    RUNTIME_DIR="$INSTALL_DIR"
    AUTHSERVER_URL="$(config_value "$CONFIG_ENV" AUTHSERVER_URL)"
    AUTHSERVER_URL="${AUTHSERVER_URL:-http://127.0.0.1:8443}"
    GATEWAY_LISTEN="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
    GATEWAY_UPSTREAM="$(config_value "$GATEWAY_ENV" GATEWAY_UPSTREAM)"
    GATEWAY_TRUSTED_PROXIES="$(config_value "$GATEWAY_ENV" GATEWAY_TRUSTED_PROXIES)"
    FEDERATION_ENABLED="$(config_value "$CONFIG_ENV" FEDERATION_ENABLED)"
    FEDERATION_LISTEN_ADDR="$(config_value "$CONFIG_ENV" FEDERATION_LISTEN_ADDR)"
    # Older configs may have the static gate without the installer-only marker.
    if [ -n "$(config_value "$CONFIG_ENV" FEDERATION_LOCAL_DOMAIN)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_CERT)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_KEY)" ]; then
        FEDERATION_ENABLED=true
    fi
    for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
        names="$(config_value "$CONFIG_ENV" "$key")"
        if [ "$key" = GO_WORKERS_OFF ]; then
            for file in federation-service federation-residue-reap; do
                case ",$names," in *,$file,*) ;; *) names="${names:+$names,}$file" ;; esac
            done
        else
            case ",$names," in *,federation-residue-reap,*) ;; *) names="${names:+$names,}federation-residue-reap" ;; esac
        fi
        tmp="$(mktemp "${CONFIG_ENV}.XXXXXX")" || return 1
        grep -v "^$key=" "$CONFIG_ENV" > "$tmp" || true
        printf '%s=%s\n' "$key" "$names" >> "$tmp"
        # Keep the existing config's owner and mode.
        cat "$tmp" > "$CONFIG_ENV" || return 1
        rm -f "$tmp"
    done
    configure_tls_front "$CONFIG_ENV" || return 1
    configure_imap_front "$CONFIG_ENV" || return 1
    configure_smtp_front "$CONFIG_ENV" || return 1
    render_tls_front_env "$TLS_ENV" "$CONFIG_ENV" || return 1
    chown root:setjoin "$TLS_ENV" || return 1
    # A descriptor belongs to the matching new binary. Recreate only this
    # release's socket set; snapshots preserve prior bytes, absence and state.
    rm -f "$SYSTEMD_DIR/setjoin-https.socket" "$SYSTEMD_DIR/setjoin-acme.socket" "$SYSTEMD_DIR/setjoin-imap.socket" "$SYSTEMD_DIR/setjoin-imaps.socket" "$SYSTEMD_DIR/setjoin-smtp.socket" "$SYSTEMD_DIR/setjoin-smtps.socket" "$SYSTEMD_DIR/setjoin-submission.socket"
    render_gateway_env "$GATEWAY_ENV" || return 1
    render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$FEDERATION_ENV" || return 1
    # SMTP (#501): its own allow-listed file, re-rendered with the unit set.
    render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$SMTP_ENV" || return 1
    render_gateway_unit "$root/mailserver/deploy/setjoin-gateway.service.template" "$SYSTEMD_DIR/setjoin-gateway.service" || return 1
    systemctl daemon-reload || return 1
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -f "$SYSTEMD_DIR/$file" ]; then systemctl enable "$file" || return 1; fi
    done
    if [ "${FEDERATION_ENABLED:-false}" = true ]; then
        systemctl enable setjoin-federation.socket || return 1
    fi
)

if [ -n "$NEW_GATEWAY" ]; then
    backup_gateway_deployment
fi

echo "=== Mailserver Upgrade ==="
echo "1. Stopping gateway..."
if [ -n "$NEW_GATEWAY" ]; then
    # Stop the front door before changing its upstreams or descriptor set.
    systemctl stop setjoin-gateway
    systemctl stop setjoin-federation.socket || true
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        systemctl stop "$file" || true
        systemctl disable "$file" || true
    done
fi
systemctl stop setjoin
if [ -n "$NEW_AUTH" ]; then
    if systemctl is-active --quiet setjoin-auth; then
        AUTH_WAS_ACTIVE=1
    fi
    systemctl stop setjoin-auth
fi

echo "2. Backing up current binaries..."
cp "$INSTALL_DIR/mailserverd" "$INSTALL_DIR/mailserverd.prev"
[ -f "$INSTALL_DIR/mailctl" ] && cp "$INSTALL_DIR/mailctl" "$INSTALL_DIR/mailctl.prev" || true
if [ -n "$NEW_AUTH" ] && [ -f "$INSTALL_DIR/authserverd" ]; then
    cp "$INSTALL_DIR/authserverd" "$INSTALL_DIR/authserverd.prev"
fi
if [ -n "$NEW_GATEWAY" ] && [ -f "$INSTALL_DIR/setjoin-gateway" ]; then
    cp "$INSTALL_DIR/setjoin-gateway" "$INSTALL_DIR/setjoin-gateway.prev"
fi
if [ -n "$NEW_WEBMAIL" ] && [ -d "$INSTALL_DIR/webmail" ]; then
    HAD_WEBMAIL=1
    rm -rf "$INSTALL_DIR/webmail.prev"
    cp -a "$INSTALL_DIR/webmail" "$INSTALL_DIR/webmail.prev"
fi

echo "3. Installing new binary..."
cp "$NEW_BIN" "$INSTALL_DIR/mailserverd"
chmod 755 "$INSTALL_DIR/mailserverd"
chown setjoin:setjoin "$INSTALL_DIR/mailserverd"
if [ -n "$NEW_MAILCTL" ] && [ -f "$NEW_MAILCTL" ]; then
    cp "$NEW_MAILCTL" "$INSTALL_DIR/mailctl"
    chmod 755 "$INSTALL_DIR/mailctl"
    chown setjoin:setjoin "$INSTALL_DIR/mailctl"
fi
if [ -n "$NEW_AUTH" ]; then
    cp "$NEW_AUTH" "$INSTALL_DIR/authserverd"
    chmod 755 "$INSTALL_DIR/authserverd"
    chown setjoin:setjoin "$INSTALL_DIR/authserverd"
fi
if [ -n "$NEW_GATEWAY" ]; then
    cp "$NEW_GATEWAY" "$INSTALL_DIR/setjoin-gateway"
    chmod 755 "$INSTALL_DIR/setjoin-gateway"
    chown setjoin:setjoin "$INSTALL_DIR/setjoin-gateway"
fi
if [ -n "$NEW_WEBMAIL" ]; then
    rm -rf "$INSTALL_DIR/webmail.new"
    mkdir -p "$INSTALL_DIR/webmail.new"
    cp -a "$NEW_WEBMAIL"/. "$INSTALL_DIR/webmail.new/"
    chown -R setjoin:setjoin "$INSTALL_DIR/webmail.new"
    rm -rf "$INSTALL_DIR/webmail"
    mv "$INSTALL_DIR/webmail.new" "$INSTALL_DIR/webmail"
fi

# roll_back_and_exit — restore the previous binaries, restart, and exit non-zero.
# Used when a pre-start step fails so the service is never left DOWN (it was
# stopped at step 1). The previous binary works against the un-migrated schema.
roll_back_and_exit() {
    echo "   Rolling back to the previous version and restarting..."
    cp "$INSTALL_DIR/mailserverd.prev" "$INSTALL_DIR/mailserverd"
    [ -f "$INSTALL_DIR/mailctl.prev" ] && cp "$INSTALL_DIR/mailctl.prev" "$INSTALL_DIR/mailctl" || true
    if [ -n "$NEW_AUTH" ] && [ -f "$INSTALL_DIR/authserverd.prev" ]; then
        cp "$INSTALL_DIR/authserverd.prev" "$INSTALL_DIR/authserverd"
    fi
    if [ -n "$NEW_GATEWAY" ] && [ -f "$INSTALL_DIR/setjoin-gateway.prev" ]; then
        cp "$INSTALL_DIR/setjoin-gateway.prev" "$INSTALL_DIR/setjoin-gateway"
    fi
    if [ -n "$NEW_WEBMAIL" ]; then
        rm -rf "$INSTALL_DIR/webmail"
        if [ "$HAD_WEBMAIL" = "1" ] && [ -d "$INSTALL_DIR/webmail.prev" ]; then
            cp -a "$INSTALL_DIR/webmail.prev" "$INSTALL_DIR/webmail"
        fi
    fi
    if [ -n "$NEW_GATEWAY" ]; then
        restore_gateway_deployment
    fi
    if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
        systemctl start setjoin-auth || true
    fi
    systemctl start setjoin || true
    if [ -n "$NEW_GATEWAY" ]; then
        systemctl start setjoin-gateway || true
    fi
    echo "   Restored previous version. Fix the issue, then re-run the upgrade."
    exit 1
}

echo "3.5. Applying pending DB schema migrations (before start)..."
# resolve_schema_dsn CONFIG_ENV CRED_FILE — print the DSN schema apply should
# run under, honoring the DEPLOY-004 privileged-DSN split. DDL runs as the
# OWNER identity: under the constrained native-RLS shape install.sh writes
# (DB_DSN = setjoin_app), applying migrations over DB_DSN would create
# app-owned tables — runbook footgun #1 (docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md).
# Preference order: the owner tiers from the root-owned credential file
# (direct, then pooled — where a split install keeps them), then the
# pre-split config.env owner copies, then the legacy fallbacks
# (DB_DIRECT_DSN/DB_DSN — correct on permissive/pre-flip installs where those
# ARE the owner).
# Refusal contract: when CRED_FILE exists but fails its installed namespace
# posture (symlink, widened mode, wrong owner, substituted or runtime-writable
# parent directory), this function returns 1 WITHOUT a fallback — a substitute
# at the live pathname would point schema apply at attacker-chosen content
# (whole-directory replacement). The caller must refuse loud, not silently
# skip: the skip path only prints a warning, and the gateway's
# refuse-to-start backstop must not become the only thing standing between a
# planted credential file and a migration run.
# The `|| true` on the greps is load-bearing: under `set -euo pipefail`, a grep
# that matches nothing exits 1 and would otherwise abort the whole upgrade with
# the service already stopped — and every key here is legitimately optional.
# Expected-namespace-posture parameters (ROOT_OWNER/ROOT_GROUP/RUNTIME_GROUP)
# default to the production literals (root/root/setjoin); the hermetic render
# lane overrides them with its own identity to execute this function over
# fixture trees it actually owns.
resolve_schema_dsn() {
    local config_env="$1" cred_file="$2"
    local want_owner="${3:-root}" want_group="${4:-root}" runtime_group="${5:-setjoin}"
    local cred_dir val key st want
    cred_dir="$(dirname "$cred_file")"
    if [ -L "$cred_file" ] || [ -e "$cred_file" ]; then
        if [ -L "$cred_file" ] || [ ! -f "$cred_file" ]; then
            echo "privileged credential file $cred_file is a symlink or not a regular file — possible plant" >&2
            return 1
        fi
        st="$(stat -c '%U %G %a' "$cred_file" 2>/dev/null)" \
          || st="$(stat -f '%Su %Sg %Lp' "$cred_file" 2>/dev/null)" \
          || { echo "cannot stat $cred_file" >&2; return 1; }
        want="$want_owner $want_group 600"
        if [ "$st" != "$want" ]; then
            echo "privileged credential file $cred_file is '$st', want '$want' — posture does not match the installed store" >&2
            return 1
        fi
        st="$(stat -c '%U %G %a' "$cred_dir" 2>/dev/null)" \
          || st="$(stat -f '%Su %Sg %Lp' "$cred_dir" 2>/dev/null)" \
          || { echo "cannot stat $cred_dir" >&2; return 1; }
        want="$want_owner $runtime_group 750"
        if [ -L "$cred_dir" ] || [ ! -d "$cred_dir" ] || [ "$st" != "$want" ]; then
            echo "credential directory $cred_dir is '${st:-missing}', want '$want' — possible whole-directory replacement (the real directory was renamed aside and a substitute planted); refusing the substitute" >&2
            return 1
        fi
        st="$(stat -c '%U %G %a' "$(dirname "$cred_dir")" 2>/dev/null)" \
          || st="$(stat -f '%Su %Sg %Lp' "$(dirname "$cred_dir")" 2>/dev/null)" \
          || { echo "cannot stat the credential ancestor" >&2; return 1; }
        want="$want_owner $want_group 755"
        if [ "$st" != "$want" ]; then
            echo "credential ancestor $(dirname "$cred_dir") is '$st', want '$want' — a runtime-writable ancestor permits whole-directory replacement; refusing" >&2
            return 1
        fi
        for key in DB_DIRECT_OWNER_DSN DB_OWNER_DSN; do
            val="$(grep -E "^$key=" "$cred_file" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
            if [ -n "$val" ]; then
                printf '%s\n' "$val"
                return 0
            fi
        done
    fi
    # Pre-split/legacy fallbacks from config.env — owner keys first, exactly
    # as this probe has always ordered them.
    if [ -f "$config_env" ]; then
        for key in DB_DIRECT_OWNER_DSN DB_OWNER_DSN DB_DIRECT_DSN DB_DSN; do
            val="$(grep -E "^$key=" "$config_env" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
            if [ -n "$val" ]; then
                printf '%s\n' "$val"
                return 0
            fi
        done
    fi
    return 0
}
if ! SCHEMA_DSN="$(resolve_schema_dsn "$CONFIG_ENV" "$DB_CRED_FILE")"; then
    echo "   ✗ privileged DB credential namespace failed validation — refusing to pick a schema DSN from a substituted store."
    roll_back_and_exit
fi
# Prefer the just-installed (matching) mailctl; else a mailctl on PATH.
MAILCTL_BIN=""
if [ -x "$INSTALL_DIR/mailctl" ]; then MAILCTL_BIN="$INSTALL_DIR/mailctl"
elif command -v mailctl >/dev/null 2>&1; then MAILCTL_BIN="$(command -v mailctl)"; fi
if [ -n "$MAILCTL_BIN" ] && [ -n "$SCHEMA_DSN" ]; then
    if [ -n "$NEW_MAILCTL" ] || [ "$MAILCTL_BIN" = "$INSTALL_DIR/mailctl" ]; then
        # Guard the apply: a migration failure must NOT leave the service down
        # (it was stopped at step 1). Roll back to the previous version instead.
        if ! DB_DSN="$SCHEMA_DSN" "$MAILCTL_BIN" schema apply --yes; then
            echo "   ✗ schema apply FAILED — the new gateway would refuse to start on this schema."
            roll_back_and_exit
        fi
    else
        echo "   ! mailctl on PATH may not match the new gateway; checking only:"
        DB_DSN="$SCHEMA_DSN" "$MAILCTL_BIN" schema check || \
          echo "   ! schema is behind — apply with a mailctl from THIS build before the gateway will start"
    fi
else
    echo "   ! skipped (no mailctl and/or no DSN in $CONFIG_ENV). If the DB is behind, the"
    echo "     gateway will refuse to start; apply with: mailctl schema apply"
fi

# Render only with the new gateway: an old binary cannot consume the new FD.
if [ -n "$NEW_GATEWAY" ]; then
    if ! render_gateway_deployment; then
        echo "   ✗ gateway unit/config render failed."
        roll_back_and_exit
    fi
fi

echo "4. Starting services..."
if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
    systemctl start setjoin-auth
fi
systemctl start setjoin || roll_back_and_exit
if [ -n "$NEW_GATEWAY" ]; then
    systemctl start setjoin-gateway || roll_back_and_exit
fi

echo "5. Waiting for service readiness (up to 60 seconds)..."
# Probe the real HTTPS listener (self-signed OK): in the default single-node
# install :80 only serves a 301 redirect, which `curl -f` counts as success —
# the old http://localhost:80/ready check passed even with a dead gateway
# (found by the G1 upgrade smoke, 2026-07-04). Fall back to :80 for
# http.mode=serve/proxy installs with no TLS listener.
LISTEN_ADDR_CFG="$(grep -E '^LISTEN_ADDR=' "$CONFIG_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
LISTEN_ADDR_CFG="${LISTEN_ADDR_CFG:-:443}"
AUTH_LISTEN_ADDR="$(grep -E '^LISTEN_ADDR=' "$AUTH_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-127.0.0.1:8443}"
GATEWAY_ADDR="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
GATEWAY_ADDR="${GATEWAY_ADDR:-127.0.0.1:8090}"
TLS_PROBE_URL=""
PRIMARY_READY_URL="https://127.0.0.1${LISTEN_ADDR_CFG}/ready"
if [ -n "$NEW_GATEWAY" ] && tls_front_enabled "$CONFIG_ENV"; then
    TLS_PROBE_URL=$(tls_front_probe_url "$CONFIG_ENV")
    PRIMARY_READY_URL=http://127.0.0.1:80/ready
fi
READY=0
for attempt in $(seq 1 30); do
    AUTH_HEALTHY=1
    if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
        curl -sf --max-time 3 "http://${AUTH_LISTEN_ADDR}/ready" >/dev/null ||
            AUTH_HEALTHY=0
    fi
    GATEWAY_HEALTHY=1
    if [ -n "$NEW_GATEWAY" ]; then
        curl -sf --max-time 3 "http://${GATEWAY_ADDR}/_gateway/healthz" >/dev/null ||
            GATEWAY_HEALTHY=0
    fi
    if [ -n "$TLS_PROBE_URL" ]; then
        curl -skf --max-time 3 "$TLS_PROBE_URL" >/dev/null || GATEWAY_HEALTHY=0
    fi
    if { curl -skf --max-time 3 "$PRIMARY_READY_URL" >/dev/null ||
         curl -sf --max-time 3 http://localhost:80/ready >/dev/null; } &&
       [ "$AUTH_HEALTHY" = "1" ] && [ "$GATEWAY_HEALTHY" = "1" ]; then
        READY=1
        echo "   Services ready after ${attempt} attempt(s)."
        break
    fi
    sleep 2
done
if [ "$READY" = "1" ]; then
    echo "Upgrade successful!"
    # Forward migrations are designed backward-compatible with the previous binary
    # (V002 nullable / V003 inert policies / V004 RLS no-op for the owner), so a
    # previous-release rollback after applying them is safe.
    echo "To rollback: stop the gateway and federation socket; restore matching *.prev binaries, webmail.prev and $DEPLOYMENT_PREV unit/config snapshot; daemon-reload, then restart services. See mailserver/DOX.md native federation deployment."
else
    echo "Health check FAILED after 60 seconds."
    echo "(If the new gateway refused to start on a stale schema, apply migrations with a"
    echo " matching mailctl — 'mailctl schema check' — then re-run this upgrade.)"
    # Same rollback as the pre-start failure path: restores BOTH binaries (the
    # earlier version restored only mailserverd, leaving a mismatched mailctl).
    roll_back_and_exit
fi
