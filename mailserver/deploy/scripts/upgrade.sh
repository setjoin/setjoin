#!/bin/bash
set -euo pipefail
# Setjoin server/auth upgrade (Rust-only post-#142; also supports one-time
# cutover from a pre-#142 host with setjoin-gateway and optional setjoin.service).
# Usage: ./upgrade.sh /path/to/new/setjoin-server [/path/to/new/mailctl] [/path/to/webmail-build] [/path/to/new/setjoin-auth]
#
# The new server REFUSES TO START if the database schema is behind the version
# it expects. So this script applies any pending DB schema migrations BEFORE
# starting the new binary, using a MATCHING Rust mailctl (same build) — pass the
# new mailctl as arg 2, or have a matching `mailctl` on PATH. If no matching
# mailctl is available it only CHECKS and warns; the server's refuse-to-start +
# the health-check rollback below are the backstop.

INSTALL_DIR="${INSTALL_DIR:-/opt/setjoin}"
REFRESH_GATEWAY_ENV=0
SUBCOMMAND=""
ALLOW_SINGLE_COHORT=0

case "${1:-}" in
    migrate-to-setjoind)
        SUBCOMMAND="migrate-to-setjoind"
        shift
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --allow-single-cohort) ALLOW_SINGLE_COHORT=1 ;;
                *)
                    echo "Usage: $0 migrate-to-setjoind [--allow-single-cohort]" >&2
                    exit 2
                    ;;
            esac
            shift
        done
        ;;
    rollback-to-split-units)
        SUBCOMMAND="rollback-to-split-units"
        shift
        if [ "$#" -ne 0 ]; then
            echo "Usage: $0 rollback-to-split-units" >&2
            exit 2
        fi
        ;;
esac

if [ -z "$SUBCOMMAND" ] && [ -L "$INSTALL_DIR/current" ]; then
    case "${1:-}" in
        status|evidence|activate-previous)
            action="$1"; shift
            exec /usr/libexec/setjoin-recovery "$action" "$@"
            ;;
        refresh-gateway-env)
            REFRESH_GATEWAY_ENV=1
            ;;
        *)
            echo "This installation uses the transactional immutable layout; positional artifact-copy upgrades are disabled." >&2
            echo "Use the signed Updates workflow, or 'sudo $0 refresh-gateway-env | migrate-to-setjoind | rollback-to-split-units'; for recovery: sudo $0 status | evidence | activate-previous --reason TEXT" >&2
            exit 2
            ;;
    esac
fi

NEW_SERVER=""
NEW_MAILCTL=""
NEW_WEBMAIL=""
NEW_AUTH=""
NEW_SETJOIND=""
if [ -z "$SUBCOMMAND" ] && [ "$REFRESH_GATEWAY_ENV" = 0 ]; then
    NEW_SERVER="${1:-}"
    NEW_MAILCTL="${2:-}"
    NEW_WEBMAIL="${3:-}"
    NEW_AUTH="${4:-}"
    NEW_SETJOIND="${5:-}"
    if [ ! -f "$NEW_SERVER" ]; then
        echo "Usage: $0 /path/to/new/setjoin-server [/path/to/new/mailctl] [/path/to/webmail-build] [/path/to/new/setjoin-auth] [/path/to/new/setjoind]"
        echo "  1. Build: cd server-rust && cargo build --release --locked -p setjoind -p setjoin-mailctl"
        echo "  2. Deploy: scp setjoin-server setjoin-auth setjoind mailctl user@host:/tmp/ && \\"
        echo "             ssh user@host 'sudo /opt/setjoin/deploy/scripts/upgrade.sh /tmp/setjoin-server /tmp/mailctl /tmp/webmail-build /tmp/setjoin-auth /tmp/setjoind'"
        exit 1
    fi
    if [ -n "$NEW_WEBMAIL" ] && [ ! -f "$NEW_WEBMAIL/index.html" ]; then
        echo "Webmail build must be a directory containing index.html: $NEW_WEBMAIL"
        exit 1
    fi
    if [ -n "$NEW_AUTH" ] && [ ! -f "$NEW_AUTH" ]; then
        echo "Auth binary does not exist: $NEW_AUTH"
        exit 1
    fi
    if [ -z "$NEW_SETJOIND" ] && [ -f "$(dirname "$NEW_SERVER")/setjoind" ]; then
        NEW_SETJOIND="$(dirname "$NEW_SERVER")/setjoind"
    fi
    if [ -n "$NEW_SETJOIND" ] && [ ! -f "$NEW_SETJOIND" ]; then
        echo "setjoind binary does not exist: $NEW_SETJOIND" >&2
        exit 1
    fi
    if { grep -aq 'SETJOIND_SHIM_V1' "$NEW_SERVER" 2>/dev/null ||
         { [ -n "$NEW_AUTH" ] && grep -aq 'SETJOIND_SHIM_V1' "$NEW_AUTH" 2>/dev/null; }; } &&
       [ -z "$NEW_SETJOIND" ]; then
        echo "Refusing to install Release N shim binary without a companion setjoind executable (pass arg 5 or place setjoind beside $NEW_SERVER)." >&2
        exit 1
    fi
fi

CONFIG_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/config.env"
AUTH_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/auth.env"
# Privileged DB credential tier (DEPLOY-004 split): the owner keys moved out of
# config.env into this root-owned 0600 file below the root-owned config dir.
DB_CRED_FILE="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/db-credentials.d/db-credentials.env"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
GATEWAY_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/gateway.env"
SETJOIND_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/setjoind.env"
SETJOIND_AUTH_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/setjoind-auth.env"
FEDERATION_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/federation.env"
STORAGE_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/storage.env"
TLS_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/tls.env"
SMTP_ENV="${SETJOIN_CONFIG_DIR:-/etc/setjoin}/smtp.env"
source "$(dirname "${BASH_SOURCE[0]}")/lib-livekit.sh"
DEPLOYMENT_PREV="$INSTALL_DIR/federation-deploy.prev"
CUTOVER_PREV="$INSTALL_DIR/setjoind-cutover.prev"
ALL_SERVER_SOCKETS=(
    setjoin-gateway.socket
    setjoin-https.socket
    setjoin-acme.socket
    setjoin-federation.socket
    setjoin-imap.socket
    setjoin-imaps.socket
    setjoin-smtp.socket
    setjoin-smtps.socket
    setjoin-submission.socket
)
HAD_WEBMAIL=0
AUTH_WAS_ACTIVE=0

# The descriptor set is part of the release: older gateways cannot consume
# the federation FD. Keep absence as well as bytes/modes for whole-release rollback.
backup_gateway_deployment() {
    local file state=""
    [ ! -L "$DEPLOYMENT_PREV" ] || return 1
    rm -rf "$DEPLOYMENT_PREV"
    ( umask 077; mkdir -p "$DEPLOYMENT_PREV/units" "$DEPLOYMENT_PREV/config" )
    for file in setjoin.service setjoin-auth.service setjoin-gateway.service setjoind.service setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -e "$SYSTEMD_DIR/$file" ] || [ -L "$SYSTEMD_DIR/$file" ]; then
            cp -a "$SYSTEMD_DIR/$file" "$DEPLOYMENT_PREV/units/"
        fi
    done
    local legacy_go_unit="setjoin"
    if [ -e "$SYSTEMD_DIR/${legacy_go_unit}.service" ] || [ -L "$SYSTEMD_DIR/${legacy_go_unit}.service" ]; then
        systemctl is-active --quiet "${legacy_go_unit}.service" && touch "$DEPLOYMENT_PREV/setjoin.service-active" || true
        if state="$(systemctl is-enabled "${legacy_go_unit}.service" 2>/dev/null)"; then
            case "$state" in
                enabled-runtime) printf 'enabled-runtime\n' > "$DEPLOYMENT_PREV/setjoin.service-enabled" ;;
                enabled|'') printf 'enabled\n' > "$DEPLOYMENT_PREV/setjoin.service-enabled" ;;
            esac
        fi
    fi
    for file in config.env auth.env gateway.env setjoind.env setjoind-auth.env federation.env tls.env smtp.env storage.env; do
        if [ -e "${CONFIG_ENV%/*}/$file" ]; then
            cp -a "${CONFIG_ENV%/*}/$file" "$DEPLOYMENT_PREV/config/"
        fi
    done
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -e "$SYSTEMD_DIR/$file" ]; then
            systemctl is-active --quiet "$file" && touch "$DEPLOYMENT_PREV/$file-active" || true
            if state="$(systemctl is-enabled "$file" 2>/dev/null)"; then
                case "$state" in
                    enabled-runtime) printf 'enabled-runtime\n' > "$DEPLOYMENT_PREV/$file-enabled" ;;
                    enabled|'') printf 'enabled\n' > "$DEPLOYMENT_PREV/$file-enabled" ;;
                esac
            fi
        fi
    done
    if [ -e "$SYSTEMD_DIR/setjoin-federation.socket" ]; then
        systemctl is-active --quiet setjoin-federation.socket && touch "$DEPLOYMENT_PREV/socket-active" || true
        if state="$(systemctl is-enabled setjoin-federation.socket 2>/dev/null)"; then
            case "$state" in
                enabled-runtime) printf 'enabled-runtime\n' > "$DEPLOYMENT_PREV/socket-enabled" ;;
                enabled|'') printf 'enabled\n' > "$DEPLOYMENT_PREV/socket-enabled" ;;
            esac
        fi
    fi
    local prev_cache="" prev_devino=""
    prev_cache="$(
        root="$(cd "$(dirname "$0")/../../.." && pwd)"
        source "$root/mailserver/deploy/scripts/lib-livekit.sh"
        tls_import_cache_dir "$CONFIG_ENV"
    )" || prev_cache=""
    if [ -n "$prev_cache" ]; then
        printf 'path=%s\n' "$prev_cache" > "$DEPLOYMENT_PREV/tls-cache.meta"
        if [ ! -L "$prev_cache" ] && [ -d "$prev_cache" ]; then
            prev_devino="$(python3 -c 'import os,sys; s=os.lstat(sys.argv[1]); print(f"{s.st_dev}:{s.st_ino}")' "$prev_cache" 2>/dev/null || true)"
            printf 'exists=1\nmode=%s\nowner=%s\ndevino=%s\n' \
                "$(stat -c '%a' "$prev_cache" 2>/dev/null || stat -f '%Lp' "$prev_cache")" \
                "$(stat -c '%u:%g' "$prev_cache" 2>/dev/null || stat -f '%u:%g' "$prev_cache")" \
                "$prev_devino" >> "$DEPLOYMENT_PREV/tls-cache.meta"
        else
            printf 'exists=0\n' >> "$DEPLOYMENT_PREV/tls-cache.meta"
        fi
    fi
}
restore_tls_cache_meta() {
    [ -f "$DEPLOYMENT_PREV/tls-cache.meta" ] || return 0
    local prev_path="" prev_exists="" prev_mode="" prev_owner="" prev_devino="" created_devino="" line k v
    while IFS= read -r line || [ -n "$line" ]; do
        k="${line%%=*}"
        v="${line#*=}"
        case "$k" in
            path) prev_path="$v" ;;
            exists) prev_exists="$v" ;;
            mode) prev_mode="$v" ;;
            owner) prev_owner="$v" ;;
            devino) prev_devino="$v" ;;
            created_devino) created_devino="$v" ;;
        esac
    done < "$DEPLOYMENT_PREV/tls-cache.meta"
    if [ -n "$prev_path" ] && [ "$prev_path" != "/" ] && [ ! -L "$prev_path" ] && [ -d "$prev_path" ]; then
        if [ "$prev_exists" = 1 ]; then
            [ -n "$prev_devino" ] || return 0
            python3 - "$prev_path" "$prev_devino" "$prev_mode" "$prev_owner" <<'PY' || return 1
import os, stat, sys
path, exp_devino, mode_str, owner_str = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3], sys.argv[4]
if hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parts = [p for p in path.split("/") if p]
    if not path.startswith("/") or not parts:
        sys.exit(0)
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    allowed_owners = {0}
    if is_root:
        try:
            import pwd
            allowed_owners.add(pwd.getpwnam("setjoin").pw_uid)
        except KeyError:
            pass
    fd = os.open("/", flags)
    try:
        for seg in parts:
            if is_root:
                pst = os.fstat(fd)
                if pst.st_uid not in allowed_owners or (pst.st_mode & 0o002) != 0:
                    sys.exit(0)
            nxt = os.open(seg, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or f"{st.st_dev}:{st.st_ino}" != exp_devino:
            sys.stderr.write(f"   ! skipping tls-cache rollback for {path}: directory identity changed ({st.st_dev}:{st.st_ino} != {exp_devino})\n")
            sys.exit(0)
        if mode_str and hasattr(os, "fchmod"):
            os.fchmod(fd, int(mode_str, 8))
        if owner_str and ":" in owner_str and hasattr(os, "fchown"):
            uid, gid = (int(x) for x in owner_str.split(":", 1))
            try:
                os.fchown(fd, uid, gid)
            except PermissionError:
                if is_root:
                    raise
    except OSError as exc:
        sys.stderr.write(f"   ✗ tls-cache rollback failed for {path}: {exc}\n")
        sys.exit(1)
    finally:
        os.close(fd)
PY
        elif [ "$prev_exists" = 0 ] && [ -n "$created_devino" ]; then
            python3 - "$prev_path" "$created_devino" <<'PY' || return 1
import os, stat, sys
path, exp_devino = sys.argv[1].rstrip("/"), sys.argv[2]
if hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
    parts = [p for p in path.split("/") if p]
    if not path.startswith("/") or not parts:
        sys.exit(0)
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    allowed_owners = {0}
    if is_root:
        try:
            import pwd
            allowed_owners.add(pwd.getpwnam("setjoin").pw_uid)
        except KeyError:
            pass
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    pfd = os.open("/", flags)
    try:
        for seg in parts[:-1]:
            if is_root:
                pst = os.fstat(pfd)
                if pst.st_uid not in allowed_owners or (pst.st_mode & 0o002) != 0:
                    sys.exit(0)
            nxt = os.open(seg, flags, dir_fd=pfd)
            os.close(pfd)
            pfd = nxt
        if is_root:
            pst = os.fstat(pfd)
            if pst.st_uid not in allowed_owners or (pst.st_mode & 0o002) != 0:
                sys.exit(0)
        name = parts[-1]
        st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode) or f"{st.st_dev}:{st.st_ino}" != exp_devino:
            sys.exit(0)
        os.rmdir(name, dir_fd=pfd)
    except FileNotFoundError:
        sys.exit(0)
    except OSError as exc:
        sys.stderr.write(f"   ✗ tls-cache removal rollback failed for {path}: {exc}\n")
        sys.exit(1)
    finally:
        os.close(pfd)
else:
    try:
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode) and f"{st.st_dev}:{st.st_ino}" == exp_devino:
            os.rmdir(path)
    except FileNotFoundError:
        sys.exit(0)
    except OSError as exc:
        sys.stderr.write(f"   ✗ tls-cache removal rollback failed for {path}: {exc}\n")
        sys.exit(1)
PY
        fi
    fi
}
restore_gateway_files_only() {
    local file rc=0
    for file in setjoin.service setjoin-auth.service setjoin-gateway.service setjoind.service setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        rm -f "$SYSTEMD_DIR/$file" || rc=1
        if [ -e "$DEPLOYMENT_PREV/units/$file" ] || [ -L "$DEPLOYMENT_PREV/units/$file" ]; then
            cp -a "$DEPLOYMENT_PREV/units/$file" "$SYSTEMD_DIR/" || rc=1
        fi
    done
    for file in config.env auth.env gateway.env setjoind.env setjoind-auth.env federation.env tls.env smtp.env storage.env; do
        rm -f "${CONFIG_ENV%/*}/$file" || rc=1
        if [ -e "$DEPLOYMENT_PREV/config/$file" ]; then
            cp -a "$DEPLOYMENT_PREV/config/$file" "${CONFIG_ENV%/*}/" || rc=1
        fi
    done
    systemctl daemon-reload || rc=1
    restore_tls_cache_meta || rc=1
    return "$rc"
}
restore_socket_enabled_state() {
    local unit="$1" marker="$2" state=""
    [ -f "$marker" ] || return 0
    state="$(cat "$marker" 2>/dev/null || true)"
    if [ "$state" = enabled-runtime ]; then
        systemctl enable --runtime "$unit"
    else
        systemctl enable "$unit"
    fi
}
restore_gateway_refresh() {
    local file state="" rc=0 removed_https=0 removed_acme=0
    if [ ! -e "$SYSTEMD_DIR/setjoin-https.socket" ] && [ -e "$DEPLOYMENT_PREV/units/setjoin-https.socket" ]; then
        removed_https=1
    fi
    if [ ! -e "$SYSTEMD_DIR/setjoin-acme.socket" ] && [ -e "$DEPLOYMENT_PREV/units/setjoin-acme.socket" ]; then
        removed_acme=1
    fi
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        state="$(cat "$DEPLOYMENT_PREV/$file-enabled" 2>/dev/null || true)"
        if { [ ! -f "$DEPLOYMENT_PREV/$file-enabled" ] || [ "$state" = enabled-runtime ]; } && [ -e "$SYSTEMD_DIR/$file" ]; then
            systemctl disable "$file" || rc=1
        fi
    done
    state="$(cat "$DEPLOYMENT_PREV/socket-enabled" 2>/dev/null || true)"
    if { [ ! -f "$DEPLOYMENT_PREV/socket-enabled" ] || [ "$state" = enabled-runtime ]; } && [ -e "$SYSTEMD_DIR/setjoin-federation.socket" ]; then
        systemctl disable setjoin-federation.socket || rc=1
    fi
    restore_gateway_files_only || rc=1
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        restore_socket_enabled_state "$file" "$DEPLOYMENT_PREV/$file-enabled" || rc=1
    done
    if [ "$removed_https" = 1 ] && [ -f "$DEPLOYMENT_PREV/setjoin-https.socket-active" ]; then
        systemctl start setjoin-https.socket || rc=1
    fi
    if [ "$removed_acme" = 1 ] && [ -f "$DEPLOYMENT_PREV/setjoin-acme.socket-active" ]; then
        local legacy_acme_socket="setjoin-acme.socket"
        systemctl start "$legacy_acme_socket" || rc=1
    fi
    restore_socket_enabled_state setjoin-federation.socket "$DEPLOYMENT_PREV/socket-enabled" || rc=1
    if [ "$rc" != 0 ]; then
        echo "   ✗ Incomplete refresh rollback: failed to restore one or more deployment files or socket states." >&2
    fi
    return "$rc"
}
restore_gateway_deployment() {
    local file rc=0
    # Close the new socket before the previous executable can receive its FD.
    if [ -e "$SYSTEMD_DIR/setjoin-gateway.service" ]; then
        systemctl stop setjoin-gateway || rc=1
    fi
    if [ -e "$SYSTEMD_DIR/setjoin-federation.socket" ]; then
        systemctl stop setjoin-federation.socket || rc=1
        systemctl disable setjoin-federation.socket || rc=1
    fi
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -e "$SYSTEMD_DIR/$file" ]; then
            systemctl stop "$file" || rc=1
            systemctl disable "$file" || rc=1
        fi
    done
    restore_gateway_files_only || rc=1
    for file in setjoin-https.socket setjoin-acme.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        restore_socket_enabled_state "$file" "$DEPLOYMENT_PREV/$file-enabled" || rc=1
        if [ -f "$DEPLOYMENT_PREV/$file-active" ]; then systemctl start "$file" || rc=1; fi
    done
    restore_socket_enabled_state setjoin-federation.socket "$DEPLOYMENT_PREV/socket-enabled" || rc=1
    if [ -f "$DEPLOYMENT_PREV/socket-active" ]; then systemctl start setjoin-federation.socket || rc=1; fi
    restore_socket_enabled_state setjoin.service "$DEPLOYMENT_PREV/setjoin.service-enabled" || rc=1
    return "$rc"
}

# Read literal installer EnvironmentFile assignments, without evaluating secrets.
config_value() {
    sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1 || true
}
# Validate DB_CRED_FILE ownership/mode/symlink posture (matching resolve_schema_dsn)
# before extracting DB_WORKER_DSN into root-0600 auth.env.
validate_db_cred_file_posture() {
    local cred_file="$1"
    local want_owner="${2:-${DB_CRED_WANT_OWNER:-root}}"
    local want_group="${3:-${DB_CRED_WANT_GROUP:-root}}"
    local runtime_group="${4:-${DB_CRED_RUNTIME_GROUP:-setjoin}}"
    local cred_dir st want
    cred_dir="$(dirname "$cred_file")"
    if [ ! -L "$cred_file" ] && [ ! -e "$cred_file" ]; then
        return 0
    fi
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
    return 0
}
render_auth_deployment() (
    local root
    root="$(cd "$(dirname "$0")/../../.." && pwd)"
    source "$root/mailserver/deploy/scripts/lib-livekit.sh" || return 1
    RUNTIME_DIR="${RUNTIME_DIR:-$INSTALL_DIR}"
    if [ ! -x "$RUNTIME_DIR/setjoin-auth" ]; then
        echo "missing executable $RUNTIME_DIR/setjoin-auth — refusing to cut over setjoin-auth.service" >&2
        return 1
    fi
    AUTHSERVER_URL="$(config_value "$CONFIG_ENV" AUTHSERVER_URL)"
    AUTHSERVER_URL="${AUTHSERVER_URL:-http://127.0.0.1:8443}"
    AUTH_LISTEN="${AUTHSERVER_URL#http://}"; AUTH_LISTEN="${AUTH_LISTEN#https://}"; AUTH_LISTEN="${AUTH_LISTEN%%/*}"
    validate_db_cred_file_posture "$DB_CRED_FILE" || return 1
    render_auth_env "$AUTH_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:root "$AUTH_ENV" || return 1
    render_authserver_unit "$root/mailserver/deploy/authserver.service.template" "$SYSTEMD_DIR/setjoin-auth.service" || return 1
    systemctl daemon-reload || return 1
)
render_gateway_deployment() (
    local root key names file tmp _tls_cache
    root="$(cd "$(dirname "$0")/../../.." && pwd)"
    source "$root/mailserver/deploy/scripts/lib-livekit.sh" || return 1
    # Use caller's RUNTIME_DIR for immutable refresh, or INSTALL_DIR on legacy flat layout.
    RUNTIME_DIR="${RUNTIME_DIR:-$INSTALL_DIR}"
    AUTHSERVER_URL="$(config_value "$CONFIG_ENV" AUTHSERVER_URL)"
    AUTHSERVER_URL="${AUTHSERVER_URL:-http://127.0.0.1:8443}"
    AUTH_LISTEN="${AUTHSERVER_URL#http://}"; AUTH_LISTEN="${AUTH_LISTEN#https://}"; AUTH_LISTEN="${AUTH_LISTEN%%/*}"
    GATEWAY_LISTEN="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
    GATEWAY_TRUSTED_PROXIES="$(config_value "$GATEWAY_ENV" GATEWAY_TRUSTED_PROXIES)"
    FEDERATION_ENABLED="$(config_value "$CONFIG_ENV" FEDERATION_ENABLED)"
    FEDERATION_LISTEN_ADDR="$(config_value "$CONFIG_ENV" FEDERATION_LISTEN_ADDR)"
    # Older configs may have the static gate without the installer-only marker.
    if [ -n "$(config_value "$CONFIG_ENV" FEDERATION_LOCAL_DOMAIN)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_CERT)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_KEY)" ]; then
        FEDERATION_ENABLED=true
    fi
    # Fail closed on retired built-in ACME configuration (#560) before mutating config.env or env files.
    check_no_retired_acme_config "$CONFIG_ENV" || return 1
    for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
        names="$(config_env_value "$CONFIG_ENV" "$key")"
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
    _tls_cache=$(tls_import_cache_dir "$CONFIG_ENV")
    validate_tls_cache_target "$_tls_cache" || return 1
    render_tls_front_env "$TLS_ENV" "$CONFIG_ENV" || return 1
    chown root:setjoin "$TLS_ENV" || return 1
    render_gateway_env "$GATEWAY_ENV" || return 1
    local render_auth=0
    if [ -x "$RUNTIME_DIR/setjoin-auth" ]; then
        render_auth=1
    elif [ -n "${NEW_AUTH:-}" ]; then
        echo "missing executable $RUNTIME_DIR/setjoin-auth — refusing to cut over setjoin-auth.service" >&2
        return 1
    fi
    if [ "$render_auth" = 1 ]; then
        validate_db_cred_file_posture "$DB_CRED_FILE" || return 1
        render_auth_env "$AUTH_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
        chown root:root "$AUTH_ENV" || return 1
    fi
    render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$FEDERATION_ENV" || return 1
    render_storage_env "$STORAGE_ENV" "$CONFIG_ENV" || return 1
    chown root:setjoin "$STORAGE_ENV" || return 1
    # SMTP (#501): its own allow-listed file, re-rendered with the unit set.
    render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$SMTP_ENV" || return 1
    ensure_tls_cache_dir "$_tls_cache" "${DEPLOYMENT_PREV:-}/tls-cache.meta" || return 1
    # A descriptor belongs to the matching new binary. Recreate only this
    # release's socket set; snapshots preserve prior bytes, absence and state.
    if [ -e "$SYSTEMD_DIR/setjoin-acme.socket" ] || [ -L "$SYSTEMD_DIR/setjoin-acme.socket" ]; then
        systemctl stop setjoin-acme.socket || true
        systemctl disable setjoin-acme.socket || true
    fi
    if ! tls_front_enabled "$CONFIG_ENV" && { [ -e "$SYSTEMD_DIR/setjoin-https.socket" ] || [ -L "$SYSTEMD_DIR/setjoin-https.socket" ]; }; then
        systemctl stop setjoin-https.socket || true
        systemctl disable setjoin-https.socket || true
    fi
    rm -f "$SYSTEMD_DIR/setjoin-https.socket" "$SYSTEMD_DIR/setjoin-acme.socket" "$SYSTEMD_DIR/setjoin-imap.socket" "$SYSTEMD_DIR/setjoin-imaps.socket" "$SYSTEMD_DIR/setjoin-smtp.socket" "$SYSTEMD_DIR/setjoin-smtps.socket" "$SYSTEMD_DIR/setjoin-submission.socket"
    if [ "$render_auth" = 1 ]; then
        render_authserver_unit "$root/mailserver/deploy/authserver.service.template" "$SYSTEMD_DIR/setjoin-auth.service" || return 1
    fi
    render_gateway_unit "$root/mailserver/deploy/setjoin-gateway.service.template" "$SYSTEMD_DIR/setjoin-gateway.service" || return 1
    systemctl daemon-reload || return 1
    for file in setjoin-https.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
        if [ -f "$SYSTEMD_DIR/$file" ]; then systemctl enable "$file" || return 1; fi
    done
    if [ "${FEDERATION_ENABLED:-false}" = true ]; then
        systemctl enable setjoin-federation.socket || return 1
    fi
)

render_setjoind_deployment() (
    local root key names file tmp _tls_cache
    root="$(cd "$(dirname "$0")/../../.." && pwd)"
    source "$root/mailserver/deploy/scripts/lib-livekit.sh" || return 1
    RUNTIME_DIR="${RUNTIME_DIR:-$INSTALL_DIR}"
    if [ ! -x "$RUNTIME_DIR/setjoind" ]; then
        echo "missing executable $RUNTIME_DIR/setjoind — refusing to render setjoind.service" >&2
        return 1
    fi
    validate_db_cred_file_posture "$DB_CRED_FILE" || return 1
    if [ -f "$CONFIG_ENV" ] && grep -Eq '^[[:space:]]*(DB_OWNER_DSN|DB_DIRECT_OWNER_DSN)=' "$CONFIG_ENV"; then
        echo "config.env still contains DB_OWNER_DSN or DB_DIRECT_OWNER_DSN; run DEPLOY-004 credential split / mailctl schema provision-roles first" >&2
        return 1
    fi
    GATEWAY_LISTEN="$(config_value "$SETJOIND_ENV" GATEWAY_LISTEN)"
    [ -n "$GATEWAY_LISTEN" ] || GATEWAY_LISTEN="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
    GATEWAY_TRUSTED_PROXIES="$(config_value "$SETJOIND_ENV" GATEWAY_TRUSTED_PROXIES)"
    [ -n "$GATEWAY_TRUSTED_PROXIES" ] || GATEWAY_TRUSTED_PROXIES="$(config_value "$GATEWAY_ENV" GATEWAY_TRUSTED_PROXIES)"
    FEDERATION_ENABLED="$(config_value "$CONFIG_ENV" FEDERATION_ENABLED)"
    FEDERATION_LISTEN_ADDR="$(config_value "$CONFIG_ENV" FEDERATION_LISTEN_ADDR)"
    if [ -n "$(config_value "$CONFIG_ENV" FEDERATION_LOCAL_DOMAIN)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_CERT)" ] &&
       [ -n "$(config_value "$CONFIG_ENV" FEDERATION_KEY)" ]; then
        FEDERATION_ENABLED=true
    fi
    # Fail closed on retired built-in ACME configuration (#560) before mutating config.env or env files.
    check_no_retired_acme_config "$CONFIG_ENV" || return 1
    configure_tls_front "$CONFIG_ENV" || return 1
    configure_imap_front "$CONFIG_ENV" || return 1
    configure_smtp_front "$CONFIG_ENV" || return 1
    _tls_cache=$(tls_import_cache_dir "$CONFIG_ENV")
    validate_tls_cache_target "$_tls_cache" || return 1
    render_tls_front_env "$TLS_ENV" "$CONFIG_ENV" || return 1
    chown root:setjoin "$TLS_ENV" || return 1
    render_setjoind_env "$SETJOIND_ENV" || return 1
    render_setjoind_auth_env "$SETJOIND_AUTH_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:root "$SETJOIND_AUTH_ENV" || return 1
    chmod 0600 "$SETJOIND_AUTH_ENV" || return 1
    render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$FEDERATION_ENV" || return 1
    render_storage_env "$STORAGE_ENV" "$CONFIG_ENV" || return 1
    chown root:setjoin "$STORAGE_ENV" || return 1
    render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$DB_CRED_FILE" || return 1
    chown root:setjoin "$SMTP_ENV" || return 1
    ensure_tls_cache_dir "$_tls_cache" "${DEPLOYMENT_PREV:-}/tls-cache.meta" || return 1
    if [ -e "$SYSTEMD_DIR/setjoin-acme.socket" ] || [ -L "$SYSTEMD_DIR/setjoin-acme.socket" ]; then
        systemctl stop setjoin-acme.socket || true
        systemctl disable setjoin-acme.socket || true
    fi
    if ! tls_front_enabled "$CONFIG_ENV" && { [ -e "$SYSTEMD_DIR/setjoin-https.socket" ] || [ -L "$SYSTEMD_DIR/setjoin-https.socket" ]; }; then
        systemctl stop setjoin-https.socket || true
        systemctl disable setjoin-https.socket || true
    fi
    rm -f "$SYSTEMD_DIR/setjoin-https.socket" "$SYSTEMD_DIR/setjoin-acme.socket" "$SYSTEMD_DIR/setjoin-imap.socket" "$SYSTEMD_DIR/setjoin-imaps.socket" "$SYSTEMD_DIR/setjoin-smtp.socket" "$SYSTEMD_DIR/setjoin-smtps.socket" "$SYSTEMD_DIR/setjoin-submission.socket" "$SYSTEMD_DIR/setjoin-federation.socket"
    render_setjoind_unit "$root/mailserver/deploy/setjoind.service.template" "$SYSTEMD_DIR/setjoind.service" || return 1
    systemctl daemon-reload || return 1
    systemctl enable setjoin-gateway.socket || return 1
    for file in setjoin-https.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket setjoin-federation.socket; do
        if [ -f "$SYSTEMD_DIR/$file" ]; then systemctl enable "$file" || return 1; fi
    done
)

acquire_updater_lock_and_check_journal() {
    local check_journal="${1:-0}" _updater_state _old_umask recovery_bin status_json
    _updater_state="${UPDATER_STATE_DIR:-}"
    if [ -z "$_updater_state" ] && [ -f "$SYSTEMD_DIR/setjoin-updater.service" ]; then
        _updater_state="$(sed -n '/^[[:space:]]*ExecStart=/s/.*--state-dir=\([^[:space:]]*\).*/\1/p' "$SYSTEMD_DIR/setjoin-updater.service" | tail -1 || true)"
    fi
    if [ -z "$_updater_state" ]; then
        _updater_state="${UPDATER_DATA_DIR:-/var/lib/setjoin-updater}/journal"
    fi
    if [ -d "$_updater_state" ] || [ -f "$SYSTEMD_DIR/setjoin-updater.service" ]; then
        [ -d "$_updater_state" ] || {
            echo "   ✗ updater state directory $_updater_state missing; cannot verify executor.lock." >&2
            return 1
        }
        command -v flock >/dev/null 2>&1 || {
            echo "   ✗ flock is required to coordinate with setjoin-updater." >&2
            return 1
        }
        # Append mode preserves the executor.lock inode shared with setjoin-updater.
        _old_umask=$(umask)
        umask 077
        exec 9>>"$_updater_state/executor.lock"
        umask "$_old_umask"
        if ! flock -n 9; then
            echo "   ✗ active signed update holds $_updater_state/executor.lock; refusing concurrent operation." >&2
            return 1
        fi
    fi
    if [ "$check_journal" = "1" ] && [ -d "$_updater_state" ]; then
        recovery_bin="${SETJOIN_RECOVERY_BIN:-/usr/libexec/setjoin-recovery}"
        if [ -x "$recovery_bin" ] && { [ -L "$INSTALL_DIR/current" ] || [ -e "$_updater_state/rust-events.jsonl" ] || [ -e "$_updater_state/events.jsonl" ] || [ -e "$_updater_state/rust-tip.json" ]; }; then
            if ! status_json="$("$recovery_bin" --install-root "$INSTALL_DIR" --state-dir "$_updater_state" status --json)"; then
                echo "   ✗ updater journal status check failed; reconcile updater state before continuing." >&2
                return 1
            fi
            if ! python3 - "$status_json" <<'PY'; then
import json, sys
s = json.loads(sys.argv[1])
if s.get("recovery_required") or s.get("database_reconciliation_required"):
    sys.stderr.write("   ✗ updater journal reports recovery_required or database_reconciliation_required; reconcile first.\n")
    sys.exit(1)
state = s.get("intent_state") or ""
if state and state not in ("verified", "failed", "rolled_back", "cancelled"):
    sys.stderr.write(f"   ✗ updater journal has non-terminal transaction state ({state!r}); finish or reconcile first.\n")
    sys.exit(1)
PY
                return 1
            fi
        elif [ -e "$_updater_state/rust-tip.json" ] || [ -s "$_updater_state/rust-events.jsonl" ] || [ -s "$_updater_state/events.jsonl" ]; then
            echo "   ✗ updater journal files exist in $_updater_state but $recovery_bin is unavailable; refusing cutover." >&2
            return 1
        fi
    fi
    return 0
}

verify_unified_readiness() {
    local ready_url jwks_url gw_addr https_probe attempt
    gw_addr="$(config_value "$SETJOIND_ENV" GATEWAY_LISTEN)"
    gw_addr="${gw_addr:-127.0.0.1:8090}"
    if tls_front_enabled "$CONFIG_ENV"; then
        https_probe="$(tls_front_probe_url "$CONFIG_ENV")"
        ready_url="${https_probe%/_gateway/healthz}/ready"
        jwks_url="${https_probe%/_gateway/healthz}/.well-known/jwks.json"
    else
        ready_url="http://${gw_addr}/ready"
        jwks_url="http://${gw_addr}/.well-known/jwks.json"
    fi
    for attempt in $(seq 1 30); do
        if curl -skf --max-time 3 "$ready_url" >/dev/null 2>&1; then
            local jwks_body=""
            if jwks_body="$(curl -skf --max-time 3 "$jwks_url" 2>/dev/null)" &&
               python3 - "$jwks_body" <<'PY' 2>/dev/null; then
import json, sys
doc = json.loads(sys.argv[1])
assert isinstance(doc.get("keys"), list)
PY
                echo "   setjoind ready after ${attempt} attempt(s)."
                return 0
            fi
        fi
        sleep 2
    done
    echo "   ✗ setjoind readiness check failed (/ready + /.well-known/jwks.json)." >&2
    return 1
}

if [ "$SUBCOMMAND" = "migrate-to-setjoind" ]; then
    echo "=== Setjoin Cutover: Split Units -> Unified setjoind ==="
    acquire_updater_lock_and_check_journal 1 || exit 1
    if [ -L "$INSTALL_DIR/current" ]; then
        RUNTIME_DIR="$INSTALL_DIR/current"
    else
        RUNTIME_DIR="$INSTALL_DIR"
    fi
    if [ -e "$SYSTEMD_DIR/setjoind.service" ] || [ -L "$SYSTEMD_DIR/setjoind.service" ]; then
        echo "   ✗ setjoind.service is already installed in $SYSTEMD_DIR; refusing duplicate or mixed cutover." >&2
        exit 1
    fi
    if [ ! -f "$SYSTEMD_DIR/setjoin-gateway.service" ] || [ ! -f "$SYSTEMD_DIR/setjoin-auth.service" ]; then
        echo "   ✗ split units (setjoin-gateway.service and setjoin-auth.service) must both exist in $SYSTEMD_DIR before cutover." >&2
        exit 1
    fi
    if [ ! -x "$RUNTIME_DIR/setjoind" ]; then
        echo "   ✗ missing executable $RUNTIME_DIR/setjoind; stage a Release N cohort first." >&2
        exit 1
    fi
    if [ -L "$INSTALL_DIR/current" ] && { [ -e "$INSTALL_DIR/previous" ] || [ -L "$INSTALL_DIR/previous" ]; } && [ "$ALLOW_SINGLE_COHORT" != "1" ]; then
        if [ ! -x "$INSTALL_DIR/previous/setjoind" ]; then
            echo "   ✗ $INSTALL_DIR/previous lacks setjoind; upgrade twice through Release N first or pass --allow-single-cohort." >&2
            exit 1
        fi
    fi
    validate_db_cred_file_posture "$DB_CRED_FILE" || exit 1
    if [ -f "$CONFIG_ENV" ] && grep -Eq '^[[:space:]]*(DB_OWNER_DSN|DB_DIRECT_OWNER_DSN)=' "$CONFIG_ENV"; then
        echo "   ✗ $CONFIG_ENV contains DB_OWNER_DSN or DB_DIRECT_OWNER_DSN; complete DEPLOY-004 credential split / mailctl schema provision-roles before cutover." >&2
        exit 1
    fi
    check_no_retired_acme_config "$CONFIG_ENV" || exit 1
    if [ -L "$CUTOVER_PREV" ]; then
        echo "   ✗ $CUTOVER_PREV is a symlink; refusing unsafe snapshot path." >&2
        exit 1
    fi
    rm -rf "$CUTOVER_PREV"
    ( umask 077; mkdir -p "$CUTOVER_PREV/units" "$CUTOVER_PREV/config" )
    chmod 0700 "$CUTOVER_PREV"
    if [ "$(id -u)" = 0 ]; then chown root:root "$CUTOVER_PREV"; fi
    for file in setjoin-gateway.service setjoin-auth.service "${ALL_SERVER_SOCKETS[@]}"; do
        if [ -e "$SYSTEMD_DIR/$file" ] || [ -L "$SYSTEMD_DIR/$file" ]; then
            cp -a "$SYSTEMD_DIR/$file" "$CUTOVER_PREV/units/"
        fi
    done
    : > "$CUTOVER_PREV/enabled-sockets"
    : > "$CUTOVER_PREV/active-sockets"
    for sock in "${ALL_SERVER_SOCKETS[@]}"; do
        if [ -e "$SYSTEMD_DIR/$sock" ]; then
            sock_state=""
            if sock_state="$(systemctl is-enabled "$sock" 2>/dev/null)"; then
                case "$sock_state" in
                    enabled-runtime) printf 'enabled-runtime %s\n' "$sock" >> "$CUTOVER_PREV/enabled-sockets" ;;
                    enabled|'') printf 'enabled %s\n' "$sock" >> "$CUTOVER_PREV/enabled-sockets" ;;
                esac
            fi
            if systemctl is-active --quiet "$sock" 2>/dev/null; then
                printf '%s\n' "$sock" >> "$CUTOVER_PREV/active-sockets"
            fi
        fi
    done
    for file in config.env auth.env gateway.env federation.env storage.env smtp.env tls.env; do
        if [ -e "${CONFIG_ENV%/*}/$file" ]; then
            cp -a "${CONFIG_ENV%/*}/$file" "$CUTOVER_PREV/config/"
        fi
    done

    rollback_cutover_and_exit() {
        echo "   Rolling back failed setjoind cutover to split units..." >&2
        local s f mode
        for s in "${ALL_SERVER_SOCKETS[@]}"; do
            if [ -e "$SYSTEMD_DIR/$s" ]; then
                systemctl stop "$s" || true
                systemctl disable "$s" || true
            fi
        done
        systemctl stop setjoind || true
        systemctl disable setjoind || true
        rm -f "$SYSTEMD_DIR/setjoind.service" "$SETJOIND_ENV" "$SETJOIND_AUTH_ENV"
        for f in setjoin-gateway.service setjoin-auth.service "${ALL_SERVER_SOCKETS[@]}"; do
            rm -f "$SYSTEMD_DIR/$f"
            if [ -e "$CUTOVER_PREV/units/$f" ] || [ -L "$CUTOVER_PREV/units/$f" ]; then
                cp -a "$CUTOVER_PREV/units/$f" "$SYSTEMD_DIR/"
            fi
        done
        for f in config.env auth.env gateway.env federation.env storage.env smtp.env tls.env; do
            rm -f "${CONFIG_ENV%/*}/$f"
            if [ -e "$CUTOVER_PREV/config/$f" ]; then
                cp -a "$CUTOVER_PREV/config/$f" "${CONFIG_ENV%/*}/"
            fi
        done
        systemctl daemon-reload || true
        while IFS=' ' read -r mode s; do
            [ -n "$s" ] || continue
            if [ "$mode" = enabled-runtime ]; then
                systemctl enable --runtime "$s" || true
            else
                systemctl enable "$s" || true
            fi
        done < "$CUTOVER_PREV/enabled-sockets"
        while IFS= read -r s; do
            [ -n "$s" ] || continue
            systemctl start "$s" || true
        done < "$CUTOVER_PREV/active-sockets"
        systemctl enable setjoin-auth || true
        systemctl enable setjoin-gateway || true
        systemctl start setjoin-auth || true
        systemctl start setjoin-gateway || true
        rm -rf "$CUTOVER_PREV"
        exit 1
    }

    # Stop ALL 9 sockets FIRST so systemd cannot reactivate setjoin-gateway mid-cutover.
    for sock in "${ALL_SERVER_SOCKETS[@]}"; do
        if [ -e "$SYSTEMD_DIR/$sock" ]; then
            systemctl stop "$sock" || rollback_cutover_and_exit
        fi
    done
    systemctl stop setjoin-gateway || rollback_cutover_and_exit
    systemctl stop setjoin-auth || rollback_cutover_and_exit
    systemctl disable setjoin-gateway || rollback_cutover_and_exit
    systemctl disable setjoin-auth || rollback_cutover_and_exit

    if ! RUNTIME_DIR="$RUNTIME_DIR" render_setjoind_deployment; then
        rollback_cutover_and_exit
    fi
    rm -f "$SYSTEMD_DIR/setjoin-gateway.service" "$SYSTEMD_DIR/setjoin-auth.service"
    systemctl daemon-reload || rollback_cutover_and_exit
    systemctl enable setjoin-gateway.socket || rollback_cutover_and_exit
    systemctl start setjoin-gateway.socket || rollback_cutover_and_exit
    for sock in "${ALL_SERVER_SOCKETS[@]}"; do
        [ "$sock" = setjoin-gateway.socket ] && continue
        if [ -f "$SYSTEMD_DIR/$sock" ]; then
            systemctl enable "$sock" || rollback_cutover_and_exit
            systemctl start "$sock" || rollback_cutover_and_exit
        fi
    done
    systemctl enable setjoind || rollback_cutover_and_exit
    systemctl start setjoind || rollback_cutover_and_exit

    if ! verify_unified_readiness; then
        rollback_cutover_and_exit
    fi
    # Purge secret env copies so stale credentials never linger on disk.
    rm -rf "$CUTOVER_PREV/config" "$CUTOVER_PREV/units"
    echo "Cutover to unified setjoind.service succeeded."
    exit 0
fi

if [ "$SUBCOMMAND" = "rollback-to-split-units" ]; then
    echo "=== Setjoin Reverse Cutover: Unified setjoind -> Split Units ==="
    acquire_updater_lock_and_check_journal 1 || exit 1
    if [ -L "$INSTALL_DIR/current" ]; then
        RUNTIME_DIR="$INSTALL_DIR/current"
    else
        RUNTIME_DIR="$INSTALL_DIR"
    fi
    if [ ! -f "$SYSTEMD_DIR/setjoind.service" ]; then
        echo "   ✗ setjoind.service is not installed in $SYSTEMD_DIR." >&2
        exit 1
    fi
    if [ -e "$SYSTEMD_DIR/setjoin-gateway.service" ] || [ -e "$SYSTEMD_DIR/setjoin-auth.service" ]; then
        echo "   ✗ mixed unit topology detected in $SYSTEMD_DIR; resolve manually before rollback." >&2
        exit 1
    fi
    if [ ! -x "$RUNTIME_DIR/setjoin-server" ] || [ ! -x "$RUNTIME_DIR/setjoin-auth" ]; then
        echo "   ✗ $RUNTIME_DIR lacks setjoin-server or setjoin-auth shims; cannot return to split units." >&2
        exit 1
    fi
    validate_db_cred_file_posture "$DB_CRED_FILE" || exit 1
    check_no_retired_acme_config "$CONFIG_ENV" || exit 1

    # Stop ALL 9 sockets FIRST, then stop and remove setjoind.service.
    for sock in "${ALL_SERVER_SOCKETS[@]}"; do
        if [ -e "$SYSTEMD_DIR/$sock" ]; then
            systemctl stop "$sock" || true
            systemctl disable "$sock" || true
        fi
    done
    systemctl stop setjoind || true
    systemctl disable setjoind || true
    rm -f "$SYSTEMD_DIR/setjoind.service" "$SETJOIND_ENV" "$SETJOIND_AUTH_ENV"

    # Re-render split units & env files from LIVE config.env + db-credentials.env.
    if ! RUNTIME_DIR="$RUNTIME_DIR" render_gateway_deployment; then
        echo "   ✗ failed to re-render split units from live configuration." >&2
        exit 1
    fi
    systemctl daemon-reload
    systemctl enable setjoin-gateway.socket
    systemctl start setjoin-gateway.socket
    for sock in "${ALL_SERVER_SOCKETS[@]}"; do
        [ "$sock" = setjoin-gateway.socket ] && continue
        if [ -f "$SYSTEMD_DIR/$sock" ]; then
            systemctl enable "$sock"
            systemctl start "$sock"
        fi
    done
    systemctl enable setjoin-auth
    systemctl enable setjoin-gateway
    systemctl start setjoin-auth
    systemctl start setjoin-gateway

    AUTH_LISTEN_ADDR="$(config_value "$AUTH_ENV" LISTEN_ADDR)"
    AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-127.0.0.1:8443}"
    GATEWAY_ADDR="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
    GATEWAY_ADDR="${GATEWAY_ADDR:-127.0.0.1:8090}"
    READY_URL="http://${GATEWAY_ADDR}/ready"
    if tls_front_enabled "$CONFIG_ENV"; then
        HTTPS_BASE="$(tls_front_probe_url "$CONFIG_ENV")"
        READY_URL="${HTTPS_BASE%/_gateway/healthz}/ready"
    fi
    SPLIT_READY=0
    for attempt in $(seq 1 30); do
        if curl -skf --max-time 3 "$READY_URL" >/dev/null 2>&1 &&
           curl -sf --max-time 3 "http://${AUTH_LISTEN_ADDR}/health" >/dev/null 2>&1; then
            SPLIT_READY=1
            echo "   Split units ready after ${attempt} attempt(s)."
            break
        fi
        sleep 2
    done
    if [ "$SPLIT_READY" != "1" ]; then
        echo "   ✗ Split unit readiness check failed after rollback." >&2
        exit 1
    fi
    echo "Reverse cutover to split units succeeded."
    exit 0
fi

if [ "$REFRESH_GATEWAY_ENV" = 1 ]; then
    acquire_updater_lock_and_check_journal 0 || exit 1
    RUNTIME_DIR="$INSTALL_DIR/current"
    if [ -e "$SYSTEMD_DIR/setjoind.service" ] || [ -L "$SYSTEMD_DIR/setjoind.service" ]; then
        if [ -e "$SYSTEMD_DIR/setjoin-gateway.service" ] || [ -e "$SYSTEMD_DIR/setjoin-auth.service" ]; then
            echo "   ✗ mixed unit topology: setjoind.service coexists with split units in $SYSTEMD_DIR." >&2
            exit 1
        fi
        check_no_retired_acme_config "$CONFIG_ENV" || exit 1
        backup_gateway_deployment
        if ! RUNTIME_DIR="$RUNTIME_DIR" render_setjoind_deployment; then
            echo "   ✗ setjoind unit/config refresh failed." >&2
            restore_gateway_refresh || true
            exit 1
        fi
        exit 0
    fi
    check_no_retired_acme_config "$CONFIG_ENV" || exit 1
    backup_gateway_deployment
    if ! RUNTIME_DIR="$RUNTIME_DIR" render_gateway_deployment; then
        echo "   ✗ gateway unit/config refresh failed." >&2
        restore_gateway_refresh || true
        exit 1
    fi
    exit 0
fi

# resolve_schema_dsn CONFIG_ENV CRED_FILE — print the DSN schema apply/preflight
# should run under, honoring the DEPLOY-004 privileged-DSN split. DDL runs as
# the OWNER identity: under the constrained native-RLS shape install.sh writes
# (DB_DSN = setjoin_app), applying migrations over DB_DSN would create
# app-owned tables — runbook footgun #1 (docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md).
# Preference order: the owner tiers from the root-owned credential file
# (direct, then pooled — where a split install keeps them), then the
# pre-split config.env owner copies, then the legacy fallbacks
# (DB_DIRECT_DSN/DB_DSN — for pre-DEPLOY-004 hosts where those hold the owner).
# Refusal contract: when CRED_FILE exists but fails its installed namespace
# posture (symlink, widened mode, wrong owner, substituted or runtime-writable
# parent directory), this function returns 1 WITHOUT a fallback.
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
            val="$(strip_env_quotes "$val")"
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
            val="$(strip_env_quotes "$val")"
            if [ -n "$val" ]; then
                printf '%s\n' "$val"
                return 0
            fi
        done
    fi
    return 0
}

# run_rls_preflight_gate MAILCTL_BIN SCHEMA_DSN — run fail-closed `mailctl
# schema preflight` with runtime DB_DSN (from CONFIG_ENV) and DB_WORKER_DSN
# (from DB_CRED_FILE, falling back to CONFIG_ENV ONLY when DB_CRED_FILE does
# not exist on legacy pre-DEPLOY-004 hosts), normalized via strip_env_quotes
# and supplied strictly via process environment (never argv or echoed logs).
run_rls_preflight_gate() {
    local mailctl_bin="$1" schema_dsn="$2"
    local app_dsn="" worker_dsn="" raw_val=""
    if [ -f "$CONFIG_ENV" ]; then
        raw_val="$(grep -E '^DB_DSN=' "$CONFIG_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        app_dsn="$(strip_env_quotes "$raw_val")"
    fi
    if [ -e "$DB_CRED_FILE" ] || [ -L "$DB_CRED_FILE" ]; then
        # Posture was already verified by resolve_schema_dsn; never fall back to
        # CONFIG_ENV when DB_CRED_FILE exists.
        raw_val="$(grep -E '^DB_WORKER_DSN=' "$DB_CRED_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        worker_dsn="$(strip_env_quotes "$raw_val")"
    elif [ -f "$CONFIG_ENV" ]; then
        # Legacy pre-DEPLOY-004 fallback ONLY when DB_CRED_FILE does not exist.
        raw_val="$(grep -E '^DB_WORKER_DSN=' "$CONFIG_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        worker_dsn="$(strip_env_quotes "$raw_val")"
    fi
    DB_DIRECT_OWNER_DSN="$schema_dsn" \
    DB_OWNER_DSN="$schema_dsn" \
    DB_DSN="$app_dsn" \
    DB_WORKER_DSN="$worker_dsn" \
        "$mailctl_bin" schema preflight
}

echo "=== Setjoin Server Upgrade ==="
check_no_retired_acme_config "$CONFIG_ENV" || exit 1
# Wave 1.9 (#547): Pre-stop / pre-swap fail-closed native-RLS & PG CVE-2026-14666
# gate BEFORE Step 1 so doomed upgrades fail with zero downtime and zero DDL.
echo "0. Pre-flight native-RLS and PostgreSQL version check (before stopping services)..."
if ! PREFLIGHT_SCHEMA_DSN="$(resolve_schema_dsn "$CONFIG_ENV" "$DB_CRED_FILE" "${DB_CRED_WANT_OWNER:-root}" "${DB_CRED_WANT_GROUP:-root}" "${DB_CRED_RUNTIME_GROUP:-setjoin}")"; then
    echo "   ✗ privileged DB credential namespace failed validation — aborting before stopping services." >&2
    exit 1
fi
PREFLIGHT_MAILCTL=""
if [ -n "$NEW_MAILCTL" ] && [ -x "$NEW_MAILCTL" ]; then
    PREFLIGHT_MAILCTL="$NEW_MAILCTL"
elif [ -x "$INSTALL_DIR/mailctl" ]; then
    PREFLIGHT_MAILCTL="$INSTALL_DIR/mailctl"
elif command -v mailctl >/dev/null 2>&1; then
    PREFLIGHT_MAILCTL="$(command -v mailctl)"
fi
if [ -n "$PREFLIGHT_MAILCTL" ] && [ -n "$PREFLIGHT_SCHEMA_DSN" ]; then
    _preflight_rc=0
    run_rls_preflight_gate "$PREFLIGHT_MAILCTL" "$PREFLIGHT_SCHEMA_DSN" || _preflight_rc=$?
    if [ "$_preflight_rc" -ne 0 ]; then
        echo "   ✗ pre-stop native-RLS preflight FAILED (exit $_preflight_rc) — aborting upgrade before stopping services or swapping binaries." >&2
        exit 1
    fi
fi

backup_gateway_deployment

LEGACY_SETJOIN_PRESENT=0
HAD_SERVER=0
HAD_LEGACY_GATEWAY=0
HAD_LEGACY_MAILSERVER=0
HAD_MAILCTL=0
HAD_AUTH=0
HAD_LEGACY_AUTHSERVER=0
HAD_SETJOIND=0

echo "1. Stopping services..."
# Stop the front door before changing its upstreams or descriptor set.
systemctl stop setjoin-gateway
systemctl stop setjoin-federation.socket || true
for file in setjoin-https.socket setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
    systemctl stop "$file" || true
    systemctl disable "$file" || true
done
if [ -e "$SYSTEMD_DIR/setjoin-acme.socket" ] || [ -L "$SYSTEMD_DIR/setjoin-acme.socket" ]; then
    # Pre-#560 cutover: retire legacy :80 ACME socket (backed up in $DEPLOYMENT_PREV/units/).
    systemctl stop setjoin-acme.socket || true
    systemctl disable setjoin-acme.socket || true
    rm -f "$SYSTEMD_DIR/setjoin-acme.socket"
fi
LEGACY_GO_UNIT="setjoin"
if [ -e "$SYSTEMD_DIR/${LEGACY_GO_UNIT}.service" ] || [ -L "$SYSTEMD_DIR/${LEGACY_GO_UNIT}.service" ]; then
    # Pre-#142 cutover: retire legacy Go unit (backed up in $DEPLOYMENT_PREV/units/).
    LEGACY_SETJOIN_PRESENT=1
    systemctl stop "$LEGACY_GO_UNIT" || true
    systemctl disable "$LEGACY_GO_UNIT" || true
    rm -f "$SYSTEMD_DIR/${LEGACY_GO_UNIT}.service"
fi
if [ -n "$NEW_AUTH" ]; then
    if systemctl is-active --quiet setjoin-auth; then
        AUTH_WAS_ACTIVE=1
    fi
    systemctl stop setjoin-auth
fi

echo "2. Backing up current binaries..."
if [ -f "$INSTALL_DIR/setjoin-server" ]; then
    HAD_SERVER=1
    cp "$INSTALL_DIR/setjoin-server" "$INSTALL_DIR/setjoin-server.prev"
fi
if [ -f "$INSTALL_DIR/setjoin-gateway" ]; then
    HAD_LEGACY_GATEWAY=1
    cp "$INSTALL_DIR/setjoin-gateway" "$INSTALL_DIR/setjoin-gateway.prev"
fi
if [ -f "$INSTALL_DIR/mailserverd" ]; then
    HAD_LEGACY_MAILSERVER=1
    cp "$INSTALL_DIR/mailserverd" "$INSTALL_DIR/mailserverd.prev"
fi
if [ -f "$INSTALL_DIR/mailctl" ]; then
    HAD_MAILCTL=1
    cp "$INSTALL_DIR/mailctl" "$INSTALL_DIR/mailctl.prev"
fi
if [ -n "$NEW_AUTH" ] && [ -f "$INSTALL_DIR/setjoin-auth" ]; then
    HAD_AUTH=1
    cp "$INSTALL_DIR/setjoin-auth" "$INSTALL_DIR/setjoin-auth.prev"
fi
if [ -n "$NEW_AUTH" ] && [ -f "$INSTALL_DIR/authserverd" ]; then
    HAD_LEGACY_AUTHSERVER=1
    cp "$INSTALL_DIR/authserverd" "$INSTALL_DIR/authserverd.prev"
fi
if [ -n "$NEW_SETJOIND" ] && [ -f "$INSTALL_DIR/setjoind" ]; then
    HAD_SETJOIND=1
    cp "$INSTALL_DIR/setjoind" "$INSTALL_DIR/setjoind.prev"
fi
if [ -n "$NEW_WEBMAIL" ] && [ -d "$INSTALL_DIR/webmail" ]; then
    HAD_WEBMAIL=1
    rm -rf "$INSTALL_DIR/webmail.prev"
    cp -a "$INSTALL_DIR/webmail" "$INSTALL_DIR/webmail.prev"
fi

echo "3. Installing new binary..."
cp "$NEW_SERVER" "$INSTALL_DIR/setjoin-server"
chmod 755 "$INSTALL_DIR/setjoin-server"
chown setjoin:setjoin "$INSTALL_DIR/setjoin-server"
if [ "$HAD_LEGACY_GATEWAY" = "1" ]; then
    rm -f "$INSTALL_DIR/setjoin-gateway"
fi
if [ "$HAD_LEGACY_MAILSERVER" = "1" ]; then
    rm -f "$INSTALL_DIR/mailserverd"
fi
if [ -n "$NEW_MAILCTL" ] && [ -f "$NEW_MAILCTL" ]; then
    cp "$NEW_MAILCTL" "$INSTALL_DIR/mailctl"
    chmod 755 "$INSTALL_DIR/mailctl"
    chown setjoin:setjoin "$INSTALL_DIR/mailctl"
fi
if [ -n "$NEW_AUTH" ]; then
    cp "$NEW_AUTH" "$INSTALL_DIR/setjoin-auth"
    chmod 755 "$INSTALL_DIR/setjoin-auth"
    chown setjoin:setjoin "$INSTALL_DIR/setjoin-auth"
    if [ "$HAD_LEGACY_AUTHSERVER" = "1" ]; then
        rm -f "$INSTALL_DIR/authserverd"
    fi
fi
if [ -n "$NEW_SETJOIND" ]; then
    cp "$NEW_SETJOIND" "$INSTALL_DIR/setjoind"
    chmod 755 "$INSTALL_DIR/setjoind"
fi
if [ -n "$NEW_WEBMAIL" ]; then
    rm -rf "$INSTALL_DIR/webmail.new"
    mkdir -p "$INSTALL_DIR/webmail.new"
    cp -a "$NEW_WEBMAIL"/. "$INSTALL_DIR/webmail.new/"
    chown -R setjoin:setjoin "$INSTALL_DIR/webmail.new"
    rm -rf "$INSTALL_DIR/webmail"
    mv "$INSTALL_DIR/webmail.new" "$INSTALL_DIR/webmail"
fi

# roll_back_and_exit — restore the previous binaries, units, and config, restart,
# and exit non-zero. Used when a pre-start step or readiness check fails so the
# service is never left DOWN (it was stopped at step 1).
roll_back_and_exit() {
    echo "   Rolling back to the previous version and restarting..."
    if [ "$HAD_SERVER" = "1" ] && [ -f "$INSTALL_DIR/setjoin-server.prev" ]; then
        cp "$INSTALL_DIR/setjoin-server.prev" "$INSTALL_DIR/setjoin-server"
    else
        rm -f "$INSTALL_DIR/setjoin-server"
    fi
    if [ "$HAD_LEGACY_GATEWAY" = "1" ] && [ -f "$INSTALL_DIR/setjoin-gateway.prev" ]; then
        cp "$INSTALL_DIR/setjoin-gateway.prev" "$INSTALL_DIR/setjoin-gateway"
    fi
    if [ "$HAD_LEGACY_MAILSERVER" = "1" ] && [ -f "$INSTALL_DIR/mailserverd.prev" ]; then
        cp "$INSTALL_DIR/mailserverd.prev" "$INSTALL_DIR/mailserverd"
    fi
    if [ "$HAD_MAILCTL" = "1" ] && [ -f "$INSTALL_DIR/mailctl.prev" ]; then
        cp "$INSTALL_DIR/mailctl.prev" "$INSTALL_DIR/mailctl"
    fi
    if [ -n "$NEW_AUTH" ]; then
        if [ "$HAD_AUTH" = "1" ] && [ -f "$INSTALL_DIR/setjoin-auth.prev" ]; then
            cp "$INSTALL_DIR/setjoin-auth.prev" "$INSTALL_DIR/setjoin-auth"
        else
            rm -f "$INSTALL_DIR/setjoin-auth"
        fi
        if [ "$HAD_LEGACY_AUTHSERVER" = "1" ] && [ -f "$INSTALL_DIR/authserverd.prev" ]; then
            cp "$INSTALL_DIR/authserverd.prev" "$INSTALL_DIR/authserverd"
        fi
    fi
    if [ -n "$NEW_SETJOIND" ]; then
        if [ "$HAD_SETJOIND" = "1" ] && [ -f "$INSTALL_DIR/setjoind.prev" ]; then
            cp "$INSTALL_DIR/setjoind.prev" "$INSTALL_DIR/setjoind"
        else
            rm -f "$INSTALL_DIR/setjoind"
        fi
    fi
    if [ -n "$NEW_WEBMAIL" ]; then
        rm -rf "$INSTALL_DIR/webmail"
        if [ "$HAD_WEBMAIL" = "1" ] && [ -d "$INSTALL_DIR/webmail.prev" ]; then
            cp -a "$INSTALL_DIR/webmail.prev" "$INSTALL_DIR/webmail"
        fi
    fi
    local restore_rc=0
    restore_gateway_deployment || restore_rc=$?
    if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
        systemctl start setjoin-auth || restore_rc=1
    fi
    if [ "$LEGACY_SETJOIN_PRESENT" = "1" ] && [ -f "$DEPLOYMENT_PREV/setjoin.service-active" ]; then
        systemctl start "$LEGACY_GO_UNIT" || restore_rc=1
    fi
    systemctl start setjoin-gateway || restore_rc=1
    if [ "$restore_rc" != 0 ]; then
        echo "   ✗ Incomplete rollback: failed to restore one or more deployment files, sockets, or services; inspect systemd units before retrying." >&2
    else
        echo "   Restored previous version. Fix the issue, then re-run the upgrade."
    fi
    exit 1
}

echo "3.5. Applying pending DB schema migrations (before start)..."
if ! SCHEMA_DSN="$(resolve_schema_dsn "$CONFIG_ENV" "$DB_CRED_FILE" "${DB_CRED_WANT_OWNER:-root}" "${DB_CRED_WANT_GROUP:-root}" "${DB_CRED_RUNTIME_GROUP:-setjoin}")"; then
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
        # Wave 1.9 (#547): defense-in-depth post-apply fail-closed preflight
        # (catches newly applied migrations introducing unforced RLS or drifted
        # SECURITY DEFINER helpers; any non-zero exit rolls back immediately).
        _preflight_rc=0
        run_rls_preflight_gate "$MAILCTL_BIN" "$SCHEMA_DSN" || _preflight_rc=$?
        if [ "$_preflight_rc" -ne 0 ]; then
            echo "   ✗ native-RLS preflight FAILED (exit $_preflight_rc) — rolling back."
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

# Render only with the new server: an old binary cannot consume the new FD.
if ! render_gateway_deployment; then
    echo "   ✗ gateway unit/config render failed."
    roll_back_and_exit
fi

echo "4. Starting services..."
if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
    systemctl start setjoin-auth || roll_back_and_exit
fi
systemctl start setjoin-gateway || roll_back_and_exit

echo "5. Waiting for service readiness (up to 60 seconds)..."
LISTEN_ADDR_CFG="$(grep -E '^LISTEN_ADDR=' "$CONFIG_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
LISTEN_ADDR_CFG="${LISTEN_ADDR_CFG:-:443}"
AUTH_LISTEN_ADDR="$(grep -E '^LISTEN_ADDR=' "$AUTH_ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-127.0.0.1:8443}"
GATEWAY_ADDR="$(config_value "$GATEWAY_ENV" GATEWAY_LISTEN)"
GATEWAY_ADDR="${GATEWAY_ADDR:-127.0.0.1:8090}"
TLS_PROBE_URL=""
PRIMARY_READY_URL="https://127.0.0.1${LISTEN_ADDR_CFG}/ready"
if tls_front_enabled "$CONFIG_ENV"; then
    TLS_PROBE_URL=$(tls_front_probe_url "$CONFIG_ENV")
    PRIMARY_READY_URL="http://${GATEWAY_ADDR}/ready"
fi
READY=0
for attempt in $(seq 1 30); do
    AUTH_HEALTHY=1
    if [ "$AUTH_WAS_ACTIVE" = "1" ]; then
        curl -sf --max-time 3 "http://${AUTH_LISTEN_ADDR}/ready" >/dev/null ||
            AUTH_HEALTHY=0
    fi
    GATEWAY_HEALTHY=1
    curl -sf --max-time 3 "http://${GATEWAY_ADDR}/_gateway/healthz" >/dev/null ||
        GATEWAY_HEALTHY=0
    if [ -n "$TLS_PROBE_URL" ]; then
        curl -skf --max-time 3 "$TLS_PROBE_URL" >/dev/null || GATEWAY_HEALTHY=0
    fi
    if { curl -skf --max-time 3 "$PRIMARY_READY_URL" >/dev/null ||
         curl -sf --max-time 3 "http://${GATEWAY_ADDR}/ready" >/dev/null; } &&
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
