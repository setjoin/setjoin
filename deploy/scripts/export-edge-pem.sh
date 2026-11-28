#!/usr/bin/env bash
# export-edge-pem.sh — Atomic, DANE-safe PEM exporter from an edge TLS/ACME
# terminator (Caddy, certbot, etc.) into Setjoin's TLS directory (#559).
#
# Defaults:
#   DEST_DIR=/etc/mail/tls (must be 0750 root:setjoin, no symlinks on any ancestor)
#   TLS_OWNER=root:setjoin
#   DANE_ENFORCE_KEY_PIN=1 (fail closed if SPKI SHA-256 changes without --allow-key-rotation)
#
# Usage:
#   export-edge-pem.sh --cert <fullchain.pem> --key <privkey.pem> \
#     [--dest-dir /etc/mail/tls] [--owner root:setjoin] [--lock-file <path>] \
#     [--allow-key-rotation]
set -euo pipefail

SOURCE_CERT="${SOURCE_CERT:-}"
SOURCE_KEY="${SOURCE_KEY:-}"
DEST_DIR="${DEST_DIR:-/etc/mail/tls}"
TLS_OWNER="${TLS_OWNER:-root:setjoin}"
LOCK_FILE="${LOCK_FILE:-}"
DANE_ENFORCE_KEY_PIN="${DANE_ENFORCE_KEY_PIN:-1}"
ALLOW_KEY_ROTATION="${ALLOW_KEY_ROTATION:-0}"

usage() {
  cat <<'EOF'
Usage: export-edge-pem.sh --cert <path> --key <path> [options]

Options:
  --cert <path>          Source fullchain PEM (or SOURCE_CERT env)
  --key <path>           Source private key PEM (or SOURCE_KEY env)
  --dest-dir <dir>       Destination directory (default: /etc/mail/tls, DEST_DIR)
  --owner <user:group>   Ownership when run as root (default: root:setjoin, TLS_OWNER)
  --lock-file <path>     Exclusive lock path (default: <dest-dir>/.export-edge-pem.lock, LOCK_FILE)
  --allow-key-rotation   Permit DANE-EE SPKI key change (or ALLOW_KEY_ROTATION=1)
  -h, --help             Show this help
EOF
}

ORIG_ARGS=("$@")
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cert)
      [ "$#" -ge 2 ] || {
        echo "export-edge-pem: --cert requires a value" >&2
        exit 2
      }
      SOURCE_CERT="$2"
      shift 2
      ;;
    --key)
      [ "$#" -ge 2 ] || {
        echo "export-edge-pem: --key requires a value" >&2
        exit 2
      }
      SOURCE_KEY="$2"
      shift 2
      ;;
    --dest-dir)
      [ "$#" -ge 2 ] || {
        echo "export-edge-pem: --dest-dir requires a value" >&2
        exit 2
      }
      DEST_DIR="$2"
      shift 2
      ;;
    --owner)
      [ "$#" -ge 2 ] || {
        echo "export-edge-pem: --owner requires a value" >&2
        exit 2
      }
      TLS_OWNER="$2"
      shift 2
      ;;
    --lock-file)
      [ "$#" -ge 2 ] || {
        echo "export-edge-pem: --lock-file requires a value" >&2
        exit 2
      }
      LOCK_FILE="$2"
      shift 2
      ;;
    --allow-key-rotation)
      ALLOW_KEY_ROTATION=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "export-edge-pem: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$SOURCE_CERT" ] || [ -z "$SOURCE_KEY" ]; then
  echo "export-edge-pem: --cert and --key are required" >&2
  exit 2
fi

DEST_DIR="${DEST_DIR%/}"
if [ -z "$DEST_DIR" ]; then
  echo "export-edge-pem: refusing root directory as --dest-dir" >&2
  exit 2
fi

if [ -z "$LOCK_FILE" ]; then
  LOCK_FILE="$DEST_DIR/.export-edge-pem.lock"
fi

# Validate destination directory, every ancestor component (no symlinks,
# root-owned when uid=0, no group/world write on DEST_DIR), and existing target
# files BEFORE touching or locking anything inside DEST_DIR.
validate_dest_tree() {
  python3 - "$DEST_DIR" "$LOCK_FILE" <<'PY'
import os, stat, sys

dest = sys.argv[1]
lock_file = sys.argv[2]

if not dest.startswith("/") or dest == "/":
    sys.stderr.write(f"export-edge-pem: destination directory must be a non-root absolute path: {dest}\n")
    sys.exit(1)

parts = [p for p in dest.split("/") if p]
is_root = hasattr(os, "geteuid") and os.geteuid() == 0
dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

try:
    cur_fd = os.open("/", dir_flags)
except OSError as exc:
    sys.stderr.write(f"export-edge-pem: cannot open /: {exc}\n")
    sys.exit(1)

try:
    for idx, seg in enumerate(parts):
        is_last = idx == len(parts) - 1
        if is_root:
            pst = os.fstat(cur_fd)
            if pst.st_uid != 0:
                sys.stderr.write(f"export-edge-pem: untrusted non-root ancestor before {seg!r}\n")
                sys.exit(1)
            if (pst.st_mode & 0o002) != 0:
                sys.stderr.write(f"export-edge-pem: world-writable ancestor before {seg!r}\n")
                sys.exit(1)
        try:
            nxt = os.open(seg, dir_flags, dir_fd=cur_fd)
        except OSError as exc:
            sys.stderr.write(f"export-edge-pem: unsafe or missing directory component {seg!r} in {dest}: {exc}\n")
            sys.exit(1)
        os.close(cur_fd)
        cur_fd = nxt
        if is_last:
            st = os.fstat(cur_fd)
            if not stat.S_ISDIR(st.st_mode):
                sys.stderr.write(f"export-edge-pem: destination is not a directory: {dest}\n")
                sys.exit(1)
            if is_root and st.st_uid != 0:
                sys.stderr.write(
                    f"export-edge-pem: destination directory {dest} must be owned by root (uid=0), found uid={st.st_uid}\n"
                )
                sys.exit(1)
            if (st.st_mode & 0o022) != 0:
                sys.stderr.write(
                    f"export-edge-pem: destination directory {dest} must not be group- or world-writable (mode={oct(st.st_mode & 0o7777)})\n"
                )
                sys.exit(1)
            for fname in ("server.pem", "server-key.pem"):
                try:
                    fst = os.stat(fname, dir_fd=cur_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(fst.st_mode) or not stat.S_ISREG(fst.st_mode):
                    sys.stderr.write(
                        f"export-edge-pem: refusing symlink or non-regular destination file: {dest}/{fname}\n"
                    )
                    sys.exit(1)
finally:
    os.close(cur_fd)

lock_parent = os.path.dirname(lock_file)
if not lock_file.startswith("/") or not lock_parent:
    sys.stderr.write(f"export-edge-pem: lock file must be an absolute path: {lock_file}\n")
    sys.exit(1)

if lock_parent != dest:
    lparts = [p for p in lock_parent.split("/") if p]
    lfd = os.open("/", dir_flags)
    try:
        for seg in lparts:
            if is_root:
                pst = os.fstat(lfd)
                if pst.st_uid != 0 or (pst.st_mode & 0o002) != 0:
                    sys.stderr.write(f"export-edge-pem: untrusted lock parent before {seg!r}\n")
                    sys.exit(1)
            try:
                nxt = os.open(seg, dir_flags, dir_fd=lfd)
            except OSError as exc:
                sys.stderr.write(f"export-edge-pem: unsafe or missing lock parent {seg!r} in {lock_file}: {exc}\n")
                sys.exit(1)
            os.close(lfd)
            lfd = nxt
        lpst = os.fstat(lfd)
        if not stat.S_ISDIR(lpst.st_mode) or (lpst.st_mode & 0o022) != 0:
            sys.stderr.write(f"export-edge-pem: lock parent {lock_parent} must be a non-group/world-writable directory\n")
            sys.exit(1)
    finally:
        os.close(lfd)

try:
    lst = os.lstat(lock_file)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        sys.stderr.write(f"export-edge-pem: refusing symlink or non-regular lock file: {lock_file}\n")
        sys.exit(1)
except FileNotFoundError:
    pass
PY
}

validate_dest_tree

# Acquire an exclusive lock so rapid systemd .path triggers while Caddy writes
# .crt and .key separately cannot race. Opens lock with O_NOFOLLOW via Python
# fcntl.flock so custom --lock-file paths cannot be redirected via symlink race.
if [ "${_EXPORT_EDGE_PEM_LOCKED:-0}" != "1" ]; then
  export _EXPORT_EDGE_PEM_LOCKED=1
  exec python3 - "$LOCK_FILE" "$0" "${ORIG_ARGS[@]}" <<'PY'
import fcntl, os, stat, subprocess, sys

lock_path = sys.argv[1]
script = sys.argv[2]
args = sys.argv[3:]
flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(lock_path, flags, 0o600)
try:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        sys.stderr.write(f"export-edge-pem: lock file is not regular: {lock_path}\n")
        sys.exit(1)
    fcntl.flock(fd, fcntl.LOCK_EX)
    res = subprocess.run(["bash", script, *args])
    sys.exit(res.returncode)
finally:
    os.close(fd)
PY
fi

# Re-validate destination tree under the exclusive lock.
validate_dest_tree

tmp_cert=""
tmp_key=""
cleanup() {
  [ -n "$tmp_cert" ] && rm -f "$tmp_cert" || true
  [ -n "$tmp_key" ] && rm -f "$tmp_key" || true
}
trap cleanup EXIT

# Stage dereferenced source PEM bytes into root-only 0600 temp files inside
# DEST_DIR FIRST (TOCTOU-free, bounded to 1 MiB, regular files only).
umask 077
tmp_cert="$(mktemp "$DEST_DIR/.server.pem.XXXXXX")"
tmp_key="$(mktemp "$DEST_DIR/.server-key.pem.XXXXXX")"

stage_bounded() {
  local src="$1" dst="$2" label="$3"
  python3 - "$src" "$dst" "$label" <<'PY'
import os, stat, sys

src, dst, label = sys.argv[1], sys.argv[2], sys.argv[3]
max_bytes = 1 << 20
try:
    st = os.stat(src)
except OSError as exc:
    sys.stderr.write(f"export-edge-pem: cannot stat {label} {src}: {exc}\n")
    sys.exit(1)
if not stat.S_ISREG(st.st_mode):
    sys.stderr.write(f"export-edge-pem: {label} is not a regular file: {src}\n")
    sys.exit(1)
with open(src, "rb") as fh:
    if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
        sys.stderr.write(f"export-edge-pem: {label} is not a regular file after open: {src}\n")
        sys.exit(1)
    data = fh.read(max_bytes + 1)
if len(data) == 0:
    sys.stderr.write(f"export-edge-pem: {label} is empty: {src}\n")
    sys.exit(1)
if len(data) > max_bytes:
    sys.stderr.write(f"export-edge-pem: {label} exceeds 1 MiB limit: {src}\n")
    sys.exit(1)
with open(dst, "wb") as out:
    out.write(data)
    out.flush()
    os.fsync(out.fileno())
PY
}

stage_bounded "$SOURCE_CERT" "$tmp_cert" "certificate"
stage_bounded "$SOURCE_KEY" "$tmp_key" "private key"

# Validate EVERY PEM certificate block in the staged chain (prevents corrupt
# intermediate certs from passing single-block `openssl x509` and breaking
# rustls `pem_slice_iter`).
validate_all_cert_blocks() {
  python3 - "$1" <<'PY'
import re, subprocess, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="strict") as fh:
    text = fh.read()

begin_re = re.compile(r"^-----BEGIN CERTIFICATE-----\s*$", re.MULTILINE)
end_re = re.compile(r"^-----END CERTIFICATE-----\s*$", re.MULTILINE)
begins = list(begin_re.finditer(text))
ends = list(end_re.finditer(text))
if not begins or len(begins) != len(ends):
    sys.stderr.write("export-edge-pem: malformed or empty PEM certificate chain\n")
    sys.exit(1)

pos = 0
for idx, (b, e) in enumerate(zip(begins, ends), start=1):
    if b.start() < pos or e.start() <= b.end():
        sys.stderr.write(f"export-edge-pem: overlapping or malformed PEM block #{idx}\n")
        sys.exit(1)
    between = text[pos:b.start()].strip()
    if between:
        sys.stderr.write(f"export-edge-pem: unexpected non-certificate PEM data before block #{idx}\n")
        sys.exit(1)
    block = text[b.start():e.end()] + "\n"
    proc = subprocess.run(
        ["openssl", "x509", "-noout"],
        input=block.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"export-edge-pem: invalid X.509 certificate in chain block #{idx}: {proc.stderr.decode('utf-8', 'replace').strip()}\n"
        )
        sys.exit(1)
    pos = e.end()

trailing = text[pos:].strip()
if trailing:
    sys.stderr.write("export-edge-pem: trailing non-certificate data after PEM chain\n")
    sys.exit(1)
PY
}

validate_all_cert_blocks "$tmp_cert"

# Reject already-expired leaf certificates.
if ! openssl x509 -in "$tmp_cert" -checkend 0 -noout >/dev/null 2>&1; then
  echo "export-edge-pem: leaf certificate is already expired" >&2
  exit 1
fi

# Validate private key and compute portable DER SPKI SHA-256 hashes.
if ! openssl pkey -in "$tmp_key" -noout >/dev/null 2>&1; then
  echo "export-edge-pem: staged private key is invalid" >&2
  exit 1
fi

cert_spki="$(
  openssl x509 -in "$tmp_cert" -noout -pubkey |
    openssl pkey -pubin -outform DER |
    openssl dgst -sha256 |
    awk '{print $NF}'
)"
key_spki="$(
  openssl pkey -in "$tmp_key" -pubout -outform DER |
    openssl dgst -sha256 |
    awk '{print $NF}'
)"

if [ -z "$cert_spki" ] || [ "$cert_spki" != "$key_spki" ]; then
  echo "export-edge-pem: certificate public key does not match private key" >&2
  exit 1
fi

dest_cert="$DEST_DIR/server.pem"
dest_key="$DEST_DIR/server-key.pem"

# DANE-EE (TLSA 3 1 1) SPKI continuity guard.
if [ "$DANE_ENFORCE_KEY_PIN" = "1" ] && [ -f "$dest_key" ]; then
  if ! openssl pkey -in "$dest_key" -noout >/dev/null 2>&1; then
    if [ "$ALLOW_KEY_ROTATION" != "1" ]; then
      echo "export-edge-pem: existing $dest_key is unreadable/corrupt under DANE_ENFORCE_KEY_PIN=1; pass --allow-key-rotation to replace" >&2
      exit 1
    fi
  else
    old_spki="$(
      openssl pkey -in "$dest_key" -pubout -outform DER 2>/dev/null |
        openssl dgst -sha256 |
        awk '{print $NF}'
    )"
    if [ -n "$old_spki" ] && [ "$old_spki" != "$key_spki" ] && [ "$ALLOW_KEY_ROTATION" != "1" ]; then
      cat >&2 <<EOF
export-edge-pem: REFUSING key rotation under DANE_ENFORCE_KEY_PIN=1!
  existing TLSA 3 1 1 SPKI SHA-256: $old_spki
  incoming TLSA 3 1 1 SPKI SHA-256: $key_spki

Publishing a new key without pre-publishing its TLSA record breaks inbound
DANE-validated SMTP delivery (RFC 7672). Perform a double-TLSA rollover:
  1. Publish a second DNS record alongside the existing one:
       _25._tcp.<hostname> IN TLSA 3 1 1 $key_spki
  2. Wait at least 2x your DNS TTL for resolvers to cache both records.
  3. Re-run export-edge-pem.sh with --allow-key-rotation (or ALLOW_KEY_ROTATION=1).
  4. Wait another 2x DNS TTL, then remove the old TLSA record ($old_spki).
EOF
      exit 1
    fi
  fi
fi

fsync_path() {
  python3 - "$1" <<'PY'
import os, sys

fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

is_root=0
if [ "$(id -u)" -eq 0 ]; then
  is_root=1
fi

chmod 0644 "$tmp_cert"
if [ "$is_root" -eq 1 ]; then
  chown "$TLS_OWNER" "$tmp_cert"
fi

if [ -f "$dest_key" ] && [ ! -L "$dest_key" ] && cmp -s "$tmp_key" "$dest_key"; then
  # Unchanged key (standard DANE-EE key-reuse renewal): preserve existing key
  # inode, still normalize mode/ownership to 0640, and perform a single atomic
  # mv of server.pem (zero cert/key mismatch window).
  chmod 0640 "$dest_key"
  if [ "$is_root" -eq 1 ]; then
    chown "$TLS_OWNER" "$dest_key"
  fi
  rm -f "$tmp_key"
  tmp_key=""
  fsync_path "$tmp_cert"
  mv -f "$tmp_cert" "$dest_cert"
  tmp_cert=""
  fsync_path "$DEST_DIR"
else
  chmod 0640 "$tmp_key"
  if [ "$is_root" -eq 1 ]; then
    chown "$TLS_OWNER" "$tmp_key"
  fi
  fsync_path "$tmp_key"
  fsync_path "$tmp_cert"
  mv -f "$tmp_key" "$dest_key"
  tmp_key=""
  mv -f "$tmp_cert" "$dest_cert"
  tmp_cert=""
  fsync_path "$DEST_DIR"
fi

echo "export-edge-pem: published $dest_cert and $dest_key (spki_sha256=$key_spki)"
