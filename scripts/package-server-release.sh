#!/usr/bin/env bash
# Stage committed HEAD plus supplied binaries and webmail. This does not publish
# or prove an installation works. HEAD can differ from the source used to build
# the inputs. The ELF header check identifies the machine only; it does not prove
# a file is executable, meets the glibc floor, or came from that source.
set -euo pipefail
source "$(dirname "$0")/_base.sh"

if [[ $# -ne 9 ]]; then
  echo "usage: $0 <amd64|arm64|loong64> <go-bin-dir> <gateway> <rust-auth> <rust-mailctl> <rust-asrbotd> <rust-updater> <webmail-build> <output.tar.gz>" >&2
  echo 'Stages committed HEAD and supplied inputs; verify build provenance, executability and glibc floor separately.' >&2
  exit 1
fi
arch=$1 go_dir=$2 gateway=$3 rustauth=$4 mailctl=$5 asrbotd=$6 updater=$7 webmail=$8 output=$9
case "$arch" in amd64 | arm64 | loong64) ;; *)
  echo "unsupported architecture: $arch" >&2
  exit 1
  ;;
esac
for bin in mailserverd authserverd setjoin-updater; do
  [[ -s "$go_dir/$bin" && -f "$go_dir/$bin" ]] || {
    echo "missing $bin" >&2
    exit 1
  }
done
[[ -s "$mailctl" && -f "$mailctl" ]] || {
  echo 'missing Rust mailctl' >&2
  exit 1
}
[[ -s "$asrbotd" && -f "$asrbotd" ]] || {
  echo 'missing Rust asrbotd' >&2
  exit 1
}
[[ -s "$updater" && -f "$updater" ]] || {
  echo 'missing Rust updater/recovery' >&2
  exit 1
}
[[ -s "$gateway" && -f "$gateway" ]] || {
  echo 'missing gateway' >&2
  exit 1
}
[[ -s "$rustauth" && -f "$rustauth" ]] || {
  echo 'missing Rust setjoin-auth' >&2
  exit 1
}
[[ -s "$webmail/index.html" && -f "$webmail/index.html" ]] || {
  echo 'missing webmail build' >&2
  exit 1
}
python3 - "$arch" "$go_dir/mailserverd" "$go_dir/authserverd" "$mailctl" \
  "$go_dir/setjoin-updater" "$updater" "$gateway" "$rustauth" "$asrbotd" <<'PY'
import struct
import sys

machine = {'amd64': 62, 'arm64': 183, 'loong64': 258}[sys.argv[1]]
for name in sys.argv[2:]:
    with open(name, 'rb') as binary:
        header = binary.read(24)
    if (len(header) < 24 or header[:7] != b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<H', header, 16)[0] not in (2, 3)
            or struct.unpack_from('<H', header, 18)[0] != machine
            or struct.unpack_from('<I', header, 20)[0] != 1):
        raise SystemExit(f'{name}: expected ELF64 {sys.argv[1]} machine header')
PY
output=$(realpath -m -- "$output")
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-t13-package.XXXXXXXX")
outtmp=''
trap 'rm -rf "$tmp"; if [[ -n "$outtmp" ]]; then rm -f -- "$outtmp"; fi' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$tmp"
install -m 0755 "$go_dir/mailserverd" "$tmp/mailserver/mailserverd"
# Frozen Go updater is only the Office app runner source until #300.
install -m 0755 "$go_dir/setjoin-updater" "$tmp/mailserver/setjoin-updater"
install -m 0755 "$go_dir/authserverd" "$tmp/authserver/authserverd"
install -m 0755 "$mailctl" "$tmp/mailctl/mailctl"
install -m 0755 "$mailctl" "$tmp/server-rust/mailctl"
install -m 0755 "$gateway" "$tmp/server-rust/setjoin-gateway"
install -m 0755 "$rustauth" "$tmp/server-rust/setjoin-auth"
install -m 0755 "$updater" "$tmp/server-rust/setjoin-updater"
install -m 0755 "$asrbotd" "$tmp/server-rust/asrbotd"
# Vendor PUBLIC release trust roots (#507): a build input, never in git. The installer
# places them at /etc/setjoin/release-roots.json before adopting a managed release.
roots=${SETJOIN_RELEASE_TRUST_ROOTS:-}
if [[ -n "$roots" ]]; then
  [[ -s "$roots" && -f "$roots" ]] || { echo "SETJOIN_RELEASE_TRUST_ROOTS is not a non-empty file: $roots" >&2; exit 1; }
  python3 - "$roots" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
ok = (d.get('schema_version') == 1 and d.get('purpose') == 'release'
      and 1 <= len(d.get('keys', [])) <= 16
      and all(k.get('algorithm') == 'ed25519' and not k.get('test_only') for k in d['keys']))
if not ok:
    raise SystemExit('release trust roots must be schema 1, purpose release, 1..16 ed25519 keys, none test-only')
PY
  install -m 0644 "$roots" "$tmp/server-rust/release-roots.json"
else
  echo 'warning: SETJOIN_RELEASE_TRUST_ROOTS unset; the package ships no release trust roots and upgrades of managed installs will require the operator to provide /etc/setjoin/release-roots.json' >&2
fi
mkdir -p "$tmp/mailserver/webmail/build"
cp -R "$webmail/." "$tmp/mailserver/webmail/build/"
outtmp=$(mktemp "${output}.tmp.XXXXXXXX")
tar -C "$tmp" -cf - . | gzip -1 >"$outtmp"
mv -f -- "$outtmp" "$output"
