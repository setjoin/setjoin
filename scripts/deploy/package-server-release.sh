#!/usr/bin/env bash
# Stage committed HEAD plus supplied binaries and webmail. This does not publish
# or prove an installation works. HEAD can differ from the source used to build
# the inputs. The ELF header check identifies the machine only; it does not prove
# a file is executable, meets the glibc floor, or came from that source.
set -euo pipefail
source "$(dirname "$0")/../_base.sh"

usage() {
  echo "usage: $0 [--setjoind <path>] [--cohort <split|expand|unified>] <amd64|arm64|loong64> <setjoin-server> <rust-auth> <rust-mailctl> <rust-asrbotd> <rust-updater> <webmail-build> <output.tar.gz>" >&2
  echo "   or: $0 --cohort=unified --setjoind <path> <amd64|arm64|loong64> <rust-mailctl> <rust-asrbotd> <rust-updater> <webmail-build> <output.tar.gz>" >&2
  echo 'Stages committed HEAD and supplied inputs; verify build provenance, executability and glibc floor separately.' >&2
  exit 1
}

setjoind=""
cohort=""
positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setjoind)
      [[ $# -ge 2 ]] || usage
      setjoind=$2
      shift 2
      ;;
    --setjoind=*)
      setjoind=${1#--setjoind=}
      shift
      ;;
    --cohort)
      [[ $# -ge 2 ]] || usage
      cohort=$2
      shift 2
      ;;
    --cohort=*)
      cohort=${1#--cohort=}
      shift
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        positional+=("$1")
        shift
      done
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage
      ;;
    *)
      positional+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$cohort" ]]; then
  if [[ -n "$setjoind" ]]; then
    cohort=expand
  else
    cohort=split
  fi
fi

case "$cohort" in
  split | expand | unified) ;;
  *)
    echo "unsupported cohort: $cohort (expected split, expand, or unified)" >&2
    exit 1
    ;;
esac

server=""
rustauth=""
if [[ "$cohort" == "unified" ]]; then
  if [[ ${#positional[@]} -eq 6 ]]; then
    arch=${positional[0]}
    mailctl=${positional[1]}
    asrbotd=${positional[2]}
    updater=${positional[3]}
    webmail=${positional[4]}
    output=${positional[5]}
  elif [[ ${#positional[@]} -eq 8 && -z "${positional[1]}" && -z "${positional[2]}" ]]; then
    arch=${positional[0]}
    mailctl=${positional[3]}
    asrbotd=${positional[4]}
    updater=${positional[5]}
    webmail=${positional[6]}
    output=${positional[7]}
  else
    usage
  fi
  if [[ -z "$setjoind" ]]; then
    echo 'cohort=unified requires --setjoind <path>' >&2
    exit 1
  fi
else
  [[ ${#positional[@]} -eq 8 ]] || usage
  arch=${positional[0]}
  server=${positional[1]}
  rustauth=${positional[2]}
  mailctl=${positional[3]}
  asrbotd=${positional[4]}
  updater=${positional[5]}
  webmail=${positional[6]}
  output=${positional[7]}
  if [[ "$cohort" == "split" && -n "$setjoind" ]]; then
    echo 'cohort=split forbids --setjoind' >&2
    exit 1
  fi
  if [[ "$cohort" == "expand" && -z "$setjoind" ]]; then
    echo 'cohort=expand requires --setjoind <path>' >&2
    exit 1
  fi
fi

case "$arch" in
  amd64 | arm64 | loong64) ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

elf_inputs=()
if [[ -n "$setjoind" ]]; then
  [[ -s "$setjoind" && -f "$setjoind" ]] || {
    echo 'missing Rust setjoind' >&2
    exit 1
  }
  elf_inputs+=("$setjoind")
fi
if [[ "$cohort" != "unified" ]]; then
  [[ -s "$server" && -f "$server" ]] || {
    echo 'missing Rust setjoin-server' >&2
    exit 1
  }
  [[ -s "$rustauth" && -f "$rustauth" ]] || {
    echo 'missing Rust setjoin-auth' >&2
    exit 1
  }
  elf_inputs+=("$server" "$rustauth")
fi
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
[[ -s "$webmail/index.html" && -f "$webmail/index.html" ]] || {
  echo 'missing webmail build' >&2
  exit 1
}
elf_inputs+=("$mailctl" "$asrbotd" "$updater")

python3 - "$arch" "${elf_inputs[@]}" <<'PY'
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
output=$(realpath -m -- "$output" 2>/dev/null || python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$output")
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-t13-package.XXXXXXXX")
outtmp=''
trap 'rm -rf "$tmp"; if [[ -n "$outtmp" ]]; then rm -f -- "$outtmp"; fi' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$tmp"
install -d -m 0755 "$tmp/server-rust"
if [[ -n "$setjoind" ]]; then
  install -m 0755 "$setjoind" "$tmp/server-rust/setjoind"
fi
if [[ "$cohort" != "unified" ]]; then
  install -m 0755 "$server" "$tmp/server-rust/setjoin-server"
  install -m 0755 "$rustauth" "$tmp/server-rust/setjoin-auth"
fi
install -m 0755 "$mailctl" "$tmp/server-rust/mailctl"
install -m 0755 "$updater" "$tmp/server-rust/setjoin-updater"
install -m 0755 "$asrbotd" "$tmp/server-rust/asrbotd"
# Vendor PUBLIC release trust roots (#507): a build input, never in git. The installer
# places them at /etc/setjoin/release-roots.json before adopting a managed release.
roots=${SETJOIN_RELEASE_TRUST_ROOTS:-}
if [[ -n "$roots" ]]; then
  [[ -s "$roots" && -f "$roots" ]] || {
    echo "SETJOIN_RELEASE_TRUST_ROOTS is not a non-empty file: $roots" >&2
    exit 1
  }
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
