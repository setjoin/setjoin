#!/usr/bin/env python3
"""Build and verify every workspace binary inside its floor toolchain image."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / 'server-rust'
TARGETS = {
    'x86_64-unknown-linux-gnu': '2.28',
    'aarch64-unknown-linux-gnu': '2.28',
    'loongarch64-unknown-linux-gnu': '2.36',
}


def main():
    if len(sys.argv) != 3 or TARGETS.get(sys.argv[1]) != sys.argv[2]:
        raise SystemExit('usage: build-rust-floor.py <target> <matching-floor>')
    target, floor = sys.argv[1:]
    meta = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--no-deps', '--format-version=1'], cwd=WORKSPACE))
    members = set(meta['workspace_members'])
    expected = {(p['id'], t['name']) for p in meta['packages'] if p['id'] in members
                for t in p['targets'] if 'bin' in t['kind']}
    if not expected:
        raise SystemExit('workspace has no binary targets')
    if len({name for _, name in expected}) != len(expected):
        raise SystemExit('duplicate binary names would overwrite each other')
    proc = subprocess.Popen(
        ['cargo', 'build', '--locked', '--release', '--workspace', '--bins',
         '--target', target, '--message-format=json-render-diagnostics'],
        cwd=WORKSPACE, stdout=subprocess.PIPE, universal_newlines=True)
    built = {}
    for line in proc.stdout:
        try:
            msg = json.loads(line)
        except ValueError:
            print(line, end='')
            continue
        if msg.get('reason') == 'compiler-artifact' and msg.get('executable'):
            key = (msg.get('package_id'), msg.get('target', {}).get('name'))
            if key in expected:
                built[key] = msg['executable']
        elif msg.get('reason') == 'compiler-message':
            rendered = msg.get('message', {}).get('rendered')
            if rendered:
                print(rendered, file=sys.stderr, end='')
    if proc.wait() != 0:
        raise SystemExit('cargo build failed')
    missing = expected - built.keys()
    if missing:
        raise SystemExit('missing workspace binaries: ' + ', '.join(sorted(name for _, name in missing)))
    subprocess.run([sys.executable, str(ROOT / 'scripts/check-glibc-floor.py'), '--floor', floor,
                    *[built[key] for key in sorted(expected)]], check=True)
    for key in sorted(expected):
        print('verified:', built[key], flush=True)

if __name__ == '__main__':
    main()
