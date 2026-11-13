#!/usr/bin/env python3
"""Frozen-Go recovery process oracle; each run owns only its temporary install."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BINARY = str(Path(sys.argv[1]).resolve())
GO = '--go' in sys.argv
CASE = os.environ.get('REL3_RECOVERY_CASE', 'inspection')
GOLDEN = Path(__file__).with_name('goldens') / ('recovery-' + CASE + '.json')

def write(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    path.chmod(mode)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

with tempfile.TemporaryDirectory(prefix='gofree-rel3-recovery-') as tmp:
    root = Path(tmp)
    install = root / 'install'
    old = install / 'releases' / 'old'
    artifacts = {}
    for name in ('mailserverd', 'authserverd', 'mailctl', 'setjoin-gateway'):
        raw = ('old ' + name).encode()
        write(old / name, raw, 0o500)
        artifacts[name] = digest(raw)
    write(old / 'webmail/index.html', 'old webmail', 0o400)
    artifacts['webmail'] = digest(b'f\0index.html\0' + digest(b'old webmail').encode() + b'\0')
    write(old / 'adoption.json', json.dumps(dict(schema_version=1, release_id='old',
          database_schema=178, config_sha256='a'*64, artifacts=artifacts)), 0o400)
    (install / 'current').symlink_to('releases/old')
    write(root / 'bin/systemctl', '#!/bin/sh\necho active\n', 0o700)
    env = os.environ | dict(PATH=str(root / 'bin') + ':' + os.environ['PATH'],
         REL3_INSTALL_ROOT=str(install), REL3_JOURNAL_DIR=str(root / 'journal'),
         REL3_EVIDENCE_DIR=str(root / 'evidence'), REL3_DSN_FILE=str(root / 'dsn'))

    if CASE == 'unavailable-units':
        (root/'bin/systemctl').unlink()
        env['PATH']=str(root/'bin')

    def run(*args, input=None, stdin=None):
        flags = [] if GO else ['recover', '--install-root', str(install),
             '--state-dir', str(root / 'journal'), '--evidence-dir', str(root / 'evidence'),
             '--dsn-file', str(root / 'dsn')]
        return subprocess.run([BINARY, *flags, *args], capture_output=True, text=True,
                              env=env, timeout=15, input=input, stdin=stdin)

    if CASE == 'arguments':
        cases = [[], ['unknown'], ['status', 'extra'], ['status', '--bad'],
            ['evidence', '--reason'], ['evidence', '--reason', 'short'],
            ['activate-previous'], ['activate-previous', '--reason', '   '],
            ['activate-previous', '--reason', 'operator rollback', '--force=invalid']]
        observed = {'exit_codes': [run(*args, input='').returncode for args in cases]}
    elif CASE == 'activation':
        import shutil
        shutil.copytree(old, install / 'releases/new')
        adopted = json.loads((install / 'releases/new/adoption.json').read_text())
        adopted['release_id'] = 'new'
        write(install / 'releases/new/adoption.json', json.dumps(adopted), 0o400)
        (install / 'current').unlink()
        (install / 'current').symlink_to('releases/new')
        (install / 'previous').symlink_to('releases/old')
        write(root / 'bin/systemctl', '#!/bin/sh\nprintf "%s\\n" "$*" >> "'+str(root / 'host.log')+'"\n[ "$1" != is-active ] || echo active\n', 0o700)
        write(root / 'bin/curl', '#!/bin/sh\nexit 0\n', 0o700)
        denied = run('activate-previous', '--reason', 'operator rollback', input='')
        forced_pipe = run('activate-previous', '--reason', 'operator rollback', '--force', input='')
        assert denied.returncode == forced_pipe.returncode == 1
        assert 'break-glass recovery is not authorized' in denied.stderr, denied.stderr
        assert 'break-glass recovery is not authorized' in forced_pipe.stderr, forced_pipe.stderr
        # #506 (owner-approved security fix 2026-11-05): frozen Go accepted any character
        # device (S_IFCHR), so /dev/null passed. Rust requires a real terminal (isatty).
        if not GO:
            for device in ('/dev/null', '/dev/zero'):
                with open(device) as dev:
                    refused = run('activate-previous', '--reason', 'operator rollback', '--force', stdin=dev)
                assert refused.returncode == 1 and 'break-glass recovery is not authorized' in refused.stderr, (device, refused.stderr)
                assert (install / 'current').readlink() == Path('releases/new')
        import pty
        master, slave = pty.openpty()
        try:
            activated = run('activate-previous', '--reason', 'operator rollback', '--force', stdin=slave)
        finally:
            os.close(master); os.close(slave)
        assert activated.returncode == 0, activated.stderr
        assert (install / 'current').readlink() == Path('releases/old')
        assert (install / 'previous').readlink() == Path('releases/new')
        files = []
        for p in sorted((root / 'evidence').glob('*.json')):
            e = json.loads(p.read_text()); e['recorded_at'] = '<time>'; files.append(e)
        files.sort(key=lambda e: e['phase'])
        observed = dict(current='old', previous='new', evidence=files,
            host=(root / 'host.log').read_text().splitlines())
    else:
        status = run('status', '--json')
        assert status.returncode == 0, status.stderr
        text = run('status')
        assert text.returncode == 0, text.stderr
        snapshot = run('evidence', '--reason', 'operator inspection')
        assert snapshot.returncode == 0, snapshot.stderr
        path = Path(snapshot.stdout.strip())
        assert path.parent == root / 'evidence'
        assert path.stat().st_mode & 0o777 == 0o600
        assert digest(path.read_bytes())[:12] in path.name
        evidence = json.loads(path.read_text())
        evidence['recorded_at'] = '<time>'
        observed = dict(status=json.loads(status.stdout), text=text.stdout, evidence=evidence)
    if GO:
        dest = Path(os.environ['REL3_RECORD_DIR']) / GOLDEN.name
        with dest.open('x') as f:
            json.dump(dict(go_source=os.environ['GOFREE_GO_SOURCE'], observed=observed), f, indent=2)
            f.write('\n')
    else:
        assert observed == json.loads(GOLDEN.read_text())['observed'], observed
    print('REL3 recovery '+CASE+': Go process parity passed')
