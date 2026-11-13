"""Installer process contract over the same isolated DB/fixture as updater run."""
import json
import os
from pathlib import Path
import shutil
import subprocess


def copy_when_idle(src, dst):
    """Overwrite an installed executable once nothing executes it: a just-exited updater (or a
    helper it spawned) can still hold the image for a moment on a loaded host (ETXTBSY)."""
    import errno, time
    for _ in range(150):
        try:
            shutil.copyfile(src, dst)
            return
        except OSError as error:
            if error.errno != errno.ETXTBSY:
                raise
            time.sleep(0.1)
    shutil.copyfile(src, dst)


def run(root, install, env, binary, sql, rid):
    libexec = root/'libexec'; units = root/'units'
    libexec.mkdir(); units.mkdir()
    old = b'#!/bin/sh\necho old-updater "$@"\n'
    recovery = b'#!/bin/sh\necho old-recovery "$@"\n'
    prior_unit = b'[Service]\nExecStart=/usr/libexec/setjoin-updater\n'
    for path, raw, mode in [(libexec/'setjoin-updater', old, 0o755),
                            (libexec/'setjoin-recovery', recovery, 0o755),
                            (units/'setjoin-updater.service', prior_unit, 0o644)]:
        path.write_bytes(raw); path.chmod(mode)
    source = root/'rust-updater'; shutil.copyfile(binary, source); source.chmod(0o755)
    unit = root/'unit-source'; unit.write_text('[Service]\nExecStart=/usr/libexec/setjoin-updater run\n')
    args = [binary, 'install', '--binary', str(source), '--state-dir', str(root/'swap-journal'),
            '--libexec-dir', str(libexec), '--unit-source', str(unit), '--systemd-dir', str(units),
            '--dsn-file', str(root/'dsn')]
    denied = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
    assert denied.returncode == 1 and 'update is in progress (database state=approved)' in denied.stderr, denied.stderr
    assert (libexec/'setjoin-updater').read_bytes() == old
    assert not (libexec/'setjoin-updater.prev').exists()
    corpus = json.loads((Path(__file__).with_name('goldens')/'legacy-journals.json').read_text())['cases']['verified']
    snapshot = json.loads(corpus['snapshot'])['last']
    state = root/'swap-journal'
    for name, key in [('events.jsonl', 'events'), ('snapshot.json', 'snapshot')]:
        path = state/name; path.write_text(corpus[key]); path.chmod(0o600)
    # Root fixture seeds an independently recorded terminal Go tip's exact authority.
    sql("INSERT INTO upgrade_release_catalog SELECT (jsonb_populate_record(NULL::upgrade_release_catalog, to_jsonb(c)||jsonb_build_object('release_id','fixture','manifest_digest',decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex')))).* FROM upgrade_release_catalog c WHERE release_id="+"'"+rid+"'")
    sql("UPDATE upgrade_intents SET id=42,release_id='fixture',manifest_digest=decode('"+snapshot['manifest_digest']+"','hex'),state='verified',state_generation=9,claimed_at=now(),executor_id='setjoin-updater',lease_id='"+snapshot['lease_id']+"',completed_at=now() WHERE release_id='"+rid+"'")
    accepted = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
    assert accepted.returncode == 0, accepted.stderr
    assert (libexec/'setjoin-updater').read_bytes() == source.read_bytes()
    assert (libexec/'setjoin-updater.prev').read_bytes() == old
    assert (libexec/'setjoin-recovery.prev').read_bytes() == recovery
    assert (units/'setjoin-updater.service.prev').read_bytes() == prior_unit
    assert (state/'go-terminal/events.jsonl').read_text() == corpus['events']
    assert (state/'go-terminal/snapshot.json').read_text() == corpus['snapshot']
    assert not (state/'events.jsonl').exists() and not (state/'snapshot.json').exists()
    alias = subprocess.run([str(libexec/'setjoin-updater'), 'recover', '--state-dir', str(state),
        '--install-root', str(install), 'status', '--json'], env=env, capture_output=True, text=True, timeout=15)
    assert alias.returncode == 0, alias.stderr
    assert json.loads(alias.stdout)['current'] == 'old'
    # Whole-release operator rollback restores matching executable/unit backups.
    for path in [libexec/'setjoin-updater', libexec/'setjoin-recovery', units/'setjoin-updater.service']:
        copy_when_idle(path.with_name(path.name+'.prev'), path)
    restored = subprocess.run([str(libexec/'setjoin-updater'), 'probe'], capture_output=True, text=True, timeout=10)
    assert restored.stdout == 'old-updater probe\n'
    assert (units/'setjoin-updater.service').read_bytes() == prior_unit
    print('REL3 swap: active DB refused; terminal Go archived, Rust installed, recovery alias and *.prev restored')
