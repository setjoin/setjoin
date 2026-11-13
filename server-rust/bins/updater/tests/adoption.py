#!/usr/bin/env python3
"""Frozen-Go initial immutable-layout adoption at the executable/filesystem seam."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve()); go = '--go' in sys.argv
case = os.environ.get('REL3_ADOPTION_CASE', 'adoption')
with tempfile.TemporaryDirectory(prefix='gofree-rel3-adoption-') as tmp:
    root = Path(tmp); install = root/'install'; install.mkdir()
    for name in ['mailserverd', 'authserverd', 'mailctl', 'setjoin-gateway']:
        (install/name).write_text(name); (install/name).chmod(0o755)
        (install/(name+'.prev')).write_text('prior '+name)
    (install/'webmail').mkdir(); (install/'webmail/index.html').write_text('webmail')
    (install/'webmail.prev').mkdir(); (install/'webmail.prev/index.html').write_text('prior webmail')
    config = root/'config.env'; config.write_text('SECRET=fixture\n'); config.chmod(0o600)
    args = [binary, 'adopt-current-layout', '--install-root', str(install), '--config-file', str(config), '--quarantine-dir', str(root/'quarantine')]
    first = subprocess.run(args, capture_output=True, text=True, timeout=20)
    assert first.returncode == 0, first.stderr
    current = install/'current'
    if case == 'adoption-managed-tamper':
        manifest = json.loads((Path(__file__).parents[3]/'crates/release-format/tests/goldens/updater-fixtures.json').read_text())['samples'][0]['manifest']
        manifest['release_id'] = current.readlink().name
        (current/'adoption.json').unlink()
        (current/'manifest.json').write_text(json.dumps(manifest))
        (current/'manifest.digest').write_text('bad digest\n')
        (current/'installed.evidence.json').write_text('{}')
        (current/'mailserverd').write_text('tampered executable')
    before = current.readlink()
    # A tampered managed release is quarantine-eligible state: re-create the flat *.prev
    # evidence so a wrongly accepted adoption would visibly consume it.
    if case == 'adoption-managed-tamper':
        for name in ['mailserverd', 'authserverd', 'mailctl', 'setjoin-gateway']:
            (install/(name+'.prev')).write_text('prior '+name)
    repeat = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if case == 'adoption-managed-tamper':
        # #506 (owner-approved security fix 2026-11-05): frozen Go accepted this; Rust refuses.
        assert repeat.returncode != 0, 'tampered managed current was adopted: ' + repeat.stdout
        assert 'refusing to adopt' in repeat.stderr and 'installed digest differs' in repeat.stderr, 'tampered managed current was adopted (no content refusal): ' + repeat.stderr
        assert current.readlink() == before
        assert (install/'mailserverd.prev').read_text() == 'prior mailserverd', 'install must abort before quarantine'
        print('REL3 adoption-managed-tamper: refused'); sys.exit(0)
    assert repeat.returncode == 0 and first.stdout == repeat.stdout, repeat.stderr
    if False: pass
    else:
        adopted = json.loads((current/'adoption.json').read_text())
        # Schema comes from the canonical SQL catalog, unlike content identity.
        assert adopted['database_schema'] > 178
        adopted['database_schema'] = '<schema-version>'
        assert not (install/'previous').exists()
        assert not list(install.glob('*.prev'))
        assert b'SECRET=fixture' not in b''.join(p.read_bytes() for p in current.rglob('*') if p.is_file())
        modes = {str(p.relative_to(current)): p.stat().st_mode & 0o777 for p in current.rglob('*')}
        observed = dict(stdout=first.stdout, current=str(current.readlink()), evidence=adopted,
            modes=modes, quarantine=sorted(p.name for p in (root/'quarantine').iterdir()))
    golden = Path(__file__).with_name('goldens')/(case+'.json')
    if go:
        with (Path(os.environ['REL3_RECORD_DIR'])/golden.name).open('x') as f:
            json.dump(dict(go_source=os.environ['GOFREE_GO_SOURCE'], observed=observed), f, indent=2); f.write('\n')
    else: assert observed == json.loads(golden.read_text())['observed'], observed
    print('REL3 '+case+': Go process parity passed')
