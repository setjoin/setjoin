#!/usr/bin/env python3
"""Record one new toggle-ON corpus from frozen Go, refusing existing goldens."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
ORACLE = Path(__file__).resolve().parent

def hashes(paths):
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}

def receipt(corpus):
    path = ORACLE / 'security-recording.json'
    record = json.loads(path.read_text()) if path.exists() else {'ticket': 526, 'corpora': []}
    if any(c['name'] == corpus for c in record['corpora']):
        raise RuntimeError('receipt already exists')
    cases = json.loads((ORACLE / f'{corpus}-go.json').read_text())
    runtime = list((ROOT / 'mailserver/internal/smtp').glob('*.go'))
    runtime = [p for p in runtime if not p.name.endswith('_test.go')]
    record['go_runtime_sha256'] = hashes(runtime)
    record['corpora'].append({
        'name': corpus, 'cases': len(cases),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'recorder_sha256': hashes([ROOT / 'mailserver/internal/smtp/listener_oracle_record_test.go', *sorted((ROOT / 'mailserver/internal/smtp').glob('security*_test.go'))]),
        'sha256': hashes([ORACLE / f'{corpus}-{kind}.json' for kind in ('requests', 'go')]),
        'observation_sha256': hashes([ORACLE / name for name in ('observe.sql', 'security-observe.sql', 'seed.sql', 'cleanup.sql', 'pipeline-observe.sql', 'imip-observe.sql', 'imip-event_id.sql', 'imip-calendar_id.sql') if (ORACLE / name).exists()]),
    })
    path.write_text(json.dumps(record, indent=2) + '\n')

if __name__ == '__main__':
    corpus = sys.argv[1]
    if not re.fullmatch(r'security-[a-z0-9-]+', corpus):
        sys.exit('expected security-<topic>')
    if len(sys.argv) == 3 and sys.argv[2] == '--receipt-only':
        receipt(corpus)
        sys.exit(0)
    if (ORACLE / f'{corpus}-go.json').exists():
        sys.exit('golden exists; record a new corpus')
    if os.environ.get('REQUIRE_DB') != '1' or not os.environ.get('DB_DSN', '').endswith('/gofree_e2e_smtp6'):
        sys.exit('requires REQUIRE_DB=1 and assigned disposable gofree_e2e_smtp6 DSNs')
    cache = Path(os.environ.get('GOFREE_GO_BUILD_CACHE', str(Path.home() / '.cache' / 'go-build')))
    cache.mkdir(parents=True, exist_ok=True)
    name = f'gofree-smtp6-record-{corpus}'
    if subprocess.run(['docker', 'container', 'inspect', name], capture_output=True).returncode == 0:
        sys.exit('owned container name already in use')
    command = ['docker', 'run', '--rm', '--name', name, '--label', 'org.setjoin.task=gofree-smtp6',
               '--network', 'host', '-v', f'{ROOT}:/src', '-w', '/src/mailserver',
               '-v', f"{os.environ.get('GOFREE_GO_MOD_CACHE', str(Path.home() / 'go' / 'pkg' / 'mod'))}:/root/go/pkg/mod", '-v', f'{cache}:/root/.cache/go-build']
    for key in ('DB_DSN', 'TEST_DB_DSN', 'DB_APP_DSN', 'REQUIRE_DB'):
        command += ['-e', key]
    command += ['-e', 'GOMAXPROCS=2', '-e', 'SMTP_ORACLE_DIR=/src/server-rust/crates/protocols/smtp/oracle',
                '-e', f'SMTP_CORPUS={corpus}', 'setjoin-ci-linux-tc:local-amd64',
                'go', 'test', '-p', '2', '-tags', 'gofree_record', './internal/smtp',
                '-run', '^TestRecordSMTPListener$', '-count=1']
    try:
        subprocess.run(command, check=True)
        receipt(corpus)
    finally:
        # Name was absent before this invocation; only this invocation can own it.
        if subprocess.run(['docker', 'container', 'inspect', name], capture_output=True).returncode == 0:
            subprocess.run(['docker', 'stop', name], check=True, capture_output=True)
