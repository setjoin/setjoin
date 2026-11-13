#!/usr/bin/env python3
"""Append #334's qualified TOTP registrations without rewriting other suites."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[4]
corpus = Path(__file__).resolve().parent
inventory = root / 'server-rust/bins/gateway/route-inventory.json'
catalog = root / 'server-rust/tests/conformance/route-catalog.json'
inv = json.loads(inventory.read_text())
cat = json.loads(catalog.read_text())
qualified = {
    ('GET', '/auth/totp/setup'): 'setup',
    ('POST', '/auth/totp/confirm'): 'confirm',
    ('POST', '/auth/totp/verify'): 'verify',
    ('POST', '/auth/totp/enroll/setup'): 'bootstrap-setup',
    ('POST', '/auth/totp/enroll/confirm'): 'bootstrap-confirm',
    ('POST', '/auth/totp/remove/begin'): 'begin',
    ('POST', '/auth/totp/remove'): 'remove',
    ('*', '/auth/totp/'): 'subtree',
}

def replay(test):
    return dict(package='setjoin-auth', target='mfa_oracle', test=test)

rows = []
for route in inv['routes']:
    key = route['method'], route['path']
    if route['family'] != 'F21' or key not in qualified:
        continue
    prefix = qualified[key]
    mutator = prefix != 'subtree'  # GET setup stages a secret and binds a grant.
    route.update(state='ON', upstream='rust-auth', oracle_commands=[''],
                 oracle_mutators=[''] if mutator else [])
    suite = dict(listener=route['listener'], method=key[0], path=key[1], family='F21',
                 command='', mutator=mutator, cases=[],
                 mutant=dict(replay(prefix.replace('-', '_') + '_status_mutant'), name='status'),
                 handler_sources=['server-rust/bins/auth/src/totp.rs',
                                  'server-rust/crates/domains/identity/src/totp.rs'])
    for p in sorted((corpus / 'qualified').glob(prefix + '-*.json')):
        if p.stem.endswith('-rows'):
            continue
        doc = json.loads(p.read_text())
        # bootstrap-setup and setup are distinct prefixes; compare actual registration.
        if doc['route'] != ' '.join(key):
            continue
        case = doc['case']
        kind = case.removeprefix(prefix + '-')
        name = case.replace('-', '_')
        if kind not in {'success', 'cross-tenant', 'invalid-input', 'repeat'}:
            name = 'edge_' + name
            kind = 'edge'
        item = dict(kind=kind, golden=p.relative_to(root).as_posix(), replay=replay(name))
        if mutator:
            item['row_golden'] = p.with_name(p.stem + '-rows.json').relative_to(root).as_posix()
        suite['cases'].append(item)
    rows.append(suite)
keys = {(r['listener'], r['method'], r['path'], r['family'], r.get('command', '')) for r in rows}
cat['routes'] = [r for r in cat['routes'] if
                 (r['listener'], r['method'], r['path'], r['family'], r.get('command', '')) not in keys] + rows
for path, data in [(inventory, inv), (catalog, cat)]:
    text = json.dumps(data, indent=2) + '\n'
    if path.read_text() != text:
        path.write_text(text)
print(f'IDMFA1: {len(rows)} qualified TOTP registrations')
