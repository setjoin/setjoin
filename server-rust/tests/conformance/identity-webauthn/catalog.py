#!/usr/bin/env python3
"""Append #335's qualified WebAuthn registrations without rewriting other suites."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[4]
corpus = Path(__file__).resolve().parent
inventory = root / 'server-rust/bins/gateway/route-inventory.json'
catalog = root / 'server-rust/tests/conformance/route-catalog.json'
inv = json.loads(inventory.read_text())
cat = json.loads(catalog.read_text())
qualified = {
    ('GET', '/auth/webauthn/credentials'): 'list',
    ('PUT', '/auth/webauthn/credential/{id}/name'): 'name',
    ('DELETE', '/auth/webauthn/credential/{id}'): 'revoke',
    ('GET', '/auth/webauthn/login/begin'): 'login-begin',
    ('POST', '/auth/webauthn/login/finish'): 'login-finish',
    ('GET', '/auth/webauthn/register/begin'): 'register-begin',
    ('POST', '/auth/webauthn/register/finish'): 'register-finish',
    ('*', '/auth/webauthn/'): 'subtree',
}

def replay(test):
    return dict(package='setjoin-auth', target='webauthn_oracle', test=test)

rows = []
for route in inv['routes']:
    key = route['method'], route['path']
    if route['family'] != 'F21' or key not in qualified:
        continue
    prefix = qualified[key]
    mutator = prefix not in {'list', 'subtree'}  # Begin may persist a handle/bind a grant.
    route.update(state='ON', upstream='rust-auth', oracle_commands=[''],
                 oracle_mutators=[''] if mutator else [])
    suite = dict(listener=route['listener'], method=key[0], path=key[1], family='F21',
                 command='', mutator=mutator, cases=[],
                 mutant=dict(replay(prefix.replace('-', '_') + '_status_mutant'), name='status'),
                 handler_sources=['server-rust/bins/auth/src/webauthn.rs',
                                  'server-rust/crates/domains/identity/src/webauthn.rs'])
    for p in sorted((corpus / 'qualified').glob(prefix + '-*.json')):
        if p.stem.endswith(('-rows', '-anonymous')):
            continue
        doc = json.loads(p.read_text())
        # Match the normalized registration, never a neighboring prefix.
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
print(f'IDMFA2: {len(rows)} qualified WebAuthn registrations')
