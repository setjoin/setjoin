#!/usr/bin/env python3
"""Register #416's immutable HTTP recordings; never change a golden."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
CATALOG = ROOT / 'server-rust/tests/conformance/route-catalog.json'
FAMILIES = {'/': 'F22', '/api/': 'F22', '/chat/': 'F12', '/drive/': 'F14', '/meet': 'F13', '/meet/': 'F13'}
PREFIX = {'/': 'root', '/api/': 'api', '/chat/': 'chat', '/drive/': 'drive', '/meet': 'meet_exact', '/meet/': 'meet'}
SUCCESS = {'root_unknown', 'api_unknown', 'chat_unknown', 'drive_unknown', 'meet_unknown', 'meet_exact_unknown'}
INVALID = {'mux_encoded_dot', 'api_invalid', 'chat_invalid', 'drive_invalid', 'meet_invalid', 'meet_exact_invalid'}
catalog = json.loads(CATALOG.read_text())
keys = {('gateway', '*', path) for path in FAMILIES}
catalog['routes'] = [r for r in catalog['routes'] if (r['listener'], r['method'], r['path']) not in keys]
for path, family in FAMILIES.items():
    cases = []
    for golden in sorted(Path(__file__).with_name('goldens').glob('*.json')):
        document = json.loads(golden.read_text())
        if document['route'] != f'* {path}':
            continue
        name = document['case']
        kind = ('cross-tenant' if 'foreign' in name else 'success' if name in SUCCESS else 'invalid-input' if name in INVALID else 'edge-case')
        cases.append({'kind': kind, 'golden': str(golden.relative_to(ROOT)), 'replay': {'package': 'setjoin-gateway', 'target': 'catchall_recorded', 'test': name}})
    catalog['routes'].append({'listener': 'gateway', 'method': '*', 'path': path, 'family': family,
        'handler_sources': ['server-rust/bins/gateway/src/catchall.rs', 'server-rust/bins/gateway/src/inventory.rs', 'server-rust/bins/gateway/src/catchall/static_file.rs', 'server-rust/crates/domains/static/src/website.rs'],
        'cases': cases, 'mutant': {'name': 'changed-status', 'package': 'setjoin-gateway', 'target': 'catchall_recorded', 'test': PREFIX[path] + '_status_mutant'}})
CATALOG.write_text(json.dumps(catalog, indent=2) + '\n')
