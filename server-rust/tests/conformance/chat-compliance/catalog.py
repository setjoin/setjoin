#!/usr/bin/env python3
"""Append F04 slice qualification; project row effects from immutable Go records.
Run after recording, never synthesize response/effect expectations from Rust.
"""
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'server-rust/tests/conformance/chat-compliance'
INVENTORY = ROOT / 'server-rust/bins/gateway/route-inventory.json'
CATALOG = ROOT / 'server-rust/tests/conformance/route-catalog.json'
TESTS = ROOT / 'server-rust/bins/gateway/tests/chat_compliance_recorded.rs'

def main():
    selectors = {(a, b): t for t, a, b in re.findall(r'case!\(\s*(\w+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', TESTS.read_text())}
    selectors.update({('policies', 'success'): 'policies_success', ('policies', 'foreign'): 'policies_foreign'})
    inventory = json.loads(INVENTORY.read_text())
    catalog = json.loads(CATALOG.read_text())
    catalog['routes'] = [r for r in catalog['routes'] if not (r['family'] == 'F04' and r.get('compl3') is True)]
    action_routes = {}
    for file in sorted((BASE / 'goldens').glob('*.json')):
        if file.stem.endswith('-row-effects'):
            continue
        doc = json.loads(file.read_text())
        # HEAD aliases are supplemental full-target proofs; the catalog keys
        # use the literal inventory method, as the existing F04 slice does.
        if doc['observation']['request']['method'] == 'HEAD':
            assert doc['route'].startswith('GET ')
            continue
        action = file.stem.split('-', 1)[0]
        action_routes.setdefault(doc['route'], []).append((action, doc, file))
    for route in inventory['routes']:
        if route['family'] != 'F04' or route['slice'] != 'chat-compliance':
            continue
        key = route['method'] + ' ' + route['path']
        records = action_routes[key]
        action = records[0][0]
        mutator = action in ('create','update','delete','hold','release','holds','search','read','export')
        suite = {k: route[k] for k in ('listener', 'method', 'path', 'family')}
        suite.update(compl3=True, mutator=mutator, handler_sources=[
            'server-rust/bins/gateway/src/chat_compliance.rs',
            'server-rust/crates/domains/compliance/src/chat.rs',
        ], cases=[])
        if action == 'export':
            suite['handler_sources'].extend([
                'server-rust/crates/domains/compliance/src/chat_export.rs',
                'server-rust/bins/gateway/src/chat_compliance_export.rs',
                'server-rust/bins/gateway/src/compliance_export.rs',
                'server-rust/bins/gateway/src/recovery_worker.rs',
            ])
        labels = {doc['case'] for _, doc, _ in records}
        assert {'success', 'foreign', 'invalid'} <= labels, (key, labels)
        if mutator:
            assert 'repeat' in labels, (key, 'missing repeat')
        for _, doc, file in records:
            label = doc['case']
            case = {'kind': {'foreign': 'cross-tenant', 'invalid': 'invalid-input'}.get(label, label), 'golden': str(file.relative_to(ROOT)),
                    'replay': {'package': 'setjoin-gateway', 'target': 'chat_compliance_recorded', 'test': selectors[(action, label)]}}
            if mutator:
                row_file = file.with_name(file.stem + '-row-effects.json')
                projection = {k: doc[k] for k in ('format', 'route', 'go_source')}
                projection.update(case=doc['case'] + '-row-effects', effects=doc['observation']['effects'])
                if row_file.exists():
                    assert json.loads(row_file.read_text()) == projection, row_file
                else:
                    with row_file.open('x') as out:
                        out.write(json.dumps(projection, indent=2) + '\n')
                case['row_golden'] = str(row_file.relative_to(ROOT))
            suite['cases'].append(case)
        suite['mutant'] = {'name': 'status', 'package': 'setjoin-gateway', 'target': 'chat_compliance_recorded', 'test': 'mutant_' + action}
        catalog['routes'].append(suite)
        route.update(state='ON', upstream='local-rust', oracle_commands=[''], oracle_mutators=[''] if mutator else [])
    CATALOG.write_text(json.dumps(catalog, indent=2) + '\n')
    INVENTORY.write_text(json.dumps(inventory, indent=2) + '\n')

if __name__ == '__main__':
    main()
