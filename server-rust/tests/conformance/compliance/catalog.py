#!/usr/bin/env python3
"""Append F04 slice qualification; project row effects from immutable Go records.
Run after recording, never synthesize response/effect expectations from Rust.
"""
import json
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'server-rust/tests/conformance/compliance'
INVENTORY = ROOT / 'server-rust/bins/gateway/route-inventory.json'
CATALOG = ROOT / 'server-rust/tests/conformance/route-catalog.json'
TESTS = ROOT / 'server-rust/bins/gateway/tests/compliance_recorded.rs'

def main():
    selectors = {(a, b): t for t, a, b in re.findall(r'case!\(\s*(\w+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', TESTS.read_text())}
    selectors.update({('list', 'success'): 'cases_list_success', ('get', 'success'): 'case_get_success'})
    inventory = json.loads(INVENTORY.read_text())
    catalog = json.loads(CATALOG.read_text())
    catalog['routes'] = [r for r in catalog['routes'] if not (r['family'] == 'F04' and r.get('compl1') is True)]
    action_routes = {}
    for file in sorted((BASE / 'goldens').glob('*.json')):
        if file.stem.endswith('-row-effects'):
            continue
        doc = json.loads(file.read_text())
        action = file.stem.split('-', 1)[0]
        action_routes.setdefault(doc['route'], []).append((action, doc, file))
    for route in inventory['routes']:
        if route['family'] != 'F04' or route['slice'] != 'ediscovery':
            continue
        key = route['method'] + ' ' + route['path']
        records = action_routes[key]
        action = records[0][0]
        mutator = action not in ('list', 'get', 'search')
        suite = {k: route[k] for k in ('listener', 'method', 'path', 'family')}
        suite.update(compl1=True, mutator=mutator, handler_sources=[
            'server-rust/bins/gateway/src/compliance.rs',
            'server-rust/crates/domains/compliance/src/lib.rs',
        ], cases=[])
        if action in ('start', 'search'):
            suite['handler_sources'].append('server-rust/crates/domains/compliance/src/kql.rs')
        if action == 'start':
            suite['handler_sources'].append('server-rust/crates/domains/compliance/src/search.rs')
        if action == 'export':
            suite['handler_sources'].extend([
                'server-rust/crates/domains/compliance/src/export.rs',
                'server-rust/bins/gateway/src/compliance_export.rs',
                'server-rust/bins/gateway/src/recovery_worker.rs',
            ])
        for _, doc, file in records:
            label = doc['case']
            case = {'kind': {'foreign': 'cross-tenant', 'invalid': 'invalid-input'}.get(label, label), 'golden': str(file.relative_to(ROOT)),
                    'replay': {'package': 'setjoin-gateway', 'target': 'compliance_recorded', 'test': selectors[(action, label)]}}
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
        suite['mutant'] = {'name': 'status', 'package': 'setjoin-gateway', 'target': 'compliance_recorded', 'test': 'mutant_' + action}
        if action == 'hold':
            suite['family_mutants'] = [{'name': name, 'package': 'setjoin-gateway', 'target': 'compliance_recorded', 'test': 'mutant_' + name.replace('-', '_')} for name in ('no-audit', 'double-bump')]
        if action == 'list':
            suite['family_mutants'] = [{'name': 'no-tenant-filter', 'package': 'setjoin-gateway', 'target': 'compliance_recorded', 'test': 'mutant_no_tenant_filter'}]
        catalog['routes'].append(suite)
        route.update(state='ON', upstream='local-rust', oracle_commands=[''], oracle_mutators=[''] if mutator else [])
    CATALOG.write_text(json.dumps(catalog, indent=2) + '\n')
    INVENTORY.write_text(json.dumps(inventory, indent=2) + '\n')

if __name__ == '__main__':
    main()
