#!/usr/bin/env python3
"""Reconcile only CardDAV catalog entries; row effects are exact Go extracts."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
COMMANDS = ['options', 'propfind', 'get', 'query', 'multiget', 'sync', 'put',
            'put-update', 'delete', 'unsupported', 'gal-options', 'gal-propfind',
            'gal-get', 'gal-query', 'gal-multiget', 'gal-sync', 'gal-put',
            'gal-delete', 'entitlement']
MUTATORS = {'put', 'put-update', 'delete', 'gal-propfind', 'gal-get',
            'gal-query', 'gal-multiget', 'gal-sync'}


def selector(test):
    return dict(package='setjoin-gateway', target='carddav', test=test)


cases = json.loads((HERE / 'cases.json').read_text())
for command, test in [('options', 'options_success'), ('propfind', 'propfind_success'),
                      ('get', 'get_success'), ('query', 'reports_success'),
                      ('multiget', 'reports_success'), ('sync', 'reports_success'),
                      ('put', 'writes_success'), ('put-update', 'writes_success'),
                      ('delete', 'writes_success')]:
    cases.append(dict(route=command, label='success', kind='success', test=test))
cases.append(dict(route='propfind', label='members', kind='member-properties', test='propfind_members'))
for command in COMMANDS:
    if command.startswith('gal-'):
        cases.append(dict(route=command, label='success', kind='success', test='gal_success'))
entries = []
for command in COMMANDS:
    entry = dict(listener='gateway', method='*', path='/carddav/', family='F17',
                 command=command, handler_sources=[
                     'server-rust/bins/gateway/src/carddav.rs',
                     *['server-rust/bins/gateway/src/carddav/' + name + '.rs'
                       for name in ['xml', 'report', 'write', 'gal']],
                     'server-rust/crates/domains/calendar/src/carddav.rs'], cases=[],
                 mutant=dict(name='status', **selector('status_mutant_' + command.replace('-', '_'))))
    if command in MUTATORS:
        entry['mutator'] = True
    for case in sorted((c for c in cases if c['route'] == command), key=lambda c: c['label']):
        path = HERE / 'goldens' / (command + '-' + case['label'] + '.json')
        original = json.loads(path.read_text())
        row = dict(kind=case['kind'], golden=str(path.relative_to(ROOT)), replay=selector(case['test']))
        if command in MUTATORS:
            effect_path = path.with_stem(path.stem + '-row-effects')
            effect = {key: original[key] for key in ['format', 'route', 'go_source']}
            effect.update(case=original['case'] + '-row-effects', effects=original['observation']['effects'])
            if effect_path.exists():
                assert json.loads(effect_path.read_text()) == effect, effect_path
            else:
                with effect_path.open('x') as output:
                    json.dump(effect, output, indent=2, ensure_ascii=False)
                    output.write('\n')
            row['row_golden'] = str(effect_path.relative_to(ROOT))
        entry['cases'].append(row)
    if command == 'put':
        entry['family_mutants'] = [dict(name='no-notify', **selector('mutants_no_notify'))]
    entries.append(entry)
path = ROOT / 'server-rust/tests/conformance/route-catalog.json'
catalog = json.loads(path.read_text())
catalog['routes'] = [row for row in catalog['routes'] if row.get('path') != '/carddav/'] + entries
path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + '\n')
