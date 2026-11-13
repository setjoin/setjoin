#!/usr/bin/env python3
"""Append F21 #331/#332 qualification from immutable Go recordings; preserve other families."""
import json
from pathlib import Path
root=Path(__file__).resolve().parents[4]
corpus=Path(__file__).resolve().parent
inventory=root/'server-rust/bins/gateway/route-inventory.json'
catalog=root/'server-rust/tests/conformance/route-catalog.json'
inv=json.loads(inventory.read_text());cat=json.loads(catalog.read_text())
qualified={('POST','/auth/login'):'login',('GET','/auth/password-policy'):'policy',('GET','/.well-known/jwks.json'):'jwks',('GET','/health'):'health',('GET','/ready'):'ready'}
sessions={('GET','/auth/me'):'me',('GET','/auth/session/token'):'session-token',('POST','/auth/logout'):'logout',('POST','/auth/refresh'):'refresh',('PUT','/auth/password'):'password',('POST','/auth/forgot-password/reset'):'reset',('POST','/auth/change-password'):'change-password'}
qualified.update(sessions)
def replay(test):return dict(package='setjoin-auth',target='oracle',test=test)
rows=[]
for route in inv['routes']:
    key=(route['method'],route['path'])
    if route['family']!='F21' or route['slice'] not in ('login','sessions-refresh','connectors-a') or key not in qualified:continue
    method,path=key;prefix=qualified[key]
    route.update(state='ON',upstream='rust-auth',oracle_commands=[''],oracle_mutators=[''] if method in ('POST','PUT') else [])
    suite=dict(listener=route['listener'],method=method,path=path,family='F21',command='',mutator=method in ('POST','PUT'),cases=[],mutant=dict(replay(prefix.replace('-','_')+'_status_mutant'),name='status'),handler_sources=['server-rust/bins/auth/src/lib.rs'])
    domain={'login':'login','me':'session','session-token':'session','logout':'session','refresh':'session','password':'password','reset':'password'}.get(prefix)
    if domain:suite['handler_sources'].append(f'server-rust/crates/domains/identity/src/{domain}.rs')
    if method in ('POST','PUT') and prefix!='change-password':suite['handler_sources'].append('server-rust/crates/pg/src/executor.rs')
    for p in sorted((corpus/'goldens').glob('*.json')):
        if p.stem.endswith(('-rows','-state','-rotation','-credentials')):continue
        doc=json.loads(p.read_text())
        if doc['route']!=method+' '+path:continue
        case=doc['case'];kind='edge'
        floor_case=case.replace('password-connector-','password-',1) if prefix=='password' else case
        if floor_case==prefix+'-success':kind='success'
        elif floor_case==prefix+'-cross-tenant':kind='cross-tenant'
        elif floor_case in (prefix+'-invalid-input','login-invalid-json'):kind='invalid-input'
        elif floor_case==prefix+'-repeat':kind='repeat'
        if case.startswith('login-csrf'):kind='security'
        row=dict(kind=kind,golden=p.relative_to(root).as_posix(),replay=replay(case.replace('-','_')))
        if method in ('POST','PUT'):row['row_golden']=p.with_name(case+'-rows.json').relative_to(root).as_posix()
        suite['cases'].append(row)
    if route['listener']=='auth' and path=='/auth/login':
        suite['family_mutants']=[dict(replay(test),name=name) for name,test in [('no-audit','no_audit_mutant'),('no-tenant-filter','no_tenant_filter_mutant'),('double-bump','double_bump_mutant')]]
    if prefix in ('logout','password','reset','refresh'):
        notify_test='password_connector_no_notify_mutant' if prefix=='password' else prefix+('_gateway' if route['listener']=='gateway' else '')+'_no_notify_mutant'
        suite.setdefault('family_mutants',[]).append(dict(replay(notify_test),name='no-notify'))
    rows.append(suite)
def identity(r):return (r['listener'],r['method'],r['path'],r['family'],r.get('command',''))
replacements={identity(r):r for r in rows}
def replace_owned(old):
    new=replacements.pop(identity(old),None)
    if new is None:return old
    # Later MFA slices qualify the same login entry. Preserve their cases,
    # sources and mutants, as well as the catalog's existing route order.
    merged={**old,**new}
    merged['cases']=new['cases']+[c for c in old['cases'] if not c['golden'].startswith('server-rust/tests/conformance/identity-login/')]
    merged['handler_sources']=list(dict.fromkeys(old['handler_sources']+new['handler_sources']))
    if old.get('family_mutants'):
        owned_names={m['name'] for m in new.get('family_mutants',[])}
        merged['family_mutants']=new.get('family_mutants',[])+[m for m in old['family_mutants'] if m['name'] not in owned_names]
    return merged
cat['routes']=[replace_owned(r) for r in cat['routes']]+list(replacements.values())
for path,document in ((inventory,inv),(catalog,cat)):
    content=json.dumps(document,indent=2)+'\n'
    if path.read_text()!=content:path.write_text(content)
print(f'F21 identity sessions: {len(rows)} qualified registrations, {len(list((corpus/"goldens").glob("*.json")))} immutable documents')
