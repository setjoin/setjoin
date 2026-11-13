#!/usr/bin/env python3
"""Append #333's qualified registrations; preserve every other oracle suite."""
import json
from pathlib import Path
root=Path(__file__).resolve().parents[4]
corpus=Path(__file__).resolve().parent
inventory=root/'server-rust/bins/gateway/route-inventory.json'
catalog=root/'server-rust/tests/conformance/route-catalog.json'
inv=json.loads(inventory.read_text()); cat=json.loads(catalog.read_text())
qualified={('GET','/.well-known/setjoin'):'discovery',('GET','/api/v1/version'):'version',('POST','/auth/introspect'):'introspect',('POST','/auth/revoke'):'revoke',('GET','/terms/pending'):'pending',('POST','/terms/accept'):'accept',('POST','/auth/scim/disable'):'scim',('POST','/admin/reload'):'reload',('POST','/auth/admin/users/{id}/impersonate'):'impersonate',('POST','/device/register'):'bootstrap',('POST','/auth/device/register'):'webpush'}
def replay(test): return dict(package='setjoin-auth',target='token_oracle',test=test)
rows=[]
for route in inv['routes']:
    key=(route['method'],route['path'])
    if route['family']!='F21' or key not in qualified: continue
    method,path=key; prefix=qualified[key]; mutator=prefix in {'revoke','accept','scim','reload','impersonate','bootstrap','webpush'}
    route.update(state='ON',upstream='rust-auth',oracle_commands=[''],oracle_mutators=[''] if mutator else [])
    suite=dict(listener=route['listener'],method=method,path=path,family='F21',command='',mutator=mutator,cases=[],mutant=dict(replay(prefix+'_status_mutant'),name='status'),handler_sources=['server-rust/bins/auth/src/lib.rs'] if prefix in {'discovery','version'} else ['server-rust/bins/auth/src/issuance.rs','server-rust/crates/domains/identity/src/issuance.rs'])
    for p in sorted((corpus/'goldens').glob(prefix+'-*.json')):
        if p.stem.endswith('-rows'): continue
        doc=json.loads(p.read_text()); case=doc['case']; kind=case.removeprefix(prefix+'-'); kind=kind if kind in {'success','cross-tenant','invalid-input','repeat'} else 'edge'
        row=dict(kind=kind,golden=p.relative_to(root).as_posix(),replay=replay(case.replace('-','_')))
        if mutator: row['row_golden']=p.with_name(p.stem+'-rows.json').relative_to(root).as_posix()
        suite['cases'].append(row)
    if prefix=='scim': suite['family_mutants']=[dict(replay('scim_no_notify_mutant'),name='no-notify')]
    if prefix=='impersonate': suite['handler_sources']+=['server-rust/crates/domains/identity/src/impersonation.rs']
    if prefix=='bootstrap': suite['handler_sources']+=['server-rust/crates/domains/identity/src/bootstrap.rs']
    rows.append(suite)
for route in inv['routes']:
    if route['listener']=='gateway' and route['path']=='/drive/native-token': route['oracle_mutators']=[]
# Native Drive is a gateway-local scoped mint, independently recorded against Go mail.
drive=[]
for p in sorted((corpus/'goldens').glob('drive-native-*.json')):
    kind=p.stem.removeprefix('drive-native-')
    drive.append(dict(kind=kind if kind in {'success','cross-tenant','invalid-input'} else 'edge',golden=p.relative_to(root).as_posix(),replay=dict(package='setjoin-gateway',target='drive_native_token',test=p.stem.replace('-','_'))))
rows.append(dict(listener='gateway',method='POST',path='/drive/native-token',family='F14',cases=drive,mutant=dict(name='status',package='setjoin-gateway',target='drive_native_token',test='drive_native_status_mutant'),handler_sources=['server-rust/bins/gateway/src/drive_native.rs','server-rust/crates/domains/identity/src/drive_token.rs']))
keys={(r['listener'],r['method'],r['path'],r['family'],r.get('command','')) for r in rows}
cat['routes']=[r for r in cat['routes'] if (r['listener'],r['method'],r['path'],r['family'],r.get('command','')) not in keys]+rows
inventory.write_text(json.dumps(inv,indent=2)+'\n');catalog.write_text(json.dumps(cat,indent=2)+'\n')
print(f'IDLOGIN3: {len(rows)} qualified registrations')
