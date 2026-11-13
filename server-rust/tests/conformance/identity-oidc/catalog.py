#!/usr/bin/env python3
"""Register only frozen-Go qualified OP recordings; preserve other slices."""
import json
from pathlib import Path
root=Path(__file__).resolve().parents[4]
corpus=Path(__file__).resolve().parent
inventory=root/'server-rust/bins/gateway/route-inventory.json'
catalog=root/'server-rust/tests/conformance/route-catalog.json'
inv=json.loads(inventory.read_text()); cat=json.loads(catalog.read_text())
def selector(name): return dict(package='setjoin-auth',target='oidc_oracle',test=name)
def test_name(case):
    special={'authorize-missing-scope':'authorize_empty_scope','authorize-bad-response-type':'authorize_bad_response_type'}
    return special.get(case,case.replace('-','_'))
def category(key):
    return {'* /.well-known/ discovery':'discovery','* /.well-known/ mux':'well_known_mux',
            'GET /.well-known/openid-configuration':'discovery','GET /.well-known/oauth-authorization-server':'metadata',
            'GET /keys':'keys','* /keys':'keys','* /authorize':'authorize','* /authorize/':'authorize_mux',
            '* /authorize/callback':'callback','GET /auth/oidc/op/complete':'complete',
            '* /oauth':'oauth_namespace','* /oauth/':'gateway_oauth_mux','* /oauth/ mux':'oauth_mux',
            '* /oauth/ authorization-code':'token','* /oauth/token authorization-code':'token',
            '* /oauth/ refresh-token':'refresh','* /oauth/token refresh-token':'refresh',
            '* /oauth/ introspection':'introspect','* /oauth/introspect':'introspect',
            '* /userinfo':'userinfo','* /revoke':'revoke','* /end_session':'end_session'}[key]
by_route={}
for path in sorted((corpus/'qualified').glob('*.json')):
    if path.stem.endswith('-rows'):continue
    doc=json.loads(path.read_text());by_route.setdefault(doc['route'],[]).append((path,doc))
rows=[]
for route in inv['routes']:
    if route.get('slice')!='federation-op':continue
    method,path=route['method'],route['path'];prefix=f'{method} {path}'
    commands=[''] if route['listener']=='gateway' and path=='/oauth/' else ['discovery','mux'] if path=='/.well-known/' else ['authorization-code','refresh-token','introspection','mux'] if path=='/oauth/' else ['authorization-code','refresh-token'] if path=='/oauth/token' else ['']
    mutators=[c for c in commands if category(prefix+(' '+c if c else '')) in {'authorize','callback','complete','token','refresh','revoke','end_session'}]
    route.update(state='ON',upstream='local-rust' if route['listener']=='gateway' and path in {'/oauth','/oauth/','/authorize/'} else 'rust-auth',oracle_commands=commands,oracle_mutators=mutators)
    for command in commands:
        key=prefix+(' '+command if command else '');group=category(key);mutator=command in mutators
        cases=[]
        for golden,doc in by_route.get(key,[]):
            case=doc['case'];kind=case.removeprefix(group+'-');kind=kind if kind in {'success','cross-tenant','invalid-input','repeat'} else 'edge'
            row=dict(kind=kind,golden=golden.relative_to(root).as_posix(),replay=selector(test_name(case)))
            if mutator:row['row_golden']=golden.with_name(golden.stem+'-rows.json').relative_to(root).as_posix()
            cases.append(row)
        if not {'success','cross-tenant','invalid-input'}.issubset({c['kind'] for c in cases}):raise SystemExit(f'missing recorded floor: {key}')
        base='server-rust/crates/domains/identity/src/oidc'
        sources=(['server-rust/bins/gateway/src/oidc_namespace.rs'] if group in {'authorize_mux','oauth_namespace','gateway_oauth_mux'} else ['server-rust/bins/auth/src/lib.rs',base+'.rs'] if group in {'discovery','metadata'} else ['server-rust/bins/auth/src/lib.rs',base+'/keys.rs'] if group=='keys' else ['server-rust/bins/auth/src/lib.rs'] if group=='well_known_mux' else ['server-rust/bins/auth/src/oidc.rs']+[base+suffix for suffix in ({'callback':['/requests.rs','/crypto.rs'],'token':['/grants.rs','/keys.rs'],'refresh':['/grants.rs'],'userinfo':['/consumers.rs'],'introspect':['/consumers.rs'],'revoke':['/consumers.rs'],'end_session':['/consumers.rs'],'oauth_mux':[]}.get(group,['.rs']))])
        rows.append(dict(listener=route['listener'],method=method,path=path,family='F21',command=command,mutator=mutator,cases=cases,mutant=dict(name='status',**selector(group+'_status_mutant')),handler_sources=sources))
keys={(r['listener'],r['method'],r['path'],r['family'],r.get('command','')) for r in rows}
cat['routes']=[r for r in cat['routes'] if (r['listener'],r['method'],r['path'],r['family'],r.get('command','')) not in keys]+rows
inventory.write_text(json.dumps(inv,indent=2)+'\n');catalog.write_text(json.dumps(cat,indent=2)+'\n')
print(f'IDFED1: {len(rows)} OP route/command suites ON; RP#340 and SAML#341 retained')
