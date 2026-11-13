#!/usr/bin/env python3
"""Append #336's qualified registrations without rewriting other suite decisions."""
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[4]
corpus=Path(__file__).resolve().parent
inventory=root/'server-rust/bins/gateway/route-inventory.json'
catalog=root/'server-rust/tests/conformance/route-catalog.json'
inv=json.loads(inventory.read_text());cat=json.loads(catalog.read_text())
qualified={('GET','/auth/push/vapid-key'):('vapid',False),('POST','/auth/mfa/reauth'):('reauth',True),('POST','/auth/mfa/possession/totp'):('possession-totp',True),('POST','/auth/backup-codes/generate'):('backup-generate',True),('POST','/auth/backup-codes/verify'):('backup-verify',True),('POST','/auth/push/verify'):('push-verify',False),('POST','/auth/push/status'):('push-status',True),('POST','/auth/mfa/approve'):('push-approve',True),('POST','/auth/mfa/push/send'):('push-send',True),('POST','/auth/forgot-password/begin'):('recovery-begin',True),('POST','/auth/forgot-password/verify'):('recovery-verify',True),('POST','/auth/mfa/possession/webauthn/begin'):('possession-webauthn-begin',True),('POST','/auth/mfa/possession/webauthn/finish'):('possession-webauthn-finish',True),('*','/auth/push/'):('push-subtree',False),('*','/auth/backup-codes/'):('backup-subtree',False)}
tests=set(re.findall(r"async fn (\w+)\(",(root/"server-rust/bins/auth/tests/push_oracle.rs").read_text()))
rows=[]
for route in inv['routes']:
 key=route['method'],route['path']
 if route['listener'] not in {'auth','gateway'} or key not in qualified:continue
 prefix,mutator=qualified[key]
 route.update(state='ON',upstream='rust-auth',oracle_commands=[''],oracle_mutators=[''] if mutator else [])
 replay=lambda test:dict(package='setjoin-auth',target='push_oracle',test=test)
 suite=dict(listener=route['listener'],method=key[0],path=key[1],family='F21',command='',mutator=mutator,cases=[],mutant=dict(replay(prefix.replace('-','_')+'_status_mutant'),name='status'),handler_sources=['server-rust/bins/auth/src/'+('lib.rs' if prefix=='vapid' else 'possession.rs' if prefix.startswith('possession-webauthn-') else 'recovery.rs' if prefix.startswith('recovery-') else 'totp.rs' if prefix=='backup-verify' else 'push.rs'),'server-rust/crates/domains/identity/src/'+('possession.rs' if prefix.startswith('possession-webauthn-') else 'recovery.rs' if prefix.startswith('recovery-') else 'push.rs')])
 if prefix.endswith('-subtree'):suite['handler_sources']=['server-rust/bins/auth/src/push.rs','server-rust/bins/auth/src/lib.rs']
 if prefix.startswith('possession-webauthn-'):suite['handler_sources'].append('server-rust/crates/domains/identity/src/webauthn.rs')
 if prefix=='recovery-verify':suite['handler_sources'].append('server-rust/crates/domains/identity/src/totp.rs')
 if prefix=='push-send':suite['handler_sources'].append('server-rust/crates/domains/identity/src/push_delivery.rs')
 for p in sorted((corpus/'goldens').glob(prefix+'-*.json')):
  if p.stem.endswith('-rows'):continue
  doc=json.loads(p.read_text());kind=doc['case'].removeprefix(prefix+'-')
  if doc['route']!=' '.join(key):continue
  selector=p.stem.replace('-','_')
  if selector not in tests:
   if prefix.startswith('recovery-'):selector='recovery_edge_'+prefix.removeprefix('recovery-')+'_'+kind.replace('-','_')
   elif prefix.startswith('possession-webauthn-'):selector='possession_edge_'+prefix.removeprefix('possession-webauthn-')+'_'+kind.replace('-','_')
  assert selector in tests,(p,selector)
  case=dict(kind=kind if kind in {'success','cross-tenant','invalid-input','repeat'} else 'edge',golden=p.relative_to(root).as_posix(),replay=replay(selector))
  if prefix.endswith('-subtree') or prefix=='vapid' and kind=='head':case['golden']=(corpus/'qualified'/p.name).relative_to(root).as_posix()
  if mutator:case['row_golden']=(corpus/'qualified'/(p.stem+'-rows.json')).relative_to(root).as_posix()
  suite['cases'].append(case)
 rows.append(suite)
keys={(r['listener'],r['method'],r['path'],r['family'],r.get('command','')) for r in rows}
cat['routes']=[r for r in cat['routes'] if (r['listener'],r['method'],r['path'],r['family'],r.get('command','')) not in keys]+rows
# #333 already owns both registration aliases and its WebPush case floor.
# Append native-device observations without replacing that suite or its decisions.
for suite in cat['routes']:
 if suite['family']!='F21' or suite['method']!='POST' or suite['path']!='/auth/device/register':continue
 suite['cases']=[case for case in suite['cases'] if not(case.get('replay',{}).get('target')=='push_oracle' and case['replay']['test'].startswith('native_register_'))]
 for source in ['server-rust/bins/auth/src/push.rs','server-rust/crates/domains/identity/src/push.rs']:
  if source not in suite['handler_sources']:suite['handler_sources'].append(source)
 for p in sorted((corpus/'goldens').glob('native-register-*.json')):
  if p.stem.endswith('-rows'):continue
  suite['cases'].append(dict(kind='edge',golden=p.relative_to(root).as_posix(),row_golden=(corpus/'qualified'/(p.stem+'-rows.json')).relative_to(root).as_posix(),replay=dict(package='setjoin-auth',target='push_oracle',test=p.stem.replace('-','_'))))
# #331 owns the login registrations; retain its complete floor and decisions.
for suite in cat['routes']:
 if suite['family']!='F21' or suite['method']!='POST' or suite['path']!='/auth/login':continue
 suite['cases']=[case for case in suite['cases'] if not(case.get('replay',{}).get('target')=='push_oracle' and case['replay']['test'].startswith('push_login_'))]
 for source in ['server-rust/bins/auth/src/push.rs','server-rust/crates/domains/identity/src/push.rs','server-rust/crates/domains/identity/src/push_delivery.rs']:
  if source not in suite['handler_sources']:suite['handler_sources'].append(source)
 for p in sorted((corpus/'goldens').glob('push-login-*.json')):
  if p.stem.endswith('-rows'):continue
  suite['cases'].append(dict(kind='edge',golden=p.relative_to(root).as_posix(),row_golden=(corpus/'qualified'/(p.stem+'-rows.json')).relative_to(root).as_posix(),replay=dict(package='setjoin-auth',target='push_oracle',test=p.stem.replace('-','_'))))
# #335 owns this registration; append #336's passkey-first push handoffs.
for suite in cat['routes']:
 if suite['family']!='F21' or suite['method']!='POST' or suite['path']!='/auth/webauthn/login/finish':continue
 suite['cases']=[case for case in suite['cases'] if not case.get('replay',{}).get('test','').startswith('login_finish_pending_push')]
 for p in sorted((root/'server-rust/tests/conformance/identity-webauthn/qualified').glob('login-finish-pending-push*.json')):
  if p.stem.endswith(('-rows','-anonymous')):continue
  suite['cases'].append(dict(kind='edge',golden=p.relative_to(root).as_posix(),row_golden=p.with_name(p.stem+'-rows.json').relative_to(root).as_posix(),replay=dict(package='setjoin-auth',target='webauthn_oracle',test=p.stem.replace('-','_'))))
for path,data in [(inventory,inv),(catalog,cat)]:
 text=json.dumps(data,indent=2)+'\n'
 if path.read_text()!=text:path.write_text(text)
print(f'IDMFA3: {len(rows)} qualified registrations')
