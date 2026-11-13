#!/usr/bin/env python3
"""Updater process oracle. Only the explicitly assigned disposable DB is touched."""
import base64
import contextlib
import copy
import datetime as dt
import hashlib
import fcntl
import hmac
import http.server
import io
import json
import os
import pathlib
import shutil
import signal
import time
import socketserver
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.parse
import uuid

# Fixed probe ports and one fixture schema are serialized within each container.
fixture_lock=open('/tmp/gofree-rel2-installer.lock','w')
fcntl.flock(fixture_lock,fcntl.LOCK_EX)
BINARY = sys.argv[1]
GO = '--go' in sys.argv
CASE = os.environ.get('REL2_INSTALLER_CASE','apply')
assert CASE in ('apply','interrupted','tampered-artifact','nested-comment','rollback')
DSN = os.environ['TEST_DB_DSN']
u = urllib.parse.urlparse(DSN)
assert u.path == '/' + os.environ.get('REL_FIXTURE_DB', 'gofree_e2e_rel2') and u.hostname == '127.0.0.1' and u.port == 55452
PG = dict(os.environ, PGHOST=u.hostname, PGPORT=str(u.port), PGUSER=u.username,
          PGPASSWORD=u.password, PGDATABASE=u.path[1:])

def sql(query):
    p = subprocess.run(['psql', '-XAtq', '-v', 'ON_ERROR_STOP=1'], input=query, text=True,
                       capture_output=True, env=PG, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout.strip()

def literal(v):
    return "'" + str(v).replace("'", "''") + "'"

def sha(b): return hashlib.sha256(b).hexdigest()
def compact(v): return json.dumps(v, separators=(',', ':'), ensure_ascii=False).encode()
def stamp(t): return t.isoformat(timespec='seconds').replace('+00:00', 'Z')
def write(p, b, mode=0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b if isinstance(b, bytes) else b.encode()); p.chmod(mode)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class IMAP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'* OK fixture IMAP4rev2\r\n')
        while line := self.rfile.readline():
            tag, _, rest = line.partition(b' ')
            cmd = rest.upper()
            if cmd.startswith(b'CAPABILITY'):
                self.wfile.write(b'* CAPABILITY IMAP4rev2\r\n')
            elif cmd.startswith((b'SELECT', b'EXAMINE')):
                self.wfile.write(b'* 1 EXISTS\r\n* FLAGS (\\Seen)\r\n* OK [UIDVALIDITY 1]\r\n')
            elif cmd.startswith(b'SEARCH') or cmd.startswith(b'UID SEARCH'):
                self.wfile.write(b'* ESEARCH ALL 1\r\n')
            elif cmd.startswith(b'LOGOUT'):
                self.wfile.write(b'* BYE\r\n' + tag + b' OK done\r\n'); return
            self.wfile.write(tag + b' OK done\r\n')

class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 localhost ESMTP\r\n')
        while line := self.rfile.readline():
            cmd = line.upper()
            if cmd.startswith(b'EHLO'):
                self.wfile.write(b'250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n')
            elif cmd.startswith(b'STARTTLS'):
                self.wfile.write(b'220 ready\r\n'); self.wfile.flush()
                self.connection = TLS.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile('rb'); self.wfile = self.connection.makefile('wb', buffering=0)
            elif cmd.startswith(b'DATA'):
                self.wfile.write(b'354 go\r\n')
                while self.rfile.readline() != b'.\r\n': pass
                self.wfile.write(b'250 queued\r\n')
            elif cmd.startswith(b'QUIT'):
                self.wfile.write(b'221 bye\r\n'); return
            elif cmd.startswith(b'AUTH'): self.wfile.write(b'235 ok\r\n')
            else: self.wfile.write(b'250 ok\r\n')

OBJECTS = {}
class HTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_HEAD(self): self.reply(False)
    def do_GET(self): self.reply(True)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', '0')))
        body=b'{"access_token":"fixture"}' if CASE!='rollback' or (install/'current').readlink().name!=rid else b'{}'; self.send_response(500 if body==b'{}' else 200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def reply(self, body):
        key = urllib.parse.urlparse(self.path).path.removeprefix('/rel2/')
        data = OBJECTS.get(key, b'{}')
        self.send_response(200); self.send_header('Content-Length', str(len(data)))
        self.send_header('ETag', '"fixture"'); self.send_header('Last-Modified','Wed, 04 Nov 2026 00:00:00 GMT'); self.end_headers()
        if body: self.wfile.write(data)

def serve(stack, port, handler, tls=False):
    server = Server(('127.0.0.1', port), handler)
    if tls: server.socket = TLS.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, name='gofree-rel2-fixture', daemon=True)
    thread.start()
    def close(): server.shutdown(); server.server_close(); thread.join(timeout=5)
    stack.callback(close)
    return server.server_address[1]

with tempfile.TemporaryDirectory(prefix='gofree-rel2-installer-') as tmp, contextlib.ExitStack() as stack:
    root = pathlib.Path(tmp)
    subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                    '-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-days','1',
                    '-subj','/CN=localhost'], check=True, capture_output=True)
    TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); TLS.load_cert_chain(root/'cert.pem', root/'key.pem')
    serve(stack, 443, HTTP, True); serve(stack, 8443, HTTP); serve(stack, 993, IMAP, True); serve(stack, 587, SMTP)
    s3 = serve(stack, 0, HTTP)
    bindir = root/'bin'
    write(bindir/'systemctl', '#!/bin/sh\nprintf "%s\\n" "$*" >> "'+str(root/'host.log')+'"\n', 0o700)
    if CASE=='interrupted':
        write(root/'pause-start',b'1')
        with (bindir/'systemctl').open('a') as f:
            f.write('if [ "$1" = start ] && [ -f "'+str(root/'pause-start')+'" ]; then touch "'+str(root/'paused')+'"; while [ -f "'+str(root/'pause-start')+'" ]; do sleep 0.1; done; fi\n')
    if os.environ.get('REL3_RECOVERY_CASE'):
        write(root/'fail-start', '1')
        with (bindir/'systemctl').open('a') as f:
            f.write('if [ "$1" = start ] && [ -f "'+str(root/'fail-start')+'" ]; then exit 1; fi\n')
    env = dict(os.environ, PATH=str(bindir)+':'+os.environ['PATH'])
    for name in ['setjoin-auth.service','setjoin.service','setjoin-gateway.service']:
        write(pathlib.Path('/etc/systemd/system')/name, '[Unit]\nDescription=REL2 fixture\n', 0o644)
    install = root/'install'; store = root/'store'; store.mkdir(mode=0o700)
    old = install/'releases'/'old'; old.mkdir(parents=True)
    artifacts = {}
    for name in ['mailserverd','authserverd','mailctl','setjoin-gateway']:
        content = ('old '+name).encode(); write(old/name, content, 0o500); artifacts[name] = sha(content)
    write(old/'webmail'/'index.html', b'old webmail', 0o400)
    artifacts['webmail'] = sha(b'f\0index.html\0'+sha(b'old webmail').encode()+b'\0')
    write(old/'adoption.json', compact(dict(schema_version=1, release_id='old', database_schema=178,
                                           config_sha256='a'*64, artifacts=artifacts)), 0o400)
    (install/'current').symlink_to('releases/old')
    if CASE=='nested-comment': (install/'previous').symlink_to('releases/old')
    schema = int(sql('SELECT max(version) FROM schema_migrations'))
    registry = json.loads(sql("SELECT json_build_object('catalog_digest',registry_digest,'compatible_modes',ARRAY['enforce','observe'],'compatible_rollback_digests',ARRAY[registry_digest]) FROM feature_toggle_registry_state WHERE singleton"))
    rid = 'rel2-'+uuid.uuid4().hex
    release = store/rid; release.mkdir(mode=0o700)
    fixture = json.load(open('/src/server-rust/crates/release-format/tests/goldens/updater-fixtures.json'))['samples'][0]['manifest']
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    fixture.update(release_id=rid, published_at=stamp(now-dt.timedelta(hours=1)), expires_at=stamp(now+dt.timedelta(days=1)),
                   schema_from=schema, schema_to=schema+1, feature_registry=registry)
    web = io.BytesIO()
    with tarfile.open(fileobj=web, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo('index.html'); content=b'new webmail'; info.size=len(content); info.mode=0o644
        tar.addfile(info, io.BytesIO(content))
    migration_sql=f"CREATE TABLE public.rel2_installer_effect(id integer PRIMARY KEY); INSERT INTO public.rel2_installer_effect VALUES(1); INSERT INTO public.schema_migrations(version) VALUES({schema+1});".encode()
    if CASE=='nested-comment': migration_sql=b'/* outer /* nested */ COMMIT */ '+migration_sql
    mid='migration-rel2'
    fixture['migrations']=[dict(id=mid,from_schema=schema,to_schema=schema+1,sha256=sha(migration_sql),
        **{'class':'expand'},compatibility_evidence='fixture-current',transaction_required=True,previous_binary_evidence='fixture-previous')]
    fixture['artifacts'].append(dict(id=mid,**{'class':'migration'},platform='linux',architecture='amd64',
        size=len(migration_sql),sha256=sha(migration_sql),media_type='application/sql',cohort='core',target='core_migrations'))
    fixture['artifacts'].sort(key=lambda a:a['id'])
    expected = {}
    for a in fixture['artifacts']:
        content = web.getvalue() if a['id']=='webmail' else migration_sql if a['id']==mid else ('new '+a['id']).encode()
        a.update(size=len(content),sha256=sha(content))
        if a['id']=='webmail': a['media_type']='application/vnd.setjoin.webmail.tar'
        if a['id']=='recovery-guide': a['media_type']='text/markdown'
        write(release/a['id'], content, 0o400); expected[a['id']]=content
    # Go canonical bytes: declaration order from the recorded fixture; encoding/json HTML escaping.
    fixture['signatures'] = None
    # Newly inserted optional feature_registry belongs before recovery in Go's struct.
    keys=list(fixture); keys.remove('feature_registry'); keys.insert(keys.index('recovery'),'feature_registry')
    fixture={k:fixture[k] for k in keys}
    canonical=compact(fixture).replace(b'>',b'\\u003e').replace(b'<',b'\\u003c').replace(b'&',b'\\u0026')
    digest=sha(canonical)
    # Real fixture signature. Run mode binds catalog digest, not this test key's policy.
    write(root/'signing.der', bytes.fromhex('302e020100300506032b657004220420')+b'0123456789abcdef0123456789abcdef')
    write(root/'canonical',canonical)
    sig=subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(root/'signing.der'),'-keyform','DER','-in',str(root/'canonical')],check=True,capture_output=True).stdout
    fixture['signatures']=[dict(key_id='rel2-fixture',algorithm='ed25519',value=base64.b64encode(sig).decode().rstrip('='))]
    write(release/'manifest.json',compact(fixture),0o400)
    if CASE=='rollback':
        (old/'adoption.json').unlink()
        old_manifest=copy.deepcopy(fixture)
        old_manifest.update(release_id='old',schema_to=schema,migrations=None,signatures=None)
        old_manifest['artifacts']=[a for a in old_manifest['artifacts'] if a['id']!=mid]
        for a in old_manifest['artifacts']:
            body=('old '+a['id']).encode()
            if a['id']=='webmail':
                archived=io.BytesIO()
                with tarfile.open(fileobj=archived,mode='w',format=tarfile.USTAR_FORMAT) as tar:
                    info=tarfile.TarInfo('index.html'); info.size=len(b'old webmail'); info.mode=0o644; tar.addfile(info,io.BytesIO(b'old webmail'))
                body=archived.getvalue()
            elif a['target']=='recovery_guide': write(old/'share/docs/UPGRADE_RECOVERY.md',body,0o400)
            elif a['target']=='release_sbom': write(old/'share/evidence/sbom.json',body,0o400)
            elif a['target']=='release_provenance': write(old/'share/evidence/provenance.json',body,0o400)
            a.update(size=len(body),sha256=sha(body))
        old_canonical=compact(old_manifest).replace(b'>',b'\\u003e').replace(b'<',b'\\u003c').replace(b'&',b'\\u0026')
        old_digest=sha(old_canonical)
        write(root/'old-canonical',old_canonical)
        old_sig=subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(root/'signing.der'),'-keyform','DER','-in',str(root/'old-canonical')],check=True,capture_output=True).stdout
        old_manifest['signatures']=[dict(key_id='rel2-fixture',algorithm='ed25519',value=base64.b64encode(old_sig).decode().rstrip('='))]
        write(old/'manifest.json',compact(old_manifest),0o400); write(old/'manifest.digest',old_digest+'\n',0o400)
        tree_bytes=b''
        for path in sorted(old.rglob('*')):
            relative=str(path.relative_to(old))
            tree_bytes+=(('d' if path.is_dir() else 'f')+'\0'+relative+'\0'+('' if path.is_dir() else sha(path.read_bytes()))+'\0').encode()
        write(old/'installed.evidence.json',compact(dict(schema_version=1,release_id='old',manifest_sha256=old_digest,content_sha256=sha(tree_bytes))),0o400)
    identity = json.loads(sql('SELECT upgrade_recovery_identity_read()'))
    recovery_id=str(uuid.uuid4()); hkey=b'rel2 recovery public fixture key!'
    recovery={
      'version':1,'recoverySetId':recovery_id,'installationId':identity['installationId'],'timelineId':identity['timelineId'],
      'sourceReleaseId':'old','schemaVersion':schema,'createdAt':stamp(now-dt.timedelta(minutes=1)),
      'expiresAt':stamp(now+dt.timedelta(hours=23))}
    components={'database':b'fixture database','databaseRestoreList':b'fixture list','blobs':compact(dict(timestamp='fixture',type='full',hashes=[],count=0,total_size=0)), 'configuration':b'{}'}
    for name, content in components.items():
        key='recovery-sets/'+recovery_id+'/'+name; OBJECTS[key]=content
        recovery[name]=dict(objectKey=key,size=len(content),sha256=sha(content))
    recovery.update(protectedKeyEvidence=dict(mode='external',keyId='test',fingerprint='a'*64),
                    featureToggleSha256='b'*64,counts=dict(blobs=0,blobBytes=0,users=1,mailboxes=1),representativeIds=None)
    recovery_raw=compact(recovery); recovery_digest=sha(recovery_raw)
    OBJECTS['recovery-sets/'+recovery_id+'/manifest.json']=compact(dict(manifest=recovery,manifestSha256=recovery_digest,hmacSha256=hmac.new(hkey,recovery_raw,hashlib.sha256).hexdigest()))
    # Fresh schema contains no account; provision an isolated fixture via the canonical reducer.
    uid=sql("SELECT id FROM users ORDER BY id LIMIT 1")
    if not uid:
        sql("INSERT INTO domains(name) VALUES('rel2.test') ON CONFLICT DO NOTHING")
        uid=sql("SELECT provision_account(p_email=>'rel2@rel2.test',p_display_name=>'REL2',p_password_hash=>'fixture')->>'user_id'")
    # Seed the approved state; claims/progress/completion use real restricted reducers.
    challenge,elevation,request=[str(uuid.uuid4()) for _ in range(3)]
    q=literal
    sql(f"""
    UPDATE feature_toggles SET enabled=true WHERE key='feature.transactional_upgrades_execution';
    INSERT INTO upgrade_release_catalog(release_id,version,channel,platform,architecture,manifest_digest,manifest,metadata_version,catalog_generation,verified_by_key_ids,verified_at,metadata_expires_at)
    SELECT {q(rid)},'2.1.0','community','linux','amd64',decode('{digest}','hex'),{q(json.dumps(fixture))}::jsonb,1,catalog_generation,ARRAY['rel2-fixture'],now(),now()+interval '1 day' FROM upgrade_control_state WHERE singleton;
    INSERT INTO upgrade_readiness(release_id,manifest_digest,readiness_generation,status,source_version,source_schema_version,target_schema_version,checks,blocker_count,expires_at,checked_by_user_id)
    VALUES({q(rid)},decode('{digest}','hex'),1,'ready','2.0.0',{schema},{schema+1},'{{}}',0,now()+interval '1 day',{uid});
    INSERT INTO upgrade_recovery_sets(recovery_set_id,installation_id,timeline_id,source_release_id,schema_version,manifest_digest,status,checks,created_at,expires_at,recorded_by_user_id)
    VALUES('{recovery_id}','{identity['installationId']}','{identity['timelineId']}',{q(rid)},{schema},decode('{recovery_digest}','hex'),'verified','{{"database":true,"databaseRestoreList":true,"blobs":true,"configuration":true,"protectedKey":true,"featureToggles":true,"hmac":true}}',now(),now()+interval '23 hours',{uid});
    INSERT INTO upgrade_challenges(id,actor_user_id,release_id,preview_digest,readiness_generation,policy_generation,expires_at,idempotency_key,request_digest)
    SELECT '{challenge}',{uid},{q(rid)},decode('{digest}','hex'),1,policy_generation,now()+interval '4 minutes','{request}',decode('{digest}','hex') FROM upgrade_control_state WHERE singleton;
    INSERT INTO upgrade_elevations(id,actor_user_id,challenge_id,release_id,preview_digest,readiness_generation,policy_generation,session_digest,factor_digest,amr,acr,expires_at,request_digest)
    SELECT '{elevation}',{uid},'{challenge}',{q(rid)},decode('{digest}','hex'),1,policy_generation,decode('{digest}','hex'),decode('{digest}','hex'),ARRAY['pwd','totp'],'urn:setjoin:aal2',now()+interval '4 minutes',decode('{digest}','hex') FROM upgrade_control_state WHERE singleton;
    UPDATE upgrade_challenges SET completed_at=now(),elevation_id='{elevation}' WHERE id='{challenge}';
    INSERT INTO upgrade_intents(installation_id,release_id,manifest_digest,catalog_generation,readiness_generation,policy_generation,preview_digest,state,requested_by_user_id,requester_elevation_id,approved_by_user_id,reason,expires_at,idempotency_key,request_digest,recovery_set_id,recovery_set_digest)
    SELECT installation_id,{q(rid)},decode('{digest}','hex'),catalog_generation,1,policy_generation,decode('{digest}','hex'),'approved',{uid},'{elevation}',{uid},'REL2 installer fixture',now()+interval '1 hour','{request}',decode('{digest}','hex'),'{recovery_id}',decode('{recovery_digest}','hex') FROM upgrade_control_state WHERE singleton;
    """)
    def cleanup():
        # History is append-only. Keep fixture records until the private cluster
        # is destroyed; only release an interrupted fixture's active slot.
        sql(f"""UPDATE upgrade_intents SET state='failed',completed_at=now(),result='{{"fixtureCleanup":true}}'::jsonb
          WHERE release_id={q(rid)} AND state NOT IN ('verified','rolled_back','failed','cancelled','expired');
        DELETE FROM upgrade_schema_migration_evidence WHERE release_id={q(rid)};
        DROP TABLE IF EXISTS public.rel2_installer_effect; DELETE FROM schema_migrations WHERE version={schema+1};
        UPDATE feature_toggles SET enabled=false WHERE key='feature.transactional_upgrades_execution';""")
    stack.callback(cleanup)
    control=os.environ.get('UPDATER_TEST_DSN', DSN.replace('postgres:gofree@','setjoin_updater:updater_e2e@'))
    write(root/'dsn',control); write(root/'owner',DSN)
    write(root/'access','fixture'); write(root/'secret','fixture-secret'); write(root/'hmac',hkey)
    write(root/'probe',compact(dict(email='probe@rel2.test',password='fixture-password-123')))
    write(root/'execution.json',compact(dict(version=1,enabled=True,installRoot=str(install),recoveryProvider='s3',recoveryEndpoint=f'http://127.0.0.1:{s3}',recoveryBucket='rel2',recoveryRegion='us-east-1')))
    if os.environ.get('REL3_SWAP_ONLY'):
        import swap_flow
        swap_flow.run(root, install, env, BINARY, sql, rid)
        sys.exit(0)
    if CASE=='tampered-artifact':
        original=(release/'mailserverd').read_bytes()
        write(release/'mailserverd',b'X'+original[1:],0o400)
    args=[BINARY]+([] if GO else ['run'])+['--once','--state-dir',str(root/'state'),'--release-store',str(store),'--dsn-file',str(root/'dsn'),
        '--owner-dsn-file',str(root/'owner'),'--execution-config',str(root/'execution.json'),
        '--recovery-access-key-file',str(root/'access'),'--recovery-secret-key-file',str(root/'secret'),
        '--recovery-hmac-key-file',str(root/'hmac'),'--probe-credential-file',str(root/'probe')]
    if CASE=='interrupted':
        child=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        try:
            deadline=time.monotonic()+45
            while not (root/'paused').exists():
                assert child.poll() is None, child.communicate()[1]
                assert time.monotonic()<deadline,'updater never reached the start boundary'
                time.sleep(0.05)
            # A process crash after activation leaves the reducer at switched.
            observed_tip=json.loads(sql('SELECT upgrade_intent_read(NULL)'))
            assert observed_tip['state']=='switched',observed_tip
        finally:
            if child.poll() is None: os.killpg(child.pid,signal.SIGKILL)
            child.communicate(timeout=10)
            (root/'pause-start').unlink(missing_ok=True)
    p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=100)
    if os.environ.get('REL3_RECOVERY_CASE'):
        assert p.returncode != 0, p.stderr
        assert json.loads(sql('SELECT upgrade_intent_read(NULL)'))['state'] == 'recovery_required', p.stderr
        (root/'fail-start').unlink()
        import recovery_flow
        recovery_flow.run(root, install, env, BINARY, GO, PG, sql, rid, stack)
        sys.exit(0)
    assert (p.returncode==0)==(CASE not in ('tampered-artifact','nested-comment','rollback')), p.stderr
    result=json.loads(sql('SELECT upgrade_intent_read(NULL)'))
    if CASE in ('tampered-artifact','nested-comment'):
        assert result['state']==('failed' if CASE=='tampered-artifact' else 'recovery_required'),result
        assert (install/'current').readlink()==pathlib.Path('releases/old')
        assert (install/'previous').exists()==(CASE=='nested-comment')
        assert (install/'releases'/rid).exists()==(CASE=='nested-comment')
        assert sql("SELECT to_regclass('public.rel2_installer_effect')") == ''
    elif CASE=='rollback':
        assert result['state']=='rolled_back',result
        assert (install/'current').readlink()==pathlib.Path('releases/old')
        assert (install/'previous').readlink()==pathlib.Path('releases')/rid
        assert (install/'current'/'mailserverd').read_bytes()==b'old mailserverd'
        assert sql('SELECT count(*) FROM rel2_installer_effect')=='1'
        assert sql('SELECT count(*) FROM upgrade_schema_migration_evidence WHERE release_id='+literal(rid))=='1'
    else:
        assert result['state']=='verified', result
        assert (install/'current').readlink()==pathlib.Path('releases')/rid
        assert (install/'previous').readlink()==pathlib.Path('releases/old')
        assert (install/'current'/'mailserverd').read_bytes()==expected['mailserverd']
        assert (install/'current'/'webmail'/'index.html').read_bytes()==b'new webmail'
        assert sql('SELECT count(*) FROM rel2_installer_effect')=='1'
        assert sql('SELECT count(*) FROM upgrade_schema_migration_evidence WHERE release_id='+literal(rid))=='1'
    states=[e['to'] for e in result['events']]
    observed=dict(states=states, host=(root/'host.log').read_text().splitlines(),
                  result=json.loads(json.dumps(result['result']).replace(rid,'<release>')),files=sorted(str(p.relative_to(install/'current')) for p in (install/'current').rglob('*') if p.is_file()))
    golden_name='installer.json' if CASE=='apply' else 'installer-'+CASE+'.json'
    golden_path=pathlib.Path('/src/server-rust/bins/updater/tests/goldens')/golden_name
    if GO:
        dest=pathlib.Path(os.environ['REL2_RECORD_DIR'])/golden_name
        with dest.open('x') as f: json.dump(dict(go_source=os.environ['GOFREE_GO_SOURCE'],observed=observed),f,indent=2); f.write('\n')
    else:
        assert observed==json.loads(golden_path.read_text())['observed'], observed
    # A completed intent replays without a second stop/start or state bump.
    second=subprocess.run(args,env=env,capture_output=True,text=True,timeout=30)
    assert second.returncode==0,second.stderr
    repeated=json.loads(sql('SELECT upgrade_intent_read(NULL)'))
    assert repeated['stateGeneration']==result['stateGeneration']
    assert (root/'host.log').read_text().splitlines()==observed['host']
    print('REL2 installer '+CASE+': Go parity and repeat passed')
