"""Frozen-Go standalone process oracle; only operates on an explicit test DSN."""
import argparse
import sys
import json
import os
import contextlib
import copy
import re
import hashlib
import fnmatch
import fcntl
import signal
import tempfile
import base64
from push_service import Service
from backup_oracle import reset_public_fixture
from db_snapshot import snapshot, diff, FK_SQL, expected_normalization
from pathlib import Path
import subprocess
import urllib.parse

HERE = Path(__file__).resolve().parent

# Frozen recordings used V275. Schema commands are parameterized by the
# canonical catalog, so retarget only expected version/name tokens. Actual
# process output and effects remain exact and may not choose their own target.
SCHEMA_CATALOG = sorted((int(p.name[1:].split("__",1)[0]),p.name) for p in
    (HERE.parents[3]/"mailserver/sql/dbschema").glob("V*__*.sql"))
SCHEMA_LATEST, SCHEMA_FILENAME = SCHEMA_CATALOG[-1]
SCHEMA_PREVIOUS = SCHEMA_CATALOG[-2][0]

def schema_expectation(case, expected):
    if case["args"][0] != "schema": return expected
    expected = copy.deepcopy(expected)
    for stream in ("stdout", "stderr"):
        expected[stream] = expected[stream].replace("V275__feature_toggle_registry_projection.sql", SCHEMA_FILENAME)
        expected[stream] = re.sub(r"(?<![A-Za-z0-9_])(?:274|275)(?![A-Za-z0-9_])",
            lambda m: str(SCHEMA_LATEST if m[0]=="275" else SCHEMA_PREVIOUS), expected[stream])
    for effect in ("schema_added", "schema_removed"):
        expected["database_effects"][effect] = [SCHEMA_LATEST if n==275 else n for n in expected["database_effects"][effect]]
    return expected

def sql(statement):
    return subprocess.check_output(["psql", DSN, "-XAt", "--set", "VERBOSITY=terse", "-v", "ON_ERROR_STOP=1", "-c", statement], text=True).strip()

def cases():
    items = [
        {"name":"push-test-apns","args":["push","test","--user","alice@gofree-mctl3.test"],"env":{"APNS_CERT_PATH":"{ROOT}/apns.p12","APNS_CERT_PASSWORD":"synthetic","APNS_BUNDLE_ID":"test.fixture.app","DB_ENCRYPTION_KEY":"mctl3-fixture-encryption"},"service":True,"users":True,"apns_loopback":True,"files":{"apns.p12":{"base64":base64.b64encode((HERE/"fixtures/push-apns.p12").read_bytes()).decode()}}},
        *[{"name":"push-test-webpush-"+str(i),"args":["push","test","--user","alice@gofree-mctl3.test"],"env":{"VAPID_PRIVATE_KEY":json.loads((HERE/"fixtures/push-vapid.json").read_text())["private"],"DB_ENCRYPTION_KEY":"mctl3-fixture-encryption",**({"MAILCTL_ORACLE_WEBPUSH_LOOPBACK":"1"} if i==0 else {})},"service":True,"users":True,"webpush_device":True} for i in range(2)],
        {"name":"push-test-hms","args":["push","test","--user","ALICE@gofree-mctl3.test"],"env":{"HMS_APP_ID":"fixture-app","HMS_APP_SECRET":"synthetic-secret","DB_ENCRYPTION_KEY":"mctl3-fixture-encryption"},"service":True,"users":True,"push_devices":True},
        {"name":"push-test-fcm","args":["push","test","--user","alice@gofree-mctl3.test"],"env":{"FCM_SERVICE_ACCOUNT_FILE":"{ROOT}/sa.json","DB_ENCRYPTION_KEY":"mctl3-fixture-encryption"},"service":True,"users":True,"push_devices":True,"files":{"sa.json":json.dumps({"type":"service_account","project_id":"fixture-project","client_email":"synthetic@fixture.invalid","private_key_id":"fixture-key","private_key":(HERE/"fixtures/smime-key.pem").read_text(),"token_uri":"{HTTP}/oauth/fcm"})}},
        *[{"name":"push-apns-"+str(i),"args":["push","doctor"],"env":{"APNS_CERT_PATH":"{ROOT}/apns.p12","APNS_CERT_PASSWORD":password,"APNS_BUNDLE_ID":"test.fixture.app"},"files":{"apns.p12":{"base64":base64.b64encode((HERE/("fixtures/push-apns-modern.p12" if i==2 else "fixtures/push-apns.p12")).read_bytes()).decode()}}} for i,password in enumerate(["synthetic","wrong","synthetic"])],
        {"name":"push-hms-doctor","args":["push","doctor"],"env":{"HMS_APP_ID":"fixture-app","HMS_APP_SECRET":"synthetic-secret"},"service":True},
        {"name":"push-fcm-doctor","args":["push","doctor"],"env":{"FCM_SERVICE_ACCOUNT_FILE":"{ROOT}/sa.json"},"service":True,"files":{"sa.json":json.dumps({"type":"service_account","project_id":"fixture-project","client_email":"synthetic@fixture.invalid","private_key_id":"fixture-key","private_key":(HERE/"fixtures/smime-key.pem").read_text(),"token_uri":"{HTTP}/oauth/fcm"})}},
        *[{"name":"push-provider-"+str(i),"args":["push","doctor"],"env":env,"files":files} for i,(env,files) in enumerate([
            ({"VAPID_PRIVATE_KEY":"a?"},{}), ({"VAPID_PRIVATE_KEY":"AA"},{}), ({"VAPID_PRIVATE_KEY":"A"*43},{}),
            ({"VAPID_PRIVATE_KEY":"A"*43,"VAPID_SUBJECT":"mailto:synthetic@example.test"},{}),
            ({"APNS_CERT_PATH":"/gofree-mctl3-missing-p12"},{}),
            ({"FCM_SERVICE_ACCOUNT_FILE":"{ROOT}/sa.json"},{"sa.json":"{"}),
            ({"FCM_SERVICE_ACCOUNT_FILE":"{ROOT}/sa.json"},{"sa.json":'{"type":"wrong"}'}),
            ({"FCM_SERVICE_ACCOUNT_FILE":"{ROOT}/sa.json"},{"sa.json":'{"type":"service_account"}'}),
        ])],
        {"name":"push-doctor","args":["push","doctor","--json"],"env":{"DB_DSN":""}},
        *[{"name":"smime-write-"+str(i),"args":["smime","import","{ROOT}/manifest.csv",*flags],"env":{"DB_ENCRYPTION_KEY":"mctl3-fixture-encryption"},"users":True,"files":{
            "manifest.csv":"email,cert_path,key_path,label\nalice@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/key.pem,signing\n"+("alice@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/key.pem,signing\nmissing@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/key.pem,signing\n" if i==1 else ""),
            "cert.pem":(HERE/"fixtures/smime-cert.pem").read_text(),"key.pem":(HERE/"fixtures/smime-key.pem").read_text()
        },"smime_fault":i==2} for i,flags in enumerate([["--default"],[],["--default"]])],
        {"name":"smime-key-formats","args":["smime","import","--dry-run","{ROOT}/manifest.csv"],"env":{"DB_DSN":""},"files":{
            "manifest.csv":"email,cert_path,key_path,label\n# comment\n\nalice@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/rsa.pem,pkcs1\nbob@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/ec.pem,sec1\nalice@gofree-mctl3.test,{ROOT}/missing.pem,{ROOT}/rsa.pem\nalice@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/bad.pem\n",
            "cert.pem":(HERE/"fixtures/smime-cert.pem").read_text(),"rsa.pem":(HERE/"fixtures/smime-rsa.pem").read_text(),"ec.pem":(HERE/"fixtures/smime-ec.pem").read_text(),"bad.pem":"not a private key"
        }},
        *[{"name":"smime-invalid-"+str(i),"args":["smime","import",*argv],"env":{"DB_DSN":""},"files":{"manifest.csv":manifest,"cert.pem":cert,"key.pem":key}} for i,(argv,manifest,cert,key) in enumerate([
            (["{ROOT}/manifest.csv","--dry-run"],"email,cert_path,key_path\n","", ""),
            (["{ROOT}/manifest.csv","--dry-run"],"a,b\n","", ""),
            (["{ROOT}/manifest.csv","--dry-run"],"a,,key\n","", ""),
            (["{ROOT}/manifest.csv","--dry-run"],"alice,{ROOT}/cert.pem,{ROOT}/key.pem\n","bad certificate", "bad key"),
            (["{ROOT}/manifest.csv","--dry-run"],"alice,{ROOT}/cert.pem,{ROOT}/key.pem\n",(HERE/"fixtures/smime-cert.pem").read_text(),(HERE/"fixtures/smime-encrypted.pem").read_text()),
            (["--unknown"],"","", ""), (["--help"],"","", ""), ([],"","", ""),
            (["{ROOT}/manifest.csv"],"email,cert_path,key_path\n","", ""),
        ])],
        {"name":"smime-dry-run","args":["smime","import","{ROOT}/manifest.csv","--dry-run","--default"],"env":{"DB_DSN":"","DB_ENCRYPTION_KEY":""},"files":{
            "manifest.csv":"email,cert_path,key_path,label\nalice@gofree-mctl3.test,{ROOT}/cert.pem,{ROOT}/key.pem,signing\n",
            "cert.pem":(HERE/"fixtures/smime-cert.pem").read_text(),"key.pem":(HERE/"fixtures/smime-key.pem").read_text()
        }},
        *[{"name":"sources-profile-"+str(i),"args":["sources",action,"--root","{ROOT}",*argv],"env":{"DB_DSN":""},"files":{"etc/os-release":"ID=ubuntu\nVERSION_ID=24.04\n"}} for i,(action,argv) in enumerate([
            ("doctor",["--json","--profile","china"]), ("status",["--profile","china","--china-registry","registry.example/code"]),
            ("doctor",["--json","--profile","isolated","--isolated-registry","registry.lan/code"]),
            ("doctor",["--json","--profile","isolated","--isolated-registry","registry.lan/code","--isolated-registry-approved"]),
            ("status",["--json","--profile","custom","--custom-registry","registry.lan:5000/team/code/"]),
            ("doctor",["--json","--profile","unknown"]), ("doctor",["--json","--collabora-registry","https://user:secret@host/code"]),
            ("doctor",["--json","--collabora-registry","host/code:latest"]), ("status",["--json","--profile","isolated"]),
            ("status",["--json","--profile","custom"]), ("status",["--unknown"]), ("status",["extra"]),
        ])],
        {"name":"sources-host","args":["sources","status","--json","--root","{ROOT}"],"env":{"DB_DSN":"","SAFEBROWSING_API_KEY":"synthetic"},"files":{
            "etc/os-release":"ID=ubuntu\nVERSION_ID='22.04'\n", "etc/apt/sources.list":"deb [arch=amd64 signed-by=/key] https://archive.example/ubuntu noble main\n",
            "etc/apt/sources.list.d/setjoin-code.sources":"Types: deb\nURIs: https://user:secret@repo.example/path?token=secret https://other.example/code\nEnabled: no\n",
            "etc/docker/daemon.json":'{"registry-mirrors":["https://user:secret@mirror.example:5000/path?token=secret"]}'
        }},
        {"name":"sources-db","args":["sources","status","--json","--root","{ROOT}"],"files":{},"assist":True},
        {"name":"sources-db-invalid","args":["sources","doctor","--root","{ROOT}"],"files":{},"assist":"invalid"},
        {"name":"sources-missing-host","args":["sources","status","--root","{ROOT}"],"files":{},"env":{"DB_DSN":"","NETWORK_MODE":"manual"}},
        {"name": "sources-global", "args": ["sources","status","--json","--root","{ROOT}"], "env": {"DB_DSN":""}, "files": {"etc/os-release": "ID=ubuntu\nVERSION_ID=24.04\n", "etc/apt/sources.list": "deb https://user:secret@archive.example/ubuntu?token=secret noble main\n# deb https://old.example/ubuntu stable main\n"}},
        {"name": "bootstrap-smx", "args": ["bootstrap-admin", "--email", "operator@gofree-mctl3.test", "--password-stdin"], "stdin": "Strong-Synthetic-123!\n", "bootstrap": True, "env": {"CRYPTO_PROFILE": "smx"}},
        *[{"name": "bootstrap-invalid-"+str(i), "args": ["bootstrap-admin",*argv], "stdin": "Strong-Synthetic-123!\n"} for i,argv in enumerate([
            ["--email","not-an-address"], ["--email","Admin <admin@example.test>"], ["--email","a..b@example.test"],
            ["--email",'"simple"@example.test'], ["--email","postmaster@example.test"], ["--email","admin@example.test","extra"],
            ["--email","admin@example.test","--password-stdin","--password-file","secret"], ["--unknown"], ["--email"],
            ["--email","admin@example.test","--password-file","/gofree-mctl3-missing-password"]])],
        *[{"name": "bootstrap-password-"+str(i), "args": ["bootstrap-admin","--email","operator@gofree-mctl3.test","--password-stdin"],"stdin":password} for i,password in enumerate([
            "", "short\n", "a"*73+"\n", "lowercase123!\n", "UPPERCASE123!\n", "NoNumbers-Here!\n", "NoPunct123\n", "Operator-123!\n", "Aa1\u0301漢字漢字\n"] )],
        {"name": "bootstrap-create", "args": ["bootstrap-admin", "--email", "Operator@Gofree-Mctl3.Test", "--password-stdin"], "stdin": "Strong-Synthetic-123!\n", "bootstrap": True},
        {"name": "scim-list-empty", "args": ["scim", "list-tokens", "ignored"]},
        {"name": "scim-list", "args": ["scim", "list-tokens"], "token_seed": True},
        {"name": "scim-list-paused", "args": ["scim", "list-tokens"], "token_seed": True, "source_state": "paused"},
        {"name": "scim-create", "args": ["scim", "create-token", "--name", "oracle", "--source", "scim:gofree-mctl3"]},
        {"name": "scim-expiry", "args": ["scim", "create-token", "--name", "oracle", "--source", "scim:gofree-mctl3", "--expiry", "1h30m", "--deletion-policy", "hard"], "expiry": 5400},
        {"name": "scim-missing-source", "args": ["scim", "create-token", "--name", "oracle", "--source", "scim:missing"]},
        {"name": "scim-paused-source", "args": ["scim", "create-token", "--name", "oracle", "--source", "scim:gofree-mctl3"], "source_state": "paused"},
        *[{"name": "scim-invalid-"+str(i), "args": ["scim", "create-token", *argv]} for i,argv in enumerate([
            [], ["--name"," oracle "], ["--name","oracle"], ["--name","oracle","--source"," padded "],
            ["--name","oracle","--source","scim:gofree-mctl3","--expiry","-1s"],
            ["--expiry","wat"], ["--unknown"], ["--help"], ["arg"],
            ["--name","oracle","--source","scim:gofree-mctl3","--deletion-policy","x"]])],
        {"name":"bootstrap-repeat","args":["bootstrap-admin","--email","operator@gofree-mctl3.test","--password-stdin"],"stdin":"Strong-Synthetic-123!\n","bootstrap":True,"bootstrap_repeat":True},
        {"name":"bootstrap-rollback","args":["bootstrap-admin","--email","operator@gofree-mctl3.test","--password-stdin"],"stdin":"Strong-Synthetic-123!\n","bootstrap":True,"bootstrap_fault":True},
        {"name":"bootstrap-utf8-limit","args":["bootstrap-admin","--email","operator@gofree-mctl3.test","--password-stdin"],"stdin":"a"*73+"漢\n"},
        {"name":"schema-rollback","args":["schema","apply","--yes"],"schema":"behind","schema_fault":True,"snapshot":True},
        {"name": "schema-current", "args": ["schema", "check", "--json"]},
        {"name": "schema-current-human", "args": ["schema", "check"]},
        {"name": "schema-apply-current", "args": ["schema", "apply", "--yes"]},
        {"name": "schema-behind", "args": ["schema", "check", "--json"], "schema": "behind"},
        {"name": "schema-apply", "args": ["schema", "apply", "--yes"], "schema": "behind"},
        {"name": "schema-cancel", "args": ["schema", "apply"], "schema": "behind", "stdin": "n\n"},
        {"name": "schema-yes", "args": ["schema", "apply", "-y"], "schema": "behind"},
        {"name": "schema-missing-baseline", "args": ["schema", "apply"], "schema": "empty"},
        {"name": "schema-unknown", "args": ["schema", "bogus"], "env": {"DB_DSN": "", "DB_DIRECT_DSN": ""}},
        {"name": "schema-owner-precedence", "args": ["schema", "check", "--json"], "env": {"DB_DIRECT_OWNER_DSN": "{DSN}", "DB_OWNER_DSN": "invalid", "DB_DIRECT_DSN": "invalid", "DB_DSN": "invalid"}},
    ]

    for name,base,changes in [
        ("push-fcm-dead","push-test-fcm",{"push_status":404}),
        ("push-hms-dead","push-test-hms",{"hms_code":"80300007"}),
        ("push-hms-http-failure","push-test-hms",{"push_status":503}),
        ("push-fcm-cache","push-test-fcm",{"extra_fcm":True}),
        ("push-missing-user","push-test-hms",{"args":["push","test","--user","missing@gofree-mctl3.test"]}),
        ("push-empty-devices","push-test-hms",{"push_devices":False}),
        ("push-wrong-key","push-test-hms",{"wrong_key":True}),
        ("push-corrupt-device","push-test-hms",{"corrupt_device":True}),
        ("push-operator-dsn","push-test-hms",{"dsn_sentinels":True}),
        ("push-apns-reuse","push-test-apns",{"extra_apns":True,"capture_connection":True}),
        ("push-apns-production","push-test-apns",{"production":"t","capture_authority":True}),
        ("push-apns-invalid-bool","push-test-apns",{"production":"yes","capture_authority":True}),
    ]:
        item=copy.deepcopy(next(c for c in items if c["name"]==base));item.update(changes);item["name"]=name
        if item.get("wrong_key"):item["env"]["DB_ENCRYPTION_KEY"]="incorrect-key"
        if "production" in item:item["env"]["APNS_PRODUCTION"]=item["production"]
        if item.get("dsn_sentinels"):item["env"].update({k:"invalid" for k in ["DB_DIRECT_DSN","DB_OWNER_DSN","DB_DIRECT_OWNER_DSN","DB_WORKER_DSN"]})
        items.append(item)
    items.extend({"name":"push-invalid-"+str(i),"args":argv,"env":env} for i,(argv,env) in enumerate([
        (["push","bogus"],{"DB_DSN":""}), (["push","test"],{}),(["push","test","--help"],{}),(["push","test","--unknown"],{}),
        (["push","test","--user","alice@example.test"],{}),(["push","test","--user","alice@example.test"],{"DB_ENCRYPTION_KEY":"synthetic"}),
        (["push","test","--user","alice@example.test"],{"DB_ENCRYPTION_KEY":"synthetic","VAPID_PRIVATE_KEY":"A"*43,"DB_DSN":""}),
    ]))
    return items

@contextlib.contextmanager
def fixture(case):
    root = tempfile.TemporaryDirectory(prefix="gofree-mctl3-cli-",dir="/tmp")
    case["root"] = root.name
    for path,content in case.get("files",{}).items():
        target = Path(root.name)/path
        target.parent.mkdir(parents=True,exist_ok=True)
        if isinstance(content,dict): target.write_bytes(base64.b64decode(content["base64"]))
        else: target.write_text(content.replace("{ROOT}",root.name))
        target.chmod(0o600)
    saved = sql("SELECT COALESCE(json_agg(t ORDER BY version),'[]') FROM schema_migrations t")
    backup = None
    if case["args"][0]=="bootstrap-admin":
        assert sql("SELECT count(*) FROM users") == "0", "bootstrap fixture requires an empty assigned database"
        backup = tempfile.NamedTemporaryFile(prefix="gofree-mctl3-bootstrap-", suffix=".dump", delete=False)
        subprocess.run(["pg_dump",DSN,"-Fc","-f",backup.name],check=True,capture_output=True)
    if case.get("bootstrap_repeat"):
        sql("SELECT ensure_default_admin('operator@gofree-mctl3.test','$2a$10$abcdefghijklmnopqrstuu0123456789012345678901234567890')")
    if case.get("bootstrap_fault"):
        sql("UPDATE admin_role_groups SET name='MCTL3 hidden Super Admin' WHERE name='Super Admin' AND is_builtin")
    if case.get("schema_fault"):
        sql("CREATE FUNCTION gofree_mctl3_schema_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture migration failure'; END $$; CREATE TRIGGER gofree_mctl3_schema_fail BEFORE INSERT ON schema_migrations FOR EACH ROW EXECUTE FUNCTION gofree_mctl3_schema_fail()")
    if case.get("schema") == "behind":
        sql(f"DELETE FROM schema_migrations WHERE version = {SCHEMA_LATEST}")
    if case.get("schema") == "empty":
        sql("DELETE FROM schema_migrations")
    if case["args"][0] == "scim":
        sql("INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state) VALUES ('scim:gofree-mctl3','MCTL3 oracle','scim','{\"provision\":true,\"stable_immutable_subject\":true}','active')")
    if case.get("token_seed"):
        sql("INSERT INTO scim_tokens(id,name,source_id,token_hash,token_lookup_hash,created_at,last_used_at,expires_at,revoked_at,deletion_policy,created_by) SELECT 9900000+n, CASE WHEN n=1 THEN 'a-very-long-token-name-for-truncate' ELSE 'token-'||n END, id, '$2a$10$abcdefghijklmnopqrstuu0123456789012345678901234567890', repeat(n::text,64), '2020-01-02T03:04:05Z', CASE WHEN n=2 THEN '2020-02-03T04:05:06Z'::timestamptz END, CASE WHEN n=3 THEN '2000-01-01Z'::timestamptz WHEN n=4 THEN '2100-01-01Z'::timestamptz END, CASE WHEN n=5 THEN '2021-01-01Z'::timestamptz END, CASE WHEN n%2=0 THEN 'hard' ELSE 'soft' END,'mailctl' FROM identity_sources CROSS JOIN generate_series(1,5) n WHERE source_key='scim:gofree-mctl3'")
    if case.get("source_state"):
        sql("UPDATE identity_sources SET state='paused' WHERE source_key='scim:gofree-mctl3'")
    if case.get("users"):
        sql("INSERT INTO domains(id,name) VALUES (9900200,'gofree-mctl3.test'); INSERT INTO users(id,username,email,domain_id,display_name) VALUES (9900201,'alice','alice@gofree-mctl3.test',9900200,'Alice'),(9900202,'bob','bob@gofree-mctl3.test',9900200,'Bob')")
        if case["args"][0]=="smime": sql("INSERT INTO user_smime_certs(user_id,label,cert_pem,private_key_enc,is_default) VALUES (9900201,'seed','seed-cert',pgp_sym_encrypt('seed-key','mctl3-fixture-encryption'),true),(9900202,'seed','seed-cert',pgp_sym_encrypt('seed-key','mctl3-fixture-encryption'),true)")
    if case.get("push_devices"):
        sql("INSERT INTO push_devices(id,user_id,push_provider,push_token_enc,revoked_at) VALUES (9900301,9900201,'hms',pgp_sym_encrypt('fixture-device-alice-hms','mctl3-fixture-encryption'),NULL),(9900302,9900201,'fcm',pgp_sym_encrypt('fixture-device-alice-fcm','mctl3-fixture-encryption'),NULL),(9900303,9900201,'hms',pgp_sym_encrypt('fixture-device-revoked','mctl3-fixture-encryption'),now()),(9900304,9900202,'hms',pgp_sym_encrypt('fixture-device-bob','mctl3-fixture-encryption'),NULL)")
    if case.get("extra_fcm"):
        sql("INSERT INTO push_devices(id,user_id,push_provider,push_token_enc) VALUES (9900307,9900201,'fcm',pgp_sym_encrypt('fixture-device-alice-fcm2','mctl3-fixture-encryption'))")
    if case.get("corrupt_device"):
        sql("UPDATE push_devices SET push_token_enc=pgp_sym_encrypt('fixture-device-corrupt','wrong-key') WHERE id=9900301 AND user_id=9900201")
    if case.get("smime_fault"):
        sql("CREATE FUNCTION gofree_mctl3_smime_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture set-default failure'; END $$; CREATE TRIGGER gofree_mctl3_smime_fail BEFORE UPDATE OF is_default ON user_smime_certs FOR EACH ROW EXECUTE FUNCTION gofree_mctl3_smime_fail()")
    config_saved = None
    if case.get("assist"):
        config_saved = sql("SELECT COALESCE(json_agg(t),'[]') FROM system_config t WHERE key LIKE 'assist.%'")
        endpoint = 'https://user:secret@assist.example:8443/v1?token=secret' if case["assist"] is True else 'file:///etc/passwd'
        sql("INSERT INTO system_config(key,value) VALUES ('assist.provider_url',to_jsonb('"+endpoint+"'::text)),('assist.model','\"fixture-model\"'),('assist.api_key','\"synthetic-secret\"') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    try:
        with contextlib.ExitStack() as stack:
            service = stack.enter_context(Service(case)) if case.get("service") else None
            case["service_object"] = service
            if service:
                for path,content in case.get("files",{}).items():
                    if isinstance(content,str):
                        target=Path(root.name)/path; target.write_text(target.read_text().replace("{HTTP}",service.url))
            if service and case.get("webpush_device"):
                subscription=json.dumps({"endpoint":service.url+"/webpush/capability?token=synthetic","keys":{"p256dh":base64.urlsafe_b64encode((HERE/"fixtures/push-web-public.der").read_bytes()[-65:]).decode().rstrip('='),"auth":base64.urlsafe_b64encode(b'\x01'*16).decode().rstrip('=')}})
                sql("INSERT INTO push_devices(id,user_id,push_provider,push_token_enc) VALUES (9900305,9900201,'webpush',pgp_sym_encrypt('"+subscription.replace("'","''")+"','mctl3-fixture-encryption'))")
            if service and case.get("apns_loopback"):
                sql("INSERT INTO push_devices(id,user_id,push_provider,push_token_enc) VALUES (9900306,9900201,'apns',pgp_sym_encrypt('fixture-device-apns','mctl3-fixture-encryption'))")
            if service and case.get("extra_apns"):
                sql("INSERT INTO push_devices(id,user_id,push_provider,push_token_enc) VALUES (9900308,9900201,'apns',pgp_sym_encrypt('fixture-device-apns2','mctl3-fixture-encryption'))")
            yield
    finally:
        # Finish restoring the disposable DB before delivering another stop signal.
        pending = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT,signal.SIGTERM})
        try:
            root.cleanup()
            if case.get("schema_fault"):
                sql("DROP TRIGGER gofree_mctl3_schema_fail ON schema_migrations; DROP FUNCTION gofree_mctl3_schema_fail()")
            if case.get("smime_fault"):
                sql("DROP TRIGGER gofree_mctl3_smime_fail ON user_smime_certs; DROP FUNCTION gofree_mctl3_smime_fail()")
            if case.get("users"):
                sql("DELETE FROM push_devices WHERE user_id IN (9900201,9900202); DELETE FROM user_smime_certs WHERE user_id IN (9900201,9900202); DELETE FROM users WHERE id IN (9900201,9900202); DELETE FROM domains WHERE id=9900200")
            if config_saved:
                sql("DELETE FROM system_config WHERE key LIKE 'assist.%'; INSERT INTO system_config SELECT * FROM json_populate_recordset(NULL::system_config,'"+config_saved.replace("'","''")+"')")
            if backup and (case.get("bootstrap") or sql("SELECT count(*) FROM users") != "0"):
                backup.close()
                try:
                    reset_public_fixture(DSN)
                    restored = subprocess.run(["pg_restore","--exit-on-error","-d",DSN,backup.name],capture_output=True,text=True)
                    assert restored.returncode == 0, restored.stderr
                except BaseException:
                    print("MCTL3_RETAINED_SNAPSHOT="+backup.name, file=sys.stderr, flush=True)
                    raise
                else:
                    Path(backup.name).unlink()
            elif backup:
                backup.close()
                Path(backup.name).unlink()
            if case["args"][0] == "scim":
                sql("DELETE FROM scim_tokens WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key='scim:gofree-mctl3'); DELETE FROM identity_sources WHERE source_key='scim:gofree-mctl3'")
            if case.get("schema"):
                sql("DELETE FROM schema_migrations; INSERT INTO schema_migrations SELECT * FROM json_populate_recordset(NULL::schema_migrations, '" + saved.replace("'", "''") + "')")
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,pending)

def run(binary, case):
    env = {k:v for k,v in os.environ.items() if not k.startswith(("DB_", "MAILCTL_", "VAPID_", "APNS_", "HMS_", "FCM_", "CRYPTO_PROFILE", "NETWORK_MODE", "SETJOIN_CONNECTIVITY_PROFILE", "COLLABORA_", "SAFEBROWSING_API_KEY"))}
    env.update(DB_DSN=DSN, DB_DIRECT_DSN=DSN)
    if case.get("service_object"):
        proxy=case["service_object"].url
        if case.get("apns_loopback"): env["MAILCTL_ORACLE_APNS_ADDR"]=proxy.removeprefix("http://")
        env.update(HTTP_PROXY=proxy,HTTPS_PROXY=proxy,http_proxy=proxy,https_proxy=proxy,NO_PROXY="127.0.0.1,localhost",no_proxy="127.0.0.1,localhost",SSL_CERT_FILE=str(HERE/"fixtures/push-ca.pem"))
    env.update({k:v.replace("{DSN}",DSN).replace("{ROOT}",case["root"]) for k,v in case.get("env",{}).items()})
    host_before = {str(p.relative_to(case["root"])):p.read_bytes() for p in Path(case["root"]).rglob('*') if p.is_file()}
    all_before = snapshot(sql) if case["args"][0]=="bootstrap-admin" or (case.get("users") or case.get("snapshot")) else None
    before = sql("SELECT COALESCE(json_agg(version ORDER BY version),'[]') FROM schema_migrations")
    proc = subprocess.run([str(Path(binary).resolve()), *[arg.replace("{ROOT}",case["root"]) for arg in case["args"]]], env=env, input=case.get("stdin", ""), text=True, capture_output=True, timeout=30)
    proc.stdout = proc.stdout.replace(case["root"],"{ROOT}")
    proc.stderr = proc.stderr.replace(case["root"],"{ROOT}")
    if case.get("service_object"):
        proc.stdout=proc.stdout.replace(case["service_object"].url,"{HTTP}")
        proc.stderr=proc.stderr.replace(case["service_object"].url,"{HTTP}")
    proc.stderr=re.sub(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d ","{LOG_TIME} ",proc.stderr,flags=re.M)
    after = sql("SELECT COALESCE(json_agg(version ORDER BY version),'[]') FROM schema_migrations")
    effects = {}
    if case.get("service_object"):
        service=case["service_object"]
        service.finish()
        assert not service.errors, service.errors
        effects["outbound"] = service.requests
    if "files" in case:
        effects["host_unchanged"] = host_before == {str(p.relative_to(case["root"])):p.read_bytes() for p in Path(case["root"]).rglob('*') if p.is_file()}
    if all_before is not None:
        if "First administrator created:" in proc.stdout:
            assert sql("SELECT bool_and(sending_quota_reset_at=CURRENT_DATE) FROM mailboxes WHERE user_id=(SELECT id FROM users WHERE email='operator@gofree-mctl3.test')") == "t", "initial quota date must equal database CURRENT_DATE"
            stored = sql("SELECT password_hash FROM users WHERE email='operator@gofree-mctl3.test'")
            if case.get("env",{}).get("CRYPTO_PROFILE") in ("smx","hybrid"):
                _,algorithm,iterations,salt,digest = stored.split('$')
                assert algorithm == "sm3" and iterations == "100000"
                derived = hashlib.pbkdf2_hmac('sm3',b'Strong-Synthetic-123!',base64.b64decode(salt+'=='),int(iterations),32)
                assert derived == base64.b64decode(digest+'=='), "SM3 password must verify"
            else:
                assert stored.startswith('$2a$10$')
                assert sql("SELECT password_hash = crypt('Strong-Synthetic-123!',password_hash) FROM users WHERE email='operator@gofree-mctl3.test'") == "t"
            proc.stdout = re.sub(r"(?<=\(user )\d+(?=\))", "{USER_ID}", proc.stdout)
        if case["args"][0]=="smime":
            for label,key in json.loads(sql("SELECT COALESCE(json_agg(json_build_array(label,pgp_sym_decrypt(private_key_enc::bytea,'mctl3-fixture-encryption'))),'[]') FROM user_smime_certs WHERE user_id IN (9900201,9900202)")):
                assert key == ("seed-key" if label=="seed" else (HERE/"fixtures/smime-key.pem").read_text()), "private key must decrypt byte-exactly"
        effects["tables"] = diff(all_before,snapshot(sql),json.loads(sql(FK_SQL)))
    if case["args"][0] == "scim":
        tokens = re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", proc.stdout)
        if tokens:
            assert len(tokens) == 2 and tokens[0] == tokens[1], "token must appear twice and match"
            token = tokens[0]
            assert sql("SELECT token_hash = crypt('"+token+"',token_hash) AND token_lookup_hash = encode(digest('"+token+"','sha256'),'hex') FROM scim_tokens WHERE name='oracle'") == "t", "stored token must verify"
            proc.stdout = proc.stdout.replace(token, "{TOKEN}")
            if case.get("expiry"):
                remaining = float(sql("SELECT extract(epoch from (expires_at-now())) FROM scim_tokens WHERE name='oracle'"))
                assert abs(remaining-case["expiry"]) < 5, "expiry must match argv"
                proc.stdout = re.sub(r"(?<=Expires:         )\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", "{EXPIRY}", proc.stdout)
        effects["tokens"] = json.loads(sql("SELECT COALESCE(json_agg(json_build_object('name',t.name,'source',s.source_key,'policy',t.deletion_policy,'created_by',t.created_by,'expires',t.expires_at IS NOT NULL,'hash_format',left(t.token_hash,7)) ORDER BY t.id),'[]') FROM scim_tokens t JOIN identity_sources s ON s.id=t.source_id WHERE s.source_key='scim:gofree-mctl3'"))
    return expected_normalization(dict(stdout=proc.stdout, stderr=proc.stderr, exit=proc.returncode, database_effects=effects | {"schema_added": sorted(set(json.loads(after)) - set(json.loads(before))), "schema_removed": sorted(set(json.loads(before)) - set(json.loads(after))) }))

def self_test(binary):
    case=next(c for c in cases() if c["name"]=="scim-create")
    expected=json.loads((HERE/"direct-goldens/scim-create.json").read_text())
    with fixture(case): assert run(binary,case)==expected, "mutant baseline must match Go"
    with tempfile.TemporaryDirectory(prefix="gofree-mctl3-mutant-",dir="/tmp") as root:
        for mutation in ("database","stdout","exit"):
            wrapper=Path(root)/mutation
            wrapper.write_text("#!/usr/bin/env python3\nimport os,subprocess,sys\np=subprocess.run("+repr([str(Path(binary).resolve())])+"+sys.argv[1:])\n"+{
                "database":"subprocess.run(['psql',os.environ['DB_DSN'],'-XAt','-v','ON_ERROR_STOP=1','-c',\"UPDATE scim_tokens SET deletion_policy='hard' WHERE name='oracle' AND source_id=(SELECT id FROM identity_sources WHERE source_key='scim:gofree-mctl3')\"],check=True,capture_output=True)\n",
                "stdout":"print('unexpected output',flush=True)\n",
                "exit":"sys.exit(2)\n",
            }[mutation]+"sys.exit(p.returncode)\n")
            wrapper.chmod(0o700)
            with fixture(case): actual=run(wrapper,case)
            assert actual!=expected, mutation+" mutant escaped oracle"
            print("PASS direct DB oracle rejects "+mutation,flush=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["record", "replay", "self-test"])
    ap.add_argument("binary")
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    DSN = os.environ.get("TEST_DB_DSN", os.environ.get("DB_DSN", ""))
    name = urllib.parse.urlparse(DSN).path.lstrip("/")
    if not DSN or not (name.startswith("gofree_") or name.endswith("_test")):
        raise SystemExit("explicit disposable TEST_DB_DSN required")
    # Serialize this disposable database across concurrent local replay processes.
    lock = open("/tmp/gofree-mctl3-oracle-" + hashlib.sha256(DSN.encode()).hexdigest()[:16] + ".lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    if a.mode == "self-test":
        self_test(a.binary)
        raise SystemExit(0)
    out = a.output if a.mode == "record" else HERE / "direct-goldens"
    if a.mode == "record":
        if out is None or out.exists():
            raise SystemExit("record requires a new output directory")
        out.mkdir(parents=True)
    selected=[c for c in cases() if fnmatch.fnmatchcase(c["name"],os.environ.get("MAILCTL_DB_CASE","*"))]
    assert selected,"no direct database oracle cases selected"
    for case in selected:
        with fixture(case):
            result = run(a.binary, case)
        path = out / (case["name"] + ".json")
        if a.mode == "record":
            path.write_text(json.dumps(result, indent=2) + "\n")
        else:
            expected = schema_expectation(case, expected_normalization(json.loads(path.read_text())))
            assert result == expected, f"{case['name']}\nexpected={expected}\nactual={result}"
        print("PASS " + case["name"],flush=True)
