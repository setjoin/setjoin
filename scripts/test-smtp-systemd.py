#!/usr/bin/env python3
"""Replay enabled frozen-Go SMTP on rendered, disposable real-systemd sockets.
Only the assigned SMTP6 database and gofree-smtp6-* resources are used. S3 and
clamd are independent wire peers; no Go process is present. Public fixture keys only.
"""
import argparse
import base64
import contextlib
import http.server
import json
import os
import re
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
ORACLE = ROOT / 'server-rust/crates/protocols/smtp/oracle'

def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()

def sql(dsn, text):
    return run('psql', '-XAt', '-v', 'ON_ERROR_STOP=1', dsn, '-c', text)

def quote(value):
    return "'" + value.replace("'", "''") + "'"

class Store(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if 'location' in self.path:
            body=b'<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>'
        else:
            body=b'<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></ListMultipartUploadsResult>'
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_PUT(self):
        self.server.blobs[self.path] = self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(200); self.end_headers()
    def log_message(self, *args):
        pass

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        # Independent loopback fixture: one ordinary question, always NXDOMAIN.
        end=query.index(b'\0',12)+5
        sock.sendto(query[:2]+b'\x81\x83'+query[4:6]+b'\0'*6+query[12:end],self.client_address)

class Clam(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            command = self.rfile.readline()
            if not command: return
            if command == b'nPING\n':
                self.wfile.write(b'PONG\n'); self.wfile.flush()
            elif command == b'nINSTREAM\n':
                while True:
                    length = int.from_bytes(self.rfile.read(4), 'big')
                    if not length: break
                    assert len(self.rfile.read(length)) == length
                self.wfile.write((self.server.reply + '\n').encode()); self.wfile.flush()
            else:
                raise AssertionError(command)

@contextlib.contextmanager
def peer(server):
    thread = threading.Thread(target=server.serve_forever, name='gofree-smtp6-peer', daemon=True)
    thread.start()
    try: yield server
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        assert not thread.is_alive()

def compare_effects(dsn, case):
    for field, file in [('effects','observe.sql'),('security_effects','security-observe.sql'),('pipeline_effects','pipeline-observe.sql')]:
        if field in case:
            got = json.loads(sql(dsn, (ORACLE / file).read_text()))
            assert got == case[field], (field, case['name'], got, case[field])

def verify(binary):
    dsn = os.environ['TEST_DB_DSN']
    assert dsn.endswith('/gofree_e2e_smtp6') and os.environ.get('REQUIRE_DB') == '1'
    assert os.geteuid() == 0
    run('systemctl','show','--property=Version','--value')
    cases = json.loads((ORACLE / 'security-joint-pipeline-go.json').read_text())[:2]
    previous = sql(dsn, "SELECT jsonb_object_agg(key,enabled) FROM feature_toggles")
    with tempfile.TemporaryDirectory(prefix='gofree-smtp6-systemd-', dir='/run') as path, peer(http.server.ThreadingHTTPServer(('127.0.0.1',0),Store)) as store, peer(socketserver.ThreadingTCPServer(('127.0.0.1',0),Clam)) as clam, peer(socketserver.UDPServer(('127.26.5.26',53),DNS)) as dns:
        directory = Path(path); directory.chmod(0o755)
        executable = directory / 'setjoin-gateway'; shutil.copyfile(binary,executable); executable.chmod(0o755)
        name = directory.name
        mappings = {'setjoin-gateway.service':name+'.service','setjoin-gateway.socket':name+'.socket','setjoin-smtp.socket':name+'-smtp.socket','setjoin-submission.socket':name+'-submission.socket'}
        units = list(mappings.values()); installed=[]
        resolver=directory/'resolv.conf'; resolver.write_text('nameserver 127.26.5.26\noptions timeout:1 attempts:1\n'); resolver.chmod(0o644)
        print('Owned SMTP resources:',directory,units,'(removed on exit)',flush=True)
        fixture = ROOT / 'server-rust/tests/conformance/directory-sync/ldap-fixture'
        for original,target in [('server.pem','cert.pem'),('server.p8','key.pem')]:
            shutil.copyfile(fixture/original,directory/target); (directory/target).chmod(0o644)
        reservations=[]
        for _ in range(3):
            sock=socket.socket();sock.bind(('127.0.0.1',0));reservations.append(sock)
        http_port,smtp,submission=[s.getsockname()[1] for s in reservations]
        config=directory/'config.env'
        config.write_text(f'DB_ENCRYPTION_KEY={"22"*32}\nAUDIT_HMAC_KEY={"33"*32}\nDB_DSN={dsn}\nDB_DIRECT_DSN={dsn}\nDB_WORKER_DSN={dsn}\nSMTP_TLS_CERT_FILE={directory}/cert.pem\nSMTP_TLS_KEY_FILE={directory}/key.pem\nIMAP_ADDR=\nIMAP_TLS_ADDR=\nSMTP_INBOUND_ADDR=127.0.0.1:{smtp}\nSMTP_SUBMISSION_ADDR=127.0.0.1:{submission}\nSMTP_INBOUND_TLS_ADDR=\nCLAMAV_ADDR=127.0.0.1:{clam.server_address[1]}\nSANDBOX_FAIL_MODE=\nJWT_SECRET=smtp6-joint-secret-32-bytes-minimum\nJWT_LINK_PROTECT_TOKEN_VERSION=2\nINTERNAL_DOMAINS=smtp1.test\nPROTECTED_DOMAINS=smtp1.test\nS3_ENDPOINT=http://127.0.0.1:{store.server_address[1]}\nS3_SECURE=false\nS3_BUCKET=mailblobs\nS3_ACCESS_KEY=smtp6-fixture\nS3_SECRET_KEY=smtp6-fixture\n')
        bootstrap=directory/'bootstrap.env'; bootstrap.write_text('smtp6 disposable bootstrap\n'); bootstrap.chmod(0o600); shutil.chown(bootstrap,user='nobody',group='nogroup')
        (directory/'gateway.env').write_text(f'CONFIG_PATH={bootstrap}\nGATEWAY_AUTH_UPSTREAM=http://127.0.0.1:9\nGO_LISTENERS_OFF=smtp,submission\n')
        env=dict(os.environ,INSTALL_DIR=str(directory),RUNTIME_DIR=str(directory),CONFIG_ENV=str(config),GATEWAY_ENV=str(directory/'gateway.env'),SMTP_ENV=str(directory/'smtp.env'),GATEWAY_LISTEN=f'127.0.0.1:{http_port}',FEDERATION_ENABLED='false')
        try:
            run('bash','-c','source "$1"; configure_smtp_front "$2"; render_smtp_env "$3" "$2" /nonexistent; render_gateway_unit "$4" "$5"','render',str(ROOT/'mailserver/deploy/scripts/lib-livekit.sh'),str(config),str(directory/'smtp.env'),str(ROOT/'mailserver/deploy/setjoin-gateway.service.template'),str(directory/'setjoin-gateway.service'),env=env)
            assert 'SMTP_FRONT_ENABLED=true' in config.read_text()
            for original,target in mappings.items():
                text=(directory/original).read_text()
                for src,dst in mappings.items():text=text.replace(src,dst)
                text=text.replace(' setjoin.service setjoin-auth.service','').replace('Wants=setjoin.service setjoin-auth.service\n','')
                text=text.replace('User=setjoin','User=nobody').replace('Group=setjoin','Group=nogroup')
                if original.endswith('.service'):text=text.replace('[Service]','[Service]\nBindReadOnlyPaths='+str(resolver)+':/etc/resolv.conf')
                dest=Path('/run/systemd/system')/target;assert not dest.exists();dest.write_text(text);installed.append(dest)
            for file in directory.glob('*.env'):
                if file.name!='bootstrap.env':file.chmod(0o644) # Public disposable credentials only.
            for sock in reservations:sock.close()
            run('systemctl','daemon-reload')
            for generation,case in enumerate(cases):
                sql(dsn,(ORACLE/'cleanup.sql').read_text()+(ORACLE/'seed.sql').read_text())
                if case.get('setup_sql'):sql(dsn,case['setup_sql'])
                flags=dict(case['mail_auth']);flags['feature.smtp_inbound']=True;flags['feature.smtp_submission']=True
                # NewStatic in the Go recorder explicitly disables every Go key.
                # Missing DB rows otherwise inherit default-ON, so materialize them.
                keys=re.findall(r'^\s*\w+\s*=\s*"([^"\n]+\.[^"\n]+)"', (ROOT/'shared/toggle/toggle.go').read_text(), re.M)
                seed='INSERT INTO feature_toggles(key,enabled) VALUES '+','.join('('+quote(k)+',false)' for k in keys)+' ON CONFLICT(key) DO UPDATE SET enabled=false;'
                sql(dsn,'UPDATE feature_toggles SET enabled=false;'+seed+''.join(f'UPDATE feature_toggles SET enabled=true WHERE key={quote(k)};' for k,v in flags.items() if v))
                store.blobs={};clam.reply=case['pipeline']['clam_reply']
                run('systemctl','start' if generation==0 else 'restart',mappings['setjoin-gateway.service'])
                with socket.create_connection(('127.0.0.1',smtp),timeout=20) as connection:
                    connection.settimeout(30);reader=connection.makefile('rb')
                    for step in case['steps']:
                        connection.sendall(base64.b64decode(step['send_base64']) if step.get('send_base64') else step['send'].encode())
                        got=b''.join(reader.readline() for _ in range(step['lines'])).decode()
                        assert got==step['reply'],(case['name'],got,step['reply'])
                reader.close()
                compare_effects(dsn,case)
                expected={f'/mailblobs/{key}':base64.b64decode(value) for key,value in case['blobs'].items()}
                assert store.blobs==expected,(case['name'],'raw objects differ')
                pid=int(run('systemctl','show',mappings['setjoin-gateway.service'],'-p','MainPID','--value'))
                status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                assert int(status['Uid'].split()[0])!=0
                for field in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):assert int(status[field],16)==0,(field,status[field])
                with socket.create_connection(('127.0.0.1',submission),timeout=10) as connection:
                    connection.settimeout(10);assert connection.recv(4096).startswith(b'220 mailserver ESMTP submission ready')
                if generation == 0:
                    logs=run('journalctl','-u',mappings['setjoin-gateway.service'],'--no-pager','-o','cat')
                    assert 'INCREASES MEMORY FOOTPRINT' in logs, 'missing startup FTRL batch warning'
                    for enabled,marker in [(False,'spam model batch loading disabled'),(True,'INCREASES MEMORY FOOTPRINT')]:
                        before=logs.count(marker)
                        sql(dsn,"UPDATE feature_toggles SET enabled="+str(enabled).lower()+" WHERE key='feature.spam_model_batch_load'; SELECT pg_notify('config_changed','{}');")
                        deadline=time.monotonic()+15
                        while True:
                            logs=run('journalctl','-u',mappings['setjoin-gateway.service'],'--no-pager','-o','cat')
                            if logs.count(marker)>before: break
                            assert time.monotonic()<deadline, ('missing FTRL flip posture',marker)
                            time.sleep(0.1)
                print('SYSTEMD-SMTP-PASS',case['name'],'generation',generation,flush=True)
                run('systemctl','stop',mappings['setjoin-gateway.service'])
                if case.get('teardown_sql'):sql(dsn,case['teardown_sql'])
        except BaseException:
            print(run('journalctl','-u',mappings['setjoin-gateway.service'],'--no-pager','-n','70','-o','cat'),flush=True)
            raise
        finally:
            subprocess.run(['systemctl','stop',*units],capture_output=True)
            subprocess.run(['systemctl','reset-failed',*units],capture_output=True)
            for dest in installed:dest.unlink()
            run('systemctl','daemon-reload')
            sql(dsn,(ORACLE/'cleanup.sql').read_text()+f'DELETE FROM feature_toggles WHERE NOT ({quote(previous)}::jsonb ? key); UPDATE feature_toggles f SET enabled=(v.value)::boolean FROM jsonb_each_text({quote(previous)}::jsonb) v WHERE f.key=v.key;')
    print('SMTP systemd: PASS (default rendered sockets, enabled Go transcripts, no Go listeners, capability-empty service, restart)')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path)
    verify(parser.parse_args().binary.resolve())
