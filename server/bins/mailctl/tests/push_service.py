"""Owned loopback OAuth/push peers. No request is forwarded to the network."""
import base64
import hashlib
import http.server
import json
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from push_wire import http2,webpush

HERE=Path(__file__).resolve().parent

def b64(raw): return base64.urlsafe_b64decode(raw+'='*((-len(raw))%4))

class Service:
    def __init__(self,case):
        self.requests=[];self.case=case;self.errors=[];self.connections=0
        service=self
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(HERE/'fixtures/push-server-cert.pem',HERE/'fixtures/push-server-key.pem')
        context.load_verify_locations(cafile=HERE/'fixtures/smime-cert.pem')
        context.verify_mode=ssl.CERT_OPTIONAL
        context.set_alpn_protocols(['h2','http/1.1'])
        class HTTP(http.server.BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            # Status-only FCM clients may close as soon as headers arrive.
            # Publish each complete fixture reply in one buffered write.
            wbufsize=-1
            def log_message(self,*args): pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers.get('Content-Length',0)))
                try:
                    status,data=service.handle({k.lower():v for k,v in self.headers.items()},self.path,raw,None)
                    self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass  # the client already has its status
                except Exception as error:
                    service.errors.append(repr(error));self.send_error(500)
        class Proxy(socketserver.BaseRequestHandler):
            def handle(self):
                service.connections+=1
                connection_number=service.connections
                def handle(headers,path,raw,cert):
                    if service.case.get("capture_connection"): headers["fixture-connection"]=connection_number
                    return service.handle(headers,path,raw,cert)
                try:
                    prefix=self.request.recv(7,socket.MSG_PEEK)
                    tls=bool(prefix and prefix[0]==22)
                    if prefix==b'CONNECT':
                        stream=self.request.makefile('rb');line=stream.readline();authority=line.decode().split()[1]
                        assert authority in ('oauth-login.cloud.huawei.com:443','push-api.cloud.huawei.com:443','fcm.googleapis.com:443','api.sandbox.push.apple.com:443','api.push.apple.com:443'),authority
                        while stream.readline() not in (b'\r\n',b'\n',b''): pass
                        self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n');tls=True
                    if tls:
                        with context.wrap_socket(self.request,server_side=True) as connection:
                            if connection.selected_alpn_protocol()=='h2':http2(connection,handle)
                            else:HTTP(connection,self.client_address,self.server)
                    else:HTTP(self.request,self.client_address,self.server)
                except (EOFError,ConnectionError):pass  # includes a client closing after its headers
                except Exception as error:service.errors.append(repr(error))
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=True;daemon_threads=False
        self.server=Server(('127.0.0.1',0),Proxy)
        self.url='http://127.0.0.1:'+str(self.server.server_address[1])
        self.thread=threading.Thread(target=self.server.serve_forever,name='gofree-mctl3-push-service')
    def handle(self,headers,path,raw,client_cert):
        path=urllib.parse.urlparse(path).path
        row=dict(method='POST',path=path,content_type=headers.get('content-type',''),authorization=headers.get('authorization',''),body=raw.decode() if path!='/webpush/capability' else '')
        if path=='/webpush/capability':
            row['body']=webpush(headers,raw,self.url);row['authorization']='{VERIFIED_VAPID}'
        elif path=='/oauth/fcm':
            form=urllib.parse.parse_qs(raw.decode(),strict_parsing=True);jwt=form['assertion'][0];header,payload,signature=jwt.split('.')
            decoded=json.loads(b64(payload))
            assert json.loads(b64(header))['alg']=='RS256'
            assert abs(decoded['iat']-time.time())<60
            assert 3500<decoded['exp']-time.time()<3700
            lifetime=decoded['exp']-decoded['iat']
            with tempfile.TemporaryDirectory(prefix='gofree-mctl3-jwt-',dir='/tmp') as temp:
                message=Path(temp)/'message';sig=Path(temp)/'signature';message.write_bytes((header+'.'+payload).encode());sig.write_bytes(b64(signature))
                subprocess.run(['openssl','dgst','-sha256','-verify',str(HERE/'fixtures/push-sa-public.pem'),'-signature',str(sig),str(message)],check=True,capture_output=True)
            decoded['iat']='{IAT}';decoded['exp']='{EXPIRY}';decoded['lifetime']=lifetime;decoded['aud']=decoded['aud'].replace(self.url,'{HTTP}')
            row['body']=dict(grant_type=form['grant_type'][0],assertion=dict(header=json.loads(b64(header)),claims=decoded,signature_verified=True))
        elif row['content_type'].startswith('application/json'): row['body']=json.loads(raw)
        elif path.endswith('/token'):row['body']={k:v[0] for k,v in urllib.parse.parse_qs(raw.decode()).items()}
        if self.case.get('capture_connection'):row['connection']=headers['fixture-connection']
        if self.case.get('capture_authority'): row['authority']=headers.get(':authority',headers.get('host'))
        if path.startswith('/3/device/'):
            assert client_cert, 'APNs must use certificate authentication'
            row['client_certificate_sha256']=hashlib.sha256(client_cert).hexdigest()
            row['headers']={k:headers.get(k) for k in ('apns-topic','apns-push-type','apns-priority','apns-expiration')}
        self.requests.append(row)
        if path.endswith('/token') or path=='/oauth/fcm':response={'access_token':'synthetic-access','token_type':'Bearer','expires_in':3600}
        elif path.startswith('/v3/'):response={'code':self.case.get('hms_code','80000000')}
        elif path.startswith('/3/device/'):response={'reason':self.case.get('apns_reason','')}
        else:response={}
        status=self.case.get('push_status',200) if path.endswith('messages:send') or path.startswith(('/3/device/','/webpush/')) else 200
        return status,json.dumps(response,separators=(',',':')).encode()
    def __enter__(self):self.thread.start();return self
    def finish(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def __exit__(self,*args):self.finish()
