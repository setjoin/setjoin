"""Protocol verification at the fake peer: HTTP/2 HPACK and RFC 8291 Web Push."""
import base64
import ctypes as C
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent
SPKI=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')

def library(name):
    path=ctypes.util.find_library(name)
    assert path, f'process oracle requires system lib{name}'
    return C.CDLL(path)

def exact(sock,size):
    data=b''
    while len(data)<size:
        block=sock.recv(size-len(data))
        if not block: raise EOFError
        data+=block
    return data

class NV(C.Structure):
    _fields_=[('name',C.c_void_p),('value',C.c_void_p),('namelen',C.c_size_t),('valuelen',C.c_size_t),('flags',C.c_uint8)]

class HPACK:
    def __init__(self):
        self.lib=library('nghttp2');self.ctx=C.c_void_p()
        self.lib.nghttp2_hd_inflate_new.argtypes=[C.POINTER(C.c_void_p)]
        self.lib.nghttp2_hd_inflate_del.argtypes=[C.c_void_p]
        self.lib.nghttp2_hd_inflate_hd2.argtypes=[C.c_void_p,C.POINTER(NV),C.POINTER(C.c_int),C.c_void_p,C.c_size_t,C.c_int]
        self.lib.nghttp2_hd_inflate_hd2.restype=C.c_ssize_t
        self.lib.nghttp2_hd_inflate_end_headers.argtypes=[C.c_void_p]
        assert self.lib.nghttp2_hd_inflate_new(C.byref(self.ctx))==0
    def decode(self,block):
        data=C.create_string_buffer(block);offset=0;headers={}
        while True:
            field=NV();flags=C.c_int()
            used=self.lib.nghttp2_hd_inflate_hd2(self.ctx,C.byref(field),C.byref(flags),C.byref(data,offset),len(block)-offset,1)
            assert used>=0, 'invalid HPACK request'
            offset+=used
            if flags.value & 2: headers[C.string_at(field.name,field.namelen).decode()]=C.string_at(field.value,field.valuelen).decode()
            if flags.value & 1: break
            assert used or flags.value & 2, 'HPACK made no progress'
        self.lib.nghttp2_hd_inflate_end_headers(self.ctx)
        return headers
    def close(self): self.lib.nghttp2_hd_inflate_del(self.ctx)

def integer(value,prefix,base=0):
    maximum=(1<<prefix)-1
    if value<maximum:return bytes([base|value])
    data=bytes([base|maximum]);value-=maximum
    while value>=128:data+=bytes([(value&127)|128]);value>>=7
    return data+bytes([value])
def text(raw):
    if isinstance(raw,str):raw=raw.encode()
    return integer(len(raw),7)+raw

def http2(sock,handle):
    assert exact(sock,24)==b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    def frame(kind,flags,stream,data=b''):
        sock.sendall(len(data).to_bytes(3,'big')+bytes([kind,flags])+stream.to_bytes(4,'big')+data)
    frame(4,0,0)
    codec=HPACK();streams={}
    try:
        while True:
            header=exact(sock,9);size=int.from_bytes(header[:3],'big');kind,flags=header[3:5];stream=int.from_bytes(header[5:],'big')&0x7fffffff
            assert size<=1<<20
            data=exact(sock,size)
            if kind==4:
                if not flags&1:frame(4,1,0)
                continue
            if kind==6:
                if not flags&1:frame(6,1,0,data)
                continue
            if kind in (7,3): return
            if kind not in (0,1,9): continue
            row=streams.setdefault(stream,dict(block=b'',body=b'',headers={},end=False))
            if flags&8:
                pad=data[0];data=data[1:len(data)-pad]
            if kind==1 and flags&32:data=data[5:]
            if kind in (1,9):
                row['block']+=data
                if flags&4:row['headers']=codec.decode(row['block'])
            else: row['body']+=data
            if kind in (0,1) and flags&1:row['end']=True
            if row['end'] and row['headers']:
                status,body=handle(row['headers'],row['headers'][':path'],row['body'],sock.getpeercert(binary_form=True))
                reply=(b'\x88' if status==200 else b'\x08'+text(str(status)))+integer(31,4)+text('application/json')+integer(28,4)+text(str(len(body)))+b'\x00'+text('apns-id')+text('fixture-apns-id')
                frame(1,4,stream,reply);frame(0,1,stream,body);del streams[stream]
    except (EOFError,ConnectionResetError):pass
    finally:codec.close()

def hkdf(key,info,size): return hmac.new(key,info+b'\x01',hashlib.sha256).digest()[:size]
def pem(kind,raw): return ('-----BEGIN '+kind+'-----\n').encode()+base64.encodebytes(raw)+('-----END '+kind+'-----\n').encode()
def b64(raw):return base64.urlsafe_b64decode(raw+'='*((-len(raw))%4))
def asn_integer(raw):
    raw=raw.lstrip(b'\0') or b'\0'
    if raw[0]&128:raw=b'\0'+raw
    return bytes([2,len(raw)])+raw

def webpush(headers,encrypted,url):
    assert headers.get('content-encoding')=='aes128gcm'
    assert headers.get('ttl')=='60'
    authorization=headers.get('authorization','')
    assert authorization.startswith('vapid '),authorization
    parts=dict(field.strip().split('=',1) for field in authorization[6:].split(','))
    token=parts['t'];head,claims,sig=token.split('.')
    claim=json.loads(b64(claims));header=json.loads(b64(head));public=b64(parts['k'])
    assert public==b'', 'frozen Go omits VAPIDPublicKey in webpush.Options'
    verification_public=(HERE/'fixtures/push-web-public.der').read_bytes()[-65:]
    assert header=={'typ':'JWT','alg':'ES256'}
    assert abs(claim['exp']-time.time()-43200)<60
    assert claim['aud']==url
    signature=b64(sig);assert len(signature)==64
    signature=asn_integer(signature[:32])+asn_integer(signature[32:]);signature=bytes([0x30,len(signature)])+signature
    salt=encrypted[:16];record_size=int.from_bytes(encrypted[16:20],'big');key_size=encrypted[20];assert key_size==65
    peer=encrypted[21:21+key_size];cipher=encrypted[21+key_size:]
    with tempfile.TemporaryDirectory(prefix='gofree-mctl3-webpush-',dir='/tmp') as temp:
        temp=Path(temp);(temp/'vapid.pem').write_bytes(pem('PUBLIC KEY',SPKI+verification_public));(temp/'signature').write_bytes(signature);(temp/'jwt').write_bytes((head+'.'+claims).encode())
        checked=subprocess.run(['openssl','dgst','-sha256','-verify',str(temp/'vapid.pem'),'-signature',str(temp/'signature'),str(temp/'jwt')],capture_output=True)
        assert checked.returncode==0, repr((checked.stdout,checked.stderr,len(public),header,public==((HERE/'fixtures/push-web-public.der').read_bytes()[-65:])))
        (temp/'peer.pem').write_bytes(pem('PUBLIC KEY',SPKI+peer))
        shared=subprocess.check_output(['openssl','pkeyutl','-derive','-inkey',str(HERE/'fixtures/smime-ec.pem'),'-peerkey',str(temp/'peer.pem')],stderr=subprocess.DEVNULL)
    client=(HERE/'fixtures/push-web-public.der').read_bytes()[-65:]
    auth=b'\x01'*16
    prk=hmac.new(auth,shared,hashlib.sha256).digest();ikm=hkdf(prk,b'WebPush: info\0'+client+peer,32)
    prk=hmac.new(salt,ikm,hashlib.sha256).digest();key=hkdf(prk,b'Content-Encoding: aes128gcm\0',16);nonce=hkdf(prk,b'Content-Encoding: nonce\0',12)
    lib=library('crypto')
    lib.EVP_CIPHER_CTX_new.restype=C.c_void_p;lib.EVP_aes_128_gcm.restype=C.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes=[C.c_void_p]
    lib.EVP_DecryptInit_ex.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p]
    lib.EVP_CIPHER_CTX_ctrl.argtypes=[C.c_void_p,C.c_int,C.c_int,C.c_void_p]
    lib.EVP_DecryptUpdate.argtypes=[C.c_void_p,C.c_void_p,C.POINTER(C.c_int),C.c_void_p,C.c_int]
    lib.EVP_DecryptFinal_ex.argtypes=[C.c_void_p,C.c_void_p,C.POINTER(C.c_int)]
    ctx=lib.EVP_CIPHER_CTX_new();output=C.create_string_buffer(len(cipher));size=C.c_int();tail=C.c_int()
    try:
        assert lib.EVP_DecryptInit_ex(ctx,lib.EVP_aes_128_gcm(),None,None,None)==1
        assert lib.EVP_CIPHER_CTX_ctrl(ctx,9,len(nonce),None)==1
        assert lib.EVP_DecryptInit_ex(ctx,None,None,C.c_char_p(key),C.c_char_p(nonce))==1
        assert lib.EVP_DecryptUpdate(ctx,output,C.byref(size),C.c_char_p(cipher[:-16]),len(cipher)-16)==1
        assert lib.EVP_CIPHER_CTX_ctrl(ctx,17,16,C.c_char_p(cipher[-16:]))==1
        assert lib.EVP_DecryptFinal_ex(ctx,C.byref(output,size.value),C.byref(tail))==1, 'Web Push authentication tag invalid'
        plain=output.raw[:size.value+tail.value]
    finally:lib.EVP_CIPHER_CTX_free(ctx)
    unpadded=plain.rstrip(b'\0');assert unpadded[-1]==2
    claim['exp']='{EXPIRY}';claim['aud']='{HTTP}'
    return dict(payload=json.loads(unpadded[:-1]),record_size=record_size,body_length=len(encrypted),padding_length=len(plain)-len(unpadded),vapid=dict(header=header,claims=claim,public_key=parts['k'],signature_verified=True))
