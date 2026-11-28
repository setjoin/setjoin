#!/usr/bin/env python3
"""Deterministic test-only DER mutations of a.pem; no signature is recomputed.
Runtime parsing uses audited crates. Expected acceptance is checked against Go,
not inferred from this fixture builder. Existing fixtures are never overwritten.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import textwrap

ROOT = Path(__file__).resolve().parent

def take(data):
    tag, size, offset = data[0], data[1], 2
    if size & 128:
        width = size & 127
        size = int.from_bytes(data[2:2 + width], 'big')
        offset += width
    return (tag, data[offset:offset + size]), data[offset + size:]

def items(data):
    result = []
    while data:
        item, data = take(data)
        result.append(item)
    return result

def tlv(tag, body):
    size = len(body)
    width = (size.bit_length() + 7) // 8
    length = bytes([size]) if size < 128 else bytes([128 + width]) + size.to_bytes(width, 'big')
    return bytes([tag]) + length + body

def pack(nodes):
    return b''.join(tlv(tag, value) for tag, value in nodes)

def seq(nodes):
    return tlv(48, pack(nodes))

pem = (ROOT / 'a.pem').read_text()
der = base64.b64decode(''.join(pem.splitlines()[1:-1]))
base = items(take(der)[0][1])

def extension(oid, value, critical=False):
    fields = [(6, oid)]
    if critical:
        fields.append((1, b'\xff'))
    fields.append((4, value))
    return (48, pack(fields))

def mutate(name, rejected, modify):
    top = copy.deepcopy(base)
    tbs = items(top[0][1])
    exts = items(take(tbs[-1][1])[0][1])
    modify(top, tbs, exts)
    tbs[-1] = (163, seq(exts))
    top[0] = (48, pack(tbs))
    data = seq(top)
    if name == 'trailing-der':
        data += b'\x00'
    if name == 'nonminimal-length':
        width = data[1] & 127
        data = data[:1] + bytes([128 + width + 1, 0]) + data[2:]
    output = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(textwrap.wrap(base64.b64encode(data).decode(), 64)) + '\n-----END CERTIFICATE-----\n'
    path = ROOT / f'{name}.pem'
    if path.exists():
        assert path.read_text() == output, f'refusing to overwrite {path}'
    else:
        path.write_text(output)
    return {'name': name, 'rejected': rejected, 'sha256': hashlib.sha256(data).hexdigest()}

def ext_change(oid, transform):
    def apply(top, tbs, exts):
        for at, (_, payload) in enumerate(exts):
            fields = items(payload)
            if fields[0] == (6, oid):
                exts[at] = (48, pack(transform(fields)))
                return
        raise AssertionError(oid)
    return apply

def add(oid, value, critical=False):
    return lambda top, tbs, exts: exts.append(extension(oid, value, critical))

def cn(tag, value):
    def apply(top, tbs, exts):
        rdns = items(tbs[5][1])
        attrs = items(rdns[-1][1])
        fields = items(attrs[-1][1])
        assert fields[0] == (6, b'\x55\x04\x03')
        fields[-1] = (tag, value)
        attrs[-1] = (48, pack(fields))
        rdns[-1] = (49, pack(attrs))
        tbs[5] = (48, pack(rdns))
    return apply

def spki(modify):
    def apply(top, tbs, exts):
        fields = items(tbs[6][1])
        modify(fields)
        tbs[6] = (48, pack(fields))
    return apply

cases = []
def case(name, rejected, change):
    cases.append(mutate(name, rejected, change))

case('duplicate-extension', True, lambda a,b,c: c.append(c[0]))
case('negative-serial', True, lambda a,b,c: b.__setitem__(1, (2, bytes([b[1][1][0] | 128]) + b[1][1][1:])))
case('padded-serial', True, lambda a,b,c: b.__setitem__(1, (2, b'\x00' + b[1][1])))
case('invalid-version', True, lambda a,b,c: b.__setitem__(0, (160, tlv(2, b'\x03'))))
case('signature-mismatch', True, lambda a,b,c: a.__setitem__(1, (48, a[1][1][:-1] + b'\x03')))
for name, oid in [('ski', b'\x55\x1d\x0e'), ('aki', b'\x55\x1d\x23')]:
    case('critical-' + name, True, ext_change(oid, lambda f: [f[0], (1,b'\xff'), f[-1]]))
case('critical-aia', True, add(b'\x2b\x06\x01\x05\x05\x07\x01\x01', b'\x30\x00', True))
case('malformed-key-usage', True, add(b'\x55\x1d\x0f', b'\x05\x00'))
case('malformed-basic-constraints', True, ext_change(b'\x55\x1d\x13', lambda f: f[:-1] + [(4, seq([(1,b'\x01')]))]))
case('malformed-san-ip', True, add(b'\x55\x1d\x11', seq([(135,b'\x01\x02\x03')])))
case('malformed-san-uri', True, add(b'\x55\x1d\x11', seq([(134,b'https://cert.test/%zz')])))
case('malformed-san-opaque-fragment', True, add(b'\x55\x1d\x11', seq([(134,b'urn:client#%zz')])))
case('empty-name-constraints', True, add(b'\x55\x1d\x1e', b'\x30\x00'))
case('duplicate-policies', True, add(b'\x55\x1d\x20', seq([(48,tlv(6,b'\x2a\x03'))]*2)))
case('invalid-utf8-subject', True, cn(12,b'\xff'))
case('invalid-printable-subject', True, cn(19,b'bad@name'))
case('invalid-bmp-subject', True, cn(30,b'\xd8\x00'))
case('invalid-ec-point', True, spki(lambda f: f.__setitem__(1,(3,b'\x00\x04'+bytes(64)))))
case('unsupported-curve', True, spki(lambda f: f.__setitem__(0,(48,pack([items(f[0][1])[0],(6,b'\x2b\x81\x04\x00\x0a')])))))
case('trailing-der', True, lambda a,b,c: None)
case('nonminimal-length', True, lambda a,b,c: None)
case('bad-oid-extension', True, add(b'\x2a\x86', b'\x30\x00'))
case('malformed-key-usage-padding', True, add(b'\x55\x1d\x0f', b'\x03\x02\x03\x01'))
case('unknown-critical', False, add(b'\x2a\x03\x04', b'\xff', True))
case('bad-signature', False, lambda a,b,c: a.__setitem__(2,(3,a[2][1][:-1]+bytes([a[2][1][-1]^1]))))
case('unknown-public-key', False, spki(lambda f: f.__setitem__(0,(48,tlv(6,b'\x2a\x03\x04')))))
case('valid-bmp-subject', False, cn(30, '终端'.encode('utf-16-be')))
case('valid-teletex-subject', False, cn(20,b'caf\xe9'))
def legacy(a,b,c):
    b[0] = (160,tlv(2,b'\x00'))
    c.append(c[0])
case('valid-v1-duplicate', False, legacy)
case('valid-serial-zero', False, lambda a,b,c: b.__setitem__(1,(2,b'\x00')))
case('valid-long-serial', False, lambda a,b,c: b.__setitem__(1,(2,bytes([1])*32)))
case('valid-basic-constraints-wide', False, ext_change(b'\x55\x1d\x13', lambda f: f[:-1]+[(4,seq([(1,b'\xff'),(2,b'\x01\x00\x00\x00\x00')]))]))
case('valid-inhibit-negative', False, add(b'\x55\x1d\x36', tlv(2,b'\xff')))
# OID arc bound from Go cryptobyte; long OID control exceeds fixed-size OID storage.
case('oversized-oid-extension', True, add(b'\x2a\x88\x80\x80\x80\x00', b'\xff'))
case('valid-long-oid', False, add(b'\x2a' + bytes([3])*64, b'\xff'))
# NIST public P-224 generator, also published in RustCrypto p224 test_vectors/group.rs.
def p224_key(fields, invalid=False):
    fields[0] = (48, pack([items(fields[0][1])[0], (6,b'\x2b\x81\x04\x00\x21')]))
    point = bytes.fromhex('b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34')
    fields[1] = (3,b'\x00\x04' + (bytes(56) if invalid else point))
case('valid-p224', False, spki(p224_key))
case('invalid-p224', True, spki(lambda f: p224_key(f, True)))
# Go x509.OID policies retain arbitrary-width components (unlike asn1.ObjectIdentifier).
case('valid-wide-policy', False, add(b'\x55\x1d\x20', seq([(48,tlv(6,b'\x2a\x82'+bytes([128])*9+b'\x00'))])))
case('nonminimal-policy-oid', True, add(b'\x55\x1d\x20', seq([(48,tlv(6,b'\x2a\x80\x01'))])))
(ROOT / 'strict-cases.json').write_text(json.dumps(cases, indent=2) + '\n')
print(f'{len(cases)} strict-parser fixtures')
