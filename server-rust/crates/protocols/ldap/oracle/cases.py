#!/usr/bin/env python3
"""Author new wire stimuli. Does not generate or overwrite Go golden responses."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def tlv(tag, payload):
    n = len(payload)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + length + payload

def text(value):
    return tlv(4, value.encode())

def number(value, tag=2):
    return tlv(tag, value.to_bytes(max(1, (value.bit_length()+8)//8), 'big', signed=True))

def message(op, controls=b''):
    return tlv(48, number(1)+op+controls).hex()

def bind(name='alice@ldap1.test', password='LDAP1-correct-password!'):
    return tlv(96, number(3)+text(name)+tlv(128,password.encode()))

def eq(name,value):
    return tlv(163,text(name)+text(value))

def search(base='ou=People,dc=ldap1,dc=test',scope=2,filter=None,attrs=(),size=0,types=False,controls=b''):
    return message(tlv(99,text(base)+number(scope,10)+number(0,10)+number(size)+number(0)+tlv(1,b'\xff' if types else b'\0')+(filter or tlv(135,b'objectClass'))+tlv(48,b''.join(map(text,attrs)))),controls)

def compare(dn, attr, value):
    return message(tlv(110,text(dn)+tlv(48,text(attr)+text(value))))

def session(name, ops, transport='tls', login=True):
    return dict(name=name,transport=transport,steps=[dict(request=x,responses=[]) for x in ([message(bind())] if login else [])+ops])

def extended():
    cases=[]
    for ou,cn,email in [('Groups','Team','team@ldap1.test'),('Resources','Room','room@ldap1.test'),('Contacts','External','')]:
        base=f'ou={ou},dc=ldap1,dc=test'
        cases += [session(f'{ou.lower()}-search',[search(base,attrs=['cn','mail','displayname','objectclass','givenname','sn','o','title','department'])]),session(f'{ou.lower()}-base',[search(f'cn={cn},{base}',scope=0)]),session(f'{ou.lower()}-filter',[search(base,filter=eq('cn',cn))]),session(f'{ou.lower()}-compare',[compare(f'cn={cn},{base}','cn',cn)])]
    cases += [session('contact-private-denial',[search('ou=Contacts,dc=ldap1,dc=test',filter=eq('cn','Private'))]),session('people-all-attrs',[search(attrs=['cn','mail','displayname','objectclass','givenname','sn','telephonenumber','title','ou','department'])]),session('people-cn-filter',[search(filter=eq('cn','Bob'))]),session('people-boolean-filter',[search(filter=tlv(160,eq('cn','Bob')+tlv(161,eq('sn','Builder')+eq('sn','Other'))))]),session('people-department-subtree',[search('ou=Engineering,ou=People,dc=ldap1,dc=test')]),session('people-department-miss',[search('ou=Absent,ou=People,dc=ldap1,dc=test')]),session('people-star-attrs',[search(attrs=['*'])]),session('bind-dn',[message(bind('cn=alice,ou=People,dc=ldap1,dc=test'))],login=False),session('bind-mixed-cn-bug',[message(bind('Cn=alice,ou=People,dc=ldap1,dc=test'))],login=False)]
    cookie=tlv(48,number(1)+text('{"o":1}'))
    controls=tlv(160,tlv(48,text('1.2.840.113556.1.4.319')+tlv(4,cookie)))
    cases += [session('paged-offset',[search(controls=controls)]),session('configured-starttls',[message(tlv(119,tlv(128,b'1.3.6.1.4.1.1466.20037'))),message(bind())],transport='starttls',login=False)]
    return cases

def edges():
    cases=[]
    for ou in ['Groups','Resources','Contacts']:
        base=f'ou={ou},dc=ldap1,dc=test'
        cases.append(session(f'{ou.lower()}-missing-filter',[search(base,filter=eq('cn','Absent'))]))
    for name,f in [('not',tlv(162,eq('cn','Bob'))),('substring',tlv(164,text('cn')+tlv(48,tlv(128,b'Bo')))),('approx',tlv(168,text('cn')+text('Bob'))),('unknown',eq('unmappedAttribute','x')),('greater-ignored',tlv(165,text('cn')+text('Z'))),('presence-ignored',tlv(135,b'cn'))]:
        cases.append(session('filter-'+name,[search(filter=f)]))
    for name,op in [('add',tlv(104,text('cn=New,ou=People,dc=ldap1,dc=test')+tlv(48,b''))),('delete',tlv(74,b'cn=bob,ou=People,dc=ldap1,dc=test')),('modify',tlv(102,text('cn=bob,ou=People,dc=ldap1,dc=test')+tlv(48,b''))),('modifydn',tlv(108,text('cn=bob,ou=People,dc=ldap1,dc=test')+text('cn=Robert')+tlv(1,b'\xff'))),('empty-extension',tlv(119,tlv(128,b'')))]:
        cases.append(session(name,[message(op)]))
    vectors=json.loads(ROOT.joinpath('../../../../tests/conformance/shared-vectors/goldens/pwhash.json').read_text())['cases']
    for name,vector in [('rehash-bcrypt','legacy_bcrypt_cost'),('rehash-sm3','legacy_sm3_iterations')]:
        v=next(v for v in vectors if v['name']==vector)['input']
        c=session(name,[message(bind(password=v['password']))]*2,login=False)
        c['password_hash']=v['hash'];cases.append(c)
    c=session('sm3-bind',[message(bind())],login=False);c['password_hash']='generate-sm3';cases.append(c)
    return cases

if __name__ == '__main__':
    ROOT.joinpath('extended-requests.json').write_text(json.dumps(extended(),indent=2)+'\n')
    ROOT.joinpath('edges-requests.json').write_text(json.dumps(edges(),indent=2)+'\n')
