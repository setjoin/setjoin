#!/usr/bin/env python3
"""Record real frozen-Go /auth/login over direct TLS and malformed proxy headers."""
import argparse, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--http',required=True);p.add_argument('--https',required=True);p.add_argument('--ca',required=True);a=p.parse_args()
out=Path(__file__).with_name('csrf.json')
if out.exists(): raise SystemExit('immutable recording exists')
cases=[]
for tls,proto,host in [(True,'',''),(True,'garbage',''),(True,' httpS ',''),(False,'https','bad.example,mail.test'),(False,'https','bad host'),(False,'https','mail.test/evil'),(False,'https','mail.test')]:
    args=['curl','--silent','--show-error','--cacert',a.ca,'-i','-X','POST',(a.https if tls else a.http)+'/auth/login','-H','Host: mail.test','-H','Origin: https://mail.test','-H','X-Forwarded-Proto: '+proto,'-H','X-Forwarded-Host: '+host,'--data-binary','{']
    wire=subprocess.check_output(args).decode();head,body=wire.split('\r\n\r\n',1);status=int(head.split()[1]);assert status==400,wire
    cases.append(dict(tls=tls,proto=proto,host=host,status=status,body=body))
source=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
out.write_text(json.dumps(dict(format=1,go_source=source,route='POST /auth/login',cases=cases),indent=2)+'\n')
