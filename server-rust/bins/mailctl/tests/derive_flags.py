import re,json
from pathlib import Path
import argparse
import oracle
ROOT=Path(__file__).resolve().parents[4]
parser=argparse.ArgumentParser(description='Read frozen Go flagsets and record their help; no output is overwritten.')
parser.add_argument('--go-binary',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
assert not args.output.exists(), 'derive into a new file'

FILES=['mailbox_lifecycle','upgrade','ca','ca_verbs','eap','mam','quarantine','identity','office','office_lifecycle','audit','approval','role']
U='00000000-0000-4000-8000-000000000001'
dynamic={
 'mailboxLifecycleTransitionCmd':['mailbox '+a for a in ['suspend','resume','detach-retain','reconnect']],
 'mailboxPurgeApprovalCmd':['mailbox purge-approve','mailbox purge-deny'],
 'mailboxPurgeActionCmd':['mailbox purge-cancel','mailbox purge-execute'],
 'runIdentitySourceLifecycle':['identity source '+a for a in ['dry-run','activate','pause','resume','retire']],
 'runIdentitySourceSecret':['identity source set-secret','identity source rotate-secret'],
 'runIdentityTransitionAuthorizedCommand':['identity transition '+a for a in ['request','execute','approve','deny','rollback']],
 'runIdentityTransitionGenerationCommand':['identity transition cancel','identity transition rollback-preview'],
 'parseOfficeOutputFlags':['office doctor','office diagnostics']}
identity=(ROOT/'mailctl/identity.go').read_text()
dynamic['parseIdentityReadFlags']=sorted(set(re.findall(r'parseIdentityReadFlags\("([^"]+)"',identity)))
def prefix(name):
 if not name:return ['ca','diff']
 args=name.split()
 if name.startswith('mailbox '):args.append(U if name in ['mailbox purge-cancel','mailbox purge-execute'] else '7')
 if name in ['upgrade watch','upgrade cancel','upgrade diagnostics']:args.append('7')
 if name in ['role delete','role grant','role revoke']:args.append('7' if name=='role delete' else 'a@example.test')
 if name=='device wipe':args.append('d1')
 if name in ['identity source show','identity source dry-run','identity source activate','identity source pause','identity source resume','identity source retire','identity source set-secret','identity source rotate-secret']:args.append('directory')
 if name=='identity people show':args.append('7')
 if name in ['identity conflict show','identity conflict decide','identity job watch','identity job results']:args.append(U)
 if name.startswith('identity transition ') and name not in ['identity transition preview','identity transition list']:args.append(U)
 return args
metadata={};cases=[]
for file in FILES:
 s=(ROOT/f'mailctl/{file}.go').read_text()
 found=list(re.finditer(r'flag.NewFlagSet\(([^\n]+?), flag\.(\w+)OnError\)',s))
 funcs=list(re.finditer(r'^func (\w+)\(',s,re.M))
 for i,m in enumerate(found):
  func=next(f for f in reversed(funcs) if f.start()<m.start())[1]
  ends=[x for x in [found[i+1].start() if i+1<len(found) else len(s),next((f.start() for f in funcs if f.start()>m.start()),len(s))] if x>m.start()]
  block=s[m.end():min(ends)]
  flags={}
  for f in re.finditer(r'fs\.(String|Bool|Int64|Int|Duration)(Var)?\((?:[^,]+,\s*)?"([^"\n]+)"',block):
   # Explicit patterns distinguish Name from Var's destination argument.
   pass
  for f in re.finditer(r'fs\.(String|Bool|Int64|Int|Duration)\("([^"\n]+)"',block):flags[f[2]]=f[1]
  for f in re.finditer(r'fs\.(String|Bool|Int64|Int|Duration)Var\([^,]+,\s*"([^"\n]+)"',block):flags[f[2]]=f[1]
  if 'bindIdentityOutputFlags(fs, c)' in block:flags.update(json='Bool',quiet='Bool')
  expression=m[1]
  names=[json.loads(expression)] if expression.startswith('"') and expression.endswith('"') and '+' not in expression else dynamic[func]
  for name in names:
   argv=prefix(name)+['--help'];obs=oracle.observe(str(args.go_binary.resolve()),{'args':argv})
   assert not obs['requests'],(name,obs)
   assert obs['stdout']=='',(name,obs)
   usage=obs['stderr'];override=None
   if obs['exit']==1:
    usage,sep,error=usage.rpartition('Error: ');assert sep,(name,obs)
    error=error.rstrip('\n');override=error if error!='flag: help requested' else None
   mode='exit' if m[2]=='Exit' else 'silent' if not usage else 'continue'
   assert usage or override,(name,func,obs)
   metadata[name]={'flags':flags,'mode':mode,'help':usage,'override_error':override}
   cases.append({'name':'b-flag-help-'+(name.replace(' ','-') or 'document'),'args':argv})
args.output.write_text(json.dumps(metadata,indent=2,ensure_ascii=False)+'\n')
print(f'derived {len(metadata)} flagsets')
