"""Translate this repository's frozen Go JSON wire declarations to serde shapes."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[4]
def snake(s):
 if s=='Type':return 'r#type'
 return re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',re.sub(r'(.)([A-Z][a-z]+)',r'\1_\2',s)).lower()
def pascal(s):return s[0].upper()+s[1:]
def derive(paths,names,out):
 sources='\n'.join((ROOT/p).read_text() for p in paths)
 definitions={};generated={}
 for m in re.finditer(r'^type (\w+) struct \{\n',sources,re.M):
  start=m.end();d=1;i=start
  while d:
   if sources[i]=='{':d+=1
   if sources[i]=='}':d-=1
   i+=1
  definitions[m[1]]=sources[start:i-1].splitlines()
 def typ(t,base):
  if t.startswith('*'):return 'Option<'+typ(t[1:],base)+'>'
  if t.startswith('[]'):return 'Option<Vec<'+typ(t[2:],base)+'>>'
  if t.startswith('map[string]'):return 'Option<std::collections::BTreeMap<String,'+typ(t[len('map[string]'):],base)+'>>'
  if t=='json.RawMessage':return 'Raw'
  if t in ['interface{}','interface {}','any']:return 'serde_json::Value'
  if t=='string':return 'String'
  if t=='bool':return 'bool'
  if t in ['int','int64']:return 'i64'
  if t in ['float64']:return 'f64'
  if t in definitions:emit(t,definitions[t]);return pascal(t)
  raise ValueError((t,base))
 def emit(name,lines):
  key=pascal(name)
  if key in generated:return
  generated[key]=''
  fields=[];i=0
  while i<len(lines):
   line=lines[i].strip();i+=1
   if not line or line.startswith('//'):continue
   m=re.match(r'(\w+)\s+(\[\]|\*)?struct \{',line)
   if m:
    field=m[1];array=m[2]=='[]';pointer=m[2]=='*';nested=[];d=1
    while d:
     line=lines[i].strip();i+=1;d+=line.count('{')-line.count('}')
     if d:nested.append(line)
    tag=re.search(r'json:"([^"]+)"',line)[1];child=key+field;emit(child,nested);rust=('Option<Vec<'+child+'>>') if array else ('Option<'+child+'>') if pointer else child
   else:
    m=re.match(r'(\w+)\s+(.+?)\s+`json:"([^"]+)"`',line)
    if not m:raise ValueError((key,line))
    field,t,tag=m.groups();rust=typ(t,key)
   parts=tag.split(',');attrs=[f'rename = "{parts[0]}"']
   if 'omitempty' in parts:
    skip='option_vec_empty' if rust.startswith('Option<Vec<') else 'Option::is_none' if rust.startswith('Option<') else 'String::is_empty' if rust=='String' else 'serde_json::Value::is_null' if rust=='serde_json::Value' else 'Raw::is_absent' if rust=='Raw' else 'zero'
    attrs.append(f'skip_serializing_if = "{skip}"')
   if rust=='Option<f64>':attrs.append('serialize_with = "optional_float"')
   extra='    #[serde(deserialize_with = "crate::models::null_default")]\n' if not rust.startswith('Option<') and rust!='Raw' else ''
   fields.append(f'    #[serde({", ".join(attrs)})]\n{extra}    pub {snake(field)}: {rust},')
  generated[key]='#[derive(Default, serde::Deserialize, serde::Serialize)]\n#[serde(default)]\npub struct '+key+' {\n'+'\n'.join(fields)+'\n}\n'
 for name in names:emit(name,definitions[name])
 output='//! Wire shapes translated from frozen Go; field order, nil slices and omissions are observable.\n'+r"""
#[derive(Default)]
pub struct Raw(Option<Box<serde_json::value::RawValue>>);
impl Raw {fn is_absent(&self)->bool{self.0.is_none()}}
impl<'de> serde::Deserialize<'de> for Raw {fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{Ok(Self(Some(serde::Deserialize::deserialize(d)?)))}}
impl serde::Serialize for Raw {fn serialize<S:serde::Serializer>(&self,s:S)->Result<S::Ok,S::Error>{match &self.0{Some(raw)=>raw.serialize(s),None=>s.serialize_none()}}}
"""+''.join(generated.values())
 output+='\nfn zero<T:Default+PartialEq>(v:&T)->bool{*v==T::default()}\n'
 output+='pub fn json(name:&str,raw:&str)->Result<String,crate::client::Failure>{\nmatch name{\n'
 for name in names:
  for prefix,ty in ([('',pascal(name)),('[]','Option<Vec<'+pascal(name)+'>>')] if name in ['approvalPolicy','roleRow','roleMemberRow'] else [('',pascal(name))]):
   if prefix=='':ty='Option<'+ty+'>'
   post='let v=v.unwrap_or_default();' if prefix=='' else ''
   output+=f'"{prefix}{name}"=>{{let v: {ty}=serde_json::from_str(raw).map_err(|e|crate::client::json_error(raw,&e,false))?;{post}Ok(crate::part_b::ordered_pretty(&serde_json::to_string(&v).unwrap()))}},\n'
 output+='_=>unreachable!("unknown wire shape {name}"),\n}\n}\n'
 output+=r"""
fn optional_float<S:serde::Serializer>(v:&Option<f64>,s:S)->Result<S::Ok,S::Error>{match v{Some(v)=>crate::models::float(v,s),None=>s.serialize_none()}}

fn option_vec_empty<T>(v:&Option<Vec<T>>)->bool{v.as_ref().is_none_or(Vec::is_empty)}
"""
 out.write_text(output)
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args()
 assert not args.output.exists(), 'derive into a new file; compare before replacing reviewed wire shapes'
 derive(['mailctl/identity_types.go','mailctl/identity.go','mailctl/role.go','mailctl/approval.go','mailctl/office.go'],['approvalPolicy', 'roleRow', 'roleMemberRow', 'roleExport', 'officeDoctorReport', 'officeDiagnosticsReport', 'identityInventoryResponse', 'identitySourceList', 'identitySourceDetail', 'identitySourcePlanResult', 'identitySourceMutationResult', 'identityPeopleList', 'identityPersonDetail', 'identityConflictList', 'identityConflictDetail', 'identityConflictDecisionResult', 'identityTransitionList', 'identityEventList', 'identityTransitionPreview', 'identityTransitionDetail', 'identityTransitionChallenge', 'identityTransitionElevation', 'identityUpgradeStatus', 'identityUpgradeCanaryResult', 'identityUpgradeRollbackResult', 'identityDoctor', 'identityInventoryExport', 'identityJob', 'identityJobResults', 'identityUpgradePreflight', 'identityUpgradeShadow', 'identityUpgradeRetirementCheck', 'identityTransitionReport'],args.output)
