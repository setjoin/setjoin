import json,os,subprocess,spec
ROOT=os.path.abspath(os.path.join(os.path.dirname(__file__),'../../../../..'))
def rs(s): return json.dumps(s)  # JSON string literal is a valid Rust string for our ASCII/escapes
def world(w):
    toggles="vec!["+",".join(f'({rs(k)},{str(v).lower()})' for k,v in w.get("toggles",[]))+"]"
    assist={None:"None",True:"Some(true)",False:"Some(false)"}[w.get("assist")]
    health="None" if w.get("health") is None else f'Some({rs(w["health"])})'
    return f'World{{assist:{assist},provider:Provider::{w.get("provider","None")},compliance:{str(w.get("compliance",False)).lower()},chat:{str(w.get("chat",False)).lower()},toggles:{toggles},health:{health},telemetry:{("None" if w.get("telemetry") is None else "Some("+rs(w["telemetry"])+")")}}}'
out=["// GENERATED case table (see tests/conformance/static1/README.md). Do not hand-edit.\n","// included at the root of tests/static_recorded.rs\n","\n","pub fn cases() -> Vec<Case> {\n","    vec![\n"]
for c in spec.CASES:
    hs="vec!["+",".join(f'({rs(k)},{rs(v)})' for k,v in c["headers"])+"]"
    out.append(f'        Case{{name:{rs(c["name"])},route:{rs(c["route"])},kind:{rs(c["kind"])},method:{rs(c["method"])},uri:{rs(c["uri"])},headers:{hs},body:{rs(c["body"])},auth:Auth::{c["auth"]},cfg:Cfg::{c["cfg"]},forwarded:{str(c["forwarded"]).lower()},repeat:{str(c["repeat"]).lower()},contract:{str(c["contract"]).lower()},world:{world(c["world"])}}},\n')
out.append("    ]\n}\n\n")
for c in spec.CASES:
    out.append(f'#[tokio::test]\nasync fn {c["name"]}() -> Result<(), BoxError> {{\n    run({rs(c["name"])}).await\n}}\n\n')
keys=[c["name"][:-len("_success")] for c in spec.CASES if c["name"].endswith("_success")]
for k in keys:
    out.append(f'#[tokio::test]\nasync fn {k}_rejects_status() -> Result<(), BoxError> {{\n    run_inner({rs(k+"_success")}, Mutant::Status).await\n}}\n\n')
out.append('#[tokio::test]\nasync fn autoconfig_oracle_rejects_missing_domain_filter() -> Result<(), BoxError> {\n    run_inner("autoconfig_foreign", Mutant::NoFilter).await\n}\n\n#[tokio::test]\nasync fn assist_oracle_rejects_missing_authentication() -> Result<(), BoxError> {\n    run_inner("assist_anonymous", Mutant::NoFilter).await\n}\n')
open(os.path.join(ROOT,"server-rust/bins/gateway/tests/static_oracle/cases.rs"),"w").write("".join(out))
subprocess.run(["rustfmt","--edition","2021",os.path.join(ROOT,"server-rust/bins/gateway/tests/static_oracle/cases.rs")],check=True)
print("ok",len(spec.CASES))
