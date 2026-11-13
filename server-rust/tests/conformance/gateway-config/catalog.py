"""Project immutable Go observations into the route catalog; never edit recordings."""
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
raw = json.loads((HERE / "reload-http.json").read_text())
path = ROOT / "server-rust/tests/conformance/route-catalog.json"
catalog = json.loads(path.read_text())
route = "POST /admin/reload"
suite = {"listener":"gateway", "method":"POST", "path":"/admin/reload", "family":"F08", "command":"", "mutator":False,
         "handler_sources":["server-rust/bins/gateway/src/platform.rs", "server-rust/bins/gateway/src/configuration/mod.rs", "server-rust/bins/gateway/src/configuration/runtime.rs"], "cases":[],
         "mutant":{"name":"changed-status","package":"setjoin-gateway","target":"gateway_config_runtime","test":"reload_status_mutant_is_rejected"}}
for label,kind,test in [("success","success","reload_success_recording"),("cross-tenant","cross-tenant","reload_scoped_recording"),("invalid-input","invalid-input","reload_invalid_recording"),("denied","edge","reload_denied_recording"),("repeat","repeat","reload_repeat_recording")]:
    observation = {"request":{"method":"POST","path":"/admin/reload"},"response":raw["observation"][label],"effects":[],"audit":raw["observation"]["audit"] if label=="denied" else [],"notify":[]}
    document = {"format":1,"route":route,"case":label,"go_source":raw["go_source"],"observation":observation}
    target = HERE / f"reload-{label}.json"
    if target.exists():
        assert json.loads(target.read_text()) == document, f"immutable projection changed: {target}"
    else:
        target.write_text(json.dumps(document,indent=2)+"\n")
    suite["cases"].append({"kind":kind,"golden":str(target.relative_to(ROOT)),"replay":{"package":"setjoin-gateway","target":"gateway_config_runtime","test":test}})
catalog["routes"] = [r for r in catalog["routes"] if not (r["listener"]=="gateway" and r["method"]=="POST" and r["path"]=="/admin/reload")]
catalog["routes"].append(suite)
path.write_text(json.dumps(catalog,indent=2)+"\n")
