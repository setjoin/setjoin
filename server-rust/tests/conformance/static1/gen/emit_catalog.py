"""Merge this family's generated cases without dropping later qualification work."""
import json
from pathlib import Path
import spec

ROOT = Path(__file__).resolve().parents[5]
GW = "server-rust/bins/gateway/src/"
ST = "server-rust/crates/domains/static/src/"


def sources(path, command):
    if command == "device-proof":
        return [GW + "telemetry.rs", ST + "telemetry.rs", "server-rust/crates/authz/src/device.rs"]
    if path.startswith("/assist/"):
        return [GW + "assist.rs"] + ([ST + "assist.rs"] if path.endswith("complete") else [])
    if path.startswith("/chat/"):
        return [GW + "translate.rs", "server-rust/crates/domains/chat/src/members.rs", ST + "assist.rs"]
    result = [GW + "surface.rs"]
    if "openapi" in path or path in ("/api/docs", "/api/logo.svg", "/api/redoc.standalone.js") or "/api/fonts/" in path:
        result.append(ST + "openapi.rs")
    elif path.startswith("/downloads"):
        result.append(ST + "downloads.rs")
    elif path in ("/health", "/ready"):
        result.append(ST + "health.rs")
    elif path == "/api/discover":
        result.append(GW + "discovery.rs")
    elif path == "/metrics":
        result += [ST + "metrics.rs", GW + "served_stats.rs"]
    elif path == "/.well-known/setjoin" or "autoconfig" in path:
        result.append(ST + "wellknown.rs")
    elif path == "/telemetry":
        result.append(GW + "telemetry.rs")
    return result


def family(path):
    return "F20" if path.startswith("/assist/") else "F12" if path.startswith("/chat/") else "F22"


def key(row):
    return row["listener"], row["method"], row["path"], row.get("command", "")


groups = {}
partitioned_telemetry = any(c["route"] == "POST /telemetry toggle-off" for c in spec.CASES)
for case in spec.CASES:
    if partitioned_telemetry and case["route"] == "POST /telemetry":
        continue
    if case["contract"]:
        continue
    method, path, *command = case["route"].split(" ", 2)
    groups.setdefault(("gateway", method, path, command[0] if command else ""), []).append(case)

catalog_path = ROOT / "server-rust/tests/conformance/route-catalog.json"
catalog = json.loads(catalog_path.read_text())
owned = []
# The old whole-route telemetry recordings remain regression tests. Fresh
# named OFF/ON suites partition qualification without changing any golden.
legacy = next((row for row in catalog["routes"] if key(row) == ("gateway","POST","/telemetry","")), None)
if legacy is not None and ("gateway","POST","/telemetry","toggle-off") in groups:
    expected = {"telemetry-success.json","telemetry-foreign.json","telemetry-invalid.json","telemetry-enabled-unproven.json","telemetry-enabled-invalid.json"}
    assert {Path(c["golden"]).name for c in legacy["cases"]} == expected, "review new telemetry qualification before replacing legacy suite"
    catalog["routes"].remove(legacy)
for route, cases in groups.items():
    listener, method, path, command = route
    suite = next((row for row in catalog["routes"] if key(row) == route), None)
    mutator = path.startswith("/chat/") or command == "device-proof"
    stem = next(case["name"][:-8] for case in cases if case["name"].endswith("_success"))
    if suite is None:
        suite = dict(listener=listener, method=method, path=path, family=family(path), mutator=mutator, cases=[])
        if command:
            suite["command"] = command
        catalog["routes"].append(suite)
    suite["handler_sources"] = list(dict.fromkeys(suite.get("handler_sources", []) + sources(path, command)))
    suite.setdefault("mutant", dict(name="changed-status", package="setjoin-gateway", target="static_recorded", test=stem + "_rejects_status"))
    for case in cases:
        golden = "server-rust/tests/conformance/static1/goldens/" + case["name"].replace("_", "-")
        entry = next((row for row in suite["cases"] if row["golden"] == golden + ".json"), None)
        if entry is None:
            entry = {}
            suite["cases"].append(entry)
        entry.update(kind=case["kind"], golden=golden + ".json", replay=dict(package="setjoin-gateway", target="static_recorded", test=case["name"]))
        if mutator:
            entry["row_golden"] = golden + "-row-effects.json"
    if command == "device-proof":
        prior = suite.get("family_mutants", [])
        assert all(m["test"] in ("telemetry_oracle_rejects_missing_device_proof","telemetry_oracle_rejects_double_report") for m in prior)
        suite["family_mutants"] = [dict(name="double-bump",package="setjoin-gateway",target="static_recorded",test="telemetry_oracle_rejects_double_report")]
    if "autoconfig" in path:
        for mutant in suite.get("family_mutants", []):
            if mutant["name"] == "no-tenant-filter":
                assert mutant["test"] in ("autoconfig_oracle_rejects_missing_domain_filter", "static_oracle_rejects_missing_tenant_authority")
                mutant["test"] = "static_oracle_rejects_missing_tenant_authority"
    owned.append((method, path, command, mutator))
catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")

inventory_path = ROOT / "server-rust/bins/gateway/route-inventory.json"
inventory = json.loads(inventory_path.read_text())
for row in inventory["routes"]:
    if row["listener"] != "gateway":
        continue
    if row["method"] == "POST" and row["path"] == "/telemetry" and ("gateway","POST","/telemetry","toggle-off") in groups:
        row["oracle_commands"] = [c for c in row.get("oracle_commands",[]) if c]
    for method, path, command, mutator in owned:
        if (row["method"], row["path"]) != (method, path):
            continue
        commands = row.setdefault("oracle_commands", [])
        mutators = row.setdefault("oracle_mutators", [])
        if command not in commands:
            commands.append(command)
        if mutator and command not in mutators:
            mutators.append(command)
inventory_path.write_text(json.dumps(inventory, indent=2) + "\n")
print(f"merged {len(owned)} static suites")
