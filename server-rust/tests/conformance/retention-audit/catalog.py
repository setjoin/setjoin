#!/usr/bin/env python3
"""Qualify #290 only from immutable Go HTTP/effect records; retain other slices."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = Path(__file__).resolve().parent
INVENTORY = ROOT / "server-rust/bins/gateway/route-inventory.json"
CATALOG = ROOT / "server-rust/tests/conformance/route-catalog.json"
TESTS = ROOT / "server-rust/bins/gateway/tests/retention_audit_recorded.rs"
WRITES = {"create", "update", "delete", "log_set", "log_prune", "audit_set", "purge"}

def selector(name):
    return {"package": "setjoin-gateway", "target": "retention_audit_recorded", "test": name}

def main():
    tests = {(action, label): test for test, action, label in re.findall(
        r'(?<![\w])case!\(\s*(\w+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', TESTS.read_text())}
    tests.update({("policies", "success"): "policies_success", ("create", "success"): "create_success"})
    inventory = json.loads(INVENTORY.read_text())
    catalog = json.loads(CATALOG.read_text())
    catalog["routes"] = [r for r in catalog["routes"] if r.get("compl2") is not True]
    records = {}
    for file in sorted((BASE / "goldens").glob("*.json")):
        if file.stem.endswith("-row-effects") or file.stem == "policies-invalid":
            continue  # legacy empty GET; bad-query is the genuine invalid floor
        doc = json.loads(file.read_text())
        action = file.stem.split("-", 1)[0]
        records.setdefault(doc["route"], []).append((action, doc, file))
    existing_effects = {m["name"] for row in catalog["routes"] if row["family"] == "F04" for m in row.get("family_mutants", [])}
    changed = 0
    for route in inventory["routes"]:
        if route["family"] != "F04" or route["slice"] != "retention-audit":
            continue
        key = route["method"] + " " + route["path"]
        group = records[key]
        action = group[0][0]
        assert all(a == action for a, _, _ in group)
        assert not any(r["family"] == "F04" and r["method"] == route["method"] and r["path"] == route["path"] for r in catalog["routes"]), key
        suite = {k: route[k] for k in ("listener", "method", "path", "family")}
        source = "content" if action in ("search", "purge") else "audit" if action.startswith("audit_") else "retention"
        suite.update(compl2=True, mutator=action in WRITES, handler_sources=[
            "server-rust/bins/gateway/src/retention_audit.rs",
            "server-rust/crates/domains/compliance/src/lib.rs",
            f"server-rust/crates/domains/compliance/src/{source}.rs",
        ], cases=[])
        if action == "search":
            suite["handler_sources"].append("server-rust/crates/domains/compliance/src/kql.rs")
        for _, doc, file in group:
            label = doc["case"]
            kind = {"foreign": "cross-tenant", "invalid": "invalid-input"}.get(label, label)
            if action == "policies" and label == "bad-query":
                kind = "invalid-input"
            case = {"kind": kind, "golden": str(file.relative_to(ROOT)), "replay": selector(tests[(action, label)])}
            if action in WRITES:
                row_file = file.with_name(file.stem + "-row-effects.json")
                projection = {k: doc[k] for k in ("format", "route", "go_source")}
                projection.update(case=label + "-row-effects", effects=doc["observation"]["effects"])
                if row_file.exists():
                    assert json.loads(row_file.read_text()) == projection, row_file
                else:
                    with row_file.open("x") as out:
                        out.write(json.dumps(projection, indent=2) + "\n")
                case["row_golden"] = str(row_file.relative_to(ROOT))
            suite["cases"].append(case)
        suite["mutant"] = dict(name="status", **selector("mutant_" + action))
        effect = {"create": ("no-audit", "mutant_no_audit"), "log_set": ("no-notify", "mutant_no_notify"),
                  "update": ("no-tenant-filter", "mutant_no_tenant_filter"), "purge": ("double-bump", "mutant_double_bump")}.get(action)
        if effect:
            mutant = dict(name=effect[0], **selector(effect[1]))
            if effect[0] in existing_effects:
                # F04's standard family names are unique across its slices.
                # Use this slice's deeper effect mutant as its route self-test.
                suite["mutant"] = mutant
            else:
                suite["family_mutants"] = [mutant]
                existing_effects.add(effect[0])
        catalog["routes"].append(suite)
        route.update(state="ON", upstream="local-rust", oracle_commands=[""], oracle_mutators=[""] if action in WRITES else [])
        changed += 1
    assert changed == 14, changed
    CATALOG.write_text(json.dumps(catalog, indent=2) + "\n")
    INVENTORY.write_text(json.dumps(inventory, indent=2) + "\n")

if __name__ == "__main__":
    main()
