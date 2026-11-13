#!/usr/bin/env python3
"""Qualify SAML route aliases from immutable frozen-Go wire/effect observations."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CORPUS = Path(__file__).resolve().parent
GROUPS = {
    "GET /auth/saml/{idp}/login":"login", "GET /auth/saml/{idp}/metadata":"metadata",
    "POST /auth/saml/{idp}/acs":"acs", "POST /auth/saml/{idp}/link":"link",
    "GET /auth/saml/{idp}/link":"alias", "GET /auth/identity-links":"list", "DELETE /auth/identity-links/{id}":"unlink",
    **{f"* /auth/saml/ {g}":"gateway-"+g for g in ["login","metadata","acs","link","mux"]},
}

def qualify(original):
    values = [json.loads(json.dumps(original))]
    command = {"GET /auth/saml/{idp}/login":"login", "GET /auth/saml/{idp}/metadata":"metadata", "POST /auth/saml/{idp}/acs":"acs", "POST /auth/saml/{idp}/link":"link"}.get(original["route"])
    if command:
        alias = json.loads(json.dumps(original))
        alias["route"] = f"* /auth/saml/ {command}"
        values.append(alias)
    for value in values:
        method, path, *_ = value["route"].split(" ")
        request = value["observation"]["request"]
        request.setdefault("wire_method", request["method"])
        request.setdefault("wire_path", request["path"])
        request.update(method=method, path=path)
    return values



def immutable(path, value):
    if path.exists():
        if json.loads(path.read_text()) != value:
            raise SystemExit(f"refuse changed qualified Go observation: {path}")
    else:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def selector(case):
    if case.startswith("ssrf-"):return {"package":"setjoin-auth","target":"saml_oracle","test":"metadata_ssrf_private_literal_and_dns"}
    special={"login-success":"login_redirect_success","login-post":"login_post_success","login-encoded":"login_encoded_idp","login-session":"login_existing_sp_session","list-infinity":"list_infinite_timestamp_fails_closed"}
    if case in special:test=special[case]
    elif case.startswith("login-") and not case.endswith("status-mutant"):test="floor_"+case.replace("-","_")
    elif case.startswith(("metadata-","alias-")) and not case.endswith("status-mutant"):test="floor_"+case.replace("-","_")
    elif case.startswith(("acs-","mux-")) and case.split("-",1)[1] not in {"success","status-mutant"}:test="floor_"+case.replace("-","_")
    elif case.startswith(("list-","link-","unlink-")) and case.split("-",1)[1] not in {"success","status-mutant"}:test=case.split("-",1)[0]+"_floor_"+case.split("-",1)[1].replace("-","_")
    else:test=case.replace("-","_")
    return {"package":"setjoin-auth","target":"saml_oracle","test":test}


def main():
    directory = CORPUS / "qualified"
    directory.mkdir(exist_ok=True)
    grouped = {}
    for path in sorted(list((CORPUS / "goldens").glob("*.json"))+list(CORPUS.glob("ssrf-*.json"))):
        for doc in qualify(json.loads(path.read_text())):
            stem = GROUPS[doc["route"]] + "--" + doc["case"]
            golden = directory / (stem + ".json")
            immutable(golden, doc)
            observation = doc["observation"]
            rows = {"format": 1, "go_source": doc["go_source"], "route": doc["route"], "case": doc["case"] + "-row-effects",
                    "effects": [{"table": "saml_projection", "snapshot": observation["effects"], "identity": observation.get("identity"), "mapping": observation.get("mapping")}]}
            row_path = directory / (stem + "-rows.json")
            immutable(row_path, rows)
            grouped.setdefault(doc["route"], []).append((golden, row_path, doc))
    inventory_path = ROOT / "server-rust/bins/gateway/route-inventory.json"
    catalog_path = ROOT / "server-rust/tests/conformance/route-catalog.json"
    inventory = json.loads(inventory_path.read_text())
    catalog = json.loads(catalog_path.read_text())
    suites = []
    for route in inventory["routes"]:
        if route.get("slice") != "federation-saml":
            continue
        commands = ["login", "metadata", "acs", "link", "mux"] if route["path"] == "/auth/saml/" else [""]
        mutators = [c for c in commands if (c or GROUPS[f"{route['method']} {route['path']}"]) in {"acs", "link", "unlink"}]
        route.update(state="ON", upstream="rust-auth", oracle_commands=commands, oracle_mutators=mutators)
        for command in commands:
            key = f"{route['method']} {route['path']}" + (f" {command}" if command else "")
            group = GROUPS[key].removeprefix("gateway-")
            entries = grouped.get(key, [])
            floor = {group + "-" + kind: kind for kind in ("success", "cross-tenant", "invalid-input", "repeat")}
            entries.sort(key=lambda entry: (entry[2]["case"] not in floor, entry[2]["case"]))
            cases = []
            seen = set()
            for golden, rows, doc in entries:
                replay = selector(doc["case"])
                if replay["test"] in seen:
                    continue
                seen.add(replay["test"])
                case = {"kind": floor.get(doc["case"], "security" if doc["case"].startswith("ssrf-") else "edge"),
                        "golden": golden.relative_to(ROOT).as_posix(), "replay": replay}
                if command in mutators:
                    case["row_golden"] = rows.relative_to(ROOT).as_posix()
                cases.append(case)
            required = {"success", "cross-tenant", "invalid-input"} | ({"repeat"} if command in mutators else set())
            if not required <= {case["kind"] for case in cases}:
                raise SystemExit(f"missing frozen-Go floor for {key}")
            sources = ["server-rust/bins/auth/src/saml.rs"]
            if group in {"login","metadata","acs","link"}:sources.append("server-rust/crates/domains/identity/src/saml.rs")
            if group=="link":sources.append("server-rust/crates/domains/identity/src/rp/link.rs")
            if group in {"list","unlink"}:sources.append("server-rust/crates/domains/identity/src/identity_links.rs")
            suites.append({"listener": route["listener"], "method": route["method"], "path": route["path"], "family": "F21", "command": command,
                           "mutator": command in mutators, "cases": cases, "mutant": {"name": "status", **selector(group + "-status-mutant")}, "handler_sources": sources})
    def identity(row):
        return row["listener"], row["method"], row["path"], row["family"], row.get("command", "")
    owned = {identity(row) for row in suites}
    catalog["routes"] = [row for row in catalog["routes"] if identity(row) not in owned] + suites
    for path, value in [(inventory_path,inventory),(catalog_path,catalog)]:
        content=json.dumps(value,indent=2)+"\n"
        if path.read_text()!=content:path.write_text(content)
    print(f"IDFED3: {len(suites)} SAML route/command suites ON; immutable Go inputs retained")


if __name__ == "__main__":
    main()
