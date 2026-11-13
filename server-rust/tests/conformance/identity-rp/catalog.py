#!/usr/bin/env python3
"""Qualify RP route aliases from immutable frozen-Go wire/effect observations."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CORPUS = Path(__file__).resolve().parent
GROUPS = {
    "GET /auth/oidc/login": "login", "GET /auth/oidc/callback": "callback",
    "POST /auth/oidc/link": "link", "GET /auth/oidc/link": "alias",
    "* /auth/oidc/ login": "gateway-login", "* /auth/oidc/ callback": "gateway-callback",
    "* /auth/oidc/ link": "gateway-link", "* /auth/oidc/ mux": "mux",
}


def qualify(original):
    values = [json.loads(json.dumps(original))]
    command = {"GET /auth/oidc/login": "login", "GET /auth/oidc/callback": "callback", "POST /auth/oidc/link": "link"}.get(original["route"])
    if command:
        alias = json.loads(json.dumps(original))
        alias["route"] = f"* /auth/oidc/ {command}"
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
    if case.startswith("ssrf-"):
        test = "rp_ssrf_private_issuer"
    elif case.startswith("callback-link-"):
        test = "callback_explicit_link"
    elif case in {"callback-missing-verifier", "callback-bad-verifier"}:
        test = "callback_verifier_guards"
    elif case in {"callback-missing-provider", "callback-unknown-provider", "callback-redirect-mismatch"}:
        test = "callback_provider_guards"
    elif case in {"callback-no-email", "callback-invalid-groups", "callback-unknown-user"}:
        test = "callback_verified_assertion_guards"
    elif case in {"callback-address-collision", "callback-disabled", "callback-profile-invalid", "callback-profile-conflict"}:
        test = "callback_account_guards"
    elif case.startswith("callback-groups-"):
        test = "callback_group_mappings"
    elif case.startswith("callback-normalized"):
        test = "callback_normalized_identity"
    elif case == "callback-jit":
        test = "callback_profile_update"
    elif case == "callback-jit-create":
        test = "callback_jit_create"
    elif case.startswith("callback-") and case.removeprefix("callback-") in {
        "bad-nonce", "missing-nonce-cookie", "bad-signature", "bad-issuer", "bad-audience",
        "multi-audience-no-azp", "multi-audience-azp", "bad-azp", "expired", "future-iat",
        "bad-at-hash", "valid-at-hash",
    }:
        test = "callback_id_token_checks"
    else:
        test = case.replace("-", "_")
    return {"package": "setjoin-auth", "target": "rp_oracle", "test": test}


def main():
    directory = CORPUS / "qualified"
    directory.mkdir(exist_ok=True)
    grouped = {}
    for path in sorted((CORPUS / "goldens").glob("*.json")):
        for doc in qualify(json.loads(path.read_text())):
            stem = GROUPS[doc["route"]] + "--" + doc["case"]
            golden = directory / (stem + ".json")
            immutable(golden, doc)
            observation = doc["observation"]
            rows = {"format": 1, "go_source": doc["go_source"], "route": doc["route"], "case": doc["case"] + "-row-effects",
                    "effects": [{"table": "rp_projection", "snapshot": observation["effects"], "identity": observation.get("identity"), "mapping": observation.get("mapping")}]}
            row_path = directory / (stem + "-rows.json")
            immutable(row_path, rows)
            grouped.setdefault(doc["route"], []).append((golden, row_path, doc))
    inventory_path = ROOT / "server-rust/bins/gateway/route-inventory.json"
    catalog_path = ROOT / "server-rust/tests/conformance/route-catalog.json"
    inventory = json.loads(inventory_path.read_text())
    catalog = json.loads(catalog_path.read_text())
    suites = []
    for route in inventory["routes"]:
        if route.get("slice") != "federation-rp":
            continue
        commands = ["login", "callback", "link", "mux"] if route["path"] == "/auth/oidc/" else [""]
        mutators = [c for c in commands if (c or GROUPS[f"{route['method']} {route['path']}"]) in {"callback", "link"}]
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
            base = "server-rust/crates/domains/identity/src/rp"
            sources = ["server-rust/bins/auth/src/rp.rs"]
            if group in {"login", "callback", "link"}:
                sources.append(base + ".rs")
            if group == "callback":
                sources.extend([base + "/account.rs", base + "/link.rs"])
            elif group == "link":
                sources.append(base + "/link.rs")
            suites.append({"listener": route["listener"], "method": route["method"], "path": route["path"], "family": "F21", "command": command,
                           "mutator": command in mutators, "cases": cases, "mutant": {"name": "status", **selector(group + "-status-mutant")}, "handler_sources": sources})
    def identity(row):
        return row["listener"], row["method"], row["path"], row["family"], row.get("command", "")
    owned = {identity(row) for row in suites}
    catalog["routes"] = [row for row in catalog["routes"] if identity(row) not in owned] + suites
    inventory_path.write_text(json.dumps(inventory, indent=2) + "\n")
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"IDFED2: {len(suites)} RP route/command suites ON; immutable Go inputs retained")


if __name__ == "__main__":
    main()
