#!/usr/bin/env python3
"""Qualify #494's recorded routes without replacing other oracle suites."""
import json
import copy
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
ROOT = CORPUS.parents[3]
INVENTORY = ROOT / "server-rust/bins/gateway/route-inventory.json"
CATALOG = ROOT / "server-rust/tests/conformance/route-catalog.json"
# Append a route only after its immutable Go floors and native mutant pass.
QUALIFIED = {
    "app-list": ("GET", "/auth/me/app-passwords", False),
    "app-create": ("POST", "/auth/me/app-passwords", True),
    "app-revoke": ("DELETE", "/auth/me/app-passwords/{id}", True),
    "dlp": ("POST", "/auth/me/dlp-check", False),
    "org": ("GET", "/auth/me/org-chart", False),
    "tips": ("GET", "/auth/me/mailtips", False),
    "receipt": ("POST", "/auth/me/read-receipt", True),
    "hook-list": ("GET", "/auth/me/webhooks", False),
    "hook-create": ("POST", "/auth/me/webhooks", True),
    "hook-delete": ("DELETE", "/auth/me/webhooks/{id}", True),
    "cert-list": ("GET", "/auth/me/smime/certs", False),
    "cert-upload": ("POST", "/auth/me/smime/certs", True),
    "cert-delete": ("DELETE", "/auth/me/smime/certs/{id}", True),
    "cert-default": ("POST", "/auth/me/smime/certs/{id}/default", True),
    "recipient-list": ("GET", "/auth/me/smime/recipient-certs", False),
    "recipient-upload": ("POST", "/auth/me/smime/recipient-certs", True),
    "recipient-delete": ("DELETE", "/auth/me/smime/recipient-certs/{id}", True),
    "migration-status": ("GET", "/auth/me/migration", False),
    "migration-delete": ("DELETE", "/auth/me/migration", True),
    "migration-start": ("POST", "/auth/me/migration", True),
    "migration-resume": ("POST", "/auth/me/migration/resume", True),
    "migration-cancel": ("POST", "/auth/me/migration/cancel", True),
    "migration-pause": ("POST", "/auth/me/migration/pause", True),
    "migration-upload": ("POST", "/auth/me/migration/upload", True),
    "migration-test-imap": ("POST", "/auth/me/migration/test-imap", False),
}


def replay(test):
    return dict(package="setjoin-gateway", target="identity_self_service", test=test)


def main():
    inventory = json.loads(INVENTORY.read_text())
    catalog = json.loads(CATALOG.read_text())
    suites = []
    for prefix, (method, path, mutator) in QUALIFIED.items():
        for kind in ("success", "cross-tenant", "invalid-input"):
            assert (CORPUS / "goldens" / f"{prefix}-{kind}.json").is_file(), (prefix, kind)
        registration = next(r for r in inventory["routes"] if
                            r["listener"] == "gateway" and r["family"] == "F21"
                            and r["method"] == method and r["path"] == path)
        registration.update(state="ON", upstream="local-rust", oracle_commands=[""],
                            oracle_mutators=[""] if mutator else [])
        suite = dict(listener="gateway", method=method, path=path, family="F21", command="",
                     mutator=mutator, cases=[],
                     mutant=dict(replay(prefix.replace("-", "_") + "_status_mutant"), name="status"),
                     handler_sources=["server-rust/bins/gateway/src/identity_self_service.rs",
                                      "server-rust/crates/domains/identity/src/self_service.rs"])
        if prefix.startswith(("cert-", "recipient-")):
            suite["handler_sources"].append("server-rust/bins/gateway/src/identity_smime.rs")
        if prefix.startswith("migration-"):
            suite["handler_sources"].append("server-rust/bins/gateway/src/identity_migration.rs")
        for file in sorted((CORPUS / "goldens").glob(prefix + "-*.json")):
            if file.stem.endswith("-rows"):
                continue
            document = json.loads(file.read_text())
            qualified = copy.deepcopy(document)
            request = qualified["observation"]["request"]
            request["wire_path"] = request["path"]
            request["path"] = path
            channels = qualified["observation"]["notify"]
            qualified["observation"]["notify"] = [dict(channel=channel, payload=payload)
                for channel, payloads in sorted(channels.items()) for payload in payloads]
            projected = CORPUS / "qualified" / file.name
            projected.parent.mkdir(exist_ok=True)
            if projected.exists():
                assert json.loads(projected.read_text()) == qualified, projected
            else:
                with projected.open("x") as output:
                    output.write(json.dumps(qualified, indent=2) + "\n")
            kind = document["case"]
            case = dict(kind=kind if kind in {"success", "cross-tenant", "invalid-input", "repeat"} else "edge",
                        golden=projected.relative_to(ROOT).as_posix(),
                        replay=replay((prefix + "-" + kind).replace("-", "_")))
            if mutator:
                companion = file.with_name(file.stem + "-rows.json")
                assert companion.is_file(), companion
                case["row_golden"] = companion.relative_to(ROOT).as_posix()
            suite["cases"].append(case)
        suites.append(suite)
    keys = {(r["listener"], r["method"], r["path"], r["family"], r.get("command", "")) for r in suites}
    catalog["routes"] = [r for r in catalog["routes"] if
                         (r["listener"], r["method"], r["path"], r["family"], r.get("command", "")) not in keys] + suites
    for destination, document in ((INVENTORY, inventory), (CATALOG, catalog)):
        encoded = json.dumps(document, indent=2) + "\n"
        if destination.read_text() != encoded:
            destination.write_text(encoded)
    print(f"IDLOGIN4: {len(suites)} native mailserver self-service registrations")


if __name__ == "__main__":
    main()
