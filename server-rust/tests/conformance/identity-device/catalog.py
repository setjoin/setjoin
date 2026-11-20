#!/usr/bin/env python3
"""Register #341's qualified device-trust routes and preserve other oracle suites."""

import json
from pathlib import Path


def replay(test):
    return dict(package="setjoin-auth", target="device_oracle", test=test)


def suite_key(suite):
    return (suite["listener"], suite["method"], suite["path"], suite["family"], suite.get("command", ""))


root = Path(__file__).resolve().parents[4]
corpus = Path(__file__).resolve().parent
inventory = root / "server-rust/bins/gateway/route-inventory.json"
catalog = root / "server-rust/tests/conformance/route-catalog.json"
inv = json.loads(inventory.read_text())
cat = json.loads(catalog.read_text())
qualified = {
    ("GET", "/device/policy"): ("policy", False, 17),
    ("POST", "/device/checkin"): ("checkin", True, 32),
}

suites = []
for route in inv["routes"]:
    key = (route["method"], route["path"])
    if route["listener"] != "auth" or key not in qualified:
        continue
    prefix, mutator, count = qualified[key]
    route.update(
        state="ON",
        upstream="rust-auth",
        oracle_commands=[""],
        oracle_mutators=[""] if mutator else [],
    )
    suite = dict(
        listener="auth",
        method=key[0],
        path=key[1],
        family="F21",
        command="",
        mutator=mutator,
        cases=[],
        mutant=dict(replay(f"status_mutant_{prefix}_route"), name="status"),
        handler_sources=[
            "server-rust/bins/auth/src/device.rs",
            "server-rust/crates/domains/identity/src/device_trust.rs",
        ],
    )
    for path in sorted((corpus / "goldens").glob(f"{prefix}-*.json")):
        if path.stem.endswith("-rows"):
            continue
        case = json.loads(path.read_text())["case"]
        kind = case.removeprefix(f"{prefix}-")
        if kind not in {"success", "cross-tenant", "invalid-input"} and not (mutator and kind == "repeat"):
            kind = "edge"
        row = dict(
            kind=kind,
            golden=path.relative_to(root).as_posix(),
            replay=replay("device_" + case.replace("-", "_")),
        )
        if mutator:
            row["row_golden"] = path.with_name(f"{path.stem}-rows.json").relative_to(root).as_posix()
        suite["cases"].append(row)
    if len(suite["cases"]) != count:
        raise SystemExit(f'identity-device: {prefix} has {len(suite["cases"])} recordings, expected {count}')
    suites.append(suite)

if len(suites) != 2:
    raise SystemExit("identity-device: both auth device rows must exist in the inventory")
keys = {suite_key(suite) for suite in suites}
cat["routes"] = [suite for suite in cat["routes"] if suite_key(suite) not in keys] + suites
inventory.write_text(json.dumps(inv, indent=2) + "\n")
catalog.write_text(json.dumps(cat, indent=2) + "\n")
print(f"DEVICE341: {len(suites)} qualified registrations")
