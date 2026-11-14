#!/usr/bin/env python3
"""Exercise the route-transfer gate through its operator CLI."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
GUARD = ROOT / "scripts/check-gofree-oracle-adequacy.py"
FAMILY_MUTANTS = [
    {"name": name, "package": "fake-package", "target": "recorded", "test": name}
    for name in ("no-audit", "no-notify", "no-tenant-filter", "double-bump")
]


class TransferGate(unittest.TestCase):
    def effect_gate(self, *, notify=False, omit_notify=False, surviving_notify=False,
                    audit=True, omit_audit=False, state=True, omit_bump=False):
        """Exercise the operator CLI with recorded effects and executable receipts."""
        with tempfile.TemporaryDirectory(prefix="gofree-chat1-adequacy-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F12"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "row_golden": f"{kind}-rows.json",
                      "replay": {"package": "fake-package", "target": "recorded", "test": kind}}
                     for kind in ("success", "cross-tenant", "invalid-input", "repeat")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust",
                 "oracle_commands": [""], "oracle_mutators": [""]},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "mutator": True, "cases": cases,
                 "family_mutants": [m for m in FAMILY_MUTANTS
                                    if not ((omit_notify and m["name"] == "no-notify")
                                            or (omit_audit and m["name"] == "no-audit")
                                            or (omit_bump and m["name"] == "double-bump"))],
                 "mutant": {"package": "fake-package", "target": "recorded", "test": "mutant",
                            "name": "changed-status"}},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"], "go_source": "a" * 40,
                    "observation": {"request": {"method": "POST", "path": "/example"},
                                    "response": {"status": 200}, "effects": [{"state": 1}] if state else [],
                                    "audit": [{"action": "write"}] if audit else [],
                                    "notify": [{"channel": "changes", "payload": "1"}] if notify else []},
                }))
                (root / case["row_golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"] + "-row-effects",
                    "go_source": "a" * 40, "effects": [{"table": "example", "before": [], "after": [{"state": 1}]}] if state else [],
                }))
            cargo = root / "gofree-chat1-fake-cargo"
            cargo.write_text("""#!/bin/sh
case "$8" in
  success|cross-tenant|invalid-input|repeat) echo "GOLDEN-REPLAY: POST /example :: $8" ;;
  mutant) echo "MUTANT-REJECTED: POST /example :: changed-status" ;;
  no-notify) """ + ('echo "mutant survived"' if surviving_notify else 'echo "MUTANT-REJECTED: POST /example :: no-notify"') + """ ;;
  *) echo "MUTANT-REJECTED: POST /example :: $8" ;;
esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
""")
            cargo.chmod(0o755)
            return subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )

    def test_family_without_recorded_notifies_qualifies_without_notify_mutant(self):
        result = self.effect_gate(omit_notify=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("F12: no-notify not-applicable (0 recorded notifications in 4 ON-route goldens)", result.stdout)

    def test_family_with_recorded_notifies_rejects_a_surviving_notify_mutant(self):
        result = self.effect_gate(notify=True, surviving_notify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not emit receipt MUTANT-REJECTED: POST /example :: no-notify", result.stderr)
        self.assertNotIn("no-notify not-applicable", result.stdout)

    def test_family_with_recorded_notifies_cannot_omit_notify_mutant(self):
        result = self.effect_gate(notify=True, omit_notify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing family mutants: no-notify", result.stderr)

    def test_family_without_recorded_audit_qualifies_without_audit_mutant(self):
        result = self.effect_gate(audit=False, omit_audit=True, omit_notify=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("F12: no-audit not-applicable (0 recorded audit rows in 4 ON-route goldens)", result.stdout)

    def test_family_with_recorded_audit_cannot_omit_audit_mutant(self):
        result = self.effect_gate(omit_audit=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing family mutants: no-audit", result.stderr)

    def test_family_without_recorded_state_qualifies_without_bump_mutant(self):
        result = self.effect_gate(state=False, omit_bump=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("F12: double-bump not-applicable (0 recorded state snapshots in 4 ON-route goldens)", result.stdout)

    def test_family_with_recorded_state_cannot_omit_bump_mutant(self):
        result = self.effect_gate(omit_bump=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing family mutants: double-bump", result.stderr)

    def two_route_family(self, mutants_a, mutants_b):
        """Two ON routes of one family, each with its own family mutants (no execution)."""
        with tempfile.TemporaryDirectory(prefix="gofree-fix9-adequacy-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            routes, catalog = [], []
            for path, mutants in (("/one", mutants_a), ("/two", mutants_b)):
                route = {"listener": "gateway", "method": "POST", "path": path, "family": "F12"}
                cases = [{"kind": kind, "golden": f"{path[1:]}-{kind}.json",
                          "row_golden": f"{path[1:]}-{kind}-rows.json",
                          "replay": {"package": "fake-package", "target": "recorded", "test": path[1:] + kind}}
                         for kind in ("success", "cross-tenant", "invalid-input", "repeat")]
                routes.append({**route, "state": "ON", "upstream": "local-rust",
                               "oracle_commands": [""], "oracle_mutators": [""]})
                catalog.append({**route, "mutator": True, "cases": cases, "family_mutants": mutants,
                                "mutant": {"package": "fake-package", "target": "recorded",
                                           "test": path[1:] + "-mutant", "name": "changed-status"}})
                for case in cases:
                    (root / case["golden"]).write_text(json.dumps({
                        "format": 1, "route": f"POST {path}", "case": case["kind"], "go_source": "a" * 40,
                        "observation": {"request": {"method": "POST", "path": path},
                                        "response": {"status": 200}, "effects": [{"state": 1}],
                                        "audit": [{"action": "write"}],
                                        "notify": [{"channel": "changes", "payload": "1"}]},
                    }))
                    (root / case["row_golden"]).write_text(json.dumps({
                        "format": 1, "route": f"POST {path}", "case": case["kind"] + "-row-effects",
                        "go_source": "a" * 40, "effects": [{"table": "example", "before": [], "after": [{"state": 1}]}],
                    }))
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": routes}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": catalog}))
            return subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )

    @staticmethod
    def mutants(*names, suffix=""):
        return [{"name": n, "package": "fake-package", "target": "recorded", "test": n + suffix}
                for n in names]

    def test_a_family_accepts_one_notify_mutant_per_route(self):
        result = self.two_route_family(
            self.mutants("no-audit", "no-notify", "no-tenant-filter", "double-bump"),
            self.mutants("no-notify", suffix="-two"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_route_cannot_carry_two_notify_mutants(self):
        result = self.two_route_family(
            self.mutants("no-audit", "no-notify", "no-tenant-filter", "double-bump")
            + self.mutants("no-notify", suffix="-again"), [])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate family mutant no-notify", result.stderr)

    def test_other_family_mutants_stay_one_per_family(self):
        result = self.two_route_family(
            self.mutants("no-audit", "no-notify", "no-tenant-filter", "double-bump"),
            self.mutants("no-audit", suffix="-two"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate family mutant no-audit", result.stderr)

    def test_two_notify_mutants_cannot_share_one_selector(self):
        result = self.two_route_family(
            self.mutants("no-audit", "no-notify", "no-tenant-filter", "double-bump"),
            self.mutants("no-notify"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate family mutant selector", result.stderr)

    def test_a_recording_misplaced_in_handler_sources_fails_before_coverage(self):
        with tempfile.TemporaryDirectory(prefix="gofree-blobs1-adequacy-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "GET", "path": "/example", "family": "F16"}
            case = {"kind": "success", "golden": "success.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": "success",
            }}
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "OFF", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": [case], "handler_sources": [case]},
            ]}))
            (root / "success.json").write_text(json.dumps({
                "format": 1, "route": "GET /example", "case": "success", "go_source": "a" * 40,
                "observation": {"request": {"method": "GET", "path": "/example"},
                                "response": {"status": 200}, "effects": [], "audit": [], "notify": []},
            }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid handler coverage sources", result.stderr)

    def test_an_on_route_cannot_omit_its_command_inventory(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "family_mutants": FAMILY_MUTANTS, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("command inventory", result.stderr)

    def test_an_off_route_with_recorded_cases_is_still_replayed(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "OFF", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": [{"kind": "success", "golden": "success.json", "replay": {
                    "package": "fake-package", "target": "recorded", "test": "success",
                }}]},
            ]}))
            (root / "success.json").write_text(json.dumps({
                "format": 1, "route": "POST /example", "case": "success", "go_source": "a" * 40,
                "observation": {"request": {"method": "POST", "path": "/example"},
                                "response": {"status": 200}, "effects": {}, "audit": [], "notify": []},
            }))
            cargo = root / "gofree-t3-fake-cargo"
            cargo.write_text('#!/bin/sh\necho "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"\n')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("zero", result.stderr)

    def test_on_family_still_requires_the_authority_filter_mutant(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": [""], "oracle_mutators": []},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("family mutants", result.stderr)

    def test_inventory_mutator_cannot_be_declared_read_only_in_the_catalog(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": ["set"], "oracle_mutators": ["set"]},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "command": "set", "cases": cases, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example set", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutator", result.stderr)

    def test_mutating_route_requires_a_repeated_request(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "mutator": True, "cases": [
                    {"kind": kind, "golden": f"{kind}.json"}
                    for kind in ("success", "cross-tenant", "invalid-input")
                ]},
            ]}))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("repeat", result.stderr)

    def test_mutator_cannot_qualify_without_row_effect_recordings(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "row_golden": f"{kind}-rows.json",
                      "replay": {"package": "fake-package", "target": "recorded", "test": kind}}
                     for kind in ("success", "cross-tenant", "invalid-input", "repeat")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "mutator": True, "cases": cases, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("row effect", result.stderr)

    def test_on_route_requires_all_three_recorded_cases(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            inventory = {"version": 1, "routes": [{
                "listener": "gateway", "method": "POST", "path": "/example",
                "family": "F18", "state": "ON", "upstream": "local-rust",
            }]}
            catalog = {"version": 1, "routes": [{
                "listener": "gateway", "method": "POST", "path": "/example",
                "family": "F18", "cases": [{"kind": "success", "golden": "success.json"}],
            }]}
            (root / "inventory.json").write_text(json.dumps(inventory))
            (root / "catalog.json").write_text(json.dumps(catalog))
            (root / "success.json").write_text("{}")
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cross-tenant", result.stderr)
            self.assertIn("invalid-input", result.stderr)

    def test_declaring_a_case_without_its_recording_does_not_enable_a_route(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": [
                    {"kind": kind, "golden": f"{kind}.json"}
                    for kind in ("success", "cross-tenant", "invalid-input")
                ]},
            ]}))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recording", result.stderr)

    def test_empty_files_are_not_go_recordings(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json"}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text("{}")
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recording", result.stderr)

    def test_one_recording_cannot_stand_in_for_all_three_categories(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": "same.json"}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases},
            ]}))
            (root / "same.json").write_text(json.dumps({
                "format": 1, "route": "POST /example", "case": "success",
                "go_source": "a" * 40, "observation": {
                    "request": {"method": "POST", "path": "/example"},
                    "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                },
            }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate", result.stderr)

    def test_each_command_sharing_a_route_must_meet_the_floor(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            complete = [{"kind": kind, "golden": f"{kind}.json"}
                        for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "command": "first", "cases": complete[:1]},
                {**route, "command": "second", "cases": complete},
            ]}))
            for case in complete:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example second", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("first", result.stderr)
            self.assertIn("invalid-input", result.stderr)

    def test_omitting_a_command_from_the_catalog_cannot_hide_it(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json"}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": ["first", "second"]},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "command": "first", "cases": cases},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example first", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("second", result.stderr)

    def test_a_recording_for_another_command_cannot_qualify_a_route(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json"}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": ["first"]},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "command": "first", "cases": cases},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example second", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recording", result.stderr)

    def test_recordings_without_executable_replays_cannot_qualify_a_route(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json"}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("replay", result.stderr)

    def test_a_selector_that_runs_zero_tests_is_not_a_replay(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": [""], "oracle_mutators": []},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "family_mutants": FAMILY_MUTANTS, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            cargo = root / "gofree-t3-fake-cargo"
            cargo.write_text('#!/bin/sh\necho "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"\n')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("zero", result.stderr)

    def test_an_on_route_also_needs_a_mutant_self_test(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutant", result.stderr)

    def test_a_single_replay_cannot_claim_all_three_cases(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            replay = {"package": "fake-package", "target": "recorded", "test": "same_replay"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": replay}
                     for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "mutant": {**replay, "test": "mutant"}},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate replay", result.stderr)

    def test_a_passing_test_without_the_golden_receipt_does_not_qualify(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": [""], "oracle_mutators": []},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "family_mutants": FAMILY_MUTANTS, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            cargo = root / "gofree-t3-fake-cargo"
            cargo.write_text('#!/bin/sh\necho "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"\n')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("receipt", result.stderr)

    def test_a_passing_test_without_mutant_rejection_does_not_qualify(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": [""], "oracle_mutators": []},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "family_mutants": FAMILY_MUTANTS, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant", "name": "changed-status",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            cargo = root / "gofree-t3-fake-cargo"
            cargo.write_text('''#!/bin/sh
case "$*" in
  *success*) echo "test success ... GOLDEN-REPLAY: POST /example :: success" ;;
  *cross-tenant*) echo "test cross-tenant ... GOLDEN-REPLAY: POST /example :: cross-tenant" ;;
  *invalid-input*) echo "test invalid-input ... GOLDEN-REPLAY: POST /example :: invalid-input" ;;
esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
''')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("MUTANT-REJECTED", result.stderr)

    def test_missing_instrumented_binary_cannot_be_reported_as_coverage(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t3-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            source = root / "handler.rs"
            source.write_text("fn handler() {}\n")
            route = {"listener": "gateway", "method": "POST", "path": "/example", "family": "F18"}
            cases = [{"kind": kind, "golden": f"{kind}.json", "replay": {
                "package": "fake-package", "target": "recorded", "test": kind,
            }} for kind in ("success", "cross-tenant", "invalid-input")]
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "ON", "upstream": "local-rust", "oracle_commands": [""], "oracle_mutators": []},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": cases, "handler_sources": ["handler.rs"], "family_mutants": FAMILY_MUTANTS, "mutant": {
                    "package": "fake-package", "target": "recorded", "test": "mutant", "name": "changed-status",
                }},
            ]}))
            for case in cases:
                (root / case["golden"]).write_text(json.dumps({
                    "format": 1, "route": "POST /example", "case": case["kind"],
                    "go_source": "a" * 40, "observation": {
                        "request": {"method": "POST", "path": "/example"},
                        "response": {"status": 200}, "effects": {}, "audit": [], "notify": [],
                    },
                }))
            cargo = root / "gofree-t3-fake-cargo"
            cargo.write_text('''#!/bin/sh
case "$*" in
  *--no-run*) case "${RUSTFLAGS:-}" in *instrument-coverage*) [ -n "${LLVM_PROFILE_FILE:-}" ] || { echo "missing build profile path" >&2; exit 1; } ;; esac; exit 0 ;;
  *success*) echo "GOLDEN-REPLAY: POST /example :: success" ;;
  *cross-tenant*) echo "GOLDEN-REPLAY: POST /example :: cross-tenant" ;;
  *invalid-input*) echo "GOLDEN-REPLAY: POST /example :: invalid-input" ;;
  *no-audit*) echo "MUTANT-REJECTED: POST /example :: no-audit" ;;
  *no-notify*) echo "MUTANT-REJECTED: POST /example :: no-notify" ;;
  *no-tenant-filter*) echo "MUTANT-REJECTED: POST /example :: no-tenant-filter" ;;
  *double-bump*) echo "MUTANT-REJECTED: POST /example :: double-bump" ;;
  *mutant*) echo "MUTANT-REJECTED: POST /example :: changed-status" ;;
esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
''')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--coverage", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("coverage binary", result.stderr)

    def test_recording_a_go_binary_cannot_leak_into_rust_replay(self):
        with tempfile.TemporaryDirectory(prefix="gofree-blobs1-floor-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            route = {"listener": "gateway", "method": "GET", "path": "/example", "family": "F16"}
            (root / "inventory.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "state": "OFF", "upstream": "go-mail"},
            ]}))
            (root / "catalog.json").write_text(json.dumps({"version": 1, "routes": [
                {**route, "cases": [{"kind": "success", "golden": "success.json", "replay": {
                    "package": "fake-package", "target": "recorded", "test": "success",
                }}]},
            ]}))
            (root / "success.json").write_text(json.dumps({
                "format": 1, "route": "GET /example", "case": "success", "go_source": "a" * 40,
                "observation": {"request": {"method": "GET", "path": "/example"},
                                "response": {"status": 200}, "effects": [], "audit": [], "notify": []},
            }))
            cargo = root / "gofree-blobs1-fake-cargo"
            cargo.write_text('''#!/bin/sh
test -z "${GOFREE_RECORD_GO_BINARY+x}" || exit 7
echo "GOLDEN-REPLAY: GET /example :: success"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
''')
            cargo.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(GUARD), "--skip-preflight", "--root", str(root), "--execute", "--cargo", str(cargo),
                 "--inventory", str(root / "inventory.json"), "--catalog", str(root / "catalog.json")],
                env={**os.environ, "GOFREE_RECORD_GO_BINARY": "/nonexistent-go-recording-binary"},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_keep_going_runs_everything_and_still_fails(self):
        """--keep-going records every failing replay and exits non-zero; the default stops at the first."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("adequacy", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="gofree-keep-going-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            cargo = root / "cargo"
            # Fails the tests named bad-*; passes the rest with the receipt line on stdout.
            cargo.write_text('''#!/bin/sh
for arg in "$@"; do last="$arg"; done
for arg in "$@"; do case "$arg" in bad-*) echo "test $arg ... FAILED"; exit 101;; esac; done
echo "GOLDEN-REPLAY: r :: c"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
''')
            cargo.chmod(0o755)
            replays = [({"package": "p", "target": "t", "test": name}, "GOLDEN-REPLAY: r :: c")
                       for name in ("good-1", "bad-1", "good-2", "bad-2")]
            failures = []
            module.execute_replays(root, str(cargo), replays, failures, jobs=1)
            self.assertEqual([name for _, name, _ in failures], ["r :: p::t::bad-1", "r :: p::t::bad-2"])
            with self.assertRaises(ValueError):
                module.execute_replays(root, str(cargo), replays, jobs=1)

    def test_replays_run_side_by_side_but_never_two_of_one_serial_group(self):
        """On per-replay clones replays run `jobs` at a time; replays whose binaries share a serial
        group never overlap; each target builds once; failures name entry and selector in manifest
        order whatever order they finish in."""
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location("adequacy", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="gofree-parallel-replays-") as directory:
            root = Path(directory)
            (root / "server-rust").mkdir()
            spans = root / "spans"
            spans.mkdir()
            cargo = root / "cargo"
            # argv: test --locked --offline -p P --test T (--no-run | NAME -- --exact --nocapture)
            cargo.write_text('''#!/bin/sh
spans="$(dirname "$0")/spans"
if [ "$8" = --no-run ]; then echo "$5::$7" >>"$spans/builds"; exit 0; fi
start=$(date +%s%N)
case "$8" in *slow*) sleep 0.6 ;; *) sleep 0.25 ;; esac
echo "$start $(date +%s%N)" >"$spans/$8"
case "$8" in bad-*) echo "test $8 ... FAILED"; exit 101 ;; esac
echo "GOLDEN-REPLAY: GET /$7 :: c"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
''')
            cargo.chmod(0o755)
            names = {"free": ["bad-slow-free", "free-1", "free-2", "bad-free"],
                     "grouped": ["grouped-1", "grouped-2", "grouped-3"]}
            replays = [({"package": "p", "target": target, "test": name}, f"GOLDEN-REPLAY: GET /{target} :: c")
                       for target in ("free", "grouped") for name in names[target]]
            clones = {"LANE_ADMIN_DSN": "postgres://lane/postgres", "LANE_TEMPLATE_DB": "tpl", "LANE_BASE_DB": "base",
                      "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "bash wrapper.sh"}
            failures = []
            with mock.patch.dict(os.environ, clones), \
                    mock.patch.object(module, "load_serial_groups", lambda root: {"p::grouped": "host-00"}):
                module.execute_replays(root, str(cargo), replays, failures, jobs=3)

            def span(name):
                start, end = (int(value) for value in (spans / name).read_text().split())
                return start, end

            def overlap(a, b):
                return a[0] < b[1] and b[0] < a[1]

            grouped = [span(name) for name in names["grouped"]]
            for i in range(len(grouped)):
                for j in range(i + 1, len(grouped)):
                    self.assertFalse(overlap(grouped[i], grouped[j]), (names["grouped"][i], names["grouped"][j]))
            free = [span(name) for name in names["free"]]
            everything = free + grouped
            self.assertTrue(any(overlap(everything[i], everything[j])
                                for i in range(len(free)) for j in range(len(everything)) if i != j))
            self.assertEqual(sorted((spans / "builds").read_text().split()), ["p::free", "p::grouped"])
            self.assertEqual([name for _, name, _ in failures],
                             ["GET /free :: p::free::bad-slow-free", "GET /free :: p::free::bad-free"])

    def test_parallel_replays_need_per_replay_clones(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location("adequacy", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        env = {name: value for name, value in os.environ.items()
               if not (name.startswith("CARGO_TARGET_") and name.endswith("_RUNNER"))
               and name not in ("LANE_ADMIN_DSN", "LANE_TEMPLATE_DB", "LANE_BASE_DB", "LANE_ADEQUACY_JOBS")}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as caught:
                module.execute_replays(Path("/nonexistent"), "cargo", [], [], jobs=2)
            self.assertIn("per-replay database clones", str(caught.exception))
            self.assertEqual(module.replay_jobs(None), 1)


class Preflight(unittest.TestCase):
    """The static manifest checks that run before anything is built (error classes of run 43075019863)."""

    @staticmethod
    def module():
        import importlib.util
        spec = importlib.util.spec_from_file_location("adequacy", GUARD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def workspace(root):
        package = root / "server-rust/crates/demo"
        (package / "src").mkdir(parents=True)
        (package / "tests").mkdir()
        (package / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.0.0"\n')
        (package / "src/real.rs").write_text("pub fn handler() -> u32 { 1 }\n")
        (package / "src/stub.rs").write_text("pub use other::handler;\n")
        (package / "src/pages.rs").write_text('pub const PAGE: &str = "<html></html>";\n')
        (package / "tests/recorded.rs").write_text("#[test] fn replay() {}\n")

    def errors(self, sources, selectors):
        module = self.module()
        with tempfile.TemporaryDirectory(prefix="gofree-preflight-") as directory:
            root = Path(directory)
            self.workspace(root)
            suite = {"handler_sources": sources,
                     "cases": [{"replay": selector} for selector in selectors]}
            return module.preflight(root, [("GET /demo", suite)], [])

    GOOD = {"package": "demo", "target": "recorded", "test": "replay"}

    def test_a_real_handler_with_a_real_test_target_passes(self):
        self.assertEqual(self.errors(["server-rust/crates/demo/src/real.rs"], [self.GOOD]), [])

    def test_a_moved_handler_source_fails(self):
        errors = self.errors(["server-rust/crates/demo/src/gone/mod.rs"], [self.GOOD])
        self.assertEqual(len(errors), 1)
        self.assertIn("does not exist", errors[0])

    def test_a_re_export_stub_and_a_data_only_file_fail(self):
        errors = self.errors(["server-rust/crates/demo/src/stub.rs", "server-rust/crates/demo/src/pages.rs"], [self.GOOD])
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("defines no function" in error for error in errors))

    def test_a_replay_in_an_unknown_package_or_target_fails(self):
        errors = self.errors(["server-rust/crates/demo/src/real.rs"], [
            {**self.GOOD, "package": "nope"}, {**self.GOOD, "target": "nope"}])
        self.assertEqual(len(errors), 2)

    def test_a_route_spread_over_two_binaries_is_listed_and_accepted(self):
        module = self.module()
        with tempfile.TemporaryDirectory(prefix="gofree-preflight-") as directory:
            root = Path(directory)
            self.workspace(root)
            (root / "server-rust/crates/demo/tests/second.rs").write_text("#[test] fn replay() {}\n")
            suite = {"handler_sources": ["server-rust/crates/demo/src/real.rs"],
                     "cases": [{"replay": self.GOOD}, {"replay": {**self.GOOD, "target": "second"}}]}
            self.assertEqual(module.preflight(root, [("GET /demo", suite)], []), [])

    def test_the_real_manifest_passes_in_seconds(self):
        result = subprocess.run([sys.executable, str(GUARD), "--preflight-only"],
                                capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("preflight ok", result.stdout)

    def test_the_lane_never_skips_preflight_or_runs_a_subset_by_default(self):
        for name in ("scripts/check-server-rust.sh", "scripts/server-rust-parallel-lane.sh"):
            text = (ROOT / name).read_text()
            self.assertNotIn("--skip-preflight", text, name)
        text = (ROOT / "scripts/check-server-rust.sh").read_text()
        self.assertIn("--preflight-only", text)
        # coverage stays on unless the lane's full tier turns it off explicitly
        self.assertIn('"${LANE_COVERAGE:-1}" == 0', text)

    def test_entry_names_come_from_receipts(self):
        module = self.module()
        self.assertEqual(module.receipt_entry("GOLDEN-REPLAY: GET /health :: success"), "GET /health")
        self.assertEqual(module.receipt_entry("MUTANT-REJECTED: POST /auth/login mfa :: status"), "POST /auth/login mfa")
        self.assertEqual(module.receipt_entry("GOLDEN-REPLAY: control socket :: hardening"), "control socket")

    def test_subset_flags_reject_nonsense(self):
        for flags in (["--only", "bogus"], ["--entries", "GET /health"], ["--only", "coverage", "--execute"]):
            result = subprocess.run([sys.executable, str(GUARD), "--skip-preflight", *flags],
                                    capture_output=True, text=True, check=False, timeout=60)
            self.assertNotEqual(result.returncode, 0, flags)
        result = subprocess.run([sys.executable, str(GUARD), "--skip-preflight", "--only", "replays",
                                 "--entries", "GET /no-such-route"],
                                capture_output=True, text=True, check=False, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown route entries", result.stderr)


class CoverageScheduler(unittest.TestCase):
    """Entries whose test binaries share a nextest serial group never overlap (shared host ports)."""

    @staticmethod
    def module():
        return Preflight.module()

    def run_items(self, groups_by_item, jobs=3, delay=0.15):
        import threading
        import time
        module = self.module()
        lock = threading.Lock()
        active, spans, peak = set(), {}, [0]

        def work(item):
            with lock:
                active.add(item)
                peak[0] = max(peak[0], len(active))
                spans[item] = [time.monotonic(), None]
            time.sleep(delay)
            with lock:
                active.discard(item)
                spans[item][1] = time.monotonic()
            return item

        items = [(item, frozenset(groups)) for item, groups in groups_by_item.items()]
        done = list(module.run_grouped(items, jobs, work))
        self.assertEqual(sorted(done), sorted(groups_by_item))
        return spans, peak[0]

    @staticmethod
    def overlap(a, b):
        return a[0] < b[1] and b[0] < a[1]

    def test_entries_sharing_a_group_never_overlap_and_the_rest_run_concurrently(self):
        spans, peak = self.run_items({"a1": {"g1"}, "a2": {"g1"}, "a3": {"g1"}, "b1": {"g2"}, "free1": set(), "free2": set()})
        for x, y in (("a1", "a2"), ("a1", "a3"), ("a2", "a3")):
            self.assertFalse(self.overlap(spans[x], spans[y]), (x, y))
        # unrelated entries are not serialised behind the group
        self.assertTrue(self.overlap(spans["a1"], spans["b1"]) or self.overlap(spans["a1"], spans["free1"]))
        self.assertGreaterEqual(peak, 2)
        self.assertLessEqual(peak, 3)

    def test_an_entry_holding_two_groups_waits_for_both(self):
        spans, _ = self.run_items({"x": {"g1"}, "y": {"g2"}, "both": {"g1", "g2"}, "z": {"g1"}})
        for other in ("x", "y", "z"):
            self.assertFalse(self.overlap(spans["both"], spans[other]), other)

    def test_a_blocked_entry_does_not_idle_the_workers(self):
        # four entries of one group plus two free ones, 3 workers: the free ones run beside the group
        spans, peak = self.run_items({"g1a": {"g"}, "g1b": {"g"}, "g1c": {"g"}, "g1d": {"g"}, "f1": set(), "f2": set()})
        self.assertGreaterEqual(peak, 2)
        self.assertTrue(self.overlap(spans["f1"], spans["g1a"]) or self.overlap(spans["f2"], spans["g1a"]))

    def test_groups_come_from_the_nextest_group_config(self):
        module = self.module()
        groups = module.load_serial_groups(ROOT)
        self.assertEqual(groups["setjoin-auth::rp_oracle"], groups["setjoin-auth::rp_swap"])
        self.assertEqual(groups["setjoin-gateway::mailsec_tls"], groups["setjoin-gateway::mailsec_smime"])
        suite = {"cases": [{"replay": {"package": "setjoin-auth", "target": "rp_oracle", "test": "t"}},
                           {"replay": {"package": "setjoin-auth", "target": "csrf", "test": "t"}},
                           {"replay": {"package": "setjoin-auth", "target": "no_such_binary", "test": "t"}}]}
        self.assertEqual(module.entry_groups(suite, groups),
                         frozenset({groups["setjoin-auth::rp_oracle"], groups["setjoin-auth::csrf"]}))


class HostedShards(unittest.TestCase):
    """Hosted CI: replay and coverage shards, prebuilt binaries launched directly."""

    @staticmethod
    def module():
        return Preflight.module()

    def test_round_robin_slices_cover_the_input_once(self):
        module = self.module()
        self.assertEqual(module.shard_items(list(range(10)), (2, 3)), [1, 4, 7])
        union = sorted(item for k in (1, 2, 3) for item in module.shard_items(list(range(10)), (k, 3)))
        self.assertEqual(union, list(range(10)))
        self.assertEqual(module.parse_shard("2/3"), (2, 3))
        for bad in ("0/3", "4/3", "x", "", None):
            with self.assertRaises(ValueError):
                module.parse_shard(bad)

    def test_a_prebuilt_binary_is_launched_directly_through_the_clone_runner(self):
        from unittest import mock
        module = self.module()
        with tempfile.TemporaryDirectory(prefix="gofree-prebuilt-") as directory:
            root = Path(directory)
            Preflight.workspace(root)
            fake = root / "fake-test-binary"
            fake.write_text("""#!/bin/sh
echo "argv: $*"
echo "pwd: $PWD"
echo "manifest: $CARGO_MANIFEST_DIR"
echo "runner: ${LANE_RUNNER_SEEN:-no}"
echo "GOLDEN-REPLAY: r :: c"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
""")
            fake.chmod(0o755)
            replay = {"package": "demo", "target": "recorded", "test": "t"}
            captured = []
            real_popen = subprocess.Popen

            def spy(args, *a, **kw):
                captured.append((args, kw.get("cwd")))
                return real_popen(args, *a, **kw)

            package = (root / "server-rust/crates/demo").resolve()
            env = {"CARGO_TARGET_X_RUNNER": "env LANE_RUNNER_SEEN=1"}
            with mock.patch.dict(os.environ, env), mock.patch.object(module.subprocess, "Popen", spy):
                module.run_replay(root, "cargo-unused", replay, "GOLDEN-REPLAY: r :: c", {"demo::recorded": str(fake)})
            args, cwd = captured[0]
            self.assertEqual(args[-3:], ["t", "--exact", "--nocapture"])
            self.assertEqual(args[:2], ["env", "LANE_RUNNER_SEEN=1"])
            self.assertEqual(Path(cwd).resolve(), package)
            with self.assertRaises(ValueError) as caught:
                module.run_replay(root, "cargo-unused", replay, "GOLDEN-REPLAY: r :: c", {})
            self.assertIn("demo::recorded", str(caught.exception))

    def test_the_cli_accepts_a_coverage_only_shard_and_prints_coverage_targets(self):
        flags = ["--skip-preflight", "--cargo", "/nonexistent-cargo"]
        alone = subprocess.run([sys.executable, str(GUARD), *flags, "--coverage"],
                               capture_output=True, text=True, check=False, timeout=120)
        self.assertNotEqual(alone.returncode, 0)
        self.assertIn("requires --execute", alone.stderr)
        sharded = subprocess.run([sys.executable, str(GUARD), *flags, "--coverage", "--shard", "1/2"],
                                 capture_output=True, text=True, check=False, timeout=300)
        self.assertNotIn("requires --execute", sharded.stderr)
        printed = subprocess.run([sys.executable, str(GUARD), "--print-coverage-targets"],
                                 capture_output=True, text=True, check=False, timeout=300)
        self.assertEqual(printed.returncode, 0, printed.stderr)
        tokens = printed.stdout.split()
        self.assertTrue(tokens and all(token in ("-p", "--test") or not token.startswith("-") for token in tokens))
        self.assertIn("setjoin-gateway", tokens)
        self.assertIn("jmap_recorded", tokens)


if __name__ == "__main__":
    unittest.main()
