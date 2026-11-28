#!/usr/bin/env python3
"""Unit tests for scripts/ci/lane-shard-plan.py.

python3 scripts/ci/test-lane-shard-plan.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("lane-shard-plan.py")
ROOT = Path(__file__).resolve().parents[2]


def load_planner():
    spec = importlib.util.spec_from_file_location("lane_shard_plan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_suite(listener, method, path, family, command, cases):
    route_name = f"{method} {path}" + (f" {command}" if command else "")
    suite = {
        "listener": listener,
        "method": method,
        "path": path,
        "family": family,
        "cases": [
            {"replay": {"package": pkg, "target": tgt, "test": test}}
            for pkg, tgt, test in cases
        ],
    }
    if command:
        suite["command"] = command
    return route_name, suite


class LaneShardPlanUnit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_planner()

    def test_partition_exactness_and_shared_components(self):
        # Entries 0, 1, 2 form one connected component via shared tests t_shared_01 and t_shared_12.
        # Entries 3 and 4 have the SAME route_name ("GET /health") on different listeners (auth vs gateway).
        suites = [
            make_suite("gateway", "POST", "/a", "F1", "", [("pkg", "s1", "a_ok"), ("pkg", "s1", "t_shared_01")]),
            make_suite("gateway", "POST", "/b", "F1", "", [("pkg", "s1", "t_shared_01"), ("pkg", "s1", "t_shared_12")]),
            make_suite("gateway", "POST", "/c", "F1", "", [("pkg", "s1", "t_shared_12"), ("pkg", "s2", "c_err")]),
            make_suite("auth", "GET", "/health", "F2", "", [("auth", "s1", "auth_health")]),
            make_suite("gateway", "GET", "/health", "F2", "", [("gw", "s1", "gw_health")]),
            make_suite("gateway", "POST", "/jmap", "F3", "Mail/get", [("gw", "jmap", "m1"), ("gw", "jmap", "m2")]),
            make_suite("gateway", "POST", "/jmap", "F3", "Mail/set", [("gw", "jmap", "m3"), ("gw", "jmap", "m4")]),
        ]
        all_tests = {
            (f"{c['replay']['package']}::{c['replay']['target']}", c["replay"]["test"])
            for _, s in suites
            for c in s["cases"]
        }
        # Add 30 non-coverage tests across multiple binaries.
        for i in range(30):
            all_tests.add((f"unit::bin{i % 4}", f"mod::test_{i}"))

        num_shards = 4
        plan = self.mod.plan_shards(all_tests, suites, num_shards)

        # Union of shard tests == exact all_tests (0 missing, 0 duplicates).
        seen_tests = []
        for s_tests in plan["shard_tests"]:
            seen_tests.extend(s_tests)
        self.assertEqual(len(seen_tests), len(all_tests))
        self.assertEqual(set(seen_tests), all_tests)

        # Union of shard coverage entries == exact 0..len(suites)-1 (0 missing, 0 duplicates).
        seen_eids = []
        for s_eids in plan["shard_eids"]:
            seen_eids.extend(s_eids)
        self.assertEqual(len(seen_eids), len(suites))
        self.assertEqual(set(seen_eids), set(range(len(suites))))

        # Entries 0, 1, 2 share tests -> MUST land on the exact same shard!
        shard_of_eid = {eid: s for s, eids in enumerate(plan["shard_eids"]) for eid in eids}
        self.assertEqual(shard_of_eid[0], shard_of_eid[1])
        self.assertEqual(shard_of_eid[1], shard_of_eid[2])

        # Every coverage entry's cases are 100% contained in the entry's own shard.
        for eid, (_, suite) in enumerate(suites):
            s = shard_of_eid[eid]
            for c in suite["cases"]:
                key = (f"{c['replay']['package']}::{c['replay']['target']}", c["replay"]["test"])
                self.assertIn(key, plan["shard_tests"][s])

        # Total tests per shard are balanced within +/- 1.
        counts = [len(s) for s in plan["shard_tests"]]
        self.assertLessEqual(max(counts) - min(counts), 1)

        # Same route_name on auth vs gateway stay distinct entries (3 and 4).
        with tempfile.TemporaryDirectory(prefix="shard-plan-") as d:
            all_entries_emitted = []
            all_tsv_rows = []
            for k in range(1, num_shards + 1):
                sub = Path(d) / f"s{k}"
                self.mod.write_shard_outputs(sub, k, num_shards, plan, suites, "deadbeef")
                toml_text = (sub / "shard-filter.toml").read_text()
                self.assertIn("[profile.lane]", toml_text)
                self.assertIn("default-filter = '''", toml_text)
                entries_doc = json.loads((sub / "shard-coverage-entries.json").read_text())
                self.assertEqual(entries_doc["shard"], f"{k}/{num_shards}")
                self.assertEqual(entries_doc["manifest_hash"], "deadbeef")
                all_entries_emitted.extend(entries_doc["entries"])
                for line in (sub / "coverage-cases.tsv").read_text().splitlines():
                    all_tsv_rows.append(line.split("\t"))
            self.assertEqual(sorted(e["entry_idx"] for e in all_entries_emitted), list(range(len(suites))))
            health_entries = [e for e in all_entries_emitted if e["route_name"] == "GET /health"]
            self.assertEqual(sorted(e["key"]["listener"] for e in health_entries), ["auth", "gateway"])
            # Shared test t_shared_01 maps to both 0 and 1 on a single shard.
            shared_rows = [r for r in all_tsv_rows if r[1] == "t_shared_01"]
            self.assertEqual(len(shared_rows), 1)
            self.assertEqual(shared_rows[0][2], "0,1")

    def test_missing_coverage_case_fails_closed(self):
        suites = [make_suite("gateway", "GET", "/x", "F1", "", [("pkg", "s1", "missing_test")])]
        with self.assertRaises(ValueError) as ctx:
            self.mod.plan_shards({("pkg::s1", "other_test")}, suites, 2)
        self.assertIn("absent from lane-list.json", str(ctx.exception))

    def test_regex_escaping_and_chunking(self):
        tests = {("pkg::bin", f"mod::test_{i}") for i in range(self.mod.REGEX_CHUNK_SIZE + 5)}
        tests.add(("pkg::bin", "mod::a+b.c(d)[e]/f"))
        toml_text = self.mod.build_filter_toml(tests, "1/2")
        self.assertIn(r"mod::a\+b\.c\(d\)\[e\]\/f", toml_text)
        # Should split into 2 regex chunks for > REGEX_CHUNK_SIZE tests in one binary.
        self.assertEqual(len(re.findall(r"test\(/\^\(\?:", toml_text)), 2)

    def test_real_manifest_synthetic_lane_list_all_1096_entries(self):
        """Exercise the real repository manifest (1,096 coverage entries) with a synthetic lane-list
        containing all real coverage cases plus 13,000 non-coverage tests."""
        adequacy = self.mod.load_adequacy_module(ROOT)
        inv = json.loads((ROOT / "server/bins/gateway/route-inventory.json").read_text())
        cat = json.loads((ROOT / "server/tests/conformance/route-catalog.json").read_text())
        _, suites = adequacy.check(ROOT, inv, cat)
        self.assertGreaterEqual(len(suites), 1096)

        rust_suites = {}
        for _, suite in suites:
            for c in suite["cases"]:
                b = f"{c['replay']['package']}::{c['replay']['target']}"
                rust_suites.setdefault(b, {"testcases": {}})["testcases"][c["replay"]["test"]] = {}
        for i in range(13000):
            b = f"unit-crate-{i % 20}::lib"
            rust_suites.setdefault(b, {"testcases": {}})["testcases"][f"unit::case_{i}"] = {}

        with tempfile.TemporaryDirectory(prefix="shard-plan-real-") as d:
            lane_list = Path(d) / "lane-list.json"
            lane_list.write_text(json.dumps({"rust-suites": rust_suites}))
            res = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(ROOT), "--lane-list", str(lane_list),
                 "--shards", "8", "--validate"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("lane-shard-plan validate OK", res.stdout)
            self.assertIn("spread=1", res.stdout)

            # Emit all 8 shards and verify disjoint union of entries & tests across files.
            seen_entries = []
            seen_cov_cases = set()
            for k in range(1, 9):
                out_dir = Path(d) / f"shard-{k}"
                r = subprocess.run(
                    [sys.executable, str(SCRIPT), "--root", str(ROOT), "--lane-list", str(lane_list),
                     "--shard", f"{k}/8", "--out-dir", str(out_dir)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                entries_doc = json.loads((out_dir / "shard-coverage-entries.json").read_text())
                seen_entries.extend(e["entry_idx"] for e in entries_doc["entries"])
                for line in (out_dir / "coverage-cases.tsv").read_text().splitlines():
                    b, t, _ = line.split("\t")
                    self.assertNotIn((b, t), seen_cov_cases)
                    seen_cov_cases.add((b, t))
            self.assertEqual(sorted(seen_entries), list(range(len(suites))))


if __name__ == "__main__":
    unittest.main()
