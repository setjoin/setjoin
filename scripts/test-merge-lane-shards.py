#!/usr/bin/env python3
"""Tests for scripts/merge-lane-shards.py: the hosted lane's completeness verdict, run on a
synthetic results tree (no cargo, no database).  python3 scripts/test-merge-lane-shards.py"""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("merge-lane-shards.py")
LIST = {"rust-suites": {
    "a::x": {"testcases": {"t1": {}, "t2": {}, "skipme": {"ignored": True}}},
    "b::y": {"testcases": {"t1": {}, "t2": {}}},
}}


REPLAYS = [f"r{i}" for i in range(10)]
COVERAGE = ["c0", "c1", "c2"]
HASH = "h" * 8


def receipt(shard, replays=(), coverage=(), manifest_hash=HASH):
    return {"shard": shard, "manifest_hash": manifest_hash, "replays": list(replays), "coverage": list(coverage)}


def junit(cases, failed=()):
    rows = []
    for binary, name in cases:
        body = "<failure/>" if (binary, name) in failed else ""
        rows.append(f'<testcase classname="{binary}" name="{name}">{body}</testcase>')
    return "<testsuites><testsuite>" + "".join(rows) + "</testsuite></testsuites>"


class MergeLaneShards(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("merge_lane_shards", SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.tmp = tempfile.TemporaryDirectory(prefix="merge-lane-shards-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.results = self.root / "results"
        self.list = self.root / "lane-list.json"
        self.list.write_text(json.dumps(LIST))
        self.make("lane-result-roots")
        self.make("lane-result-shard-1", junit([("a::x", "t1"), ("a::x", "t2")]), "replay summary: 6 passed, 0 failed\n",
                  receipt=receipt("1/2", REPLAYS[:6]))
        self.make("lane-result-shard-2", junit([("b::y", "t1"), ("b::y", "t2")]), "replay summary: 4 passed, 0 failed\n",
                  receipt=receipt("2/2", REPLAYS[6:]))
        self.make("lane-result-coverage-1", None, "coverage summary: 2 entries measured\n",
                  receipt=receipt("1/2", coverage=COVERAGE[:2]))
        self.make("lane-result-coverage-2", None, "coverage summary: 1 entries measured\n",
                  receipt=receipt("2/2", coverage=COVERAGE[2:]))

    def make(self, name, junit_text=None, log="", rc="rc=0\n", receipt=None):
        directory = self.results / name
        directory.mkdir(parents=True, exist_ok=True)
        if receipt is not None:
            (directory / "adequacy-receipt.json").write_text(json.dumps(receipt))
        if rc is not None:
            (directory / "lane-complete.txt").write_text(rc)
        (directory / "lane.log").write_text(log)
        if junit_text is not None:
            (directory / "junit.xml").write_text(junit_text)

    def run_merge(self, coverage=True):
        argv = ["merge-lane-shards.py", "--list", str(self.list), "--results", str(self.results), "--shards", "2"]
        if coverage:
            argv += ["--coverage-shards", "2"]
        out, code = io.StringIO(), 0
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.module, "manifest", lambda: {"replays": REPLAYS, "coverage": COVERAGE, "hash": HASH}), \
                contextlib.redirect_stdout(out):
            try:
                self.module.main()
            except SystemExit as error:
                code = error.code if isinstance(error.code, int) else 1
        return code, out.getvalue()

    def test_a_complete_run_is_green(self):
        code, out = self.run_merge()
        self.assertEqual(code, 0, out)
        self.assertIn("coverage complete", out)

    def test_a_test_that_never_ran_is_red(self):
        self.make("lane-result-shard-2", junit([("b::y", "t1")]), "replay summary: 4 passed, 0 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("never ran", out)

    def test_a_test_in_two_shards_is_red(self):
        self.make("lane-result-shard-2", junit([("b::y", "t1"), ("b::y", "t2"), ("a::x", "t1")]), "replay summary: 4 passed, 0 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("ran twice", out)

    def test_a_failure_is_red(self):
        self.make("lane-result-shard-1", junit([("a::x", "t1"), ("a::x", "t2")], failed={("a::x", "t2")}),
                  "replay summary: 6 passed, 0 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("failed", out)

    def test_a_db_skip_marker_is_red(self):
        self.make("lane-result-shard-1", junit([("a::x", "t1"), ("a::x", "t2")]),
                  "SETJOIN-PG-DB-SKIP (reason=no-dsn) test=x\nreplay summary: 6 passed, 0 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("skip marker", out)

    def test_a_shard_without_its_receipt_is_red(self):
        (self.results / "lane-result-shard-2" / "lane-complete.txt").unlink()
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("did not finish", out)

    def test_a_nonzero_receipt_is_red(self):
        self.make("lane-result-roots", rc="rc=1\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("lane-result-roots: rc=1", out)

    def test_replays_that_do_not_add_up_to_the_manifest_are_red(self):
        self.make("lane-result-shard-2", junit([("b::y", "t1"), ("b::y", "t2")]), "replay summary: 3 passed, 0 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("replays:", out)

    def test_a_failed_replay_is_red(self):
        self.make("lane-result-shard-2", junit([("b::y", "t1"), ("b::y", "t2")]), "replay summary: 3 passed, 1 failed\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("1 failed", out)

    def test_coverage_that_does_not_add_up_to_the_entries_is_red(self):
        self.make("lane-result-coverage-2", None, "coverage summary: 0 entries measured\n")
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("coverage:", out)

    def test_a_missing_coverage_shard_is_red(self):
        (self.results / "lane-result-coverage-2" / "lane-complete.txt").unlink()
        code, out = self.run_merge()
        self.assertEqual(code, 1)
        self.assertIn("lane-result-coverage-2: did not finish", out)

    def test_a_duplicate_slice_hiding_a_missing_one_is_red(self):
        # shard 2 re-ran shard 1's slice: the counts still add up to 10, one slice never ran
        self.make("lane-result-shard-2", junit([("b::y", "t1"), ("b::y", "t2")]), "replay summary: 4 passed, 0 failed\n",
                  receipt=receipt("2/2", REPLAYS[:4]))
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("never ran", out)
        self.assertIn("ran twice", out)

    def test_duplicate_coverage_routes_are_red(self):
        self.make("lane-result-coverage-2", None, "coverage summary: 1 entries measured\n",
                  receipt=receipt("2/2", coverage=["c0"]))
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("coverage entries", out)

    def test_an_empty_inventory_is_red(self):
        self.list.write_text(json.dumps({"rust-suites": {}}))
        for name in ("lane-result-shard-1", "lane-result-shard-2"):
            (self.results / name / "junit.xml").write_text("<testsuites/>")
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("empty", out)

    def test_zero_executed_tests_are_red(self):
        for name in ("lane-result-shard-1", "lane-result-shard-2"):
            (self.results / name / "junit.xml").write_text("<testsuites/>")
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("no test executed", out)

    def test_a_receipt_with_the_wrong_manifest_hash_is_red(self):
        self.make("lane-result-shard-1", junit([("a::x", "t1"), ("a::x", "t2")]), "replay summary: 6 passed, 0 failed\n",
                  receipt=receipt("1/2", REPLAYS[:6], manifest_hash="stale"))
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("manifest hash", out)

    def test_a_receipt_for_another_shard_selector_is_red(self):
        self.make("lane-result-shard-1", junit([("a::x", "t1"), ("a::x", "t2")]), "replay summary: 6 passed, 0 failed\n",
                  receipt=receipt("2/2", REPLAYS[:6]))
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("selector", out)

    def test_a_missing_shard_receipt_is_red(self):
        (self.results / "lane-result-shard-2" / "adequacy-receipt.json").unlink()
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("lane-result-shard-2: no adequacy receipt", out)

    def test_a_missing_coverage_receipt_is_red(self):
        (self.results / "lane-result-coverage-1" / "adequacy-receipt.json").unlink()
        code, out = self.run_merge()
        self.assertEqual(code, 1, out)
        self.assertIn("lane-result-coverage-1: no adequacy receipt", out)


if __name__ == "__main__":
    unittest.main()
