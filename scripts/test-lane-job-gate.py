#!/usr/bin/env python3
"""Tests for scripts/lane-job-gate.py (mode choice and the aggregate verdict). No cargo, no network.
python3 scripts/test-lane-job-gate.py"""
import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("lane-job-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

ALL = ["plan", "debug", "build", "roots", "pgtap", "guards", "shard", "coverage-build", "coverage-shard", "gomod-cache"]


def needs(mode, results=None, debug="false"):
    r = {j: "skipped" for j in ALL}
    r.update(results or {})
    out = {j: {"result": v, "outputs": {}} for j, v in r.items()}
    out["plan"]["outputs"] = {"mode": mode, "debug": debug}
    return out


def ok(*jobs):
    return {j: "success" for j in jobs}


def check(n, event):
    with contextlib.redirect_stdout(io.StringIO()):
        return gate.verdict(n, event)


FULL = ok("plan", "build", "roots", "pgtap", "guards", "shard", "coverage-build", "coverage-shard")
CACHE = ok("plan", "build", "coverage-build", "gomod-cache")


class Mode(unittest.TestCase):
    def test_modes(self):
        self.assertEqual(gate.mode_for("push"), "cache")
        self.assertEqual(gate.mode_for("schedule", 3), "full")
        self.assertEqual(gate.mode_for("schedule", 0), "skip")
        for e in ("merge_group", "workflow_dispatch"):
            self.assertEqual(gate.mode_for(e), "full")

    def test_schedule_without_count_is_an_error_not_skip(self):
        with self.assertRaises(ValueError):
            gate.mode_for("schedule")


class Verdict(unittest.TestCase):
    def test_full_green_on_every_event(self):
        for e in ("merge_group", "workflow_dispatch", "schedule"):
            self.assertIsNone(check(needs("full", FULL), e))

    def test_full_red_when_any_required_job_not_success(self):
        for job in FULL:
            for bad in ("failure", "cancelled", "skipped"):
                self.assertIsNotNone(check(needs("full", {**FULL, job: bad}), "merge_group"), (job, bad))

    def test_merge_group_never_passes_vacuously(self):
        for mode in ("cache", "skip", ""):
            self.assertIsNotNone(check(needs(mode, CACHE), "merge_group"), mode)
            self.assertIsNotNone(check(needs(mode, ok("plan")), "workflow_dispatch"), mode)
        self.assertIsNotNone(check(needs("full", ok("plan")), "merge_group"))  # everything else skipped
        self.assertIsNotNone(check(needs("", {}), "merge_group"))  # plan failed, no outputs

    def test_push_cache(self):
        self.assertIsNone(check(needs("cache", CACHE), "push"))
        for job in CACHE:
            self.assertIsNotNone(check(needs("cache", {**CACHE, job: "failure"}), "push"), job)
            self.assertIsNotNone(check(needs("cache", {**CACHE, job: "skipped"}), "push"), job)
        self.assertIsNotNone(check(needs("full", FULL), "push"))  # a push must never plan the full lane
        self.assertIsNotNone(check(needs("skip", ok("plan")), "push"))

    def test_test_job_failure_is_red_even_in_cache_mode(self):
        self.assertIsNotNone(check(needs("cache", {**CACHE, "shard": "failure"}), "push"))

    def test_schedule_skip(self):
        self.assertIsNone(check(needs("skip", ok("plan")), "schedule"))
        self.assertIsNotNone(check(needs("skip", {"plan": "failure"}), "schedule"))
        self.assertIsNotNone(check(needs("skip", {**ok("plan"), "build": "failure"}), "schedule"))
        self.assertIsNotNone(check(needs("cache", CACHE), "schedule"))

    def test_debug_dispatch(self):
        self.assertIsNone(check(needs("full", ok("plan", "debug"), debug="true"), "workflow_dispatch"))
        self.assertIsNotNone(check(needs("full", {"plan": "success"}, debug="true"), "workflow_dispatch"))


if __name__ == "__main__":
    unittest.main()
