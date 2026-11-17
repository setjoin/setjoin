#!/usr/bin/env python3
"""Tests for scripts/lane-job-gate.py (mode choice, the aggregate verdict and the merge-queue role). No cargo,
no network: every git call, the clock and the sleep are injected or the CLI is run on a branch that never calls git.
python3 scripts/test-lane-job-gate.py"""
import contextlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("lane-job-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "server-rust-lane.yml"
ALL = ["plan", "debug", "build", "roots", "pgtap", "guards", "shard", "coverage-build", "coverage-shard",
       "gomod-cache", "queue"]


def needs(mode, results=None, debug="false"):
    r = {j: "skipped" for j in ALL}
    r["queue"] = "success"  # queue always runs; plan needs it
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

OWN_REF = "refs/heads/gh-readonly-queue/main/pr-5-aaa"
OWN = "a" * 40
LATER_REF = "refs/heads/gh-readonly-queue/main/pr-6-" + OWN  # name suffix is our sha: a real successor
LATER2_REF = "refs/heads/gh-readonly-queue/main/pr-7-" + OWN
AHEAD_REF = "refs/heads/gh-readonly-queue/main/pr-4-" + "c" * 40
STALE_REF = "refs/heads/gh-readonly-queue/main/pr-1-" + "d" * 40
SETTLE, POLL, CAP = 120, 60, gate.QUEUE_CAP_S


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

    def test_gone_role_only_matters_for_merge_group(self):
        self.assertEqual(gate.mode_for("merge_group", queue_role="gone"), "gone")
        self.assertEqual(gate.mode_for("merge_group", queue_role="head"), "full")
        self.assertEqual(gate.mode_for("push", queue_role="gone"), "cache")
        self.assertEqual(gate.mode_for("schedule", 3, queue_role="gone"), "full")
        self.assertEqual(gate.mode_for("workflow_dispatch", queue_role="gone"), "full")


class Verdict(unittest.TestCase):
    def test_full_green_on_every_event(self):
        for e in ("merge_group", "workflow_dispatch", "schedule"):
            self.assertIsNone(check(needs("full", FULL), e))

    def test_full_red_when_any_required_job_not_success(self):
        for job in FULL:
            for bad in ("failure", "cancelled", "skipped"):
                self.assertIsNotNone(check(needs("full", {**FULL, job: bad}), "merge_group"), (job, bad))

    def test_merge_group_never_passes_vacuously(self):
        for mode in ("cache", "skip", "", "gone"):
            self.assertIsNotNone(check(needs(mode, CACHE), "merge_group"), mode)
            self.assertIsNotNone(check(needs(mode, ok("plan")), "workflow_dispatch"), mode)
        self.assertIsNotNone(check(needs("full", ok("plan")), "merge_group"))  # everything else skipped
        self.assertIsNotNone(check(needs("", {}), "merge_group"))  # plan failed, no outputs

    def test_gone_is_red_even_with_every_other_job_green(self):
        self.assertIsNotNone(check(needs("gone", ok("plan")), "merge_group"))
        self.assertIsNotNone(check(needs("gone", {"plan": "success", "queue": "success"}), "merge_group"))

    def test_queue_failure_or_cancel_is_red(self):
        for bad in ("failure", "cancelled"):
            self.assertIsNotNone(check(needs("full", {**FULL, "queue": bad}), "merge_group"), bad)
            self.assertIsNotNone(check(needs("cache", {**CACHE, "queue": bad}), "push"), bad)

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

    def test_missing_required_entry_is_red(self):
        n = needs("full", FULL)
        del n["guards"]
        self.assertIsNotNone(check(n, "merge_group"))

    def test_debug_dispatch(self):
        self.assertIsNone(check(needs("full", ok("plan", "debug"), debug="true"), "workflow_dispatch"))
        self.assertIsNotNone(check(needs("full", {"plan": "success"}, debug="true"), "workflow_dispatch"))


class QueueRole(unittest.TestCase):
    """queue_role table: own ref OWN_REF at sha OWN, settle 120 s, cap CAP."""

    def role(self, remote, later=frozenset(), waited=200, enabled=True):
        return gate.queue_role(OWN_REF, OWN, remote, later, waited, enabled=enabled, settle_s=SETTLE, cap_s=CAP)

    def test_1_disabled_is_head_even_with_a_later_ref(self):
        self.assertEqual(self.role({OWN_REF: OWN, LATER_REF: OWN}, {LATER_REF}, enabled=False), "head")

    def test_2_own_ref_missing_is_gone(self):
        self.assertEqual(self.role({LATER_REF: OWN}, set()), "gone")

    def test_3_own_ref_at_another_sha_is_gone(self):
        self.assertEqual(self.role({OWN_REF: "b" * 40}, set()), "gone")

    def test_4_inside_settle_without_later_waits(self):
        self.assertEqual(self.role({OWN_REF: OWN}, set(), waited=60), "wait")

    def test_5_only_own_ref_is_head(self):
        self.assertEqual(self.role({OWN_REF: OWN}, set()), "head")

    def test_6_ahead_ref_is_not_later(self):
        self.assertEqual(self.role({OWN_REF: OWN, AHEAD_REF: "c" * 40}, set()), "head")

    def test_7_unrelated_stale_ref_is_not_later(self):
        self.assertEqual(self.role({OWN_REF: OWN, STALE_REF: "d" * 40}, set()), "head")

    def test_8_later_ref_waits(self):
        self.assertEqual(self.role({OWN_REF: OWN, LATER_REF: OWN}, {LATER_REF}), "wait")

    def test_9_later_ref_at_cap_is_head(self):
        self.assertEqual(self.role({OWN_REF: OWN, LATER_REF: OWN}, {LATER_REF}, waited=CAP), "head")

    def test_10_ls_remote_failure_waits_then_heads_at_cap(self):
        self.assertEqual(self.role(None, waited=CAP - 1), "wait")
        self.assertEqual(self.role(None, waited=CAP), "head")

    def test_11_ancestry_failure_waits_then_heads_at_cap(self):
        self.assertEqual(self.role({OWN_REF: OWN}, None, waited=CAP - 1), "wait")
        self.assertEqual(self.role({OWN_REF: OWN}, None, waited=CAP), "head")

    def test_12_gone_wins_over_later(self):
        self.assertEqual(self.role({LATER_REF: OWN}, {LATER_REF}), "gone")


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


class Script:
    """Scripted answers: call k returns items[k-1], the last item repeats; counts calls."""

    def __init__(self, items):
        self.items = list(items)
        self.calls = 0

    def next(self, *_args):
        self.calls += 1
        return self.items[min(self.calls, len(self.items)) - 1]


def drive(remotes, descs=None, *, enabled=True, cap=CAP):
    clock = FakeClock()
    ls = Script(remotes)
    ds = Script(descs if descs is not None else [set()])
    role = gate.wait_for_role(OWN_REF, OWN, enabled=enabled, poll_s=POLL, settle_s=SETTLE, cap_s=cap,
                              ls_remote=ls.next, descendants=ds.next, sleep=clock.sleep, now=clock.now,
                              log=lambda _m: None)
    return role, clock, ls, ds


BOTH = {OWN_REF: OWN, LATER_REF: OWN}
OWN_ONLY = {OWN_REF: OWN}
LATER_ONLY = {LATER_REF: OWN}


class WaitLoop(unittest.TestCase):
    def test_a_later_ref_vanishes_then_head(self):
        # polls at t=0,60,120,180: wait, wait, wait (later seen), head (later gone)
        role, clock, _, ds = drive([OWN_ONLY, OWN_ONLY, BOTH, OWN_ONLY], [{LATER_REF}, set()])
        self.assertEqual(role, "head")
        self.assertEqual(clock.sleeps, [POLL, POLL, POLL])
        self.assertEqual(ds.calls, 2)

    def test_b_own_ref_vanishes_while_waiting_is_gone(self):
        role, clock, _, _ = drive([OWN_ONLY, BOTH, LATER_ONLY], [{LATER_REF}])
        self.assertEqual(role, "gone")
        self.assertEqual(clock.sleeps, [POLL, POLL])

    def test_c_ancestry_runs_only_when_the_sha_set_changes(self):
        base = BOTH
        plus = {**BOTH, LATER2_REF: OWN}
        remotes = [base] * 6 + [plus, OWN_ONLY]
        role, clock, _, ds = drive(remotes, [{LATER_REF}, {LATER_REF, LATER2_REF}, set()])
        self.assertEqual(role, "head")
        self.assertEqual(ds.calls, 3)  # first settled poll, the change, the change back
        self.assertEqual(len(clock.sleeps), 7)

    def test_d_errors_forever_heads_at_cap_before_the_job_timeout(self):
        role, clock, _, _ = drive([None])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, CAP)
        self.assertLess(CAP + 300, gate.QUEUE_JOB_TIMEOUT_S)  # one poll's worst overshoot fits under the timeout

    def test_e_output_is_only_head_or_gone(self):
        outcomes = {
            drive([OWN_ONLY])[0],                                    # head
            drive([OWN_ONLY, BOTH, LATER_ONLY], [{LATER_REF}])[0],   # gone
            drive([None])[0],                                        # head at cap
            drive([OWN_ONLY], enabled=False)[0],                     # head
        }
        self.assertEqual(outcomes, {"head", "gone"})

    def test_f_ancestry_error_then_empty_answer_is_head_without_waiting_to_cap(self):
        # settled at t=120: descendants None -> wait; t=180 same sha set but the last answer was None -> asked again
        role, clock, _, ds = drive([BOTH], [None, set()])
        self.assertEqual(role, "head")
        self.assertEqual(ds.calls, 2)
        self.assertEqual(clock.t, 180)

    def test_disabled_makes_no_git_call(self):
        role, _, ls, ds = drive([BOTH], [{LATER_REF}], enabled=False)
        self.assertEqual(role, "head")
        self.assertEqual((ls.calls, ds.calls), (0, 0))


class QueueRoleCli(unittest.TestCase):
    """The CLI paths that return before any git call, so they stay offline."""

    def run_cli(self, env, argv):
        proc = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("lane-job-gate.py")), *argv],
                              env=env, capture_output=True, text=True, timeout=60, check=False)
        return proc.returncode, proc.stdout

    def test_push_prints_head_without_git(self):
        rc, out = self.run_cli({"EVENT": "push", "BATCHING": "1", "OWN_REF": OWN_REF, "OWN_SHA": OWN,
                                "REPO": "x/y"}, ["queue-role"])
        self.assertEqual((rc, out), (0, "head\n"))

    def test_merge_group_with_switch_unset_prints_head(self):
        rc, out = self.run_cli({"EVENT": "merge_group", "OWN_REF": OWN_REF, "OWN_SHA": OWN, "REPO": "x/y"},
                               ["queue-role"])
        self.assertEqual((rc, out), (0, "head\n"))

    def test_mode_reads_queue_role_from_env(self):
        rc, out = self.run_cli({"EVENT": "merge_group", "QUEUE_ROLE": "gone"}, ["mode", "merge_group"])
        self.assertEqual((rc, out), (0, "gone\n"))
        rc, out = self.run_cli({"EVENT": "merge_group", "QUEUE_ROLE": ""}, ["mode", "merge_group"])
        self.assertEqual((rc, out), (0, "full\n"))


class WorkflowWiring(unittest.TestCase):
    def test_queue_job_timeout_matches_the_gate_constant(self):
        text = WORKFLOW.read_text()
        block = text.split("\n  queue:\n", 1)[1].split("\n  plan:\n", 1)[0]
        minutes = int(re.search(r"timeout-minutes: (\d+)", block).group(1))
        self.assertEqual(minutes * 60, gate.QUEUE_JOB_TIMEOUT_S)
        self.assertLess(gate.QUEUE_CAP_S + 300, minutes * 60)


if __name__ == "__main__":
    unittest.main()
