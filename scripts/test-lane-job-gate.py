#!/usr/bin/env python3
"""Tests for scripts/lane-job-gate.py (mode choice, the aggregate verdict and the merge-queue role). No cargo,
no network: the role logic gets injected git, clock and sleep; the real git functions run only against local
file:// fixtures in a temp dir; the CLI runs only on paths that never call git.
python3 scripts/test-lane-job-gate.py"""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

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
        self.lines = []  # every log line the loop wrote
        self.failed = None  # the scripted failed_later, set by drive

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


def drive(remotes, descs=None, *, enabled=True, cap=CAP, fails=None):
    clock = FakeClock()
    ls = Script(remotes)
    ds = Script(descs if descs is not None else [set()])
    fs = Script(fails if fails is not None else [{}])
    clock.failed = fs
    role = gate.wait_for_role(OWN_REF, OWN, enabled=enabled, poll_s=POLL, settle_s=SETTLE, cap_s=cap,
                              ls_remote=ls.next, descendants=ds.next, failed_later=fs.next, sleep=clock.sleep,
                              now=clock.now, log=clock.lines.append)
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
        self.assertLess(CAP + gate.QUEUE_POLL_WORST_IO_S + gate.QUEUE_SETUP_MARGIN_S, gate.QUEUE_JOB_TIMEOUT_S)

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


LATER_SHA = "b" * 40
LATER2_SHA = "c" * 40
BOTH_REAL = {OWN_REF: OWN, LATER_REF: LATER_SHA}  # a later ref's head is its own sha, not ours
TWO_LATER = {OWN_REF: OWN, LATER_REF: LATER_SHA, LATER2_REF: LATER2_SHA}


class FailedLaterLoop(unittest.TestCase):
    """A later ref whose merge_group lane run failed does not count as later (failed_later answers per sha)."""

    def waits(self, clock):
        return [line for line in clock.lines if "queue-role=wait" in line]

    def test_1_failed_later_run_is_excluded_so_the_role_is_head(self):
        role, clock, _, ds = drive([BOTH_REAL], [{LATER_REF}], fails=[{LATER_SHA: "failure"}])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, SETTLE)  # the first settled poll decides
        self.assertEqual(clock.sleeps, [POLL, POLL])
        self.assertIn(f"excluded_failed=[{LATER_REF} sha={LATER_SHA} conclusion=failure]", clock.lines[-1])

    def test_2_failed_plus_in_progress_the_in_progress_one_still_counts(self):
        role, clock, _, _ = drive([TWO_LATER], [{LATER_REF, LATER2_REF}], fails=[{LATER_SHA: "failure"}])
        self.assertEqual(role, "head")  # only at the cap: the in-progress later ref keeps us waiting
        self.assertEqual(clock.t, CAP)
        self.assertEqual(len(self.waits(clock)), len(clock.lines))  # the cap exit logs nothing: all lines wait
        self.assertFalse(any(f"sha={LATER2_SHA} conclusion" in line for line in clock.lines))
        self.assertIn(f"excluded_failed=[{LATER_REF} sha={LATER_SHA} conclusion=failure]", clock.lines[-1])

    def test_3_unknown_failed_answer_keeps_waiting_until_the_cap(self):
        role, clock, _, _ = drive([BOTH_REAL], [{LATER_REF}], fails=[None])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, CAP)
        self.assertEqual(len(self.waits(clock)), len(clock.lines))  # the cap exit logs nothing: all lines wait
        self.assertTrue(all("failed_later=unknown" in line for line in clock.lines[2:]))
        self.assertTrue(all("excluded_failed=[]" in line for line in clock.lines))

    def test_4_cancelled_counts_as_failed_and_success_does_not(self):
        role, clock, _, _ = drive([BOTH_REAL], [{LATER_REF}], fails=[{LATER_SHA: "cancelled"}])
        self.assertEqual((role, clock.t), ("head", SETTLE))
        # a later run that succeeded is not in the failed map: it stays later, so we wait to the cap
        role, clock, _, _ = drive([BOTH_REAL], [{LATER_REF}], fails=[{}])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, CAP)
        self.assertEqual(len(self.waits(clock)), len(clock.lines))  # the cap exit logs nothing: all lines wait

    def test_5_in_progress_then_failure_on_the_third_poll(self):
        # poll at t=120 (settled): in progress -> wait; t=180: still in progress -> wait; t=240: failure -> head
        role, clock, _, ds = drive([BOTH_REAL], [{LATER_REF}],
                                   fails=[{}, {}, {LATER_SHA: "failure"}])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, 240)
        self.assertEqual(len(self.waits(clock)), 4)  # t=0 and t=60 before the settle, then t=120 and t=180
        self.assertEqual(clock.failed.calls, 3)  # asked on every poll that has later refs
        self.assertEqual(ds.calls, 1)  # the sha set did not change, so the ancestry was not asked again

    def test_6_unknown_ancestry_waits_to_the_cap_even_when_a_run_failed(self):
        # ancestry unknown (None): the failed answer cannot make a later ref disappear, so only the cap ends the wait
        role, clock, _, _ = drive([BOTH_REAL], [None], fails=[{LATER_SHA: "failure"}])
        self.assertEqual(role, "head")
        self.assertEqual(clock.t, CAP)


class Done:
    """What subprocess.run returns for the curl lookup: exit code and stdout."""

    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def api_body(*runs):
    return json.dumps({"total_count": len(runs), "workflow_runs": list(runs)})


def api_run(run_id, sha, status, conclusion=None):
    return {"id": run_id, "head_sha": sha, "status": status, "conclusion": conclusion}


def fake_api(answers, calls, clock=None, worst=False):
    """run_cmd stand-in for subprocess.run. answers maps head_sha -> stdout text (a curl exit code as an int, or an
    exception to raise); an unknown sha gets no runs. Each call records (argv, kwargs); with a clock it also advances
    the clock by the timeout (worst case). No process is started."""

    def run_cmd(argv, **kw):
        calls.append((argv, kw))
        if clock is not None:
            clock.t += kw["timeout"] if worst else 1
        sha = parse_qs(urlsplit(argv[-1]).query)["head_sha"][0]
        answer = answers.get(sha, api_body())
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, int):
            return Done("", answer)
        return Done(answer)

    return run_cmd


class FailedLaterApi(unittest.TestCase):
    """gate.failed_later_from_api over an injected subprocess.run stand-in: no network, no process, no sleeping."""

    S = "d" * 40
    T = "e" * 40
    REPO = "setjoin/setjoin"
    TOKEN = "ghs_TEST_ONLY_TOKEN"

    def call(self, shas, answers=None, may_start=lambda: True):
        calls = []
        out = gate.failed_later_from_api(shas, may_start, repo=self.REPO, token=self.TOKEN,
                                         run_cmd=fake_api(answers or {}, calls))
        return out, calls

    def test_request_shape_timeouts_and_headers_on_stdin(self):
        out, calls = self.call([self.S])
        self.assertEqual(out, {})
        self.assertEqual(len(calls), 1)
        argv, kw = calls[0]
        self.assertEqual(argv[0], "curl")
        self.assertEqual(argv[-1], "https://api.github.com/repos/setjoin/setjoin/actions/workflows/"
                                   f"server-rust-lane.yml/runs?event=merge_group&head_sha={self.S}&per_page=5")
        self.assertIn("--fail", argv)
        self.assertEqual(argv[argv.index("--max-time") + 1], "12")
        self.assertEqual(argv[argv.index("-H") + 1], "@-")
        self.assertEqual(kw["timeout"], 15)
        self.assertEqual((gate.QUEUE_RUN_LOOKUP_TIMEOUT_S, gate.QUEUE_RUN_CURL_MAX_TIME_S), (15, 12))
        self.assertTrue(kw["capture_output"])
        self.assertIn("Authorization: Bearer " + self.TOKEN + "\n", kw["input"])
        self.assertIn("Accept: application/vnd.github+json\n", kw["input"])
        self.assertIn("X-GitHub-Api-Version: 2022-11-28\n", kw["input"])

    def test_token_is_in_stdin_never_in_argv(self):
        _, calls = self.call([self.S, self.T])
        for argv, kw in calls:
            self.assertNotIn(self.TOKEN, " ".join(argv))
            self.assertIn(self.TOKEN, kw["input"])
        self.assertNotIn("Authorization", " ".join(a for argv, _ in calls for a in argv))

    def test_newest_run_by_id_decides(self):
        out, _ = self.call([self.S], {self.S: api_body(api_run(10, self.S, "completed", "failure"),
                                                       api_run(12, self.S, "completed", "success"),
                                                       api_run(11, self.S, "completed", "failure"))})
        self.assertEqual(out, {})  # run 12 succeeded and is the newest
        out, _ = self.call([self.S], {self.S: api_body(api_run(10, self.S, "completed", "success"),
                                                       api_run(12, self.S, "completed", "failure"),
                                                       api_run(11, self.S, "completed", "success"))})
        self.assertEqual(out, {self.S: "failure"})

    def test_completed_non_success_is_in_the_failed_map(self):
        for conclusion in ("failure", "cancelled", "timed_out"):
            out, _ = self.call([self.S], {self.S: api_body(api_run(7, self.S, "completed", conclusion))})
            self.assertEqual(out, {self.S: conclusion})

    def test_in_progress_queued_and_missing_are_not_failed(self):
        for status in ("in_progress", "queued", "waiting"):
            out, _ = self.call([self.S], {self.S: api_body(api_run(7, self.S, status, None))})
            self.assertEqual(out, {}, status)
        out, _ = self.call([self.S], {self.S: api_body()})  # no run for this sha at all
        self.assertEqual(out, {})

    def test_success_is_not_failed(self):
        out, _ = self.call([self.S], {self.S: api_body(api_run(7, self.S, "completed", "success"))})
        self.assertEqual(out, {})

    def test_runs_for_another_head_sha_do_not_count(self):
        out, _ = self.call([self.S], {self.S: api_body(api_run(7, self.T, "completed", "failure"))})
        self.assertEqual(out, {})

    def test_one_request_per_sha(self):
        out, calls = self.call([self.S, self.T], {self.T: api_body(api_run(9, self.T, "completed", "failure"))})
        self.assertEqual(out, {self.T: "failure"})
        self.assertEqual(len(calls), 2)

    def test_nonzero_curl_exit_is_unknown(self):
        self.assertIsNone(self.call([self.S], {self.S: 22})[0])  # --fail: HTTP 403/5xx
        self.assertIsNone(self.call([self.S], {self.S: 6})[0])   # could not resolve host

    def test_timeout_is_unknown_and_no_further_request_starts(self):
        # the hard bound: subprocess.run raises TimeoutExpired after killing the child
        expired = subprocess.TimeoutExpired(cmd="curl", timeout=15)
        out, calls = self.call([self.S, self.T], {self.S: expired})
        self.assertIsNone(out)
        self.assertEqual(len(calls), 1)

    def test_os_error_is_unknown(self):
        self.assertIsNone(self.call([self.S], {self.S: FileNotFoundError("curl")})[0])

    def test_bad_json_and_bad_shape_are_unknown(self):
        self.assertIsNone(self.call([self.S], {self.S: "not json"})[0])
        self.assertIsNone(self.call([self.S], {self.S: '{"workflow_runs": [{"id": 1}]}'})[0])  # no head_sha
        self.assertIsNone(self.call([self.S], {self.S: "[]"})[0])  # not an object

    def test_one_failing_sha_makes_the_whole_answer_unknown(self):
        out, calls = self.call([self.S, self.T], {self.S: api_body(api_run(7, self.S, "completed", "failure")),
                                                  self.T: 22})
        self.assertIsNone(out)  # never a partial map: the caller would keep the rest as later
        self.assertEqual(len(calls), 2)

    def test_past_the_deadline_returns_unknown_and_starts_nothing(self):
        out, calls = self.call([self.S], may_start=lambda: False)
        self.assertEqual((out, calls), (None, []))

    def test_deadline_is_checked_before_each_request(self):
        answers = iter([True, False])
        out, calls = self.call([self.S, self.T], may_start=lambda: next(answers))
        self.assertIsNone(out)
        self.assertEqual(len(calls), 1)

    def test_no_shas_no_request(self):
        self.assertEqual(self.call([])[0], {})
        self.assertEqual(self.call([])[1], [])


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
        # the token is present but must not be used: the switch is off, so no API and no git call
        rc, out = self.run_cli({"EVENT": "merge_group", "OWN_REF": OWN_REF, "OWN_SHA": OWN, "REPO": "x/y",
                                "GH_TOKEN": "unused"}, ["queue-role"])
        self.assertEqual((rc, out), (0, "head\n"))

    def test_mode_reads_queue_role_from_env(self):
        rc, out = self.run_cli({"EVENT": "merge_group", "QUEUE_ROLE": "gone"}, ["mode", "merge_group"])
        self.assertEqual((rc, out), (0, "gone\n"))
        rc, out = self.run_cli({"EVENT": "merge_group", "QUEUE_ROLE": ""}, ["mode", "merge_group"])
        self.assertEqual((rc, out), (0, "full\n"))


GIT_OUT = {"init": "", "fetch": "", "cat-file": "", "for-each-ref": f"refs/q/pr-6-{OWN}\n"}


def fake_git(clock, starts, worst, out=GIT_OUT):
    """Stands in for gate._git: each command is modelled on its own. It starts at the clock, takes its full timeout
    (worst) or 1 s, and answers like git would. Subcommand is args[0], or args[2] after `-C <dir>`."""

    def run(args, timeout):
        kind = args[2] if args[0] == "-C" else args[0]
        starts.append((kind, clock.t))
        clock.t += timeout if worst else 1
        return out.get(kind)

    return run


class WorstCaseTiming(unittest.TestCase):
    """Each git subprocess and each ls-remote advances the fake clock and records its start. The production
    wait_for_role and descendants_of run unchanged on top of them."""

    def test_no_subprocess_starts_at_or_after_cap_and_return_is_within_worst_io(self):
        # MAX_BATCH later refs per poll, each with a failed-run lookup (the production function, its subprocess.run faked):
        # every git command and every lookup is charged its full timeout when worst, and a fresh stale ref each poll
        # makes the ancestry check run every poll.
        later = {f"{gate.QUEUE_REF_PREFIX}pr-{k}-{k:040x}": f"{k:040x}" for k in range(6, 6 + gate.QUEUE_MAX_BATCH)}
        listed = "".join(f"refs/q/{ref[len(gate.QUEUE_REF_PREFIX):]}\n" for ref in later)
        for poll in (45, 60, 77):
            for worst in (True, False):
                clock, starts, nonce = FakeClock(), [], [0]

                def ls():
                    starts.append(("ls-remote", clock.t))
                    clock.t += gate.QUEUE_LS_REMOTE_TIMEOUT_S if worst else 1
                    nonce[0] += 1
                    return {OWN_REF: OWN, **later, f"{gate.QUEUE_REF_PREFIX}pr-9-{nonce[0]}": "e" * 40}

                def lookup(argv, **kw):
                    starts.append(("run-lookup", clock.t))
                    clock.t += kw["timeout"] if worst else 1
                    return Done(api_body())  # no run anywhere: nothing failed, every later ref stays

                out = {**GIT_OUT, "for-each-ref": listed}
                with mock.patch.object(gate, "_git", fake_git(clock, starts, worst, out)):
                    role = gate.wait_for_role(
                        OWN_REF, OWN, enabled=True, poll_s=poll, settle_s=SETTLE, cap_s=CAP, ls_remote=ls,
                        descendants=lambda sha, remote, may_start: gate.descendants_of(
                            OWN_REF, sha, remote, "unused-dir", "unused-url", may_start),
                        failed_later=lambda shas, may_start: gate.failed_later_from_api(
                            shas, may_start, repo="x/y", token="t", run_cmd=lookup),
                        sleep=clock.sleep, now=clock.now, log=lambda _m: None)
                context = (poll, worst)
                self.assertEqual(role, "head", context)
                kinds = {kind for kind, _t in starts}
                self.assertTrue({"ls-remote", "init", "fetch", "cat-file", "for-each-ref", "run-lookup"} <= kinds,
                                context)
                self.assertGreater(len(starts), 5, context)  # the ancestry commands really ran in several polls
                self.assertTrue(all(t < CAP for _kind, t in starts), (context, starts))
                self.assertLessEqual(clock.t, CAP + gate.QUEUE_POLL_WORST_IO_S, context)

    def test_deadline_stops_descendants_before_the_next_command(self):
        for start_at in (CAP - 1, CAP - 20, CAP - 50, CAP - 80, CAP - 170):
            clock, starts = FakeClock(), []
            clock.t = start_at
            with mock.patch.object(gate, "_git", fake_git(clock, starts, worst=True)):
                out = gate.descendants_of(OWN_REF, OWN, {OWN_REF: OWN, LATER_REF: OWN}, "unused-dir", "unused-url",
                                          may_start=lambda: clock.t < CAP)
            context = start_at
            self.assertTrue(all(t < CAP for _kind, t in starts), (context, starts))
            self.assertLessEqual(clock.t, CAP + max(gate.QUEUE_FETCH_TIMEOUT_S, gate.QUEUE_LS_REMOTE_TIMEOUT_S),
                                 context)
            self.assertIn(out, (None, {LATER_REF}), context)
        clock, starts = FakeClock(), []
        clock.t = CAP - 170  # every command fits before the cap: the answer is complete
        with mock.patch.object(gate, "_git", fake_git(clock, starts, worst=True)):
            full = gate.descendants_of(OWN_REF, OWN, {OWN_REF: OWN, LATER_REF: OWN}, "d", "u",
                                       may_start=lambda: clock.t < CAP)
        self.assertEqual(full, {LATER_REF})
        self.assertEqual([k for k, _t in starts], ["init", "fetch", "cat-file", "for-each-ref"])

    def test_no_command_at_all_once_past_the_cap(self):
        clock, starts = FakeClock(), []
        clock.t = CAP
        with mock.patch.object(gate, "_git", fake_git(clock, starts, worst=True)):
            out = gate.descendants_of(OWN_REF, OWN, {LATER_REF: OWN}, "d", "u", may_start=lambda: clock.t < CAP)
        self.assertEqual((out, starts), (None, []))

    def test_a_failed_command_is_unknown_never_an_empty_set(self):
        for failing in ("init", "fetch", "cat-file", "for-each-ref"):
            clock, starts = FakeClock(), []
            run = fake_git(clock, starts, worst=False)

            def broken(args, timeout, run=run, failing=failing):
                kind = args[2] if args[0] == "-C" else args[0]
                return None if kind == failing else run(args, timeout)

            with mock.patch.object(gate, "_git", broken):
                self.assertIsNone(gate.descendants_of(OWN_REF, OWN, {LATER_REF: OWN}, "d", "u"), failing)


class WorkflowWiring(unittest.TestCase):
    def test_queue_job_timeout_matches_the_gate_constant_and_covers_worst_case(self):
        text = WORKFLOW.read_text()
        block = text.split("\n  queue:\n", 1)[1].split("\n  plan:\n", 1)[0]
        minutes = int(re.search(r"timeout-minutes: (\d+)", block).group(1))
        self.assertEqual(minutes * 60, gate.QUEUE_JOB_TIMEOUT_S)
        self.assertLess(gate.QUEUE_CAP_S + gate.QUEUE_POLL_WORST_IO_S + gate.QUEUE_SETUP_MARGIN_S, minutes * 60)
        # ls-remote 60 + init 15 + cat-file 15 + fetch 60 + for-each-ref 30, plus 5 run lookups of 15 s each
        self.assertEqual(gate.QUEUE_POLL_WORST_IO_S, 180 + gate.QUEUE_MAX_BATCH * 15)
        self.assertEqual(gate.QUEUE_POLL_WORST_IO_S, 255)
        self.assertEqual(gate.QUEUE_CAP_S + gate.QUEUE_POLL_WORST_IO_S + gate.QUEUE_SETUP_MARGIN_S, 5955)
        self.assertEqual(minutes, 110)
        self.assertEqual(gate.QUEUE_JOB_TIMEOUT_S, 6600)

    def test_queue_job_can_read_actions_and_gets_the_token_only_there(self):
        text = WORKFLOW.read_text()
        block = text.split("\n  queue:\n", 1)[1].split("\n  plan:\n", 1)[0]
        self.assertIn("    permissions:\n      contents: read\n      actions: read\n", block)
        self.assertIn("GH_TOKEN: ${{ github.token }}", block)
        self.assertEqual(text.count("\n      actions: read\n"), 1)  # no other job or the workflow gains it
        self.assertEqual(block.count("GH_TOKEN: ${{ github.token }}"), 1)


class RealAncestry(unittest.TestCase):
    """Production ls_remote_queue and descendants_of over file:// URLs of a real local git DAG (no network).
    Layout: ROOT -> P -> A -> C on main, X branches from ROOT. Our entry is A; C is a later entry (descendant);
    P is an earlier entry (ancestor, never later); X is an unrelated stale branch."""

    def git(self, cwd, *args):
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env)
        return done.stdout.strip()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.work, self.remote, self.qdir = root / "work", root / "remote.git", root / "q.git"
        self.git(root, "init", "-q", "-b", "main", str(self.work))
        self.git(self.work, "commit", "-q", "--allow-empty", "-m", "root")
        self.root = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "commit", "-q", "--allow-empty", "-m", "p")
        self.p = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "commit", "-q", "--allow-empty", "-m", "a")
        self.a = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "commit", "-q", "--allow-empty", "-m", "c")
        self.c = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "checkout", "-q", "-b", "stale", self.root)
        self.git(self.work, "commit", "-q", "--allow-empty", "-m", "x")
        self.x = self.git(self.work, "rev-parse", "HEAD")
        self.git(root, "init", "-q", "--bare", str(self.remote))
        # GitHub serves tree:0 partial fetches; the fixture remote must allow the filter too.
        self.git(self.remote, "config", "uploadpack.allowFilter", "true")
        base = "refs/heads/gh-readonly-queue/main/"
        self.own_ref, self.later_ref = base + "pr-5-aaa", base + "pr-6-ccc"
        self.git(self.work, "push", "-q", str(self.remote),
                 f"{self.a}:{self.own_ref}", f"{self.c}:{self.later_ref}",
                 f"{self.p}:{base}pr-4-ppp", f"{self.x}:{base}pr-1-zzz")
        self.url = self.remote.as_uri()

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_the_descendant_is_later(self):
        remote = gate.ls_remote_queue(self.url)
        self.assertEqual(set(remote), {self.own_ref, self.later_ref, gate.QUEUE_REF_PREFIX + "pr-4-ppp",
                                       gate.QUEUE_REF_PREFIX + "pr-1-zzz"})
        self.assertEqual(remote[self.own_ref], self.a)
        later = gate.descendants_of(self.own_ref, self.a, remote, str(self.qdir), self.url)
        self.assertEqual(later, {self.later_ref})

    def test_deleted_later_ref_is_pruned_and_not_later(self):
        gate.descendants_of(self.own_ref, self.a, gate.ls_remote_queue(self.url), str(self.qdir), self.url)
        self.git(self.remote, "update-ref", "-d", self.later_ref)
        remote = gate.ls_remote_queue(self.url)
        self.assertNotIn(self.later_ref, remote)
        self.assertEqual(gate.descendants_of(self.own_ref, self.a, remote, str(self.qdir), self.url), set())
        self.assertNotIn("refs/q/pr-6-ccc", self.git(self.qdir, "for-each-ref", "--format=%(refname)"))

    def test_bad_url_returns_none(self):
        bad = (Path(self.tmp.name) / "no-such-remote.git").as_uri()
        self.assertIsNone(gate.ls_remote_queue(bad))
        self.assertIsNone(gate.descendants_of(self.own_ref, self.a, {self.own_ref: self.a},
                                              str(Path(self.tmp.name) / "q2.git"), bad))

    def chain_on(self, base, n, ref):
        """Push a branch n empty commits above base, under ref. Returns its tip."""
        self.git(self.work, "checkout", "-q", "--detach", base)
        for i in range(n):
            self.git(self.work, "commit", "-q", "--allow-empty", "-m", f"chain {i}")
        tip = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "push", "-q", str(self.remote), f"{tip}:{ref}")
        return tip

    def test_descendant_at_the_batch_bound_is_found(self):
        within = gate.QUEUE_MAX_BATCH  # 5 commits above ours: inside the depth-6 fetch
        ref = gate.QUEUE_REF_PREFIX + "pr-7-eee"
        self.chain_on(self.a, within, ref)
        remote = gate.ls_remote_queue(self.url)
        found = gate.descendants_of(self.own_ref, self.a, remote, str(self.qdir), self.url)
        self.assertEqual(found, {self.later_ref, ref})

    def test_chain_longer_than_the_depth_is_safe(self):
        # 7 commits above ours: our commit is cut off the shallow graph, so the deeper entry is missed. A miss means
        # `head` (our own full lane), never an untested merge. The function must still answer, not None, not raise.
        deep = gate.QUEUE_MAX_BATCH + 2
        ref = gate.QUEUE_REF_PREFIX + "pr-8-fff"
        self.chain_on(self.a, deep, ref)
        remote = gate.ls_remote_queue(self.url)
        found = gate.descendants_of(self.own_ref, self.a, remote, str(self.qdir), self.url)
        self.assertIsNotNone(found)
        self.assertEqual(found, {self.later_ref})  # the 7-deep entry is missed: documented, and safe (head)

    def test_own_commit_missing_is_unknown(self):
        remote = gate.ls_remote_queue(self.url)
        self.assertIsNone(gate.descendants_of(self.own_ref, "f" * 40, remote, str(self.qdir), self.url))


class DepthTie(unittest.TestCase):
    def test_fetch_depth_is_the_ruleset_batch_bound_plus_one(self):
        self.assertEqual(gate.QUEUE_MAX_BATCH, 5)
        self.assertEqual(gate.QUEUE_FETCH_DEPTH, gate.QUEUE_MAX_BATCH + 1)
        dox = (Path(__file__).resolve().parent.parent / "server-rust" / "DOX.md").read_text()
        self.assertRegex(dox, r"`max_entries_to_build` " + str(gate.QUEUE_MAX_BATCH) + r"\b")
        self.assertTrue(f"`--depth {gate.QUEUE_FETCH_DEPTH}`" in dox, "server-rust/DOX.md must state the fetch depth")


if __name__ == "__main__":
    unittest.main()
