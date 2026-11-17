#!/usr/bin/env python3
"""Decisions of .github/workflows/server-rust-lane.yml that are not plain job wiring.

  lane-job-gate.py mode EVENT [COMMITS]   print full|cache|skip|gone; COMMITS = commits on main in the nightly
                                          window; env QUEUE_ROLE (head|gone, default head) matters for merge_group only
  lane-job-gate.py verdict                aggregate verdict from $NEEDS (toJSON(needs)) and $EVENT; exit 0 = green
  lane-job-gate.py queue-role             the `queue` job's decision for this merge-queue entry: prints head or gone
                                          on stdout (logs go to stderr). Env: EVENT, OWN_REF (github.ref), OWN_SHA
                                          (github.sha), REPO, BATCHING (vars.LANE_QUEUE_BATCHING; only "1" enables
                                          waiting). Optional LANE_QUEUE_POLL / LANE_QUEUE_SETTLE / LANE_QUEUE_CAP in seconds.

Tests: python3 scripts/test-lane-job-gate.py"""
import json
import os
import subprocess
import sys
import tempfile
import time

FULL_JOBS = {"plan", "build", "roots", "pgtap", "guards", "shard", "coverage-build", "coverage-shard"}
CACHE_JOBS = {"plan", "build", "coverage-build", "gomod-cache"}

# Merge-queue batching. Worst case for one entry: SETTLE + CAP + the lane. The queue job's timeout-minutes
# (server-rust-lane.yml) is QUEUE_JOB_TIMEOUT_S; CAP plus one poll's worst overshoot (git timeouts
# 60 + 30 + 120 + 30 = 240 s) must stay below it, and tests/test-lane-job-gate.py asserts both.
QUEUE_POLL_S = 60
QUEUE_SETTLE_S = 120
QUEUE_CAP_S = 5400
QUEUE_JOB_TIMEOUT_S = 100 * 60
QUEUE_REF_PREFIX = "refs/heads/gh-readonly-queue/main/"


def mode_for(event, commits=None, queue_role="head"):
    """push refreshes caches only; the nightly runs the full lane only when main has news; a merge-queue entry
    whose queue role is gone runs nothing (mode gone, never green); the rest is full.
    An unreadable commit count never reaches here (the caller fails first), so it can not become skip."""
    if event == "push":
        return "cache"
    if event == "schedule":
        if commits is None:
            raise ValueError("schedule needs the commit count")
        return "full" if commits > 0 else "skip"
    if event == "merge_group" and queue_role == "gone":
        return "gone"
    return "full"


def verdict(needs, event):
    """Return None when green, else the red reason. Only mode=full is a test pass; merge_group and
    workflow_dispatch can never be green with any other mode (a skipped or mis-planned queue run is red,
    and so is mode=gone: the entry left the queue, nothing ran)."""
    plan = needs.get("plan", {})
    debug = plan.get("outputs", {}).get("debug") == "true"
    mode = plan.get("outputs", {}).get("mode", "")
    allowed = {"push": {"cache"}, "schedule": {"full", "skip"}}.get(event, {"full"})
    if mode not in allowed:
        return f"event {event} planned mode {mode!r}, allowed {sorted(allowed)}"
    if debug:
        required = {"plan", "debug"}
    elif mode == "full":
        required = FULL_JOBS
    elif mode == "cache":
        required = CACHE_JOBS
    else:
        required = {"plan"}
    results = {name: job["result"] for name, job in needs.items()}
    print("debug" if debug else mode, "job results", results)
    bad = {n: r for n, r in results.items() if r in ("failure", "cancelled") or (n in required and r != "success")}
    missing = sorted(required - set(results))
    if bad or missing:
        return f"{bad} missing={missing}"
    return None


def queue_role(own_ref, own_sha, remote, later, waited_s, *, enabled, settle_s, cap_s):
    """Return head (run the full lane), gone (the entry left the queue; nothing runs) or wait (poll again).

    remote: {ref: sha} from ls-remote, None when ls-remote failed.
    later:  refs proven to descend from own_sha (own_ref excluded), None when that check failed.
    An error is never a reason to skip: it waits until the cap, then runs the lane (fail-safe, just slower)."""
    if not enabled:
        return "head"
    capped = waited_s >= cap_s
    if remote is None:
        return "head" if capped else "wait"
    if remote.get(own_ref) != own_sha:
        return "gone"
    if waited_s < settle_s:
        return "wait"
    if later is None or later:
        return "head" if capped else "wait"
    return "head"


def wait_for_role(own_ref, own_sha, *, enabled, poll_s, settle_s, cap_s, ls_remote, descendants, sleep, now, log):
    """Poll until queue_role is not wait. ls_remote() -> {ref: sha} or None; descendants(own_sha, remote) -> set or
    None. descendants runs only when the queued sha set changed since the last answer, or the last answer was None.
    Every git call, the clock and the sleep are injected, so tests run with no network and no waiting."""
    if not enabled:
        return "head"
    start = now()
    later = None
    last_key = None
    while True:
        waited = now() - start
        remote = ls_remote()
        if remote is not None and remote.get(own_ref) == own_sha and waited >= settle_s:
            key = tuple(sorted(remote.items()))
            if key != last_key or later is None:
                later = descendants(own_sha, remote)
                last_key = key
        role = queue_role(own_ref, own_sha, remote, later, waited,
                          enabled=True, settle_s=settle_s, cap_s=cap_s)
        successors = sorted(r for r in (remote or {}) if r.endswith("-" + own_sha))
        log(f"queue-role={role} waited={int(waited)}s entry={own_ref} sha={own_sha[:12]} "
            f"ancestry_later={sorted(later) if later is not None else 'unknown'} "
            f"name_successors={successors or 'none'}")
        if role != "wait":
            return role
        sleep(poll_s)


def _git(args, timeout):
    """Run git with no prompts. Return stdout, or None on any failure (exit, timeout, missing git)."""
    try:
        done = subprocess.run(["git", *args], check=False, timeout=timeout, capture_output=True, text=True,
                              env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def ls_remote_queue(url):
    """Anonymous ls-remote of the queue branches of a public repo (no API, no token). None on failure."""
    out = _git(["ls-remote", url, QUEUE_REF_PREFIX + "*"], timeout=60)
    if out is None:
        return None
    remote = {}
    for line in out.splitlines():
        sha, _, ref = line.partition("\t")
        if sha and ref.startswith(QUEUE_REF_PREFIX):
            remote[ref] = sha
    return remote


def descendants_of(own_ref, own_sha, remote, git_dir, url):
    """Queue refs whose commit descends from own_sha, excluding own_ref. Commits only (--filter=tree:0) into a
    bare repo, so the shallow checkout is never used. None when fetch or lookup fails."""
    if _git(["init", "-q", "--bare", git_dir], timeout=30) is None:
        return None
    fetched = _git(["-C", git_dir, "fetch", "-q", "--prune", "--no-tags", "--filter=tree:0", url,
                    f"+{QUEUE_REF_PREFIX}*:refs/q/*"], timeout=120)
    if fetched is None:
        return None
    # for-each-ref --contains lists the refs whose tip has own_sha as an ancestor (own_sha itself included).
    listed = _git(["-C", git_dir, "for-each-ref", "--contains", own_sha, "--format=%(refname)", "refs/q/"], timeout=30)
    if listed is None:
        return None
    names = {QUEUE_REF_PREFIX + line[len("refs/q/"):] for line in listed.splitlines() if line.startswith("refs/q/")}
    return {r for r in names if r != own_ref and r in remote}


def queue_role_cli(env):
    if env.get("EVENT") != "merge_group" or env.get("BATCHING") != "1":
        return "head"  # switch off or not a queue entry: no git call at all
    own_ref, own_sha, repo = env["OWN_REF"], env["OWN_SHA"], env["REPO"]
    url = f"https://github.com/{repo}.git"
    git_dir = os.path.join(env.get("RUNNER_TEMP") or tempfile.gettempdir(), "q.git")
    return wait_for_role(
        own_ref, own_sha, enabled=True,
        poll_s=int(env.get("LANE_QUEUE_POLL", QUEUE_POLL_S)),
        settle_s=int(env.get("LANE_QUEUE_SETTLE", QUEUE_SETTLE_S)),
        cap_s=int(env.get("LANE_QUEUE_CAP", QUEUE_CAP_S)),
        ls_remote=lambda: ls_remote_queue(url),
        descendants=lambda sha, remote: descendants_of(own_ref, sha, remote, git_dir, url),
        sleep=time.sleep,
        now=time.monotonic,
        log=lambda msg: print(msg, file=sys.stderr),
    )


def main(argv):
    if len(argv) >= 3 and argv[1] == "mode":
        print(mode_for(argv[2], int(argv[3]) if len(argv) > 3 else None,
                       queue_role=os.environ.get("QUEUE_ROLE") or "head"))
        return 0
    if len(argv) == 2 and argv[1] == "verdict":
        reason = verdict(json.loads(os.environ["NEEDS"]), os.environ["EVENT"])
        if reason:
            print("red: " + reason)
        return 1 if reason else 0
    if len(argv) == 2 and argv[1] == "queue-role":
        print(queue_role_cli(os.environ))
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
