#!/usr/bin/env python3
"""Decisions of .github/workflows/server-rust-lane.yml that are not plain job wiring.

  lane-job-gate.py mode EVENT [COMMITS]   print full|cache|skip; COMMITS = commits on main in the nightly window
  lane-job-gate.py verdict                 aggregate verdict from $NEEDS (toJSON(needs)) and $EVENT; exit 0 = green

Tests: python3 scripts/test-lane-job-gate.py"""
import json
import os
import sys

FULL_JOBS = {"plan", "build", "roots", "pgtap", "guards", "shard", "coverage-build", "coverage-shard"}
CACHE_JOBS = {"plan", "build", "coverage-build", "gomod-cache"}


def mode_for(event, commits=None):
    """push refreshes caches only; the nightly runs the full lane only when main has news; the rest is full.
    An unreadable commit count never reaches here (the caller fails first), so it can not become skip."""
    if event == "push":
        return "cache"
    if event == "schedule":
        if commits is None:
            raise ValueError("schedule needs the commit count")
        return "full" if commits > 0 else "skip"
    return "full"


def verdict(needs, event):
    """Return None when green, else the red reason. Only mode=full is a test pass; merge_group and
    workflow_dispatch can never be green with any other mode (a skipped or mis-planned queue run is red)."""
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


def main(argv):
    if len(argv) >= 3 and argv[1] == "mode":
        print(mode_for(argv[2], int(argv[3]) if len(argv) > 3 else None))
        return 0
    if len(argv) == 2 and argv[1] == "verdict":
        reason = verdict(json.loads(os.environ["NEEDS"]), os.environ["EVENT"])
        if reason:
            print("red: " + reason)
        return 1 if reason else 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
