#!/usr/bin/env python3
"""Compare a serial `cargo test` lane log with a parallel nextest JUnit (#550).

Usage: compare-lane-runs.py SERIAL_LOG PARALLEL_JUNIT [--parallel-log PARALLEL_LOG]

The test set is keyed by (binary, test name) where binary is the cargo target name
(`cache`, `setjoin_acme`); the serial side comes from libtest's `Running ... (deps/NAME-hash)`
and `test NAME ... ` lines, the parallel side from the JUnit testsuite/testcase names.
Doc tests are excluded on both sides (nextest does not run them; the lane runs them with
`cargo test --doc`). Exit 0 only when both sides ran exactly the same tests with the same
pass/fail result per test. Prints per-binary counts for the differing binaries.
"""
import argparse
import collections
import re
import sys
import xml.etree.ElementTree as ET

RUNNING = re.compile(r"^\s*Running .*?/deps/([A-Za-z0-9_]+)-[0-9a-f]{16}\)")
DOCTESTS = re.compile(r"^\s*Doc-tests ")
CASE = re.compile(r"\btest (\S+)(?: - should panic)? \.\.\. ?(ok|FAILED|ignored)?")
FAILBLOCK = re.compile(r"^---- (\S+) stdout ----")


def serial(path):
    ran, failed, ignored = collections.Counter(), set(), set()
    binary = None
    for line in open(path, errors="replace"):
        if DOCTESTS.match(line):
            binary = None
            continue
        m = RUNNING.match(line)
        if m:
            binary = m.group(1)
            continue
        if binary is None:
            continue
        m = CASE.search(line)
        if m and not line.startswith(" "):
            ran[(binary, m.group(1))] += 1
            if m.group(2) == "FAILED":
                failed.add((binary, m.group(1)))
            elif m.group(2) == "ignored":
                ignored.add((binary, m.group(1)))
            continue
        m = FAILBLOCK.match(line)
        if m:
            failed.add((binary, m.group(1)))
    return ran, failed, ignored


def binary_key(suite):
    # junit suite name is the nextest binary id: `pkg`, `pkg::test`, `pkg::bin/name`.
    pkg, _, rest = suite.partition("::")
    if not rest:
        return pkg.replace("-", "_")
    return rest[4:].replace("-", "_") if rest.startswith("bin/") else rest


def parallel(path):
    ran, failed, ignored = collections.Counter(), set(), set()
    for suite in ET.parse(path).getroot().iter("testsuite"):
        key = binary_key(suite.get("name", ""))
        for case in suite.iter("testcase"):
            item = (key, case.get("name"))
            ran[item] += 1
            if case.find("failure") is not None or case.find("error") is not None:
                failed.add(item)
            elif case.find("skipped") is not None:
                ignored.add(item)
    return ran, failed, ignored


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("serial_log")
    ap.add_argument("junit")
    ap.add_argument("--parallel-log", help="parallel lane log: adds the binaries run in-process under libtest")
    ap.add_argument("--all", action="store_true", help="list every difference, not the first 40 per kind")
    args = ap.parse_args()
    limit = 10**9 if args.all else 40
    s_ran, s_fail, s_ign = serial(args.serial_log)
    p_ran, p_fail, p_ign = parallel(args.junit)
    if args.parallel_log:
        l_ran, l_fail, l_ign = serial(args.parallel_log)
        p_ran.update(l_ran)
        p_fail |= l_fail
        p_ign |= l_ign
    print(f"serial:   {sum(s_ran.values())} tests, {len(s_fail)} failed, {len(s_ign)} ignored, {len({b for b, _ in s_ran})} binaries")
    print(f"parallel: {sum(p_ran.values())} tests, {len(p_fail)} failed, {len(p_ign)} skipped, {len({b for b, _ in p_ran})} binaries")
    bad = 0
    only_s, only_p = sorted(set(s_ran) - set(p_ran)), sorted(set(p_ran) - set(s_ran))
    for label, items in (("only in serial", only_s), ("only in parallel", only_p)):
        for item in items[:limit]:
            print(f"  {label}: {item[0]}::{item[1]}")
        if items:
            print(f"  {label}: {len(items)} test(s)")
            bad = 1
    for label, items in (("failed only in serial", s_fail - p_fail), ("failed only in parallel", p_fail - s_fail)):
        for item in sorted(items)[:limit]:
            print(f"  {label}: {item[0]}::{item[1]}")
        if items:
            bad = 1
    if s_ign or p_ign:
        print(f"  ignored/skipped tests present: serial={len(s_ign)} parallel={len(p_ign)}")
        bad = 1
    per_s, per_p = collections.Counter(), collections.Counter()
    for (b, _), n in s_ran.items():
        per_s[b] += n
    for (b, _), n in p_ran.items():
        per_p[b] += n
    for b in sorted(set(per_s) | set(per_p)):
        if per_s[b] != per_p[b]:
            print(f"  binary {b}: serial={per_s[b]} parallel={per_p[b]}")
            bad = 1
    print("IDENTICAL" if not bad else "DIFFERENT")
    return bad


sys.exit(main())
