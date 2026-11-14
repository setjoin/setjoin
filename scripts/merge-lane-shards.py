#!/usr/bin/env python3
"""Merge the hosted server-rust lane's job results into one verdict (server-rust-lane.yml).

  merge-lane-shards.py --list LANE_LIST_JSON --results DIR --shards N [--coverage-shards M]

Red unless every job directory (lane-result-roots, lane-result-shard-1..N, lane-result-coverage-1..M)
holds lane-complete.txt with rc=0; every non-ignored test of the build's `cargo nextest list`
ran exactly once across the shard junit files and none failed; no log prints a `*-SKIP (reason=`
marker; the shards together replayed every replay and mutant of the manifest with none failed;
and (with M) the coverage shards together measured every coverage entry. Each shard's
adequacy-receipt.json names the replays/mutants and coverage entries it ran, bound to the manifest
hash and its K/N selector; the multiset of those items must equal the manifest (no omission, no
duplicate). An empty inventory or zero executed tests is red. Prints Markdown.
"""
import argparse
import collections
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = re.compile(r"[A-Z][A-Z0-9-]*-SKIP \(reason=")


def expected_tests(document):
    tests = set()
    for binary, suite in document["rust-suites"].items():
        for name, case in suite["testcases"].items():
            if not case.get("ignored") and case.get("filter-match", {}).get("status", "matches") == "matches":
                tests.add((binary, name))
    return tests


def junit_results(path):
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.find("skipped") is not None:
            continue
        failed = case.find("failure") is not None or case.find("error") is not None
        yield (case.get("classname"), case.get("name")), failed


def manifest():
    out = subprocess.run([sys.executable, str(ROOT / "scripts/check-gofree-oracle-adequacy.py"), "--print-manifest"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def check_receipts(results, names, selectors, key, expected, manifest_hash, problems):
    """Every job's receipt must be bound to the manifest hash and its selector; the items they
    name, taken together, must equal the manifest's multiset."""
    ran = []
    for name, selector in zip(names, selectors):
        path = results / name / "adequacy-receipt.json"
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError):
            problems.append(f"{name}: no adequacy receipt (adequacy-receipt.json missing or unreadable)")
            continue
        if document.get("manifest_hash") != manifest_hash:
            problems.append(f"{name}: receipt manifest hash {document.get('manifest_hash')!r} is not the build's {manifest_hash!r}")
            continue
        if document.get("shard") != selector:
            problems.append(f"{name}: receipt selector {document.get('shard')!r}, expected {selector!r}")
            continue
        ran.extend(document.get(key) or [])
    want, got = collections.Counter(expected), collections.Counter(ran)
    absent, extra = sorted((want - got).elements()), sorted((got - want).elements())
    label = "replays/mutants" if key == "replays" else "coverage entries"
    if absent:
        problems.append(f"{len(absent)} {label} never ran: " + ", ".join(absent[:5]))
    if extra:
        problems.append(f"{len(extra)} {label} ran twice or are not in the manifest: " + ", ".join(extra[:5]))


def summed(paths, pattern):
    total, found = [0, 0], 0
    for path in paths:
        for match in re.finditer(pattern, path.read_text(errors="replace") if path.is_file() else "", re.MULTILINE):
            found += 1
            for i, value in enumerate(match.groups()):
                total[i] += int(value or 0)  # an empty group counts 0
    return found, total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--coverage-shards", type=int, default=0)
    args = parser.parse_args()
    shards = [f"lane-result-shard-{k}" for k in range(1, args.shards + 1)]
    coverage = [f"lane-result-coverage-{k}" for k in range(1, args.coverage_shards + 1)]
    problems = []
    for name in ["lane-result-roots", *shards, *coverage]:
        directory = args.results / name
        receipt = directory / "lane-complete.txt"
        rc = receipt.read_text().strip() if receipt.is_file() else None
        if rc != "rc=0":
            problems.append(f"{name}: {'did not finish' if rc is None else rc}")
        log = directory / "lane.log"
        hits = [line for line in (log.read_text(errors="replace").splitlines() if log.is_file() else []) if SKIP.search(line)]
        if hits:
            problems.append(f"{name}: {len(hits)} skip marker(s), first: {hits[0][:160]}")
    expected = expected_tests(json.loads(args.list.read_text()))
    seen, failed = {}, []
    for name in shards:
        junit = args.results / name / "junit.xml"
        if not junit.is_file():
            problems.append(f"{name}: no junit.xml")
            continue
        for key, bad in junit_results(junit):
            seen[key] = seen.get(key, 0) + 1
            if bad:
                failed.append(key)
    missing = sorted(expected - seen.keys())
    unexpected = sorted(seen.keys() - expected)
    twice = sorted(key for key, count in seen.items() if count > 1)
    for label, keys in (("failed", failed), ("never ran", missing), ("not in the build's list", unexpected), ("ran twice", twice)):
        if keys:
            problems.append(f"{len(keys)} test(s) {label}: " + ", ".join(f"{b}::{t}" for b, t in sorted(keys)[:10]))
    if not expected:
        problems.append("the build's test inventory is empty (a list with no runnable test proves nothing)")
    if not seen:
        problems.append("no test executed in any shard")
    document = manifest()
    entries, replays = len(document["coverage"]), len(document["replays"])
    if not entries or not replays:
        problems.append(f"the oracle manifest is empty ({replays} replays, {entries} coverage entries)")
    check_receipts(args.results, shards, [f"{k}/{args.shards}" for k in range(1, args.shards + 1)],
                   "replays", document["replays"], document["hash"], problems)
    found, (passed, bad) = summed([args.results / n / "lane.log" for n in shards],
                                  r"^replay summary: (\d+) passed, (\d+) failed$")
    if found != args.shards or bad or passed != replays:
        problems.append(f"replays: {found}/{args.shards} shard summaries, {passed} passed, {bad} failed, manifest {replays}")
    if coverage:
        check_receipts(args.results, coverage, [f"{k}/{args.coverage_shards}" for k in range(1, args.coverage_shards + 1)],
                       "coverage", document["coverage"], document["hash"], problems)
        found, (measured, _) = summed([args.results / n / "lane.log" for n in coverage],
                                      r"^coverage summary: (\d+) entries measured()$")
        if found != args.coverage_shards or measured != entries:
            problems.append(f"coverage: {found}/{args.coverage_shards} shard summaries, {measured} measured, manifest {entries}")
    print(f"### server-rust lane: {len(seen)} tests over {args.shards} shards, {replays} replays"
          + (f", {entries} coverage entries over {args.coverage_shards} shards" if coverage else ""))
    for problem in problems:
        print(f"- ✗ {problem}")
    if problems:
        sys.exit(1)
    print("- ✓ every test, replay and mutant ran once and passed" + ("; coverage complete" if coverage else ""))


if __name__ == "__main__":
    main()
