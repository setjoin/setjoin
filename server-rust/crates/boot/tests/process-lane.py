#!/usr/bin/env python3
"""Build/run only the gateway process targets affected by server boot.

REQUIRE_DB=1 and the four disposable DSNs are mandatory. Resume reuses a pass
only when the executable, runtime fixtures, database and toolchain still match.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_digest():
    inputs = []
    for base in [ROOT / "server-rust", ROOT / "mailserver", ROOT / "authserver", ROOT / "shared"]:
        tracked = subprocess.check_output(["git", "ls-files", "-z", "--", str(base)], cwd=ROOT).split(b"\0")
        for raw in tracked:
            if not raw:
                continue
            path = ROOT / os.fsdecode(raw)
            if path.suffix in {".json", ".sql", ".pg", ".go", ".txt"} and path.is_file():
                inputs.append((str(path.relative_to(ROOT)), digest(path)))
    return hashlib.sha256(json.dumps(sorted(inputs)).encode()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--only", action="append")
    args = p.parse_args()
    env = os.environ.copy()
    assert env.get("REQUIRE_DB") == "1", "REQUIRE_DB=1 required"
    coords = []
    for key in ["TEST_DB_DSN", "DB_DSN", "DB_DIRECT_DSN", "DB_APP_DSN"]:
        parsed = urllib.parse.urlsplit(env[key])
        db = parsed.path.removeprefix("/")
        assert db == "mailserver_test" or "_e2e" in db or db.startswith("mailserver_determinism_"), f"non-disposable {key}"
        coords.append((parsed.hostname, parsed.port, db, parsed.username))
    assert len({c[:3] for c in coords}) == 1, "all DSNs must address the same owned disposable database"
    for key in list(env):
        if key.startswith("GOFREE_RECORD"):
            del env[key]
    env.setdefault("GOFREE_RESOURCE_PREFIX", "gofree-boot")
    args.output.mkdir(parents=True, exist_ok=True)
    targets = args.only or json.loads((HERE / "process-targets.json").read_text())
    command = ["cargo", "test", "--manifest-path", str(ROOT / "server-rust/Cargo.toml"), "--locked", "-p", "setjoin-gateway"]
    for target in targets:
        command += ["--test", target]
    command += ["--no-run", "--message-format=json"]
    artifacts = {}
    with (args.output / "build.log").open("w") as log:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=log, text=True)
        for line in proc.stdout:
            log.write(line)
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("executable") and item.get("profile", {}).get("test"):
                artifacts[item["target"]["name"]] = Path(item["executable"])
        assert proc.wait() == 0, f"build failed: {args.output / 'build.log'}"
    data = runtime_digest()
    toolchain = subprocess.check_output(["rustc", "--version"], text=True).strip()
    test_args = ["--test-threads=1", "--nocapture"]
    runner = digest(Path(__file__))
    receipts_path = args.output / "receipts.json"
    receipts = json.loads(receipts_path.read_text()) if args.resume and receipts_path.exists() else {}
    failures = []
    for index, target in enumerate(targets):
        binary = artifacts[target]
        inputs = {"executable_sha256": digest(binary), "runtime_data_sha256": data, "database": coords, "toolchain": toolchain, "test_args": test_args, "runner_sha256": runner}
        # JSON roundtrip makes tuples/lists identical when checking prior receipts.
        inputs = json.loads(json.dumps(inputs))
        prior = receipts.get(target, {})
        if args.resume and prior.get("passed") and prior.get("inputs") == inputs:
            print(f"{index+1}/{len(targets)} {target}: verified prior PASS", flush=True)
            continue
        started = time.monotonic()
        with (args.output / f"{target}.log").open("w") as log:
            result = subprocess.run([str(binary), *test_args], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        text = (args.output / f"{target}.log").read_text()
        summary = re.search(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", text)
        passed = result.returncode == 0 and summary is not None and int(summary[1]) > 0 and "DB-SKIP" not in text and "GOLDEN-SKIP" not in text
        receipts[target] = {"inputs": inputs, "passed": passed, "exit": result.returncode, "tests": int(summary[1]) if summary else None, "seconds": round(time.monotonic()-started, 2)}
        receipts_path.write_text(json.dumps(receipts, indent=2) + "\n")
        print(f"{index+1}/{len(targets)} {target}: {'PASS' if passed else 'FAIL'} ({receipts[target]['seconds']}s)", flush=True)
        if not passed:
            print(text[-12000:], flush=True)
            failures.append(target)
    if failures:
        print(f"BOOT process lane: FAIL ({', '.join(failures)})", flush=True)
        raise SystemExit(1)
    print(f"BOOT process lane: PASS ({len(targets)} targets)", flush=True)


if __name__ == "__main__":
    main()
