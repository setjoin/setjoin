#!/usr/bin/env python3
"""Measure instrumented Rust handler coverage from named golden replays.

One route's replays may live in several test binaries (`--case BINARY TEST`, repeatable): each
replay runs in its own binary and the profiles are merged, so the report is the union of what the
route's replays executed. `--binary BINARY --test TEST` stays for the one-binary form.

Environment:
  CARGO_TARGET_<TRIPLE>_RUNNER      wraps every launch, as `cargo test` does (per-replay DB clone)
  LANE_COVERAGE_REPLAY_TIMEOUT      seconds one replay may run before it is killed and fails
                                    (default 900); a hung replay is a failure, never a stall
"""

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)
    if result.returncode:
        raise ValueError(f"command failed {command!r}:\n{result.stdout}{result.stderr}")
    return result.stdout


def launch(command, env, timeout):
    """Runs a replay in its own process group so a timeout kills the runner, the test binary and
    every child it spawned."""
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        raise ValueError(f"replay exceeded {timeout:.0f}s and was killed (hung?):\n{out}{err}")
    return process.returncode, out + err


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--route", required=True)
    parser.add_argument("--binary", type=Path, action="append", default=[])
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--case", nargs=2, action="append", default=[], metavar=("BINARY", "TEST"))
    args = parser.parse_args()
    cases = [(Path(binary), test) for binary, test in args.case]
    if args.test:
        if len(args.binary) != 1:
            raise ValueError("--test needs exactly one --binary (use --case BINARY TEST for several binaries)")
        cases += [(args.binary[0], test) for test in args.test]
    if not cases:
        raise ValueError("no replays selected")
    binaries = []
    for binary, _ in cases + [(binary, None) for binary in args.binary]:
        binary = binary.resolve()
        if binary not in binaries:
            binaries.append(binary)
    host = next(line.split(": ", 1)[1] for line in run(["rustc", "-vV"]).splitlines()
                if line.startswith("host: "))
    # `cargo test` hands a test binary to CARGO_TARGET_<triple>_RUNNER; this reporter launches the
    # instrumented binary itself, so it applies the same runner (the lane's per-replay database
    # clone). Bypassing it would connect to the base database, which the leak guard refuses.
    runner = shlex.split(os.environ.get("CARGO_TARGET_" + host.upper().replace("-", "_") + "_RUNNER", ""))
    timeout = float(os.environ.get("LANE_COVERAGE_REPLAY_TIMEOUT", "900"))
    tools = Path(run(["rustc", "--print", "sysroot"]).strip()) / "lib/rustlib" / host / "bin"
    profdata, cov = tools / "llvm-profdata", tools / "llvm-cov"
    if not profdata.is_file() or not cov.is_file():
        raise ValueError("Rust llvm-tools component is required for coverage")
    with tempfile.TemporaryDirectory(prefix="gofree-oracle-coverage-") as directory:
        tmp = Path(directory)
        profiles = tmp / "cases"
        profiles.mkdir()

        env = dict(os.environ, REQUIRE_DB="1", RUST_TEST_THREADS="1")
        for name in ("GOFREE_RECORD_UPSTREAM", "GOFREE_RECORD_GO_BINARY", "GOFREE_RECORD_EFFECTS", "GOFREE_GO_SOURCE"):
            env.pop(name, None)
        for index, (binary, test) in enumerate(cases):
            # One raw profile set per replay (every process the replay starts writes `%p-%m` into
            # its own directory), folded at once into that replay's sparse profile and deleted:
            # attribution stays per replay, and a gateway raw profile never piles up on disk.
            raw = tmp / f"raw-{index}"
            raw.mkdir()
            env["LLVM_PROFILE_FILE"] = str(raw / "%p-%m.profraw")
            returncode, output = launch([*runner, str(binary.resolve()), "--exact", test, "--nocapture"], env, timeout)
            if (returncode
                    or not re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE)
                    or re.search(r"[A-Z][A-Z0-9-]*-SKIP \(reason=", output)):
                raise ValueError(f"replay {test} ran zero or multiple tests or skipped:\n{output}")
            raws = sorted(raw.glob("*.profraw"))
            if not raws:
                # A replay that ran but wrote no profile is not coverage evidence (an
                # uninstrumented binary, or one that exited without flushing): never let another
                # replay's profile stand in for it.
                raise ValueError(f"replay {test} produced no coverage profile")
            run([str(profdata), "merge", "-sparse", *(str(path) for path in raws), "-o", str(profiles / f"{index}.profdata")])
            for path in raws:
                path.unlink()
            raw.rmdir()
        # One merge per entry over the per-replay profiles.
        case_profiles = sorted(profiles.glob("*.profdata"))
        if not case_profiles:
            raise ValueError("instrumented replays produced no coverage profiles")
        merged = tmp / "merged.profdata"
        run([str(profdata), "merge", "-sparse", *(str(path) for path in case_profiles), "-o", str(merged)])
        sources = [source.resolve() for source in args.source]
        command = [str(cov), "export", "--format=text", "--skip-functions", "--skip-expansions",
                   f"--instr-profile={merged}", str(binaries[0])]
        for extra in binaries[1:]:
            command += ["--object", str(extra)]
        command += ["--sources", *(str(source) for source in sources)]
        data = json.loads(run(command))
        files = {Path(file["filename"]).resolve(): file for group in data["data"] for file in group["files"]}
        report = []
        for source in args.source:
            file = files.get(source.resolve())
            if file is None:
                raise ValueError(f"handler source has no coverage mapping: {source}")
            summary = file["summary"]
            if not summary["lines"]["count"]:
                raise ValueError(f"handler source has no executable coverage lines: {source}")
            report.append({"file": str(source), "lines": summary["lines"], "regions": summary["regions"]})
        print(json.dumps({"route": args.route, "tests": [test for _, test in cases], "files": report}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, StopIteration) as error:
        sys.exit(str(error))
