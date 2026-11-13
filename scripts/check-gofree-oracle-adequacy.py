#!/usr/bin/env python3
"""Reject Rust route transfers whose recorded parity corpus is incomplete."""

import argparse
import concurrent.futures
import json
import os
import re
import signal
import subprocess
import threading
import time
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLOOR = {"success", "cross-tenant", "invalid-input"}
FAMILY_MUTANTS = {"no-audit", "no-notify", "no-tenant-filter", "double-bump"}
# A family may carry one mutant of these kinds per route: each route's notification
# (or the like) is a separate effect, so one route's mutant says nothing about another's.
PER_ROUTE_FAMILY_MUTANTS = {"no-notify"}


def route_key(row):
    return tuple(row[field] for field in ("listener", "method", "path", "family"))


ASRBOT_FLOOR = {("GET", "/healthz"): {200}, ("GET", "/status"): {200, 401}, ("POST", "/start"): {200, 400, 401, 409},
                ("POST", "/stop"): {200, 400, 401}}


def check_asrbot_route(root, route, executable):
    """The captions bot is its own listener: its oracle is the crate's byte-for-byte replay of
    goldens recorded from frozen Go, so the DB observation catalog does not apply."""
    key = route_key(route)
    if route["upstream"] != "rust-asrbot" or route["state"] != "ON":
        return  # still owned by Go: nothing to qualify
    goldens = route.get("oracle_goldens")
    if not isinstance(goldens, list) or not goldens or len(set(goldens)) != len(goldens):
        raise ValueError(f"{key}: missing asrbot goldens")
    statuses = set()
    for name in goldens:
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError(f"{key}: missing asrbot golden {name}")
        stem = path.stem
        document = json.loads(path.read_text())
        if document.get("scenario") != stem.removeprefix("control-") or not document.get("steps"):
            raise ValueError(f"{key}: invalid asrbot golden {name}")
        for step in document["steps"]:
            request, response = step.get("request", {}), step.get("response", {})
            if request.get("method") == route["method"] and request.get("path") == route["path"]:
                statuses.add(response.get("status"))
        test = stem.replace("-", "_") + "_matches_recorded_go"
        executable.append(({"package": "setjoin-asrbot", "target": "control_oracle", "test": test},
                           f"GOLDEN-REPLAY: asrbot control :: {stem}"))
    missing = sorted(ASRBOT_FLOOR[(route["method"], route["path"])] - statuses)
    if missing:
        raise ValueError(f"{key}: asrbot goldens lack recorded statuses {missing}")
    mutant = f"status_mutant_{route['method'].lower()}_{route['path'].strip('/')}"
    executable.append(({"package": "setjoin-asrbot", "target": "control_oracle", "test": mutant},
                       f"MUTANT-REJECTED: {route['method']} {route['path']} :: status"))


# Platform's non-HTTP listeners (#305): the :80 ACME responder and the unix setup control socket
# are separate listeners the gateway never mounts. Like the captions bot, their oracle is a
# byte-for-byte replay of goldens recorded from frozen Go, not the DB observation catalog.
PLATFORM_LISTENER_FLOOR = {"control": {200, 400, 403, 409}, "acme": {200, 301}}
PLATFORM_LISTENER_TESTS = {
    "control": [("setup_control_recorded", "control_socket_matches_recorded_go"),
                ("setup_control_recorded", "socket_hardening")],
    "acme": [("acme_http80_recorded", "http80_matches_recorded_go")],
}


def check_platform_listener_route(root, route, executable):
    key = route_key(route)
    if route["state"] != "ON":
        return  # still owned by Go: nothing to qualify
    goldens = route.get("oracle_goldens")
    if not isinstance(goldens, list) or not goldens or len(set(goldens)) != len(goldens):
        raise ValueError(f"{key}: missing {route['listener']} goldens")
    statuses = set()
    first = None
    for name in goldens:
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError(f"{key}: missing {route['listener']} golden {name}")
        document = json.loads(path.read_text())
        if document.get("format") != 1 or not re.fullmatch(r"[0-9a-f]{40}", document.get("go_source", "")):
            raise ValueError(f"{key}: invalid Go recording {name}")
        observation = document.get("observation")
        if route["listener"] == "control":
            if observation["request"]["path"] != route["path"]:
                raise ValueError(f"{key}: golden {name} records another path")
            statuses.add(observation["response"]["status"])
            first = first or (observation["request"]["method"], document["case"])
        else:
            for row in observation:
                statuses.add(row["status"])
    missing = sorted(PLATFORM_LISTENER_FLOOR[route["listener"]] - statuses)
    if missing:
        raise ValueError(f"{key}: {route['listener']} goldens lack recorded statuses {missing}")
    for target, test in PLATFORM_LISTENER_TESTS[route["listener"]]:
        receipt = (f"GOLDEN-REPLAY: {first[0]} {route['path']} :: {first[1]}"
                   if test == "control_socket_matches_recorded_go"
                   else "GOLDEN-REPLAY: control socket :: hardening" if test == "socket_hardening"
                   else "GOLDEN-REPLAY: acme :80 :: http80")
        item = ({"package": "setjoin-gateway", "target": target, "test": test}, receipt)
        if item not in executable:
            executable.append(item)


def check(root, inventory, catalog):
    if inventory.get("version") != 1 or catalog.get("version") != 1:
        raise ValueError("unsupported inventory or oracle catalog version")
    suites = {}
    for suite in catalog["routes"]:
        suites.setdefault(route_key(suite), []).append(suite)
    keys = [route_key(route) for route in inventory["routes"]]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate route inventory entry")
    if suites.keys() - set(keys):
        raise ValueError(f"oracle catalog routes are absent from inventory: {sorted(suites.keys() - set(keys))}")
    executable = []
    coverage_suites = []
    family_mutants = {}
    family_effects = {}
    for route in inventory["routes"]:
        if route["state"] not in ("ON", "OFF"):
            raise ValueError(f"invalid route state for {route_key(route)}")
        if route["listener"] == "asrbot":
            check_asrbot_route(root, route, executable)
            continue
        if route["listener"] in PLATFORM_LISTENER_FLOOR:
            check_platform_listener_route(root, route, executable)
            continue
        on = route["state"] == "ON"
        key = route_key(route)
        candidates = suites.get(key, [{}] if on else [])
        if not candidates:
            continue
        if on and "oracle_commands" in route:
            required = route["oracle_commands"]
            if (not isinstance(required, list) or not required
                    or any(not isinstance(command, str) for command in required)
                    or ("" in required and required != [""])
                    or len(set(required)) != len(required)):
                raise ValueError(f"{key}: invalid oracle command inventory")
            declared = [suite.get("command", "") for suite in candidates]
            if len(set(declared)) != len(declared) or set(declared) != set(required):
                raise ValueError(f"{key}: command inventory {required} does not match catalog {declared}")
            mutators = route.get("oracle_mutators", [])
            if (not isinstance(mutators, list) or any(not isinstance(name, str) for name in mutators)
                    or len(set(mutators)) != len(mutators) or not set(mutators).issubset(required)):
                raise ValueError(f"{key}: invalid mutator inventory")
            for suite in candidates:
                if (suite.get("mutator") is True) != (suite.get("command", "") in mutators):
                    raise ValueError(f"{key}: mutator mismatch for {suite.get('command', '')}")
        for suite in candidates:
            check_suite(root, route, suite, on)
            if not suite.get("cases"):
                continue
            for case in suite["cases"]:
                document = json.loads((root / case["golden"]).read_text())
                if on:
                    effects = family_effects.setdefault(route["family"], {"goldens": 0, "notify": 0, "audit": 0, "state": 0})
                    effects["goldens"] += 1
                    notifications = document["observation"]["notify"]
                    if not isinstance(notifications, list):
                        raise ValueError(f"{key}: recorded notifications must be a list")
                    effects["notify"] += len(notifications)
                    audit = document["observation"]["audit"]
                    if not isinstance(audit, list):
                        raise ValueError(f"{key}: recorded audit rows must be a list")
                    effects["audit"] += len(audit)
                    # Persisted snapshots count even when the legitimate state
                    # stays unchanged: an extra bump must still be observable.
                    effects["state"] += bool(document["observation"]["effects"])
                receipt = f"GOLDEN-REPLAY: {document['route']} :: {document['case']}"
                executable.append((case["replay"], receipt))
            route_name = f"{route['method']} {route['path']}"
            if suite.get("command"):
                route_name += f" {suite['command']}"
            if "mutant" in suite:
                executable.append((suite["mutant"],
                                   f"MUTANT-REJECTED: {route_name} :: {suite['mutant'].get('name', 'mutant')}"))
            coverage_suites.append((route_name, suite))
            for mutant in suite.get("family_mutants", []) if on else []:
                if (not isinstance(mutant, dict) or mutant.get("name") not in FAMILY_MUTANTS
                        or any(not isinstance(mutant.get(field), str)
                               or not re.fullmatch(r"[A-Za-z0-9_-]+", mutant[field])
                               for field in ("package", "target", "test"))):
                    raise ValueError(f"{key}: invalid family mutant")
                family = family_mutants.setdefault(route["family"], {})
                held = family.setdefault(mutant["name"], [])
                if held and (mutant["name"] not in PER_ROUTE_FAMILY_MUTANTS
                             or any(owner == key for _, _, owner in held)):
                    raise ValueError(f"{key}: duplicate family mutant {mutant['name']}")
                held.append((mutant, route_name, key))
        if on and "oracle_commands" not in route:
            raise ValueError(f"{key}: missing command inventory")
        if on and "oracle_mutators" not in route:
            raise ValueError(f"{key}: missing mutator inventory")
    enabled_families = {route["family"] for route in inventory["routes"] if route["state"] == "ON"}
    for family in sorted(enabled_families):
        mutants = family_mutants.get(family, {})
        required = set(FAMILY_MUTANTS)
        effects = family_effects[family]
        if effects["notify"] == 0:
            required.remove("no-notify")
            print(f"{family}: no-notify not-applicable (0 recorded notifications in "
                  f"{effects['goldens']} ON-route goldens)")
        if effects["audit"] == 0:
            required.remove("no-audit")
            print(f"{family}: no-audit not-applicable (0 recorded audit rows in "
                  f"{effects['goldens']} ON-route goldens)")
        if effects["state"] == 0:
            required.remove("double-bump")
            print(f"{family}: double-bump not-applicable (0 recorded state snapshots in "
                  f"{effects['goldens']} ON-route goldens)")
        missing = sorted(required - mutants.keys())
        if missing:
            raise ValueError(f"{family}: missing family mutants: {', '.join(missing)}")
        entries = [(name, mutant, route_name) for name, held in sorted(mutants.items())
                   for mutant, route_name, _ in held]
        selectors = [tuple(mutant[field] for field in ("package", "target", "test"))
                     for _, mutant, _ in entries]
        if len(set(selectors)) != len(selectors):
            raise ValueError(f"{family}: duplicate family mutant selector")
        for name, mutant, route_name in entries:
            executable.append((mutant, f"MUTANT-REJECTED: {route_name} :: {name}"))
    return executable, coverage_suites


FN_ITEM = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:default[ \t]+)?(?:const[ \t]+)?(?:async[ \t]+)?"
                     r"(?:unsafe[ \t]+)?(?:extern[ \t]+\"[^\"]*\"[ \t]+)?fn[ \t]+\w+", re.MULTILINE)


def workspace_packages(root):
    """name -> (directory, {test target: source path}) for every Cargo package under server-rust."""
    packages = {}
    base = root / "server-rust"
    for manifest in sorted(base.rglob("Cargo.toml")):
        relative = manifest.relative_to(base).parts
        if "target" in relative or "node_modules" in relative:
            continue
        try:
            document = tomllib.loads(manifest.read_text())
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        name = document.get("package", {}).get("name")
        if not name:
            continue
        directory = manifest.parent
        targets = {}
        tests = directory / "tests"
        if tests.is_dir():
            for entry in sorted(tests.iterdir()):
                if entry.suffix == ".rs" and entry.is_file():
                    targets[entry.stem] = entry
                elif entry.is_dir() and (entry / "main.rs").is_file():
                    targets[entry.name] = entry / "main.rs"
        for item in document.get("test", []):
            if item.get("name"):
                targets[item["name"]] = directory / item.get("path", f"tests/{item['name']}.rs")
        packages[name] = (directory, targets)
    return packages


def preflight(root, suites, replays):
    """Static checks of the coverage manifest, in seconds, before anything is built: every
    handler source exists and defines functions, and every replay selector (cases, mutants,
    family mutants) names a real package and test target. A route whose replays sit in
    several test binaries is legitimate (their profiles merge), so it is listed, not rejected.
    Returns the error lines; the gate itself still proves each source maps to executed lines."""
    errors = []
    packages = workspace_packages(root)
    resolved = {}

    def resolve(selector, where):
        key = (selector["package"], selector["target"])
        if key not in resolved:
            package = packages.get(key[0])
            if package is None:
                resolved[key] = f"package {key[0]!r} is not in the workspace"
            elif key[1] not in package[1]:
                resolved[key] = f"package {key[0]} has no test target {key[1]!r}"
            elif not package[1][key[1]].is_file():
                resolved[key] = f"test target {key[0]}::{key[1]} source {package[1][key[1]]} is missing"
            else:
                resolved[key] = None
        if resolved[key]:
            errors.append(f"{where}: {resolved[key]}")

    seen_sources = {}
    for route_name, suite in suites:
        sources = suite.get("handler_sources") or []
        for source in sources:
            path = (root / source).resolve()
            if not path.is_relative_to(root.resolve()):
                errors.append(f"{route_name}: handler source {source} is outside the repository")
                continue
            if path not in seen_sources:
                if not path.is_file():
                    seen_sources[path] = "does not exist (moved or renamed? point at the file that holds the handler)"
                elif not FN_ITEM.search(path.read_text(errors="replace")):
                    seen_sources[path] = ("defines no function (a re-export stub or data-only file has no "
                                          "executable lines; point at the file that holds the handler)")
                else:
                    seen_sources[path] = None
            if seen_sources[path]:
                errors.append(f"{route_name}: handler source {source} {seen_sources[path]}")
        for case in suite.get("cases", []):
            resolve(case["replay"], f"{route_name}: replay {case['replay'].get('test')}")
        binaries = {(case["replay"]["package"], case["replay"]["target"]) for case in suite.get("cases", [])}
        if len(binaries) > 1:
            print(f"preflight: {route_name} spans {len(binaries)} test binaries "
                  f"({', '.join(f'{p}::{t}' for p, t in sorted(binaries))}); coverage merges them")
    for selector, receipt in replays:
        resolve(selector, f"replay/mutant {selector.get('test')} ({receipt})")
    return sorted(set(errors))


_REPLAY_BUILT = set()


def run_replay(root, cargo, replay, receipt):
    args = [cargo, "test", "--locked", "--offline", "-p", replay["package"],
            "--test", replay["target"], replay["test"], "--", "--exact", "--nocapture"]
    env = dict(os.environ, REQUIRE_DB="1")
    for name in ("GOFREE_RECORD_UPSTREAM", "GOFREE_RECORD_GO_BINARY", "GOFREE_RECORD_EFFECTS", "GOFREE_GO_SOURCE"):
        env.pop(name, None)
    name = f"{replay['package']}::{replay['target']}::{replay['test']}"
    timeout = int(os.environ.get("LANE_REPLAY_TIMEOUT", "900"))
    # Compile each distinct test target once, outside the timeout: a cold target dir must not
    # time out the first replay (the limit is for the run only).
    target = (replay["package"], replay["target"])
    if target not in _REPLAY_BUILT:
        built = subprocess.run([cargo, "test", "--locked", "--offline", "-p", target[0], "--test", target[1], "--no-run"],
                               cwd=root / "server-rust", env=env, capture_output=True, text=True, check=False)
        if built.returncode:
            raise ValueError(f"replay {name} build failed:\n{(built.stdout + built.stderr)[-4000:]}")
        _REPLAY_BUILT.add(target)
    proc = subprocess.Popen(args, cwd=root / "server-rust", env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # a hung replay would hold the lane until the job timeout: kill its whole process group
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        raise ValueError(f"replay {name} timed out after {timeout}s (LANE_REPLAY_TIMEOUT); "
                         f"last output:\n{(stdout + stderr)[-2000:]}")
    result = subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
    output = result.stdout + result.stderr
    if result.returncode or re.search(r"[A-Z][A-Z0-9-]*-SKIP \(reason=", output):
        raise ValueError(f"replay {replay} failed or skipped:\n{output}")
    if not re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE):
        raise ValueError(f"replay {replay} ran zero or multiple tests:\n{output}")
    receipt_pattern = r"^(?:test [^\n]* \.\.\. )?" + re.escape(receipt) + r"$"
    if not re.search(receipt_pattern, output, re.MULTILINE):
        raise ValueError(f"replay or mutant {replay} did not emit receipt {receipt}")
    print(f"replay PASS {name}", flush=True)


def execute_replays(root, cargo, replays, failures=None):
    """Runs every replay and mutant singly. By default the first failure raises; with a
    `failures` list (--keep-going) each failure is recorded and the run goes on."""
    for replay, receipt in replays:
        try:
            run_replay(root, cargo, replay, receipt)
        except ValueError as error:
            if failures is None:
                raise
            failures.append(("replay/mutant", f"{replay['package']}::{replay['target']}::{replay['test']}", str(error)))
            print(f"replay FAIL {replay['package']}::{replay['target']}::{replay['test']}", flush=True)


def measure_coverage(root, cargo, suites, failures=None, jobs=None):
    """Builds each distinct test binary once, then measures the entries `jobs` at a time.

    The replays of one route may sit in several test binaries; every entry gets all of them
    (report-gofree-oracle-coverage.py merges their profiles). Entries are independent: each
    replay runs in its own cloned database, so running entries side by side changes no result.
    Progress lines every LANE_COVERAGE_HEARTBEAT seconds (default 300) separate a slow run from
    a hung one; one replay is limited by LANE_COVERAGE_REPLAY_TIMEOUT (default 900 s).
    The singly-run replays and mutants (run_replay) build their test target first, then run under
    LANE_REPLAY_TIMEOUT (default 900 s, run time only); a hang is killed and reported by name."""
    env = dict(os.environ, REQUIRE_DB="1")
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
    for name in ("GOFREE_RECORD_UPSTREAM", "GOFREE_RECORD_GO_BINARY", "GOFREE_RECORD_EFFECTS", "GOFREE_GO_SOURCE"):
        env.pop(name, None)
    # Entries side by side need one cloned database per replay (the target runner of the lane);
    # on a single shared database two replays would observe each other's rows. Without that
    # isolation the default is one at a time and asking for more is an error.
    host = next(line.split(": ", 1)[1] for line in subprocess.run(
        ["rustc", "-vV"], capture_output=True, text=True, check=True).stdout.splitlines() if line.startswith("host: "))
    isolated = bool(os.environ.get("CARGO_TARGET_" + host.upper().replace("-", "_") + "_RUNNER")
                    and all(os.environ.get(name) for name in ("LANE_ADMIN_DSN", "LANE_TEMPLATE_DB", "LANE_BASE_DB")))
    wanted = jobs if jobs is not None else int(os.environ.get("LANE_COVERAGE_JOBS", "0"))
    if wanted > 1 and not isolated:
        raise ValueError("parallel coverage needs per-replay database clones (CARGO_TARGET_<triple>_RUNNER and "
                         "LANE_ADMIN_DSN/LANE_TEMPLATE_DB/LANE_BASE_DB); run with --coverage-jobs 1 here")
    jobs = wanted or ((os.cpu_count() or 1) if isolated else 1)
    # Instrumented Cargo build scripts execute during compilation. Their
    # profiles are not replay coverage and must never land in the worktree.
    with tempfile.TemporaryDirectory(prefix="gofree-oracle-build-") as directory:
        env["LLVM_PROFILE_FILE"] = str(Path(directory) / "%p-%m.profraw")
        return measure_suites(root, cargo, suites, env, failures, jobs)


def suite_targets(suite):
    targets = []
    for case in suite["cases"]:
        target = (case["replay"]["package"], case["replay"]["target"])
        if target not in targets:
            targets.append(target)
    return targets


def build_binary(root, cargo, target, env):
    """The instrumented test executable of one (package, target); a ValueError text on failure."""
    command = [cargo, "test", "--locked", "--offline", "-p", target[0], "--test", target[1],
               "--no-run", "--message-format=json"]
    result = subprocess.run(command, cwd=root / "server-rust", env=env,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        diagnostics = []
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-message":
                diagnostics.append(item.get("message", {}).get("rendered") or "")
        raise ValueError(f"coverage build failed:\n{''.join(diagnostics)}{result.stderr}")
    artifacts = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == target[1]
                and "test" in item.get("target", {}).get("kind", []) and item.get("executable")):
            artifacts.append(item["executable"])
    if len(artifacts) != 1 or not Path(artifacts[0]).is_file():
        raise ValueError("coverage binary missing or ambiguous")
    return artifacts[0]


def load_serial_groups(root):
    """binary id -> serial test group, read from the nextest group config the lane generates
    (`scripts/server-rust-lane-groups.py`, its TOML output): one source of truth, so the
    coverage stage serialises exactly what the nextest run serialises. A group is a set of
    binaries that share host state (fixed ports, docker, /tmp names), `max-threads = 1`."""
    script = Path(__file__).with_name("server-rust-lane-groups.py")
    result = subprocess.run([sys.executable, str(script), "--root", str(root / "server-rust")],
                            cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"serial group config failed:\n{result.stdout}{result.stderr}")
    document = tomllib.loads(result.stdout)
    serial = set(document.get("test-groups", {}))
    groups = {}
    for override in document.get("profile", {}).get("lane", {}).get("overrides", []):
        group = override.get("test-group")
        if group in serial:
            for binary in re.findall(r"binary_id\(=([^)\s]+)\)", override.get("filter", "")):
                groups[binary] = group
    if not groups:
        raise ValueError("serial group config names no binaries; refusing to run entries side by side")
    return groups


def entry_groups(suite, groups):
    """Every serial group any test binary of the entry is in: it holds all of them while it runs."""
    return frozenset(groups[f"{package}::{target}"] for package, target in suite_targets(suite)
                     if f"{package}::{target}" in groups)


def run_grouped(items, jobs, work):
    """Runs work(item_index) for every (index, groups) in items, `jobs` at a time, never two at
    once whose groups intersect (they share host state). Entries holding no group, or different
    groups, overlap freely. Yields work's results as they finish."""
    pending = list(items)
    held = set()
    running = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        while pending or running:
            index = 0
            while len(running) < jobs and index < len(pending):
                item, groups = pending[index]
                if groups & held:
                    index += 1
                    continue
                pending.pop(index)
                held |= groups
                running[pool.submit(work, item)] = groups
            if not running:
                raise RuntimeError("scheduler stalled")  # unreachable: nothing held means anything can start
            done, _ = concurrent.futures.wait(running, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                held -= running.pop(future)
                yield future.result()


def measure_suites(root, cargo, suites, env, failures=None, jobs=1):
    wanted = []
    for _, suite in suites:
        for target in suite_targets(suite):
            if target not in wanted:
                wanted.append(target)
    binaries = {}
    build_errors = {}
    started = time.monotonic()
    for number, target in enumerate(wanted, 1):
        try:
            binaries[target] = build_binary(root, cargo, target, env)
        except ValueError as error:
            build_errors[target] = str(error)
        print(f"coverage build {number}/{len(wanted)} {target[0]}::{target[1]} "
              f"({time.monotonic() - started:.0f}s)", flush=True)
    state = {"done": 0, "failed": 0, "running": {}}
    lock = threading.Lock()
    stop = threading.Event()
    heartbeat = float(os.environ.get("LANE_COVERAGE_HEARTBEAT", "300"))

    def beat():
        while not stop.wait(heartbeat):
            with lock:
                now = time.monotonic()
                running = ", ".join(f"{name} {now - since:.0f}s" for name, since in sorted(state["running"].values()))
                print(f"coverage progress {state['done']}/{len(suites)} done, {state['failed']} failed, "
                      f"{now - started:.0f}s elapsed; running: {running or 'none'}", flush=True)

    def one(index, route_name, suite):
        with lock:
            state["running"][index] = (route_name, time.monotonic())
        lines = []
        try:
            report = measure_one(root, route_name, suite, binaries, build_errors, lines)
            return index, route_name, report, lines, None
        except ValueError as error:
            return index, route_name, None, lines, str(error)
        finally:
            with lock:
                state["running"].pop(index, None)

    results = []
    watcher = threading.Thread(target=beat, daemon=True)
    watcher.start()
    serial = load_serial_groups(root) if jobs > 1 else {}
    items = [(index, entry_groups(suite, serial)) for index, (_, suite) in enumerate(suites)]
    if jobs > 1:
        held = sum(1 for _, groups in items if groups)
        print(f"coverage schedule: {len(suites)} entries, {jobs} at a time, {held} in serial groups "
              f"({len({g for _, groups in items for g in groups})} groups; entries sharing one never overlap)", flush=True)
    try:
        for index, route_name, report, lines, error in run_grouped(
                items, jobs, lambda index: one(index, *suites[index])):
            with lock:
                state["done"] += 1
                state["failed"] += error is not None
                for line in lines:
                    print(line, flush=True)
                if error is not None:
                    print(f"coverage FAIL {route_name}", flush=True)
            results.append((index, route_name, report, error))
            if error is not None and failures is None:
                raise ValueError(f"{route_name}: {error}")
    finally:
        stop.set()
    reports = []
    for index, route_name, report, error in sorted(results, key=lambda item: item[0]):
        if error is not None:
            failures.append(("coverage", route_name, f"{route_name}: {error}"))
        else:
            reports.append(report)
    return reports


def measure_one(root, route_name, suite, binaries, build_errors, lines):
    selectors = [case["replay"] for case in suite["cases"]]
    command_binaries = []
    for target in suite_targets(suite):
        if target in build_errors:
            raise ValueError(build_errors[target])
        command_binaries.append(binaries[target])
    sources = suite.get("handler_sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("missing handler coverage sources")
    command = [sys.executable, str(Path(__file__).with_name("report-gofree-oracle-coverage.py")),
               "--route", route_name]
    for source in sources:
        path = (root / source).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError(f"invalid handler coverage source {source}")
        command.extend(["--source", str(path)])
    for selector in selectors:
        command.extend(["--case", binaries[(selector["package"], selector["target"])], selector["test"]])
    result = subprocess.run(command, cwd=root, env=dict(os.environ, REQUIRE_DB="1"), capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"coverage failed:\n{result.stdout}{result.stderr}")
    report = json.loads(result.stdout)
    for file in report["files"]:
        file_lines, regions = file["lines"], file["regions"]
        lines.append(f"coverage {route_name} {file['file']}: lines {file_lines['covered']}/{file_lines['count']}; "
                     f"regions {regions['covered']}/{regions['count']}")
    return report


def check_suite(root, route, suite, on):
    key = (*route_key(route), suite.get("command", ""))
    sources = suite.get("handler_sources")
    if sources is not None and (not isinstance(sources, list) or not sources
                                or any(not isinstance(source, str) or not source for source in sources)):
        raise ValueError(f"{key}: invalid handler coverage sources: expected nonempty path strings")
    present = {case["kind"] for case in suite.get("cases", [])}
    required = (FLOOR | ({"repeat"} if suite.get("mutator") is True else set())) if on else set()
    missing = sorted(required - present)
    if missing:
        raise ValueError(f"{key}: missing recorded cases: {', '.join(missing)}")
    recordings = set()
    for case in suite["cases"]:
        recording = (root / case["golden"]).resolve()
        if not recording.is_relative_to(root.resolve()) or not recording.is_file():
            raise ValueError(f"{key}: missing recording for {case['kind']}: {recording}")
        if recording in recordings:
            raise ValueError(f"{key}: duplicate recording: {recording}")
        recordings.add(recording)
        document = json.loads(recording.read_text())
        observation = document.get("observation", {})
        request = observation.get("request", {})
        response = observation.get("response", {})
        expected_route = f"{route['method']} {route['path']}"
        if suite.get("command"):
            expected_route += f" {suite['command']}"
        recorded_route = document.get("route", "")
        if (document.get("format") != 1
                or not isinstance(recorded_route, str)
                or recorded_route != expected_route
                or not isinstance(document.get("case"), str) or not document["case"]
                or not re.fullmatch(r"[0-9a-f]{40}", document.get("go_source", ""))
                or request.get("method") != route["method"] or request.get("path") != route["path"]
                or not isinstance(response.get("status"), int)
                or not 100 <= response["status"] <= 599
                or not all(field in observation for field in ("effects", "audit", "notify"))):
            raise ValueError(f"{key}: invalid Go recording: {recording}")
        if suite.get("mutator") is True:
            row_name = case.get("row_golden")
            if not isinstance(row_name, str):
                raise ValueError(f"{key}: missing row effect recording for {document['case']}")
            row_path = (root / row_name).resolve()
            if not row_path.is_relative_to(root.resolve()) or not row_path.is_file():
                raise ValueError(f"{key}: missing row effect recording: {row_path}")
            row_document = json.loads(row_path.read_text())
            if (row_document.get("format") != 1 or row_document.get("route") != recorded_route
                    or row_document.get("case") != document["case"] + "-row-effects"
                    or row_document.get("go_source") != document["go_source"]
                    or not isinstance(row_document.get("effects"), list)):
                raise ValueError(f"{key}: invalid row effect recording: {row_path}")
    selectors = set()
    for case in suite["cases"]:
        replay = case.get("replay", {})
        if (not isinstance(replay, dict)
                or any(not isinstance(replay.get(field), str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]+", replay[field])
                       for field in ("package", "target", "test"))):
            raise ValueError(f"{key}: missing executable replay selector for {case['kind']}")
        selector = tuple(replay[field] for field in ("package", "target", "test"))
        if selector in selectors:
            raise ValueError(f"{key}: duplicate replay selector {selector}")
        selectors.add(selector)
    mutant = suite.get("mutant")
    if not on and mutant is None:
        return
    if mutant is None:
        mutant = {}
    if (not isinstance(mutant, dict)
            or any(not isinstance(mutant.get(field), str)
                   or not re.fullmatch(r"[A-Za-z0-9_-]+", mutant[field])
                   for field in ("package", "target", "test"))):
        raise ValueError(f"{key}: missing executable mutant self-test")
    if tuple(mutant[field] for field in ("package", "target", "test")) in selectors:
        raise ValueError(f"{key}: mutant self-test duplicates a replay")


def report_failures(failures):
    print(f"\ngofree-oracle-adequacy: {len(failures)} FAILED")
    for stage, name, detail in failures:
        lines = detail.strip().splitlines()
        tail = "\n".join(lines[-40:])
        print(f"\n--- {stage} {name} ---\n{tail}")
    print("\ngofree-oracle-adequacy: FAILED (" + ", ".join(f"{stage} {name}" for stage, name, _ in failures) + ")")


STAGES = ("replays", "coverage")


def receipt_entry(receipt):
    """The route entry a replay or mutant receipt belongs to: 'GOLDEN-REPLAY: GET /x :: case'
    and 'MUTANT-REJECTED: GET /x :: name' name it; platform-listener receipts name no entry."""
    head = receipt.split(": ", 1)[1] if ": " in receipt else receipt
    return head.rsplit(" :: ", 1)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--coverage-output", type=Path)
    parser.add_argument("--coverage-jobs", type=int, default=None,
                        help="entries measured side by side (default: LANE_COVERAGE_JOBS or the CPU count)")
    parser.add_argument("--only", metavar="STAGES",
                        help="subset run, never a lane result: comma list of stages to run, from "
                             f"{', '.join(STAGES)} (replays = replays and mutants); the full gate is the default")
    parser.add_argument("--entries", metavar="ROUTES",
                        help="with --only: comma list of route entries to restrict the stages to, e.g. "
                             "'GET /health,POST /auth/login' (a replay belongs to the entry its receipt names)")
    parser.add_argument("--preflight-only", action="store_true",
                        help="run only the static manifest checks and exit")
    parser.add_argument("--skip-preflight", action="store_true",
                        help="gate self-tests with synthetic roots only; the lane never passes it")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--keep-going", action="store_true",
                        help="run every replay, every mutant and then coverage, print all failures "
                             "at the end and exit non-zero if any failed (default: stop at the first)")
    args = parser.parse_args()
    inventory = args.inventory or args.root / "server-rust/bins/gateway/route-inventory.json"
    catalog = args.catalog or args.root / "server-rust/tests/conformance/route-catalog.json"
    if args.only is not None:
        stages = [name.strip() for name in args.only.split(",") if name.strip()]
        unknown = sorted(set(stages) - set(STAGES))
        if not stages or unknown:
            parser.error(f"--only takes stages from {', '.join(STAGES)}; got {args.only!r}")
        if args.execute or args.coverage:
            parser.error("--only replaces --execute and --coverage")
        args.execute, args.coverage = "replays" in stages, "coverage" in stages
    elif args.entries is not None:
        parser.error("--entries needs --only")
    elif args.coverage and not args.execute:
        parser.error("--coverage requires --execute")
    entries = None
    if args.entries is not None:
        entries = {name.strip() for name in args.entries.split(",") if name.strip()}
        if not entries:
            parser.error("--entries names no route entry")
    replays, suites = check(args.root, json.loads(inventory.read_text()), json.loads(catalog.read_text()))
    if not args.skip_preflight:
        errors = preflight(args.root, suites, replays)
        if errors:
            print("gofree-oracle-adequacy: PREFLIGHT FAILED (static manifest checks, nothing was built)")
            for error in errors:
                print(f"  {error}")
            sys.exit(1)
        print(f"gofree-oracle-adequacy: preflight ok ({len(suites)} coverage entries, {len(replays)} replays)")
    if args.preflight_only:
        return
    if entries is not None:
        known = {name for name, _ in suites} | {receipt_entry(receipt) for _, receipt in replays}
        unknown = sorted(entries - known)
        if unknown:
            parser.error(f"unknown route entries: {unknown}")
        replays = [(replay, receipt) for replay, receipt in replays if receipt_entry(receipt) in entries]
        suites = [(name, suite) for name, suite in suites if name in entries]
        print(f"gofree-oracle-adequacy: SUBSET RUN (stages {args.only}; {len(replays)} replays, "
              f"{len(suites)} coverage entries) — not a lane result", flush=True)
    elif args.only is not None:
        print(f"gofree-oracle-adequacy: SUBSET RUN (stages {args.only}) — not a lane result", flush=True)
    failures = [] if args.keep_going else None
    if args.execute:
        started = time.monotonic()
        execute_replays(args.root, args.cargo, replays, failures)
        print(f"gofree-oracle-adequacy: replays and mutants took {time.monotonic() - started:.0f}s", flush=True)
    if args.coverage:
        started = time.monotonic()
        reports = measure_coverage(args.root, args.cargo, suites, failures, args.coverage_jobs)
        print(f"gofree-oracle-adequacy: coverage took {time.monotonic() - started:.0f}s", flush=True)
        if args.coverage_output:
            args.coverage_output.write_text(json.dumps(reports, indent=2) + "\n")
    if failures:
        report_failures(failures)
        sys.exit(1)
    print("gofree-oracle-adequacy: PASS" + (" (subset)" if args.only is not None else ""))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        sys.exit(str(error))
