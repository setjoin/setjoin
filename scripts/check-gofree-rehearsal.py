#!/usr/bin/env python3
"""Go-deletion dress rehearsal guard (#141): every Setjoin test seam runs with Go stopped.

  check-gofree-rehearsal.py static        inventory ON (fedharness excluded, PENDING ratchet), no ON
                                          route proxies to Go, forward-to-Go call sites (FORWARD_SITES
                                          ratchet), every accepted divergence reviewed, worker_semantics.json
                                          owned by Rust, every seam present
  check-gofree-rehearsal.py env           red if a Go upstream or Go recording variable is present, or (with
                                          LANE_GO_MASKED=1) if a Go toolchain is reachable
  check-gofree-rehearsal.py watch FILE --ready PATH
                                          record container create/start/exec and image events into FILE until
                                          SIGTERM, with image identities, a container snapshot and a Go-ELF
                                          scan at ready and stop; PATH appears once the event stream is proven
                                          live (scripts/check-server-rust.sh lane_go_watch)
  check-gofree-rehearsal.py containers [--require-masked] FILE...
                                          red on an incomplete watch, an unpinned or mutated image, a Go-capable
                                          container outside GO_TASKS, or an unallowed Go ELF
  check-gofree-rehearsal.py lane DIR --shards N --coverage-shards M
                                          the aggregate job: static, every shard watched with Go masked, no
                                          Go launch, no route whose handler sources all report 0 covered lines

Self-test: python3 scripts/test-check-gofree-rehearsal.py. Contract: server-rust/DOX.md#go-deletion-rehearsal-141.
"""
import argparse
import json
import os
import queue
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "server-rust/bins/gateway/route-inventory.json"
WORKERS = "mailserver/cmd/mailserverd/testdata/worker_semantics.json"

# Owner decision 2026-11-02 (#141): the fedharness test-tool listener is test tooling, not shipped behaviour.
EXCLUDED_LISTENERS = {"fedharness"}
# Inventory entries still OFF, with the ticket that turns each ON. Ratchet: an entry that turns ON or
# leaves the inventory must be deleted here; never add one. #141 criterion 1 holds only when this is empty.
PENDING = {
    ("auth", "GET", "/auth/guest-invite/accept"): "#342",
    ("auth", "POST", "/auth/guest-invite/accept"): "#342",
    ("auth", "GET", "/device/policy"): "#341",
    ("auth", "POST", "/device/checkin"): "#341",
    ("gateway", "*", "/auth/admin/"): "#340",
    ("gateway", "GET", "/auth/guest-invite/accept"): "#342",
    ("gateway", "POST", "/auth/guest-invite/accept"): "#342",
    ("gateway", "GET", "/setup/status"): "#340",
    ("gateway", "GET", "/terms/pending"): "#340",
    ("gateway", "POST", "/terms/accept"): "#340",
}
# Call sites in server-rust/bins/*/src that forward a request to a Go upstream: the auth server's
# `self.forward(` to Go auth, the gateway's `upstream.forward(` proxy, `forward_body(`, and the JMAP
# WebSocket fallback (`forward_unported(`, its raw `client_async(` dial). Exact ratchet: a new site is
# red; a removed site is red until the pin is lowered. #141 criterion 4 holds only when every count is 0.
FORWARD_PATTERNS = {
    "forward": re.compile(r"\.forward\("),
    "forward_body": re.compile(r"(?<!fn )\bforward_body\("),
    "forward_unported": re.compile(r"(?<!fn )\bforward_unported\("),
    "ws_client": re.compile(r"\bclient_async\("),
}
FORWARD_SITES = {
    ("auth", "forward"): 60,
    ("gateway", "forward"): 197,
    ("gateway", "forward_body"): 3,
    ("gateway", "forward_unported"): 1,
    ("gateway", "ws_client"): 1,
}
# The Go background workers (worker_semantics.json). The owner counted 49 on 2026-11-02; the file now
# lists 51. A change here goes with the #141 evidence checklist.
EXPECTED_WORKERS = 51
# Go workers with no separately switchable Rust worker of the same name: process plumbing the Rust
# process does itself.
INTRINSIC_WORKERS = {
    "config-reload": "gateway config reload (server-rust/bins/gateway/tests/gateway_config_runtime.rs)",
    "db-listener": "direct LISTEN connection (server-rust/crates/pg/src/workers.rs)",
    "auth-chain-reload": "shared authorize chain reload (server-rust/crates/authz/src/auth_chain.rs)",
}
# The seams #141 names, each a set of workspace test files the hosted lane runs (nextest, every test
# exactly once, scripts/merge-lane-shards.py). Each pattern must match at least one file.
SEAMS = {
    "front-door goldens": ["server-rust/bins/gateway/tests/*_recorded.rs", "server-rust/bins/auth/tests/*.rs"],
    "IMAP transcripts and interop": ["server-rust/crates/protocols/imap/tests/replay.rs",
                                     "server-rust/crates/protocols/imap/tests/interop.rs"],
    "SMTP transcripts and interop": ["server-rust/crates/protocols/smtp/tests/session.rs",
                                     "server-rust/crates/protocols/smtp/tests/interop.rs"],
    "DAV": ["server-rust/bins/gateway/tests/caldav.rs", "server-rust/bins/gateway/tests/carddav.rs"],
    "LDAP": ["server-rust/crates/protocols/ldap/tests/interop.rs"],
    "JMAP": ["server-rust/bins/gateway/tests/jmap_*.rs"],
    "worker oracles": ["server-rust/bins/gateway/tests/*_startup.rs", "server-rust/bins/gateway/tests/*worker*.rs"],
    "binary process-boundary oracles": ["server-rust/bins/gateway/tests/startup.rs",
                                        "server-rust/bins/updater/tests/*.rs", "server-rust/bins/mailctl/tests/*.rs"],
}
# Present at all (even empty) is red: tests read several of these with `var_os(..).is_some()`.
FORBIDDEN_ENV = re.compile(r"^(GOFREE_RECORD\w*|GOFREE_GO_SOURCE|GOFREE_GO_COVERAGE_DIR|GOFREE_\w*SWAP_UPSTREAM"
                           r"|GATEWAY_UPSTREAM|GATEWAY_AUTH_UPSTREAM|AUTHSERVER_GO_UPSTREAM|AUTHSERVER_URL)$")
GO_TOOLCHAIN = "/usr/local/go/bin/go"
IMAGES_LOCK = ".github/ci/images.lock"
# images.lock entries (local name) that carry the Go toolchain; the lane image is built FROM the CI image.
GO_IMAGES = ("setjoin-ci-linux-tc", "setjoin-server-rust-lane")
# Reviewed tasks allowed to create, start or exec into a Go-capable container during the lane.
GO_TASKS = {
    "gofree-fed2": "go: fedharness interop peer, build and run (owner decision 2026-11-02: test tooling)",
    "gofree-tlsfront": "go: frozen Go TLS client peer of the TLS front interchange replay",
    "gofree-rel3": "no Go (reviewed scripts): bash runs the Rust setjoin-updater installer/office oracles",
}
PROBE_TASK = "gofree-rehearsal-probe"
LANE_LABEL, LANE_NAME = "setjoin-lane-run", "setjoin-lane-run-"
CONTAINER_ACTIONS = {"create", "start", "exec_create", "exec_start", "existing"}
IMAGE_MUTATIONS = {"tag", "untag", "delete", "load", "import"}
DOCKER_TIMEOUT = 60
# Go-built executables allowed to exist where the lane container can execute them.
GO_ELF_ALLOW = {
    "/usr/local/bin/docker": "host docker CLI (bind mount in scripts/lane-container.sh)",
    "/usr/local/bin/pebble": "pinned ACME test server (scripts/server-rust-lane-tools.sh)",
}
TLS_PEER = "test-results/gofree-tlsfront/gofree-tlsfront-peer"
FEDHARNESS_BUILD = re.compile(r"/gofree-fed2-peer-\d+/fedharness$")
# Every source reference to a frozen Go peer binary, pinned per file. Each reviewed reference runs the
# binary only inside its labelled sibling container (container paths /src/..., /output/..., absent in the
# lane container) or only checks it exists; a new reference is red until reviewed.
GO_PEER_PATTERN = re.compile(r"gofree-tlsfront-peer|/fedharness\b")
GO_PEER_REFERENCES = {
    "server-rust/crates/protocols/federation/tests/interop.rs": 3,
    "server-rust/tests/conformance/tlsfront/build-peer.py": 3,
    "server-rust/tests/conformance/tlsfront/peer.rs": 2,
}
COVERAGE_LINE = re.compile(r"^coverage (?P<route>.+) (?P<file>[^ ]+): lines (?P<covered>\d+)/(?P<count>\d+); regions")
PRUNE = {"target", "node_modules", ".git"}


def walk(root, suffix):
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in PRUNE)
        for name in sorted(files):
            if name.endswith(suffix):
                yield Path(directory) / name


def inventory_problems(root):
    routes = json.loads((root / INVENTORY).read_text())["routes"]
    problems, pending, on, excluded = [], set(), set(), 0
    for route in routes:
        key = (route["listener"], route["method"], route["path"])
        if route["listener"] in EXCLUDED_LISTENERS:
            excluded += 1
            continue
        if route["state"] == "ON":
            on.add(key)
            if route["upstream"].startswith("go-"):
                problems.append(f"{key}: ON with upstream {route['upstream']} (the gateway would proxy it to Go)")
            if key in PENDING:
                problems.append(f"{key}: now ON; delete it from PENDING in scripts/check-gofree-rehearsal.py")
        elif key in PENDING:
            pending.add(key)
        else:
            problems.append(f"{key}: {route['state']} and not in PENDING (every inventory entry must be ON)")
    for key in sorted(set(PENDING) - pending - on):
        problems.append(f"{key}: no longer in the inventory; delete it from PENDING")
    return problems, {"routes": len(routes), "on": len(on), "excluded": excluded, "pending": sorted(pending)}


def forward_sites(root):
    counts = {}
    for path in sorted((root / "server-rust/bins").glob("*/src/**/*.rs")):
        binary = path.relative_to(root / "server-rust/bins").parts[0]
        text = path.read_text(errors="ignore")
        for kind, pattern in FORWARD_PATTERNS.items():
            found = len(pattern.findall(text))
            if found:
                counts[(binary, kind)] = counts.get((binary, kind), 0) + found
    return counts


def forward_problems(root):
    counts, problems = forward_sites(root), []
    for key in sorted(set(counts) | set(FORWARD_SITES)):
        now, pinned = counts.get(key, 0), FORWARD_SITES.get(key, 0)
        if now > pinned:
            problems.append(f"forward-to-Go sites {key[0]}/{key[1]}: {now} > pinned {pinned} (no new Go forwarding)")
        elif now < pinned:
            problems.append(f"forward-to-Go sites {key[0]}/{key[1]}: {now} < pinned {pinned}; lower FORWARD_SITES")
    return problems, counts


def divergence_problems(root):
    problems, files, entries = [], 0, 0
    for path in walk(root / "server-rust", "divergences.json"):
        files += 1
        document = json.loads(path.read_text())
        items = document.items() if isinstance(document, dict) else enumerate(document)
        name = path.relative_to(root)
        for key, entry in items:
            entries += 1
            if not isinstance(entry, dict):
                problems.append(f"{name} [{key}]: not an object")
                continue
            approval = [entry.get(field) for field in ("reviewer", "review", "review_reference")]
            if "reviewed" in entry:
                if entry["reviewed"] is not True:
                    problems.append(f"{name} [{key}]: reviewed is {entry['reviewed']!r}")
                elif not any(isinstance(value, str) and value.strip() for value in approval):
                    problems.append(f"{name} [{key}]: reviewed without reviewer, review or review_reference")
            elif not (isinstance(entry.get("review"), str) and re.search(r"owner-(approved|requested)", entry["review"])):
                problems.append(f"{name} [{key}]: no reviewed flag and no owner-approved/owner-requested review")
    return problems, {"files": files, "entries": entries}


def worker_problems(root):
    names = [worker["name"] for worker in json.loads((root / WORKERS).read_text())["workers"]]
    problems = []
    if len(set(names)) != len(names):
        problems.append(f"{WORKERS}: duplicate worker names")
    if len(names) != EXPECTED_WORKERS:
        problems.append(f"{WORKERS}: {len(names)} workers, expected {EXPECTED_WORKERS}; update EXPECTED_WORKERS "
                        "and the #141 evidence checklist together")
    rust = "\n".join(path.read_text(errors="ignore") for path in walk(root / "server-rust", ".rs")
                     if "tests" not in path.relative_to(root).parts)
    for name in names:
        literal = f'"{name}"' in rust
        if name in INTRINSIC_WORKERS:
            if literal:
                problems.append(f"worker {name}: Rust now names it; delete it from INTRINSIC_WORKERS")
        elif not literal:
            problems.append(f"worker {name}: no Rust worker of that name in server-rust (non-test source)")
    for name in sorted(set(INTRINSIC_WORKERS) - set(names)):
        problems.append(f"worker {name}: not in {WORKERS}; delete it from INTRINSIC_WORKERS")
    return problems, names


def seam_problems(root):
    problems, counts = [], {}
    for seam, patterns in SEAMS.items():
        counts[seam] = 0
        for pattern in patterns:
            found = sorted(root.glob(pattern))
            if not found:
                problems.append(f"seam {seam}: {pattern} matches no file")
            counts[seam] += len(found)
    return problems, counts


def peer_reference_problems(root):
    counts = {}
    for suffix in (".rs", ".py", ".sh"):
        for path in walk(root / "server-rust", suffix):
            found = len(GO_PEER_PATTERN.findall(path.read_text(errors="ignore")))
            if found:
                counts[str(path.relative_to(root))] = found
    problems = [f"frozen Go peer references in {name}: {counts.get(name, 0)}, pinned {GO_PEER_REFERENCES.get(name, 0)}; "
                "review that the peer runs only inside its labelled container, then update GO_PEER_REFERENCES"
                for name in sorted(set(counts) | set(GO_PEER_REFERENCES))
                if counts.get(name, 0) != GO_PEER_REFERENCES.get(name, 0)]
    return problems, sum(counts.values())


def static(root):
    problems, lines = [], []
    found, inv = inventory_problems(root)
    problems += found
    lines.append(f"inventory: {inv['routes']} entries, {inv['on']} ON, {inv['excluded']} fedharness excluded, "
                 f"{len(inv['pending'])} pending")
    for key in inv["pending"]:
        lines.append(f"REHEARSAL-PENDING (criterion 1 open): {' '.join(key)} -> {PENDING[key]}")
    found, sites = forward_problems(root)
    problems += found
    lines.append(f"REHEARSAL-FORWARD-SITES (criterion 4 open until 0): {sum(sites.values())} "
                 f"({', '.join(f'{b}/{k} {n}' for (b, k), n in sorted(sites.items()))})")
    found, references = peer_reference_problems(root)
    problems += found
    lines.append(f"frozen Go peer references: {references} (pinned, container-internal)")
    found, div = divergence_problems(root)
    problems += found
    lines.append(f"divergences: {div['entries']} entries in {div['files']} files, every one reviewed"
                 if not found else f"divergences: {len(found)} unreviewed")
    found, names = worker_problems(root)
    problems += found
    lines.append(f"workers: {len(names)} Go workers, {len(names) - len(INTRINSIC_WORKERS)} named Rust workers, "
                 f"{len(INTRINSIC_WORKERS)} process-intrinsic ({', '.join(sorted(INTRINSIC_WORKERS))})")
    lines.append("GO_WORKERS_OFF=" + ",".join(names))
    found, seams = seam_problems(root)
    problems += found
    lines.append("seams: " + "; ".join(f"{seam} {count} files" for seam, count in seams.items()))
    return problems, lines


def go_reachable():
    return shutil.which("go") is not None or os.path.exists(GO_TOOLCHAIN)


def env_problems(environ, reachable):
    problems = [f"{name} is present" for name in sorted(environ) if FORBIDDEN_ENV.match(name)]
    if environ.get("LANE_GO_MASKED") == "1" and reachable:
        problems.append("LANE_GO_MASKED=1 but a Go toolchain is reachable (go on PATH or /usr/local/go/bin/go)")
    return problems


def is_go_elf(path):
    """True when PATH is an ELF64 executable with a .go.buildinfo section (any Go-built binary)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(64)
            if len(head) < 64 or head[:4] != b"\x7fELF" or head[4] != 2:
                return False
            order = "<" if head[5] == 1 else ">"
            (shoff,) = struct.unpack_from(order + "Q", head, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", head, 0x3A)
            if not shoff or not shnum or shstrndx >= shnum:
                return False
            handle.seek(shoff + shstrndx * shentsize + 0x18)
            offset, size = struct.unpack(order + "QQ", handle.read(16))
            handle.seek(offset)
            return b".go.buildinfo\x00" in handle.read(min(size, 1 << 20))
    except (OSError, struct.error):
        return False


def go_elves(top="/"):
    """Every executable Go-built ELF under TOP. TOP "/" is the whole lane container (its image, the
    workspace, $HOME, /tmp, the build and cache dirs), skipping /proc, /sys and /dev except /dev/shm."""
    found = []
    for start in [top] + (["/dev/shm"] if top == "/" else []):
        for directory, dirs, files in os.walk(start):
            if directory == "/":
                dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in files:
                path = os.path.join(directory, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and is_go_elf(path):
                    found.append(path)
    return sorted(found)


def elf_allowed(path, root):
    return path in GO_ELF_ALLOW or path == str(Path(root) / TLS_PEER) or FEDHARNESS_BUILD.search(path) is not None


class WatchError(Exception):
    pass


def docker(*args, timeout=DOCKER_TIMEOUT):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as error:
        return subprocess.CompletedProcess(["docker", *args], 124, "", str(error))


def normalize(ref):
    return ref if "@" in ref or ":" in ref.rsplit("/", 1)[-1] else ref + ":latest"


def lock_entries(root):
    entries = []
    for line in (Path(root) / IMAGES_LOCK).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            entries.append(tuple(line.split("=", 1)))
    return entries


def image_identities(root):
    """Image id of every images.lock name and pinned reference; a tag that does not resolve to its pinned
    digest's image is a problem."""
    images, problems = {}, []
    for want, pinned in lock_entries(root):
        ids = {}
        for ref in dict.fromkeys((want, pinned)):
            result = docker("image", "inspect", "--format", "{{.Id}}", ref)
            if result.returncode:
                problems.append(f"image {ref}: not present ({result.stderr.strip()[:200]})")
            else:
                ids[normalize(ref)] = result.stdout.strip()
        if len(set(ids.values())) > 1:
            problems.append(f"image {want}: tag and pinned digest resolve to different images {ids}")
        images.update(ids)
    return images, problems


def go_image_ids(root, images):
    return {images[normalize(ref)] for want, pinned in lock_entries(root) if want.startswith(GO_IMAGES)
            for ref in (want, pinned) if normalize(ref) in images}


def container_record(kind, cid, name, image, labels):
    return {"kind": kind, "id": cid[:12], "name": name, "image": image,
            "task": labels.get("org.setjoin.task", ""), "lane": LANE_LABEL in labels and name.startswith(LANE_NAME)}


def existing_containers():
    result = docker("ps", "-a", "--no-trunc", "--format", "{{json .}}")
    if result.returncode:
        raise WatchError(f"docker ps failed: {result.stderr.strip()[:200]}")
    records = []
    for line in result.stdout.splitlines():
        row = json.loads(line)
        labels = dict(item.split("=", 1) for item in (row.get("Labels") or "").split(",") if "=" in item)
        records.append(container_record("existing", row.get("ID", ""), row.get("Names", ""), row.get("Image", ""), labels))
    return records


def event_record(event):
    actor = event.get("Actor") or {}
    attributes = actor.get("Attributes") or {}
    action = (event.get("Action") or event.get("status") or "").split(":", 1)[0].strip()
    if event.get("Type") == "image":
        return {"kind": "image", "action": action, "ref": attributes.get("name") or actor.get("ID") or ""}
    return container_record(action, actor.get("ID") or event.get("id") or "", attributes.get("name", ""),
                            attributes.get("image", event.get("from", "")), attributes)


def probe(tag):
    name = f"{PROBE_TASK}-{os.getpid()}-{tag}"
    image = os.environ.get("LANE_IMAGE") or "setjoin-ci-linux-tc:local-amd64"
    created = docker("create", "--name", name, "--label", f"org.setjoin.task={PROBE_TASK}", image, "true")
    if created.returncode:
        raise WatchError(f"probe {name}: docker create failed ({created.stderr.strip()[:200]})")
    removed = docker("rm", "-f", name)
    if removed.returncode:
        raise WatchError(f"probe {name}: docker rm failed ({removed.stderr.strip()[:200]})")
    return name


def remove_probes():
    listed = docker("ps", "-aq", "--filter", f"label=org.setjoin.task={PROBE_TASK}",
                    "--filter", f"name={PROBE_TASK}-{os.getpid()}-")
    for cid in listed.stdout.split():
        docker("rm", "-f", cid)


def stop_events(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def watch(path, ready):
    """Ready only after a probe container's create event came back through the stream; then the image
    identities, a snapshot of every existing container and a Go-ELF scan go into the `ready` line. On
    SIGTERM a second probe drains every earlier event, a second scan runs, and `stopped` is written. Any
    other ending writes a failure line and exits 1."""
    path, ready = Path(path), Path(ready)
    path.parent.mkdir(parents=True, exist_ok=True)
    scan = os.environ.get("LANE_GO_SCAN_ROOT") or "/"
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    proc = subprocess.Popen(["docker", "events", "--filter", "type=container", "--filter", "type=image",
                             "--format", "{{json .}}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    lines = queue.Queue()

    def pump():
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    probes, records, state = [], 0, "starting"
    deadline, next_probe = time.monotonic() + 60, 0.0
    with path.open("a") as sink:
        def put(record):
            sink.write(json.dumps(record, sort_keys=True) + "\n")
            sink.flush()

        try:
            while True:
                now = time.monotonic()
                if state == "starting" and stop.is_set():
                    put({"watch": "timeout", "state": state})
                    return 1
                if state == "starting" and now >= next_probe:
                    probes.append(probe(f"ready{len(probes) + 1}"))
                    next_probe = now + 2
                if state == "ready" and stop.is_set():
                    probes.append(probe("stop"))
                    deadline, state = now + 120, "draining"
                if state != "ready" and now > deadline:
                    put({"watch": "timeout", "state": state})
                    return 1
                try:
                    line = lines.get(timeout=0.5)
                except queue.Empty:
                    continue
                if line is None:
                    put({"watch": "ended", "state": state, "rc": proc.poll()})
                    return 1
                try:
                    record = event_record(json.loads(line))
                except ValueError:
                    continue
                if record["kind"] == "create" and record["name"] in probes:
                    if state == "starting":
                        images, identity = image_identities(ROOT)
                        snapshot = existing_containers()
                        put({"watch": "ready", "go_masked": not go_reachable(), "root": str(ROOT), "scan": scan,
                             "images": images, "identity": identity, "go_elves": go_elves(scan)})
                        for item in snapshot:
                            if item["task"] != PROBE_TASK:
                                put(item)
                        state = "ready"
                        ready.touch()
                    elif state == "draining" and record["name"] == probes[-1]:
                        put({"watch": "stopped", "records": records, "go_elves": go_elves(scan)})
                        return 0
                    continue
                if record.get("task") == PROBE_TASK or state == "starting":
                    continue
                if record["kind"] in CONTAINER_ACTIONS or record["kind"] == "image":
                    put(record)
                    records += 1
        except WatchError as error:
            put({"watch": "error", "detail": str(error)[:500]})
            return 1
        finally:
            remove_probes()
            stop_events(proc)


def classify(record, images, go_ids):
    if "watch" in record:
        return "watch-" + record["watch"]
    if record.get("kind") == "image":
        action, ref = record.get("action"), record.get("ref", "")
        if action in IMAGE_MUTATIONS or (action == "pull" and "@sha256:" not in ref):
            return "image-mutation"
        return "other"
    ref = record.get("image", "")
    image_id = images.get(normalize(ref)) if ref else None
    bare = ref.removeprefix("sha256:")
    if image_id is None and re.fullmatch(r"[0-9a-f]{12,64}", bare):
        image_id = next((value for value in images.values() if value.removeprefix("sha256:").startswith(bare)), None)
    if image_id is None:
        return "unpinned-image"
    if image_id not in go_ids:
        return "other"
    if record.get("lane"):
        return "lane"
    return "allowed" if record.get("task") in GO_TASKS else "go"


def container_problems(paths, root, require_masked=False):
    problems, counts = [], {}
    for path in paths:
        state, windows, images, go_ids, lane_root = "closed", 0, {}, set(), str(root)
        for number, line in enumerate(Path(path).read_text().splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            kind = classify(record, images, go_ids)
            counts[kind] = counts.get(kind, 0) + 1
            where = f"{path}:{number}"
            if kind == "watch-ready":
                if state == "open":
                    problems.append(f"{where}: a watch window never stopped cleanly")
                if require_masked and record.get("go_masked") is not True:
                    problems.append(f"{where}: the Go toolchain was reachable in the lane container")
                if require_masked and record.get("scan") != "/":
                    problems.append(f"{where}: the Go-ELF scan did not cover the whole lane container")
                problems += [f"{where}: {item}" for item in record.get("identity", [])]
                images, lane_root = record.get("images") or {}, record.get("root") or str(root)
                go_ids = go_image_ids(root, images)
                if not go_ids:
                    problems.append(f"{where}: no Go-capable image identity resolved")
                state = "open"
                windows += 1
            elif kind == "watch-stopped":
                if state != "open":
                    problems.append(f"{where}: stop without a ready line")
                state = "closed"
            elif kind.startswith("watch-"):
                problems.append(f"{where}: the container watch failed ({record})")
                state = "closed"
            elif state != "open":
                problems.append(f"{where}: event outside a ready/stopped window")
            elif kind == "go":
                problems.append(f"{where}: {record['kind']} of Go-capable container {record.get('name')} "
                                f"(image {record.get('image') or 'unknown'}, task {record.get('task') or 'none'}) "
                                "outside GO_TASKS")
            elif kind == "unpinned-image":
                problems.append(f"{where}: {record['kind']} of {record.get('name')} from image "
                                f"{record.get('image') or 'unknown'} not pinned in {IMAGES_LOCK}")
            elif kind == "image-mutation":
                problems.append(f"{where}: image {record.get('action')} {record.get('ref')} during the lane")
            if kind in ("watch-ready", "watch-stopped"):
                problems += [f"{where}: Go-built executable {elf} is not allowed"
                             for elf in record.get("go_elves", []) if not elf_allowed(elf, lane_root)]
        if state == "open":
            problems.append(f"{path}: the last watch window never stopped cleanly")
        if windows == 0:
            problems.append(f"{path}: no watch window (the watch never became ready)")
    return problems, counts


def coverage_problems(paths):
    routes = {}
    for path in paths:
        for line in Path(path).read_text(errors="ignore").splitlines():
            match = COVERAGE_LINE.match(line)
            if match:
                total = routes.setdefault(match["route"], [0, 0])
                total[0] += int(match["covered"])
                total[1] += int(match["count"])
    problems = [f"coverage {route}: 0/{count} handler lines covered (gap)"
                for route, (covered, count) in sorted(routes.items()) if covered == 0 and count > 0]
    return problems, len(routes)


def lane(root, results, shards, coverage_shards):
    problems, lines = static(root)
    shard_dirs = [f"lane-result-shard-{k}" for k in range(1, shards + 1)]
    coverage_dirs = [f"lane-result-coverage-{k}" for k in range(1, coverage_shards + 1)]
    watched = []
    for name in shard_dirs + coverage_dirs:
        path = results / name / "rehearsal-containers.jsonl"
        if path.is_file():
            watched.append(path)
        else:
            problems.append(f"{name}: no rehearsal-containers.jsonl (the container watch did not run)")
    found, counts = container_problems(watched, root, require_masked=True)
    problems += found
    lines.append(f"containers: {len(watched)} jobs watched: "
                 + ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items())))
    logs = [results / name / "lane.log" for name in coverage_dirs if (results / name / "lane.log").is_file()]
    found, measured = coverage_problems(logs)
    problems += found
    lines.append(f"coverage: {measured} routes measured, {len(found)} with no covered handler line")
    return problems, lines


def report(problems, lines, title):
    print(f"### {title}")
    for line in lines:
        print(f"- `{line}`")
    for problem in problems:
        print(f"- ✗ {problem}")
    print(f"- {'✗ red' if problems else '✓ green'}")
    return 1 if problems else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("static")
    sub.add_parser("env")
    watch_parser = sub.add_parser("watch")
    watch_parser.add_argument("file")
    watch_parser.add_argument("--ready", required=True)
    containers_parser = sub.add_parser("containers")
    containers_parser.add_argument("--require-masked", action="store_true")
    containers_parser.add_argument("files", nargs="+")
    lane_parser = sub.add_parser("lane")
    lane_parser.add_argument("results", type=Path)
    lane_parser.add_argument("--shards", type=int, required=True)
    lane_parser.add_argument("--coverage-shards", type=int, required=True)
    args = parser.parse_args(argv)
    if args.command == "static":
        return report(*static(args.root), "Go-deletion rehearsal: static")
    if args.command == "env":
        return report(env_problems(dict(os.environ), go_reachable()), [], "Go-deletion rehearsal: env")
    if args.command == "watch":
        return watch(args.file, args.ready)
    if args.command == "containers":
        problems, counts = container_problems(args.files, args.root, args.require_masked)
        return report(problems, [f"containers: {counts}"], "Go-deletion rehearsal: containers")
    return report(*lane(args.root, args.results, args.shards, args.coverage_shards), "Go-deletion rehearsal (#141)")


if __name__ == "__main__":
    sys.exit(main())
