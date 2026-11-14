#!/usr/bin/env python3
"""Tests for scripts/check-gofree-rehearsal.py (#141) on synthetic trees, event records and ELF headers, plus
the real tree's static check (no docker, no cargo).  python3 scripts/test-check-gofree-rehearsal.py"""
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("check-gofree-rehearsal.py")
SPEC = importlib.util.spec_from_file_location("check_gofree_rehearsal", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
GO = "setjoin-ci-linux-tc:local-amd64"
READY = {"watch": "ready", "go_masked": True, "pid": 1}
STOPPED = {"watch": "stopped", "records": 0}


def route(listener, method, path, state="ON", upstream="local-rust"):
    return {"listener": listener, "method": method, "path": path, "family": "F00", "slice": "s",
            "upstream": upstream, "state": state, "sources": [], "oracle_goldens": []}


def write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


def jsonl(records):
    return "".join(json.dumps(record) + "\n" for record in records)


def created(image, task="", kind="create", name="c"):
    attributes = {"name": name, "image": image}
    if task:
        attributes["org.setjoin.task"] = task
    action = "exec_create: bash -c true" if kind == "exec" else "create"
    return guard.event_record({"Action": action, "Actor": {"ID": "0123456789abcdef", "Attributes": attributes}})


def elf(names):
    head = bytearray(64)
    head[:4], head[4], head[5] = b"\x7fELF", 2, 1
    struct.pack_into("<Q", head, 0x28, 64)
    struct.pack_into("<HHH", head, 0x3A, 64, 2, 1)
    sections = bytearray(128)
    struct.pack_into("<QQ", sections, 64 + 0x18, 192, len(names))
    return bytes(head + sections + names)


class Inventory(unittest.TestCase):
    def check(self, routes, pending):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "PENDING", pending):
            write(Path(tmp), guard.INVENTORY, {"version": 1, "routes": routes})
            return guard.inventory_problems(Path(tmp))[0]

    def test_on_excluded_and_pending_pass(self):
        routes = [route("gateway", "GET", "/a"), route("fedharness", "*", "/inbox", "OFF", "go-mail"),
                  route("gateway", "GET", "/terms/pending", "OFF", "go-mail")]
        self.assertEqual(self.check(routes, {("gateway", "GET", "/terms/pending"): "#340"}), [])

    def test_off_not_pending_is_red(self):
        self.assertIn("not in PENDING", self.check([route("gateway", "GET", "/a", "OFF", "go-mail")], {})[0])

    def test_on_with_go_upstream_is_red(self):
        self.assertIn("proxy it to Go", self.check([route("gateway", "GET", "/a", "ON", "go-mail")], {})[0])

    def test_pending_ratchet(self):
        pending = {("gateway", "GET", "/a"): "#1", ("gateway", "GET", "/gone"): "#2"}
        problems = self.check([route("gateway", "GET", "/a")], pending)
        self.assertEqual(len(problems), 2)
        self.assertIn("now ON", problems[0])
        self.assertIn("no longer in the inventory", problems[1])


class Forward(unittest.TestCase):
    SRC = ("pub async fn forward(&self) {}\nc.upstream.forward(req, &id)\n"
           "pub(crate) async fn forward_body(\nforward_body(c, b)\npub async fn forward_unported(\n"
           "super::ws_request::forward_unported(&d)\ntokio_tungstenite::client_async(r, s)\n")
    PIN = {("gateway", "forward"): 1, ("gateway", "forward_body"): 1, ("gateway", "forward_unported"): 1,
           ("gateway", "ws_client"): 1}

    def check(self, gateway_src, pinned):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "FORWARD_SITES", pinned):
            write(Path(tmp), "server-rust/bins/gateway/src/lib.rs", gateway_src)
            write(Path(tmp), "server-rust/bins/gateway/tests/t.rs", "c.upstream.forward(req)")
            return guard.forward_problems(Path(tmp))

    def test_exact_pin_passes(self):
        problems, counts = self.check(self.SRC, self.PIN)
        self.assertEqual(problems, [])
        self.assertEqual(counts, self.PIN)

    def test_new_site_is_red(self):
        self.assertIn("> pinned 1", self.check(self.SRC + "go_mail.forward(r)\n", self.PIN)[0][0])

    def test_removed_site_must_lower_the_pin(self):
        source = self.SRC.replace("c.upstream.forward(req, &id)", "")
        self.assertIn("lower FORWARD_SITES", self.check(source, self.PIN)[0][0])


class Divergences(unittest.TestCase):
    def check(self, document):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "server-rust/tests/conformance/x/divergences.json", document)
            write(Path(tmp), "server-rust/target/debug/divergences.json", [{"reviewed": False}])
            return guard.divergence_problems(Path(tmp))[0]

    def test_reviewed_forms_pass(self):
        self.assertEqual(self.check([{"reviewed": True, "reviewer": "Setjoin owner"}]), [])
        self.assertEqual(self.check({"case": {"review": "owner-approved security fix 2026-11-05"}}), [])
        self.assertEqual(self.check([]), [])

    def test_unreviewed_is_red(self):
        self.assertIn("reviewed is False", self.check([{"reviewed": False, "reviewer": "x"}])[0])
        self.assertIn("without reviewer", self.check([{"reviewed": True}])[0])
        self.assertIn("no reviewed flag", self.check([{"review": "later"}])[0])
        self.assertIn("not an object", self.check(["x"])[0])


class Workers(unittest.TestCase):
    def check(self, names, rust, intrinsic, expected=None):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(guard, "EXPECTED_WORKERS", len(names) if expected is None else expected), \
                mock.patch.object(guard, "INTRINSIC_WORKERS", intrinsic):
            root = Path(tmp)
            write(root, guard.WORKERS, {"schemaVersion": 1, "workers": [{"name": name} for name in names]})
            write(root, "server-rust/bins/gateway/src/main.rs", rust)
            write(root, "server-rust/bins/gateway/tests/w.rs", '"only-in-tests"')
            return guard.worker_problems(root)[0]

    def test_named_and_intrinsic_pass(self):
        self.assertEqual(self.check(["cron", "db-listener"], 'listed("RUST_WORKERS_ON", "cron")',
                                    {"db-listener": "x"}), [])

    def test_missing_rust_worker_is_red(self):
        self.assertIn("no Rust worker", self.check(["only-in-tests"], "", {})[0])

    def test_stale_intrinsic_is_red(self):
        self.assertIn("delete it from INTRINSIC_WORKERS", self.check(["cron"], '"cron"', {"gone": "x"})[0])

    def test_count_drift_is_red(self):
        self.assertIn("expected 5", self.check(["cron"], '"cron"', {}, expected=5)[0])


class Env(unittest.TestCase):
    def test_presence_is_red_even_when_empty(self):
        environ = {"GOFREE_RECORD_RISK": "", "GOFREE_GO_SOURCE": "abc", "GATEWAY_UPSTREAM": "",
                   "AUTHSERVER_GO_UPSTREAM": "x", "GOFREE_GO_MOD_CACHE": "/cache",
                   "GATEWAY_RUST_AUTH_UPSTREAM": "r", "LANE_JOBS": "4"}
        self.assertEqual(guard.env_problems(environ, False),
                         ["AUTHSERVER_GO_UPSTREAM is present", "GATEWAY_UPSTREAM is present",
                          "GOFREE_GO_SOURCE is present", "GOFREE_RECORD_RISK is present"])

    def test_masked_lane_needs_no_go(self):
        self.assertEqual(guard.env_problems({"LANE_GO_MASKED": "1"}, False), [])
        self.assertIn("toolchain is reachable", guard.env_problems({"LANE_GO_MASKED": "1"}, True)[0])
        self.assertEqual(guard.env_problems({}, True), [])


class Elf(unittest.TestCase):
    def test_go_buildinfo_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = write(Path(tmp), "go-bin", "")
            go.write_bytes(elf(b"\x00.shstrtab\x00.go.buildinfo\x00"))
            rust = write(Path(tmp), "rust-bin", "")
            rust.write_bytes(elf(b"\x00.shstrtab\x00.text\x00"))
            self.assertTrue(guard.is_go_elf(go))
            self.assertFalse(guard.is_go_elf(rust))
            self.assertFalse(guard.is_go_elf(write(Path(tmp), "script", "#!/bin/sh\n")))
        self.assertFalse(guard.is_go_elf(sys.executable))


class Scope(unittest.TestCase):
    def test_only_the_lane_tree_is_sampled(self):
        parents = {1: 0, 50: 1, 100: 1, 101: 100, 102: 101, 200: 1, 201: 200}
        self.assertEqual(guard.descendants(parents, 100), {101, 102})
        self.assertEqual(guard.descendants({5: 6, 6: 5}, 100), set())
        self.assertEqual(guard.descendants(parents, 999), set())


class Classify(unittest.TestCase):
    def test_rules(self):
        cases = [
            (created(GO, "gofree-fed2"), "allowed"),
            (created(GO, "gofree-rel3", kind="exec"), "allowed"),
            (created(GO), "go"),
            (created(GO, "gofree-guests1"), "go"),
            (created("ghcr.io/setjoin/setjoin-server-rust-lane@sha256:" + "a" * 64), "go"),
            (created("sha256:" + "b" * 64, "x"), "go"),
            (created(""), "go"),
            (created("setjoin-lane-pg:17", kind="exec"), "other"),
            (created("postgres:17"), "other"),
            ({"kind": "process", "pid": 7, "exe": "/w/test-results/peer"}, "go-process"),
            (READY, "watch-ready"),
            ({"watch": "timeout", "state": "starting"}, "watch-timeout"),
        ]
        for record, kind in cases:
            self.assertEqual(guard.classify(record), kind, record)


class Windows(unittest.TestCase):
    def check(self, records, require_masked=True):
        with tempfile.TemporaryDirectory() as tmp:
            path = write(Path(tmp), "w.jsonl", jsonl(records))
            return guard.container_problems([path], require_masked)[0]

    def test_clean_windows_pass(self):
        allowed = created(GO, "gofree-tlsfront")
        self.assertEqual(self.check([READY, allowed, STOPPED, READY, created("postgres:17"), STOPPED]), [])

    def test_empty_or_crashed_watch_is_red(self):
        self.assertIn("no watch window", self.check([])[0])
        self.assertIn("never stopped cleanly", self.check([READY, created("postgres:17")])[0])
        self.assertIn("watch failed", self.check([READY, {"watch": "ended", "state": "ready", "rc": 1}])[0])
        self.assertIn("outside a ready/stopped window", self.check([created("postgres:17"), READY, STOPPED])[0])

    def test_go_launch_and_process_are_red(self):
        self.assertIn("outside GO_TASKS", self.check([READY, created(GO), STOPPED])[0])
        process = {"kind": "process", "pid": 9, "exe": "/w/test-results/gofree-tlsfront/gofree-tlsfront-peer"}
        self.assertIn("Go-built process", self.check([READY, process, STOPPED])[0])

    def test_unmasked_go_is_red_when_required(self):
        unmasked = dict(READY, go_masked=False)
        self.assertIn("toolchain was reachable", self.check([unmasked, STOPPED])[0])
        self.assertEqual(self.check([unmasked, STOPPED], require_masked=False), [])


class Lane(unittest.TestCase):
    COVERED = ("coverage GET /a /src/server-rust/a.rs: lines 3/10; regions 3/9\n"
               "coverage GET /a /src/server-rust/b.rs: lines 0/5; regions 0/2\n")

    def run_lane(self, shard_records, coverage_log, watch_coverage=True):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "static", lambda root: ([], [])):
            results = Path(tmp)
            write(results, "lane-result-shard-1/rehearsal-containers.jsonl", jsonl(shard_records))
            if watch_coverage:
                write(results, "lane-result-coverage-1/rehearsal-containers.jsonl", jsonl([READY, STOPPED]))
            write(results, "lane-result-coverage-1/lane.log", coverage_log)
            return guard.lane(results, results, 1, 1)[0]

    def test_green(self):
        self.assertEqual(self.run_lane([READY, created(GO, "gofree-rel3"), STOPPED], self.COVERED), [])

    def test_missing_watch_is_red(self):
        self.assertIn("container watch did not run", self.run_lane([READY, STOPPED], self.COVERED, False)[0])

    def test_uncovered_route_is_red(self):
        log = self.COVERED + "coverage POST /b /src/server-rust/b.rs: lines 0/7; regions 0/3\n"
        self.assertIn("POST /b: 0/7 handler lines", self.run_lane([READY, STOPPED], log)[0])


class RealTree(unittest.TestCase):
    def test_static_is_green(self):
        problems, lines = guard.static(guard.ROOT)
        self.assertEqual(problems, [])
        self.assertTrue(any(line.startswith("GO_WORKERS_OFF=") for line in lines))
        self.assertTrue(any(line.startswith("REHEARSAL-FORWARD-SITES") for line in lines))


if __name__ == "__main__":
    unittest.main()
