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
GO_PINNED = "ghcr.io/setjoin/setjoin-ci-linux-tc@sha256:" + "0" * 64
LOCK = ("# comment\nsetjoin-ci-linux-tc:local-amd64=" + GO_PINNED + "\n"
        "setjoin-lane-pg:17=ghcr.io/setjoin/setjoin-lane-pg@sha256:" + "1" * 64 + "\n")
IMAGES = {GO: "sha256:" + "a" * 64, GO_PINNED: "sha256:" + "a" * 64,
          "setjoin-lane-pg:17": "sha256:" + "b" * 64,
          "ghcr.io/setjoin/setjoin-lane-pg@sha256:" + "1" * 64: "sha256:" + "b" * 64}
READY = {"watch": "ready", "go_masked": True, "scan": "/", "root": "/w", "images": IMAGES, "identity": [],
         "go_elves": []}
STOPPED = {"watch": "stopped", "records": 0, "go_elves": []}


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


def event(image, task="", action="create", name="c", **labels):
    attributes = {"name": name, "image": image, **labels}
    if task:
        attributes["org.setjoin.task"] = task
    return guard.event_record({"Type": "container", "Action": action,
                               "Actor": {"ID": "0123456789abcdef", "Attributes": attributes}})


def image_event(action, ref):
    return guard.event_record({"Type": "image", "Action": action, "Actor": {"ID": ref, "Attributes": {"name": ref}}})


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

    def test_zero_pin_is_red(self):
        pinned = {**self.PIN, ("gateway", "go_target"): 0}
        self.assertIn("delete the entry", self.check(self.SRC, pinned)[0][0])

    def test_unpinned_kind_is_banned(self):
        problems = self.check(self.SRC + "Target::GoMail => x,\n", self.PIN)[0]
        self.assertTrue(any("DELETE gate (#358)" in p and "gateway/go_target" in p for p in problems), problems)

    def test_absolute_ban_when_nothing_is_pinned(self):
        problems = self.check(self.SRC, {})[0]
        self.assertTrue(problems and all("banned" in p for p in problems), problems)

    def test_plumbing_forms_are_counted(self):
        src = self.SRC + "shared.upstream.clone().with_go_counter(c, f)\ncfg.go_upstream = None\nunported_push_target(x)\n"
        pinned = {**self.PIN, ("gateway", "go_counter"): 1, ("gateway", "go_upstream"): 1,
                  ("gateway", "unported_push_target"): 1}
        self.assertEqual(self.check(src, pinned)[0], [])

    ARM = ("            return match &shared.rust_auth_upstream {\n"
           "                Some(upstream) => upstream.forward(req, &identity).await,\n")

    def test_rust_auth_hop_is_not_a_go_forward(self):
        self.assertEqual(self.check(self.SRC + self.ARM, self.PIN)[0], [])

    def test_go_forward_beside_the_rust_auth_arm_is_counted(self):
        src = self.SRC + self.ARM + "                None => go_mail.forward(req, &identity).await,\n"
        self.assertIn("> pinned 1", self.check(src, self.PIN)[0][0])

    def test_other_receiver_in_the_arm_is_counted(self):
        src = self.SRC + ("            return match &shared.rust_auth_upstream {\n"
                          "                Some(upstream) => go_mail.forward(req, &identity).await,\n")
        self.assertIn("> pinned 1", self.check(src, self.PIN)[0][0])


class Matrix(unittest.TestCase):
    AUTH = ('const ALL: &[&str] = &["a", "b", "c"];\nconst ONE: &[&str] = &["a"];\n'
            'const EXPECT: &[(&[&str], &str, Outcome)] = &[\n'
            '    (ALL, "s1", Hop("#349")),\n    (ONE, "s2", Hop("#350")),\n    (&["b"], "s3", Hop("#351")),\n'
            '    (ALL, "s4", Native(200)),\n];\nmatch want { Hop(_) => 1, Native(c) => c }\n')
    GATEWAY = 'const ALL: &[&str] = &["x", "y"];\nconst EXPECT: X = &[\n    (ALL, "g", Hop("#355")),\n];\n'
    PIN = {"server-rust/bins/auth/tests/delete_gate.rs": 5, "server-rust/bins/gateway/tests/delete_gate.rs": 2}

    def check(self, auth, gateway, pinned=None):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "MATRIX_HOPS", pinned or self.PIN):
            write(Path(tmp), "server-rust/bins/auth/tests/delete_gate.rs", auth)
            write(Path(tmp), "server-rust/bins/gateway/tests/delete_gate.rs", gateway)
            return guard.matrix_problems(Path(tmp))[0]

    def test_cells_not_rows_are_pinned(self):
        self.assertEqual(self.check(self.AUTH, self.GATEWAY), [])

    def test_widening_a_group_is_red(self):
        widened = self.AUTH.replace('const ONE: &[&str] = &["a"];', 'const ONE: &[&str] = &["a", "b"];')
        self.assertIn("never fill it from CI output", self.check(widened, self.GATEWAY)[0])

    def test_removed_hop_must_lower_the_pin(self):
        narrowed = self.AUTH.replace('(&["b"], "s3", Hop("#351"))', '(&["b"], "s3", Native(200))')
        self.assertIn("lower MATRIX_HOPS", self.check(narrowed, self.GATEWAY)[0])

    def test_unparsable_or_unknown_group_is_red(self):
        odd = self.AUTH + 'let x = Hop("#999");\n'
        self.assertIn("not a parsable", self.check(odd, self.GATEWAY)[0])
        unknown = self.AUTH.replace('(ONE, "s2"', '(TWO, "s2"')
        self.assertIn("unknown cell group TWO", self.check(unknown, self.GATEWAY)[0])


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


class Lock(unittest.TestCase):
    def test_entries_and_go_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), guard.IMAGES_LOCK, LOCK)
            self.assertEqual(len(guard.lock_entries(Path(tmp))), 2)
            self.assertEqual(guard.go_image_ids(Path(tmp), IMAGES), {"sha256:" + "a" * 64})
        self.assertEqual(guard.normalize("setjoin-server-rust-lane"), "setjoin-server-rust-lane:latest")
        self.assertEqual(guard.normalize(GO_PINNED), GO_PINNED)


class Classify(unittest.TestCase):
    def test_rules(self):
        go_ids = {"sha256:" + "a" * 64}
        cases = [
            (event(GO, "gofree-fed2"), "allowed"),
            (event(GO_PINNED, "gofree-rel3", action="exec_start: bash -c true"), "allowed"),
            (event(GO, action="start"), "go"),
            (event(GO, "gofree-guests1"), "go"),
            (event("a" * 12), "go"),
            (event(GO, name="setjoin-lane-run-1-1-shard-1", action="exec_create: ls", **{"setjoin-lane-run": "1-1"}),
             "lane"),
            (event(GO, name="impostor", **{"setjoin-lane-run": "1-1"}), "go"),
            (event("setjoin-lane-pg:17", action="exec_start: df"), "other"),
            (event("golang:1.26"), "unpinned-image"),
            (event("postgres:17"), "unpinned-image"),
            (event(""), "unpinned-image"),
            (image_event("tag", GO), "image-mutation"),
            (image_event("pull", "golang:1.26"), "image-mutation"),
            (image_event("pull", GO_PINNED), "other"),
            (READY, "watch-ready"),
        ]
        for record, kind in cases:
            self.assertEqual(guard.classify(record, IMAGES, go_ids), kind, record)


class Windows(unittest.TestCase):
    def check(self, records, require_masked=True):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), guard.IMAGES_LOCK, LOCK)
            path = write(Path(tmp), "w.jsonl", jsonl(records))
            return guard.container_problems([path], Path(tmp), require_masked)[0]

    def test_clean_windows_pass(self):
        existing = dict(event("setjoin-lane-pg:17"), kind="existing")
        self.assertEqual(self.check([READY, existing, event(GO, "gofree-tlsfront", action="start"), STOPPED,
                                     READY, image_event("pull", GO_PINNED), STOPPED]), [])

    def test_empty_or_crashed_watch_is_red(self):
        self.assertIn("no watch window", self.check([])[0])
        self.assertIn("never stopped cleanly", self.check([READY])[0])
        self.assertIn("watch failed", self.check([READY, {"watch": "error", "detail": "probe rm failed"}])[0])
        self.assertIn("outside a ready/stopped window", self.check([event("setjoin-lane-pg:17"), READY, STOPPED])[0])

    def test_launches_and_mutations_are_red(self):
        self.assertIn("outside GO_TASKS", self.check([READY, event(GO, action="exec_start: go"), STOPPED])[0])
        self.assertIn("not pinned", self.check([READY, event("golang:1.26", "gofree-fed2"), STOPPED])[0])
        self.assertIn("during the lane", self.check([READY, image_event("tag", GO), STOPPED])[0])

    def test_ready_line_proofs(self):
        self.assertIn("toolchain was reachable", self.check([dict(READY, go_masked=False), STOPPED])[0])
        self.assertIn("whole lane container", self.check([dict(READY, scan="/w"), STOPPED])[0])
        mismatch = ["image x: tag and pinned digest resolve to different images"]
        self.assertIn("different images", self.check([dict(READY, identity=mismatch), STOPPED])[0])
        self.assertEqual(self.check([dict(READY, scan="/w"), STOPPED], require_masked=False), [])

    def test_go_elves(self):
        ok = ["/usr/local/bin/docker", "/w/test-results/gofree-tlsfront/gofree-tlsfront-peer",
              "/home/runner/.cache/x/tmp/gofree-fed2-peer-77/fedharness"]
        self.assertEqual(self.check([dict(READY, go_elves=ok), dict(STOPPED, go_elves=ok)]), [])
        bad = self.check([READY, dict(STOPPED, go_elves=["/usr/local/bin/mailserverd"])])
        self.assertIn("mailserverd is not allowed", bad[0])


class Scan(unittest.TestCase):
    def test_finds_executable_go_elves_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            go = write(Path(tmp), "bin/peer", "")
            go.write_bytes(elf(b"\x00.shstrtab\x00.go.buildinfo\x00"))
            go.chmod(0o755)
            data = write(Path(tmp), "cache/obj", "")
            data.write_bytes(elf(b"\x00.go.buildinfo\x00"))
            rust = write(Path(tmp), "bin/rust", "")
            rust.write_bytes(elf(b"\x00.text\x00"))
            rust.chmod(0o755)
            hidden = write(Path(tmp), ".git/hooks/x", "")
            hidden.write_bytes(elf(b"\x00.go.buildinfo\x00"))
            hidden.chmod(0o755)
            self.assertEqual(guard.go_elves(tmp), [str(go)])


class PeerReferences(unittest.TestCase):
    def test_real_tree_pinned(self):
        self.assertEqual(guard.peer_reference_problems(guard.ROOT), ([], 8))

    def test_new_reference_is_red(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "GO_PEER_REFERENCES", {}):
            write(Path(tmp), "server-rust/tests/x.rs",
                  'Command::new(root.join("test-results/gofree-tlsfront/gofree-tlsfront-peer"))')
            self.assertIn("review that the peer runs only inside", guard.peer_reference_problems(Path(tmp))[0][0])


class Lane(unittest.TestCase):
    COVERED = ("coverage GET /a /src/server-rust/a.rs: lines 3/10; regions 3/9\n"
               "coverage GET /a /src/server-rust/b.rs: lines 0/5; regions 0/2\n")

    def run_lane(self, shard_records, coverage_log, watch_coverage=True):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(guard, "static", lambda root: ([], [])):
            results = Path(tmp)
            write(results, guard.IMAGES_LOCK, LOCK)
            write(results, "lane-result-shard-1/rehearsal-containers.jsonl", jsonl(shard_records))
            if watch_coverage:
                write(results, "lane-result-coverage-1/rehearsal-containers.jsonl", jsonl([READY, STOPPED]))
            write(results, "lane-result-coverage-1/lane.log", coverage_log)
            return guard.lane(results, results, 1, 1)[0]

    def test_green(self):
        self.assertEqual(self.run_lane([READY, event(GO, "gofree-rel3"), STOPPED], self.COVERED), [])

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
