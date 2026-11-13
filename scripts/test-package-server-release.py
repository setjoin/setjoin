#!/usr/bin/env python3
"""Check server archive contents and machine-header validation."""

import os
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARIES = ("mailserverd", "authserverd", "setjoin-updater")
MACHINES = {"amd64": 62, "arm64": 183, "loong64": 258}


def elf(arch, label):
    return (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack("<HHI", 2, MACHINES[arch], 1)
        + label.encode()
    )


class ServerRelease(unittest.TestCase):
    def test_each_architecture_archive_contains_go_rust_and_installer_inputs(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t13-package-") as directory:
            root = Path(directory)
            go = root / "go"
            go.mkdir()
            rust = root / "setjoin-gateway"
            mailctl = root / "rust-mailctl"
            asrbotd = root / "rust-asrbotd"
            updater = root / "rust-updater"
            webmail = root / "webmail"
            webmail.mkdir()
            (webmail / "index.html").write_text("webmail")
            for arch in ("amd64", "arm64", "loong64"):
                with self.subTest(arch=arch):
                    for name in BINARIES:
                        (go / name).write_bytes(elf(arch, "go:" + name))
                    rust.write_bytes(elf(arch, "rust:gateway"))
                    mailctl.write_bytes(elf(arch, "rust:mailctl"))
                    asrbotd.write_bytes(elf(arch, "rust:asrbotd"))
                    updater.write_bytes(elf(arch, "rust:updater"))
                    (go / "mailctl").write_bytes(elf(arch, "stale-go:mailctl"))
                    expected = {
                        "mailserver/mailserverd": elf(arch, "go:mailserverd"),
                        "mailserver/setjoin-updater": elf(arch, "go:setjoin-updater"),
                        "authserver/authserverd": elf(arch, "go:authserverd"),
                        "mailctl/mailctl": elf(arch, "rust:mailctl"),
                        "server-rust/mailctl": elf(arch, "rust:mailctl"),
                        "server-rust/setjoin-gateway": elf(arch, "rust:gateway"),
                        "server-rust/setjoin-updater": elf(arch, "rust:updater"),
                        "server-rust/asrbotd": elf(arch, "rust:asrbotd"),
                        "mailserver/webmail/build/index.html": b"webmail",
                    }
                    output = root / (arch + ".tar.gz")
                    result = subprocess.run(
                        [
                            "bash",
                            str(ROOT / "scripts/package-server-release.sh"),
                            arch,
                            str(go),
                            str(rust),
                            str(mailctl),
                            str(asrbotd),
                            str(updater),
                            str(webmail),
                            str(output),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    found = {}
                    with tarfile.open(output, mode="r|gz") as archive:
                        for member in archive:
                            name = member.name.removeprefix("./")
                            self.assertNotEqual(name, "mailserver/setjoin-recovery", "Go recovery must not ship after the Rust swap")
                            if name in expected:
                                found[name] = (
                                    archive.extractfile(member).read(),
                                    member.mode,
                                )
                            elif name == "mailserver/deploy/scripts/install.sh":
                                found[name] = (None, member.mode)
                    for name, content in expected.items():
                        self.assertEqual(found[name][0], content)
                    self.assertTrue(found["mailserver/mailserverd"][1] & 0o111)
                    self.assertTrue(found["server-rust/setjoin-gateway"][1] & 0o111)
                    self.assertIn("mailserver/deploy/scripts/install.sh", found)

    def test_source_build_installs_rust_cli_over_a_stale_go_artifact(self):
        with tempfile.TemporaryDirectory(prefix="gofree-mctl4-build-") as directory:
            root = Path(directory)
            for name in ["scripts", "mailctl", "server-rust", "tools"]:
                (root / name).mkdir()
            for name in ["build.sh", "_base.sh"]:
                shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
            (root / "mailctl/mailctl").write_text("stale Go CLI")
            tools = root / "tools"
            scripts = {
                "node": "#!/bin/sh\nexit 0\n",
                "pkg-config": "#!/bin/sh\nexit 1\n",
                "go": '#!/bin/sh\necho "Go mailctl must not build" >&2; exit 99\n',
                "cargo": '#!/bin/sh\n[ "$*" = "build --release --locked -p setjoin-mailctl -p setjoin-asrbot -p setjoin-updater" ] || exit 98\nmkdir -p "$CARGO_TARGET_DIR/release"\nprintf "Rust CLI" > "$CARGO_TARGET_DIR/release/mailctl"\nprintf "Rust asrbotd" > "$CARGO_TARGET_DIR/release/asrbotd"\nprintf "Rust updater" > "$CARGO_TARGET_DIR/release/setjoin-updater"\n',
            }
            for name, text in scripts.items():
                (tools / name).write_text(text)
                (tools / name).chmod(0o755)
            env = os.environ | {
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "CARGO_TARGET_DIR": str(root / "target"),
            }
            result = subprocess.run(
                ["bash", str(root / "scripts/build.sh")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ["mailctl/mailctl", "server-rust/mailctl"]:
                self.assertEqual((root / name).read_text(), "Rust CLI")
                self.assertTrue((root / name).stat().st_mode & 0o111)
            self.assertEqual((root / "server-rust/setjoin-updater").read_text(), "Rust updater")
            # The captions bot ships as the Rust binary, staged where install.sh reads it.
            self.assertEqual((root / "server-rust/asrbotd").read_text(), "Rust asrbotd")
            self.assertTrue((root / "server-rust/asrbotd").stat().st_mode & 0o111)

    def _package(self, root, roots_env):
        go = root / "go"
        go.mkdir(exist_ok=True)
        for name in BINARIES:
            (go / name).write_bytes(elf("amd64", name))
        for name in ("gateway", "mailctl", "asrbotd", "updater"):
            (root / name).write_bytes(elf("amd64", name))
        webmail = root / "webmail"
        webmail.mkdir(exist_ok=True)
        (webmail / "index.html").write_text("webmail")
        out = root / "out.tar.gz"
        env = {k: v for k, v in os.environ.items() if k != "SETJOIN_RELEASE_TRUST_ROOTS"}
        env.update(roots_env)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/package-server-release.sh"), "amd64", str(go),
             str(root / "gateway"), str(root / "mailctl"), str(root / "asrbotd"),
             str(root / "updater"), str(webmail), str(out)],
            capture_output=True, text=True, check=False, env=env)
        return result, out

    def test_package_ships_vendor_release_roots_only_when_supplied_and_valid(self):
        import json
        good = {"schema_version": 1, "purpose": "release",
                "keys": [{"id": "k1", "algorithm": "ed25519", "public_key": "AAAA"}]}
        with tempfile.TemporaryDirectory(prefix="secfix1-roots-") as directory:
            root = Path(directory)
            roots = root / "roots.json"
            roots.write_text(json.dumps(good))
            result, out = self._package(root, {"SETJOIN_RELEASE_TRUST_ROOTS": str(roots)})
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(out, mode="r|gz") as archive:
                for member in archive:
                    if member.name.removeprefix("./") == "server-rust/release-roots.json":
                        self.assertEqual(archive.extractfile(member).read(), roots.read_bytes())
                        self.assertEqual(member.mode & 0o777, 0o644)
                        break
                else:
                    self.fail("release-roots.json missing from the package")
            out.unlink()
            roots.write_text(json.dumps(dict(good, keys=[dict(good["keys"][0], test_only=True)])))
            result, _ = self._package(root, {"SETJOIN_RELEASE_TRUST_ROOTS": str(roots)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("none test-only", result.stderr)
            result, out = self._package(root, {})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ships no release trust roots", result.stderr)
            with tarfile.open(out, mode="r|gz") as archive:
                self.assertNotIn("server-rust/release-roots.json",
                                 [m.name.removeprefix("./") for m in archive])

    def test_rejects_a_mixed_architecture_cohort(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t13-package-") as directory:
            root = Path(directory)
            go = root / "go"
            go.mkdir()
            for name in BINARIES:
                (go / name).write_bytes(elf("amd64", name))
            rust = root / "setjoin-gateway"
            mailctl = root / "rust-mailctl"
            asrbotd = root / "rust-asrbotd"
            updater = root / "rust-updater"
            rust.write_bytes(elf("amd64", "gateway"))
            mailctl.write_bytes(elf("amd64", "rust:mailctl"))
            asrbotd.write_bytes(elf("amd64", "rust:asrbotd"))
            updater.write_bytes(elf("amd64", "rust:updater"))
            webmail = root / "webmail"
            webmail.mkdir()
            (webmail / "index.html").write_text("webmail")
            output = root / "release.tar.gz"
            for binary in [*(go / name for name in BINARIES), rust, mailctl, asrbotd, updater]:
                with self.subTest(binary=binary.name):
                    original = binary.read_bytes()
                    binary.write_bytes(elf("arm64", "wrong architecture"))
                    result = subprocess.run(
                        [
                            "bash",
                            str(ROOT / "scripts/package-server-release.sh"),
                            "amd64",
                            str(go),
                            str(rust),
                            str(mailctl),
                            str(asrbotd),
                            str(updater),
                            str(webmail),
                            str(output),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                    binary.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
