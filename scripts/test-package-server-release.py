#!/usr/bin/env python3
"""Check Rust-only server archive contents and machine-header validation."""

import json
import os
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MACHINES = {"amd64": 62, "arm64": 183, "loong64": 258}
RETIRED_MEMBERS = {
    "mailserver/mailserverd",
    "mailserver/setjoin-updater",
    "mailserver/setjoin-recovery",
    "authserver/authserverd",
    "mailctl/mailctl",
    "server-rust/setjoin-gateway",
}


def elf(arch, label):
    return (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack("<HHI", 2, MACHINES[arch], 1)
        + label.encode()
    )


class ServerRelease(unittest.TestCase):
    def test_each_architecture_archive_contains_rust_and_installer_inputs(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t13-package-") as directory:
            root = Path(directory)
            server = root / "setjoin-server"
            rustauth = root / "setjoin-auth"
            mailctl = root / "mailctl"
            asrbotd = root / "asrbotd"
            updater = root / "setjoin-updater"
            webmail = root / "webmail"
            webmail.mkdir()
            (webmail / "index.html").write_text("webmail")
            for arch in ("amd64", "arm64", "loong64"):
                with self.subTest(arch=arch):
                    server.write_bytes(elf(arch, "rust:server"))
                    rustauth.write_bytes(elf(arch, "rust:auth"))
                    mailctl.write_bytes(elf(arch, "rust:mailctl"))
                    asrbotd.write_bytes(elf(arch, "rust:asrbotd"))
                    updater.write_bytes(elf(arch, "rust:updater"))
                    expected = {
                        "server-rust/setjoin-server": elf(arch, "rust:server"),
                        "server-rust/setjoin-auth": elf(arch, "rust:auth"),
                        "server-rust/mailctl": elf(arch, "rust:mailctl"),
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
                            str(server),
                            str(rustauth),
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
                            self.assertNotIn(
                                name,
                                RETIRED_MEMBERS,
                                f"retired Go/gateway member must not ship: {name}",
                            )
                            if name in expected:
                                found[name] = (
                                    archive.extractfile(member).read(),
                                    member.mode,
                                )
                            elif name == "mailserver/deploy/scripts/install.sh":
                                found[name] = (None, member.mode)
                    for name, content in expected.items():
                        self.assertIn(name, found)
                        self.assertEqual(found[name][0], content)
                    for bin_name in (
                        "server-rust/setjoin-server",
                        "server-rust/setjoin-auth",
                        "server-rust/mailctl",
                        "server-rust/setjoin-updater",
                        "server-rust/asrbotd",
                    ):
                        self.assertTrue(found[bin_name][1] & 0o111, bin_name)
                    self.assertIn("mailserver/deploy/scripts/install.sh", found)

    def _package(self, root, roots_env):
        for name in ("setjoin-server", "setjoin-auth", "mailctl", "asrbotd", "setjoin-updater"):
            (root / name).write_bytes(elf("amd64", name))
        webmail = root / "webmail"
        webmail.mkdir(exist_ok=True)
        (webmail / "index.html").write_text("webmail")
        out = root / "out.tar.gz"
        env = {k: v for k, v in os.environ.items() if k != "SETJOIN_RELEASE_TRUST_ROOTS"}
        env.update(roots_env)
        result = subprocess.run(
            [
                "bash",
                str(ROOT / "scripts/package-server-release.sh"),
                "amd64",
                str(root / "setjoin-server"),
                str(root / "setjoin-auth"),
                str(root / "mailctl"),
                str(root / "asrbotd"),
                str(root / "setjoin-updater"),
                str(webmail),
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return result, out

    def test_package_ships_vendor_release_roots_only_when_supplied_and_valid(self):
        good = {
            "schema_version": 1,
            "purpose": "release",
            "keys": [{"id": "k1", "algorithm": "ed25519", "public_key": "AAAA"}],
        }
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
            roots.write_text(
                json.dumps(dict(good, keys=[dict(good["keys"][0], test_only=True)]))
            )
            result, _ = self._package(root, {"SETJOIN_RELEASE_TRUST_ROOTS": str(roots)})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("none test-only", result.stderr)
            result, out = self._package(root, {})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ships no release trust roots", result.stderr)
            with tarfile.open(out, mode="r|gz") as archive:
                self.assertNotIn(
                    "server-rust/release-roots.json",
                    [m.name.removeprefix("./") for m in archive],
                )

    def test_rejects_a_mixed_architecture_cohort(self):
        with tempfile.TemporaryDirectory(prefix="gofree-t13-package-") as directory:
            root = Path(directory)
            server = root / "setjoin-server"
            rustauth = root / "setjoin-auth"
            mailctl = root / "mailctl"
            asrbotd = root / "asrbotd"
            updater = root / "setjoin-updater"
            server.write_bytes(elf("amd64", "rust:server"))
            rustauth.write_bytes(elf("amd64", "rust:auth"))
            mailctl.write_bytes(elf("amd64", "rust:mailctl"))
            asrbotd.write_bytes(elf("amd64", "rust:asrbotd"))
            updater.write_bytes(elf("amd64", "rust:updater"))
            webmail = root / "webmail"
            webmail.mkdir()
            (webmail / "index.html").write_text("webmail")
            output = root / "release.tar.gz"
            for binary in (server, rustauth, mailctl, asrbotd, updater):
                with self.subTest(binary=binary.name):
                    original = binary.read_bytes()
                    binary.write_bytes(elf("arm64", "wrong architecture"))
                    result = subprocess.run(
                        [
                            "bash",
                            str(ROOT / "scripts/package-server-release.sh"),
                            "amd64",
                            str(server),
                            str(rustauth),
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
