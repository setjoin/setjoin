#!/usr/bin/env python3
"""Root Linux Docker rehearsal for Wave 1.6 two-release setjoind cutover (#544).

Runs inside a root Linux container (matching bins/updater/tests/installer.rs with
zero test-only backdoors in setjoin-updater) against a disposable PostgreSQL DB:

  Stage 1 (N-1 Split Baseline):
    Boot real setjoin-server + setjoin-auth under rendered split units via a
    socket-activating UnitSupervisor + fake-systemctl; authenticate via
    POST /auth/login (capture Stage 1 JWT) and verify mailbox + message data.
  Stage 2 (Release N Expand Transactional Upgrade):
    Run real `setjoin-updater run --once` N-1 -> N (core_setjoind + compiled
    ELF shims, zero unit changes); assert intent == verified, /ready + :8443,
    Stage 1 JWT still authenticates, and mailbox row is intact.
  Stage 3 (Release N -> N-1 Auto-Rollback):
    Trigger a failing post-switch probe via real `setjoin-updater run --once`;
    assert intent == rolled_back, current restored to N-1, Stage 1 JWT +
    mailbox row intact.
  Stage 4 (Release N+1 Unified Cutover, Upgrade, Rollback, and Reverse):
    Re-apply Release N -> run real `upgrade.sh migrate-to-setjoind` -> assert
    setjoind.service (--subsystems=all, Type=notify, READY=1 on NOTIFY_SOCKET),
    /ready + /.well-known/jwks.json (200 JSON with "keys"), Stage 1 JWT +
    mailbox intact -> run real `setjoin-updater run --once` N -> N+1
    (core_setjoind-only) -> trigger failing-probe rollback N+1 -> N ->
    re-apply Release N expand and run real `upgrade.sh rollback-to-split-units`
    -> assert clean split return with Stage 1 JWT + mailbox row intact.

Pass `--self-test` on macOS or Linux (no root/Docker required) to validate the
architecture mapper, unit/socket parser, manifest cohort builder, and live
socket-activating UnitSupervisor + fake-systemctl IPC round-trip.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import hmac
import http.server
import io
import json
import os
import pathlib
import platform
import shlex
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "loongarch64": "loong64",
    "loong64": "loong64",
}

CORE_SOCKETS = (
    "setjoin-gateway.socket",
    "setjoin-https.socket",
    "setjoin-acme.socket",
    "setjoin-federation.socket",
    "setjoin-imap.socket",
    "setjoin-imaps.socket",
    "setjoin-smtp.socket",
    "setjoin-smtps.socket",
    "setjoin-submission.socket",
)

TEST_JWT_SECRET = "setjoind-rehearsal-jwt-secret-at-least-32-bytes!!"
TEST_DB_ENC_KEY = "setjoind-rehearsal-db-enc-key-32-bytes!!"
TEST_AUDIT_KEY = "setjoind-rehearsal-audit-hmac-key-32-bytes!!"
TEST_INTERNAL_KEY = "setjoind-rehearsal-internal-api-key-32-bytes!!"


def host_arch(machine: str | None = None) -> str:
    raw = (machine if machine is not None else platform.machine()).lower()
    if raw not in ARCH_MAP:
        raise RuntimeError(f"unsupported host architecture: {raw}")
    return ARCH_MAP[raw]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_json(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utc_stamp(ts: dt.datetime) -> str:
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z")


def sql_literal(val: object) -> str:
    return "'" + str(val).replace("'", "''") + "'"


def write_file(path: pathlib.Path, data: bytes | str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data if isinstance(data, bytes) else data.encode("utf-8")
    path.write_bytes(raw)
    path.chmod(mode)


def psql_query(pg_env: dict[str, str], query: str) -> str:
    proc = subprocess.run(
        ["psql", "-XAtq", "-v", "ON_ERROR_STOP=1"],
        input=query,
        text=True,
        capture_output=True,
        env=pg_env,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed: {proc.stderr}")
    return proc.stdout.strip()


def make_webmail_tar(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("index.html")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        out[key] = val
    return out


def parse_unit_file(path: pathlib.Path) -> dict[str, list[str]]:
    """Parse systemd INI directives into section-qualified key -> values."""
    section = ""
    directives: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        full_key = f"{section}.{key.strip()}"
        directives.setdefault(full_key, []).append(val.strip())
    return directives


def parse_listen_stream(spec: str) -> tuple[str, int]:
    """Parse systemd ListenStream= into a loopback (host, port) bind tuple."""
    text = spec.strip()
    if text.isdigit():
        return ("127.0.0.1", int(text))
    if text.startswith(":"):
        return ("127.0.0.1", int(text[1:]))
    if text.startswith("[") and "]:" in text:
        host, port_str = text[1:].split("]:", 1)
        return ("127.0.0.1" if host in ("::", "::1") else host, int(port_str))
    if ":" in text:
        host, port_str = text.rsplit(":", 1)
        return ("127.0.0.1" if host in ("0.0.0.0", "") else host, int(port_str))
    raise ValueError(f"unsupported ListenStream={spec!r}")


class UnitSupervisor:
    """In-process socket-activating systemd stand-in for real service binaries.

    Preserves bound listening sockets across service restarts, passes exact
    LISTEN_PID / LISTEN_FDS / LISTEN_FDNAMES / NOTIFY_SOCKET into real
    ExecStart= processes, and serves fake-systemctl requests over a Unix socket.
    """

    def __init__(
        self,
        systemd_dir: pathlib.Path,
        run_dir: pathlib.Path,
        log_path: pathlib.Path,
    ) -> None:
        self.systemd_dir = systemd_dir
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_path
        self.sock_path = run_dir / "supervisor.sock"
        self.sockets: dict[str, tuple[socket.socket, str, str]] = {}
        self.procs: dict[str, subprocess.Popen[bytes]] = {}
        self.notify_socks: dict[str, pathlib.Path] = {}
        self.ready_events: dict[str, list[str]] = {}
        self.enabled: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.sock_path.exists():
            self.sock_path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.sock_path))
        srv.listen(32)
        srv.settimeout(0.2)
        self._server = srv
        self._thread = threading.Thread(
            target=self._serve_loop, name="unit-supervisor", daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._server is not None:
            self._server.close()
        with self._lock:
            for svc in list(self.procs):
                self._stop_service_locked(svc)
            for sock_name in list(self.sockets):
                self._stop_socket_locked(sock_name)
        if self.sock_path.exists():
            self.sock_path.unlink()

    def _serve_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in chunk:
                        break
                if not data:
                    continue
                req = json.loads(data.decode("utf-8"))
                rc, stdout, stderr = self.handle_systemctl(req.get("args", []))
                resp = compact_json({"rc": rc, "stdout": stdout, "stderr": stderr})
                conn.sendall(resp + b"\n")

    def _normalize_unit(self, raw: str) -> str:
        if "." not in raw:
            return f"{raw}.service"
        return raw

    def handle_systemctl(self, args: list[str]) -> tuple[int, str, str]:
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(" ".join(args) + "\n")
            filtered = [a for a in args if not a.startswith("-")]
            if not filtered:
                return (0, "", "")
            verb = filtered[0]
            units = [self._normalize_unit(u) for u in filtered[1:]]

            if verb in ("daemon-reload", "reset-failed"):
                return (0, "", "")
            if verb == "enable":
                for u in units:
                    self.enabled.add(u)
                return (0, "", "")
            if verb == "disable":
                for u in units:
                    self.enabled.discard(u)
                return (0, "", "")
            if verb == "is-enabled":
                for u in units:
                    if u not in self.enabled and not (self.systemd_dir / u).exists():
                        return (1, "disabled\n", "")
                return (0, "enabled\n", "")
            if verb == "is-active":
                for u in units:
                    if u.endswith(".socket"):
                        if u not in self.sockets:
                            return (3, "inactive\n", "")
                    else:
                        proc = self.procs.get(u)
                        if proc is None or proc.poll() is not None:
                            return (3, "inactive\n", "")
                return (0, "active\n", "")
            if verb == "start":
                for u in units:
                    err = (
                        self._start_socket_locked(u)
                        if u.endswith(".socket")
                        else self._start_service_locked(u)
                    )
                    if err:
                        return (1, "", err + "\n")
                return (0, "", "")
            if verb == "stop":
                for u in units:
                    if u.endswith(".socket"):
                        self._stop_socket_locked(u)
                    else:
                        self._stop_service_locked(u)
                return (0, "", "")
            if verb == "restart":
                for u in units:
                    if u.endswith(".socket"):
                        self._stop_socket_locked(u)
                        err = self._start_socket_locked(u)
                    else:
                        self._stop_service_locked(u)
                        err = self._start_service_locked(u)
                    if err:
                        return (1, "", err + "\n")
                return (0, "", "")
            return (1, "", f"unsupported systemctl verb: {verb}\n")

    def _start_socket_locked(self, unit: str) -> str | None:
        if unit in self.sockets:
            return None
        path = self.systemd_dir / unit
        if not path.is_file():
            return f"socket unit not found: {path}"
        parsed = parse_unit_file(path)
        for cond in parsed.get("Unit.ConditionPathExists", []):
            if not pathlib.Path(cond).exists():
                return None
        streams = parsed.get("Socket.ListenStream", [])
        if not streams:
            return f"{unit} lacks ListenStream="
        host, port = parse_listen_stream(streams[-1])
        fd_name = (parsed.get("Socket.FileDescriptorName") or [unit])[-1]
        default_svc = unit.removesuffix(".socket") + ".service"
        target_svc = (parsed.get("Socket.Service") or [default_svc])[-1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            sock.listen(128)
        except OSError as exc:
            sock.close()
            return f"bind {unit} on {host}:{port}: {exc}"
        self.sockets[unit] = (sock, fd_name, target_svc)
        return None

    def _stop_socket_locked(self, unit: str) -> None:
        entry = self.sockets.pop(unit, None)
        if entry is not None:
            with contextlib.suppress(OSError):
                entry[0].close()

    def _start_service_locked(self, unit: str) -> str | None:
        existing = self.procs.get(unit)
        if existing is not None and existing.poll() is None:
            return None
        path = self.systemd_dir / unit
        if not path.is_file():
            return f"service unit not found: {path}"
        parsed = parse_unit_file(path)
        for cond in parsed.get("Unit.ConditionPathExists", []):
            if not pathlib.Path(cond).exists():
                return None
        exec_lines = parsed.get("Service.ExecStart", [])
        if not exec_lines:
            return f"{unit} lacks ExecStart="
        argv = shlex.split(exec_lines[-1])
        svc_type = (parsed.get("Service.Type") or ["simple"])[-1]
        workdir = (parsed.get("Service.WorkingDirectory") or [None])[-1]

        env: dict[str, str] = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        for raw_ef in parsed.get("Service.EnvironmentFile", []):
            optional = raw_ef.startswith("-")
            ef_path = pathlib.Path(raw_ef[1:] if optional else raw_ef)
            if not ef_path.is_file():
                if optional:
                    continue
                return f"{unit} missing required EnvironmentFile={ef_path}"
            env.update(parse_env_file(ef_path))
        for raw_env in parsed.get("Service.Environment", []):
            for token in shlex.split(raw_env):
                if "=" in token:
                    k, v = token.split("=", 1)
                    env[k] = v

        # Auto-start any required sockets if not already bound.
        for req_line in parsed.get("Unit.Requires", []):
            for dep in req_line.split():
                if dep.endswith(".socket") and dep not in self.sockets:
                    err = self._start_socket_locked(dep)
                    if err:
                        return err

        matched: list[tuple[socket.socket, str]] = []
        for sock_unit, (sock_obj, fd_name, target_svc) in sorted(self.sockets.items()):
            if target_svc == unit:
                matched.append((sock_obj, fd_name))

        notify_sock: socket.socket | None = None
        notify_path = self.run_dir / f"{unit.split('.')[0]}.ns"
        if notify_path.exists():
            notify_path.unlink()
        notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify_sock.bind(str(notify_path))
        notify_sock.settimeout(0.1)
        env["NOTIFY_SOCKET"] = str(notify_path)
        self.notify_socks[unit] = notify_path
        self.ready_events[unit] = []

        raw_fds = [s.fileno() for s, _ in matched]
        fd_names = ":".join(name for _, name in matched)
        launch_argv = list(argv)
        if raw_fds:
            env["LISTEN_FDS"] = str(len(raw_fds))
            env["LISTEN_FDNAMES"] = fd_names
            launch_argv = [
                sys.executable,
                "-c",
                "import os, sys; "
                "os.environ['LISTEN_PID'] = str(os.getpid()); "
                "os.execv(sys.argv[1], sys.argv[1:])",
                *argv,
            ]

        def setup_child() -> None:
            if raw_fds:
                high_base = 3 + len(raw_fds) + 8
                staged = []
                for idx, src_fd in enumerate(raw_fds):
                    tmp_fd = high_base + idx
                    os.dup2(src_fd, tmp_fd)
                    staged.append(tmp_fd)
                for idx, tmp_fd in enumerate(staged):
                    dst_fd = 3 + idx
                    os.dup2(tmp_fd, dst_fd)
                    os.set_inheritable(dst_fd, True)
                    os.close(tmp_fd)

        log_out = self.run_dir / f"{unit}.log"
        with log_out.open("ab") as log_fh:
            proc = subprocess.Popen(
                launch_argv,
                cwd=workdir,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=log_fh,
                close_fds=False,
                preexec_fn=setup_child,
            )
        self.procs[unit] = proc

        try:
            if svc_type == "notify":
                deadline = time.monotonic() + 25.0
                got_ready = False
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        tail = log_out.read_text(errors="replace")[-1000:]
                        return (
                            f"{unit} exited ({proc.returncode}) "
                            f"before READY=1: {tail}"
                        )
                    try:
                        msg = notify_sock.recv(512).decode("utf-8", errors="replace")
                        self.ready_events[unit].append(msg)
                        if "READY=1" in msg.splitlines():
                            got_ready = True
                            break
                    except socket.timeout:
                        continue
                if not got_ready:
                    self._stop_service_locked(unit)
                    return f"{unit} timed out waiting for READY=1 on NOTIFY_SOCKET"
            else:
                time.sleep(0.15)
                if proc.poll() is not None:
                    tail = log_out.read_text(errors="replace")[-1000:]
                    return f"{unit} exited immediately ({proc.returncode}): {tail}"
        finally:
            notify_sock.close()
        return None

    def _stop_service_locked(self, unit: str) -> None:
        proc = self.procs.pop(unit, None)
        if proc is None:
            return
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=35)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        notify_path = self.notify_socks.pop(unit, None)
        if notify_path is not None and notify_path.exists():
            with contextlib.suppress(OSError):
                notify_path.unlink()


def install_fake_systemctl(
    bindir: pathlib.Path, sock_path: pathlib.Path
) -> pathlib.Path:
    exe = bindir / "systemctl"
    script = f"""#!{sys.executable}
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect({str(sock_path)!r})
s.sendall((json.dumps({{"args": sys.argv[1:]}}) + "\\n").encode("utf-8"))
s.shutdown(socket.SHUT_WR)
raw = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    raw += chunk
resp = json.loads(raw.decode("utf-8"))
if resp.get("stdout"):
    sys.stdout.write(resp["stdout"])
if resp.get("stderr"):
    sys.stderr.write(resp["stderr"])
sys.exit(int(resp.get("rc", 1)))
"""
    write_file(exe, script, 0o755)
    return exe


def sign_manifest(
    root: pathlib.Path,
    fixture_template: dict,
    release_id: str,
    schema: int,
    registry: dict,
    cohort: str,
    bins: dict[str, pathlib.Path],
    arch: str,
    require_ed25519: bool = True,
) -> tuple[pathlib.Path, str, dict]:
    """Build and Ed25519-sign a release directory for cohort split|expand|unified."""
    rel_dir = root / "store" / release_id
    rel_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(rel_dir, 0o700)

    manifest = copy.deepcopy(fixture_template)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    manifest.update(
        release_id=release_id,
        published_at=utc_stamp(now - dt.timedelta(hours=1)),
        expires_at=utc_stamp(now + dt.timedelta(days=1)),
        architectures=[arch],
        schema_from=schema,
        schema_to=schema,
        migrations=None,
        feature_registry=registry,
        signatures=None,
    )

    art_template = manifest["artifacts"][0]
    kept = []
    for art in manifest["artifacts"]:
        if art["class"] in ("mailserverd", "authserverd", "setjoin-gateway"):
            continue
        cloned = copy.deepcopy(art)
        cloned["architecture"] = arch
        kept.append(cloned)

    def add_core(name: str, cls: str, target: str) -> None:
        item = copy.deepcopy(art_template)
        item.update(
            id=name,
            cohort="core",
            target=target,
            media_type="application/octet-stream",
            platform="linux",
            architecture=arch,
        )
        item["class"] = cls
        kept.append(item)

    if cohort == "split":
        add_core("setjoin-server", "setjoin-server", "core_setjoin_server")
        add_core("setjoin-auth", "setjoin-auth", "core_setjoin_auth")
    elif cohort == "expand":
        add_core("setjoind", "setjoind", "core_setjoind")
        add_core("setjoin-server", "setjoin-server", "core_setjoin_server")
        add_core("setjoin-auth", "setjoin-auth", "core_setjoin_auth")
    elif cohort == "unified":
        add_core("setjoind", "setjoind", "core_setjoind")
    else:
        raise ValueError(f"unsupported cohort: {cohort}")

    kept.sort(key=lambda a: a["id"])
    manifest["artifacts"] = kept

    web_tar = make_webmail_tar(f"<html>{release_id}</html>".encode("utf-8"))
    for art in manifest["artifacts"]:
        aid = art["id"]
        if aid == "webmail":
            body = web_tar
            art["media_type"] = "application/vnd.setjoin.webmail.tar"
        elif aid == "recovery-guide":
            body = b"# Recovery guide\n"
            art["media_type"] = "text/markdown"
        elif aid in bins:
            body = bins[aid].read_bytes()
        else:
            body = f"evidence-{release_id}-{aid}".encode("utf-8")
        art["size"] = len(body)
        art["sha256"] = sha256_hex(body)
        write_file(rel_dir / aid, body, 0o400)

    keys = list(manifest)
    keys.remove("feature_registry")
    keys.insert(keys.index("recovery"), "feature_registry")
    manifest = {k: manifest[k] for k in keys}

    canonical = (
        compact_json(manifest)
        .replace(b">", b"\\u003e")
        .replace(b"<", b"\\u003c")
        .replace(b"&", b"\\u0026")
    )
    digest = sha256_hex(canonical)

    signing_der = root / "signing.der"
    if not signing_der.exists():
        key_bytes = (
            bytes.fromhex("302e020100300506032b657004220420")
            + b"0123456789abcdef0123456789abcdef"
        )
        write_file(signing_der, key_bytes, 0o600)
    canon_path = root / f"canon-{release_id}"
    write_file(canon_path, canonical, 0o600)
    sign_proc = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(signing_der),
            "-keyform",
            "DER",
            "-in",
            str(canon_path),
        ],
        check=False,
        capture_output=True,
    )
    if sign_proc.returncode == 0:
        sig = sign_proc.stdout
    elif require_ed25519:
        err_txt = sign_proc.stderr.decode(errors="replace")
        raise RuntimeError(f"openssl Ed25519 signing failed: {err_txt}")
    else:
        # macOS LibreSSL lacks `pkeyutl -rawin`; self-test uses deterministic bytes.
        sig = hashlib.sha512(canonical).digest()
    manifest["signatures"] = [
        {
            "key_id": "rehearsal-key",
            "algorithm": "ed25519",
            "value": base64.b64encode(sig).decode().rstrip("="),
        }
    ]
    write_file(rel_dir / "manifest.json", compact_json(manifest), 0o400)
    return rel_dir, digest, manifest


def install_managed_release(
    install_root: pathlib.Path,
    rel_dir: pathlib.Path,
    release_id: str,
    digest: str,
    manifest: dict,
) -> pathlib.Path:
    """Materialize a valid managed release tree matching stage.rs expectations."""
    dest = install_root / "releases" / release_id
    dest.mkdir(parents=True, exist_ok=True)
    for art in manifest["artifacts"]:
        target = art["target"]
        src = rel_dir / art["id"]
        if target == "core_webmail":
            web_dir = dest / "webmail"
            web_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(src, mode="r:") as tar:
                tar.extractall(web_dir)
            for p in web_dir.rglob("*"):
                p.chmod(0o444 if p.is_file() else 0o555)
        elif target == "recovery_guide":
            write_file(dest / "share/docs/UPGRADE_RECOVERY.md", src.read_bytes(), 0o444)
        elif target == "release_sbom":
            write_file(dest / "share/evidence/sbom.json", src.read_bytes(), 0o444)
        elif target == "release_provenance":
            write_file(
                dest / "share/evidence/provenance.json", src.read_bytes(), 0o444
            )
        elif target.startswith("core_"):
            name_map = {
                "core_setjoind": "setjoind",
                "core_setjoin_server": "setjoin-server",
                "core_setjoin_auth": "setjoin-auth",
                "core_mailctl": "mailctl",
            }
            write_file(dest / name_map[target], src.read_bytes(), 0o555)
    write_file(dest / "manifest.json", (rel_dir / "manifest.json").read_bytes(), 0o444)
    write_file(dest / "manifest.digest", f"{digest}\n", 0o400)
    tree_bytes = b""
    for path in sorted(dest.rglob("*")):
        rel = str(path.relative_to(dest))
        if path.is_dir():
            tree_bytes += f"d\0{rel}\0\0".encode("utf-8")
        else:
            tree_bytes += f"f\0{rel}\0{sha256_hex(path.read_bytes())}\0".encode("utf-8")
    evidence = {
        "schema_version": 1,
        "release_id": release_id,
        "manifest_sha256": digest,
        "content_sha256": sha256_hex(tree_bytes),
    }
    write_file(dest / "installed.evidence.json", compact_json(evidence), 0o400)
    return dest


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_s3_fixture(
    stack: contextlib.ExitStack, objects: dict[str, bytes]
) -> int:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_HEAD(self) -> None:
            self._reply(False)

        def do_GET(self) -> None:
            self._reply(True)

        def _reply(self, send_body: bool) -> None:
            key = urllib.parse.urlparse(self.path).path.removeprefix("/rehearsal/")
            data = objects.get(key, b"{}")
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"rehearsal"')
            self.send_header("Last-Modified", "Wed, 04 Nov 2026 00:00:00 GMT")
            self.end_headers()
            if send_body:
                self.wfile.write(data)

    server = ReusableTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, name="rehearsal-s3", daemon=True
    )
    thread.start()

    def close() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    stack.callback(close)
    return int(server.server_address[1])


def seed_recovery_set(
    objects: dict[str, bytes],
    pg_env: dict[str, str],
    hmac_key: bytes,
    source_release_id: str,
    schema: int,
) -> tuple[str, str, dict]:
    identity = json.loads(psql_query(pg_env, "SELECT upgrade_recovery_identity_read()"))
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    recovery_id = str(uuid.uuid4())
    recovery = {
        "version": 1,
        "recoverySetId": recovery_id,
        "installationId": identity["installationId"],
        "timelineId": identity["timelineId"],
        "sourceReleaseId": source_release_id,
        "schemaVersion": schema,
        "createdAt": utc_stamp(now - dt.timedelta(minutes=1)),
        "expiresAt": utc_stamp(now + dt.timedelta(hours=23)),
    }
    components = {
        "database": b"rehearsal database",
        "databaseRestoreList": b"rehearsal list",
        "blobs": compact_json(
            {"timestamp": "rehearsal", "type": "full", "hashes": [], "count": 0,
             "total_size": 0}
        ),
        "configuration": b"{}",
    }
    for name, body in components.items():
        key = f"recovery-sets/{recovery_id}/{name}"
        objects[key] = body
        recovery[name] = {
            "objectKey": key,
            "size": len(body),
            "sha256": sha256_hex(body),
        }
    recovery.update(
        protectedKeyEvidence={
            "mode": "external",
            "keyId": "test",
            "fingerprint": "a" * 64,
        },
        featureToggleSha256="b" * 64,
        counts={"blobs": 0, "blobBytes": 0, "users": 1, "mailboxes": 1},
        representativeIds=None,
    )
    raw = compact_json(recovery)
    digest = sha256_hex(raw)
    sig = hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()
    objects[f"recovery-sets/{recovery_id}/manifest.json"] = compact_json(
        {"manifest": recovery, "manifestSha256": digest, "hmacSha256": sig}
    )
    return recovery_id, digest, identity


def approve_intent(
    pg_env: dict[str, str],
    rid: str,
    digest: str,
    manifest: dict,
    recovery_id: str,
    recovery_digest: str,
    identity: dict,
    schema: int,
    uid: str,
    arch: str,
) -> None:
    challenge, elevation, request = (str(uuid.uuid4()) for _ in range(3))
    q = sql_literal
    psql_query(
        pg_env,
        f"""
        UPDATE feature_toggles SET enabled=true
        WHERE key='feature.transactional_upgrades_execution';
        INSERT INTO upgrade_release_catalog(
          release_id,version,channel,platform,architecture,manifest_digest,manifest,
          metadata_version,catalog_generation,verified_by_key_ids,verified_at,
          metadata_expires_at
        )
        SELECT {q(rid)},'2.1.0','community','linux',{q(arch)},
               decode('{digest}','hex'),{q(json.dumps(manifest))}::jsonb,1,
               catalog_generation,ARRAY['rehearsal-key'],now(),
               now()+interval '1 day'
        FROM upgrade_control_state WHERE singleton;
        INSERT INTO upgrade_readiness(
          release_id,manifest_digest,readiness_generation,status,source_version,
          source_schema_version,target_schema_version,checks,blocker_count,
          expires_at,checked_by_user_id
        )
        VALUES({q(rid)},decode('{digest}','hex'),1,'ready','2.0.0',{schema},{schema},
               '{{}}',0,now()+interval '1 day',{uid});
        INSERT INTO upgrade_recovery_sets(
          recovery_set_id,installation_id,timeline_id,source_release_id,
          schema_version,manifest_digest,status,checks,created_at,expires_at,
          recorded_by_user_id
        )
        VALUES('{recovery_id}','{identity["installationId"]}',
               '{identity["timelineId"]}',{q(rid)},{schema},
               decode('{recovery_digest}','hex'),'verified',
               '{{"database":true,"databaseRestoreList":true,"blobs":true,
                 "configuration":true,"protectedKey":true,
                 "featureToggles":true,"hmac":true}}',
               now(),now()+interval '23 hours',{uid});
        INSERT INTO upgrade_challenges(
          id,actor_user_id,release_id,preview_digest,readiness_generation,
          policy_generation,expires_at,idempotency_key,request_digest
        )
        SELECT '{challenge}',{uid},{q(rid)},decode('{digest}','hex'),1,
               policy_generation,now()+interval '4 minutes','{request}',
               decode('{digest}','hex')
        FROM upgrade_control_state WHERE singleton;
        INSERT INTO upgrade_elevations(
          id,actor_user_id,challenge_id,release_id,preview_digest,
          readiness_generation,policy_generation,session_digest,factor_digest,
          amr,acr,expires_at,request_digest
        )
        SELECT '{elevation}',{uid},'{challenge}',{q(rid)},decode('{digest}','hex'),
               1,policy_generation,decode('{digest}','hex'),decode('{digest}','hex'),
               ARRAY['pwd','totp'],'urn:setjoin:aal2',now()+interval '4 minutes',
               decode('{digest}','hex')
        FROM upgrade_control_state WHERE singleton;
        UPDATE upgrade_challenges SET completed_at=now(),elevation_id='{elevation}'
        WHERE id='{challenge}';
        INSERT INTO upgrade_intents(
          installation_id,release_id,manifest_digest,catalog_generation,
          readiness_generation,policy_generation,preview_digest,state,
          requested_by_user_id,requester_elevation_id,approved_by_user_id,reason,
          expires_at,idempotency_key,request_digest,recovery_set_id,
          recovery_set_digest
        )
        SELECT installation_id,{q(rid)},decode('{digest}','hex'),catalog_generation,
               1,policy_generation,decode('{digest}','hex'),'approved',{uid},
               '{elevation}',{uid},'Wave 1.6 setjoind rehearsal',
               now()+interval '1 hour','{request}',decode('{digest}','hex'),
               '{recovery_id}',decode('{recovery_digest}','hex')
        FROM upgrade_control_state WHERE singleton;
        """,
    )


def http_request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes]:
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            ct = resp.headers.get("Content-Type", "")
            return (resp.status, ct, resp.read())
    except urllib.error.HTTPError as exc:
        ct = exc.headers.get("Content-Type", "") if exc.headers else ""
        return (exc.code, ct, exc.read())


def wait_for_ready(unified: bool) -> None:
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            st, _, _ = http_request("https://127.0.0.1/ready")
            if st == 200:
                if unified:
                    js, ct, body = http_request(
                        "https://127.0.0.1/.well-known/jwks.json"
                    )
                    if (
                        js == 200
                        and ct.lower().startswith("application/json")
                        and isinstance(json.loads(body.decode()).get("keys"), list)
                    ):
                        return
                else:
                    ah, _, _ = http_request("http://127.0.0.1:8443/health")
                    if ah == 200:
                        return
        except OSError:
            pass
        time.sleep(0.5)
    raise AssertionError(f"readiness timed out (unified={unified})")


def verify_session_and_mailbox(
    jwt_token: str, pg_env: dict[str, str], email: str, marker_subject: str
) -> None:
    st, _, body = http_request(
        "https://127.0.0.1/auth/me",
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    if st != 200:
        raise AssertionError(
            f"Stage 1 JWT failed /auth/me (HTTP {st}): {body[:256]!r}"
        )
    count = int(
        psql_query(
            pg_env,
            "SELECT count(*) FROM mailboxes "
            f"WHERE lower(email) = lower({sql_literal(email)}) "
            f"AND display_name = {sql_literal(marker_subject)}",
        )
    )
    if count != 1:
        raise AssertionError(f"mailbox continuity row missing: count={count}")


def render_split_host_env_and_units(
    repo_root: pathlib.Path,
    config_dir: pathlib.Path,
    systemd_dir: pathlib.Path,
    install_root: pathlib.Path,
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
    db_dsn: str,
    db_worker_dsn: str,
) -> None:
    cred_dir = config_dir / "db-credentials.d"
    cred_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o755)
    os.chmod(cred_dir, 0o750)
    cred_file = cred_dir / "db-credentials.env"
    write_file(
        cred_file,
        f"DB_WORKER_DSN={db_worker_dsn}\n"
        f"DB_OWNER_DSN={db_dsn}\n"
        f"DB_DIRECT_OWNER_DSN={db_dsn}\n",
        0o600,
    )
    config_env = config_dir / "config.env"
    write_file(
        config_env,
        "\n".join(
            [
                "HOSTNAME=localhost",
                "LISTEN_ADDR=127.0.0.1:0",
                f"TLS_CERT={cert_path}",
                f"TLS_KEY={key_path}",
                f"DB_DSN={db_dsn}",
                f"DB_DIRECT_DSN={db_dsn}",
                "AUTHSERVER_URL=http://127.0.0.1:8443",
                f"JWT_SECRET={TEST_JWT_SECRET}",
                "JWT_SIGNING_ALG=ES256",
                f"DB_ENCRYPTION_KEY={TEST_DB_ENC_KEY}",
                f"AUDIT_HMAC_KEY={TEST_AUDIT_KEY}",
                f"INTERNAL_API_KEY={TEST_INTERNAL_KEY}",
                "SMTP_INBOUND_ADDR=",
                "SMTP_INBOUND_TLS_ADDR=",
                "SMTP_SUBMISSION_ADDR=127.0.0.1:587",
                "IMAP_ADDR=",
                "IMAP_TLS_ADDR=127.0.0.1:993",
                "GATEWAY_HTTPS_LISTEN=127.0.0.1:443",
                "RUST_WORKERS_ON=http-tls,http-h2c",
                "GO_WORKERS_OFF=http-tls,http-h2c",
                "WORM_MODE=",
            ]
        )
        + "\n",
        0o600,
    )
    lib_sh = repo_root / "mailserver/deploy/scripts/lib-livekit.sh"
    deploy_dir = repo_root / "mailserver/deploy"
    auth_tmpl = shlex.quote(str(deploy_dir / "authserver.service.template"))
    auth_out = shlex.quote(str(systemd_dir / "setjoin-auth.service"))
    gw_tmpl = shlex.quote(str(deploy_dir / "setjoin-gateway.service.template"))
    gw_out = shlex.quote(str(systemd_dir / "setjoin-gateway.service"))
    render_script = f"""
set -euo pipefail
source {shlex.quote(str(lib_sh))}
INSTALL_DIR={shlex.quote(str(install_root))}
RUNTIME_DIR={shlex.quote(str(install_root / "current"))}
CONFIG_ENV={shlex.quote(str(config_env))}
AUTH_ENV={shlex.quote(str(config_dir / "auth.env"))}
GATEWAY_ENV={shlex.quote(str(config_dir / "gateway.env"))}
FEDERATION_ENV={shlex.quote(str(config_dir / "federation.env"))}
STORAGE_ENV={shlex.quote(str(config_dir / "storage.env"))}
SMTP_ENV={shlex.quote(str(config_dir / "smtp.env"))}
TLS_ENV={shlex.quote(str(config_dir / "tls.env"))}
DB_CRED_FILE={shlex.quote(str(cred_file))}
AUTHSERVER_URL=http://127.0.0.1:8443
GATEWAY_LISTEN=127.0.0.1:8090
TLS_AUTOCERT_CACHE_DIR=/var/cache/mailserver/autocert
render_auth_env "$AUTH_ENV" "$CONFIG_ENV" "$DB_CRED_FILE"
render_gateway_env "$GATEWAY_ENV"
render_tls_front_env "$TLS_ENV" "$CONFIG_ENV"
render_federation_env "$FEDERATION_ENV" "$CONFIG_ENV" "$DB_CRED_FILE"
render_storage_env "$STORAGE_ENV" "$CONFIG_ENV"
render_smtp_env "$SMTP_ENV" "$CONFIG_ENV" "$DB_CRED_FILE"
render_authserver_unit {auth_tmpl} {auth_out}
render_gateway_unit {gw_tmpl} {gw_out}
"""
    subprocess.run(["bash", "-c", render_script], check=True)


def run_updater_once(
    updater: pathlib.Path,
    root: pathlib.Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    cmd = [
        str(updater),
        "run",
        "--once",
        "--state-dir",
        str(root / "updater-journal"),
        "--release-store",
        str(root / "store"),
        "--dsn-file",
        str(root / "updater-dsn"),
        "--owner-dsn-file",
        str(root / "owner-dsn"),
        "--execution-config",
        str(root / "execution.json"),
        "--recovery-access-key-file",
        str(root / "s3-access"),
        "--recovery-secret-key-file",
        str(root / "s3-secret"),
        "--recovery-hmac-key-file",
        str(root / "recovery-hmac"),
        "--probe-credential-file",
        str(root / "probe-cred"),
    ]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)


def run_rehearsal(args: argparse.Namespace) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("setjoind_rehearsal.py must run as root in Linux Docker")

    arch = host_arch()
    dsn = args.db_dsn
    parsed = urllib.parse.urlparse(dsn)
    pg_env = dict(
        os.environ,
        PGHOST=parsed.hostname or "127.0.0.1",
        PGPORT=str(parsed.port or 5432),
        PGUSER=parsed.username or "mail",
        PGPASSWORD=parsed.password or "",
        PGDATABASE=parsed.path.lstrip("/"),
    )
    updater_dsn = args.updater_dsn or dsn.replace(
        f"{pg_env['PGUSER']}:", "setjoin_updater:updater_e2e@"
    )

    fixture_path = (
        args.repo_root
        / "server-rust/crates/release-format/tests/goldens/updater-fixtures.json"
    )
    fixture_template = json.loads(fixture_path.read_text(encoding="utf-8"))["samples"][
        0
    ]["manifest"]
    false_bin = pathlib.Path(shutil.which("false") or "/bin/false")

    with open("/tmp/setjoind-rehearsal-544.lock", "w", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        tmp_cm = tempfile.TemporaryDirectory(prefix="setjoind-rehearsal-")
        with tmp_cm as tmp_dir, contextlib.ExitStack() as stack:
            _run_rehearsal_locked(
                args,
                arch,
                dsn,
                pg_env,
                updater_dsn,
                fixture_template,
                false_bin,
                pathlib.Path(tmp_dir),
                stack,
            )


def _run_rehearsal_locked(
    args: argparse.Namespace,
    arch: str,
    dsn: str,
    pg_env: dict[str, str],
    updater_dsn: str,
    fixture_template: dict,
    false_bin: pathlib.Path,
    root: pathlib.Path,
    stack: contextlib.ExitStack,
) -> None:
    os.chmod(root, 0o755)
    systemd_dir = pathlib.Path("/etc/systemd/system")
    config_dir = pathlib.Path("/etc/setjoin")
    install_root = root / "opt-setjoin"
    install_root.mkdir(mode=0o755)
    bindir = root / "bin"
    bindir.mkdir(mode=0o755)

    supervisor = UnitSupervisor(systemd_dir, root / "run", root / "host.log")
    supervisor.start()
    stack.callback(supervisor.close)
    install_fake_systemctl(bindir, supervisor.sock_path)

    objects: dict[str, bytes] = {}
    s3_port = start_s3_fixture(stack, objects)
    hmac_key = b"wave16-setjoind-rehearsal-hmac-key-32b!"

    cert_path = root / "cert.pem"
    key_path = root / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    # Seed rehearsal user + primary mailbox with deterministic marker display_name.
    email = f"rehearsal-{uuid.uuid4().hex[:6]}@localhost"
    password = "Rehearsal-Password-2026!"
    marker_subject = f"Wave16-Marker-{uuid.uuid4().hex[:8]}"
    psql_query(
        pg_env,
        "INSERT INTO domains(name, is_local) VALUES('localhost', TRUE) "
        "ON CONFLICT (name) DO UPDATE SET is_local = TRUE;",
    )
    uid = psql_query(
        pg_env,
        f"INSERT INTO users(username, domain_id, email, password_hash, "
        f"display_name, enabled, is_local_admin, must_change_password, mfa_exempt) "
        f"SELECT {sql_literal(email.split('@')[0])}, id, {sql_literal(email)}, "
        f"crypt({sql_literal(password)}, gen_salt('bf', 4)), "
        f"{sql_literal(marker_subject)}, TRUE, FALSE, FALSE, TRUE "
        f"FROM domains WHERE name='localhost' RETURNING id;",
    )
    psql_query(
        pg_env,
        "INSERT INTO mailboxes(domain_id, user_id, email, display_name, "
        "is_primary, enabled) "
        f"SELECT domain_id, id, email, {sql_literal(marker_subject)}, TRUE, TRUE "
        f"FROM users WHERE id = {uid};",
    )

    schema = int(
        psql_query(
            pg_env,
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        )
    )
    registry = json.loads(
        psql_query(
            pg_env,
            "SELECT json_build_object("
            "'catalog_digest', registry_digest,"
            "'compatible_modes', ARRAY['enforce','observe'],"
            "'compatible_rollback_digests', ARRAY[registry_digest]"
            ") FROM feature_toggle_registry_state WHERE singleton",
        )
    )

    # Prepare updater credential & config files.
    write_file(root / "updater-dsn", updater_dsn, 0o600)
    write_file(root / "owner-dsn", dsn, 0o600)
    write_file(root / "s3-access", "rehearsal", 0o600)
    write_file(root / "s3-secret", "rehearsal-secret", 0o600)
    write_file(root / "recovery-hmac", hmac_key, 0o600)
    write_file(
        root / "probe-cred",
        compact_json({"email": email, "password": password}),
        0o600,
    )
    write_file(
        root / "execution.json",
        compact_json(
            {
                "version": 1,
                "enabled": True,
                "installRoot": str(install_root),
                "recoveryProvider": "s3",
                "recoveryEndpoint": f"http://127.0.0.1:{s3_port}",
                "recoveryBucket": "rehearsal",
                "recoveryRegion": "us-east-1",
            }
        ),
        0o600,
    )
    env = dict(
        os.environ,
        PATH=f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        INSTALL_DIR=str(install_root),
        SETJOIN_CONFIG_DIR=str(config_dir),
        SYSTEMD_DIR=str(systemd_dir),
        UPDATER_STATE_DIR=str(root / "updater-journal"),
    )

    # ── Stage 1: N-1 Split Baseline ──────────────────────────────────────
    n1_bins = {
        "setjoin-server": args.legacy_server or args.server_shim,
        "setjoin-auth": args.legacy_auth or args.auth_shim,
        "mailctl": args.mailctl,
    }
    rid_n_minus_1 = f"rel-n-minus-1-{uuid.uuid4().hex[:8]}"
    rel_n1_dir, dig_n1, man_n1 = sign_manifest(
        root, fixture_template, rid_n_minus_1, schema, registry,
        "split", n1_bins, arch,
    )
    install_managed_release(install_root, rel_n1_dir, rid_n_minus_1, dig_n1, man_n1)
    (install_root / "current").symlink_to(f"releases/{rid_n_minus_1}")

    render_split_host_env_and_units(
        args.repo_root, config_dir, systemd_dir, install_root,
        cert_path, key_path, dsn, dsn,
    )
    for sock in CORE_SOCKETS:
        if (systemd_dir / sock).exists():
            supervisor.handle_systemctl(["enable", sock])
            rc, _, err = supervisor.handle_systemctl(["start", sock])
            assert rc == 0, err
    for svc in ("setjoin-auth", "setjoin-gateway"):
        supervisor.handle_systemctl(["enable", svc])
        rc, _, err = supervisor.handle_systemctl(["start", svc])
        assert rc == 0, err
    wait_for_ready(unified=False)

    st, _, login_raw = http_request(
        "https://127.0.0.1/auth/login",
        method="POST",
        body=compact_json({"email": email, "password": password}),
        headers={"Content-Type": "application/json"},
    )
    assert st == 200, f"Stage 1 login failed ({st}): {login_raw!r}"
    stage1_jwt = json.loads(login_raw.decode("utf-8"))["access_token"]
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # ── Stage 2: Release N Expand Transactional Upgrade ──────────────────
    expand_bins = {
        "setjoind": args.setjoind,
        "setjoin-server": args.server_shim,
        "setjoin-auth": args.auth_shim,
        "mailctl": args.mailctl,
    }
    rid_n = f"rel-n-expand-{uuid.uuid4().hex[:8]}"
    _, dig_n, man_n = sign_manifest(
        root, fixture_template, rid_n, schema, registry,
        "expand", expand_bins, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n_minus_1, schema
    )
    approve_intent(
        pg_env, rid_n, dig_n, man_n, rec_id, rec_dig, ident, schema, uid, arch
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode == 0, f"Stage 2 updater failed: {res.stderr}"
    intent = json.loads(psql_query(pg_env, "SELECT upgrade_intent_read(NULL)"))
    assert intent["state"] == "verified", intent
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n}"
    )
    wait_for_ready(unified=False)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # ── Stage 3: Release N -> N-1 Auto-Rollback on Failing Probe ─────────
    # Return cleanly to N-1 baseline, then approve a failing Release N
    # cohort so `setjoin-updater run --once` switches N-1 -> N-bad, fails
    # post-switch readiness, and auto-rolls back to N-1.
    rid_n_minus_1_base = f"rel-n-minus-1-base-{uuid.uuid4().hex[:8]}"
    _, dig_n1_b, man_n1_b = sign_manifest(
        root, fixture_template, rid_n_minus_1_base, schema, registry,
        "split", n1_bins, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n, schema
    )
    approve_intent(
        pg_env, rid_n_minus_1_base, dig_n1_b, man_n1_b,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode == 0, f"Stage 3 N-1 return failed: {res.stderr}"
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n_minus_1_base}"
    )

    rid_bad_n = f"rel-n-bad-{uuid.uuid4().hex[:8]}"
    bad_expand = dict(expand_bins, setjoind=false_bin)
    _, dig_bad_n, man_bad_n = sign_manifest(
        root, fixture_template, rid_bad_n, schema, registry,
        "expand", bad_expand, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n_minus_1_base, schema
    )
    approve_intent(
        pg_env, rid_bad_n, dig_bad_n, man_bad_n,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode != 0, "Stage 3 failing probe unexpectedly succeeded"
    intent = json.loads(psql_query(pg_env, "SELECT upgrade_intent_read(NULL)"))
    assert intent["state"] == "rolled_back", intent
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n_minus_1_base}"
    )
    wait_for_ready(unified=False)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # ── Stage 4: Unified Cutover, N+1 Upgrade, Rollback, & Reverse ───────
    # Re-apply Release N expand so current carries setjoind before cutover.
    rid_n_cutover = f"rel-n-cutover-{uuid.uuid4().hex[:8]}"
    _, dig_nc, man_nc = sign_manifest(
        root, fixture_template, rid_n_cutover, schema, registry,
        "expand", expand_bins, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n_minus_1_base, schema
    )
    approve_intent(
        pg_env, rid_n_cutover, dig_nc, man_nc,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode == 0, f"Stage 4 re-apply N failed: {res.stderr}"
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n_cutover}"
    )

    upgrade_sh = args.repo_root / "mailserver/deploy/scripts/upgrade.sh"
    res = subprocess.run(
        ["bash", str(upgrade_sh), "migrate-to-setjoind", "--allow-single-cohort"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert res.returncode == 0, f"migrate-to-setjoind failed: {res.stderr}"
    assert (systemd_dir / "setjoind.service").is_file()
    assert not (systemd_dir / "setjoin-auth.service").exists()
    assert not (systemd_dir / "setjoin-gateway.service").exists()
    assert any(
        "READY=1" in m for m in supervisor.ready_events.get("setjoind.service", [])
    )
    wait_for_ready(unified=True)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # 4b. Transactional upgrade N -> N+1 (core_setjoind-only).
    unified_bins = {"setjoind": args.setjoind, "mailctl": args.mailctl}
    rid_n1 = f"rel-n1-unified-{uuid.uuid4().hex[:8]}"
    _, dig_n1_uni, man_n1_uni = sign_manifest(
        root, fixture_template, rid_n1, schema, registry,
        "unified", unified_bins, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n_cutover, schema
    )
    approve_intent(
        pg_env, rid_n1, dig_n1_uni, man_n1_uni,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode == 0, f"Stage 4 N+1 upgrade failed: {res.stderr}"
    intent = json.loads(psql_query(pg_env, "SELECT upgrade_intent_read(NULL)"))
    assert intent["state"] == "verified", intent
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n1}"
    )
    wait_for_ready(unified=True)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # 4c. Failing-probe auto-rollback under unified setjoind.service.
    rid_bad_n1 = f"rel-n1-bad-{uuid.uuid4().hex[:8]}"
    _, dig_bad_n1, man_bad_n1 = sign_manifest(
        root, fixture_template, rid_bad_n1, schema, registry,
        "unified", {"setjoind": false_bin, "mailctl": args.mailctl}, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n1, schema
    )
    approve_intent(
        pg_env, rid_bad_n1, dig_bad_n1, man_bad_n1,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode != 0, "Stage 4 bad N+1 unexpectedly succeeded"
    intent = json.loads(psql_query(pg_env, "SELECT upgrade_intent_read(NULL)"))
    assert intent["state"] == "rolled_back", intent
    assert (install_root / "current").readlink() == pathlib.Path(
        f"releases/{rid_n1}"
    )
    wait_for_ready(unified=True)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    # 4d. Return to Release N expand cohort, then run rollback-to-split-units.
    rid_n_back = f"rel-n-back-{uuid.uuid4().hex[:8]}"
    _, dig_nb, man_nb = sign_manifest(
        root, fixture_template, rid_n_back, schema, registry,
        "expand", expand_bins, arch,
    )
    rec_id, rec_dig, ident = seed_recovery_set(
        objects, pg_env, hmac_key, rid_n1, schema
    )
    approve_intent(
        pg_env, rid_n_back, dig_nb, man_nb,
        rec_id, rec_dig, ident, schema, uid, arch,
    )
    res = run_updater_once(args.updater, root, env)
    assert res.returncode == 0, f"Stage 4 return-to-N failed: {res.stderr}"
    res = subprocess.run(
        ["bash", str(upgrade_sh), "rollback-to-split-units"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert res.returncode == 0, f"rollback-to-split-units failed: {res.stderr}"
    assert not (systemd_dir / "setjoind.service").exists()
    assert (systemd_dir / "setjoin-gateway.service").is_file()
    assert (systemd_dir / "setjoin-auth.service").is_file()
    wait_for_ready(unified=False)
    verify_session_and_mailbox(stage1_jwt, pg_env, email, marker_subject)

    print("setjoind two-release Stage 1-4 live rehearsal: PASS")


class RehearsalSelfTest(unittest.TestCase):
    """Non-root portable self-test verifying arch map, units, manifests, and IPC."""

    def test_host_arch_mapping(self) -> None:
        self.assertEqual(host_arch("x86_64"), "amd64")
        self.assertEqual(host_arch("aarch64"), "arm64")
        self.assertEqual(host_arch("arm64"), "arm64")
        self.assertEqual(host_arch("loongarch64"), "loong64")
        with self.assertRaises(RuntimeError):
            host_arch("mips64")

    def test_parse_unit_templates_and_manifests(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parents[4]
        tmpl = repo_root / "mailserver/deploy/setjoind.service.template"
        parsed = parse_unit_file(tmpl)
        self.assertEqual(parsed["Service.Type"], ["notify"])
        self.assertEqual(
            parsed["Service.ExecStart"],
            ["{{RUNTIME_DIR}}/setjoind --subsystems=all"],
        )
        env_files = parsed["Service.EnvironmentFile"]
        self.assertLess(
            env_files.index("-{{FEDERATION_ENV}}"),
            env_files.index("{{CONFIG_ENV}}"),
        )
        fixture_path = (
            repo_root
            / "server-rust/crates/release-format/tests/goldens/updater-fixtures.json"
        )
        fixture_template = json.loads(fixture_path.read_text(encoding="utf-8"))[
            "samples"
        ][0]["manifest"]
        with tempfile.TemporaryDirectory(prefix="rehearsal-selftest-") as td:
            root = pathlib.Path(td)
            bins = {}
            for name in ("setjoind", "setjoin-server", "setjoin-auth", "mailctl"):
                p = root / f"bin-{name}"
                write_file(p, f"bin:{name}", 0o755)
                bins[name] = p
            reg = {
                "catalog_digest": "a" * 64,
                "compatible_modes": ["enforce", "observe"],
                "compatible_rollback_digests": ["a" * 64],
            }
            for cohort, expected_core in (
                ("split", {"setjoin-server", "setjoin-auth", "mailctl", "webmail"}),
                (
                    "expand",
                    {
                        "setjoind",
                        "setjoin-server",
                        "setjoin-auth",
                        "mailctl",
                        "webmail",
                    },
                ),
                ("unified", {"setjoind", "mailctl", "webmail"}),
            ):
                _, digest, manifest = sign_manifest(
                    root,
                    fixture_template,
                    f"test-{cohort}",
                    285,
                    reg,
                    cohort,
                    bins,
                    host_arch(),
                    require_ed25519=False,
                )
                self.assertEqual(len(digest), 64)
                core_ids = {
                    a["id"] for a in manifest["artifacts"] if a["cohort"] == "core"
                }
                self.assertEqual(core_ids, expected_core)

    def test_unit_supervisor_socket_activation_and_notify_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rs-", dir="/tmp") as td:
            root = pathlib.Path(td)
            systemd_dir = root / "units"
            systemd_dir.mkdir()
            bindir = root / "bin"
            bindir.mkdir()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            daemon = root / "dummy_daemon.py"
            write_file(
                daemon,
                f"""#!{sys.executable}
import os, signal, socket, sys
assert os.environ.get("LISTEN_PID") == str(os.getpid())
assert os.environ.get("LISTEN_FDS") == "1"
assert os.environ.get("LISTEN_FDNAMES") == "http"
srv = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
ns = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
ns.sendto(b"READY=1\\n", os.environ["NOTIFY_SOCKET"])
ns.close()
stop = False
def on_term(*_):
    global stop
    stop = True
signal.signal(signal.SIGTERM, on_term)
srv.settimeout(0.1)
while not stop:
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        continue
    with conn:
        conn.sendall(b"ok:" + str(os.getpid()).encode() + b"\\n")
""",
                0o755,
            )
            write_file(
                systemd_dir / "setjoin-gateway.socket",
                f"[Unit]\nConditionPathExists={daemon}\n"
                f"[Socket]\nListenStream=127.0.0.1:{port}\n"
                "FileDescriptorName=http\nService=setjoind.service\n",
                0o644,
            )
            write_file(
                systemd_dir / "setjoind.service",
                f"[Unit]\nRequires=setjoin-gateway.socket\n"
                f"[Service]\nType=notify\nExecStart={daemon}\n",
                0o644,
            )

            sup = UnitSupervisor(systemd_dir, root / "run", root / "host.log")
            sup.start()
            try:
                fake_ctl = install_fake_systemctl(bindir, sup.sock_path)
                for args in (
                    ["start", "setjoin-gateway.socket"],
                    ["start", "setjoind"],
                ):
                    res = subprocess.run(
                        [str(fake_ctl), *args], capture_output=True, text=True
                    )
                    self.assertEqual(res.returncode, 0, res.stderr)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
                    first = c.recv(64)
                self.assertTrue(first.startswith(b"ok:"), first)
                res = subprocess.run(
                    [str(fake_ctl), "restart", "setjoind"],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
                    second = c.recv(64)
                self.assertTrue(second.startswith(b"ok:"), second)
                self.assertNotEqual(first, second)
                res = subprocess.run(
                    [str(fake_ctl), "stop", "setjoind"], capture_output=True, text=True
                )
                self.assertEqual(res.returncode, 0, res.stderr)
            finally:
                sup.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run non-root portable self-tests (arch map, unit parser, supervisor IPC)",
    )
    parser.add_argument("--repo-root", type=pathlib.Path)
    parser.add_argument("--updater", type=pathlib.Path)
    parser.add_argument("--setjoind", type=pathlib.Path)
    parser.add_argument("--server-shim", type=pathlib.Path)
    parser.add_argument("--auth-shim", type=pathlib.Path)
    parser.add_argument("--legacy-server", type=pathlib.Path, default=None)
    parser.add_argument("--legacy-auth", type=pathlib.Path, default=None)
    parser.add_argument("--mailctl", type=pathlib.Path)
    parser.add_argument("--db-dsn", type=str)
    parser.add_argument("--updater-dsn", type=str, default=None)
    return parser.parse_args(argv)


if __name__ == "__main__":
    parsed = parse_args()
    if parsed.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RehearsalSelfTest)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)
    for required in (
        "repo_root",
        "updater",
        "setjoind",
        "server_shim",
        "auth_shim",
        "mailctl",
        "db_dsn",
    ):
        if getattr(parsed, required) is None:
            sys.exit(f"missing required option --{required.replace('_', '-')}")
    run_rehearsal(parsed)
