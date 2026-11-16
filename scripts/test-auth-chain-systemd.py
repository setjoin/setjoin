#!/usr/bin/env python3
"""#359b: setjoin-auth and the transitional authserverd under a real systemd.

Run as root on a systemd host: python3 scripts/test-auth-chain-systemd.py
Renders the real authserver.service.template and setjoin-authserverd.service.template
through lib-livekit.sh, swaps in fake executables and disposable runtime unit names,
and proves: start returns only once the credential-free readiness hand-off reaches
Go; stop returns only after authserverd has exited; a setjoin-auth crash returns
both active and ready; restart leaves authserverd active and the chain ready (N8);
authserverd never runs alone; when
setjoin-auth ends failed, authserverd is already stopped. No installed unit changes.
"""
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNITS = Path("/run/systemd/system")
RUST = '''#!/usr/bin/env python3
import http.server, os, signal, sys, urllib.error, urllib.request
if os.path.exists(os.environ["SETJOIN_TEST_FAIL_FLAG"]):
    sys.exit(1)
host, port = os.environ["LISTEN_ADDR"].rsplit(":", 1)
go = os.environ["AUTHSERVER_GO_UPSTREAM"]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code):
        self.send_response(code); self.send_header("Content-Length", "0"); self.end_headers()
    def do_GET(self):
        if self.path == "/health":
            return self.reply(200)
        try:
            urllib.request.urlopen(go + self.path, timeout=2).read()
            self.reply(200)
        except urllib.error.HTTPError as error:
            self.reply(error.code)
        except Exception:
            self.reply(502)
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
http.server.HTTPServer((host, int(port)), H).serve_forever()
'''
GO = '''#!/usr/bin/env python3
import http.server, os, signal, sys, time
host, port = os.environ["LISTEN_ADDR"].rsplit(":", 1)
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", "0"); self.end_headers()
def slow_exit(*a):
    time.sleep(3)
    sys.exit(0)
signal.signal(signal.SIGTERM, slow_exit)
http.server.HTTPServer((host, int(port)), H).serve_forever()
'''


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True).stdout.strip()


def prop(unit, name):
    return run("systemctl", "show", "-p", name, "--value", unit)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, description, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"timed out: {description}")


def readiness(port):
    try:
        return urllib.request.urlopen(f"http://127.0.0.1:{port}/_setjoin/readiness", timeout=5).status
    except urllib.error.HTTPError as error:
        return error.code


def render(directory, rs, go):
    env = dict(os.environ, INSTALL_DIR=str(directory), RUNTIME_DIR=str(directory),
               CONFIG_ENV=str(directory / "config.env"), AUTH_ENV=str(directory / "auth.env"),
               AUTHSERVERD_ENV=str(directory / "authserverd.env"),
               DB_CREDENTIALS_FILE=str(directory / "db-credentials.env"))
    script = (f'source "{ROOT}/mailserver/deploy/scripts/lib-livekit.sh" && '
              f'render_authserver_unit "{ROOT}/mailserver/deploy/authserver.service.template" "{directory}/rs.service" && '
              f'render_authserverd_unit "{ROOT}/mailserver/deploy/setjoin-authserverd.service.template" "{directory}/go.service"')
    subprocess.run(["bash", "-c", script], check=True, env=env)
    for source, name in (("rs.service", rs), ("go.service", go)):
        lines = [line for line in (directory / source).read_text().splitlines()
                 if not line.startswith(("ExecStartPre=", "User=", "Group="))]
        text = "\n".join(lines) + "\n"
        text = text.replace("RestartSec=5", "RestartSec=1")
        text = text.replace("setjoin-authserverd", go[: -len(".service")]).replace("setjoin-auth.service", rs)
        (UNITS / name).write_text(text)


def main():
    if os.geteuid() != 0:
        raise SystemExit("this lane requires root and a running systemd manager")
    run("systemctl", "show", "--property=Version", "--value")
    with tempfile.TemporaryDirectory(prefix="gofree-authchain-", dir="/run") as d:
        directory = Path(d)
        directory.chmod(0o755)
        rs, go = f"{directory.name}-rs.service", f"{directory.name}-go.service"
        p1, p2 = free_port(), free_port()
        flag = directory / "fail"
        for name, code in (("setjoin-auth", RUST), ("authserverd", GO)):
            (directory / name).write_text(code)
            (directory / name).chmod(0o755)
        (directory / "config.env").write_text("")
        (directory / "db-credentials.env").write_text("")
        (directory / "auth.env").write_text(
            f"LISTEN_ADDR=127.0.0.1:{p1}\nAUTHSERVER_GO_UPSTREAM=http://127.0.0.1:{p2}\nSETJOIN_TEST_FAIL_FLAG={flag}\n")
        (directory / "authserverd.env").write_text(f"LISTEN_ADDR=127.0.0.1:{p2}\n")
        print(f"Owned resources: {directory}, {UNITS / rs}, {UNITS / go} (removed on exit)", flush=True)
        try:
            render(directory, rs, go)
            run("systemctl", "daemon-reload")
            # 1. start returns only once the credential-free hand-off reaches Go (F7, N1).
            run("systemctl", "start", rs)
            assert prop(rs, "ActiveState") == "active" and prop(go, "ActiveState") == "active"
            assert readiness(p1) == 404, "readiness hand-off not answered by Go when start returned"
            # 2. stop returns only after authserverd's slow (3 s) exit (F3).
            started = time.monotonic()
            run("systemctl", "stop", rs)
            elapsed = time.monotonic() - started
            assert prop(go, "ActiveState") in ("inactive", "failed"), prop(go, "ActiveState")
            assert elapsed >= 2.5, f"stop returned after {elapsed:.1f}s, before authserverd exited"
            # 3. a crash: setjoin-auth auto-restarts; both end active and the chain is ready.
            run("systemctl", "start", rs)
            rs_pid = prop(rs, "MainPID")
            os.kill(int(rs_pid), 9)
            wait_for(lambda: prop(rs, "ActiveState") == "active" and prop(rs, "MainPID") not in (rs_pid, "0")
                     and prop(go, "ActiveState") == "active", "both active after a crash")
            wait_for(lambda: readiness(p1) == 404, "chain ready after a crash")
            # 4. N8: `systemctl restart setjoin-auth` must leave authserverd active and the
            # chain ready (an explicit stop in ExecStopPost would replace its restart job).
            run("systemctl", "restart", rs)
            assert prop(rs, "ActiveState") == "active", prop(rs, "ActiveState")
            assert prop(go, "ActiveState") == "active", "restart left authserverd " + prop(go, "ActiveState")
            assert readiness(p1) == 404, "chain not ready after restart"
            # 5. authserverd never runs alone (BindsTo, N2).
            run("systemctl", "stop", rs)
            run("systemctl", "start", go)
            wait_for(lambda: prop(rs, "ActiveState") == "active", "starting authserverd alone starts setjoin-auth")
            # 6. setjoin-auth ending failed leaves authserverd stopped (N2).
            flag.write_text("")
            os.kill(int(prop(rs, "MainPID")), 9)
            wait_for(lambda: prop(rs, "ActiveState") == "failed", "setjoin-auth reached failed (start limit)", 60)
            assert prop(go, "ActiveState") in ("inactive", "failed"), "authserverd still runs after setjoin-auth failed"
            started = time.monotonic()
            run("systemctl", "stop", rs)
            assert prop(go, "ActiveState") in ("inactive", "failed")
            flag.unlink()
            print("auth chain systemd: PASS")
        finally:
            run("systemctl", "stop", rs, check=False)
            run("systemctl", "stop", go, check=False)
            for name in (rs, go):
                (UNITS / name).unlink(missing_ok=True)
            run("systemctl", "daemon-reload", check=False)
            run("systemctl", "reset-failed", rs, go, check=False)


if __name__ == "__main__":
    main()
