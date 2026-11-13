"""Frozen-Go process oracle; record only into a new directory, replay never writes."""
import argparse
import base64
import http.server
import json
import os
import sys
import pwd
import re
import shutil
from pathlib import Path
import subprocess
import tempfile
import threading
import uuid
import pty
import select
import termios
import time

ROOT = Path(__file__).resolve().parent


def observe(binary, case):
    requests = []
    responses = iter(case.get("responses", []))

    class Server(http.server.BaseHTTPRequestHandler):
        def handle_request(self):
            size = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(size)
            captured_body = ({"body_base64": base64.b64encode(data).decode()} if case.get("binary_requests") else {"body": data.decode()})
            requests.append({
                "method": self.command, "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()
                            if k.lower() not in {"host", "user-agent", "connection", "accept-encoding", "content-length", "accept"}},
                **captured_body,
            })
            response = next(responses, {"status": 599, "body": "unexpected request"})
            self.send_response(response.get("status", 200))
            for key, value in response.get("headers", {}).items():
                self.send_header(key, value)
            body = (base64.b64decode(response["body_base64"]) if "body_base64" in response else (response.get("body", "{}") + " " * response.get("padding", 0)).encode())
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_GET = do_POST = do_PUT = do_DELETE = handle_request
        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(prefix="gofree-mctl2-oracle-", dir="/tmp") as home:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Server) as server:
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            thread.start()
            try:
                env = {k: v for k, v in os.environ.items()
                       if k not in {"MAILCTL_SERVER", "MAILCTL_TOKEN", "MAILCTL_API_KEY", "STORAGE_PROVIDER"}}
                env.update(HOME=home, USER="gofree-mctl2", MAILCTL_SERVER=f"http://127.0.0.1:{server.server_port}", MAILCTL_TOKEN="oracle-token")
                server_url = f"http://127.0.0.1:{server.server_port}"
                env.update({k: v.replace("$SERVER", server_url).replace("$HOME", home) for k,v in case.get("env", {}).items()})
                for name, body in case.get("files", {}).items():
                    path = Path(home, name)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body.replace("$SERVER", server_url))
                    path.chmod(case.get("file_modes", {}).get(name, 0o600))
                for name, body in case.get("binary_files", {}).items():
                    path = Path(home, name)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(base64.b64decode(body))
                    path.chmod(case.get("file_modes", {}).get(name, 0o600))
                for name, destination in case.get("symlinks", {}).items():
                    Path(home, name).symlink_to(Path(home, destination))
                args = [s.replace("$HOME", home).replace("$SERVER", server_url) for s in case["args"]]
                process_options = {}
                executable = binary
                if case.get("isolated_user"):
                    assert os.geteuid() == 0, "private-account config oracle requires root on Linux"
                    try:
                        pwd.getpwuid(65532)
                    except KeyError:
                        pass
                    else:
                        raise AssertionError("oracle UID 65532 must have no passwd entry")
                    executable = str(Path(home, "mailctl"))
                    try:
                        os.link(binary, executable)
                    except OSError:
                        shutil.copyfile(binary, executable)
                        Path(executable).chmod(0o755)
                    for path in [Path(home), *Path(home).rglob("*")]:
                        if not path.is_symlink() and str(path) != executable:
                            os.chown(path, 65532, 65532)
                    process_options = {"user":65532, "group":65532, "extra_groups":[]}
                if "umask" in case:
                    process_options["umask"] = case["umask"]
                if case.get("pty_login"):
                    master, slave = pty.openpty()
                    child = None
                    try:
                        child = subprocess.Popen([executable, *args], stdin=slave, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE, env=env, **process_options)
                        os.write(master, (case["pty_login"]["email"] + "\n").encode())
                        prefix = b""
                        deadline = time.monotonic() + 10
                        while b"Password: " not in prefix:
                            assert time.monotonic() < deadline, "login did not prompt for password"
                            ready, _, _ = select.select([child.stdout], [], [], 0.1)
                            if ready:
                                chunk = os.read(child.stdout.fileno(), 4096)
                                if not chunk:
                                    break
                                prefix += chunk
                        if b"Password: " in prefix:
                            while termios.tcgetattr(slave)[3] & termios.ECHO:
                                assert time.monotonic() < deadline, "login did not disable terminal echo"
                                time.sleep(0.001)
                            os.write(master, (case["pty_login"]["password"] + "\n").encode())
                        stdout, stderr = child.communicate(timeout=10)
                        result = subprocess.CompletedProcess(args, child.returncode, (prefix + stdout).decode(), stderr.decode())
                    finally:
                        if child is not None and child.poll() is None:
                            child.kill()
                            child.wait()
                        os.close(master)
                        os.close(slave)
                else:
                    binary_stdin = "stdin_base64" in case
                    result = subprocess.run([executable, *args],
                                            input=base64.b64decode(case["stdin_base64"]) if binary_stdin else case.get("stdin", ""),
                                            capture_output=True, text=not binary_stdin, env=env, timeout=15, **process_options)
                    if binary_stdin:
                        result.stdout = result.stdout.decode()
                        result.stderr = result.stderr.decode()
                def normalize(s):
                    s = s.replace(home, "$HOME").replace(f"127.0.0.1:{server.server_port}", "127.0.0.1:$PORT")
                    if case.get("artifact_temp_errors"):
                        s = re.sub(r"\.mailctl-private-artifact-[^/\s:]+", ".mailctl-private-artifact-$TEMP", s)
                    return s
                observation = {"requests": requests, "stdout": normalize(result.stdout),
                               "stderr": normalize(result.stderr), "exit": result.returncode}
                if case.get("generated_key"):
                    keys = {r["headers"]["idempotency-key"] for r in requests if "idempotency-key" in r["headers"]}
                    assert keys or result.returncode != 0, "generated mutation must carry its key"
                    for key in keys:
                        parsed = uuid.UUID(key)
                        assert parsed.version == 4 and str(parsed) == key
                        for request in requests:
                            if not case.get("header_only_key") and request["headers"].get("idempotency-key") == key and request.get("body") and request["headers"].get("content-type") == "application/json":
                                body = json.loads(request["body"])
                                assert body["idempotencyKey"] == key, "body/header key mismatch"
                        observation = json.loads(json.dumps(observation).replace(key, "$UUID"))
                if case.get("capture_files"):
                    observation["files"] = {}
                    for name in case["capture_files"]:
                        path = Path(home, name)
                        content = ({"body_base64": base64.b64encode(path.read_bytes()).decode()} if name in case.get("binary_capture", []) else {"body": normalize(path.read_text())}) if path.is_file() else None
                        observation["files"][name] = ({**content, "mode": path.stat().st_mode & 0o777} if content is not None else None)
                if case.get("no_artifact_temps"):
                    assert not list(Path(home).rglob(".mailctl-private-artifact-*")), "private artifact temporary file leaked"
                return observation
            finally:
                server.shutdown()
                thread.join()


def comparable(observation, case):
    if not case.get("map_table"):
        return observation
    # Go ranges over first-row map keys: column order varies between processes.
    # Keep exact cell contents and row order; normalize only column permutation.
    result = observation.copy()
    lines = result["stdout"].splitlines()
    if lines and lines[0] != "(empty)":
        columns = list(re.finditer(r"\S+", lines[0]))
        keys = [c.group() for c in columns]
        starts = [c.start() for c in columns]
        rows = []
        for line in lines[1:]:
            cells = [line[start:starts[i+1] if i+1 < len(starts) else None].rstrip(" ") for i,start in enumerate(starts)]
            rows.append(sorted(zip(keys,cells)))
        result["stdout"] = [sorted(keys), rows, result["stdout"].endswith("\n")]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["record", "replay", "self-test"])
    parser.add_argument("binary", type=lambda p: str(Path(p).resolve()))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cases = json.loads((ROOT / "cases.json").read_text())
    extra = ROOT / "cases-b.json"
    if extra.exists():
        cases += json.loads(extra.read_text())
    extra = ROOT / "cases-c.json"
    if extra.exists():
        cases += json.loads(extra.read_text())
    if args.mode == "self-test":
        case = next(c for c in cases if c["name"] == "health-check")
        expected = json.loads((ROOT / "goldens/health-check.json").read_text())
        assert observe(args.binary, case) == expected
        with tempfile.TemporaryDirectory(prefix="gofree-mctl2-mutants-", dir="/tmp") as temp:
            for mutant in ["request", "stdout", "exit"]:
                wrapper = Path(temp, mutant)
                wrapper.write_text(f"#!{sys.executable}\nimport os,subprocess,sys\n"
                    + ("os.environ['MAILCTL_TOKEN']='wrong-token'\n" if mutant == "request" else "")
                    + f"r=subprocess.run([{args.binary!r},*sys.argv[1:]])\n"
                    + ("print('wrong-output')\n" if mutant == "stdout" else "")
                    + f"sys.exit(r.returncode+{1 if mutant == 'exit' else 0})\n")
                wrapper.chmod(0o700)
                assert observe(str(wrapper), case) != expected, f"oracle missed {mutant} mutant"
            case = next(c for c in cases if c["name"] == "b-identity-upgrade-preflight")
            expected = json.loads((ROOT / "goldens" / (case["name"] + ".json")).read_text())
            assert observe(args.binary, case) == expected
            wrapper = Path(temp, "permissions")
            wrapper.write_text(f"#!{sys.executable}\nimport os,subprocess,sys\n"
                + f"r=subprocess.run([{args.binary!r},*sys.argv[1:]])\n"
                + "os.chmod(os.path.join(os.environ['HOME'],'preflight.json'),0o644)\n"
                + "sys.exit(r.returncode)\n")
            wrapper.chmod(0o700)
            assert observe(str(wrapper), case) != expected, "oracle missed file-permission mutant"
        print("mailctl oracle rejects request, stdout, exit and file-permission mutants")
        return
    selected = os.environ.get("MAILCTL_CASE")
    if selected:
        cases = [c for c in cases if c["name"] == selected]
    assert cases, "no cases selected"
    target = args.output if args.mode == "record" else ROOT / "goldens"
    if args.mode == "record":
        assert target and (not target.exists() or not any(target.iterdir())), "record into an empty directory only"
        target.mkdir(parents=True, exist_ok=True)
    for case in cases:
        got = observe(args.binary, case)
        path = target / (case["name"] + ".json")
        if args.mode == "record":
            path.write_text(json.dumps(got, indent=2, ensure_ascii=False) + "\n")
        else:
            want = json.loads(path.read_text())
            assert comparable(got, case) == comparable(want, case), f"{case['name']}\nexpected: {want}\nobserved: {got}"
    print(f"mailctl {args.mode}: {len(cases)} cases", flush=True)


if __name__ == "__main__":
    main()
