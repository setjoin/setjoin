#!/usr/bin/env python3
"""Native federation socket activation under a disposable capability-empty systemd unit.
Requires root, systemd, psql, the assigned disposable TEST_DB_DSN, and a built gateway.
Only this task's unit, temporary directory and peer-domain fixture are changed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
ORACLE = ROOT / "server-rust/crates/protocols/federation/oracle"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def sql(dsn, statement):
    return run("psql", "-XAt", "-v", "ON_ERROR_STOP=1", dsn, input=statement)


def frame(connection, payload):
    data = payload.encode()
    connection.sendall(struct.pack("!I", len(data)) + data)


def read_frame(connection):
    def read(n):
        data = b""
        while len(data) < n:
            block = connection.recv(n - len(data))
            if not block:
                raise AssertionError("unexpected federation EOF")
            data += block
        return data
    return read(struct.unpack("!I", read(4))[0]).decode()


def verify_unbindable_socket(binary):
    """Use the installed renderer: an occupied peer port cannot take HTTP down."""
    with tempfile.TemporaryDirectory(prefix="gofree-fed2-optional-", dir="/run") as path:
        directory = Path(path)
        directory.chmod(0o755)
        name = directory.name
        units = (f"{name}.service", f"{name}.socket", f"{name}-federation.socket")
        print(f"Owned optional-socket resources: {directory}, {units}; removed on exit", flush=True)
        executable = directory / "setjoin-gateway"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        (directory / "gateway.env").write_text("GATEWAY_AUTH_UPSTREAM=http://127.0.0.1:9\n")
        (directory / "federation.env").write_text(
            "FEDERATION_LOCAL_DOMAIN=zulu.test\n"
            f"FEDERATION_CERT={ORACLE}/certs/zulu.crt\nFEDERATION_KEY={ORACLE}/certs/zulu.key\n"
            "GO_WORKERS_OFF=federation-service\n"
        )
        with socket.socket() as occupied, socket.socket() as reservation:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            reservation.bind(("127.0.0.1", 0))
            http = reservation.getsockname()
            reservation.close()
            env = dict(os.environ, INSTALL_DIR=str(directory), RUNTIME_DIR=str(directory),
                       GATEWAY_ENV=str(directory / "gateway.env"), FEDERATION_ENV=str(directory / "federation.env"),
                       GATEWAY_LISTEN=f"{http[0]}:{http[1]}", FEDERATION_ENABLED="true",
                       FEDERATION_LISTEN_ADDR=f"127.0.0.1:{occupied.getsockname()[1]}")
            run("bash", "-c", 'source "$1"; render_gateway_unit "$2" "$3"', "render",
                str(ROOT / "mailserver/deploy/scripts/lib-livekit.sh"),
                str(ROOT / "mailserver/deploy/setjoin-gateway.service.template"),
                str(directory / "setjoin-gateway.service"), env=env)
            installed = []
            try:
                for original, target in zip(
                    ("setjoin-gateway.service", "setjoin-gateway.socket", "setjoin-federation.socket"), units
                ):
                    text = (directory / original).read_text()
                    text = text.replace("setjoin-gateway.service", units[0]).replace("setjoin-gateway.socket", units[1])
                    text = text.replace("setjoin-federation.socket", units[2])
                    text = text.replace(" setjoin.service setjoin-auth.service", "")
                    text = text.replace("Wants=setjoin.service setjoin-auth.service\n", "")
                    text = text.replace("User=setjoin", "User=nobody").replace("Group=setjoin", "Group=nogroup")
                    destination = Path("/run/systemd/system") / target
                    assert not destination.exists(), destination
                    destination.write_text(text)
                    installed.append(destination)
                run("systemctl", "daemon-reload")
                run("systemctl", "start", units[0])
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with urllib.request.urlopen(f"http://{http[0]}:{http[1]}/_gateway/healthz", timeout=1) as response:
                            assert response.status == 200 and response.read() == b"ok\n"
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                assert run("systemctl", "show", units[2], "-p", "ActiveState", "--value") == "failed"
                logs = run("journalctl", "-u", units[0], "--no-pager", "-o", "cat")
                assert "activated socket named federation missing" in logs, logs
            finally:
                subprocess.run(["systemctl", "stop", *units], capture_output=True)
                subprocess.run(["systemctl", "reset-failed", *units], capture_output=True)
                for destination in installed:
                    destination.unlink()
                run("systemctl", "daemon-reload")
    print("federation optional socket: PASS (occupied peer port, rendered Wants, HTTP healthy, disabled-leg log)")


def verify(binary):
    if os.geteuid() != 0:
        raise RuntimeError("requires root and a running systemd manager")
    run("systemctl", "show", "--property=Version", "--value")
    dsn = os.environ["TEST_DB_DSN"]
    # This rehearsal is deliberately tied to FED2's assigned disposable DB.
    if not dsn.endswith("/gofree_e2e_fed2"):
        raise RuntimeError("TEST_DB_DSN must name the assigned gofree_e2e_fed2 database")
    peer = "alpha.test"
    # Refuse existing peer state rather than borrowing or overwriting it.
    assert sql(dsn, "SELECT count(*) FROM federation_allowlist WHERE peer_domain='alpha.test'") == "0"
    prior = sql(dsn, "SELECT enabled FROM feature_toggles WHERE key='feature.federation'")
    with tempfile.TemporaryDirectory(prefix="gofree-fed2-systemd-", dir="/tmp") as directory:
        directory = Path(directory)
        directory.chmod(0o755)
        name = directory.name
        units = (f"{name}.socket", f"{name}.service")
        print(f"Owned resources: {directory}, {units}; assigned DB peer {peer}; removed on exit", flush=True)
        executable = directory / "gateway"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        for file in ("zulu.crt", "zulu.key", "alpha.crt", "alpha.key", "ca-zulu.crt"):
            shutil.copyfile(ORACLE / "certs" / file, directory / file)
            (directory / file).chmod(0o644)  # Public oracle keys, never production identities.
        environment = directory / "runtime.env"
        environment.write_text(
            f"DB_DSN={dsn}\nDB_DIRECT_DSN={dsn}\n"
            "GATEWAY_AUTH_UPSTREAM=http://127.0.0.1:9\nGATEWAY_LISTEN=127.0.0.1:0\n"
            "GO_WORKERS_OFF=federation-service\nFEDERATION_LOCAL_DOMAIN=zulu.test\n"
            f"FEDERATION_CERT={directory}/zulu.crt\nFEDERATION_KEY={directory}/zulu.key\n"
        )
        environment.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            address = reservation.getsockname()
        context = ssl.create_default_context(cafile=str(directory / "ca-zulu.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(directory / "alpha.crt", directory / "alpha.key")
        anchor = (ORACLE / "certs/ca-alpha.crt").read_text().replace("'", "''")
        seeded = False
        try:
            sql(dsn, f"INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('{peer}','{anchor}',true); UPDATE feature_toggles SET enabled=true WHERE key='feature.federation';")
            seeded = True
            run("systemd-run", "--quiet", "--collect", f"--unit={name}",
                f"--socket-property=ListenStream={address[0]}:{address[1]}",
                "--socket-property=FileDescriptorName=federation", "--socket-property=Accept=no",
                "--property=User=nobody", "--property=CapabilityBoundingSet=",
                "--property=AmbientCapabilities=", "--property=NoNewPrivileges=yes",
                "--property=TimeoutStopSec=15", f"--property=EnvironmentFile={environment}", str(executable))
            recordings = json.loads((ORACLE / "v2-go-sessions.json").read_text())
            requests = json.loads((ORACLE / "v2-requests.json").read_text())
            case = next(c for c in requests["cases"] if c["name"] == "unknown_content_type_redacted")
            expected = next(c for c in recordings["cases"] if c["name"] == case["name"])
            for generation in range(2):
                with socket.create_connection(address, timeout=15) as connection:
                    connection.settimeout(15)
                    with context.wrap_socket(connection, server_hostname="zulu.test") as stream:
                        frame(stream, case["steps"][0]["body"])
                        hello = read_frame(stream)
                        # Frozen Go's accept hello keeps resumeFromSeq=0 even after
                        # delivery. Durable dedup, rather than this hint, protects replay.
                        assert hello == expected["results"][0]["frames"][0]
                        frame(stream, case["steps"][2]["body"])
                        assert read_frame(stream) == expected["results"][1]["frames"][0]
                        pid = int(run("systemctl", "show", units[1], "--property=MainPID", "--value"))
                        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                        assert int(status["Uid"].split()[0]) != 0
                        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                            assert int(status[field], 16) == 0, (field, status[field])
                if generation == 0:
                    run("systemctl", "restart", units[1])
            assert sql(dsn, "SELECT count(*) FROM federation_inbox WHERE peer_domain='alpha.test'") == "1"
        finally:
            subprocess.run(["systemctl", "stop", *units], capture_output=True)
            subprocess.run(["systemctl", "reset-failed", *units], capture_output=True)
            if seeded:
                sql(dsn, "DELETE FROM federation_inbox WHERE peer_domain='alpha.test'; DELETE FROM federation_inbox_cursor WHERE peer_domain='alpha.test'; DELETE FROM federation_ingress_counters WHERE peer_domain='alpha.test'; DELETE FROM federation_allowlist WHERE peer_domain='alpha.test'; UPDATE feature_toggles SET enabled=" + ("true" if prior == "t" else "false") + " WHERE key='feature.federation';")
    print("federation systemd: PASS (native TLS delivery, capability-empty activation, durable dedup across restart)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve()
    verify_unbindable_socket(binary)
    verify(binary)
