#!/usr/bin/env python3
"""Exercise the rendered HTTPS service, queued restart and optional peer outage.

Requires root, systemd and a built gateway. Owns only gofree-tlsfront-* resources;
no database or installed Setjoin unit is used. The certificate is a public fixture.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def wait_for(predicate, description):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if value := predicate():
            return value
        time.sleep(0.05)
    raise AssertionError(f"timed out: {description}")


def health(connection):
    connection.settimeout(10)
    connection.sendall(b"GET /_gateway/healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    data = bytearray()
    while block := connection.recv(4096):
        data.extend(block)
    assert data.startswith(b"HTTP/1.1 200 ") and data.endswith(b"ok\n"), bytes(data)


def verify(binary):
    assert os.geteuid() == 0, "requires root and systemd"
    run("systemctl", "show", "--property=Version", "--value")
    with tempfile.TemporaryDirectory(prefix="gofree-tlsfront-systemd-", dir="/run") as path:
        directory = Path(path)
        directory.chmod(0o755)
        executable = directory / "setjoin-gateway"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        named_executable = directory / "gofree-tlsfront-gateway"
        os.link(executable, named_executable)
        fixture = json.loads((ROOT / "server-rust/tests/conformance/tlsfront/tls13-resumed.json").read_text())
        (directory / "cert.pem").write_text(fixture["certificate_pem"])
        (directory / "key.pem").write_text(fixture["public_test_key_pem"])
        context = ssl.create_default_context(cafile=str(directory / "cert.pem"))
        context.set_alpn_protocols(["http/1.1"])
        name = directory.name
        mappings = {
            "setjoin-gateway.service": f"{name}.service",
            "setjoin-gateway.socket": f"{name}.socket",
            "setjoin-https.socket": f"{name}-https.socket",
            "setjoin-federation.socket": f"{name}-federation.socket",
        }
        service = mappings["setjoin-gateway.service"]
        gate = directory / "stopping"
        hook = directory / "gofree-tlsfront-stop"
        hook.write_text(f"#!/bin/sh\nfor attempt in $(seq 1 200); do\n test -e '{gate}' || exit 0\n sleep 0.05\ndone\nexit 1\n")
        hook.chmod(0o755)
        (directory / "gateway.env").write_text("GATEWAY_AUTH_UPSTREAM=http://127.0.0.1:9\n")
        (directory / "federation.env").write_text(
            "RUST_WORKERS_ON=http-tls\nGO_WORKERS_OFF=http-tls,http-h2c,federation-service\n"
            f"FEDERATION_LOCAL_DOMAIN=zulu.test\nFEDERATION_CERT={directory}/cert.pem\nFEDERATION_KEY={directory}/key.pem\n"
        )
        literal_dns = '{"CF_API_TOKEN":"literal-$-value"}'
        (directory / "tls.env").write_text(
            f"TLS_CERT={directory}/cert.pem\nTLS_KEY={directory}/key.pem\n"
            f"TLS_DNS_CONFIG={literal_dns}\nTLS_SESSION_TICKET_KEY_ROTATE_SECS=60\n"
        )
        # Public test data only; the substituted nobody account must read it.
        for filename in ("cert.pem", "key.pem", "gateway.env", "federation.env", "tls.env"):
            (directory / filename).chmod(0o644)
        with socket.socket() as occupied, socket.socket() as plain, socket.socket() as tls:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            plain.bind(("127.0.0.1", 0))
            tls.bind(("127.0.0.1", 0))
            address = tls.getsockname()
            config = directory / "config.env"
            config.write_text(f"TLS_CERT={directory}/cert.pem\nRUST_WORKERS_ON=http-tls\n")
            env = dict(os.environ, INSTALL_DIR=str(directory), RUNTIME_DIR=str(directory),
                       CONFIG_ENV=str(config), GATEWAY_ENV=str(directory / "gateway.env"),
                       TLS_ENV=str(directory / "tls.env"), FEDERATION_ENV=str(directory / "federation.env"),
                       GATEWAY_LISTEN=f"127.0.0.1:{plain.getsockname()[1]}",
                       GATEWAY_HTTPS_LISTEN=f"127.0.0.1:{address[1]}", FEDERATION_ENABLED="true",
                       FEDERATION_LISTEN_ADDR=f"127.0.0.1:{occupied.getsockname()[1]}")
            run("bash", "-c", 'source "$1"; render_gateway_unit "$2" "$3"', "render",
                str(ROOT / "mailserver/deploy/scripts/lib-livekit.sh"),
                str(ROOT / "mailserver/deploy/setjoin-gateway.service.template"),
                str(directory / "setjoin-gateway.service"), env=env)
            installed = []
            print(f"Owned resources: {directory}, {list(mappings.values())}; removed on exit", flush=True)
            try:
                for original, target in mappings.items():
                    text = (directory / original).read_text()
                    for source, replacement in mappings.items():
                        text = text.replace(source, replacement)
                    text = text.replace(" setjoin.service setjoin-auth.service", "")
                    text = text.replace("Wants=setjoin.service setjoin-auth.service\n", "")
                    text = text.replace("User=setjoin", "User=nobody").replace("Group=setjoin", "Group=nogroup")
                    text = text.replace(f"ExecStart={executable}", f"ExecStart={named_executable}")
                    if original.endswith(".service"):
                        text += f"\n[Service]\nExecStopPost={hook}\n"
                    destination = Path("/run/systemd/system") / target
                    assert not destination.exists(), destination
                    destination.write_text(text)
                    installed.append(destination)
                plain.close()
                tls.close()
                run("systemctl", "daemon-reload")
                run("systemctl", "start", service)
                with context.wrap_socket(socket.create_connection(address, timeout=10), server_hostname="localhost") as connection:
                    health(connection)
                pid = run("systemctl", "show", service, "--property=MainPID", "--value")
                status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                assert int(status["Uid"].split()[0]) != 0, status["Uid"]
                for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    assert int(status[field], 16) == 0, (field, status[field])
                environment = dict(item.split(b"=", 1) for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0") if b"=" in item)
                assert environment[b"TLS_DNS_CONFIG"] == literal_dns.encode()
                assert environment[b"TLS_SESSION_TICKET_KEY_ROTATE_SECS"] == b"60"
                assert not {b"DB_OWNER_DSN", b"DB_DIRECT_OWNER_DSN", b"JWT_SECRET", b"S3_SECRET_KEY"}.intersection(environment)
                assert run("systemctl", "show", mappings["setjoin-federation.socket"], "-p", "ActiveState", "--value") == "failed"
                assert "activated socket named federation missing" in run("journalctl", "-u", service, "--no-pager", "-o", "cat")
                gate.touch()
                run("systemctl", "--no-block", "restart", service)
                wait_for(lambda: run("systemctl", "show", service, "-p", "SubState", "--value") == "stop-post", "old process stopped")
                assert run("systemctl", "show", service, "-p", "MainPID", "--value") == "0"
                with socket.create_connection(address, timeout=10) as queued:
                    gate.unlink()
                    with context.wrap_socket(queued, server_hostname="localhost") as connection:
                        health(connection)
                assert run("systemctl", "show", service, "-p", "MainPID", "--value") != pid
                print("native HTTPS systemd: PASS (rendered service, no capabilities, queued restart, federation bind outage)")
            finally:
                gate.unlink(missing_ok=True)
                subprocess.run(["systemctl", "stop", *mappings.values()], capture_output=True)
                subprocess.run(["systemctl", "reset-failed", *mappings.values()], capture_output=True)
                for destination in installed:
                    destination.unlink()
                run("systemctl", "daemon-reload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    verify(parser.parse_args().binary.resolve())
