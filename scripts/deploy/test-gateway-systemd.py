#!/usr/bin/env python3
"""Exercise the gateway with real, disposable systemd socket/service units.

Run as root on a systemd host, passing a built setjoin-server executable.
This proves HTTP activation, capability removal and restart queuing, not public
TLS/protocol handover or installer integration. No installed Setjoin unit changes.
"""

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def command(*args):
    return subprocess.run(
        args, check=True, capture_output=True, text=True
    ).stdout.strip()


def wait_for(predicate, description):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"timed out: {description}")


def response(connection):
    connection.settimeout(10)
    connection.sendall(
        b"GET /_gateway/healthz HTTP/1.1\r\n"
        b"Host: localhost\r\nConnection: close\r\n\r\n"
    )
    data = bytearray()
    while block := connection.recv(4096):
        data.extend(block)
    assert data.startswith(b"HTTP/1.1 200 "), bytes(data)
    assert data.endswith(b"ok\n"), bytes(data)


def verify(binary, mode="legacy", companion_setjoind=None):
    if os.geteuid() != 0:
        raise RuntimeError("this lane requires root and a running systemd manager")
    command("systemctl", "show", "--property=Version", "--value")
    with tempfile.TemporaryDirectory(
        prefix="gofree-t13-systemd-", dir="/tmp"
    ) as directory:
        root = Path(directory)
        # The capability-empty service uses nobody, so copy the executable out
        # of potentially private build/worktree ancestors.
        root.chmod(0o755)
        if mode == "split-shim":
            if companion_setjoind is None:
                raise RuntimeError("--setjoind is required for --mode=split-shim")
            executable = root / "setjoin-server"
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            daemon = root / "setjoind"
            shutil.copyfile(companion_setjoind, daemon)
            daemon.chmod(0o755)
            exec_args = [str(executable)]
            svc_type = "notify"
        elif mode == "unified":
            executable = root / "setjoind"
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            exec_args = [str(executable), "--subsystems=http,protocols,workers"]
            svc_type = "notify"
        else:
            executable = root / "gofree-t13-gateway"
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            exec_args = [str(executable)]
            svc_type = "simple"
        gate = root / "stopping"
        hook = root / "gofree-t13-stop"
        hook.write_text(
            "#!/bin/sh\n"
            "for attempt in $(seq 1 200); do\n"
            f"  test -e '{gate}' || exit 0\n"
            "  sleep 0.05\n"
            "done\nexit 1\n"
        )
        hook.chmod(0o755)
        name = root.name
        service, listener = f"{name}.service", f"{name}.socket"
        print(
            f"Owned resources: {root}, {listener}, {service} (remove on exit)",
            flush=True,
        )
        # Reserve a random loopback port; systemd then owns the actual listener.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            address = reservation.getsockname()
        try:
            run_args = [
                "systemd-run",
                "--quiet",
                "--collect",
                f"--unit={name}",
                f"--socket-property=ListenStream={address[0]}:{address[1]}",
                "--socket-property=FileDescriptorName=http",
                "--socket-property=Accept=no",
                f"--property=Type={svc_type}",
                "--property=User=nobody",
                "--property=CapabilityBoundingSet=",
                "--property=AmbientCapabilities=",
                "--property=NoNewPrivileges=yes",
                "--property=TimeoutStopSec=15",
                f"--property=ExecStopPost={hook}",
                "--setenv=GATEWAY_RUST_AUTH_UPSTREAM=http://127.0.0.1:9",
            ]
            run_args.extend(exec_args)
            command(*run_args)
            with socket.create_connection(address, timeout=10) as connection:
                response(connection)
            first_pid = command(
                "systemctl", "show", service, "--property=MainPID", "--value"
            )
            assert int(first_pid) > 0
            status = dict(
                line.split(":", 1)
                for line in Path(f"/proc/{first_pid}/status").read_text().splitlines()
                if ":" in line
            )
            assert int(status["Uid"].split()[0]) != 0, status["Uid"]
            for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                assert int(status[field], 16) == 0, (field, status[field])

            # ExecStopPost keeps the restart in progress after the first main
            # process exits. The new connection must queue in systemd's socket.
            gate.touch()
            command("systemctl", "--no-block", "restart", service)
            wait_for(
                lambda: (
                    command(
                        "systemctl", "show", service, "--property=SubState", "--value"
                    )
                    == "stop-post"
                ),
                "old gateway exited before restart",
            )
            assert (
                command("systemctl", "show", service, "--property=MainPID", "--value")
                == "0"
            )
            with socket.create_connection(address, timeout=10) as queued:
                gate.unlink()
                response(queued)
            second_pid = command(
                "systemctl", "show", service, "--property=MainPID", "--value"
            )
            assert int(second_pid) > 0 and second_pid != first_pid
            with socket.create_connection(address, timeout=10) as connection:
                response(connection)
            print(
                f"systemd HTTP activation ({mode}, Type={svc_type}): PASS "
                "(empty capabilities, queued restart)"
            )
        finally:
            gate.unlink(missing_ok=True)
            # Stop the socket first so cleanup cannot activate another service.
            # StopUnit is idempotent for an already collected transient unit.
            for unit in (listener, service):
                result = subprocess.run(
                    ["systemctl", "stop", unit],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode and "not loaded" not in result.stderr:
                    raise RuntimeError(f"cleanup {unit}: {result.stderr}")
            for unit in (listener, service):
                state = command(
                    "systemctl", "show", unit, "--property=ActiveState", "--value"
                )
                assert state in ("inactive", "failed"), (unit, state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--mode",
        choices=("legacy", "split-shim", "unified"),
        default="legacy",
        help="unit mode: legacy gateway, Release N split-shim, or unified setjoind",
    )
    parser.add_argument(
        "--setjoind",
        type=Path,
        default=None,
        help="sibling setjoind executable (required when --mode=split-shim)",
    )
    parsed = parser.parse_args()
    verify(
        parsed.binary.resolve(strict=True),
        mode=parsed.mode,
        companion_setjoind=(
            parsed.setjoind.resolve(strict=True) if parsed.setjoind else None
        ),
    )
