"""Frozen worker tick: database seed + authenticated object I/O, through processes."""

import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from backup_oracle import ACCESS, S3, SECRET, clean_dsn, env_for, preserve_database, sql

HERE = Path(__file__).resolve().parent
BLOB = b"MCTL4 worker blob\x00\xe9\x9b\x86\xe5\x90\x88"
HASH = hashlib.sha256(BLOB).hexdigest()
SEED = bytes(32)


DEPLOYMENT_ID = "identity.deployment_id"


def canonical_config(raw):
    """Config JSON without the deployment-ID fixture row, in Go's compact HTML-escaped form."""
    try:
        body = json.loads(raw)
    except ValueError:
        return raw  # seeded non-JSON placeholder object
    if not isinstance(body, dict) or DEPLOYMENT_ID not in body:
        return raw
    body.pop(DEPLOYMENT_ID)
    return (
        json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .encode()
    )


def observe(binary, dsn, recording, variant="worker", preserve=True):
    with (
        tempfile.TemporaryDirectory(prefix="gofree-mctl4-worker-", dir="/tmp") as tmp,
        S3() as s3,
    ):
        root = Path(tmp)
        with preserve_database(dsn, root) if preserve else contextlib.nullcontext():
            sql(
                dsn,
                "SET client_min_messages=warning; TRUNCATE backup_runs,blobs,system_config CASCADE;",
            )
            sql(
                dsn,
                "INSERT INTO system_config(key,value,encrypted) VALUES('backup.retention_policy','{\"gfs\":\"1d0w0m\"}',false),('fixture.encrypted','{\"ciphertext\":\"synthetic opaque bytes\"}',true),('fixture.escaped','[\"<node>\",\"&\"]',false)",
            )
            # Startup validates the identity connector secrets and needs the deployment ID
            # (#415); the id is a fixture row like the others.
            sql(
                dsn,
                "INSERT INTO system_config(key,value,encrypted) VALUES('identity.deployment_id','\"mctl4-oracle-deployment\"',false)",
            )
            sql(
                dsn,
                f"INSERT INTO blobs(sha256,minio_ref,size_bytes,ref_count) VALUES('{HASH}','ignored/minio/ref',{len(BLOB)},1)",
            )
            sql(
                dsn,
                "INSERT INTO backup_runs(id,status,created_at,completed_at,manifest_timestamp) VALUES(9900354,'completed','2000-01-01','2000-01-01','20000101T000000Z'); INSERT INTO backup_runs(id,status,started_at,created_at) VALUES(9900355,'running','2026-01-01','2026-01-01')",
            )
            s3.objects["primary/blobs/" + HASH] = BLOB
            for key in [
                "manifests/incr-20000101T000000Z.json",
                "config-20000101T000000Z.json",
                "backup-manifest-20000101T000000Z.json",
            ]:
                s3.objects["backup/" + key] = b"old index"
            if variant in ("worker-skip", "worker-repair"):
                s3.objects["backup/blobs/" + HASH] = (
                    BLOB if variant == "worker-skip" else b"X" * len(BLOB)
                )
            if variant == "worker-corrupt":
                s3.objects["primary/blobs/" + HASH] = b"X" * len(BLOB)
            key = root / "signing-key"
            key.write_text(SEED.hex())
            key.chmod(0o600)
            env = env_for(dsn, root) | {
                "TEST_DB_DSN": dsn,
                "MCTL4_RUN_ID": "9900355",
                "MCTL4_S3_ENDPOINT": s3.url,
                "BACKUP_SIGNING_KEY_FILE": str(key),
                "BACKUP_PROVIDER": "s3",
                "BACKUP_ENDPOINT": s3.url,
                "BACKUP_BUCKET": "backup",
                "BACKUP_REGION": "us-east-1",
                "BACKUP_ACCESS_KEY": ACCESS,
                "BACKUP_SECRET_KEY": SECRET,
                "S3_ENDPOINT": s3.url,
                "S3_BUCKET": "primary",
                "S3_ACCESS_KEY": ACCESS,
                "S3_SECRET_KEY": SECRET,
                "S3_SECURE": "false",
                "GATEWAY_LISTEN": "127.0.0.1:0",
                "GATEWAY_AUTH_UPSTREAM": "http://127.0.0.1:1",
                "RUST_WORKERS_ON": "backup-engine",
                "GO_WORKERS_OFF": "backup-engine",
            }
            if not recording and os.environ.get("MAILCTL_WORKER_WITH_RECOVERY") == "1":
                env["RUST_WORKERS_ON"] = "backup-engine,mail-recovery-cleanup"
                env["GO_WORKERS_OFF"] = "backup-engine,mail-recovery-cleanup"
            if variant == "worker-no-spool":
                env["TMPDIR"] = str(root / "unavailable")
            if variant == "worker-replica":
                env.update(
                    {
                        "MCTL4_REPLICA": "1",
                        "BACKUP_REPLICA_PROVIDER": "s3",
                        "BACKUP_REPLICA_ENDPOINT": s3.url,
                        "BACKUP_REPLICA_BUCKET": "replica",
                        "BACKUP_REPLICA_REGION": "us-east-1",
                        "BACKUP_REPLICA_ACCESS_KEY": ACCESS,
                        "BACKUP_REPLICA_SECRET_KEY": SECRET,
                    }
                )
            if variant == "worker-posix":
                bucket = root / "posix"
                bucket.mkdir()
                for name, data in list(s3.objects.items()):
                    if name.startswith("backup/"):
                        key = name.removeprefix("backup/")
                        path = bucket / key[:2] / key
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                        del s3.objects[name]
                env.update(
                    {
                        "MCTL4_BACKUP_PROVIDER": "posix",
                        "BACKUP_PROVIDER": "posix",
                        "BACKUP_BUCKET": str(bucket),
                    }
                )
            if variant == "worker-oss":
                env.update({"MCTL4_BACKUP_PROVIDER": "oss", "BACKUP_PROVIDER": "oss"})
            if variant == "worker-backup-s3":
                env.update(
                    {
                        "MCTL4_BACKUP_PROVIDER": "backup_s3",
                        "BACKUP_PROVIDER": "backup_s3",
                    }
                )
            command = (
                [binary, "-test.run=^TestMCTL4RecordBackupTick$", "-test.v"]
                if recording
                else [binary]
            )
            log = root / "process.log"
            with log.open("w") as output:
                child = subprocess.Popen(command, env=env, stdout=output, stderr=output)
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        state = json.loads(
                            sql(
                                dsn,
                                "SELECT row_to_json(t) FROM (SELECT status,blob_count,blobs_copied,blobs_skipped,config_size,blob_total_size,error_log,manifest_timestamp,started_at IS NOT NULL AS started,completed_at IS NOT NULL AS completed FROM backup_runs WHERE id=9900355) t",
                            )
                        )
                        # Retention follows the terminal row. Observe its external completion.
                        if state["status"] in ("completed", "failed") and (
                            state["status"] == "failed"
                            or (
                                sql(
                                    dsn,
                                    "SELECT count(*) FROM backup_runs WHERE id=9900354",
                                )
                                == "0"
                                and (
                                    variant != "worker-replica"
                                    or "replica/backup-manifest.json" in s3.objects
                                )
                            )
                        ):
                            break
                        if child.poll() is not None:
                            break
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(0.02)
                    if not recording and child.poll() is None:
                        child.send_signal(signal.SIGTERM)
                    code = child.wait(timeout=10)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=10)
            if variant == "worker-posix":
                for path in bucket.rglob("*"):
                    if path.is_file():
                        s3.objects[
                            "backup/" + str(path.relative_to(bucket)).split("/", 1)[1]
                        ] = path.read_bytes()
            if state["status"] != "completed":
                assert state["status"] == "failed" and code == 0, log.read_text()
                assert "backup/backup-manifest.json" not in s3.objects, (
                    "incomplete copy published a manifest"
                )
                return {
                    "exit": code,
                    "state": state,
                    "objects": {
                        k: base64.b64encode(
                            canonical_config(v)
                            if k.rsplit("/", 1)[-1].startswith("config")
                            else v
                        ).decode()
                        for k, v in sorted(s3.objects.items())
                        if "/" in k
                    },
                    "requests": [
                        [verb, key]
                        for verb, key in s3.requests
                        if "/" in key and not key.endswith("/")
                    ],
                    "old_run_removed": sql(
                        dsn, "SELECT count(*) FROM backup_runs WHERE id=9900354"
                    )
                    == "0",
                }
            assert code == 0, log.read_text()
            stamp = state["manifest_timestamp"]
            datetime.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(
                tzinfo=datetime.timezone.utc
            )
            index = json.loads(s3.objects["backup/backup-manifest.json"])
            signature = base64.b64decode(index["signature"] + "==")
            public = base64.b64decode(index["signing_public_key"] + "==")
            private = root / "ed25519.der"
            private.write_bytes(
                bytes.fromhex("302e020100300506032b657004220420") + SEED
            )
            private.chmod(0o600)
            expected_public = subprocess.check_output(
                [
                    "openssl",
                    "pkey",
                    "-inform",
                    "DER",
                    "-in",
                    str(private),
                    "-pubout",
                    "-outform",
                    "DER",
                ]
            )[-32:]
            assert (
                public == expected_public
                and index["signing_key_id"] == hashlib.sha256(public).hexdigest()
            )
            unsigned = dict(index)
            del unsigned["signature"]
            payload = (
                json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"))
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .encode()
            )
            pubfile = root / "public.der"
            pubfile.write_bytes(bytes.fromhex("302a300506032b6570032100") + public)
            sigfile = root / "signature"
            sigfile.write_bytes(signature)
            message = root / "signed.json"
            message.write_bytes(payload)
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(pubfile),
                    "-rawin",
                    "-in",
                    str(message),
                    "-sigfile",
                    str(sigfile),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            config = s3.objects["backup/config.json"]
            assert index["config_sha256"] == hashlib.sha256(
                config
            ).hexdigest() and index["config_size_bytes"] == len(config)
            assert json.loads(config)["fixture.encrypted"]["encrypted"] is True
            assert s3.objects["backup/blobs/" + HASH] == BLOB
            assert index["blob_manifest"] == {
                "timestamp": stamp,
                "type": "incr",
                "hashes": [HASH],
                "count": 1,
                "total_size": len(BLOB),
            }
            state["manifest_timestamp"] = "$STAMP"
            objects = {}
            for key, data in sorted(s3.objects.items()):
                if "/" not in key:
                    # Startup creates the missing primary bucket (#415): bucket-level,
                    # not an object of the recorded worker run.
                    continue
                if "/blobs/" in key:
                    objects[key] = base64.b64encode(data).decode()
                    continue
                value = json.loads(data)
                if "signature" in value:
                    value["signature"] = "$VERIFIED_ED25519"
                objects[key.replace(stamp, "$STAMP")] = json.loads(
                    json.dumps(value).replace(stamp, "$STAMP")
                )
            # The deployment-ID fixture row (needed by startup, #415) is not part of the recorded
            # Go run: drop it from every config object and re-derive the digests the manifests and
            # the run state carry (Go's compact, HTML-escaped config encoding; the originals were
            # verified against the manifests above).
            canonical = canonical_config(config)
            for name, value in objects.items():
                leaf = name.rsplit("/", 1)[-1]
                if leaf.startswith("config") and isinstance(value, dict):
                    value.pop(DEPLOYMENT_ID, None)
                if leaf.startswith("backup-manifest") and "config_sha256" in value:
                    value["config_sha256"] = hashlib.sha256(canonical).hexdigest()
                    value["config_size_bytes"] = len(canonical)
            state["config_size"] = len(canonical)
            # Bucket-region discovery is SDK transport metadata, not an object operation.
            requests = [
                [method, key.replace(stamp, "$STAMP")]
                for method, key in s3.requests
                if "/" in key and not key.endswith("/")
            ]
            if variant == "worker-replica":
                for key, data in s3.objects.copy().items():
                    if key.startswith("backup/"):
                        assert (
                            s3.objects["replica/" + key.removeprefix("backup/")] == data
                        )
                # Primary retention and replica execute concurrently in Go. Keep
                # each store's ordered effects while allowing their interleave.
                # The primary commit precedes both tasks; replica source reads
                # and retention deletes may interleave even on the same bucket.
                commit = next(
                    i
                    for i, r in enumerate(requests)
                    if r == ["PUT", "backup/backup-manifest.json"]
                )
                requests = {
                    "commit": requests[: commit + 1],
                    "retention": [
                        r for r in requests[commit + 1 :] if r[0] == "DELETE"
                    ],
                    "mirror": [r for r in requests[commit + 1 :] if r[0] != "DELETE"],
                }
            return {
                "exit": code,
                "state": state,
                "objects": objects,
                "requests": requests,
                "old_run_removed": sql(
                    dsn, "SELECT count(*) FROM backup_runs WHERE id=9900354"
                )
                == "0",
            }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["record", "replay"])
    p.add_argument("binary")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    dsn = os.environ.get("TEST_DB_DSN")
    assert dsn, "TEST_DB_DSN required"
    clean_dsn(dsn)
    with open("/tmp/gofree-mctl4-backup.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if a.mode == "record":
            assert a.output and not a.output.exists()
            a.output.mkdir()
        selected = os.environ.get("MAILCTL_WORKER_CASE")
        cases = [
            "worker",
            "worker-no-spool",
            "worker-replica",
            "worker-posix",
            "worker-oss",
            "worker-skip",
            "worker-repair",
            "worker-corrupt",
            "worker-backup-s3",
        ]
        assert not selected or selected in cases
        with (
            tempfile.TemporaryDirectory(
                prefix="gofree-mctl4-worker-suite-", dir="/tmp"
            ) as tmp,
            preserve_database(dsn, Path(tmp)),
        ):
            for name in cases:
                if selected and selected != name:
                    continue
                got = observe(
                    str(Path(a.binary).resolve()),
                    dsn,
                    a.mode == "record",
                    name,
                    preserve=False,
                )
                if a.mode == "record":
                    assert (
                        got["exit"] == 0
                        and got["state"]["status"]
                        == ("failed" if name == "worker-corrupt" else "completed")
                        and got["old_run_removed"] == (name != "worker-corrupt")
                    ), got
                    (a.output / (name + ".json")).write_text(
                        json.dumps(got, indent=2, ensure_ascii=False) + "\n"
                    )
                else:
                    want = json.loads(
                        (HERE / "backup-goldens" / (name + ".json")).read_text()
                    )
                    assert got == want, (name, want, got)
                print("backup worker " + a.mode + ": " + name, flush=True)


if __name__ == "__main__":
    main()
