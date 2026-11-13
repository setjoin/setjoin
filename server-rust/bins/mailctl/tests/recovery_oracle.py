"""Application recovery-set process oracle: API, exported snapshot and object store."""

import argparse
import datetime
import fcntl
import hashlib
import hmac
import http.server
import json
import os
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from backup_oracle import (
    S3,
    assert_private_children,
    audit_pg_tools,
    canonical_snapshot,
    clean_dsn,
    env_for,
    pg_env,
    preserve_database,
    reset_public_fixture,
    sql,
)

HERE = Path(__file__).resolve().parent
INSTALL = "00000000-0000-4000-8000-000000000001"
TIMELINE = "00000000-0000-4000-8000-000000000002"
STAMP = "20260823T010000Z"
KEY = b"gofree-mctl4-recovery-key-00000000"
PROTECTED = b"gofree-mctl4-protected-key-0000000"
BLOB = b"MCTL4 worker blob\x00\xe9\x9b\x86\xe5\x90\x88"
HASH = hashlib.sha256(BLOB).hexdigest()


def canonical(v):
    return (
        json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .encode()
    )


class API:
    def __enter__(self):
        service = self
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length", 0))
                ).decode()
                service.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "body": body,
                        "headers": {
                            k.lower(): v
                            for k, v in self.headers.items()
                            if k.lower()
                            in ("authorization", "content-type", "x-audit-reason")
                        },
                    }
                )
                if self.path.endswith("/recovery-context"):
                    v = {
                        "installationId": INSTALL,
                        "timelineId": TIMELINE,
                        "schemaVersion": 275,
                    }
                elif self.path.endswith("/backup/list"):
                    v = [{"id": 17, "status": "completed", "manifest_timestamp": STAMP}]
                elif self.path.endswith("/backup"):
                    v = {"run_id": 17}
                elif self.path.endswith("/version"):
                    v = {"version": "v2.4.0"}
                elif self.path.endswith("/recovery-sets"):
                    v = {"recorded": True}
                else:
                    raise AssertionError(self.path)
                data = json.dumps(v).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = respond

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01)
        )
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def seed(dsn, s3):
    reset_public_fixture(dsn)
    sql(
        dsn,
        f"""CREATE TABLE users(id bigint primary key); CREATE TABLE mailboxes(id bigint primary key,user_id bigint references users(id));
    CREATE TABLE blobs(sha256 text primary key,size_bytes bigint,ref_count int);
    CREATE TABLE system_config(key text primary key,value jsonb,encrypted boolean);
    CREATE TABLE feature_toggles(key text primary key,enabled boolean);
    CREATE TABLE upgrade_control_state(singleton boolean,installation_id uuid,timeline_id uuid);
    CREATE TABLE schema_migrations(version int);
    INSERT INTO users VALUES(7); INSERT INTO mailboxes VALUES(17,7);
    INSERT INTO blobs VALUES('{HASH}',24,1);
    INSERT INTO upgrade_control_state VALUES(true,'{INSTALL}','{TIMELINE}');INSERT INTO schema_migrations VALUES(275);
    INSERT INTO feature_toggles VALUES('feature.fixture',true),('feature.second',false);
    INSERT INTO system_config VALUES('fixture.secret','\"synthetic ciphertext\"',true),('fixture.escaped','[\"<node>\",\"&\"]',false);""",
    )
    config = {
        k: {"value": v, "encrypted": e}
        for k, v, e in json.loads(
            sql(
                dsn,
                "SELECT json_agg(json_build_array(key,value::text,encrypted) ORDER BY key) FROM system_config",
            )
        )
    }
    s3.objects["fixture/config-" + STAMP + ".json"] = canonical(config)
    s3.objects["fixture/manifests/incr-" + STAMP + ".json"] = canonical(
        {
            "timestamp": STAMP,
            "type": "incr",
            "hashes": [HASH],
            "count": 1,
            "total_size": len(BLOB),
        }
    )
    s3.objects["fixture/blobs/" + HASH] = BLOB


def create(binary, dsn, record_to=None):
    with (
        tempfile.TemporaryDirectory(prefix="gofree-mctl4-recovery-", dir="/tmp") as tmp,
        S3() as s3,
        API() as api,
    ):
        root = Path(tmp)
        with preserve_database(dsn, root):
            seed(dsn, s3)
            before = canonical_snapshot(dsn)
            for name, data in [("recovery-key", KEY), ("protected-key", PROTECTED)]:
                p = root / name
                p.write_bytes(data)
                p.chmod(0o600)
            env = env_for(dsn, root) | {
                "MAILCTL_SERVER": api.url,
                "MAILCTL_TOKEN": "oracle-token",
            }
            audit = audit_pg_tools(root, env)
            result = subprocess.run(
                [
                    binary,
                    "backup",
                    "create",
                    "--pre-upgrade",
                    "--json",
                    "--bucket",
                    "fixture",
                    "--endpoint",
                    s3.url,
                    "--region",
                    "us-east-1",
                    "--recovery-key-file",
                    str(root / "recovery-key"),
                    "--protected-key-file",
                    str(root / "protected-key"),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode:
                return {
                    "exit": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr.replace(str(root), "$HOME"),
                    "requests": api.requests,
                }
            if record_to is None:
                assert_private_children(audit, dsn, "pg_dump")
            manifest_key = next(k for k in s3.objects if k.endswith("/manifest.json"))
            envelope = json.loads(s3.objects[manifest_key])
            m = envelope["manifest"]
            parsed_id = uuid.UUID(m["recoverySetId"])
            assert parsed_id.version == 4 and str(parsed_id) == m["recoverySetId"]
            raw = canonical(m)
            assert envelope["manifestSha256"] == hashlib.sha256(
                raw
            ).hexdigest() and hmac.compare_digest(
                envelope["hmacSha256"], hmac.new(KEY, raw, hashlib.sha256).hexdigest()
            )
            assert (
                m["installationId"] == INSTALL
                and m["timelineId"] == TIMELINE
                and m["sourceReleaseId"] == "2.4.0"
                and m["schemaVersion"] == 275
            )
            assert m["counts"] == {
                "blobs": 1,
                "blobBytes": 24,
                "users": 1,
                "mailboxes": 1,
            }
            assert m["protectedKeyEvidence"] == {
                "mode": "external",
                "keyId": "db-encryption-key",
                "fingerprint": hashlib.sha256(PROTECTED).hexdigest(),
            }
            assert m["representativeIds"] == ["user:7", "mailbox:17", "blob:" + HASH]
            created = datetime.datetime.fromisoformat(
                m["createdAt"].replace("Z", "+00:00")
            )
            expires = datetime.datetime.fromisoformat(
                m["expiresAt"].replace("Z", "+00:00")
            )
            assert expires - created == datetime.timedelta(hours=24)
            assert (
                abs(
                    (
                        datetime.datetime.now(datetime.timezone.utc) - created
                    ).total_seconds()
                )
                < 120
            )
            for key in ["database", "databaseRestoreList", "blobs", "configuration"]:
                a = m[key]
                data = s3.objects["fixture/" + a["objectKey"]]
                assert (
                    len(data) == a["size"]
                    and hashlib.sha256(data).hexdigest() == a["sha256"]
                )
            dump = root / "database.dump"
            dump.write_bytes(s3.objects["fixture/" + m["database"]["objectKey"]])
            listing = subprocess.check_output(["pg_restore", "--list", str(dump)])
            assert (
                s3.objects["fixture/" + m["databaseRestoreList"]["objectKey"]]
                == listing
            ), (s3.objects["fixture/" + m["databaseRestoreList"]["objectKey"]], listing)
            reset_public_fixture(dsn)
            r = subprocess.run(
                [
                    "pg_restore",
                    "--exit-on-error",
                    "--dbname=" + clean_dsn(dsn),
                    str(dump),
                ],
                env=pg_env(dsn),
                capture_output=True,
                text=True,
                check=False,
            )
            assert r.returncode == 0, r.stderr
            assert canonical_snapshot(dsn) == before, (
                "exported dump contents differ from the snapshot seed"
            )
            replacements = {
                m["recoverySetId"]: "$UUID",
                m["createdAt"]: "$CREATED",
                m["expiresAt"]: "$EXPIRES",
                envelope["manifestSha256"]: "$VERIFIED_MANIFEST_SHA",
                m["database"]["sha256"]: "$VERIFIED_DATABASE_SHA",
                m["databaseRestoreList"]["sha256"]: "$VERIFIED_LIST_SHA",
                envelope["hmacSha256"]: "$VERIFIED_HMAC",
            }

            def normalize(v):
                raw = json.dumps(v, ensure_ascii=False)
                for old, new in replacements.items():
                    raw = raw.replace(old, new)
                return json.loads(raw)

            if record_to:
                (record_to / "create-envelope.json").write_text(
                    json.dumps(envelope, indent=2) + "\n"
                )
            normalized = normalize(envelope)
            normalized["manifest"]["database"]["size"] = "$VERIFIED_DUMP_SIZE"
            normalized["manifest"]["databaseRestoreList"]["size"] = (
                "$VERIFIED_LIST_SIZE"
            )
            stdout = normalize(result.stdout)
            requests = normalize(api.requests)
            assert (
                json.loads(result.stdout)["manifestDigest"]
                == envelope["manifestSha256"]
            )
            last = json.loads(api.requests[-1]["body"])
            assert (
                last["manifestDigest"] == envelope["manifestSha256"]
                and last["recoverySetId"] == m["recoverySetId"]
                and last["checks"]
                == {
                    "database": True,
                    "databaseRestoreList": True,
                    "blobs": True,
                    "configuration": True,
                    "protectedKey": True,
                    "featureToggles": True,
                    "hmac": True,
                }
            )
            return {
                "exit": 0,
                "stdout": stdout,
                "stderr": result.stderr,
                "requests": requests,
                "envelope": normalized,
                "objects": sorted(
                    k.replace(m["recoverySetId"], "$UUID") for k in s3.objects
                ),
                "operations": [
                    [verb, key.replace(m["recoverySetId"], "$UUID")]
                    for verb, key in s3.requests
                    if not key.endswith("/")
                ],
            }


def verify(binary, variant):
    import copy
    import gzip

    with (
        tempfile.TemporaryDirectory(
            prefix="gofree-mctl4-recovery-verify-", dir="/tmp"
        ) as tmp,
        S3() as s3,
        API() as api,
    ):
        root = Path(tmp)
        m = copy.deepcopy(
            json.loads((HERE / "backup-goldens/recovery-create.json").read_text())[
                "envelope"
            ]["manifest"]
        )
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        m.update(
            recoverySetId="00000000-0000-4000-8000-000000000003",
            createdAt=now.isoformat().replace("+00:00", "Z"),
            expiresAt=(now + datetime.timedelta(hours=24))
            .isoformat()
            .replace("+00:00", "Z"),
        )
        components = {
            "database": gzip.decompress(
                (HERE / "fixtures/go-seeded.dump.gz").read_bytes()
            ),
            "databaseRestoreList": b"; Go restore list\n",
            "blobs": canonical(
                {
                    "timestamp": STAMP,
                    "type": "incr",
                    "hashes": [HASH],
                    "count": 1,
                    "total_size": 24,
                }
            ),
            "configuration": b"{}",
        }
        for kind, data in components.items():
            a = m[kind]
            a["objectKey"] = a["objectKey"].replace("$UUID", m["recoverySetId"])
            a["size"] = len(data)
            a["sha256"] = hashlib.sha256(data).hexdigest()
            s3.objects["fixture/" + a["objectKey"]] = data
        s3.objects["fixture/blobs/" + HASH] = BLOB
        if variant == "verify-expired":
            m["createdAt"] = (
                (now - datetime.timedelta(hours=25)).isoformat().replace("+00:00", "Z")
            )
            m["expiresAt"] = (
                (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            )
        if variant == "verify-timeline":
            m["timelineId"] = "00000000-0000-4000-8000-000000000004"
        raw = canonical(m)
        e = {
            "manifest": m,
            "manifestSha256": hashlib.sha256(raw).hexdigest(),
            "hmacSha256": hmac.new(KEY, raw, hashlib.sha256).hexdigest(),
        }
        if variant == "verify-hmac":
            e["hmacSha256"] = "0" * 64
        if variant == "verify-component":
            s3.objects["fixture/" + m["configuration"]["objectKey"]] = b"[]"
        s3.objects["fixture/recovery-sets/" + m["recoverySetId"] + "/manifest.json"] = (
            canonical(e)
        )
        for name, data in [
            ("recovery-key", KEY),
            (
                "protected-key",
                b"X" * 32 if variant == "verify-protected" else PROTECTED,
            ),
        ]:
            p = root / name
            p.write_bytes(data)
            p.chmod(0o600)
        # Verification is an object/authentication operation; PostgreSQL executables
        # must never be invoked. Run without DB credentials or pg tools in PATH.
        env = env_for("", root) | {
            "MAILCTL_SERVER": api.url,
            "MAILCTL_TOKEN": "oracle-token",
            "PATH": str(root),
        }
        for key in [
            "DB_DSN",
            "DB_DIRECT_DSN",
            "DB_OWNER_DSN",
            "DB_DIRECT_OWNER_DSN",
            "TEST_DB_DSN",
        ]:
            env.pop(key, None)
        result = subprocess.run(
            [
                binary,
                "backup",
                "verify",
                "--pre-upgrade",
                "--json",
                "--bucket",
                "fixture",
                "--endpoint",
                s3.url,
                "--region",
                "us-east-1",
                "--recovery-key-file",
                str(root / "recovery-key"),
                "--protected-key-file",
                str(root / "protected-key"),
                m["recoverySetId"],
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        replacement = {
            m["recoverySetId"]: "$UUID",
            m["createdAt"]: "$CREATED",
            m["expiresAt"]: "$EXPIRES",
            e["manifestSha256"]: "$VERIFIED_MANIFEST_SHA",
        }

        def norm(v):
            raw = json.dumps(v, ensure_ascii=False)
            for old, new in replacement.items():
                raw = raw.replace(old, new)
            return json.loads(raw)

        return norm(
            {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "requests": api.requests,
                "operations": [
                    [verb, key] for verb, key in s3.requests if not key.endswith("/")
                ],
            }
        )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["record", "replay"])
    p.add_argument("binary")
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    dsn = os.environ.get("TEST_DB_DSN")
    assert dsn
    clean_dsn(dsn)
    with open("/tmp/gofree-mctl4-backup.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if a.mode == "record":
            assert a.output and not a.output.exists()
            a.output.mkdir()
        selected = os.environ.get("MAILCTL_RECOVERY_CASE")
        cases = [
            "recovery-create",
            "verify",
            "verify-hmac",
            "verify-expired",
            "verify-protected",
            "verify-timeline",
            "verify-component",
        ]
        assert not selected or selected in cases
        for name in cases:
            if selected and selected != name:
                continue
            got = (
                create(
                    str(Path(a.binary).resolve()),
                    dsn,
                    a.output if a.mode == "record" else None,
                )
                if name == "recovery-create"
                else verify(str(Path(a.binary).resolve()), name)
            )
            if a.mode == "record":
                assert got["exit"] == (
                    0 if name in ("recovery-create", "verify") else 2
                ), got
                (a.output / (name + ".json")).write_text(
                    json.dumps(got, indent=2) + "\n"
                )
            else:
                want = json.loads(
                    (HERE / "backup-goldens" / (name + ".json")).read_text()
                )
                assert got == want, (name, want, got)
            print("application recovery " + name + " " + a.mode, flush=True)


if __name__ == "__main__":
    main()
