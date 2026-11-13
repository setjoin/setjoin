"""Backup process/worker seams. Only the explicit disposable test database is used."""

import argparse
import contextlib
import datetime
import fcntl
import gzip
import hashlib
import hmac
import http.server
import io
import json
import os
import re
import shutil
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

from db_snapshot import snapshot

HERE = Path(__file__).resolve().parent
ACCESS = "mctl4-fixture-access"
SECRET = "mctl4-fixture-secret"
HMAC_KEY = b"gofree-mctl4-dump-auth-key-00000000"


def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def pg_env(dsn):
    u = urllib.parse.urlsplit(dsn)
    return os.environ | {"PGPASSWORD": urllib.parse.unquote(u.password or "")}


def clean_dsn(dsn):
    u = urllib.parse.urlsplit(dsn)
    assert (
        u.scheme in ("postgres", "postgresql")
        and u.hostname in ("127.0.0.1", "localhost")
        and (u.path.startswith("/gofree_") or u.path.endswith("_test"))
    ), "requires an explicit loopback disposable test database"
    return urllib.parse.urlunsplit(
        (
            u.scheme,
            urllib.parse.quote(u.username or "") + "@" + u.hostname + ":" + str(u.port),
            u.path,
            u.query,
            "",
        )
    )


def sql(dsn, statement):
    return subprocess.check_output(
        ["psql", clean_dsn(dsn), "-XAt", "-v", "ON_ERROR_STOP=1", "-c", statement],
        env=pg_env(dsn),
        text=True,
    ).strip()


class S3:
    def __init__(self):
        self.objects = {}
        self.requests = []
        self.errors = []
        self.fail = set()
        self.before = None

    def __enter__(self):
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def reply(self, status, body=b"", headers=None):
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def handle_object(self):
                try:
                    uri = urllib.parse.urlsplit(self.path)
                    path = uri.path
                    auth = self.headers.get("Authorization", "")
                    oss = auth.startswith("OSS4-")
                    if oss:
                        m = re.fullmatch(
                            r"OSS4-HMAC-SHA256 Credential=([^/]+)/([^,]+),(?:AdditionalHeaders=([^,]+),)?Signature=([0-9a-f]{64})",
                            auth,
                        )
                        assert m, "missing OSS4 authorization"
                        access, scope, additional, signature = m.groups()
                        assert access == ACCESS and scope.endswith(
                            "/oss/aliyun_v4_request"
                        )
                        signed = ";".join(
                            sorted(
                                {
                                    k.lower()
                                    for k in self.headers
                                    if k.lower().startswith("x-oss-")
                                    or k.lower() in ("content-type", "content-md5")
                                }
                                | set((additional or "").split(";")) - {""}
                            )
                        )
                        payload = self.headers["x-oss-content-sha256"]
                        algorithm = "OSS4-HMAC-SHA256"
                        timestamp = self.headers["x-oss-date"]
                        date, region, _, _ = scope.split("/")
                        key = mac(
                            mac(
                                mac(
                                    mac(("aliyun_v4" + SECRET).encode(), date.encode()),
                                    region.encode(),
                                ),
                                b"oss",
                            ),
                            b"aliyun_v4_request",
                        )
                        signed_line = additional or ""
                    else:
                        m = re.fullmatch(
                            r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^,]+), ?SignedHeaders=([^,]+), ?Signature=([0-9a-f]{64})",
                            auth,
                        )
                        assert m, "missing SigV4 authorization"
                        access, scope, signed, signature = m.groups()
                        assert access == ACCESS and scope.endswith("/s3/aws4_request")
                        payload = self.headers.get(
                            "x-amz-content-sha256", hashlib.sha256(b"").hexdigest()
                        )
                        algorithm = "AWS4-HMAC-SHA256"
                        timestamp = self.headers["x-amz-date"]
                        date, region, _, _ = scope.split("/")
                        key = mac(
                            mac(
                                mac(
                                    mac(("AWS4" + SECRET).encode(), date.encode()),
                                    region.encode(),
                                ),
                                b"s3",
                            ),
                            b"aws4_request",
                        )
                        signed_line = signed
                    headers = "".join(
                        k + ":" + " ".join(self.headers[k].split()) + "\n"
                        for k in signed.split(";")
                    )
                    query = urllib.parse.urlencode(
                        sorted(
                            urllib.parse.parse_qsl(uri.query, keep_blank_values=True)
                        ),
                        quote_via=urllib.parse.quote,
                    )
                    canonical = f"{self.command}\n{path}\n{query}\n{headers}\n{signed_line}\n{payload}"
                    string = (
                        algorithm
                        + "\n"
                        + timestamp
                        + "\n"
                        + scope
                        + "\n"
                        + hashlib.sha256(canonical.encode()).hexdigest()
                    )
                    assert hmac.compare_digest(
                        mac(key, string.encode()).hex(), signature
                    ), "invalid object signature: " + canonical
                    if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                        body = b""
                        while True:
                            size = int(self.rfile.readline().split(b";")[0], 16)
                            if not size:
                                self.rfile.readline()
                                break
                            body += self.rfile.read(size)
                            assert self.rfile.read(2) == b"\r\n"
                    else:
                        body = self.rfile.read(
                            int(self.headers.get("Content-Length", 0))
                        )
                    if payload.startswith("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"):
                        decoded = b""
                        stream = io.BytesIO(body)
                        previous = signature
                        while True:
                            header = stream.readline().strip()
                            size, chunk_sig = header.split(b";chunk-signature=")
                            size = int(size, 16)
                            chunk = stream.read(size)
                            assert stream.read(2) == b"\r\n"
                            text = (
                                "AWS4-HMAC-SHA256-PAYLOAD\n"
                                + self.headers["x-amz-date"]
                                + "\n"
                                + scope
                                + "\n"
                                + previous
                                + "\n"
                                + hashlib.sha256(b"").hexdigest()
                                + "\n"
                                + hashlib.sha256(chunk).hexdigest()
                            )
                            assert (
                                mac(key, text.encode()).hex() == chunk_sig.decode()
                            ), "invalid stream signature"
                            previous = chunk_sig.decode()
                            decoded += chunk
                            if not size:
                                break
                        body = decoded
                        assert len(body) == int(
                            self.headers["x-amz-decoded-content-length"]
                        )
                    elif payload != "UNSIGNED-PAYLOAD":
                        assert hashlib.sha256(body).hexdigest() == payload
                    object_key = urllib.parse.unquote(path.lstrip("/"))
                    service.requests.append((self.command, object_key))
                    if service.before:
                        service.before(self.command, object_key)
                    if (self.command, object_key) in service.fail:
                        self.reply(
                            503,
                            b"<Error><Code>ServiceUnavailable</Code><Message>fixture unavailable</Message></Error>",
                        )
                        return
                    if uri.query.startswith("location"):
                        self.reply(
                            200, b"<LocationConstraint>us-east-1</LocationConstraint>"
                        )
                        return
                    if self.command == "PUT":
                        service.objects[object_key] = body
                        self.reply(
                            200,
                            headers={"ETag": '"' + hashlib.md5(body).hexdigest() + '"'},
                        )
                        return
                    if self.command == "DELETE":
                        service.objects.pop(object_key, None)
                        self.reply(204)
                        return
                    if object_key not in service.objects:
                        self.reply(
                            404,
                            b"<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
                        )
                        return
                    body = service.objects[object_key]
                    self.reply(
                        200,
                        body,
                        {
                            "ETag": '"' + hashlib.md5(body).hexdigest() + '"',
                            "Last-Modified": "Fri, 01 Jan 2021 00:00:00 GMT",
                            "Content-Type": "application/octet-stream",
                        },
                    )
                except (AssertionError, ValueError, KeyError, OSError, TypeError) as e:
                    service.errors.append(repr(e))
                    self.reply(500, b"fixture assertion failed")

            do_GET = do_HEAD = do_PUT = do_DELETE = handle_object

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
        assert not self.errors, self.errors


def env_for(dsn, root):
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("BACKUP_", "DB_", "MAILCTL_", "SETJOIN_"))
    }
    env.update(
        DB_DSN=dsn,
        DB_DIRECT_DSN=dsn,
        DB_OWNER_DSN=dsn,
        DB_DIRECT_OWNER_DSN=dsn,
        BACKUP_ACCESS_KEY=ACCESS,
        BACKUP_SECRET_KEY=SECRET,
        HOME=str(root),
        TMPDIR=str(root),
        # Gateway startup bootstraps its secret file; the default /etc/mail path need not exist.
        CONFIG_PATH=str(Path(root) / "config.env"),
        # Startup validates the identity connector secrets against these (public test keys).
        DB_ENCRYPTION_KEY="22" * 32,
        JWT_SECRET="mailctl-oracle-jwt-secret-32-bytes-min",
    )
    return env


def audit_pg_tools(root, env):
    bindir = root / "pg-tools"
    bindir.mkdir()
    audit = root / "pg-children.jsonl"
    for tool in ["pg_dump", "pg_restore"]:
        real = shutil.which(tool)
        assert real
        wrapper = bindir / tool
        wrapper.write_text(
            "#!"
            + sys.executable
            + "\nimport os,json,sys\n"
            + f'open({str(audit)!r},"a").write(json.dumps({{"tool":{tool!r},"argv":sys.argv[1:],"password_present":bool(os.environ.get("PGPASSWORD")),"proc":open("/proc/self/cmdline","rb").read().decode()}})+"\\n")\nos.execv({real!r},[{real!r},*sys.argv[1:]])\n'
        )
        wrapper.chmod(0o700)
    env["PATH"] = str(bindir) + os.pathsep + os.environ["PATH"]
    return audit


def assert_private_children(audit, dsn, tool):
    children = [json.loads(line) for line in audit.read_text().splitlines()]
    children = [
        c
        for c in children
        if c["tool"] == tool
        and any(
            a == clean_dsn(dsn) or a.endswith("=" + clean_dsn(dsn)) for a in c["argv"]
        )
    ]
    assert children, "no authenticated PostgreSQL child was observed"
    password = urllib.parse.unquote(urllib.parse.urlsplit(dsn).password or "")
    for c in children:
        assert c["password_present"] and password
        assert not any(
            a == password or "password=" in a.lower() or ":" + password + "@" in a
            for a in c["proc"].split("\0")
        ), "password leaked into child process listing"


def check_sidecar(objects, key):
    e = json.loads(objects[key + ".hmac"])
    assert list(e) == [
        "schema",
        "objectKey",
        "sizeBytes",
        "sha256",
        "algorithm",
        "createdAt",
        "hmacSha256",
    ]
    assert (
        e["schema"] == "setjoin.mailctl.dump-auth/v1"
        and e["algorithm"] == "hmac-sha256"
        and e["objectKey"] == key.split("/", 1)[1]
    )
    assert (
        e["sizeBytes"] == len(objects[key])
        and e["sha256"] == hashlib.sha256(objects[key]).hexdigest()
    )
    signature = e["hmacSha256"]
    e["hmacSha256"] = ""
    canonical = json.dumps(e, separators=(",", ":")).encode()
    assert hmac.compare_digest(
        hmac.new(HMAC_KEY, canonical, hashlib.sha256).hexdigest(), signature
    ), "invalid dump HMAC"
    datetime.datetime.strptime(e["createdAt"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def backup_db(binary, dsn, record_to=None):
    with (
        tempfile.TemporaryDirectory(prefix="gofree-mctl4-backup-", dir="/tmp") as tmp,
        S3() as s3,
    ):
        root = Path(tmp)
        key = root / "hmac-key"
        key.write_bytes(HMAC_KEY)
        key.chmod(0o600)
        audit = root / "children.jsonl"
        bindir = root / "bin"
        bindir.mkdir()
        real = shutil.which("pg_dump")
        restore = shutil.which("pg_restore")
        assert real and restore
        wrapper = bindir / "pg_dump"
        wrapper.write_text(
            "#!"
            + sys.executable
            + "\nimport os,json,sys\n"
            + f'open({str(audit)!r},"a").write(json.dumps({{"argv":sys.argv[1:],"password_present":bool(os.environ.get("PGPASSWORD")),"proc":open("/proc/self/cmdline","rb").read().decode()}})+"\\n")\nos.execv({real!r},[{real!r},*sys.argv[1:]])\n'
        )
        wrapper.chmod(0o700)
        env = env_for(dsn, root)
        env["PATH"] = str(bindir) + os.pathsep + os.environ["PATH"]
        args = [
            "backup-db",
            "--bucket",
            "fixture",
            "--endpoint",
            s3.url,
            "--region",
            "us-east-1",
            "--dump-hmac-key-file",
            str(key),
        ]
        result = subprocess.run(
            [binary, *args],
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
                "stderr": result.stderr,
                "objects": sorted(s3.objects),
            }
        assert len(s3.objects) == 4, sorted(s3.objects)
        archive = next(
            k
            for k in s3.objects
            if re.fullmatch("fixture/db-dump-[0-9]{8}T[0-9]{6}Z.dump", k)
        )
        for name in ["fixture/db-dump.dump", archive]:
            check_sidecar(s3.objects, name)
        assert s3.objects[archive] == s3.objects["fixture/db-dump.dump"]
        dump = root / "dump"
        dump.write_bytes(s3.objects["fixture/db-dump.dump"])
        subprocess.run(
            [restore, "--list", str(dump)], check=True, stdout=subprocess.DEVNULL
        )
        children = [json.loads(s) for s in audit.read_text().splitlines()]
        password = urllib.parse.unquote(urllib.parse.urlsplit(dsn).password or "")
        assert len(children) == 1 and children[0]["password_present"]
        assert password and all(
            c["argv"][-1] == clean_dsn(dsn)
            and not any(
                a == password or "password=" in a.lower() or ":" + password + "@" in a
                for a in c["proc"].split("\0")
            )
            for c in children
        ), "password leaked into child process listing"
        if record_to:
            (record_to / "go-database.dump").write_bytes(dump.read_bytes())
            (record_to / "go-database.dump.hmac").write_bytes(
                s3.objects["fixture/db-dump.dump.hmac"]
            )
        stdout = re.sub(
            r"db-dump-[0-9]{8}T[0-9]{6}Z.dump", "db-dump-$STAMP.dump", result.stdout
        )
        stderr = result.stderr.replace(str(len(dump.read_bytes())), "$DUMP_SIZE")
        return {
            "exit": 0,
            "stdout": stdout,
            "stderr": stderr,
            "objects": [
                "db-dump.dump",
                "db-dump.dump.hmac",
                "db-dump-$STAMP.dump",
                "db-dump-$STAMP.dump.hmac",
            ],
            "dump_authenticated": True,
            "child_password_only_in_environment": True,
        }


class Control:
    def __init__(self, path, response):
        self.path = str(path)
        self.response = response
        self.requests = []

    def __enter__(self):
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                service.requests.append(
                    {
                        "path": self.path,
                        "body": raw.decode(),
                        "content-type": self.headers.get("Content-Type"),
                    }
                )
                body = json.dumps(service.response).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = socketserver.UnixStreamServer(self.path, Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01)
        )
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        Path(self.path).unlink()


def restore_preview(binary, dsn, record_to=None):
    with tempfile.TemporaryDirectory(prefix="gofree-mctl4-restore-", dir="/tmp") as tmp:
        root = Path(tmp)
        with Control(
            root / "control.sock",
            {
                "timestamp": "20260823T010000Z",
                "blob_count": 2,
                "blob_total_size_bytes": 17,
                "config_size_bytes": 42,
                "user_count": 3,
                "domain_count": 1,
                "warnings": ["fixture warning"],
            },
        ) as control:
            env = env_for(dsn, root)
            result = subprocess.run(
                [
                    binary,
                    "restore",
                    "--bucket",
                    "fixture",
                    "--dry-run",
                    "--control-socket",
                    control.path,
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr.replace(str(root), "$HOME"),
                "requests": control.requests,
            }


def restore_config(binary, dsn, record_to=None):
    with tempfile.TemporaryDirectory(prefix="gofree-mctl4-restore-", dir="/tmp") as tmp:
        root = Path(tmp)
        with Control(
            root / "control.sock",
            {
                "status": "completed",
                "restore_job_id": 17,
                "restored_config_keys": 3,
                "restored_blobs": 2,
                "errors": [],
            },
        ) as control:
            result = subprocess.run(
                [
                    binary,
                    "restore",
                    "--bucket",
                    "fixture",
                    "--type",
                    "config",
                    "--control-socket",
                    control.path,
                ],
                input="RESTORE\n",
                env=env_for(dsn, root),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr.replace(str(root), "$HOME"),
                "requests": control.requests,
            }


# Dropping and recreating `public` loses its ACL; a dump/restore of a database
# whose public schema only carries the default grants does not bring it back, so a
# failed restore used to leave later suites (the app role) without schema USAGE.
_PUBLIC_GRANTS = None


def public_schema_grants(dsn):
    """GRANT statements that rebuild the current ACL of schema `public`."""
    return sql(
        dsn,
        "SELECT coalesce(string_agg(format('GRANT %s ON SCHEMA public TO %s;', a.privilege_type,"
        " CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(r.rolname) END), ' '), '')"
        " FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a"
        " LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE n.nspname='public'",
    )


def restore_public_grants(dsn):
    if _PUBLIC_GRANTS:
        sql(dsn, "SET client_min_messages=warning; " + _PUBLIC_GRANTS)


def remember_public_grants(dsn):
    global _PUBLIC_GRANTS
    if _PUBLIC_GRANTS is None:
        _PUBLIC_GRANTS = public_schema_grants(dsn)


def orphan_rows(dsn):
    """Foreign keys (child -> parent) that some row violates.

    Suites that delete under session_replication_role=replica can leave such rows;
    pg_restore of a dump holding them fails when it validates the constraint.
    """
    statements = sql(
        dsn,
        "SELECT string_agg(format('SELECT %L WHERE EXISTS (SELECT 1 FROM %s c WHERE c.%I IS NOT NULL"
        " AND NOT EXISTS (SELECT 1 FROM %s p WHERE p.%I = c.%I));', c.conrelid::regclass::text || '.' || ca.attname"
        " || ' -> ' || c.confrelid::regclass::text, c.conrelid::regclass, ca.attname,"
        " c.confrelid::regclass, pa.attname, ca.attname), ' ')"
        " FROM pg_constraint c JOIN pg_attribute ca ON ca.attrelid=c.conrelid AND ca.attnum=c.conkey[1]"
        " JOIN pg_attribute pa ON pa.attrelid=c.confrelid AND pa.attnum=c.confkey[1]"
        " WHERE c.contype='f' AND array_length(c.conkey,1)=1 AND c.conparentid=0"
        " AND c.connamespace='public'::regnamespace",
    )
    if not statements:
        return []
    r = subprocess.run(
        ["psql", clean_dsn(dsn), "-XAtq", "-v", "ON_ERROR_STOP=1"],
        env=pg_env(dsn),
        input=statements + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    return [line for line in r.stdout.splitlines() if line]


def reset_public_fixture(dsn):
    remember_public_grants(dsn)
    # Cleanup has no application clients. Separate transactions avoid exhausting
    # a shared server's relation-lock table on the full partitioned schema.
    phases = [
        "SELECT format('DROP EXTENSION IF EXISTS %I CASCADE;',extname) FROM pg_extension WHERE extnamespace='public'::regnamespace",
        "SELECT format('DROP %s IF EXISTS %I.%I(%s) CASCADE;',CASE p.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END,n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'",
        "SELECT format('DROP TABLE IF EXISTS %I.%I CASCADE;',n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','f') AND NOT c.relispartition",
    ]
    for query in phases:
        statements = sql(dsn, query)
        r = subprocess.run(
            ["psql", clean_dsn(dsn), "-Xq", "-v", "ON_ERROR_STOP=1"],
            env=pg_env(dsn),
            input="SET client_min_messages=error;\n" + statements + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0, r.stderr
    sql(
        dsn,
        "SET client_min_messages=warning; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION pg_database_owner",
    )
    restore_public_grants(dsn)


@contextlib.contextmanager
def preserve_database(dsn, root):
    fd, name = tempfile.mkstemp(
        prefix="gofree-mctl4-original-", suffix=".dump", dir="/tmp"
    )
    os.close(fd)
    saved = Path(name)
    subprocess.run(
        ["pg_dump", "--format=custom", "--file=" + str(saved), clean_dsn(dsn)],
        env=pg_env(dsn),
        check=True,
    )
    try:
        remember_public_grants(dsn)
        orphans = orphan_rows(dsn)
    except BaseException:
        saved.unlink(missing_ok=True)
        raise
    if orphans:
        # The snapshot above could never be restored: fail before touching anything.
        saved.unlink(missing_ok=True)
        raise RuntimeError(
            "refusing to run: the database holds rows that violate foreign keys left by an "
            "earlier suite (pg_restore of its snapshot would fail): " + "; ".join(orphans)
        )
    try:
        yield
    finally:
        pending = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
        )
        try:
            reset_public_fixture(dsn)
            r = subprocess.run(
                [
                    "pg_restore",
                    "--exit-on-error",
                    "--dbname=" + clean_dsn(dsn),
                    str(saved),
                ],
                env=pg_env(dsn),
                capture_output=True,
                text=True,
                check=False,
            )
            if r.returncode != 0:
                restore_public_grants(dsn)
                raise RuntimeError(
                    "the preserved database could not be restored (the public schema is left "
                    "empty with its grants re-applied; snapshot retained): " + r.stderr
                )
            saved.unlink()
        except BaseException:
            print("MCTL4_RETAINED_SNAPSHOT=" + str(saved), file=sys.stderr, flush=True)
            raise
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, pending)


def canonical_snapshot(dsn):
    data = snapshot(lambda q: sql(dsn, q))
    return {
        k: sorted(v, key=lambda row: json.dumps(row, sort_keys=True))
        for k, v in sorted(data.items())
    }


def seed(dsn):
    assert (
        sql(dsn, "SELECT to_regclass('public.gofree_mctl4_backup_fixture') IS NULL")
        == "t"
    )
    sql(
        dsn,
        "CREATE TABLE public.gofree_mctl4_backup_fixture (id bigserial primary key, payload bytea, document jsonb, note text); INSERT INTO public.gofree_mctl4_backup_fixture(payload,document,note) VALUES(decode('000102fffe80','hex'),'{\"unicode\":\"集合\",\"nested\":[true,null,42]}','synthetic fixture'),(NULL,'null','second row'); GRANT SELECT ON public.gofree_mctl4_backup_fixture TO setjoin_app",
    )


def portable_seed(dsn):
    sql(
        dsn,
        """SET client_min_messages=warning; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION pg_database_owner;
    CREATE TABLE users(id bigint primary key,email text,password_hash text);
    CREATE TABLE mailboxes(id bigint primary key,user_id bigint references users(id));
    CREATE TABLE messages(id bigserial primary key,mailbox_id bigint references mailboxes(id),raw bytea,received_at timestamptz);
    CREATE TABLE system_config(key text primary key,value jsonb,encrypted boolean);
    CREATE TABLE blobs(sha256 text primary key,size_bytes bigint,ref_count integer);
    INSERT INTO users VALUES(7,'fixture@example.test','synthetic-password-hash');
    INSERT INTO mailboxes VALUES(17,7);
    INSERT INTO messages(mailbox_id,raw,received_at) VALUES(17,decode('0001ff','hex'),'2026-08-23T00:00:00Z');
    INSERT INTO system_config VALUES('fixture.secret','\"synthetic ciphertext\"',true);
    INSERT INTO blobs VALUES(repeat('a',64),3,1);
    ALTER TABLE users OWNER TO setjoin_worker; ALTER TABLE mailboxes OWNER TO setjoin_worker;
    ALTER TABLE messages OWNER TO setjoin_worker; ALTER TABLE system_config OWNER TO setjoin_worker; ALTER TABLE blobs OWNER TO setjoin_worker;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO setjoin_app;""",
    )
    seed(dsn)
    sql(dsn, "ALTER TABLE gofree_mctl4_backup_fixture OWNER TO setjoin_worker")


def roundtrip_go(binary, dsn, record_to=None):
    with (
        tempfile.TemporaryDirectory(
            prefix="gofree-mctl4-roundtrip-", dir="/tmp"
        ) as tmp,
        S3() as s3,
    ):
        root = Path(tmp)
        with preserve_database(dsn, root):
            env = env_for(dsn, root)
            key = root / "hmac-key"
            key.write_bytes(HMAC_KEY)
            key.chmod(0o600)
            if record_to:
                portable_seed(dsn)
                want = canonical_snapshot(dsn)
                result = subprocess.run(
                    [
                        binary,
                        "backup-db",
                        "--bucket",
                        "fixture",
                        "--endpoint",
                        s3.url,
                        "--region",
                        "us-east-1",
                        "--dump-hmac-key-file",
                        str(key),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                assert result.returncode == 0, result.stderr
                check_sidecar(s3.objects, "fixture/db-dump.dump")
                (record_to / "go-seeded.dump.gz").write_bytes(
                    gzip.compress(s3.objects["fixture/db-dump.dump"], mtime=0)
                )
                (record_to / "go-seeded.dump.hmac").write_bytes(
                    s3.objects["fixture/db-dump.dump.hmac"]
                )
                (record_to / "go-seeded.rows.json.gz").write_bytes(
                    gzip.compress(json.dumps(want, sort_keys=True).encode(), mtime=0)
                )
            else:
                s3.objects["fixture/db-dump.dump"] = gzip.decompress(
                    (HERE / "fixtures/go-seeded.dump.gz").read_bytes()
                )
                s3.objects["fixture/db-dump.dump.hmac"] = (
                    HERE / "fixtures/go-seeded.dump.hmac"
                ).read_bytes()
                want = json.loads(
                    gzip.decompress(
                        (HERE / "fixtures/go-seeded.rows.json.gz").read_bytes()
                    )
                )
            if record_to:
                sql(
                    dsn,
                    "SET client_min_messages=warning; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION pg_database_owner; CREATE TABLE public.users(id bigint primary key)",
                )
            s3.requests.clear()

            def before(method, key):
                if method == "GET":
                    assert (
                        sql(dsn, "SELECT to_regclass('public.users') IS NULL") == "t"
                    ), "schema reset must precede dump download"

            s3.before = before
            with Control(
                root / "control.sock",
                {
                    "status": "completed",
                    "restore_job_id": 17,
                    "restored_config_keys": 0,
                    "restored_blobs": 2,
                    "errors": [],
                },
            ) as control:
                result = subprocess.run(
                    [
                        binary,
                        "restore",
                        "--bucket",
                        "fixture",
                        "--endpoint",
                        s3.url,
                        "--region",
                        "us-east-1",
                        "--yes",
                        "--control-socket",
                        control.path,
                        "--dump-hmac-key-file",
                        str(key),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            got = {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr.replace(s3.url, "$S3").replace(
                    str(root), "$HOME"
                ),
                "requests": [
                    {**r, "body": r["body"].replace(s3.url, "$S3")}
                    for r in control.requests
                ],
            }
            if result.returncode == 0:
                assert canonical_snapshot(dsn) == want, (
                    "restored table contents differ from seeded Go database"
                )
                assert (
                    sql(
                        dsn, "SELECT last_value FROM gofree_mctl4_backup_fixture_id_seq"
                    )
                    == "2"
                )
                assert (
                    sql(
                        dsn,
                        "SELECT has_table_privilege('setjoin_app','gofree_mctl4_backup_fixture','SELECT')",
                    )
                    == "t"
                )
                got.update(all_table_rows_restored=True, sequence_and_acl_restored=True)
            return got


def roundtrip_rust(binary, dsn, record_to=None, env_password=False):
    with (
        tempfile.TemporaryDirectory(
            prefix="gofree-mctl4-roundtrip-", dir="/tmp"
        ) as tmp,
        S3() as s3,
    ):
        root = Path(tmp)
        with preserve_database(dsn, root):
            seed(dsn)
            want = canonical_snapshot(dsn)
            env = env_for(dsn, root)
            if env_password:
                env["PGPASSWORD"] = urllib.parse.unquote(
                    urllib.parse.urlsplit(dsn).password or ""
                )
                for k in [
                    "DB_DSN",
                    "DB_DIRECT_DSN",
                    "DB_OWNER_DSN",
                    "DB_DIRECT_OWNER_DSN",
                ]:
                    env[k] = clean_dsn(dsn)
            audit = audit_pg_tools(root, env)
            key = root / "hmac-key"
            key.write_bytes(HMAC_KEY)
            key.chmod(0o600)
            result = subprocess.run(
                [
                    binary,
                    "backup-db",
                    "--bucket",
                    "fixture",
                    "--endpoint",
                    s3.url,
                    "--region",
                    "us-east-1",
                    "--dump-hmac-key-file",
                    str(key),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            check_sidecar(s3.objects, "fixture/db-dump.dump")
            with Control(
                root / "control.sock",
                {
                    "status": "completed",
                    "restore_job_id": 17,
                    "restored_config_keys": 0,
                    "restored_blobs": 2,
                    "errors": [],
                },
            ) as control:
                result = subprocess.run(
                    [
                        binary,
                        "restore",
                        "--bucket",
                        "fixture",
                        "--endpoint",
                        s3.url,
                        "--region",
                        "us-east-1",
                        "--yes",
                        "--control-socket",
                        control.path,
                        "--dump-hmac-key-file",
                        str(key),
                    ],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
            got = {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr.replace(s3.url, "$S3").replace(
                    str(root), "$HOME"
                ),
                "requests": [
                    {**r, "body": r["body"].replace(s3.url, "$S3")}
                    for r in control.requests
                ],
            }
            if result.returncode == 0:
                assert_private_children(audit, dsn, "pg_dump")
                assert_private_children(audit, dsn, "pg_restore")
                assert canonical_snapshot(dsn) == want, (
                    "Rust round trip changed table contents"
                )
                assert (
                    sql(
                        dsn, "SELECT last_value FROM gofree_mctl4_backup_fixture_id_seq"
                    )
                    == "2"
                )
                assert (
                    sql(
                        dsn,
                        "SELECT has_table_privilege('setjoin_app','gofree_mctl4_backup_fixture','SELECT')",
                    )
                    == "t"
                )
                got.update(all_table_rows_restored=True, sequence_and_acl_restored=True)
            return got


def restore_auth(binary, dsn, record_to=None):
    with (
        tempfile.TemporaryDirectory(
            prefix="gofree-mctl4-restore-auth-", dir="/tmp"
        ) as tmp,
        S3() as s3,
    ):
        root = Path(tmp)
        observations = {}
        with preserve_database(dsn, root):
            env = env_for(dsn, root)
            audit = audit_pg_tools(root, env)
            key = root / "hmac-key"
            key.write_bytes(HMAC_KEY)
            key.chmod(0o600)
            for variant in [
                "dump-substitution",
                "hmac-substitution",
                "wrong-locator",
                "wrong-key",
            ]:
                reset_public_fixture(dsn)
                sql(dsn, "CREATE TABLE users(id bigint primary key)")
                raw = gzip.decompress(
                    (HERE / "fixtures/go-seeded.dump.gz").read_bytes()
                )
                sidecar = json.loads(
                    (HERE / "fixtures/go-seeded.dump.hmac").read_bytes()
                )
                if variant == "dump-substitution":
                    raw = raw[:-1] + bytes([raw[-1] ^ 1])
                if variant == "hmac-substitution":
                    sidecar["hmacSha256"] = "0" * 64
                if variant == "wrong-locator":
                    sidecar["objectKey"] = "different.dump"
                key.write_bytes(b"X" * 32 if variant == "wrong-key" else HMAC_KEY)
                s3.objects = {
                    "fixture/db-dump.dump": raw,
                    "fixture/db-dump.dump.hmac": json.dumps(
                        sidecar, separators=(",", ":")
                    ).encode(),
                }
                s3.requests.clear()
                with Control(
                    root / "control.sock",
                    {
                        "status": "completed",
                        "restore_job_id": 17,
                        "restored_config_keys": 0,
                        "restored_blobs": 2,
                        "errors": [],
                    },
                ) as control:
                    result = subprocess.run(
                        [
                            binary,
                            "restore",
                            "--bucket",
                            "fixture",
                            "--endpoint",
                            s3.url,
                            "--region",
                            "us-east-1",
                            "--yes",
                            "--control-socket",
                            control.path,
                            "--dump-hmac-key-file",
                            str(key),
                        ],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                assert result.returncode == 1, "tampered publication was accepted"
                assert not audit.exists() or not audit.read_text(), (
                    "untrusted dump reached a PostgreSQL child"
                )
                assert sql(dsn, "SELECT to_regclass('public.users') IS NULL") == "t"
                observations[variant] = {
                    "exit": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr.replace(str(root), "$HOME").replace(
                        s3.url, "$S3"
                    ),
                    "requests": [
                        {**r, "body": r["body"].replace(s3.url, "$S3")}
                        for r in control.requests
                    ],
                    "objects": [
                        [verb, name]
                        for verb, name in s3.requests
                        if not name.endswith("/")
                    ],
                    "untrusted_dump_never_executed": True,
                }
        return observations


def pgpass_auth(binary, dsn, record_to=None):
    import struct

    password = b"mctl4-synthetic-passfile-secret"
    with tempfile.TemporaryDirectory(prefix="gofree-mctl4-pgpass-", dir="/tmp") as tmp:
        root = Path(tmp)
        observed = []

        class Postgres(socketserver.BaseRequestHandler):
            def read_exact(self, count):
                data = b""
                while len(data) < count:
                    chunk = self.request.recv(count - len(data))
                    if not chunk:
                        return None
                    data += chunk
                return data

            def handle(self):
                size = self.read_exact(4)
                if not size:
                    return
                startup = self.read_exact(struct.unpack("!I", size)[0] - 4)
                assert b"fixture\x00" in startup
                self.request.sendall(b"R" + struct.pack("!II", 8, 3))
                tag = self.read_exact(1)
                if tag != b"p":
                    observed.append(False)
                    return
                size = self.read_exact(4)
                value = self.read_exact(struct.unpack("!I", size)[0] - 4)
                observed.append(value == password + b"\x00")
                error = b"SERROR\x00CXX000\x00MMCTL4 auth boundary reached; no SQL executed\x00\x00"
                self.request.sendall(b"E" + struct.pack("!I", len(error) + 4) + error)

        with socketserver.TCPServer(("127.0.0.1", 0), Postgres) as peer:
            thread = threading.Thread(
                target=lambda: peer.serve_forever(poll_interval=0.01),
                name="gofree-mctl4-pgpass",
            )
            thread.start()
            try:
                port = peer.server_address[1]
                conninfo = (
                    f"postgres://fixture@127.0.0.1:{port}/gofree_mctl4?sslmode=disable"
                )
                passfile = root / "pgpass"
                passfile.write_bytes(
                    b"# private synthetic operator credential\n"
                    + f"127.0.0.1:{port}:gofree_mctl4:fixture:".encode()
                    + password
                    + b"\n"
                )
                passfile.chmod(0o600)
                key = root / "hmac-key"
                key.write_bytes(HMAC_KEY)
                key.chmod(0o600)
                env = env_for(conninfo, root)
                env.pop("PGPASSWORD", None)
                env["PGPASSFILE"] = str(passfile)
                with Control(
                    root / "control.sock",
                    {
                        "status": "completed",
                        "restore_job_id": 17,
                        "restored_config_keys": 0,
                        "restored_blobs": 0,
                        "errors": [],
                    },
                ) as control:
                    result = subprocess.run(
                        [
                            binary,
                            "restore",
                            "--bucket",
                            "fixture",
                            "--yes",
                            "--control-socket",
                            control.path,
                            "--dump-hmac-key-file",
                            str(key),
                        ],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                assert observed == [True], (
                    "operator connection did not authenticate using the selected passfile"
                )
                assert result.returncode == 1 and not result.stdout
                assert "MCTL4 auth boundary reached" in result.stderr
                return {
                    "password_from_selected_file": True,
                    "exit": result.returncode,
                    "peer_denial_preserved": True,
                    "no_sql_executed": True,
                    "requests": control.requests,
                }
            finally:
                peer.shutdown()
                thread.join()


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
            assert a.output and not a.output.exists(), (
                "record into a new directory only"
            )
            a.output.mkdir()
        cases = {
            "restore-auth": restore_auth,
            "pgpass-auth": pgpass_auth,
            "backup-db": backup_db,
            "restore-preview": restore_preview,
            "restore-config": restore_config,
            "roundtrip-go": roundtrip_go,
            "roundtrip-rust": roundtrip_rust,
            "roundtrip-env-password": lambda b, d, r: roundtrip_rust(
                b, d, r, env_password=True
            ),
        }
        selected = os.environ.get("MAILCTL_BACKUP_CASE")
        assert not selected or selected in cases, "unmatched backup case"
        for name, run in cases.items():
            if selected and selected != name:
                continue
            case_dsn = dsn
            if name.startswith("roundtrip-"):
                case_dsn = os.environ.get("MAILCTL_BACKUP_ROUNDTRIP_DB_DSN") or dsn
                clean_dsn(case_dsn)
                locks = int(sql(case_dsn, "SHOW max_locks_per_transaction"))
                assert locks >= 256, (
                    "full-schema backup round trip requires "
                    f"max_locks_per_transaction >= 256 (got {locks}); "
                    "raise this PostgreSQL setting and restart the disposable server"
                )
            got = run(
                str(Path(a.binary).resolve()),
                case_dsn,
                a.output if a.mode == "record" else None,
            )
            if a.mode == "record":
                (a.output / (name + ".json")).write_text(
                    json.dumps(got, indent=2) + "\n"
                )
            else:
                want = json.loads(
                    (
                        HERE
                        / "backup-goldens"
                        / (
                            "roundtrip-rust.json"
                            if name == "roundtrip-env-password"
                            else name + ".json"
                        )
                    ).read_text()
                )
                assert got == want, (name, want, got)
            print("mailctl " + name + " " + a.mode, flush=True)


if __name__ == "__main__":
    main()
