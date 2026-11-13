#!/usr/bin/env python3
"""One isolated seed + boot at the process/SQL/S3/filesystem seams.

Record in the CI image with the immutable Go adapter. Replay never invokes Go.
Cases are appended only after their previous red/green slice passes.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import urllib.parse

HERE = Path(__file__).resolve().parent
KEY = "0123456789abcdef" * 4


def sql(statement):
    result = subprocess.run(["psql", os.environ["TEST_DB_DSN"], "-XAt", "-v", "ON_ERROR_STOP=1", "-c", statement], capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


class Storage(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.handle_request()

    def do_GET(self):
        self.handle_request()

    def do_PUT(self):
        self.handle_request()

    def do_DELETE(self):
        self.handle_request()

    def handle_request(self):
        uri = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(uri.query, keep_blank_values=True)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        # S3 signing belongs to the maintained client. Record the external
        # operation, creation-time Object Lock flag and policy, not clock/signature.
        operation = "location" if "location" in query else "uploads" if "uploads" in query else "object-lock" if "object-lock" in query else "abort" if "uploadId" in query else "bucket"
        self.server.calls.append({"method": self.command, "path": uri.path.rstrip("/"), "operation": operation,
                                  "lock": self.headers.get("x-amz-bucket-object-lock-enabled", ""),
                                  "body": body.decode() if operation == "object-lock" else ""})
        if query.get("prefix", [""])[0]:
            self.server.calls[-1]["prefix"] = query["prefix"][0]
        if operation == "abort":
            self.server.calls[-1]["upload_id"] = query["uploadId"][0]
        if self.server.options.get("region") and operation != "location":
            credential = self.headers.get("authorization", "").split("Credential=", 1)
            self.server.calls[-1]["region"] = credential[1].split(",", 1)[0].split("/")[2] if len(credential) == 2 else "unsigned"
        opts = self.server.options
        code = 200
        payload = b""
        if opts.get("fault") == operation or (opts.get("fault") == "bucket-create" and operation == "bucket" and self.command == "PUT"):
            code = 403
            payload = b"<Error><Code>AccessDenied</Code><Message>boot fixture denied</Message></Error>"
        elif operation == "location":
            payload = ('<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' + opts.get("region", "") + '</LocationConstraint>').encode()
        elif operation == "uploads":
            uploads = ""
            for key, initiated in opts.get("uploads", []):
                if not key.startswith(query.get("prefix", [""])[0]):
                    continue
                upload_id = f"id-{key}-{initiated[:4]}"
                uploads += f"<Upload><Key>{key}</Key><UploadId>{upload_id}</UploadId><Initiated>{initiated}</Initiated><StorageClass>STANDARD</StorageClass><Owner><ID>fixture</ID><DisplayName>fixture</DisplayName></Owner><Initiator><ID>fixture</ID><DisplayName>fixture</DisplayName></Initiator></Upload>"
            payload = (f'<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>boot-bucket</Bucket><KeyMarker/><UploadIdMarker/><NextKeyMarker/><NextUploadIdMarker/><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated>{uploads}</ListMultipartUploadsResult>').encode()
        elif operation == "bucket" and self.command == "HEAD" and not self.server.exists:
            code = 404
        elif operation == "bucket" and self.command == "PUT":
            self.server.exists = True
        elif operation == "abort":
            code = 204
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


def observe(case, binary, go):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Storage)
    server.daemon_threads = True
    server.calls = []
    server.options = case.get("storage", {})
    server.exists = not server.options.get("missing", False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="gofree-boot-") as directory:
            path = Path(directory)
            config = path / "config.env"
            state = case.get("file", "existing")
            if state == "existing":
                config.write_text("operator content\n")
                config.chmod(0o600)
            elif state == "symlink":
                (path / "victim").write_text("victim\n")
                config.symlink_to(path / "victim")
            elif state == "directory":
                config.mkdir()
            elif state in ("empty-wide", "content-wide", "empty-private"):
                config.write_text("preserved\n" if state == "content-wide" else "")
                config.chmod(0o600 if state == "empty-private" else 0o644)
            geo = path / "geo.mmdb"
            geo.write_bytes((HERE.parents[3] / "tests/conformance/authzgates/us.mmdb").read_bytes() if case.get("geo") == "valid" else b"hostile database payload")
            env = {"PATH": os.environ["PATH"], "BOOT_RECORD_CHILD": "1", "BOOT_PROBE_CHILD": "1",
                   "DB_DSN": os.environ["TEST_DB_DSN"], "DB_DIRECT_DSN": os.environ["TEST_DB_DSN"],
                   "DB_OWNER_DSN": os.environ["TEST_DB_DSN"], "DB_WORKER_DSN": os.environ["TEST_DB_DSN"],
                   "DB_ENCRYPTION_KEY": KEY, "JWT_SECRET": KEY, "INTERNAL_API_KEY": KEY,
                   "MINIO_ENDPOINT": f"127.0.0.1:{server.server_port}", "MINIO_BUCKET": "boot-bucket",
                   "MINIO_ACCESS_KEY": "test-access", "MINIO_SECRET_KEY": "test-secret", "MINIO_SECURE": "false",
                   "CONFIG_PATH": str(config), "GEOIP_DB_PATH": str(geo), "NETWORK_MODE": "airgap",
                   "GATEWAY_LISTEN": "127.0.0.1:0", "IMAP_ADDR": "127.0.0.1:0", "SMTP_ADDR": "127.0.0.1:0", "SMTP_SUBMISSION_ADDR": "127.0.0.1:0", "LDAP_ADDR": "127.0.0.1:0"}
            env.update(case.get("env", {}))
            if case.get("storage_http_scheme"):
                env["S3_ENDPOINT"] = "http://" + env["MINIO_ENDPOINT"]
            if case.get("invalid_storage_path"):
                env["S3_ENDPOINT"] = env["MINIO_ENDPOINT"] + "/qualified/path"
            if case.get("request_app"):
                env["DB_DSN"] = os.environ["DB_APP_DSN"]
            if case.get("owner_app"):
                env["DB_OWNER_DSN"] = os.environ["DB_APP_DSN"]
            if case.get("credential_tags"):
                for key, tag in [("DB_DSN", "request"), ("DB_OWNER_DSN", "owner"), ("DB_WORKER_DSN", "worker")]:
                    env[key] += ("&" if "?" in env[key] else "?") + f"application_name=gofree-boot-{tag}"
            before = case.get("before", "SELECT 1")
            after = case.get("after", "SELECT 1")
            health_before = int(sql("SELECT coalesce(max(id),0) FROM health_history"))
            sql("CREATE TABLE boot_base_secret AS SELECT * FROM system_config WHERE key='ad_sync_password_enc'; UPDATE system_config SET value='\"\"'::jsonb,encrypted=false WHERE key='ad_sync_password_enc'")
            sql(before)
            try:
                args = [binary, "-test.run=^TestBOOTRecord$"] if go else [binary, "--exact", "boot_probe_process", "--nocapture"]
                results = []
                first_file = None
                repeat = case.get("repeat_boot", 1)
                for index in range(repeat):
                    results.append(subprocess.run(args, env=env, capture_output=True, text=True, timeout=75))
                    if index == 0 and config.is_file() and not config.is_symlink():
                        first_file = config.read_bytes()
                    if results[-1].returncode != 0:
                        break
                    if index + 1 < repeat and case.get("between"):
                        sql(case["between"])
                    if index + 1 < repeat and case.get("reload_generated_env"):
                        env.update(dict(line.split("=", 1) for line in config.read_text().splitlines() if line and not line.startswith("#")))
                from types import SimpleNamespace
                result = SimpleNamespace(returncode=results[-1].returncode,
                                         stderr="\n".join(r.stderr for r in results),
                                         stdout="\n".join(r.stdout for r in results))
                events = []
                for line in result.stderr.splitlines():
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if "level" in event and "msg" in event:
                        events.append([event["level"], event["msg"]])
                # Location discovery is transport setup, not an S3 effect. The
                # order and contents of all storage operations remain compared.
                calls = [c for c in server.calls if c["operation"] != "location"]
                for call in calls:
                    if call["operation"] == "object-lock" and call["body"]:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(call["body"])
                        call["body"] = {e.tag.split('}')[-1]: e.text for e in root.iter() if len(e) == 0}
                raw_effects = sql(case.get("effects", "SELECT '{}'::jsonb"))
                effects = json.loads(raw_effects) if raw_effects else None
                mode = stat.S_IMODE(config.lstat().st_mode) if config.exists() else None
                file_effect = {"mode": mode}
                if repeat > 1 and first_file is not None:
                    file_effect["idempotent"] = first_file == config.read_bytes()
                if config.is_file() and not config.is_symlink():
                    contents = config.read_text()
                    if contents.startswith("# Auto-generated on first boot."):
                        import base64
                        import re
                        fields = dict(line.split("=", 1) for line in contents.splitlines() if line and not line.startswith("#"))
                        assert set(fields) == {"JWT_SECRET", "DB_ENCRYPTION_KEY", "INTERNAL_API_KEY", "VAPID_PRIVATE_KEY", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY"}
                        for key, size in [("JWT_SECRET", 64), ("DB_ENCRYPTION_KEY", 64), ("INTERNAL_API_KEY", 64), ("MINIO_ACCESS_KEY", 40), ("MINIO_SECRET_KEY", 80)]:
                            assert re.fullmatch(f"[0-9a-f]{{{size}}}", fields[key]), f"invalid generated {key}"
                        assert len({fields[k] for k in ["JWT_SECRET", "DB_ENCRYPTION_KEY", "INTERNAL_API_KEY"]}) == 3
                        der = base64.urlsafe_b64decode(fields["VAPID_PRIVATE_KEY"] + "==")
                        assert len(der) == 121, "VAPID must retain Go's SEC1 format"
                        checked = subprocess.run(["openssl", "ec", "-inform", "DER", "-check", "-noout"], input=der, capture_output=True, timeout=5)
                        assert checked.returncode == 0, "generated VAPID key is invalid"
                        params = subprocess.run(["openssl", "ec", "-inform", "DER", "-param_out", "-outform", "DER"], input=der, capture_output=True, timeout=5)
                        assert params.returncode == 0 and params.stdout.hex() == "06082a8648ce3d030107", "VAPID curve must be P-256"
                    file_effect["content"] = "generated" if contents.startswith("# Auto-generated on first boot.") else contents
                if state == "symlink":
                    file_effect["victim"] = (path / "victim").read_text()
                observed = {"exit": result.returncode, "events": events, "storage": calls, "database": effects, "file": file_effect}
                if env.get("BOOT_INSPECT_SECRETS") == "1":
                    decrypted = [line.removeprefix("BOOT_DECRYPT ") for line in result.stdout.splitlines() if line.startswith("BOOT_DECRYPT ")]
                    observed["secrets"] = json.loads(decrypted[-1]) if decrypted else None
                if not events:
                    raise AssertionError(f"{case['id']}: no boot events: {result.stderr}\n{result.stdout}")
                return observed
            finally:
                try:
                    sql(after)
                finally:
                    sql("DELETE FROM system_config WHERE key='ad_sync_password_enc'; INSERT INTO system_config SELECT * FROM boot_base_secret; DROP TABLE boot_base_secret")
                    sql(f"DELETE FROM health_history WHERE id>{health_before}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["record", "replay"])
    parser.add_argument("binary")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case")
    args = parser.parse_args()
    cases = json.loads((HERE / "cases.json").read_text())
    if args.case:
        cases = [c for c in cases if c["id"] == args.case]
        assert cases, args.case
    goldens = {}
    if args.mode == "replay":
        goldens = json.loads((HERE / "goldens.json").read_text())["cases"]
    for case in cases:
        actual = observe(case, args.binary, args.mode == "record")
        if args.mode == "record":
            goldens[case["id"]] = actual
        else:
            assert actual == goldens[case["id"]], f"{case['id']}\nexpected: {json.dumps(goldens[case['id']], indent=2)}\nactual: {json.dumps(actual, indent=2)}"
        print(f"BOOT {args.mode} {case['id']}: ok", flush=True)
    if args.mode == "record":
        assert args.output and not args.output.exists(), "record into a NEW path; never overwrite goldens"
        args.output.write_text(json.dumps({"go_source": os.environ["GOFREE_GO_SOURCE"],
                                          "recorder_sha256": hashlib.sha256((HERE / "record_test.go.txt").read_bytes()).hexdigest(),
                                          "cases_sha256": hashlib.sha256((HERE / "cases.json").read_bytes()).hexdigest(),
                                          "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                          "cases": goldens}, indent=2) + "\n")


if __name__ == "__main__":
    main()
