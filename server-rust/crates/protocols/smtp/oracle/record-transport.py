#!/usr/bin/env python3
"""Record transport corpora without changing a byte of frozen Go runtime source."""
import os
from pathlib import Path
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[5]
source = root / "mailserver/internal/smtp/mtasts.go"
original = source.read_text()
needle = "client := ssrf.SafeHTTPClient(10 * time.Second)"
assert original.count(needle) == 1
with tempfile.TemporaryDirectory(prefix="gofree-smtp4-overlay-") as temp:
    overlay_source = Path(temp) / "mtasts.go"
    overlay_source.write_text(original.replace(needle, "client := smtpTransportHTTPClient(10 * time.Second)")
                              .replace('"setjoin.com/shared/ssrf"', ''))
    overlay = Path(temp) / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(overlay_source)}}))
    env = dict(os.environ, SMTP_TRANSPORT_OVERLAY="1", GOMAXPROCS="2")
    result = subprocess.run(["go", "test", "-p", "2", "-overlay", str(overlay),
                             "-tags", "gofree_record", "./internal/smtp",
                             "-run", "^TestRecordSMTPOutbound$", "-count=1"],
                            cwd=root / "mailserver", env=env, check=False)
    raise SystemExit(result.returncode)
