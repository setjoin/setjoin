"""Real smtplib client in the existing test-smtp container image."""

import base64
import json
import smtplib
import ssl
import subprocess
import sys
import time
from pathlib import Path

plain_port, tls_port = map(int, sys.argv[1:3])
context = ssl.create_default_context(cafile="/smtp2-ca.pem")
for name, port in [("plain", plain_port), ("tls", tls_port)]:
    client = (
        smtplib.SMTP_SSL("localhost", port, timeout=10, context=context)
        if name == "tls"
        else smtplib.SMTP("127.0.0.1", port, timeout=10)
    )
    with client:
        code, _ = client.ehlo("remote.test")
        assert code == 250
        assert client.esmtp_features["size"] == "157286400"
        assert "pipelining" in client.esmtp_features
        assert "auth" not in client.esmtp_features
        assert ("starttls" in client.esmtp_features) == (name == "tls")
        try:
            client.sendmail(
                "sender@remote.test", ["relay@remote.test"], "Subject: refused\n\nbody"
            )
        except smtplib.SMTPRecipientsRefused as exc:
            assert exc.recipients["relay@remote.test"][0] == 550
        else:
            raise AssertionError("remote relay accepted")
        assert client.rset()[0] == 250
        wire = (
            "From: Sender <sender@remote.test>\n"
            "To: Alice <alice@smtp1.test>\n"
            f"Message-Id: <smtp1-interop-{name}@remote.test>\n"
            f"Subject: SMTP1 interop {name}\n\n"
            ".dot-stuffed line\nhello\n"
        )
        assert client.sendmail("sender@remote.test", ["alice@smtp1.test"], wire) == {}
        assert client.noop()[0] == 250
# A freshly signed message (mail-auth) must pass DKIM even with failing SPF.
vector = next(
    v
    for v in json.loads(Path("/smtp2-dkim.json").read_text())
    if v["name"] == "rsa-pass"
)
wire = base64.b64decode(vector["raw_base64"]).replace(
    b"<dkim@smtp2.test>", b"<smtp2-interop-dkim@remote.test>"
)
with smtplib.SMTP("127.0.0.1", plain_port, timeout=10) as client:
    assert client.sendmail("sender@dkim.smtp2.test", ["alice@smtp1.test"], wire) == {}
# Exercise the MTA shipped by test-smtp as well as the independent clients.
# Remove every inet service so this host-network fixture binds no extra port.
master = Path("/etc/postfix/master.cf")
services = []
keep = True
for line in master.read_text().splitlines():
    if line and not line[0].isspace() and not line.startswith("#"):
        fields = line.split()
        keep = len(fields) < 2 or fields[1] != "inet"
    if keep:
        services.append(line)
master.write_text("\n".join(services) + "\n")
for setting in [
    "inet_protocols=ipv4",
    "mydestination=localhost",
    f"relayhost=[127.0.0.1]:{plain_port}",
    "smtp_tls_security_level=none",
]:
    subprocess.run(["postconf", "-e", setting], check=True)
subprocess.run(["postfix", "start"], check=True)
try:
    wire = (
        "From: Sender <sender@remote.test>\n"
        "To: Alice <alice@smtp1.test>\n"
        "Message-Id: <smtp1-interop-postfix@remote.test>\n"
        "Subject: SMTP1 interop Postfix\n\n"
        ".dot-stuffed line\nhello\n"
    )
    subprocess.run(
        ["sendmail", "-i", "-f", "sender@remote.test", "alice@smtp1.test"],
        input=wire,
        text=True,
        check=True,
    )
    empty_samples = 0
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        queue = subprocess.check_output(["postqueue", "-j"], text=True)
        pending_pickup = list(Path("/var/spool/postfix/maildrop").iterdir())
        empty_samples = (
            empty_samples + 1 if not queue.strip() and not pending_pickup else 0
        )
        if empty_samples >= 5:
            break
        time.sleep(0.2)
    else:
        raise AssertionError(f"Postfix queue did not drain: {queue}")
finally:
    subprocess.run(["postfix", "stop"], check=True)
print(
    "SMTP2 mail-auth interop: plain/TLS clients, relay refusal and Postfix delivery passed"
)
