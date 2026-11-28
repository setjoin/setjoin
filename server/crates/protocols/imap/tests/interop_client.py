#!/usr/bin/env python3
"""Third-party IMAP client (CPython imaplib) run inside the owned interop image.
Prints one JSON object. argv: plain_port starttls_port tls_port."""
import base64
import imaplib
import json
import ssl
import sys

# Stock imaplib (like Dovecot imapc) refuses a server that does not advertise
# IMAP4rev1. Frozen Go advertises only IMAP4rev2, so the client is told it is
# acceptable; this is the documented parity bug, not something Rust fixes.
imaplib.AllowedVersions = ("IMAP4REV2", "IMAP4REV1", "IMAP4")
# Go answers AUTHENTICATE PLAIN with "+ Ready for additional data", text that is
# not base64; imaplib decodes every challenge and raises. Parity bug: skip decoding.
imaplib._Authenticator.decode = lambda self, inp: b""
PLAIN, STARTTLS, TLS = map(int, sys.argv[1:4])
PW = "IMAP1-correct-password!"
ctx = ssl.create_default_context(cafile="/ca.pem")
out = {}


def selected(c, name, readonly=False):
    typ, data = c.select(name, readonly)
    return dict(
        typ=typ,
        exists=data[0].decode() if data and data[0] else None,
        validity=(c.response("UIDVALIDITY")[1] or [b""])[0].decode(),
        uidnext=(c.response("UIDNEXT")[1] or [b""])[0].decode(),
    )


c = imaplib.IMAP4("127.0.0.1", PLAIN)
out["plain_capabilities"] = list(c.capabilities)
try:
    c.login("alice@imap1.test", "wrong")
    out["plain_bad_login"] = "accepted"
except imaplib.IMAP4.error as e:
    out["plain_bad_login"] = str(e)
out["plain_login"] = c.login("alice@imap1.test", PW)[0]
out["plain_select_inbox"] = selected(c, "INBOX")
out["plain_select_missing"] = c.select("Nope")[0]
out["plain_examine"] = selected(c, "Project", True)
out["plain_namespace"] = c.namespace()[1][0].decode()
out["plain_noop"] = c.noop()[0]
out["plain_logout"] = c.logout()[0]

c = imaplib.IMAP4("127.0.0.1", STARTTLS)
out["starttls_capabilities_before"] = list(c.capabilities)
try:
    c.login("alice@imap1.test", PW)
    out["starttls_plaintext_login"] = "accepted"
except imaplib.IMAP4.error as e:
    out["starttls_plaintext_login"] = str(e)
out["starttls_upgrade"] = c.starttls(ssl_context=ctx)[0]
out["starttls_capabilities_after"] = list(c.capabilities)
out["starttls_authenticate"] = c.authenticate(
    "PLAIN", lambda _: b"\0alice@imap1.test\0" + PW.encode()
)[0]
out["starttls_select"] = selected(c, "Sent")
out["starttls_logout"] = c.logout()[0]

c = imaplib.IMAP4_SSL("localhost", TLS, ssl_context=ctx)
out["tls_capabilities"] = list(c.capabilities)
out["tls_login"] = c.login("alice@imap1.test", PW)[0]
out["tls_select"] = selected(c, "Inbox")
out["tls_logout"] = c.logout()[0]
print(json.dumps(out))
