#!/usr/bin/env python3
"""Third-party IMAP client (CPython imaplib) for the folder, copy/move, APPEND and
IDLE commands (#345), run inside the owned interop image against the plaintext
Rust socket. Prints one JSON object. argv: plain_port. Same Go-parity client
patches as interop_client.py (the server advertises only IMAP4rev2)."""
import imaplib
import json
import sys

imaplib.AllowedVersions = ("IMAP4REV2", "IMAP4REV1", "IMAP4")
imaplib.Commands["MOVE"] = ("SELECTED",)
c = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]))
out = {}


def text(items):
    return [i.decode() if isinstance(i, bytes) else repr(i) for i in items if i is not None]


out["login"] = c.login("alice@imap3.test", "imap3-app-token-alice")[0]
out["status"] = [c.status("INBOX", "(MESSAGES UNSEEN)")[0]] + text(c.status("Project", "(MESSAGES)")[1])
out["create"] = [c.create("Interop")[0]]
out["rename"] = [c.rename("Interop", "Interop2")[0]]
out["select_new"] = c.select("Interop2")[0]
out["delete_selected"] = [c.delete("Interop2")[0]]
out["select_inbox"] = c.select("INBOX")[0]
typ, data = c.append("Dup", "(\\Seen)", None, b"Subject: interop\r\n\r\nbody")
out["append"] = [typ] + text(data)
typ, data = c.copy("1", "Project")
out["copy"] = [typ] + text(data)
typ, data = c.copy("1", "Project")
out["copy_again"] = [typ] + text(data)
typ, data = c._simple_command("MOVE", "2", "Empty")
out["move"] = [typ] + text(data)
typ, data = c.uid("COPY", "20", "Label")
out["uid_copy"] = [typ] + text(data)
typ, data = c.store("1", "+FLAGS", "(\\Deleted)")
out["store"] = [typ] + text(data)
typ, data = c.expunge()
out["expunge"] = [typ] + text(data)
# IDLE: imaplib has no method, so drive the continuation by hand.
c.send(b"zz1 IDLE\r\n")
out["idle_continuation"] = c.readline().decode().strip()
c.send(b"DONE\r\n")
out["idle_done"] = c.readline().decode().strip()
out["close"] = [c.close()[0]]
out["list"] = [c.list()[0]]
out["logout"] = c.logout()[0]
print(json.dumps(out))
