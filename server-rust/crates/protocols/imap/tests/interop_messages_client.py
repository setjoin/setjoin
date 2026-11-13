#!/usr/bin/env python3
"""Third-party IMAP client (CPython imaplib) for the message commands (#344),
run inside the owned interop image against the plaintext Rust socket. Prints one
JSON object. argv: plain_port. Same Go-parity client patches as interop_client.py."""
import imaplib
import json
import sys

imaplib.AllowedVersions = ("IMAP4REV2", "IMAP4REV1", "IMAP4")
c = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]))
out = {}


def text(items):
    return [i.decode() if isinstance(i, bytes) else repr(i) for i in items if i is not None]


def esearch(c):
    return text(c.response("ESEARCH")[1])


out["login"] = c.login("alice@imap2.test", "imap2-app-token-alice")[0]
out["select"] = c.select("INBOX")[0]
typ, data = c.fetch("1:2", "(FLAGS)")
out["fetch"] = [typ] + text(data)
typ, data = c.uid("FETCH", "11", "(UID)")
out["uid_fetch"] = [typ] + text(data)
out["search_unseen"] = [c.search(None, "UNSEEN")[0]] + esearch(c)
out["uid_search_from"] = [c.uid("SEARCH", "FROM", "example.org")[0]] + esearch(c)
out["search_subject"] = [c.search(None, "SUBJECT", '"needle"')[0]] + esearch(c)
typ, data = c.store("1", "+FLAGS", "(\\Flagged)")
out["store_add"] = [typ] + text(data)
typ, data = c.uid("STORE", "5", "FLAGS", "(\\Seen \\Answered)")
out["uid_store_replace"] = [typ] + text(data)
typ, data = c.store("3", "+FLAGS.SILENT", "(\\Deleted)")
out["store_silent"] = [typ] + text(data)
out["search_deleted_now"] = [c.search(None, "DELETED")[0]] + esearch(c)
out["search_undeleted"] = [c.uid("SEARCH", "UNDELETED")[0]] + esearch(c)
out["fetch_missing"] = [c.fetch("99", "(FLAGS)")[0]]
out["store_bad"] = None
try:
    c.store("x", "+FLAGS", "(\\Seen)")
except imaplib.IMAP4.error as e:
    out["store_bad"] = str(e)
out["logout"] = c.logout()[0]
print(json.dumps(out))
