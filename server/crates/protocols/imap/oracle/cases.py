#!/usr/bin/env python3
"""Author IMAP session stimuli. Never writes Go responses: the Go recorder
(mailserver/internal/imap/listener_oracle_record_test.go) fills `response`.

A step is one client write followed by a read bounded by `until`:
  "<tag>"  read lines up to and including the line that starts with "<tag> "
  "+"      read the continuation request
  "eof"    read until the server closes
  "none"   write only; the server must stay silent
Optional: conn (connection index), upgrade (TLS handshake after the reply),
sleep_ms (before the write), action (registry revocation, no write).
"""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PW = "IMAP1-correct-password!"
LOW = "IMAP1-low-cost-password!"
SPACED = "IMAP1 spaced  password"


def step(request, until, **extra):
    return dict(request=request, until=until, **extra)


def cmd(tag, text):
    return step(f"{tag} {text}\r\n", tag)


def login(tag="l1", user="alice@imap1.test", password=PW):
    return cmd(tag, f'LOGIN "{user}" "{password}"')


def plain(user, password):
    return base64.b64encode(f"\0{user}\0{password}".encode()).decode()


def auth_plain(tag, user, password):
    return [step(f"{tag} AUTHENTICATE PLAIN\r\n", "+"), step(plain(user, password) + "\r\n", tag)]


def session(name, steps, transport="plain", **extra):
    return dict(name=name, transport=transport, steps=steps, **extra)


def build():
    s = []
    s.append(session("greeting-and-session-commands", [
        step("", "*"),
        cmd("a1", "CAPABILITY"), cmd("a2", "NOOP"), cmd("a3", "ID (\"name\" \"x\")"),
        cmd("a4", "ENABLE IMAP4rev2"), cmd("a5", "NAMESPACE"), cmd("a6", "LSUB \"\" \"*\""),
        cmd("a7", "SUBSCRIBE Inbox"), cmd("a8", "UNSUBSCRIBE Inbox"), cmd("a9", "bogus"),
        cmd("b1", "noop"), cmd("b2", "capability extra args"), step("lonely\r\n", "lonely"),
        step("\r\n   \r\nc1 NOOP\r\n", "c1"), step("c2\tNOOP\textra\r\n", "c2"),
        step("c3 NOOP\n", "c3"), cmd("c4", "STARTTLS"),
        cmd("z1", "LOGOUT"),
    ]))
    s.append(session("unauthenticated-select", [
        cmd("a1", "SELECT Inbox"), cmd("a2", "EXAMINE Inbox"), cmd("a3", "UNSELECT"),
        cmd("a4", "NOOP"),
    ]))
    s.append(session("login-failures", [
        cmd("a1", "LOGIN"), cmd("a2", "LOGIN alice@imap1.test"),
        login("a3", password="wrong"), login("a4", user="nobody@imap1.test"),
        login("a5", user="Alice@imap1.test"),
        login("a6", user="dave@imap1.test"), login("a7", user="ivan@imap1.test"),
        login("a8", user="erin@imap1.test"),
        cmd("a9", "LOGIN alice@imap1.test"),
        cmd("b1", f"LOGIN alice@imap1.test {PW} trailing"),
    ]))
    s.append(session("login-success-forms", [
        cmd("a1", f"LOGIN alice@imap1.test {PW}"),
        cmd("a2", f"LOGIN alice@imap1.test {PW}"), cmd("a3", "NOOP"),
        cmd("a4", "CAPABILITY"), cmd("a5", "AUTHENTICATE PLAIN"),
    ]))
    s.append(session("login-triple-quoted", [
        cmd("a1", f'LOGIN """alice@imap1.test""" "{PW}"'),
        cmd("a2", "SELECT Inbox"),
    ]))
    s.append(session("login-argument-quirks", [
        cmd("a1", "LOGIN {11+} abcdefghijk"),
        cmd("a2", f'LOGIN "jack@imap1.test" "{SPACED}"'),
        *auth_plain("a3", "jack@imap1.test", SPACED),
        cmd("a4", "SELECT Inbox"),
    ]))
    s.append(session("tag-and-separator-quirks", [
        step("", "*"), step("* NOOP\r\n", "*"), step("+ NOOP\r\n", "+"),
        step("u1\u00a0NOOP\r\n", "u1"), step("u2\u0085NOOP\r\n", "u2"),
        step("u3 NOOP\r", "none"), step("\nu4 NOOP\r\n", "u4"),
        step("verylongtag" * 20 + " NOOP\r\n", "verylongtag"),
    ]))
    s.append(session("login-denials", [
        login("a1", user="bob@imap1.test"), cmd("a2", "SELECT Inbox"),
        login("a3", user="carol@imap1.test"),
        login("a4", user="gina@imap1.test"), cmd("a5", "SELECT GinaPrivate"),
    ]))
    s.append(session("app-passwords", [
        login("a1", password="imap1-app-token-revoked"),
        login("a2", password="imap1-app-token-expired"),
        login("a3", password="imap1-app-token-nope"),
        login("a4", user="bob@imap1.test", password="imap1-app-token-bob"),
        login("a5", user="ivan@imap1.test", password="imap1-app-token-ivan"),
        login("a6", user="ALICE@imap1.test", password="imap1-app-token-valid"),
        cmd("a7", "SELECT Inbox"),
    ]))
    s.append(session("app-password-authenticate", auth_plain("a1", "alice@imap1.test", "imap1-app-token-valid") + [cmd("a2", "SELECT Inbox")]))
    s.append(session("authenticate-forms", [
        cmd("a1", "AUTHENTICATE"), cmd("a2", "AUTHENTICATE XOAUTH2 token"),
        step("a3 AUTHENTICATE PLAIN\r\n", "+"), step("*\r\n", "a3"),
        step("a4 AUTHENTICATE PLAIN\r\n", "+"), step("not base64!\r\n", "a4"),
        step("a5 AUTHENTICATE PLAIN\r\n", "+"), step(base64.b64encode(b"onlytwo\0parts").decode() + "\r\n", "a5"),
        *auth_plain("a6", "alice@imap1.test", "wrong"),
        step("a7 authenticate plain ignoredinitial\r\n", "+"),
        step(plain("alice@imap1.test", PW) + "\r\n", "a7"),
        cmd("a8", "AUTHENTICATE PLAIN"),
        cmd("a9", f"LOGIN alice@imap1.test {PW}"),
    ]))
    s.append(session("authenticate-authzid-ignored", [
        step("a1 AUTHENTICATE PLAIN\r\n", "+"),
        step(base64.b64encode(f"someone-else\0alice@imap1.test\0{PW}".encode()).decode() + "\r\n", "a1"),
    ]))
    s.append(session("select-forms", [
        login(),
        cmd("a1", "SELECT INBOX"), cmd("a2", "select inbox"), cmd("a3", 'SELECT "Inbox"'),
        cmd("a4", "EXAMINE Inbox"), cmd("a5", "SELECT Sent"), cmd("a6", "SELECT sent"),
        cmd("a7", "SELECT Project"), cmd("a8", "SELECT Gap"), cmd("a9", "SELECT Hidden"),
        cmd("b1", "SELECT [Gmail]/Trash"), cmd("b2", 'SELECT "[Gmail]/Trash"'),
        cmd("b3", "SELECT GinaPrivate"), cmd("b4", "SELECT BobBox"), cmd("b5", "SELECT"),
        cmd("b6", 'SELECT ""'), cmd("b7", 'SELECT """Inbox"""'), cmd("b8", "SELECT Inbox extra"),
        cmd("b9", "SELECT Project"), cmd("c1", "SELECT Nope"), cmd("c2", "NOOP"),
        cmd("c3", "SELECT Inbox"), cmd("c4", "UNSELECT"), cmd("c5", "UNSELECT"),
        cmd("c6", "EXAMINE Project"), cmd("c7", "SELECT Inbox"), cmd("c8", "LOGOUT"),
    ]))
    s.append(session("select-after-app-password", [
        login("a0", password="imap1-app-token-valid"), cmd("a1", "SELECT Inbox"), cmd("a2", "EXAMINE Sent"),
    ]))
    s.append(session("hash-upgrade", [login("a1", user="hank@imap1.test", password=LOW), cmd("a2", "NOOP")]))
    s.append(session("limit-per-user", [
        login("a1"), step("", "*", conn=1), login("b1") | dict(conn=1), cmd("a2", "LOGOUT"),
        step("", "none", conn=1, sleep_ms=300), login("b2") | dict(conn=1),
    ], per_user_max=1))
    s.append(session("revocation", [
        login("a1"), cmd("a2", "SELECT Inbox"),
        dict(action=dict(kind="revoke_all", user=9343012, not_before_offset_s=0)),
        cmd("a3", "NOOP"),
        dict(action=dict(kind="revoke_all", user=9343011, not_before_offset_s=0)),
        step("", "eof", sleep_ms=200),
    ], registry=True))
    s.append(session("revoked-before-login", [
        dict(action=dict(kind="revoke_all", user=9343011, not_before_offset_s=3600)),
        step("l1 LOGIN \"alice@imap1.test\" \"%s\"\r\n" % PW, "eof"),
    ], registry=True))
    s.append(session("line-limit", [
        step("", "*"), step("a" * 65536, "eof"),
    ]))
    s.append(session("authenticate-continuation-line-limit", [
        step("a1 AUTHENTICATE PLAIN\r\n", "+"),
        step("A" * 65536 + "\r\nz1 NOOP\r\n", "z1"),
    ]))
    s.append(session("pipelined", [
        step("p1 NOOP\r\np2 CAPABILITY\r\np3 NOOP\r\n", "p3"),
        step(f"p4 LOGIN alice@imap1.test {PW}\r\np5 SELECT Inbox\r\np6 NOOP\r\n", "p6"),
    ]))
    s.append(session("plain-starttls-unavailable-after-auth", [
        login(), cmd("a1", "STARTTLS"),
    ]))
    # STARTTLS listener
    s.append(session("starttls-flow", [
        step("", "*"), cmd("a1", "CAPABILITY"), login("a2"), *auth_plain("a3", "alice@imap1.test", PW),
        cmd("a4", "SELECT Inbox"), cmd("a5", "NOOP"),
        step("a6 STARTTLS\r\n", "a6", upgrade=True),
        cmd("a7", "CAPABILITY"), cmd("a8", "STARTTLS"), login("a9"),
        cmd("b1", "SELECT Inbox"), cmd("b2", "STARTTLS"),
    ], transport="starttls"))
    s.append(session("starttls-pipelined-injection", [
        step("a1 STARTTLS\r\na2 NOOP\r\n", "a1", upgrade=True),
        cmd("a3", "NOOP"),
    ], transport="starttls"))
    s.append(session("starttls-then-authenticate", [
        step("a1 STARTTLS\r\n", "a1", upgrade=True),
        *auth_plain("a2", "alice@imap1.test", PW), cmd("a3", "SELECT Inbox"),
    ], transport="starttls"))
    # Implicit TLS listener
    s.append(session("implicit-tls", [
        step("", "*"), cmd("a1", "CAPABILITY"), cmd("a2", "STARTTLS"), login("a3"),
        cmd("a4", "SELECT Inbox"), cmd("a5", "LOGOUT"),
    ], transport="tls"))
    return s


if __name__ == "__main__":
    out = ROOT / "requests.json"
    out.write_text(json.dumps(build(), indent=1) + "\n")
