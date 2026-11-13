#!/usr/bin/env python3
"""Frozen-Go HTTP census and completeness guard for the Go-free front door (#255).

No Go build, DB or listener. Lex Go tokens (including comments/raw strings) and
fail closed on non-literal registrations. The gateway golden adds the existing
runtime-derived evidence. --write creates entries; review family/slice assignments
before committing. Subsequent checks preserve reviewed upstream/state decisions.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "server-rust/bins/gateway/route-inventory.json"
# Match strings before punctuation; neither comments nor string contents are code.
TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|[^\s]')
ROOTS = ("mailserver", "authserver", "shared", "mailctl", "asrbot", "tools")


def census(root):
    found = {}

    def add(listener, pattern, source):
        parts = pattern.split(" ", 1)
        method, path = parts if len(parts) == 2 else ("*", pattern)
        if not path.startswith("/"):
            raise ValueError(f"unrecognised Go pattern {source}: {pattern}")
        found.setdefault((listener, method, path), set()).add(source)

    for dirname in ROOTS:
        for file in sorted((root / dirname).rglob("*.go")):
            rel = file.relative_to(root).as_posix()
            if file.name.endswith("_test.go") or "vendor" in file.parts:
                continue
            # This recorder implements Handle; it never registers a runtime route.
            if rel == "mailserver/internal/testutil/routeinventory.go":
                continue
            # DNS ServeMux, not an HTTP listener.
            if rel == "mailserver/internal/federation/testharness/srvstub.go":
                continue
            tokens = [m.group() for m in TOKEN.finditer(file.read_text())
                      if not m.group().startswith(("//", "/*"))]
            for i in range(2, len(tokens) - 3):
                if tokens[i - 1] != "." or tokens[i] not in ("Handle", "HandleFunc") or tokens[i + 1] != "(":
                    continue
                # Named non-HTTP domain methods, not ServeMux registrations.
                if (rel, tokens[i - 2]) in {
                    ("mailserver/internal/federation/sender.go", "receiver"),
                    ("mailserver/cmd/mailserverd/main.go", "driveWatchNotifier"),
                }:
                    continue
                literal = tokens[i + 2]
                if not literal.startswith(('"', '`')) or tokens[i + 3] != ",":
                    raise ValueError(f"non-literal registration in {rel}; extend census explicitly")
                pattern = literal[1:-1] if literal.startswith('`') else json.loads(literal)
                listener = "gateway"
                if dirname == "authserver":
                    listener = "auth"
                elif dirname == "asrbot":
                    listener = "asrbot"
                elif "testharness" in file.parts:
                    listener = "fedharness"
                elif file.name == "setup_control.go":
                    listener = "control"
                add(listener, pattern, rel)
    golden = root / "mailserver/cmd/mailserverd/testdata/route_inventory.golden"
    if golden.exists():
        for line in golden.read_text().splitlines():
            if line and not line.startswith("#"):
                add("gateway", line.split("\t")[0], golden.relative_to(root).as_posix())
    # ACME's x/crypto handler registers its own challenge prefix, not a mux call.
    main = root / "mailserver/cmd/mailserverd/main.go"
    if main.exists() and "HTTP01Handler(" in main.read_text():
        add("acme", "/.well-known/acme-challenge/", main.relative_to(root).as_posix())
    return found


def family(listener, path):
    if listener == "auth" or path.startswith(("/auth/", "/oauth", "/authorize")) or path in ("/userinfo", "/keys", "/end_session", "/revoke", "/.well-known/jwks.json", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        return "F21"
    if listener in ("acme", "control", "fedharness"):
        return "F08"
    if listener == "asrbot":
        return "F13"
    rules = [
        ("F01", r"/admin/(identity|users|roles|scope-sets|access-reviews|departments|distribution-groups|email-address-policies|permissions|me)(/|$|-)"),
        ("F02", r"/(admin/(ad|ldap)|scim)(/|$)"),
        ("F03", r"/admin/(conditional-access|user-risk)(/|$)"),
        ("F04", r"/admin/(audit|ediscovery|retention|content-search|chat-(compliance|ediscovery|purge|retention-policies))(/|$)"),
        ("F05", r"/admin/(mailboxes|mailbox-purge|mailbox-purges|mailbox-purge-approvals|migration|exchange-replacement)(/|$)"),
        ("F06", r"/(admin/(quarantine|queue|spam|tls|outbound-tls-policy|dmarc|dlp|threat|trace|smime|anti-phish|link-protect|auth-log)|quarantine|link-protect|report|settings/(external-sender|sender-control|senders|trusted-senders)|user/cert-status|messages/[^/]+/trace)(/|$)"),
        ("F07", r"/(admin/(devices|mdm|mam|offline)|offline)(/|$)"),
        ("F09", r"/(admin/(rules|rule-templates)|settings/(rules|rules-list|rule-templates))(/|$)"),
        ("F10", r"/(approvals|me/approvals|admin/approval-(policies|requests))(/|$)"),
        ("F11", r"/(admin/(guests|guest-invite-domains|guest-profile-domains|guest-profiles)|public/guest|me/guest-invites)(/|$)"),
        ("F12", r"/(chat|admin/chat-channels)(/|$)"),
        ("F13", r"/(meet|rtc|admin/meet|public/meet)(/|$)"),
        ("F14", r"/(drive|admin/sharing|public/(drive|share)|me/sharing)(/|$)"),
        ("F15", r"/(office|admin/office)(/|$)"),
        ("F16", r"/(blobs|mail-attachment|recovery)(/|$)"),
        ("F17", r"/(calendar|caldav|carddav|contacts|booking|public/booking)(/|$)"),
        ("F18", r"/(jmap|mail|messages|\.well-known/jmap)(/|$)"),
        ("F19", r"/(settings|user|me)(/|$)"),
        ("F20", r"/assist(/|$)"),
        ("F08", r"/(admin|setup|terms|updates)(/|$)"),
        ("F22", r"/(api|downloads|health|ready|metrics|telemetry|favicon.ico|\.well-known)(/|$)|^/$"),
    ]
    for fid, pattern in rules:
        if re.match(pattern, path):
            return fid
    raise ValueError(f"assign a family to {listener} {path}")


# F18 (JMAP) is split across five tickets (#315-#319): each registration belongs to exactly one.
JMAP_SLICES = {
    ("POST", "/jmap"): "email-methods",
    ("GET", "/messages/{emailId}/download"): "email-methods",
    ("GET", "/messages/{id}/attachments.zip"): "email-methods",
    ("POST", "/messages/{emailId}/unsubscribe"): "email-methods",
    ("POST", "/messages/{id}/focus"): "email-methods",
    ("GET", "/.well-known/jmap"): "mailbox-thread-other",
    ("POST", "/jmap/upload/{accountId}"): "mailbox-thread-other",
    ("GET", "/jmap/download/{accountId}/{blobId}/{name}"): "mailbox-thread-other",
    ("GET", "/jmap/recovery-raw/{accountId}/{messageId}"): "mailbox-thread-other",
    ("POST", "/mail/attachment-transfer-token"): "mailbox-thread-other",
    ("POST", "/messages/{id}/recall"): "submission",
    ("POST", "/messages/{id}/undo"): "submission",
    ("GET", "/jmap/ws"): "websocket-push",
    ("GET", "/jmap/eventsource"): "sse-event-source",
}


# F21 login/session/token (#331–#333) and the three MFA slices (#334–#336). Identity links
# and the OIDC discovery wrapper are federation, not login routes.
def identity_slice(method, path):
    # #337/#338 census: this is the only runtime connector call site.
    # AD methods have no additional HTTP route; main warms only local.
    if (method, path) == ("PUT", "/auth/password"):
        return "connectors-a"
    if path in {"/auth/forgot-password/begin", "/auth/forgot-password/verify"}:
        return "mfa-push-possession"
    if re.search(r"/(totp|webauthn|push|mfa|backup-codes)(/|$)", path):
        return ("mfa-totp" if re.search(r"/totp(/|$)", path) and "/mfa/" not in path
                else "mfa-webauthn" if "/webauthn" in path and "/mfa/" not in path
                else "mfa-push-possession")
    if path in {"/.well-known/", "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server", "/auth/oidc/op/complete",
                "/authorize", "/authorize/", "/authorize/callback", "/oauth", "/oauth/",
                "/oauth/token", "/oauth/introspect", "/userinfo", "/keys", "/end_session", "/revoke"}:
        return "federation-op"  # #339
    if "/saml" in path or path.startswith("/auth/identity-links"):
        return "federation-saml"  # #341 owns shared link list/delete at closing check
    if "/oidc" in path:
        return "federation-rp"  # #340, including the mixed front-door subtree
    if (method, path) in {("POST", "/auth/login"), ("GET", "/auth/password-policy"),
                          ("GET", "/.well-known/jwks.json"), ("GET", "/health"), ("GET", "/ready")}:
        return "login"
    if path in {"/auth/logout", "/auth/refresh", "/auth/me", "/auth/session/token", "/auth/change-password"} or path.startswith("/auth/forgot-password/"):
        return "sessions-refresh"
    return "token-issuance"


def entry(key, sources):
    listener, method, path = key
    fid = family(listener, path)
    slice_name = "routes"
    if fid == "F21":
        slice_name = identity_slice(method, path)
    pilot = listener == "gateway" and method == "POST" and path == "/jmap"
    if fid == "F18":
        slice_name = JMAP_SLICES[(method, path)]
    upstream = "go-auth" if listener == "auth" or fid == "F21" else "go-mail"
    if listener == "asrbot":
        upstream = "go-asrbot"
    return dict(listener=listener, method=method, path=path, family=fid,
                slice=slice_name,
                upstream="local-rust" if pilot else upstream,
                state="ON" if pilot else "OFF", sources=sorted(sources))


def check(root, file):
    expected = census(root)
    data = json.loads(file.read_text())
    if data.get("version") != 1 or not isinstance(data.get("routes"), list):
        raise ValueError("unsupported inventory schema")
    actual = {}
    for row in data["routes"]:
        key = tuple(row[k] for k in ("listener", "method", "path"))
        if key in actual:
            raise ValueError(f"duplicate inventory entry {key}")
        actual[key] = row
        if row["family"] not in {f"F{i:02}" for i in range(1, 23)} or not row["slice"]:
            raise ValueError(f"invalid family/slice {key}")
        if row["family"] == "F21" and row["slice"] != identity_slice(row["method"], row["path"]):
            raise ValueError(f"F21 slice assignment changed {key}")
        if row["state"] not in ("ON", "OFF") or row["upstream"] not in ("local-rust", "rust-auth", "go-mail", "go-auth", "go-asrbot", "rust-asrbot"):
            raise ValueError(f"invalid upstream/state {key}")
        # The captions bot is its own listener process (never proxied by the gateway): its
        # transfer is the Rust binary, so only that listener may use the rust-asrbot owner.
        if row["upstream"] == "rust-asrbot" and (row["listener"] != "asrbot" or row["state"] != "ON"):
            raise ValueError(f"rust-asrbot is the ON owner of the asrbot listener only {key}")
        if row["state"] == "ON" and row["upstream"].startswith("go-"):
            raise ValueError(f"ON route still owned by Go {key}")
    missing, stale = expected.keys() - actual.keys(), actual.keys() - expected.keys()
    if missing or stale:
        raise ValueError(f"E_GOFREE_ROUTE_INVENTORY missing={sorted(missing)} stale={sorted(stale)}")
    for key, sources in expected.items():
        if actual[key]["sources"] != sorted(sources):
            raise ValueError(f"registration provenance changed {key}")
    print(f"gofree-route-inventory: PASS ({len(actual)} routes; all registrations accounted for)")


def self_test():
    # Exercise the CLI against real source mutations, not an internal parser mock.
    with tempfile.TemporaryDirectory(prefix="gofree-t4-inventory-") as tmp:
        root = Path(tmp)
        source = root / "authserver/cmd/authserverd/main.go"
        source.parent.mkdir(parents=True)
        source.write_text('package main\nfunc routes() { mux.Handle("POST /auth/login", login) }\n')
        inv = root / "inventory.json"
        args = [sys.executable, str(Path(__file__).resolve()), "--root", tmp, "--inventory", str(inv)]
        def run(*extra):
            return subprocess.run([*args, *extra], capture_output=True, text=True)
        assert run("--write").returncode == 0
        assert run().returncode == 0
        source.write_text(source.read_text() + '\nfunc added() { mux.HandleFunc(\n`GET /auth/new/{id}`, handler) }\n')
        result = run()
        assert result.returncode != 0 and "E_GOFREE_ROUTE_INVENTORY" in result.stderr, result
        assert run("--write").returncode == 0
        assert run().returncode == 0
        source.write_text(source.read_text() + '\nfunc dynamic() { mux.Handle(pattern, handler) }\n')
        assert "non-literal registration" in run().stderr
        print("gofree-route-inventory self-test: PASS (new auth route rejected; reviewed entry accepted; dynamic registration fails closed)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    file = args.inventory or args.root / INVENTORY
    if args.write:
        old = json.loads(file.read_text()) if file.exists() else {"routes": []}
        decisions = {tuple(r[k] for k in ("listener", "method", "path")): r for r in old["routes"]}
        rows = []
        for key, sources in sorted(census(args.root).items()):
            row = decisions.get(key) or entry(key, sources)
            row["sources"] = sorted(sources)
            rows.append(row)
        file.write_text('{\n  "version": 1,\n  "routes": [\n' + ",\n".join("    " + json.dumps(r) for r in rows) + "\n  ]\n}\n")
    check(args.root, file)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as err:
        sys.exit(str(err))
