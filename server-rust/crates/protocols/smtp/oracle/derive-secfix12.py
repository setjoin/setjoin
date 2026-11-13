#!/usr/bin/env python3
"""Derive the SECFIX12 secure-only cases (#544) from recorded frozen-Go cases.

Each is a recorded valid S/MIME case whose signed message gets an unsigned part appended
after the closing boundary. The signature still verifies over the first part, so frozen Go
(and the pre-fix Rust port) kept the "valid" badge and skipped phish warnings / link
rewriting for the unsigned part. The expected values are written by the replay itself
(`SECFIX12_WRITE_SECURITY=1 cargo test -p setjoin-smtp --test session secfix12`) into
`oracle/security/<name>.json` and reviewed in the diff. Run from this directory.
"""
import json
import pathlib

here = pathlib.Path(__file__).parent
TRAILER = "Content-Type: text/plain\r\n\r\nclick https://evil.example/pay now\r\n"


def derive(corpus, source, name, edit, contains, lacks=()):
    case = next(c for c in json.load(open(here / corpus)) if c["name"] == source)
    case = json.loads(json.dumps(case))
    case["name"] = name
    case["secure_only"] = True
    case["derived_from"] = f"{corpus}:{source}"
    case["blob_contains"] = contains
    if lacks:
        case["blob_lacks"] = list(lacks)
    data = next(s for s in case["steps"] if "--smtp6-signed--\r\n.\r\n" in s["send"])
    data["send"] = edit(data["send"]).replace(f"<{source}@", f"<{name}@")
    # The recorded expectations are kept as placeholders; the replay overwrites them.
    (here / "security" / f"{name}.json").write_text(json.dumps([case], indent=1) + "\n")


def trailing(send):
    return send.replace("--smtp6-signed--\r\n.\r\n", "--smtp6-signed--\r\n" + TRAILER + ".\r\n")


def preamble(send):
    # content-type (lowercase) names multipart/mixed first, so the body walkers (first
    # Content-Type, case-insensitive) frame the message by B; the old line-based boundary
    # pick still read the signed part's header.
    head, body = send.split("\r\n\r\n", 1)
    attack = "--b\r\n" + TRAILER.replace("click", "visit").replace("https://evil.example/pay now", "https://evil.example/x") + "--b--\r\n"
    return "content-type: multipart/mixed; boundary=b\r\n".join(["", head]) + "\r\n\r\n" + attack + body


# Both rewrite the signed text part like unsigned mail: the badge is gone, so the link
# protection (not the top-level multipart/signed phish banner, which Go never injects) fires.
derive("security-link-composition-go.json", "link-valid-signature-exempts", "secfix12-trailing-part-links", trailing, ["/link-protect?token="])
derive("security-link-composition-go.json", "link-valid-signature-exempts", "secfix12-preamble-part-links", preamble, ["/link-protect?token="], ["https://evil.example/x"])
