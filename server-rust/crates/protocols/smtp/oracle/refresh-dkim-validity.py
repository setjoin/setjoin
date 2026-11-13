#!/usr/bin/env python3
"""Move the DKIM expiry of the recorded vectors to 2100 (#472).

Go signs its vectors with `Expires: now+24h` (or +7d), so the frozen recordings stop
verifying after that window and every replay of a "valid" case flips to an expired verdict.
Expiry only changes the verdict of the signature, so the recorded Go results stay valid. This
script finds every DKIM-Signature whose `x=` is a real near-term instant (the deliberate
`x=2` cases are left alone), re-signs it with the public test key in auth-fixture/ when the
signer reproduces the recorded signature byte for byte (so tampered/bad signatures stay
exactly as invalid as recorded), otherwise only moves `x=`, and replaces the old bytes
everywhere in the corpora (including the stored-blob keys). `--check` only proves the signer.
"""
import base64, hashlib, json, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = [
    "security-imip-dkim-go.json", "security-imip-dkim-requests.json",
    "dkim-go.json", "dkim-requests.json", "dmarc-go.json", "dmarc-requests.json",
]
RSA, ED = HERE / "auth-fixture/rsa.pem", HERE / "auth-fixture/ed25519.pem"
EXPIRES = "4102444800"  # 2100-01-01T00:00:00Z, same width as the recorded values
REAL = lambda x: 1_700_000_000 < int(x) < 4_000_000_000


def unfold(v):
    return re.sub(r"\r\n(?=[ \t])", "", v)


def relaxed(name, value):
    value = re.sub(r"[ \t]+", " ", unfold(value)).strip(" \t")
    return f"{name.lower()}:{value}\r\n"


def tag(value, name):
    m = re.search(r"(?:^|;)\s*" + name + r"=([^;]*)", unfold(value))
    return m.group(1).strip() if m else None


def sign(send, expires):
    """Returns the re-signed message, or None when the signer cannot reproduce the recording."""
    header, rest = send.split("\r\n", 1)
    value = header[len("DKIM-Signature: "):]
    alg, canon = tag(value, "a"), (tag(value, "c") or "simple/simple")
    new_value = re.sub(r"\bx=\d+", "x=" + expires, value)
    if alg not in ("rsa-sha256", "rsa-sha1") or tag(value, "h") is None:
        return None
    head_part = rest.split("\r\n\r\n", 1)[0]
    lines = unfold(head_part).split("\r\n")
    fields = {}
    for line in lines:
        name, _, val = line.partition(":")
        fields.setdefault(name.lower(), []).append((name, val))
    def build(v, simple_extra):
        unsigned = re.sub(r"\bb=[A-Za-z0-9+/=\s]*$", "b=", v)
        out = ""
        used = {}
        for h in tag(v, "h").split(":"):
            h = h.strip().lower()
            idx = used.get(h, 0)
            # DKIM takes the instances bottom-up
            inst = fields.get(h, [])
            if len(inst) <= idx:
                continue
            name, val = inst[-1 - idx]
            used[h] = idx + 1
            out += relaxed(name, val) if canon.startswith("relaxed") else f"{name}:{val}\r\n"
        sig_header = "DKIM-Signature:" + (" " if True else "") + unsigned
        out += relaxed("DKIM-Signature", unsigned).rstrip("\r\n") if canon.startswith("relaxed") else sig_header
        return unsigned, out
    digest = "-sha256" if alg == "rsa-sha256" else "-sha1"
    def signature(v):
        unsigned, data = build(v, None)
        sig = subprocess.run(["openssl", "dgst", digest, "-sign", str(RSA)], input=data.encode(), capture_output=True, check=True).stdout
        return unsigned + base64.b64encode(sig).decode()
    recorded_b = tag(value, "b")
    # Reproduce the recording first (same x): only then is the signature a valid one to renew.
    if signature(value) != re.sub(r"\bb=[A-Za-z0-9+/=\s]*$", "b=", value) + (recorded_b or ""):
        return None
    return "DKIM-Signature: " + signature(new_value) + "\r\n" + rest


def collect(doc):
    cases = doc if isinstance(doc, list) else doc.get("cases", [])
    for case in cases:
        for step in case.get("steps", []):
            send = step.get("send", "")
            m = re.match(r"DKIM-Signature: ([^\r\n]*(?:\r\n[ \t][^\r\n]*)*)\r\n", send)
            if m and tag(m.group(1), "x") and REAL(tag(m.group(1), "x")):
                yield case.get("name"), send


def main():
    check = "--check" in sys.argv
    pairs = {}
    renewed = patched = 0
    for name in FILES:
        doc = json.loads((HERE / name).read_text())
        for case, send in collect(doc):
            if send in pairs:
                continue
            new = sign(send, EXPIRES)
            if new is None:
                # Not reproducible (tampered or bad by design): keep the bytes, move only x=.
                head, rest = send.split("\r\n", 1)
                new = re.sub(r"\bx=\d+", "x=" + EXPIRES, head, count=1) + "\r\n" + rest
                patched += 1
                if check:
                    print("  x-only:", name, case)
            else:
                renewed += 1
            pairs[send] = new
    print(f"{renewed} signatures re-signed, {patched} moved by x= only")
    if check:
        return
    extra = {}
    headers = {o.split("\r\n", 1)[0]: n.split("\r\n", 1)[0] for o, n in pairs.items()}
    def stored(message):
        # The server stores the DATA payload with LF line ends (the blob key hashes those bytes).
        return message.removesuffix(".\r\n").replace("\r\n", "\n").encode()
    def pair_blob(old_message, new_message):
        extra[hashlib.sha256(stored(old_message)).hexdigest()] = hashlib.sha256(stored(new_message)).hexdigest()
        extra[base64.b64encode(stored(old_message)).decode()] = base64.b64encode(stored(new_message)).decode()
    # Every message that carries a renewed header anywhere (also behind another signature).
    for name in FILES:
        for case in (lambda d: d if isinstance(d, list) else d.get("cases", []))(json.loads((HERE / name).read_text())):
            for step in case.get("steps", []):
                message = step.get("send", "")
                changed = message
                for old_header, new_header in headers.items():
                    changed = changed.replace(old_header, new_header)
                if changed != message:
                    pair_blob(message, changed)
                    extra[message] = changed
    pairs.update(headers)
    pairs.update(extra)
    def enc(text):
        # The recordings carry Go's JSON string encoding (HTML-escaped <, > and &).
        return json.dumps(text, ensure_ascii=False)[1:-1].replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    for name in FILES:
        text = (HERE / name).read_text()
        # Longest first: the full messages contain the shorter header/base64 forms.
        for old in sorted(pairs, key=len, reverse=True):
            text = text.replace(enc(old), enc(pairs[old]))
        (HERE / name).write_text(text)
    # tests/inbound_recording.rs pins the digests of the security corpora: re-pin the ones refreshed.
    receipt_path = HERE / "security-recording.json"
    receipt = json.loads(receipt_path.read_text())
    root = HERE.parents[4]
    for corpus in receipt["corpora"]:
        for file in corpus["sha256"]:
            corpus["sha256"][file] = hashlib.sha256((root / file).read_bytes()).hexdigest()
    receipt_path.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")

main()
