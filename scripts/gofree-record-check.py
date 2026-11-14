#!/usr/bin/env python3
"""gofree-record-check.py HEAD_SHA MANIFEST: every NEW recorded file must stamp go_source == HEAD_SHA.

Reads the new-file manifest (one path per line). A new file passes when it is JSON and every
`go_source` field in it (any depth) equals HEAD_SHA, with at least one present. Anything else
(missing provenance, a historical constant, a non-JSON file) is listed on stdout and exits 1.
New oracles must stamp GOFREE_GO_SOURCE into what they record (server-rust/DOX.md)."""
import json
import sys


def stamps(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "go_source":
                yield value
            else:
                yield from stamps(value)
    elif isinstance(node, list):
        for value in node:
            yield from stamps(value)


head, manifest = sys.argv[1], sys.argv[2]
bad = []
for line in open(manifest, encoding="utf-8"):
    path = line.rstrip("\n")
    if not path:
        continue
    try:
        found = list(stamps(json.load(open(path, encoding="utf-8"))))
    except (OSError, ValueError) as error:
        bad.append(f"{path}: not readable JSON ({type(error).__name__})")
        continue
    if not found:
        bad.append(f"{path}: no go_source provenance")
    elif any(value != head for value in found):
        bad.append(f"{path}: go_source {sorted(set(map(str, found)))} != {head}")
print("\n".join(bad))
sys.exit(1 if bad else 0)
