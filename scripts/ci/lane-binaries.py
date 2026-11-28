#!/usr/bin/env python3
"""lane-binaries.py LIST_JSON: print {binary-id: binary-path} from `cargo nextest list
--message-format json` (the build job's list). The shards extract the archive to the same
absolute target dir, so these paths are valid there; the adequacy gate launches them directly."""
import json
import sys

document = json.load(open(sys.argv[1]))
print(json.dumps({binary: suite["binary-path"] for binary, suite in sorted(document["rust-suites"].items())}, indent=1))
