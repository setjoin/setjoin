#!/usr/bin/env python3
"""Build the frozen-Go TLS recording/interchange peer in the approved CI image."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import textwrap

root = Path(__file__).resolve().parents[4]
work = root / "test-results/gofree-tlsfront"
work.mkdir(parents=True, exist_ok=True)
main = (root / "mailserver/cmd/mailserverd/main.go").read_text()
start = main.index("\t\ttlsCfg := &tls.Config{")
end = main.index("\n\n\t\t// Session ticket key rotation", start)
expression = textwrap.dedent(main[start:end])
template = Path(__file__).with_name("peer.go.txt").read_text()
source = template.replace("// FROZEN_TLS_CONFIG", expression)
source_path = work / "peer_test.go"
source_path.write_text(source)
overlay = work / "peer-overlay.json"
overlay.write_text(json.dumps({"Replace": {"/src/mailserver/internal/acme/gofree_tlsfront_peer_test.go": "/src/test-results/gofree-tlsfront/peer_test.go", "/src/mailserver/internal/acme/gofree_tlsfront_dns_test.go": "/src/server-rust/tests/conformance/tlsfront/dns.go.txt"}}))
name = f"gofree-tlsfront-peer-build-{os.getpid()}"
with (work / "resources.txt").open("a") as ledger:
    ledger.write(f"planned --rm container {name}; default local Docker; Go cache {work / 'go-cache'} retained for task\n")
# GOFREE_GO_MOD_CACHE / GOFREE_DOCKER_USER let the CI runner keep the module cache in a
# job-owned directory and avoid root-owned files in the workspace (#550); default $HOME/go/pkg/mod.
mod_cache = os.environ.get("GOFREE_GO_MOD_CACHE", str(Path.home() / "go" / "pkg" / "mod"))
user = ["--user", os.environ["GOFREE_DOCKER_USER"], "-e", "HOME=/tmp"] if os.environ.get("GOFREE_DOCKER_USER") else []
if user:
    Path(mod_cache).mkdir(parents=True, exist_ok=True)
cmd = ["docker", "run", "--rm", "--name", name, "--label", "org.setjoin.task=gofree-tlsfront", "--network", "host", *user, "-v", f"{root}:/src", "-v", f"{mod_cache}:/gomodcache", "-w", "/src/mailserver", "-e", "GOMAXPROCS=1", "-e", "GOGC=50", "-e", "GOMEMLIMIT=768MiB", "-e", "GOCACHE=/src/test-results/gofree-tlsfront/go-cache", "-e", "GOMODCACHE=/gomodcache", "setjoin-ci-linux-tc:local-amd64", "go", "test", "-p=1", "-vet=off", "-c", "-overlay=/src/test-results/gofree-tlsfront/peer-overlay.json", "-o", "/src/test-results/gofree-tlsfront/gofree-tlsfront-peer", "./internal/acme"]
with (work / "peer-build.log").open("w") as log:
    result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
if result.returncode:
    raise SystemExit((work / "peer-build.log").read_text()[-5000:])
(work / "peer-receipt.json").write_text(json.dumps({"go_source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(), "template_sha256": hashlib.sha256(template.encode()).hexdigest(), "dns_sha256": hashlib.sha256(Path(__file__).with_name("dns.go.txt").read_bytes()).hexdigest(), "tls_config_sha256": hashlib.sha256(expression.encode()).hexdigest()}, indent=2)+"\n")
print(work / "gofree-tlsfront-peer")
