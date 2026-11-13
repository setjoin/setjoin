#!/usr/bin/env python3
"""Build frozen Go with a recording-only dial mapping for the controlled TLS peer.
The original handler, DNS selection, SSRF predicate, TLS verification and decoding
remain in use. Only a DNS-approved peer.static2.test socket is mapped to loopback.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / "test-results/gofree-static2"
OUT.mkdir(parents=True, exist_ok=True)
source = ROOT / "mailserver/internal/discovery/handler.go"
original = source.read_text()
needle = "client := ssrf.SafeHTTPClient(5 * time.Second)"
assert original.count(needle) == 1
hook = original.replace('import (', 'import (\n "context"\n "os"', 1).replace(needle, "client := static2RecordingClient()")
hook += r'''
// Recording transport only: the logical destination must still pass Go's
// concrete-IP SSRF policy before reaching this test's private TLS receiver.
func static2RecordingClient() *http.Client {
    c := ssrf.SafeHTTPClient(5 * time.Second)
    t := c.Transport.(*http.Transport)
    originalDial := t.DialContext
    t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
        host, _, err := net.SplitHostPort(address)
        if err != nil || host != "peer.static2.test" || os.Getenv("GOFREE_STATIC2_PEER") == "" {
            return originalDial(ctx, network, address)
        }
        ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
        if err != nil { return nil, err }
        if len(ips) == 0 { return nil, ssrf.ErrUnsafeURL }
        for _, ip := range ips {
            if ssrf.IsBlockedIP(ip.IP) { return nil, ssrf.ErrUnsafeURL }
        }
        return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, os.Getenv("GOFREE_STATIC2_PEER"))
    }
    return c
}
'''
(OUT / "discovery-hook.go").write_text(hook)
(OUT / "discovery-overlay.json").write_text(json.dumps({"Replace": {"/src/mailserver/internal/discovery/handler.go": "/src/test-results/gofree-static2/discovery-hook.go"}}))
receipt = {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "handler_sha256": hashlib.sha256(original.encode()).hexdigest(), "hook_sha256": hashlib.sha256(hook.encode()).hexdigest()}
(OUT / "discovery-build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
with (OUT / "discovery-build.log").open("wb") as log:
    subprocess.run(["docker", "run", "--rm", "--name", "gofree-static2-discovery-build", "--network", "host", "-v", f"{ROOT}:/src", "-v", f"{os.environ.get('GOFREE_GO_MOD_CACHE', str(Path.home() / 'go' / 'pkg' / 'mod'))}:/root/go/pkg/mod", "-w", "/src/mailserver", "-e", "GOCACHE=/src/test-results/gofree-static2/go-cache", "-e", "GOMAXPROCS=1", "-e", "GOGC=50", "-e", "GOMEMLIMIT=768MiB", "setjoin-ci-linux-tc:local-amd64", "go", "build", "-p=1", "-overlay=/src/test-results/gofree-static2/discovery-overlay.json", "-o", "/src/test-results/gofree-static2/mailserverd-discovery", "./cmd/mailserverd"], stdout=log, stderr=subprocess.STDOUT, check=True)
print("built owned discovery recorder")
