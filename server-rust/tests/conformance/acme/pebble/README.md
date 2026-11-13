Pebble (Let's Encrypt's ACME test server) fixtures for the #305 acme-renewal oracle.
`certs/` are the public test CA and server certificate from pebble/lego (MIT); the CA key is
public, so these must never enter a trust store. Ports are private to PLAT7 runs:
directory https://localhost:14070/dir, HTTP-01 validation on 5072.
Build pebble: `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest` (CI image), then
`PEBBLE_BIN=<path> cargo test -p setjoin-acme`.
