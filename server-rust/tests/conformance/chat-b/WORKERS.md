# Chat worker oracle (#268)

`chat_worker_recorded` compares real one-tick frozen-Go effects with native
public worker adapters. Recording-only `.go.txt` overlays call Go's unchanged
worker methods inside their original packages; no runtime Go file is edited.
Ordinary replay has no Go process. All fixtures use the assigned disposable DB.

The TTL recording includes expired ok/pending/error rows, a fresh row, the image
blob reference and deferred cleanup queue. Native scheduling uses a full initial
hour, drops missed ticks and cancels/joins on shutdown. Its accelerated clock
passes the hour by 1 ms because Tokio rounds timer deadlines to milliseconds.
`RUST_WORKERS_ON=chat-unfurl-reap` starts this type in the executable; pair the
transfer with Go's `GO_WORKERS_OFF=chat-unfurl-reap`.

Preview recordings observe cache state, message payload/sequence, notifications
and real HTTP peers. The cache/text candidates are wired into committed URL sends by #418; its
additional fetch/image/SSRF recordings extend this same public worker seam.
Go's HTML tokenizer keeps the first duplicate attribute; the metadata oracle
records that behavior rather than inferring it from the attribute loop.

Record with `GOFREE_RECORD_CHAT_WORKER=1 GOFREE_GO_SOURCE=<frozen SHA>` and the
normal DB environment. For repeated unfurl cases, build the Go test executable
once with the `unfurl_process_test.go.txt` overlay, then set
`GOFREE_RECORD_CHAT_WORKER_BINARY` to it. Its sibling `.receipt.json` must bind
`go_source`, `helper_sha256` and `binary_sha256`; the recorder rejects stale
inputs. The bounded cold build needs GOMAXPROCS=1, GOGC=20, GOMEMLIMIT=768MiB,
`-p=1` and `-gcflags=github.com/microsoftgraph/msgraph-sdk-go/models=-N -l`.
Use an owned GOCACHE and container prefix; both Go SDK compilation and relinking
are expensive, while the prebuilt tick needs neither. Never rerecord a file.

Chat cron callbacks (#365): `chat_cron_recorded` runs frozen Go's real cron
Worker (overlay `cron_tick_test.go.txt`, package `cron`) over a seeded channel:
Go-off tick (no effect), anchor, purge, anchor again; native callbacks replay the
same rows (message ids as indexes). Go keeps its scheduler lock; Rust holds
per-task `cron-task:<name>` locks and starts only with matching
`GO_WORKERS_OFF=cron:<name>`. Record with `GOFREE_RECORD_CHAT_CRON=1
GOFREE_GO_SOURCE=<frozen SHA>` (needs the CI image and Go module cache mount).

Recording runners honor `GOFREE_RESOURCE_PREFIX` for container names and local
artifacts, and mount the shared Go module/build caches. The default prefix remains
`gofree-chat3`; #418 uses `gofree-chat4`. Never rerecord existing goldens.

#418 adds immutable page/image recordings for redirects, gzip, private DNS,
userinfo/private redirect refusal, hop limits, wrong types, decompressed size
limits, image-only/partial previews, and inert pending/error cache hits. Ordinary
replay also requires one Rust receipt per committed claim/cache/apply/blob step;
receipt metadata stays outside Go business observations. Signed S3 requests are
independently verified before comparing method, target, bytes/hash and PUT type.

[#418 recording receipt](unfurl-recording-418.json) binds all 34 new HTTP/effect
and worker goldens to frozen Go source, helper/binary hashes and the CI image.
