# asrbotd (Rust) — the Meet captions room bot (#356)

`setjoin-asrbot` replaces the Go `asrbot/` binary `asrbotd` behind the unchanged systemd unit
`setjoin-asr-bot` (`ExecStart=<install>/bin/asrbotd`, env contract in
[asrbot/DOX.md](../../../asrbot/DOX.md)). Go `asrbot/` is frozen: it stays only as the parity
oracle (ARCH-029). Same routes, same FunASR and LiveKit interactions, same outputs.

## Layout

- `src/control.rs`, `serve.rs`, `gojson.rs` — the control HTTP surface: `net/http` ServeMux
  behaviour (307 for unclean paths, 404, 405 with `Allow`, HEAD), `requireAuth` (Bearer prefix
  stripped if present, constant-time compare via `subtle`), Go `encoding/json` decode/encode
  subset (case-insensitive keys, `null` ignored, first value only, depth 10000, U+FFFD repair,
  HTML-escaped output), 8 KiB body bound, Read/Header/Idle timeouts.
- `src/registry.rs` — `RoomRegistry` (admission, capacity, cancel, compare-release; a stopping
  identity keeps its slot until the runner returns). `src/session.rs` — the real `RoomRunner`.
- `src/livekit.rs` — a minimal LiveKit participant over `webrtc` 0.21 (pure Rust, sans-io
  webrtc-rs) and `livekit-protocol`: signalling protocol 17, dual peer connections, lazy
  publisher negotiation, data on the `_lossy` channel. `src/worker.rs` — per-track pipeline
  (RTP -> Opus -> energy VAD/F10 arbiter -> FunASR -> `cc` frames), admission gate, heartbeats,
  JWT redaction. `src/funasr.rs` — FunASR 2pass WebSocket client. `src/opus.rs` — decoder over
  `unsafe-libopus` (c2rust libopus; the only `unsafe` in the crate, no native library, so the
  glibc-floor and loong64 builds need no libopus).
- No DB or S3 credential; no token minting; never log transcripts, bearer tokens or JWTs.

## Parity decisions (frozen Go is the target)

- The wire identity of Go is preserved on purpose: `/rtc?version=2.18.1&protocol=17&&auto_subscribe=1&sdk=go&os=linux`,
  `User-Agent: Go-http-client/1.1`, `Accept-Encoding: gzip` on FunASR and `/rtc/validate`.
- A failed join is diagnosed with `GET /rtc/validate` and logs the redacted error, as Go does.
- `Run` does not abandon an in-flight connect on stop (Go cannot): the identity stays admitted
  until the connect ends (<= 5 s), then the room is left at once.
- After a server `Leave` the signal socket stays open so the client `Leave{reason: CLIENT_INITIATED}`
  is still sent, as Go does.
- Known, accepted divergences: (1) no resume/reconnect: a lost signal socket or failed peer
  connection ends the session (the gateway reconcile restarts it) where Go first tries an ICE
  restart; (2) a malformed request target (`%zz`) gets the same 400 body but chunked framing
  where Go sends it close-delimited (hyper cannot write the latter; the oracle decodes chunked
  and ignores `Content-Length` for that one step); (3) `webrtc` 0.21 does not surface a DCEP
  retransmit limit on the accepting side, so tests observe `ordered` only; (4) owner-approved 2026-11-11 (#472):
  captions recognized before `Room::connect` returns wait for the connect (bounded by
  `CONNECT_TIMEOUT`+1 s) instead of being dropped as Go's `publisher.publish` does; the wait is 4 s (a compile-time check keeps it below `RESULT_DRAIN_TIMEOUT`, so a final cannot publish after the next stream's partials) and a slower connect still loses the early caption, as in Go. No golden
  covers it (`room_session` is a hand-written test), so there is no `divergences.json` entry.

## Verification

- `cargo test -p setjoin-asrbot -- --test-threads=1`: unit tests (VAD, registry, gojson, worker,
  heartbeat, redaction), `funasr_client`, `room_session` (bot vs fake SFU + FunASR) and the
  recorded oracles below. No real LiveKit, FunASR or network service is contacted.
- `control_oracle` (+ `tests/goldens/control-*.json`, `startup.json`, `graceful-stop.json`) runs
  the **Rust binary** through byte-exact HTTP and process scenarios against goldens recorded from
  the frozen Go binary. `outbound_oracle` (+ `outbound-*.json`) drives the bot process through
  `/start` against `tests/support/fake_sfu.rs` (a webrtc-rs SFU speaking signalling 17, with an Opus
  speaker) and `fake_funasr.rs`, normalises what each peripheral saw, and compares with Go.
- Record (exclusive-create; delete a golden to re-record it): build Go `asrbotd` in the CI image
  (`GOWORK=off go build -tags nolibopusfile ./cmd/asrbotd` in `asrbot/`), then
  `GOFREE_RECORD_ASRBOT_GO_BINARY=<path> cargo test -p setjoin-asrbot --test control_oracle --test outbound_oracle -- --test-threads=1`.
  Go runs in `setjoin-ci-linux-tc:local-amd64` with `--network host`, container names `gofree-asrbot-*`.
- The inventory rows of the `asrbot` listener are `ON`/`rust-asrbot` with `oracle_goldens`;
  `scripts/check-gofree-oracle-adequacy.py` checks the recorded statuses per route and, with
  `--execute`, runs one replay per golden and one `status_mutant_*` per route.
- Not proven here: a join against a real `livekit-server` and a real FunASR container (the honesty
  ledger in `asrbot/DOX.md` still applies: the live round-trip must be repeated for the Rust binary
  before `feature.meet_captions` flips on anywhere); loong64/glibc-floor builds of this crate.
