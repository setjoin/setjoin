<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# asrbot — the Meet captions room-bot sidecar (DOX child)

> **#356:** the shipped `asrbotd` is now the Rust binary in `server-rust/bins/asrbot` (contract:
> [its DOX.md](../server-rust/bins/asrbot/DOX.md)), installed under the same unit name and path. This
> Go module is frozen and kept as the recorded-golden oracle; the env contract and control API below
> bind both. The live-proof and honesty-ledger items below must be repeated for the Rust binary.

Wired into the root `AGENTS.md` Child DOX Index as of B3 Task 18 (the
program gate), alongside every other cross-cutting doc pass for this
program. Also reachable from `mailserver/internal/meet/AGENTS.md`'s
"Captions (B3b)" section.

## Purpose

`setjoin-asr-bot`: a Go binary that joins one meeting's LiveKit room as an
UNHIDDEN (2026-07-16, B3b live-gate P0 1b — see below), publish-nothing
participant, decodes each subscribed audio track's
Opus RTP through libopus, gates it through an energy VAD, streams
voice-active audio to a pinned upstream **FunASR** runtime container over
WebSocket, and publishes `{t:'cc', sid, p, text, final}` caption frames back
on the room's data channel — the ONLY producer of the `cc:` envelope B3a
(`mailserver/internal/meet/AGENTS.md`'s Breakouts section, "honesty
disclosure") already ships a dormant client-side rail for. Driven entirely
by the gateway (`mailserver/internal/meet`'s Task 14 `CaptionsController`
— `mailserver/internal/meet/AGENTS.md`'s "Captions (B3b)" section) over a
loopback-only control HTTP API — this
process holds no DB/S3 credential, mints no LiveKit token of its own, and
carries no secret beyond the per-session token the gateway hands it (spec
D4, D3 zero-Python amendment: a Go binary on our rails talking to a pinned
upstream container, no pip/PyTorch tree in the product).

Plan: `retired-docs:superpowers/plans/archive/2026-07-15-meet-B3-qol.md` Task 12 (this
module) + Global Constraints (the three spike laws extended to captions).
Spec: `retired-docs:superpowers/specs/2026-07-15-meet-B3-qol-design.md` §2/D3/F10/
F17.

## Containment (binding — eng E1/delta 5/delta 9)

`asrbot/` is a **FIFTH top-level Go module**, deliberately **NOT** in the
root `go.work` (`use`s exactly `authserver`/`mailctl`/`mailserver`/`shared`
and must stay that way — a `git diff --exit-code go.work` check is part of
this task's own verify gate). Adding it would make every root
`go build`/`go test`/`go vet` acquire a hard cgo/libopus dependency,
defeating the whole point of the split: cgo touches exactly ONE file in
this module, `internal/opus/decoder.go` — no other package here, and
nothing outside `asrbot/`, links against libopus.

Every build/test/lint invocation against this module runs with
**`GOWORK=off`** (the parent `go.work` would otherwise put these commands
in workspace mode, which refuses a non-member module: "not in a module
listed in go.work") **and `-tags nolibopusfile`**. The tag is a deviation
from the plan's literal `pkg-config --exists opus` guard command worth
naming explicitly: `gopkg.in/hraban/opus.v2` links against **two** native
libraries — `libopus` (its `Decoder`/`Encoder`, which this module uses) and
`libopusfile` (its `Stream` whole-file-reader API, which this module does
NOT use — RTP frames arrive live off the wire, never as an `.opus` file on
disk). Without the tag, `go build` fails needing `opusfile.pc` even though
nothing in this codebase calls `Stream`. The upstream package ships its own
`// +build !nolibopusfile` constraint on `stream.go`/`stream_errors.go`
specifically for this — building with `-tags nolibopusfile` excludes those
two files, and the guard scripts actually check for
(`pkg-config --exists opus`, no `opusfile`) becomes literally sufficient
again, no extra library needed on a build box. This tag is threaded through
every one of `scripts/build.sh`/`test.sh`/`lint.sh`'s asrbot legs (lint via
`golangci-lint run --build-tags nolibopusfile`) — see those scripts'
inline comments for the guard shape itself.

**No `asrbot/.golangci.yml`.** golangci-lint's upward config search from
`asrbot/`'s directory finds and reuses the repo root `.golangci.yml`
(`errcheck` only — much lighter than `mailserver/.golangci.yml`'s override,
which stays mailserver-local and untouched by this module).

## Env contract

| Var | Default | Meaning |
|---|---|---|
| `ASR_LISTEN` | `127.0.0.1:7890` | Control HTTP bind address — **refused at startup if not loopback** (`bot.ValidateLoopback`; the control API requires the `ASR_TOKEN` bearer secret below, D4, but a non-loopback bind would still let any host-network peer reach it and brute-force / relay that secret). |
| `ASR_TOKEN` | *(required)* | The control-API bearer secret (B3 Task 18 pipeline-review finding 1) — **refused at startup if empty** (`bot.ValidateToken`). Every `/start`/`/stop`/`/status` request must carry `Authorization: Bearer <ASR_TOKEN>`, `crypto/subtle`-compared; `/healthz` stays open (empty-body only, no room data). Law-3'd: `install.sh` generates it once and writes the SAME value into both `asrbot.env` and `config.env`'s `ASR_TOKEN`. |
| `LIVEKIT_URL` | *(required)* | The same SFU sidecar URL the gateway uses. |
| `FUNASR_URL` | `ws://127.0.0.1:10096` | The pinned upstream FunASR runtime's WS endpoint. |
| `ASR_MAX_MEETINGS` | `2` | The CPU-floor cap (spec §2) — at most this many rooms run a captions session concurrently in one bot process; the (N+1)th `/start` is refused `409 busy` until one frees. |
| `ASR_MAX_ACTIVE_TRACKS` | `4` | F10 — within an already-started room, at most this many simultaneously voice-active tracks hold a decoder+FunASR slot; past the cap the lowest-energy active track yields (`internal/vad.Manager`). |

## Control HTTP (loopback-only, bearer-authenticated)

Mirrors `mailserver/internal/meet/AGENTS.md`'s push/error-table convention:
a small, fixed contract, not a growing REST surface.

**B3 Task 18 pipeline-review finding 1**: `/start`, `/stop`, and `/status`
now require `Authorization: Bearer <ASR_TOKEN>` (`Server.requireAuth`,
`crypto/subtle.ConstantTimeCompare`) — before this fix, loopback TCP alone
was treated as sufficient identity, but loopback TCP carries no peer
identity: any local uid could POST `/start` directly and flip the
on-screen captions consent chip on behind the reducer's back (the fact
lives in `meeting_captions_set`, not here — this bot has no idea whether a
`/start` call came from the gateway's `CaptionsController` or a rogue local
process), POST `/stop` to DoS a live session, or GET `/status` to enumerate
which rooms are currently captioned. `/healthz` stays unauthenticated
(empty-body liveness only, no room data) so `install.sh`'s own boot probe
has no chicken-and-egg dependency on the secret it's trying to verify came
up. **Gateway-side wiring landed** (pipeline-review follow-up closed,
`mailserver/internal/meet/**`): `captions.go`'s `httpCaptionsClient` routes
every `/start`/`/stop`/`/status` request through one `newRequest` builder
that sets `req.Header.Set("Authorization", "Bearer "+token)` whenever a
non-empty token is configured; `NewCaptionsClient(baseURL, token string)`
threads `config.go`'s `Config.ASRToken` (env `ASR_TOKEN`) from
`cmd/mailserverd/main.go`. The `asr` `RegisterProbe` health check gets the
header for free — it calls the same `Status()` method every other caller
does. Proven hermetically (`captions_client_test.go`, no DB/LiveKit/asrbot
involved): a fake control-API server asserts the header on all three
routes, plus the empty-token no-header posture (a box with `ASR_URL` set
but `ASR_TOKEN` unset is a deploy misconfiguration, not a Go panic).

| Route | Body → Response |
|---|---|
| `POST /start` | `{"room":"<uuid>","token":"<jwt>"}` → `200 {}`, or `409 {"error":"busy"}` at the `ASR_MAX_MEETINGS` cap (the gateway's Task 14 `CaptionsController` projects this as a `captionsBusy` 503 to the client — this bot never speaks HTTP problem-detail itself). Idempotent: starting an already-held room succeeds without consuming a second slot. Fire-and-forget past the slot claim — a LiveKit connect failure surfaces only as a log line + the slot freeing itself (F17), never a delayed HTTP error after the 200 already went out. |
| `POST /stop` | `{"room":"<uuid>"}` → `200 {}`, idempotent (stopping a room that was never started, or already ended on its own, is a no-op). |
| `GET /status` | → `200 {"rooms":["<uuid>",…]}` (sorted). |
| `GET /healthz` | → `200` (empty body) — the gateway's own `asr` health probe target (a `RegisterProbe` closure, the `sfu`/`egress` genre — Task 14). |

`bot.RoomRegistry` is the sole room lifecycle authority between the control
surface and LiveKit: it atomically owns admission/capacity, one per-room
identity and cancel context, compare-release, and the sorted status view.
`bot.RoomRunner` is the narrow adapter port implemented by `session.go`'s
`*Sessions`; HTTP and registry tests use fake runners with no
LiveKit/FunASR/libopus dependency.

## Packages

- `cmd/asrbotd/main.go` — env parsing, the loopback-bind refusal at
  startup, wiring `bot.RoomRegistry`/`bot.Sessions`/`bot.Server` together, graceful
  shutdown on SIGINT/SIGTERM.
- `internal/bot/registry.go` — `RoomRegistry`: the single owner of the
  `ASR_MAX_MEETINGS` cap and room session identities. Reservation precedes
  runner launch; Stop cancels but retains capacity through runner drain, and
  runner exit compare-releases only that identity. This makes status and
  capacity truthful across concurrent start, stop-before-run, connection
  failure, natural disconnect and stale cleanup (`registry_test.go`, `-race`).
- `internal/bot/server.go` — the control HTTP surface + `ValidateLoopback`.
  Pure Go (routes only through `RoomRegistry`; fake runner in every test).
- `internal/bot/session.go` — the real `RoomRunner`
  (`lksdk.ConnectToRoomWithToken`, `OnTrackSubscribed`/`OnDisconnected`, the
  per-track `trackWorker` pipeline: continuous Opus decode → `vad.Manager`
  → a lazily-opened `funasr.Client` stream → `PublishDataPacket` with
  `UserData`, **never** the deprecated `PublishData`, eng E2). Audio-track
  intake is gated by a session-level pre-admission bound (`trackAdmission`,
  `trackAdmissionBound` = 8× the F10 slot cap): a track is admitted BEFORE
  any decoder/goroutine allocation and its slot frees when the worker exits,
  so a room cannot force an unbounded decode fanout (ER5
  asr-pre-admission-track-fanout). `trackWorker`
  remains the sole pipeline owner but depends on four narrow local seams
  (`rtpReader`, `pcmDecoder`, `trackArbiter`, `recognizer`) plus the existing
  publish function; `TestTrackWorkerOwnsDecodeVADStreamDrainAndPublish` proves
  decode-error recovery, VAD acquire/release, PCM forwarding, degraded-result
  filtering, final drain, publication and cleanup hermetically.
  `TestTrackWorkerSilenceCancellationRestartAndNonTerminalResults` adds silence,
  pre-cancel, empty/degraded result, speech restart and non-terminal publish
  failure. On release the worker closes FunASR and waits up to the named
  `resultDrainTimeout` for the result channel before another speech stream can
  open, so an old utterance's final cannot normally publish behind the next
  utterance; timeout degrades with a warning rather than hanging the track. The concrete
  LiveKit callback adapts `TrackRemote`, libopus, `vad.Manager` and
  `funasr.Client` directly—there is no parallel pipeline module. Real SFU
  connection behavior still belongs to the plan's §1.3 live round-trip (the
  honesty-ledger posture every other Meet package in this program follows, e.g.
  `mailserver/internal/meet/AGENTS.md`'s own live-tier sections). Two B3
  Task 18 retro fixes, both hermetically tested despite the no-real-SFU
  posture above. The prior `Slots.rooms` + `Sessions.live` dual authority is
  deleted: it allowed Stop to land between slot reservation and runner
  registration, after which the delayed runner became invisible to status and
  capacity. `RoomRegistry` now performs the atomic check-and-insert, and the
  LiveKit adapter receives only the admitted identity's context. A Stop that
  wins before runner start cancels that identity before the adapter is called;
  connection failure and natural disconnect return through the same
  compare-release path, while stale release cannot touch a replacement.
  `TestStopBetweenAdmissionAndRunnerStartDoesNotStrandSession` is the retained
  red/green race characterization.
  - **The `hb` keepalive frame (design finding #3, the bot-keepalive root
    fix).** Energy-VAD gates every REAL `cc` frame on speech, so a quiet
    room produces zero frames and a client-side degrade timer cannot tell
    "bot dead" from "nobody spoke for 15s" from silence alone.
    `publishHeartbeats` (session.go) publishes `hbFramePayload` — EXACTLY
    `{"t":"cc","hb":true}`, no `sid`/`text` — every `hbInterval` (5s) while
    a room session is live, over the SAME `PublishDataPacket` path real `cc`
    frames use. Started once the LiveKit connection succeeds (`run`), tied
    to a context DERIVED from the session's own ctx (`hbCtx, hbCancel :=
    context.WithCancel(ctx)`) so it stops on BOTH an explicit `Stop`
    (`ctx.Done()`) and a natural disconnect (`hbCancel()` called
    right after the `select` on `ctx.Done()`/`disconnected` — `ctx` itself
    is NOT cancelled on that path, only the `disconnected` channel closes,
    so a bare `ctx`-only heartbeat goroutine would otherwise leak past a
    natural disconnect). Wave B's webmail store resets the degrade timer on
    ANY attested `cc` frame including `hb`, and must not render it as a
    transcript line — this bot only produces the wire shape; the consumer
    contract lives in `mailserver/webmail/AGENTS.md` once wave B lands.
- `internal/vad/` — `Detector` (per-track attack/hangover energy state
  machine) + `Manager` (the F10 cap: at most `ASR_MAX_ACTIVE_TRACKS` tracks
  hold a slot; the lowest-energy active track yields when over cap). Pure
  Go, hermetically tested, including the multi-track cap tie-break.
  `// ponytail: energy VAD — upgrade to a real VAD model if zh WER on real
  audio demands it (the §1.3 live proof is where that verdict lands).`
- `internal/opus/decoder.go` — the ONE cgo file. Wraps
  `gopkg.in/hraban/opus.v2`'s `Decoder`, fixed at `(16000, 1)` — **no
  resampler** (delta 9): libopus's own internal resampling bridges the gap
  between the 48kHz/stereo Opus capability LiveKit clients negotiate on the
  wire and the 16kHz mono PCM FunASR's streaming mode consumes, so no
  separate resampling stage exists anywhere in this codebase. Not unit
  tested (cgo, no hermetic seam meaningful for one wrapper call) — proven
  by the build gate + the live round-trip.
- `internal/funasr/client.go` — the FunASR WS protocol seam:
  `Stream(ctx, sampleRate, wavName) (send, results, close)`. One initial
  JSON config frame (`2pass` streaming mode), then binary PCM16LE frames,
  results as JSON on the same connection; a dropped connection emits a
  `Result{Degraded:true}` and reconnects with a fixed backoff — **never**
  crashes the session or returns an error to the caller. **B3 live-gate fix
  (2026-07-16, found against the REAL pinned image):** the server emits its
  `2pass-offline` FINAL result — the full punctuated sentence,
  `is_final:true` — only ~400ms AFTER the client's `{"is_speaking":false}`
  closing frame, then closes the connection itself; the pre-gate client
  returned from `runSession` immediately after writing the closing frame
  and tore the WS down, discarding the final on EVERY VAD release, so no
  `final:true` cc frame was ever published (starving webmail's finals-only
  D7 live region). `closeFn` now drains until the server closes (bounded by
  `finalDrainGrace`, 5s; the read-error path is the normal exit), and
  `readResults` keeps forwarding past a requested close — the results
  consumer (`trackWorker.readResults`) always drains until channel close.
  `TestStreamCloseDrainsFinal` pins it hermetically; the live round-trip
  proved it end-to-end (one punctuated final per utterance). The frame
  shapes are now live-proven against
  `funasr-runtime-sdk-online-cpu-0.1.13@sha256:2a54c20f…` — re-proven at
  every pin bump, honesty-ledger item 1. `fake_test.go`/`client_test.go`
  prove the full contract (config → PCM → interim/final results;
  reconnect-on-drop; the post-close final drain) against an in-process fake
  WS server whose close-after-final behavior mirrors the real server's
  empirically pinned shape.

## Honesty ledger (Task 12, this module's own gate)

Task 12's own gate was the **hermetic tier only** — Step 1/2's TDD loop
(slots, VAD, the funasr seam, the control HTTP contract), `go build`/
`go test`/`golangci-lint run` all green under `GOWORK=off -tags
nolibopusfile`, and `git diff --exit-code go.work` proving the non-edit. It
did **not** prove: the bot actually joining a real LiveKit room and decoding
real Opus RTP (`session.go`'s glue was explicitly out of scope for Task 12);
a real FunASR container round-trip (the protocol shapes are documented and
seam-tested against a fake, not the real pinned image); or the gateway side
(`CaptionsController`, the `asr` health probe, `meeting_captions_set`).
**Since this task, Tasks 13–18 have all landed** (the reducer layer, the
gateway `CaptionsController` + routes + worker reconcile, the webmail UI,
the deploy-side systemd units, and the B3 Task 18 integration gate — see
`mailserver/internal/meet/AGENTS.md`'s "Captions (B3b)" section and its own
"B3 Task 18" honesty ledger). **The §1.3 live FunASR round-trip RAN 2026-07-16** (linux-ci-host, 6-core
CPU-mode, real pinned image + real pinned livekit-server v1.13.3 + the
real cgo/libopus linux build of this module): `session.go`'s live glue is
PROVEN — room join on the exact reducer-shaped bot grant, Opus decode of a
real published Mandarin track, VAD gating, FunASR 2pass streaming, and
`{t:'cc',…}` partials + punctuated finals + `hb` keepalives captured off
the room's data channel by an independent subscriber (the known-transcript
sample came back verbatim); `/start`→`/stop`→`/status` exercised over the
bearer contract (unauthenticated → 401); asrbot logs carried zero
transcript text and zero token material; the port math
(`-p 127.0.0.1:10096:10095`, `--port 10095`) confirmed against the real
container. The run found + fixed one real bug in this module (the funasr
client's discarded post-close final — see `internal/funasr/client.go`
above) and one in the deploy tier (the funasr unit's ExecStart ran the
upstream wrapper, which backgrounds the server and exits, killing the
container at every boot — `mailserver/deploy/setjoin-funasr.service.template`,
now direct-`exec` with all five models named + pinned). **(1) The webmail
F8 attestation P0 — FIXED 2026-07-16 (TODOS.md "Meet B3" item 1b):**
livekit-server v1.13.3 forwards a HIDDEN participant's data packets with an
EMPTY sender identity (A/B-proven live), so the `hidden:true` bot grant
meant `room.svelte.ts` dropped every cc frame and captions rendered
NOWHERE. Reversed the ratified grant posture: `meeting_captions_set`
(`meeting_control.sql`) now composes `hidden:false`; the bot joins the room
like any other participant, so its data-packet identity actually arrives
and F8 attestation works; webmail filters `cc:`-prefixed identities out of
the roster/gallery/participant-count client-side instead
(`room.svelte.ts`'s `#syncParticipants`) so no user ever sees a bot row.
`cc:{meetingId}` stays the sole reducer/`MintToken`-minted identity —
attestation security is unaffected. **(2) The D4 journald grep RAN + GREEN
under a REAL systemd deploy 2026-07-16** (fresh LXD VM, root, both ASR units
`active`): captions started in-browser, the known Mandarin sample published
as fake audio, `cc` frames rendered — then `journalctl` grepped across the
round-trip. The FIRST pass FOUND that `StandardOutput=null` alone still
leaked: funasr's glog INFO writes recognition results to STDERR, which the
unit journal-routes. Fixed same day (`GLOG_minloglevel=2` in
`setjoin-funasr.service`); POST-FIX grep = ZERO transcript / ZERO bearer /
ZERO JWT on BOTH units. `asrbot`'s own journal was clean on the first pass
(no transcript, no `ASR_TOKEN`, confirming the D4 in-process containment).
**Still owed before `feature.meet_captions` flips ON anywhere:** (3) GPU
sizing (CUDA variant, no GPU on the gate box) + the multi-meeting realtime
factor behind `ASR_MAX_MEETINGS` (one stream ≈ realtime on 6 CPU cores).

**B3 Task 18 pipeline review (this codebase's own security/deploy audit,
2026-07-16) also landed two Go-side fixes in this module, both hermetically
tested (`server_test.go`/`session_test.go`), neither requiring a live
round-trip to verify:** finding 1, the control-API bearer-token requirement
(`ValidateToken`/`requireAuth`, "Control HTTP" section above — the
gateway-side header-send landed in the same pipeline-review pass,
`mailserver/internal/meet/captions.go`'s `newRequest`, proven by
`captions_client_test.go`); finding 5,
`session.go`'s LiveKit connect-failure log line no longer logs the raw
`error.Error()` (which can embed the full dial URL, token query param
included) — `redactToken` scrubs any `eyJ...`-prefixed (base64url JWT)
run before the line reaches `slog`. **Confirmation-review fix:** the
original pattern (`eyJ[A-Za-z0-9_-]+`) stopped at the first `.` — a real JWT
is three dot-separated segments (header.payload.signature), and only the
header and payload start `eyJ` (base64 of a JSON `{`), so the signature
segment survived every redaction untouched. The pattern now trails
`(\.[A-Za-z0-9_-]+)*` to fold all three dot-joined segments into one match;
`session_test.go`'s `TestRedactTokenScrubsJWT` asserts the exact
post-redaction string, not just "changed" — no fragment of any segment,
including the signature, survives. The sibling `funasr/client.go`
malformed-frame log (`readResults`'s decode-failure `Warn`) was audited too
and does NOT need the same fix: it logs the `json.Unmarshal` error value,
never the raw `data` bytes the recognition result (spoken text) arrived in.

## Ownership

This doc owns every file under `asrbot/`. It does NOT own the reducers
(`meeting_control.sql`'s `meeting_captions_set`, Task 13 —
`mailserver/sql/AGENTS.md`), the gateway's `CaptionsController`/`asr` health
probe (Task 14 — `mailserver/internal/meet/AGENTS.md`'s "Captions (B3b)"
section), the webmail captions rail (`$lib/meet/room.svelte.ts`'s `cc`
envelope arm, dormant in B3a, wired to a live producer in Task 15 —
`mailserver/webmail/AGENTS.md`'s Meet section), or the deploy wiring
(Task 16, shipped — `mailserver/AGENTS.md`'s deploy
bullet, "units six and seven"): `mailserver/deploy/setjoin-asr-bot.service.template`
+ `setjoin-funasr.service.template` + `asrbot.env.template`, the
`render_asrbot_unit`/`render_funasr_unit`/`render_asrbot_env`/
`install_funasr_models` functions in `mailserver/deploy/scripts/lib-livekit.sh`
(incl. the pinned `FUNASR_IMAGE` digest and the ONE model this task's own
honesty ledger names — the four companion models `run_server_2pass.sh`
itself defaults to are NOT pinned there yet), and `install.sh`'s optional
`MEET_CAPTIONS_ENABLED` leg — deliberately placed under `mailserver/deploy/`
alongside every other Meet sidecar unit, not under `asrbot/`, matching the
`setjoin-sfu.service`/`setjoin-egress.service.template` precedent (deploy
wiring for a sidecar lives with the OTHER sidecars, not inside the sidecar's
own module).
