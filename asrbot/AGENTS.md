# asrbot — the Meet captions room-bot sidecar (DOX child)

Owns only the frozen Go captions room bot (the parity oracle): the shipped `asrbotd` is Rust, `server-rust/bins/asrbot/DOX.md` (#356). Keep outside go.work; GOWORK=off and nolibopusfile build/test tags, matching lint tags; only internal/opus/decoder.go introduces libopus/cgo. No DB/S3 credentials or token minting. Never log transcripts/tokens. Control binds loopback with nonempty ASR_TOKEN; start/stop/status use constant-time bearer checks; healthz is empty liveness. RoomRegistry owns admission/capacity/identity/cancel/compare-release/status; drain retains capacity and stale cleanup cannot release replacement. Preserve gateway-issued cc identity, sender attestation, bounded final drain, VAD and cancellation. FunASR changes require real round-trip proof. Read containment/env/control/packages and honesty ledger; captions rollout requires retained sizing/multimeeting gates.

## DOX sections

- [Purpose](DOX.md#purpose)
- [Containment (binding — eng E1/delta 5/delta 9)](DOX.md#containment-binding--eng-e1delta-5delta-9)
- [Env contract](DOX.md#env-contract)
- [Control HTTP (loopback-only, bearer-authenticated)](DOX.md#control-http-loopback-only-bearer-authenticated)
- [Packages](DOX.md#packages)
- [Honesty ledger (Task 12, this module's own gate)](DOX.md#honesty-ledger-task-12-this-modules-own-gate)
- [Ownership](DOX.md#ownership)
