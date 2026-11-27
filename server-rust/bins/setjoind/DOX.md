# setjoind — unified Setjoin server binary (#543)

## Purpose

`setjoind` is the unified Rust server binary composing `http`, `auth`, `protocols`, and `workers` in one process (`--subsystems=all` by default) or any chosen subset (`--subsystems=http,protocols,workers`, `--subsystems=auth`, `--subsystems=workers`, etc.).

## Contract

- **Subsystem selection:** `--subsystems=all|http,auth,protocols,workers` (also `--subsystems <val>`), fallback `SETJOIND_SUBSYSTEMS`, fallback `argv[0]` basename (`setjoin-server`/`setjoin-gateway` → `http,protocols,workers`; `setjoin-auth` → `auth`; `setjoind` → `all`). Duplicate/conflicting flags or unknown names fail closed with exit code `2`.
- **`AuthAuthority` seam:**
  - When `auth` is enabled, `setjoind` constructs `InProcessAuthAuthority` (gated on the `in-process-authority` Cargo feature, allowlisted exclusively to `setjoin-auth` and `setjoind`) backed by `AuthServer` with shared `DB_DSN`/`DB_WORKER_DSN` pools and the shared `ThreatGate`. Public HTTP requests to `/auth/*` and `/.well-known/*` dispatch directly in-process with zero loopback hop, while internal-only auth routes (`/auth/scim/disable`, auth `/admin/reload`) are blocked on the public listener.
  - When `auth` is disabled (`--subsystems=http,protocols,workers`), `setjoind` never loads `JWT_SECRET` or `SM2_PRIVATE_KEY_FILE`, authenticating via `RemoteAuthAuthority` (`Jwks` + optional `SM2_PUBLIC_KEY_FILE` / `DRIVE_NATIVE_TOKEN_SECRET`).
  - In unified mode (`http` + `auth`), `auth` does not bind a separate standalone TCP listener (and skips standalone `LISTEN_ADDR` non-loopback TLS checks because `http` / reverse-proxy edge TLS owns public TLS). In `--subsystems=auth`, `setjoind` binds `Slot::Auth` or `LISTEN_ADDR` identically to `setjoin-auth`.
- **Single `ListenHub`:** One `DB_DIRECT_DSN` PostgreSQL `LISTEN` connection multiplexes notifications across all active subsystems, driven by the root `CancellationToken`.
- **Strict pre-bind schema verification:** `setjoin_boot::run_for_subsystems(subsystems, true)` refuses any schema version mismatch (`actual != expected`) before binding any listener or accepting connections on inherited systemd FDs.
- **Socket activation & `sd_notify`:** Inherited `LISTEN_FDS` are atomically wrapped in `OwnedFd` with `FD_CLOEXEC`, validated against active subsystems (`Slot::Auth`, `http`, `https`, `imap`, `imaps`, `smtp`, `smtps`, `submission`, `federation`; retired `acme` socket is refused fail-closed per `#560`), and closed on any refusal. `NOTIFY_SOCKET` is scrubbed at startup; `READY=1` is sent only after all active listeners bind, and `STOPPING=1` is sent when the unified 30-second concurrent graceful drain begins.
- **Retired inventory override:** `GATEWAY_ROUTE_INVENTORY` is rejected fail-closed in `setjoind`.
- **Release N compiled ELF compatibility shims (#544):** `setjoin-server-shim` (packaged as `setjoin-server`, fixed `http,protocols,workers`) and `setjoin-auth-shim` (packaged as `setjoin-auth`, fixed `auth`) are `std`-only compiled ELF binaries (plus `libc` on Linux for `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` + `fstat` + `execveat(AT_EMPTY_PATH)` / `fexecve`). They answer `--version`/`-V` as `setjoin-server <ver>` / `setjoin-auth <ver>` for `smoke-rust-floor.sh`, fail closed (exit `2`) on conflicting `--subsystems` or `SETJOIND_SUBSYSTEMS`, normalize `SETJOIND_SUBSYSTEMS`, verify single-link regular non-writable sibling `setjoind` via `current_exe()`, and preserve PID plus inherited FDs `3..11` with zero leaked non-`CLOEXEC` FDs.

## Verification

- `cargo test --manifest-path server-rust/Cargo.toml -p setjoind -- --test-threads=1`
- `cargo test --manifest-path server-rust/Cargo.toml -p setjoind --test shims -- --test-threads=1`
- `python3 scripts/check-rust-family-isolation.py`
