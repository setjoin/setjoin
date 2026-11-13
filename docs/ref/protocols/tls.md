## TLS Protocol Requirements
> **RFC 8446** (TLS 1.3), **RFC 9325** (TLS Recommendations), **RFC 8996** (TLS 1.0/1.1 Deprecation)

### MANDATORY — Minimum Version
- All outbound TLS client configs MUST set `MinVersion: tls.VersionTLS12` (RFC 8996 §4-5)
- File: `outbound.go` line ~231, `ad/client.go` line ~53 (AD LDAPS client)
- Inbound/implicit TLS already sets MinVersion (inbound.go, imap.go)

### MANDATORY — Certificate Loading
- TLS certificates MUST be loaded via `tls.LoadX509KeyPair(certFile, keyFile)` before creating listener
- Store loaded certs in `tlsConfig.Certificates`
- SMTP 465 and IMAP 993 Start() methods MUST include cert loading code

### MANDATORY — STARTTLS
- Submission port 587 MUST advertise and handle STARTTLS before AUTH (RFC 9325 §3.2)
- Inbound port 25 SHOULD advertise STARTTLS for opportunistic encryption (RFC 3207 §4)
- Submission MUST reject AUTH if TLS not negotiated (return 530)
- STARTTLS command handler MUST use `tls.Server()` with loaded certs

### ✅ DONE — Cipher Suites (RFC 9325 §4.2)
- Explicit ECDHE cipher suites configured on all 8 TLS config sites via `tlsutil.DefaultCipherSuites`
- Covers: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- Sites: main.go HTTP gateway, inbound.go, submission.go, outbound.go, imap.go (2 sites), ldap/server.go, ad/client.go
- Also added `CurvePreferences: X25519, P256` to sites that were missing it (outbound.go, ldap/server.go, ad/client.go)
- Fixed missing `MinVersion: tls.VersionTLS12` on AD LDAPS client (ad/client.go)

### ✅ DONE — Session Tickets (RFC 9325 §3.4)
- `SessionTicketKeyManager` in `internal/tlsutil/` rotates keys every 24h via `SetSessionTicketKeys()`
- Previous key retained for one cycle so tickets issued during rotation remain valid
- Keys persisted to `system_config` table (key `tls_session_ticket_keys`) for survival across restarts
- Default rotation interval 86400s, configurable via `TLS_SESSION_TICKET_KEY_ROTATE_SECS` env var

### DO NOT
- Do NOT create `tls.Config` without `Certificates` set on server side
- Do NOT create outbound client `tls.Config` without `MinVersion`
- Do NOT advertise AUTH before STARTTLS on port 587
- Do NOT skip TLS cert loading validation — hard-fail on `LoadX509KeyPair` error

### Verification
```bash
go build ./...  # verify all TLS configs have MinVersion
go test ./internal/smtp/... -v
```
