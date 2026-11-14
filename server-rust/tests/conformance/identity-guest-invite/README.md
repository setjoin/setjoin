# Guest invitation acceptance oracle (#342)

`setjoin-auth --test guest_invite_oracle` drives the real front door for
`GET`/`POST /auth/guest-invite/accept`; the auth listener and the gateway alias
share these replays. Gateway-layer cases (cross-site Origin, guest bearer,
spoofed X-Forwarded-For) pass through the Rust gateway in both modes.

Record with the dispatch-only `gofree-record.yml` (package `setjoin-auth`, test
`guest_invite_oracle`, `case_filter` = one test name; record each
`*_rate_limited` and `*_fault_*` case in its own dispatch). Recording needs
`GOFREE_RECORD_UPSTREAM` and `GOFREE_GO_SOURCE` (the checked-out HEAD, stamped
into every golden's `go_source`), refuses transport, threat-leak and
enumeration-polluted captures, and never overwrites. Each case uses its own
loopback source IP. Replay runs with Go unset, REQUIRE_DB=1, one thread, and
asserts zero Go hops.

Effects: guest satellite, user (password verified, then summarised), invite
terminal fields, `guest.invite_accept` audit, `auth_attempts` (Go's postAuth
tail) and `session_revoke` notifications, for the actor and an untouched
foreign guest. Fixtures are uniquely named per run (audit rows are
append-only); emails, tokens and expiry are masked after validation.

Non-catalog tests pin the terminal-delay floor and ceiling, lock release before
the delay, the GET/POST stamp race, the executor deadline, login-shared threat
toggles, the #346 residual shapes (CAPTCHA header, username keys) and upgrade
posture (reducers absent, worker without BYPASSRLS).
