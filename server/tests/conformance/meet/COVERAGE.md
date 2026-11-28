# F13 golden-routes branch coverage (#285)

Go's meet handlers are not instrumented: the shared frozen `mailserverd` recorder
is built with `-coverpkg` for chat and `cmd/mailserverd` only, and rebuilding a
cover binary on the shared host was out of budget. Adequacy is therefore argued
branch by branch from `internal/meet/meetings.go` and `handler.go` against the
recordings; add `internal/meet` to `-coverpkg` when slice 2 needs a fresh build.

| Go branch | Recording |
| --- | --- |
| `feature.meet` off, 404 without Content-Language | `*_disabled` (list, create) |
| LiveKit not configured, 503 service-unavailable | `list_unconfigured` |
| unauthenticated / guest / entitlement denial | forwarded to Go (not a Rust answer): `executable_forwards_entitlement_denial_to_go`; token failures by shared authz |
| invalid id (`ParseIDPath`) | `get_invalid`, `lock_invalid`, `settings_invalid`, `role_invalid` |
| body decode failure, trailing value, wrong type, bad time | `create_invalid`, `create_go_json`, `create_wrong_type`, `create_bad_time`, `*_bad_body`, `create_language` |
| create success, case-folded keys, repeat | `create_success`, `create_folded`, `create_repeat` |
| `BZ188` empty title / end before start / unowned calendar event (422) | `create_empty_title`, `create_bad_window`, `create_unowned_event` |
| `BZ186` foreign chat channel / non-host control (403) | `create_foreign`, `lock_foreign`, `settings_foreign`, `role_foreign`, `lock_missing` |
| `BZ188` invalid role (422) | `role_bad_role` |
| `BZ185` unknown meeting / slug (404) | `get_missing`, `by_slug_invalid` |
| list own, other member's list excludes mine | `list_success`, `list_foreign` |
| void reducer success 204, repeat | `lock_success`, `lock_repeat`, `settings_success`, `settings_repeat`, `role_success`, `role_repeat` |
| role on an ended meeting (Go does not check) | `role_ended` |
| lost COMMIT acknowledgement or request | `lock_commit_before`, `lock_commit_after` |

Unreached here: `BZ187`/`BZ189`/`BZ190` and the LiveKit, Egress and ASR calls belong
to `join`, `kick`, `end`, lobby, recording and captions (slices 2-4). Their slug rows
are in the shared `failure` mapping but carry no recording yet.
