# CalDAV HTTP oracle (#426)

`setjoin-gateway --test caldav` records the real frozen Go handler through the
front door and replays its immutable observations against native Rust with no
Go upstream. Each case owns two accounts with divergent user/mailbox ids and
observes HTTP bytes, both accounts' rows, audit and NOTIFY. Run with the assigned
disposable schema, `TEST_DB_DSN`, `DB_DSN`, `DB_DIRECT_DSN`, `DB_APP_DSN`,
`REQUIRE_DB=1` and `--test-threads=1`.

Recording sets `GOFREE_RECORD_GO_BINARY` to a covered `mailserverd` and
`GOFREE_GO_SOURCE` to its source commit. Preserve `/root/go/pkg/mod` when using a
copied Go build cache. On the shared host, the Microsoft Graph models dependency
needs `-gcflags=github.com/microsoftgraph/msgraph-sdk-go/models=-N -l`; it is not
exercised by CalDAV. Instrument `setjoin.com/mailserver/internal/caldav`,
`setjoin.com/mailserver/internal/webdav` and `setjoin.com/mailserver/cmd/mailserverd`.
`GOFREE_RESOURCE_PREFIX=gofree-cal4` namespaces every recording container.

`record-client.py` captures actual python-caldav 3.7.0 discovery and configured
calendar traffic. The `real_client_sessions` test replays both complete sessions, including
request bodies, conditional headers, responses, committed effects and NOTIFY,
without Python or a Go upstream. Recording alone needs the pinned Python venv
at `test-results/gofree-cal4/python` (python-caldav 3.7.0).

`mutants_*` proves the HTTP/effect oracle rejects missing audit, missing
notification, a removed tenant predicate, and a double calendar-state bump.
The first two replace/restore canonical function definitions in the assigned
disposable DB; the state mutant installs/removes a task-named trigger. The
read mutant changes the real PostgreSQL Parse frame, counts its hits, and must
reach the recorded foreign resource. No production mutation hook is installed.

The bundled `/caldav/` entry is ON. `executable_client_sessions` repeats the
client transcript against production startup with shared admission and no Go
mail upstream. Replay requires zero total Go proxies. `status_mutant_*` plants
one changed status per catalog command. Entitlement floors exercise denial before
target/body processing; success here means successful enforcement (403).
PUT/DELETE `*-row-effects.json` files are exact extracts of `observation.effects`
from the immutable HTTP recordings and are checked during normal replay. Go
CalDAV does not enqueue iMIP mail, so the observed queue stays empty; scheduling
POST and MKCALENDAR retain their recorded 405/403 parity limitations.
