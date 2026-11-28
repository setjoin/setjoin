# F07 offline branch map (#312)

Frozen Go source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`; the
admin/user handlers and dispatcher are unchanged in this worktree. Goldens are
recorded through the real front door, then replayed with no Go upstream. The
catalog supplies an executable selector for each qualified observation and a
status mutant for each of the 15 routes. This is a branch map, not a claim of
measured admin-package Go coverage: the reused covered binary instruments
main/chat. The integration lane owns instrumented Rust coverage; local
`--coverage`/adequacy execution modes were excluded by the task instruction.

| Go branch / seam | Cases (gateway `offline`) |
|---|---|
| Live console permission denial, preserved denial audit | Every admin route `q_*_denied` |
| Scoped admin / target boundary | Every route `q_*_foreign`; preview403, self ack200/no other-user effect; offline admin scope gap mirrored |
| List/detail/toggle/pending/size reads, infrastructure errors | `fault_{policies,policy,enabled,pending,size}_read_error` |
| JSONB policy detail NULL / invalid / signed id | `q_policy_{missing,invalid,plus_id}` |
| Policy decoder syntax, closed fields, typed values, EOF/limit, scalar nulls | `q_create_{invalid,unknown_field,typed,fraction,trailing,too_large,null,duplicate_null}` |
| Legacy policy set and complete QoS set_v2, partial QoS refusal | `q_{create,update}_qos`, `q_create_partial_qos`, legacy success |
| Scope/value validation (Go BZ099 ->404), DB int32 overflow | `q_create_{bad_scope,no_name,negative_days,int32_overflow}` |
| Policy delete last-global / missing / repeated | `q_delete_{last_global,missing,repeat}` |
| Policy write/audit/notify failure atomicity | `fault_create_{write,audit,notify}_error` |
| Toggle first-value decoder, unknown fields, null/default/duplicate fields | `q_toggle_{invalid,typed,trailing,unknown_field,null,empty_object,case_keys,duplicate_null,unbounded}` |
| Toggle data/audit/notify transaction and Go aborted-notify behavior | `fault_toggle_{audit,notify}_error` |
| Preview parse, strict trailing EOF, target permission/lookup, reducer failure | `q_preview_{invalid,typed,bad_target,bad_device,trailing,unknown_field,foreign,missing}`, `fault_preview_read_error` |
| Device actions: invalid target, missing, illegal/repeated FSM, RLS filter | `q_{approve,deny,revoke,wipe}_{invalid,repeat,rls}`, approved/pending/missing variants |
| Device action audit/notify rollback | `fault_approve_{audit,notify}_error` |
| Ack canonical id, authenticated owner, BZ101 hidden/idempotent200 | `q_ack_{success,foreign,spoofed_owner,missing,negative_id,rls,repeat}` |
| Ack required/type failures, first value/trailing, audit/notify rollback | `q_ack_{invalid,zero_id,typed,trailing}`, `fault_ack_{audit,notify}_error` |
| Body bytes: UTF-8, attachments excluded, multiple own mailboxes, foreign exclusion, age windows, deleted/empty | `q_size_{success,foreign,windows,deleted,empty,invalid,head}` |
| Go >2KiB flushing and HEAD without synthetic length | `q_policies_{large,large_head}` |
| Unknown COMMIT before/after actual commit, authenticated receipt and exact effects | `commit_{create,toggle,wipe,ack}_{before,after}` |
| Real DB mutations of audit, notify, owner predicate and extra policy state | `no_audit_mutant`, `no_notify_mutant`, `no_tenant_filter_mutant`, `double_bump_mutant` |

Nil Go pool/caller guards are constructor-only: real mailserver startup requires
the database and constructs these handlers with pools. The recording process
cannot reach a mounted handler with a nil pool. Decoder network read failures
share the invalid-JSON response; no streaming body abstraction is mocked.
There are no accepted behavior divergences.

MDM worker: actual Go process ON/OFF with published valid and malformed
`device_policy` notifications. The dispatcher grammar refuses this channel, so
parse/log consumption branches are unreachable at this frozen revision. The
recorded startup warning and unchanged rows/audit/outbound state are replayed
through the Rust executable. Rust cancellation is checked at process shutdown.

`q_toggle_unbounded` records Go accepting a 17MiB JSON request. Its deterministic
input is represented by byte length and SHA-256 so the golden stays small;
response/effect comparisons remain exact. Toggle/ack have no handler body cap
in frozen Go; only policy/preview requests apply the 16KiB bound.
