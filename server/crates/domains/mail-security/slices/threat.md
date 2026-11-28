## Slice `threat`

- Reads need `requireLogsPerm` (`audit.read`, org-wide only: a domain-scoped admin gets the audited
  403); create and delete need `security.write`. Every table is global; the verified actor is the
  only identity written (`created_by`, audit actor). Problems are `WriteProblem` bodies.
- Views `attempts|lockouts|feed-blocks|rate-counters` answer `{limit,offset,rows,total}` (sorted
  keys) or, for `format=csv`, a download whose cells are Go's `fmt.Sprint` (`<nil>` for NULL,
  `time.Time.String()` in UTC) after formula escaping. `limit` clamps to 500 (default 100), a bad
  value falls back; `sort` is allow-listed with `EqualFold`; `since` binds as an interval and
  filters only `attempts`; an invalid value is Go's 500. `lockouts` reads only the worker-owned
  `lockout_list`/`lockout_count` accessors; its page bounds are int4 (a larger offset is 500).
- `ip-rules` create/delete call `rust_mailsec_ip_rule_create|delete` (worker credential,
  receipted): the row and Go's `ip_rule_*` audit row commit together (Go commits them
  separately; fault-only divergence). `netip.ParsePrefix` is ported with Go's exact error text
  (`parse_prefix`, checked against `tests/netip_prefix.json`, recorded from Go 1.26.6).
