# Identity Alerting

Monitor identity safety with aggregate metrics that expose no person, subject,
profile, or connector value.

## Metrics

The gateway refreshes these every 30 seconds:

| Metric | Meaning |
|---|---|
| `gateway_identity_collector_success` | Last database collection succeeded |
| `gateway_identity_shadow_critical` | Open unexplained critical divergences |
| `gateway_identity_sources_attention` | Paused/error sources or sources with an error code |
| `gateway_identity_inbox_pending` | Pending or quarantined source entries |
| `gateway_identity_inbox_quarantined` | Quarantined source entries requiring review |
| `gateway_identity_conflicts_pending` | Pending/deferred match candidates |
| `gateway_identity_transitions_pending` | Non-terminal transitions |
| `gateway_identity_effects_pending` | Incomplete transition effects |
| `gateway_identity_canary_members` | Members currently in read cohorts |
| `setjoin_identity_sync_runs_total` | Retained normalized connector runs |
| `setjoin_identity_sync_duration_seconds` | Longest retained connector-run duration |
| `setjoin_identity_cursor_age_seconds` | Oldest successful source cursor age |
| `setjoin_identity_inbox_rows` | Pending or quarantined inbox rows |
| `setjoin_identity_generation_rejects_total` | Retained stale-generation rejections |
| `setjoin_identity_candidates` / `setjoin_identity_conflicts` | Pending or deferred match evidence |
| `setjoin_identity_shadow_divergences` | Open unexplained critical divergences |
| `setjoin_identity_transitions` | Nonterminal transitions |
| `setjoin_identity_transition_age_seconds` | Oldest nonterminal transition age |
| `setjoin_identity_approval_age_seconds` | Oldest pending identity approval age |
| `gateway_identity_approvals_pending` | Pending identity transition approvals |
| `gateway_identity_approval_expiry_seconds` | Time until the earliest pending identity approval expires |
| `setjoin_identity_effect_intents` | Incomplete post-commit effects |
| `setjoin_identity_effect_oldest_age_seconds` | Oldest incomplete effect age |
| `setjoin_identity_effect_retries_total` | Retained effect attempts |
| `setjoin_identity_auth_resolution_total` | Retained normalized auth-resolution events |
| `setjoin_identity_grant_changes_total` | Retained normalized authority/grant events |

Protect `/metrics` with `METRICS_TOKEN`, or explicitly set
`METRICS_ALLOW_UNAUTHENTICATED=1` only on a trusted private network.

For the Zabbix user parameters, keep the bearer value out of argv and shell
history. Create `/etc/setjoin/metrics-curl.conf` as `root:zabbix`, mode `0640`,
then use `sudoedit` to add exactly:

```text
header = "Authorization: Bearer REPLACE_WITH_METRICS_TOKEN"
```

The shipped user parameters pass that file to curl. Restart the Zabbix agent
after installing both files and verify `zabbix_agent2 -t
gateway.identity.collector` returns `1`. Do not copy the token into the Zabbix
template, item key, macro visible to ordinary Zabbix users, or process
arguments.

Artifacts:

- Prometheus rules:
  `mailserver/deploy/prometheus/identity-alerts.yml`
- Grafana dashboard:
  `mailserver/deploy/grafana/identity.json`
- Zabbix user parameters:
  `mailserver/deploy/zabbix/userparameter_setjoin.conf`

## Collector down

`SetjoinIdentityMetricsCollectorDown` fires after two minutes when the collector
reports failure **or when the success series is absent**. A missing exporter
series is not healthy merely because no zero sample exists.

1. Treat every identity gauge as stale.
2. Check gateway/database health and worker DSN permissions.
3. Run `mailctl identity upgrade status --json`.
4. Do not add canary members or execute transitions until collection succeeds.
5. If normalized reads are active and safety cannot be observed, roll back.

## Critical divergence

`SetjoinIdentityCriticalDivergence` fires after one minute.

1. Stop cohort expansion.
2. Record source key/generation and aggregate count.
3. Run inventory/conflict checks.
4. Roll back normalized admission if any canary is active.
5. Correct the underlying projection or mapping; never mark unexplained facts
   resolved merely to clear the alert.

## Effects stuck

`SetjoinIdentityTransitionEffectsStuck` fires when an incomplete effect is older
than five minutes; `SetjoinIdentityTransitionEffectsCritical` escalates at thirty
minutes. `SetjoinIdentityTransitionStuck` covers a nonterminal transition older
than five minutes. Follow the
transition report to the exact authentication-session, subscriber-notice, or
LiveKit effect and use
[`IDENTITY_RECOVERY.md`](IDENTITY_RECOVERY.md).

## Source attention

`SetjoinIdentitySourceAttention` fires after fifteen minutes when a source or
inbox needs attention. Check connector reachability, source generation,
immutable-subject discovery, pending cursor, and quarantine reason. A pending
entry prevents cursor commit by design.

`SetjoinIdentitySourceCursorStale` fires when the oldest successful cursor age
remains beyond two polling intervals for ten minutes.
`SetjoinIdentityInboxQuarantined` fires after five minutes with any quarantined
entry. Both route to the bounded inventory/conflict evidence rather than placing
subjects or payloads in alert labels.

## Approval expiry

`SetjoinIdentityApprovalExpiring` fires when a protected transition approval
remains pending with less than thirty minutes left. Re-preview and request a new
approval if it expires; never extend or reuse the old approval or its one-use
elevation.

## Alert hygiene

- Page on collector loss and critical divergence.
- Ticket source attention and stuck effects unless a protected-user transition
  raises incident severity.
- Include only source key, generation, transition/correlation ID, count, and BZ
  code in notifications.
- Never include email, external subject, assertion, token, secret, ciphertext,
  or customer content.
- Test rules against a disposable environment before production enablement.
