# Conditional Access Break-Glass Convention

## Why This Exists

A mis-configured Conditional Access policy can lock **all** admins out of the system
if it is `on`, `scope_type=global`, `action=block` or `action=step_up`, and the
`exclude_users`/`exclude_groups` lists leave zero admin principals reachable.

The `ca_lockout_guard` reducer (BZ080) is the last-resort floor: every CA write
reducer calls it before mutation, and the database also re-runs it at transaction
end after any role-assignment, break-glass, user-group membership, or user
enabled/delete mutation. All paths share one transaction-scoped advisory fence,
so a policy write cannot race a reachability change.

The break-glass set remains the **pro-active** safety layer that must be
configured BEFORE any enforcing policy is turned on.

## Step-Zero Requirement

> **Before activating any `on`-state block/step-up policy, designate at least one
> break-glass admin user in `system_config.ca_break_glass_user_ids`.**

The break-glass set is a JSON array of admin user IDs stored in
`system_config` (key `ca_break_glass_user_ids`). These users are excluded from
**every** conditional access policy in every evaluation — even when the policy
excludes them by neither `exclude_users` nor `exclude_groups`. The exclusion fires
BEFORE the fail-closed branch so an eval error can never strand a break-glass admin.

## Setting the Break-Glass Set

Via the admin UI: `Admin → Conditional Access → Break-Glass Set` (the
`BreakGlassBanner` at the top of the policy list shows the current state and
provides a set/edit CTA).

Via the API (gated `access.policy_write`):

```http
PUT /admin/conditional-access/break-glass
Content-Type: application/json
Authorization: Bearer <admin_token>

[1001, 1042]
```

Response: 204 No Content on success.

## Reading the Break-Glass Set

```http
GET /admin/conditional-access/break-glass
Authorization: Bearer <admin_token>
```

Response: `{ "admins": [{"id": 1001, "email": "...", "display_name": "..."}] }`

An absent or empty array indicates no break-glass set is configured — treat this as
a WARNING if any `on`-state block policies exist.

## How It Works (Engine Layer)

1. **Startup**: both `mailserverd` and `authserverd` call
   `policyStore.LoadBreakGlass(ctx)` immediately after `CheckFailModePosture()` and
   pass the result to `policyEngine.SetBreakGlass(bg)`.
2. **On NOTIFY**: whenever `ca_break_glass_set` (or any CA write) fires
   `ca_notify_policy_change`, the `conditional_access` NOTIFY handler in both
   servers calls `policyStore.LoadBreakGlass` and — **only on success** — calls
   `policyEngine.SetBreakGlass` to refresh the in-memory snapshot. A transient DB
   error during a NOTIFY refresh leaves the prior snapshot intact (the engine never
   clears `pe.breakGlass` on a failed load — T6 safety).
3. **Evaluation**: `PolicyEngine.Evaluate` reads `pe.breakGlass` (under `cacheMu`
   read-lock) **before `loadPolicies` is called** — before any DB or geo-resolver
   call that could fail. A principal in the break-glass set is immediately returned
   `DecisionAllow` for **every** policy (including report-only and on-state block
   policies), and this short-circuit fires even when the policy cache is cold or the
   DB is down. The exclusion is INTERNAL to the engine; it requires no per-server
   wiring (I1 fix — the `ExcludeChecker` hook is also supported but not required
   for system break-glass to function).

## Audit

Every `ca_break_glass_set` call writes an `admin_audit_log` row with:
- `action = 'ca_break_glass_set'`
- `target_type = 'system_config'`
- `before_state` = the prior value (NULL on first set; `[]` if previously empty)
- `after_state` = the new value

## Minimum Guarantee (ca_lockout_guard / BZ080)

Even if no break-glass set is configured, the `ca_lockout_guard` reducer prevents
any serialized policy or reachability transaction from locking out all admins.
BZ080 is raised when:
- the policy being written is `on` + `scope_type=global`
- its action is `block` or `step_up`
- after accounting for `exclude_users`/`exclude_groups` and the system
  break-glass set, zero enabled admin principals with a permanent, non-JIT role
  assignment remain reachable

Finite `expires_at` assignments and eligible/JIT activation windows do not count
as the last escape path: they can lapse without a database mutation, so accepting
one would recreate the lockout after the timer expires. Deferred constraint
validation observes the transaction's final state, allowing safe remove-then-add
role/group replacements while rejecting an unsafe commit.

The guard is the floor; the break-glass set is the pro-active roof.
Set the break-glass set FIRST. The guard is there to catch you if you forget.
