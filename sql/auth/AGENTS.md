# sql/auth — auth & threat SQL DOX child (`sql/auth/`)

The Go `authserverd` server (`authserver/{cmd,internal,go.mod,DOX.md}`) was deleted in `#142` ([ARCH-031](../../docs/adr/ARCH-031-go-is-deleted.md)). The live authentication and identity server is the canonical Rust binary `setjoin-auth` under `server/bins/auth/` (see [server/bins/auth/DOX.md](../../server/bins/auth/DOX.md) and [server/crates/domains/identity/DOX.md](../../server/crates/domains/identity/DOX.md)).

## Ownership

`sql/auth/` owns PostgreSQL PL/pgSQL authority and pgTAP verification for auth and threat pipelines:

- `sql/auth/reducers/` — live PL/pgSQL reducers invoked by Rust (`setjoin-auth`, `setjoin-server`, and `setjoin-threat`):
  - `detect_spray.sql` — password-spray detection
  - `lockout_accessors.sql`, `lockout_escalate.sql`, `prune_lockouts.sql` — account/IP lockout state and escalation
  - `push_lockout_accessors.sql` — push-MFA lockout accessors
  - `recovery_budget_accessors.sql` — recovery-budget accessors
  - `prune_used_password_reset_tokens.sql` — password-reset token pruning
  - `rust_threat_device.sql`, `rust_threat_feed_replace.sql`, `rust_threat_signin.sql` — threat-pipeline state accessors
- `sql/auth/tests/` — pgTAP suites verifying auth lockouts, spray detection, audit immutability, auth-attempt isolation, backup codes, recovery budgets, SSO sweep, and TOTP step-up contracts.
- `sql/auth/_archive/` — historical pre-unification schema migrations. **Never execute `sql/auth/_archive/`**; auth and mail share the combined schema in `sql/dbschema/`.

## Local contracts

- Root `AGENTS.md` rules R1–R4 and `docs/standards/DATABASE_SECURITY.md` apply to every reducer and query.
- Follow PL/pgSQL reducer conventions in [sql/AGENTS.md](../AGENTS.md) (`p_`/`v_` prefixes, `ERRCODE='BZ0xx'`, pgTAP coverage for every reducer).
- Auth and mail share one PostgreSQL cluster and schema migration chain (`sql/dbschema/`); schema version mismatch refuses startup in both `setjoin-server` and `setjoin-auth`.

## Verification

```bash
# Reload reducers into disposable test DB
DB_NAME=mailserver_test bash scripts/reload-reducers.sh

# Run auth pgTAP tests
pg_prove -d mailserver_test sql/auth/tests/*.pg
```

## Child DOX Index

None.
