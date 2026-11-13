---
title: PostgreSQL RLS, SECURITY DEFINER & PL/pgSQL injection hardening (reducer architecture)
fetched: 2026-06-10
postgres_version: "18 (current); 19 beta1 released 2026-06-04"
source_urls:
  - https://www.postgresql.org/docs/current/ddl-rowsecurity.html
  - https://www.postgresql.org/docs/current/sql-createpolicy.html
  - https://www.postgresql.org/docs/current/sql-createfunction.html
  - https://www.postgresql.org/docs/current/pgstatstatements.html
  - https://www.postgresql.org/docs/current/plpgsql-statements.html
---

# PostgreSQL security hardening for the reducer architecture

Tailored to setjoin's "logic where the data is" model: every reducer takes
`p_account_id` and runs as a `SECURITY DEFINER` PL/pgSQL function. These rules
map the upstream PG 18 docs onto our DATABASE_SECURITY.md rules R1–R4.

---

## 1. Row Level Security (RLS) — R4

### Enable AND force on every user-data table
Owners (and the reducer's definer role, if it owns the table) **bypass RLS by
default**. RLS is also bypassed by superusers and roles with `BYPASSRLS`.
Because reducers run `SECURITY DEFINER` as a privileged owner, a bare `ENABLE`
is not enough — you must also `FORCE` so the definer is subject to policy.

```sql
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE  ROW LEVEL SECURITY;   -- owner/definer now policed
```

> "Table owners are normally exempt from RLS policies. FORCE ROW LEVEL SECURITY
> makes the owner subject to policies as well." — ddl-rowsecurity

With RLS enabled and **no** policy, the table is default-deny (no rows visible
or modifiable). Source: ddl-rowsecurity, sql-createpolicy.

### Tenant key via current_setting()
Set the account on the connection/transaction, then policy off it. Use the
3-arg `current_setting(key, missing_ok)` so a missing GUC fails closed rather
than erroring into an unexpected path; cast carefully.

```sql
-- gateway / reducer entry sets the tenant key for the txn:
--   PERFORM set_config('app.account_id', p_account_id::text, true);  -- true = local to txn

CREATE POLICY tenant_isolation ON messages
    USING      (account_id = current_setting('app.account_id')::bigint)
    WITH CHECK (account_id = current_setting('app.account_id')::bigint);
```

- `USING` filters rows visible to SELECT/UPDATE/DELETE.
- `WITH CHECK` validates rows written by INSERT/UPDATE. If you give only
  `USING`, it is **implicitly reused as `WITH CHECK`** (sql-createpolicy). For
  defense in depth on writes, state `WITH CHECK` explicitly so an UPDATE cannot
  move a row to another tenant.

### Policy combination (know the AND/OR rule)
Effective predicate = `(all RESTRICTIVE AND'd) AND (any PERMISSIVE OR'd)`.
At least one PERMISSIVE policy must pass or **no** rows are accessible; a table
with only RESTRICTIVE policies exposes nothing. Default policy class is
PERMISSIVE. (sql-createpolicy)

```sql
-- belt-and-suspenders: tenant match is permissive; soft-delete guard restrictive
CREATE POLICY p_tenant   ON messages
    USING (account_id = current_setting('app.account_id')::bigint);
CREATE POLICY p_not_purged ON messages AS RESTRICTIVE
    USING (purged_at IS NULL);
```

### RLS performance notes
- Policy expressions are evaluated **per row** before the user's own WHERE.
  Keep the predicate index-friendly: `account_id = current_setting(...)::bigint`
  matches a `(account_id, ...)` btree; a function/subquery per row does not.
- `current_setting()` is STABLE — fine inside a policy and re-read once per
  query, not per row, so the tenant key is cheap.
- **Subqueries in policies** (e.g. `group_id <= (SELECT ... FROM users ...)`)
  invite race conditions: without `FOR SHARE` a concurrent txn may read a stale
  snapshot, and `FOR SHARE` adds row locks that degrade throughput. Prefer
  checking the current row's own columns against the GUC. (ddl-rowsecurity)
- **LEAKPROOF caveat**: functions/operators marked `LEAKPROOF` may be evaluated
  *before* the policy filter. Do not rely on RLS to hide values that a
  non-leakproof operator could leak via error/timing; this is why
  `account_id = $tenant` (leakproof `=`) is safe but a custom non-leakproof
  comparator might surface filtered values. (sql-createpolicy)
- **RI bypass**: UNIQUE/PK/FK checks and `TRUNCATE` are **not** subject to RLS,
  so a duplicate-key error can reveal a hidden row's existence. Use surrogate
  keys (opaque IDs) so collisions don't leak tenant data. (sql-createpolicy)

### `row_security = off`
`SET row_security = off` does not silently disable filtering — it **errors** if
a query would otherwise be filtered. Only `BYPASSRLS`/superuser roles can use it
without error; never use it as a shortcut in reducers. (ddl-rowsecurity)

---

## 2. SECURITY DEFINER hygiene — protects R1/R2/R3

Reducers run with owner privileges. Two non-negotiable mitigations:

### a) Pin `search_path` on every definer function
Without a fixed path, an attacker who can write to a searched schema (the
**temp schema is searched first by default and is world-writable**) can shadow
`messages`, `set_config`, etc., and hijack the definer's privileges.

```sql
CREATE OR REPLACE FUNCTION jmap_email_set(p_account_id bigint, p_args jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
-- trusted schema(s) first, pg_temp LAST so temp objects can't shadow ours
SET search_path = public, pg_temp
AS $$
BEGIN
    -- ... every SELECT/UPDATE/DELETE filters on p_account_id (R1/R3) ...
END;
$$;
```

> "For security, `search_path` should be set to exclude any schemas writable by
> untrusted users... Particularly important is the temporary-table schema,
> which is searched first by default, and is normally writable by anyone."
> — sql-createfunction

Rule: list only trusted schemas, and put `pg_temp` **last** (never first, never
omit). If a definer function creates roles as a non-superuser, also pin
`createrole_self_grant`. (sql-createfunction)

### b) Revoke PUBLIC EXECUTE, grant only the gateway role
New functions get `EXECUTE` granted to `PUBLIC` by default. For a definer
reducer that means any role can run it as the owner. Lock it down **in the same
transaction** as creation to avoid an exposure window:

```sql
BEGIN;
CREATE FUNCTION jmap_email_set(p_account_id bigint, p_args jsonb) ...
    SECURITY DEFINER SET search_path = public, pg_temp;
REVOKE ALL ON FUNCTION jmap_email_set(bigint, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jmap_email_set(bigint, jsonb) TO mail_gateway;
COMMIT;
```

> "Avoids a window where the function is accessible to all users." — sql-createfunction

Note our migrations use `CREATE OR REPLACE`: `REPLACE` does **not** reset
privileges, but a fresh `CREATE` re-grants PUBLIC, so keep the REVOKE/GRANT
alongside each definition (idempotent) rather than assuming it persists.

### c) Trust `p_account_id`, never the session
`p_account_id` is the authenticated identity passed by the gateway. Inside the
reducer it is the *only* tenant source for R1/R2/R3 — never read identity from
mutable session state for the write path. If you also drive RLS from
`current_setting('app.account_id')`, set that GUC from the **same**
`p_account_id` at entry (`set_config(..., true)` = txn-local), so the policy and
the explicit `WHERE account_id = p_account_id` agree.

---

## 3. PL/pgSQL dynamic SQL — no injection (OWASP A03)

Reducers should rarely need `EXECUTE`. When they do, **never** interpolate
values with `%s`/`||`.

### Values → parameters via `USING`
```sql
-- SAFE: data values bound out-of-band, no quoting, no injection, faster
EXECUTE 'SELECT count(*) FROM messages WHERE account_id = $1 AND received <= $2'
    INTO v_count
    USING p_account_id, p_before;
```

### Identifiers → `format()` with `%I`; literals → `%L`
Parameters can't carry table/column names. Use `format()`:

| Spec | Equivalent     | Use for                          |
|------|----------------|----------------------------------|
| `%I` | `quote_ident()`   | identifiers (table/column names) |
| `%L` | `quote_nullable()`| literal values (null-safe)       |
| `%s` | plain string   | **never** for user input — injectable |

```sql
-- SAFEST: %I for the dynamic column, $1/$2 bound via USING for the values
EXECUTE format('UPDATE messages SET %I = $1 WHERE account_id = $2', v_colname)
    USING v_newvalue, p_account_id;
```

```sql
-- ACCEPTABLE when a literal must be inlined: %L is quote_nullable()
EXECUTE format('UPDATE messages SET %I = %L WHERE account_id = %L',
               v_colname, v_newvalue, p_account_id);
```

```sql
-- WRONG: %s with user value — breaks on $$ / quotes, classic injection
EXECUTE 'UPDATE messages SET ' || v_colname || ' = ' || v_newvalue || ' ...';
```

Notes from plpgsql-statements:
- `quote_literal()` returns NULL on NULL input — prefer `quote_nullable()`
  (`%L`) so a NULL becomes the SQL keyword `NULL` instead of breaking the query.
- `USING` "avoids run-time overhead of converting values to text" and is "much
  less prone to SQL-injection attacks." Prefer `format('%I', …) … USING …` over
  `format('%L', …)` for both safety and speed.
- A column-name allowlist is still wise: `%I` quotes the identifier but does not
  check it exists or that the caller may touch it.

---

## 4. pg_stat_statements — don't leak secrets or other tenants' SQL

- **Literals are normalized to `$1`, `$2`** in stored query text, so constants
  (including a stray inlined secret) are not retained:
  `SELECT * FROM test WHERE a IN ($1 /*, ... */)`. This is another reason to use
  `USING`/parameters rather than inlining literals — predictable normalization,
  no secret retention. (pgstatstatements)
- **Cross-user visibility is restricted**:
  > "only superusers and roles with privileges of the `pg_read_all_stats` role
  > are allowed to see the SQL text and `queryid` of queries executed by other
  > users. Other users can see the statistics, however." — pgstatstatements

  So grant the monitoring/admin role `pg_read_all_stats`; do **not** hand the
  gateway/app role membership in `pg_read_all_stats` or superuser, or it could
  read other tenants' (and the auth server's) SQL text.
- `pg_stat_statements_reset()` is superuser-only by default; delegate with
  `GRANT` only to an ops role. `pg_stat_statements.track*` settings are
  superuser-only. (pgstatstatements)
- Even with normalization, identifiers and structure remain visible — treat the
  view as sensitive and keep it off application roles.

---

## Checklist for a new reducer / user-data table

1. Table: `ENABLE` **and** `FORCE ROW LEVEL SECURITY`. (R4)
2. PERMISSIVE tenant policy `account_id = current_setting('app.account_id')::bigint`
   with explicit `WITH CHECK`; predicate is index-aligned. (R4)
3. Function: `SECURITY DEFINER` + `SET search_path = public, pg_temp` (pg_temp last).
4. `REVOKE ALL ... FROM PUBLIC; GRANT EXECUTE ... TO mail_gateway;` in the same txn.
5. Every SELECT/UPDATE/DELETE also has explicit `WHERE account_id = p_account_id`
   in the same statement (R1/R3) — RLS is defense in depth, not the only guard.
6. Any `EXECUTE`: `%I` for identifiers, `$n` + `USING` for values, never `%s`.
7. Keep `pg_read_all_stats`/superuser off the gateway and auth-server DB roles.

---

### Sources (fetched 2026-06-10, PostgreSQL 18 / docs/current)
- Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- CREATE POLICY: https://www.postgresql.org/docs/current/sql-createpolicy.html
- CREATE FUNCTION (SECURITY DEFINER, search_path, REVOKE PUBLIC): https://www.postgresql.org/docs/current/sql-createfunction.html
- pg_stat_statements: https://www.postgresql.org/docs/current/pgstatstatements.html
- PL/pgSQL EXECUTE / format / USING: https://www.postgresql.org/docs/current/plpgsql-statements.html
