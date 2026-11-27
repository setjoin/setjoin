//! Live PostgreSQL 187-table `setjoin_app` (`NOBYPASSRLS`) `FORCE RLS` proof matrix
//! for Wave 1.8e (#546e, completing Wave 1 #536).
//!
//! Reads `config/table-ownership-manifest.json` directly from the repository root at
//! runtime, asserts zero pending RLS cutover tables and zero pending legacy cross-domain
//! writes, verifies `relrowsecurity AND relforcerowsecurity` on every single scoped table
//! (66 `mailbox_scoped` + 121 `user_scoped` = 187 tables), asserts exact 1:1 probe
//! coverage with zero uncovered manifest tables, and proves under real `setjoin_app`
//! (`rolsuper = false`, `rolbypassrls = false`) with strictly divergent tenant IDs
//! (`user_id != mailbox_id`, `DATABASE_SECURITY.md:169-171`):
//! 1. Cross-tenant `SELECT` denial;
//! 2. Swapped-GUC / divergent-ID enforcement (`app.current_mailbox_id` vs `app.current_user_id`);
//! 3. Unset and empty GUC fail-closed behavior on `SELECT`/`INSERT`/`UPDATE`/`DELETE`;
//! 4. Cross-tenant `UPDATE` and `DELETE` denial (with owner integrity re-verification);
//! 5. Cross-tenant `INSERT` denial (`42501`);
//! 6. `INSERT ... ON CONFLICT DO NOTHING / DO UPDATE` anti-oracle behavior (`ARCH-018:51`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use tokio_postgres::{Client, NoTls};

// ---------------------------------------------------------------------------
// Strictly divergent tenant identities (user_id != mailbox_id, DATABASE_SECURITY.md:169-171)
// ---------------------------------------------------------------------------
const USER_A: i64 = 910_001;
const MAILBOX_A: i64 = 920_001;
const USER_B: i64 = 910_002;
const MAILBOX_B: i64 = 920_002;
const USER_GUEST_A: i64 = 910_004;

// ---------------------------------------------------------------------------
// Test environment gate (matching capability_tx.rs / db_scope.rs conventions)
// ---------------------------------------------------------------------------

fn owner_dsn() -> Option<String> {
    ["TEST_DB_DSN", "DB_DSN"]
        .into_iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

fn require_db() -> bool {
    std::env::var("REQUIRE_DB").as_deref() == Ok("1")
}

fn app_dsn(owner: &str) -> String {
    std::env::var("DB_APP_DSN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| swap_dsn_user(owner, "setjoin_app"))
}

fn swap_dsn_user(dsn: &str, role: &str) -> String {
    if let Some((scheme, rest)) = dsn.split_once("://") {
        if let Some((_, host)) = rest.split_once('@') {
            return format!("{scheme}://{role}@{host}");
        }
    }
    let mut parts: Vec<String> = dsn
        .split_whitespace()
        .filter(|p| !p.starts_with("user="))
        .map(str::to_owned)
        .collect();
    parts.push(format!("user={role}"));
    parts.join(" ")
}

async fn connect_raw(dsn: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(client)
}

fn skip_or_fail(test: &str, reason: &str) {
    if require_db() {
        panic!("REQUIRE_DB=1 but {test} cannot run: {reason}");
    }
    use std::io::Write;
    let line = format!("SETJOIN-PG-DB-SKIP (reason={reason}) test={test}\n");
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

// ---------------------------------------------------------------------------
// Minimal RFC 8259 zero-dependency JSON parser for config/table-ownership-manifest.json
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum JsonVal {
    Null,
    Bool,
    Num(i64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    fn as_obj(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            JsonVal::Obj(m) => Some(m),
            _ => None,
        }
    }
    fn as_arr(&self) -> Option<&[JsonVal]> {
        match self {
            JsonVal::Arr(v) => Some(v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    fn as_i64(&self) -> Option<i64> {
        match self {
            JsonVal::Num(n) => Some(*n),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(input: &'a str) -> Result<JsonVal, String> {
        let mut p = Self {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let v = p.parse_val()?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(format!("trailing bytes at offset {}", p.pos));
        }
        Ok(v)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_val(&mut self) -> Result<JsonVal, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_obj(),
            Some(b'[') => self.parse_arr(),
            Some(b'"') => self.parse_str().map(JsonVal::Str),
            Some(b't') => {
                self.expect_lit(b"true")?;
                Ok(JsonVal::Bool)
            }
            Some(b'f') => {
                self.expect_lit(b"false")?;
                Ok(JsonVal::Bool)
            }
            Some(b'n') => {
                self.expect_lit(b"null")?;
                Ok(JsonVal::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_num(),
            other => Err(format!("unexpected byte {other:?} at {}", self.pos)),
        }
    }

    fn expect_lit(&mut self, lit: &[u8]) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(format!("expected literal at {}", self.pos))
        }
    }

    fn parse_str(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("expected '\"' at {}", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        return Err("unterminated escape".into());
                    }
                    let esc = self.bytes[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err("short \\u escape".into());
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|e| e.to_string())?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                            self.pos += 4;
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            }
                        }
                        _ => return Err(format!("bad escape \\{}", esc as char)),
                    }
                }
                _ => {
                    let start = self.pos - 1;
                    while self.pos < self.bytes.len()
                        && self.bytes[self.pos] != b'"'
                        && self.bytes[self.pos] != b'\\'
                    {
                        self.pos += 1;
                    }
                    let slice = std::str::from_utf8(&self.bytes[start..self.pos])
                        .map_err(|e| e.to_string())?;
                    out.push_str(slice);
                }
            }
        }
        Err("unterminated string".into())
    }

    fn parse_num(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
            )
        {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
        let n = s
            .parse::<i64>()
            .or_else(|_| s.parse::<f64>().map(|f| f as i64))
            .map_err(|e| format!("bad number '{s}': {e}"))?;
        Ok(JsonVal::Num(n))
    }

    fn parse_arr(&mut self) -> Result<JsonVal, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonVal::Arr(items));
        }
        loop {
            items.push(self.parse_val()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonVal::Arr(items));
                }
                other => {
                    return Err(format!(
                        "expected ',' or ']' at {}, got {other:?}",
                        self.pos
                    ))
                }
            }
        }
    }

    fn parse_obj(&mut self) -> Result<JsonVal, String> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonVal::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_str()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_val()?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonVal::Obj(map));
                }
                other => {
                    return Err(format!(
                        "expected ',' or '}}' at {}, got {other:?}",
                        self.pos
                    ))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 187-table RLS probe specification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestClass {
    MailboxScoped,
    UserScoped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GucMode {
    /// Policy keys on `app.current_mailbox_id`: swapped `(USER_A, MAILBOX_B)` MUST deny;
    /// `(USER_B, MAILBOX_A)` sees Tenant A's row.
    MailboxOnly,
    /// Policy keys on `app.current_user_id`: swapped `(USER_B, MAILBOX_A)` MUST deny;
    /// `(USER_A, MAILBOX_B)` sees Tenant A's row.
    UserOnly,
    /// Policy requires BOTH `app.current_mailbox_id = MAILBOX_A` AND `app.current_user_id = USER_A`
    /// (`mail_recovery_quarantine_artifacts`, `mail_recovery_upload_sessions`):
    /// BOTH swapped pairs `(USER_A, MAILBOX_B)` and `(USER_B, MAILBOX_A)` MUST deny.
    BothRequired,
    /// Policy keys on `user_id = current_user_id OR mailbox_id = current_mailbox_id`
    /// (`mailboxes`, `mailbox_delegates`): Tenant B `(USER_B, MAILBOX_B)` denied on all 4 ops;
    /// unset/empty GUC denied on all 4 ops.
    MailboxOrOwnerUser,
    /// Zero permissive policies for `setjoin_app` (`identity_auth_link_elevations`,
    /// `identity_media_admissions`): pure default-deny on ALL ops even for Tenant A.
    DefaultDeny,
    /// Authenticated-user SELECT (`current_user_id IS NOT NULL`, for join-by-slug lobby
    /// discovery on `meetings`), with strict owner-only INSERT/UPDATE/DELETE and fail-closed
    /// unset/empty GUC on all 4 ops.
    UserAuthSelectOwnerWrite,
}

struct TableProbe {
    table: &'static str,
    class: ManifestClass,
    guc_mode: GucMode,
    seed_sql: &'static str,
    where_a: &'static str,
    update_set: &'static str,
    insert_a_sql: &'static str,
}

// 64-hex digests & deterministic UUIDs used across fixture rows:
// H1 = 'a1...' (64 hex chars), H2 = 'b2...' (64 hex chars)
// UUIDs: 91000100-0000-4000-8000-0000000000XX

/// Non-scoped parent fixture rows required by foreign keys of the 187 scoped tables.
const NON_SCOPED_PARENT_SETUP_BEFORE_USERS: &str = r#"
INSERT INTO domains (id, name) VALUES (900001, 'rls-matrix-546e.test') ON CONFLICT (id) DO NOTHING;
INSERT INTO blobs (sha256, minio_ref, size_bytes) VALUES
  ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rls-matrix-546e/blob-a1', 64),
  ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'rls-matrix-546e/blob-a2', 64)
  ON CONFLICT (sha256) DO NOTHING;
INSERT INTO drive_chunks (scope_key, sha256, size_bytes, storage_ref) VALUES
  ('rls-546e-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 64, 'rls-546e/chunk-a1'),
  ('rls-546e-a', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 64, 'rls-546e/chunk-a2')
  ON CONFLICT (scope_key, sha256) DO NOTHING;
INSERT INTO approval_policies (id, consumer_type, name, priority, conditions, approver_spec) VALUES
  (900010, 'drive.access', 'rls-546e-ap-1', 10, '{}'::jsonb, '{}'::jsonb),
  (900011, 'drive.access', 'rls-546e-ap-2', 11, '{}'::jsonb, '{}'::jsonb)
  ON CONFLICT (id) DO NOTHING;
INSERT INTO terms_of_use (id, name, body_md) OVERRIDING SYSTEM VALUE VALUES
  (900020, 'rls-546e-tou-1', '# Terms 1'),
  (900021, 'rls-546e-tou-2', '# Terms 2')
  ON CONFLICT (id) DO NOTHING;
INSERT INTO oidc_clients (id, name, secret, redirect_uris) VALUES
  ('rls-546e-oidc-client', 'RLS Matrix Client', 'secret-hash', ARRAY['https://rls-matrix-546e.test/cb'])
  ON CONFLICT (id) DO NOTHING;
INSERT INTO guest_profiles (id, host_domain_id, name) VALUES
  (900030, 900001, 'rls-546e-guest-profile')
  ON CONFLICT (id) DO NOTHING;
INSERT INTO office_provider_policies (provider_id) VALUES
  ('rls-546e-office')
  ON CONFLICT (provider_id) DO NOTHING;
INSERT INTO identity_sources (id, source_key, display_name, kind, capabilities) VALUES
  (900040, 'rls-546e-src', 'RLS Matrix Source', 'oidc', '{"authenticate":true}'::jsonb)
  ON CONFLICT (id) DO NOTHING;
"#;

const NON_SCOPED_PARENT_SETUP_AFTER_MAILBOXES: &str = r#"
INSERT INTO users (id, username, domain_id, email, display_name) VALUES
  (910002, 'rls_b_user', 900001, 'rls_b@rls-matrix-546e.test', 'Tenant B'),
  (910003, 'rls_c_user', 900001, 'rls_c@rls-matrix-546e.test', 'Neutral C'),
  (910004, 'rls_guest_a', 900001, 'rls_guest_a@rls-matrix-546e.test', 'Guest A')
  ON CONFLICT (id) DO NOTHING;
INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES
  (920002, 910002, 900001, 'rls_b@rls-matrix-546e.test', 'Tenant B Mailbox', TRUE)
  ON CONFLICT (id) DO NOTHING;
INSERT INTO addressbooks (id, mailbox_id, name) VALUES
  (930039, 920002, 'AB B')
  ON CONFLICT (id) DO NOTHING;
INSERT INTO distribution_groups (id, mailbox_id) VALUES
  (900050, 920001)
  ON CONFLICT (id) DO NOTHING;
INSERT INTO user_identity_links (id, user_id, source_id, external_subject, purposes, link_method) VALUES
  (900060, 910001, 900040, 'sub-rls-546e-a', ARRAY['authenticate'], 'operator')
  ON CONFLICT (id) DO NOTHING;
INSERT INTO mail_recovery_incidents (id, installation_id, minimum_timeline, maximum_timeline, reason, opened_by, step_up_binding, expires_at, idempotency_key) VALUES
  ('91000100-0000-4000-8000-000000000001'::uuid, '91000100-0000-4000-8000-000000000000'::uuid, 1, 10, 'rls matrix test incident 1', 910001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), now() + interval '1 day', '91000100-0000-4000-8000-000000000011'::uuid),
  ('91000100-0000-4000-8000-000000000002'::uuid, '91000100-0000-4000-8000-000000000000'::uuid, 1, 10, 'rls matrix test incident 2', 910001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), now() + interval '1 day', '91000100-0000-4000-8000-000000000012'::uuid)
  ON CONFLICT (id) DO NOTHING;
"#;

const NON_SCOPED_OUTBOX_SETUP: &str = r#"
INSERT INTO mail_work_outbox (id, event_id, consumer_kind, dedupe_key, payload) OVERRIDING SYSTEM VALUE VALUES
  (900070, '91000100-0000-4000-8000-000000000040'::uuid, 'push', 'rls-546e-outbox-1', '{}'::jsonb),
  (900071, '91000100-0000-4000-8000-000000000040'::uuid, 'push', 'rls-546e-outbox-2', '{}'::jsonb)
  ON CONFLICT (id) DO NOTHING;
"#;

/// Ordered topologically by FK dependencies so every parent row is seeded before children.
/// Exact 1:1 coverage with all 187 scoped tables (66 mailbox_scoped + 121 user_scoped) in
/// `config/table-ownership-manifest.json` is strictly asserted at runtime!
const PROBES: &[TableProbe] = &[
    // --- 1. Root identity & mailbox tables ---
    TableProbe {
        table: "users",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO users (id, username, domain_id, email, display_name) VALUES (910001, 'rls_a_user', 900001, 'rls_a@rls-matrix-546e.test', 'Tenant A')",
        where_a: "id = 910001",
        update_set: "display_name = display_name",
        insert_a_sql: "INSERT INTO users (id, username, domain_id, email, display_name) VALUES (910099, 'rls_a_ins', 900001, 'rls_a_ins@rls-matrix-546e.test', 'Ins A')",
    },
    TableProbe {
        table: "mailboxes",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOrOwnerUser,
        seed_sql: "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920001, 910001, 900001, 'rls_a@rls-matrix-546e.test', 'Tenant A Mailbox', TRUE)",
        where_a: "id = 920001",
        update_set: "display_name = display_name",
        insert_a_sql: "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920099, 910001, 900001, 'rls_a_ins@rls-matrix-546e.test', 'Ins MB', FALSE)",
    },
    // --- 2. Core mail & mailbox child tables ---
    TableProbe {
        table: "folders",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO folders (id, mailbox_id, name, path) VALUES (930001, 920001, 'RlsInbox', 'RlsInbox')",
        where_a: "id = 930001",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO folders (id, mailbox_id, name, path) VALUES (939001, 920001, 'RlsIns', 'RlsIns')",
    },
    TableProbe {
        table: "tags",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO tags (id, mailbox_id, name) VALUES (930002, 920001, 'rls-tag-a')",
        where_a: "id = 930002",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO tags (id, mailbox_id, name) VALUES (939002, 920001, 'rls-tag-ins')",
    },
    TableProbe {
        table: "messages",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO messages (id, received_at, mailbox_id, folder_id, message_id, from_addr, thread_id, raw_ref) VALUES (930003, '2026-06-15T12:00:00Z'::timestamptz, 920001, 930001, '<rls-a@rls-matrix-546e.test>', 'rls_a@rls-matrix-546e.test', 'thr-rls-a', 'rls-matrix-546e/msg-a')",
        where_a: "id = 930003 AND received_at = '2026-06-15T12:00:00Z'::timestamptz",
        update_set: "subject = subject",
        insert_a_sql: "INSERT INTO messages (id, received_at, mailbox_id, folder_id, message_id, from_addr, thread_id, raw_ref) VALUES (939003, '2026-06-15T12:00:00Z'::timestamptz, 920001, 930001, '<rls-ins@rls-matrix-546e.test>', 'rls_a@rls-matrix-546e.test', 'thr-rls-ins', 'rls-matrix-546e/msg-ins')",
    },
    TableProbe {
        table: "message_tags",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO message_tags (message_id, received_at, tag_id) VALUES (930003, '2026-06-15T12:00:00Z'::timestamptz, 930002)",
        where_a: "message_id = 930003 AND received_at = '2026-06-15T12:00:00Z'::timestamptz AND tag_id = 930002",
        update_set: "imap_modseq = imap_modseq",
        insert_a_sql: "INSERT INTO message_tags (message_id, received_at, tag_id) VALUES (930003, '2026-06-15T12:00:00Z'::timestamptz, 930002)",
    },
    TableProbe {
        table: "message_attachments",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO message_attachments (id, message_id, received_at, blob_sha256, content_type, size_bytes) VALUES (930004, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'text/plain', 64)",
        where_a: "id = 930004",
        update_set: "content_type = content_type",
        insert_a_sql: "INSERT INTO message_attachments (id, message_id, received_at, blob_sha256, content_type, size_bytes) VALUES (939004, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'text/plain', 64)",
    },
    TableProbe {
        table: "message_recalls",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO message_recalls (message_id, recalled_by) VALUES ('<rls-recall-a@rls-matrix-546e.test>', 910001)",
        where_a: "message_id = '<rls-recall-a@rls-matrix-546e.test>'",
        update_set: "recalled_by = recalled_by",
        insert_a_sql: "INSERT INTO message_recalls (message_id, recalled_by) VALUES ('<rls-recall-ins@rls-matrix-546e.test>', 910001)",
    },
    TableProbe {
        table: "aliases",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO aliases (id, mailbox_id, email, domain_id) VALUES (930005, 920001, 'rls-alias-a@rls-matrix-546e.test', 900001)",
        where_a: "id = 930005",
        update_set: "email = email",
        insert_a_sql: "INSERT INTO aliases (id, mailbox_id, email, domain_id) VALUES (939005, 920001, 'rls-alias-ins@rls-matrix-546e.test', 900001)",
    },
    TableProbe {
        table: "read_receipts",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO read_receipts (id, message_id, received_at, recipient_email) VALUES (930006, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'rcpt@rls-matrix-546e.test')",
        where_a: "id = 930006",
        update_set: "recipient_email = recipient_email",
        insert_a_sql: "INSERT INTO read_receipts (id, message_id, received_at, recipient_email) VALUES (939006, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'rcpt2@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "vote_responses",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO vote_responses (id, message_id, received_at, voter_email, vote_option) VALUES (930007, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'voter@rls-matrix-546e.test', 'yes')",
        where_a: "id = 930007",
        update_set: "vote_option = vote_option",
        insert_a_sql: "INSERT INTO vote_responses (id, message_id, received_at, voter_email, vote_option) VALUES (939007, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'voter2@rls-matrix-546e.test', 'yes')",
    },
    TableProbe {
        table: "quarantined_messages",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO quarantined_messages (id, message_id, mailbox_id, original_tag, reason) VALUES (930008, 930003, 920001, 'inbox', 'rls-test')",
        where_a: "id = 930008",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO quarantined_messages (id, message_id, mailbox_id, original_tag, reason) VALUES (939008, 930003, 920001, 'inbox', 'rls-ins')",
    },
    TableProbe {
        table: "quick_steps",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO quick_steps (id, mailbox_id, name) VALUES (930009, 920001, 'qs-a')",
        where_a: "id = 930009",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO quick_steps (id, mailbox_id, name) VALUES (939009, 920001, 'qs-ins')",
    },
    TableProbe {
        table: "rules",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO rules (id, mailbox_id, name) VALUES (930010, 920001, 'rule-a')",
        where_a: "id = 930010",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO rules (id, mailbox_id, name) VALUES (939010, 920001, 'rule-ins')",
    },
    TableProbe {
        table: "saved_searches",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO saved_searches (id, mailbox_id, name, query) VALUES (930011, 920001, 'ss-a', 'from:a')",
        where_a: "id = 930011",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO saved_searches (id, mailbox_id, name, query) VALUES (939011, 920001, 'ss-ins', 'from:a')",
    },
    TableProbe {
        table: "scheduled_actions",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO scheduled_actions (id, mailbox_id, action_kind, fire_at) VALUES ('91000100-0000-4000-8000-000000000015'::uuid, 920001, 'snooze', now() + interval '1 hour')",
        where_a: "id = '91000100-0000-4000-8000-000000000015'::uuid",
        update_set: "action_kind = action_kind",
        insert_a_sql: "INSERT INTO scheduled_actions (id, mailbox_id, action_kind, fire_at) VALUES ('91000100-0000-4000-8000-000000000016'::uuid, 920001, 'snooze', now() + interval '1 hour')",
    },
    TableProbe {
        table: "signatures",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO signatures (id, mailbox_id, name) VALUES (930013, 920001, 'sig-a')",
        where_a: "id = 930013",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO signatures (id, mailbox_id, name) VALUES (939013, 920001, 'sig-ins')",
    },
    TableProbe {
        table: "email_templates",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO email_templates (id, mailbox_id, name) VALUES (930014, 920001, 'tpl-a')",
        where_a: "id = 930014",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO email_templates (id, mailbox_id, name) VALUES (939014, 920001, 'tpl-ins')",
    },
    TableProbe {
        table: "vacation_settings",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO vacation_settings (mailbox_id) VALUES (920001)",
        where_a: "mailbox_id = 920001",
        update_set: "enabled = enabled",
        insert_a_sql: "INSERT INTO vacation_settings (mailbox_id) VALUES (920001)",
    },
    TableProbe {
        table: "vacation_replies",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO vacation_replies (sender_email, mailbox_id, vacation_start) VALUES ('ext@rls-matrix-546e.test', 920001, '2026-06-01'::date)",
        where_a: "mailbox_id = 920001 AND sender_email = 'ext@rls-matrix-546e.test'",
        update_set: "sender_email = sender_email",
        insert_a_sql: "INSERT INTO vacation_replies (sender_email, mailbox_id, vacation_start) VALUES ('ext2@rls-matrix-546e.test', 920001, '2026-06-02'::date)",
    },
    TableProbe {
        table: "reminders",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (930015, 920001, 'task', 1, '2026-06-15T12:00:00Z'::timestamptz, 'rem-a')",
        where_a: "id = 930015",
        update_set: "title = title",
        insert_a_sql: "INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (939015, 920001, 'task', 2, '2026-06-16T12:00:00Z'::timestamptz, 'rem-ins')",
    },
    TableProbe {
        table: "delivery_attempts",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO delivery_attempts (id, message_pk, received_at, mailbox_id, recipient_email, attempt_number, outcome) OVERRIDING SYSTEM VALUE VALUES (930016, 930003, '2026-06-15T12:00:00Z'::timestamptz, 920001, 'rcpt@rls-matrix-546e.test', 1, 'accepted')",
        where_a: "id = 930016",
        update_set: "outcome = outcome",
        insert_a_sql: "INSERT INTO delivery_attempts (id, message_pk, received_at, mailbox_id, recipient_email, attempt_number, outcome) OVERRIDING SYSTEM VALUE VALUES (939016, 930003, '2026-06-15T12:00:00Z'::timestamptz, 920001, 'rcpt2@rls-matrix-546e.test', 1, 'accepted')",
    },
    TableProbe {
        table: "continuity_client_witnesses",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO continuity_client_witnesses (id, mailbox_id, token_sha256, installation_id, timeline_generation, state_watermark, issued_at, boot_epoch, signal_class) OVERRIDING SYSTEM VALUE VALUES (930017, 920001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), '91000100-0000-4000-8000-000000000000'::uuid, 1, 1, now(), '91000100-0000-4000-8000-000000000000'::uuid, 'none')",
        where_a: "id = 930017",
        update_set: "state_watermark = state_watermark",
        insert_a_sql: "INSERT INTO continuity_client_witnesses (id, mailbox_id, token_sha256, installation_id, timeline_generation, state_watermark, issued_at, boot_epoch, signal_class) OVERRIDING SYSTEM VALUE VALUES (939017, 920001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), '91000100-0000-4000-8000-000000000000'::uuid, 1, 1, now(), '91000100-0000-4000-8000-000000000000'::uuid, 'none')",
    },
    TableProbe {
        table: "jmap_changes_journal",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO jmap_changes_journal (mailbox_id, datatype, state_seq, entity_id, op) VALUES (920001, 'Email', 1, 930003, 'created')",
        where_a: "mailbox_id = 920001 AND datatype = 'Email' AND state_seq = 1 AND entity_id = 930003",
        update_set: "op = op",
        insert_a_sql: "INSERT INTO jmap_changes_journal (mailbox_id, datatype, state_seq, entity_id, op) VALUES (920001, 'Email', 2, 930003, 'updated')",
    },
    TableProbe {
        table: "jmap_entity_state",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO jmap_entity_state (mailbox_id, datatype) VALUES (920001, 'Email')",
        where_a: "mailbox_id = 920001 AND datatype = 'Email'",
        update_set: "datatype = datatype",
        insert_a_sql: "INSERT INTO jmap_entity_state (mailbox_id, datatype) VALUES (920001, 'Mailbox')",
    },
    TableProbe {
        table: "imap_membership_uid_backfill",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO imap_membership_uid_backfill (tag_id) VALUES (930002)",
        where_a: "tag_id = 930002",
        update_set: "processed = processed",
        insert_a_sql: "INSERT INTO imap_membership_uid_backfill (tag_id) VALUES (930002)",
    },
    TableProbe {
        table: "imap_membership_uid_ledger",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO imap_membership_uid_ledger (tag_id, imap_uid, message_id, received_at) VALUES (930002, 1, 930003, '2026-06-15T12:00:00Z'::timestamptz) ON CONFLICT (tag_id, imap_uid) DO NOTHING",
        where_a: "tag_id = 930002 AND imap_uid = 1",
        update_set: "active = active",
        insert_a_sql: "INSERT INTO imap_membership_uid_ledger (tag_id, imap_uid, message_id, received_at) VALUES (930002, 2, 930003, '2026-06-15T12:00:00Z'::timestamptz)",
    },
    TableProbe {
        table: "mailbox_audit_log",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_audit_log (id, occurred_at, mailbox_id, action) VALUES (930018, now(), 920001, 'rls_test')",
        where_a: "id = 930018",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO mailbox_audit_log (id, occurred_at, mailbox_id, action) VALUES (939018, now(), 920001, 'rls_ins')",
    },
    TableProbe {
        table: "mailbox_delegates",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOrOwnerUser,
        seed_sql: "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES (920001, 910003, 'read', 910001)",
        where_a: "mailbox_id = 920001 AND user_id = 910003 AND permission = 'read'",
        update_set: "permission = permission",
        insert_a_sql: "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES (920001, 910003, 'send_as', 910001)",
    },
    TableProbe {
        table: "mailbox_address_claims",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_address_claims (normalized_address, mailbox_id, address_kind) VALUES ('rls_a@rls-matrix-546e.test', 920001, 'primary') ON CONFLICT (normalized_address) DO NOTHING",
        where_a: "normalized_address = 'rls_a@rls-matrix-546e.test'",
        update_set: "address_kind = address_kind",
        insert_a_sql: "INSERT INTO mailbox_address_claims (normalized_address, mailbox_id, address_kind) VALUES ('rls_a2@rls-matrix-546e.test', 920001, 'alias')",
    },
    TableProbe {
        table: "mailbox_binding_history",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_binding_history (id, mailbox_id, operation_id, evidence_kind, actor_user_id, actor_auth_time, reason) OVERRIDING SYSTEM VALUE VALUES (930019, 920001, '91000100-0000-4000-8000-000000000021'::uuid, 'initial', 910001, now(), 'rls test')",
        where_a: "id = 930019",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO mailbox_binding_history (id, mailbox_id, operation_id, evidence_kind, actor_user_id, actor_auth_time, reason) OVERRIDING SYSTEM VALUE VALUES (939019, 920001, '91000100-0000-4000-8000-000000000022'::uuid, 'initial', 910001, now(), 'rls ins')",
    },
    TableProbe {
        table: "mailbox_lifecycle",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_lifecycle (mailbox_id, bound_user_id) VALUES (920001, 910001) ON CONFLICT (mailbox_id) DO NOTHING",
        where_a: "mailbox_id = 920001",
        update_set: "generation = generation",
        insert_a_sql: "INSERT INTO mailbox_lifecycle (mailbox_id, bound_user_id) VALUES (920001, 910001)",
    },
    TableProbe {
        table: "mailbox_lifecycle_operations",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_lifecycle_operations (operation_id, mailbox_id, action, actor_user_id, expected_generation, request_digest, before_digest, after_digest, result) VALUES ('91000100-0000-4000-8000-000000000023'::uuid, 920001, 'suspend', 910001, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
        where_a: "operation_id = '91000100-0000-4000-8000-000000000023'::uuid",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO mailbox_lifecycle_operations (operation_id, mailbox_id, action, actor_user_id, expected_generation, request_digest, before_digest, after_digest, result) VALUES ('91000100-0000-4000-8000-000000000024'::uuid, 920001, 'resume', 910001, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
    },
    TableProbe {
        table: "mailbox_purge_requests",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mailbox_purge_requests (id, mailbox_id, operation_id, lifecycle_generation, preview_digest, requested_by, eligible_at, reason) VALUES ('91000100-0000-4000-8000-000000000027'::uuid, 920001, '91000100-0000-4000-8000-000000000025'::uuid, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, now() + interval '1 day', 'rls test purge')",
        where_a: "id = '91000100-0000-4000-8000-000000000027'::uuid",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO mailbox_purge_requests (id, mailbox_id, operation_id, lifecycle_generation, preview_digest, requested_by, eligible_at, reason) VALUES ('91000100-0000-4000-8000-000000000028'::uuid, 920001, '91000100-0000-4000-8000-000000000026'::uuid, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, now() + interval '1 day', 'rls ins purge')",
    },
    // --- 3. Contacts & Addressbooks ---
    TableProbe {
        table: "addressbooks",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO addressbooks (id, mailbox_id, name) VALUES (930030, 920001, 'ab-a')",
        where_a: "id = 930030",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO addressbooks (id, mailbox_id, name) VALUES (939030, 920001, 'ab-ins')",
    },
    TableProbe {
        table: "contacts",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (930031, 930030, 'vcard-rls-a', 'Contact A')",
        where_a: "id = 930031",
        update_set: "display_name = display_name",
        insert_a_sql: "INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (939031, 930030, 'vcard-rls-ins', 'Contact Ins')",
    },
    TableProbe {
        table: "contact_groups",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO contact_groups (id, mailbox_id, name) VALUES (930032, 920001, 'cg-a')",
        where_a: "id = 930032",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO contact_groups (id, mailbox_id, name) VALUES (939032, 920001, 'cg-ins')",
    },
    TableProbe {
        table: "contact_group_members",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO contact_group_members (id, group_id, contact_id) VALUES (930033, 930032, 930031)",
        where_a: "id = 930033",
        update_set: "group_id = group_id",
        insert_a_sql: "INSERT INTO contact_group_members (id, group_id, email) VALUES (939033, 930032, 'm@rls-matrix-546e.test')",
    },
    // --- 4. Calendars, Bookings & Tasks ---
    TableProbe {
        table: "calendars",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO calendars (id, mailbox_id, name) VALUES (930040, 920001, 'cal-a')",
        where_a: "id = 930040",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO calendars (id, mailbox_id, name) VALUES (939040, 920001, 'cal-ins')",
    },
    TableProbe {
        table: "calendar_acls",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES (930040, 910003, 'read')",
        where_a: "calendar_id = 930040 AND user_id = 910003",
        update_set: "permission = permission",
        insert_a_sql: "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES (930040, 910002, 'read')",
    },
    TableProbe {
        table: "calendar_events",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO calendar_events (id, calendar_id, uid, title) VALUES (930041, 930040, 'ev-uid-rls-a', 'Event A')",
        where_a: "id = 930041",
        update_set: "title = title",
        insert_a_sql: "INSERT INTO calendar_events (id, calendar_id, uid, title) VALUES (939041, 930040, 'ev-uid-rls-ins', 'Event Ins')",
    },
    TableProbe {
        table: "calendar_subscriptions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO calendar_subscriptions (id, user_id, calendar_id, url) OVERRIDING SYSTEM VALUE VALUES (930042, 910001, 930040, 'https://rls-matrix-546e.test/cal.ics')",
        where_a: "id = 930042",
        update_set: "url = url",
        insert_a_sql: "INSERT INTO calendar_subscriptions (id, user_id, calendar_id, url) OVERRIDING SYSTEM VALUE VALUES (939042, 910001, 930040, 'https://rls-matrix-546e.test/cal2.ics')",
    },
    TableProbe {
        table: "event_attendees",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO event_attendees (id, event_id, email) VALUES (930043, 930041, 'att@rls-matrix-546e.test')",
        where_a: "id = 930043",
        update_set: "email = email",
        insert_a_sql: "INSERT INTO event_attendees (id, event_id, email) VALUES (939043, 930041, 'att2@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "vt_timezone",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO vt_timezone (id, calendar_id, tzid) VALUES (930044, 930040, 'Etc/UTC')",
        where_a: "id = 930044",
        update_set: "tzid = tzid",
        insert_a_sql: "INSERT INTO vt_timezone (id, calendar_id, tzid) VALUES (939044, 930040, 'America/New_York')",
    },
    TableProbe {
        table: "booking_pages",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO booking_pages (id, mailbox_id, slug, title) VALUES (930045, 920001, 'rls-546e-bp-a', 'Booking A')",
        where_a: "id = 930045",
        update_set: "title = title",
        insert_a_sql: "INSERT INTO booking_pages (id, mailbox_id, slug, title) VALUES (939045, 920001, 'rls-546e-bp-ins', 'Booking Ins')",
    },
    TableProbe {
        table: "booking_requests",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO booking_requests (id, page_id, mailbox_id, booker_email, slot_start, slot_end, verify_token_hash, verify_expires_at) VALUES (930046, 930045, 920001, 'booker@rls-matrix-546e.test', now(), now() + interval '30 minutes', 'tok-hash-a', now() + interval '1 hour')",
        where_a: "id = 930046",
        update_set: "booker_email = booker_email",
        insert_a_sql: "INSERT INTO booking_requests (id, page_id, mailbox_id, booker_email, slot_start, slot_end, verify_token_hash, verify_expires_at) VALUES (939046, 930045, 920001, 'booker2@rls-matrix-546e.test', now(), now() + interval '30 minutes', 'tok-hash-ins', now() + interval '1 hour')",
    },
    TableProbe {
        table: "task_lists",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO task_lists (id, owner_user_id, name) VALUES (930050, 910001, 'tl-a')",
        where_a: "id = 930050",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO task_lists (id, owner_user_id, name) VALUES (939050, 910001, 'tl-ins')",
    },
    TableProbe {
        table: "task_list_members",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO task_list_members (list_id, user_id) VALUES (930050, 910001)",
        where_a: "list_id = 930050 AND user_id = 910001",
        update_set: "role = role",
        insert_a_sql: "INSERT INTO task_list_members (list_id, user_id) VALUES (930050, 910003)",
    },
    TableProbe {
        table: "tasks",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO tasks (id, mailbox_id, title) VALUES (930051, 920001, 'task-a')",
        where_a: "id = 930051",
        update_set: "title = title",
        insert_a_sql: "INSERT INTO tasks (id, mailbox_id, title) VALUES (939051, 920001, 'task-ins')",
    },
    TableProbe {
        table: "task_activity",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO task_activity (id, task_id, mailbox_id, author_user_id) VALUES (930052, 930051, 920001, 910003)",
        where_a: "id = 930052",
        update_set: "kind = kind",
        insert_a_sql: "INSERT INTO task_activity (id, task_id, mailbox_id, author_user_id) VALUES (939052, 930051, 920001, 910003)",
    },
    // --- 5. Mail Drafts, Recovery & Shared Mail Work ---
    TableProbe {
        table: "mail_draft_collaboration",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_draft_collaboration (draft_session_id, mailbox_id, message_id, received_at, final_sender_address) VALUES ('91000100-0000-4000-8000-000000000030'::uuid, 920001, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'rls_a@rls-matrix-546e.test')",
        where_a: "draft_session_id = '91000100-0000-4000-8000-000000000030'::uuid",
        update_set: "final_sender_address = final_sender_address",
        insert_a_sql: "INSERT INTO mail_draft_collaboration (draft_session_id, mailbox_id, message_id, received_at, final_sender_address) VALUES ('91000100-0000-4000-8000-000000000031'::uuid, 920001, 930004, '2026-06-15T12:00:00Z'::timestamptz, 'rls_a@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "mail_draft_revisions",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_draft_revisions (draft_session_id, revision, message_id, received_at, content_digest, attachment_digest) VALUES ('91000100-0000-4000-8000-000000000030'::uuid, 1, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
        where_a: "draft_session_id = '91000100-0000-4000-8000-000000000030'::uuid AND revision = 1",
        update_set: "content_digest = content_digest",
        insert_a_sql: "INSERT INTO mail_draft_revisions (draft_session_id, revision, message_id, received_at, content_digest, attachment_digest) VALUES ('91000100-0000-4000-8000-000000000030'::uuid, 2, 930003, '2026-06-15T12:00:00Z'::timestamptz, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
    },
    TableProbe {
        table: "mail_recovery_incident_accounts",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO mail_recovery_incident_accounts (incident_id, mailbox_id, affected_user_id, evidence_token_sha256) VALUES ('91000100-0000-4000-8000-000000000001'::uuid, 920001, 910001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'))",
        where_a: "incident_id = '91000100-0000-4000-8000-000000000001'::uuid AND mailbox_id = 920001",
        update_set: "evidence_token_sha256 = evidence_token_sha256",
        insert_a_sql: "INSERT INTO mail_recovery_incident_accounts (incident_id, mailbox_id, affected_user_id, evidence_token_sha256) VALUES ('91000100-0000-4000-8000-000000000002'::uuid, 920001, 910001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'))",
    },
    TableProbe {
        table: "mail_recovery_upload_sessions",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO mail_recovery_upload_sessions (id, incident_id, mailbox_id, uploading_user_id, device_id, artifact_identity, lineage_sha256, raw_mime_sha256, eligibility, declared_size, total_declared_size, receipt, consented_at, expires_at, idempotency_key) VALUES ('91000100-0000-4000-8000-000000000032'::uuid, '91000100-0000-4000-8000-000000000001'::uuid, 920001, 910001, '91000100-0000-4000-8000-000000000039'::uuid, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 'received', 64, 64, '{}'::jsonb, now(), now() + interval '1 hour', '91000100-0000-4000-8000-000000000033'::uuid)",
        where_a: "id = '91000100-0000-4000-8000-000000000032'::uuid",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO mail_recovery_upload_sessions (id, incident_id, mailbox_id, uploading_user_id, device_id, artifact_identity, lineage_sha256, raw_mime_sha256, eligibility, declared_size, total_declared_size, receipt, consented_at, expires_at, idempotency_key) VALUES ('91000100-0000-4000-8000-000000000034'::uuid, '91000100-0000-4000-8000-000000000001'::uuid, 920001, 910001, '91000100-0000-4000-8000-000000000039'::uuid, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 'received', 64, 64, '{}'::jsonb, now(), now() + interval '1 hour', '91000100-0000-4000-8000-000000000035'::uuid)",
    },
    TableProbe {
        table: "mail_recovery_upload_items",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_recovery_upload_items (session_id, item_id, role, sha256, declared_size) VALUES ('91000100-0000-4000-8000-000000000032'::uuid, 'item-a1', 'raw', decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 64)",
        where_a: "session_id = '91000100-0000-4000-8000-000000000032'::uuid AND item_id = 'item-a1'",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO mail_recovery_upload_items (session_id, item_id, role, sha256, declared_size) VALUES ('91000100-0000-4000-8000-000000000032'::uuid, 'item-a2', 'attachment', decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 64)",
    },
    TableProbe {
        table: "mail_recovery_upload_chunks",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_recovery_upload_chunks (session_id, item_id, start_offset, size_bytes, sha256, object_key) VALUES ('91000100-0000-4000-8000-000000000032'::uuid, 'item-a1', 0, 64, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 'recovery-quarantine/91000100-0000-4000-8000-000000000001/91000100-0000-4000-8000-000000000032/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/0-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
        where_a: "session_id = '91000100-0000-4000-8000-000000000032'::uuid AND item_id = 'item-a1' AND start_offset = 0",
        update_set: "size_bytes = size_bytes",
        insert_a_sql: "INSERT INTO mail_recovery_upload_chunks (session_id, item_id, start_offset, size_bytes, sha256, object_key) VALUES ('91000100-0000-4000-8000-000000000032'::uuid, 'item-a1', 64, 64, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 'recovery-quarantine/91000100-0000-4000-8000-000000000001/91000100-0000-4000-8000-000000000032/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/64-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
    },
    TableProbe {
        table: "mail_recovery_quarantine_artifacts",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO mail_recovery_quarantine_artifacts (id, session_id, incident_id, mailbox_id, uploading_user_id, device_id, artifact_identity, lineage_sha256, raw_mime_sha256, raw_mime_size, raw_ref, receipt, signed_timeline, signed_boot_epoch, parsed_headers, blob_inventory, malware_status) VALUES ('91000100-0000-4000-8000-000000000036'::uuid, '91000100-0000-4000-8000-000000000032'::uuid, '91000100-0000-4000-8000-000000000001'::uuid, 920001, 910001, '91000100-0000-4000-8000-000000000039'::uuid, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 64, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb, 1, '91000100-0000-4000-8000-000000000000'::uuid, '{}'::jsonb, '[]'::jsonb, 'clean')",
        where_a: "id = '91000100-0000-4000-8000-000000000036'::uuid",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO mail_recovery_quarantine_artifacts (id, session_id, incident_id, mailbox_id, uploading_user_id, device_id, artifact_identity, lineage_sha256, raw_mime_sha256, raw_mime_size, raw_ref, receipt, signed_timeline, signed_boot_epoch, parsed_headers, blob_inventory, malware_status) VALUES ('91000100-0000-4000-8000-000000000037'::uuid, '91000100-0000-4000-8000-000000000032'::uuid, '91000100-0000-4000-8000-000000000001'::uuid, 920001, 910001, '91000100-0000-4000-8000-000000000039'::uuid, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 64, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '{}'::jsonb, 1, '91000100-0000-4000-8000-000000000000'::uuid, '{}'::jsonb, '[]'::jsonb, 'clean')",
    },
    TableProbe {
        table: "mail_recovery_ledger",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_recovery_ledger (artifact_identity, incident_id, mailbox_id, quarantine_id, outcome) VALUES (decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), '91000100-0000-4000-8000-000000000001'::uuid, 920001, '91000100-0000-4000-8000-000000000036'::uuid, 'accepted')",
        where_a: "artifact_identity = decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex')",
        update_set: "outcome = outcome",
        insert_a_sql: "INSERT INTO mail_recovery_ledger (artifact_identity, incident_id, mailbox_id, quarantine_id, outcome) VALUES (decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), '91000100-0000-4000-8000-000000000001'::uuid, 920001, '91000100-0000-4000-8000-000000000036'::uuid, 'accepted')",
    },
    TableProbe {
        table: "mail_thread_comments",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_thread_comments (id, mailbox_id, thread_id, author_user_id, author_display_snapshot, body, operation_id) VALUES ('91000100-0000-4000-8000-000000000038'::uuid, 920001, 'thr-rls-a', 910001, 'Tenant A', 'hello', '91000100-0000-4000-8000-00000000003a'::uuid)",
        where_a: "id = '91000100-0000-4000-8000-000000000038'::uuid",
        update_set: "body = body",
        insert_a_sql: "INSERT INTO mail_thread_comments (id, mailbox_id, thread_id, author_user_id, author_display_snapshot, body, operation_id) VALUES ('91000100-0000-4000-8000-00000000003b'::uuid, 920001, 'thr-rls-a', 910001, 'Tenant A', 'ins', '91000100-0000-4000-8000-00000000003c'::uuid)",
    },
    TableProbe {
        table: "mail_thread_comment_mentions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_thread_comment_mentions (comment_id, user_id, capability) VALUES ('91000100-0000-4000-8000-000000000038'::uuid, 910001, 'comment')",
        where_a: "comment_id = '91000100-0000-4000-8000-000000000038'::uuid AND user_id = 910001",
        update_set: "capability = capability",
        insert_a_sql: "INSERT INTO mail_thread_comment_mentions (comment_id, user_id, capability) VALUES ('91000100-0000-4000-8000-000000000038'::uuid, 910003, 'view_only')",
    },
    TableProbe {
        table: "mail_thread_work",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_thread_work (mailbox_id, thread_id) VALUES (920001, 'thr-rls-a')",
        where_a: "mailbox_id = 920001 AND thread_id = 'thr-rls-a'",
        update_set: "generation = generation",
        insert_a_sql: "INSERT INTO mail_thread_work (mailbox_id, thread_id) VALUES (920001, 'thr-rls-ins')",
    },
    TableProbe {
        table: "mail_thread_work_events",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_thread_work_events (id, mailbox_id, thread_id, generation, event_type, actor_user_id, actor_display_snapshot, before_state, after_state, reason) VALUES ('91000100-0000-4000-8000-000000000040'::uuid, 920001, 'thr-rls-a', 1, 'created', 910001, 'Tenant A', '{}'::jsonb, '{}'::jsonb, 'rls test')",
        where_a: "id = '91000100-0000-4000-8000-000000000040'::uuid",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO mail_thread_work_events (id, mailbox_id, thread_id, generation, event_type, actor_user_id, actor_display_snapshot, before_state, after_state, reason) VALUES ('91000100-0000-4000-8000-000000000041'::uuid, 920001, 'thr-rls-a', 2, 'claimed', 910001, 'Tenant A', '{}'::jsonb, '{}'::jsonb, 'rls ins')",
    },
    TableProbe {
        table: "mail_work_action_links",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_action_links (id, mailbox_id, thread_id, action_kind, result_id, event_id) VALUES ('91000100-0000-4000-8000-000000000044'::uuid, 920001, 'thr-rls-a', 'task', 930051, '91000100-0000-4000-8000-000000000040'::uuid)",
        where_a: "id = '91000100-0000-4000-8000-000000000044'::uuid",
        update_set: "result_id = result_id",
        insert_a_sql: "INSERT INTO mail_work_action_links (id, mailbox_id, thread_id, action_kind, result_id, event_id) VALUES ('91000100-0000-4000-8000-000000000045'::uuid, 920001, 'thr-rls-a', 'chat', 1, '91000100-0000-4000-8000-000000000040'::uuid)",
    },
    TableProbe {
        table: "mail_work_changes",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_changes (mailbox_id, state_seq, object_kind, object_id, op) VALUES (920001, 1, 'work', 'thr-rls-a', 'created')",
        where_a: "mailbox_id = 920001 AND state_seq = 1 AND object_kind = 'work' AND object_id = 'thr-rls-a'",
        update_set: "op = op",
        insert_a_sql: "INSERT INTO mail_work_changes (mailbox_id, state_seq, object_kind, object_id, op) VALUES (920001, 2, 'work', 'thr-rls-a', 'updated')",
    },
    TableProbe {
        table: "mail_work_notification_preferences",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_notification_preferences (mailbox_id, user_id, category) VALUES (920001, 910001, 'assignment')",
        where_a: "mailbox_id = 920001 AND user_id = 910001 AND category = 'assignment'",
        update_set: "delivery = delivery",
        insert_a_sql: "INSERT INTO mail_work_notification_preferences (mailbox_id, user_id, category) VALUES (920001, 910001, 'mention')",
    },
    TableProbe {
        table: "mail_work_digest_ledger",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_digest_ledger (mailbox_id, user_id, category, window_start, dedupe_key) VALUES (920001, 910001, 'assignment', '2026-06-15T12:00:00Z'::timestamptz, 'rls-546e-digest-a')",
        where_a: "mailbox_id = 920001 AND user_id = 910001 AND category = 'assignment'",
        update_set: "dedupe_key = dedupe_key",
        insert_a_sql: "INSERT INTO mail_work_digest_ledger (mailbox_id, user_id, category, window_start, dedupe_key) VALUES (920001, 910001, 'assignment', '2026-06-16T12:00:00Z'::timestamptz, 'rls-546e-digest-ins')",
    },
    TableProbe {
        table: "mail_work_metric_actors",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_work_metric_actors (mailbox_id, metric_day, actor_user_id) VALUES (920001, '2026-06-15'::date, 910001)",
        where_a: "mailbox_id = 920001 AND metric_day = '2026-06-15'::date AND actor_user_id = 910001",
        update_set: "policy_version = policy_version",
        insert_a_sql: "INSERT INTO mail_work_metric_actors (mailbox_id, metric_day, actor_user_id) VALUES (920001, '2026-06-16'::date, 910001)",
    },
    TableProbe {
        table: "mail_work_metric_conversations",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_work_metric_conversations (mailbox_id, metric_day, thread_id) VALUES (920001, '2026-06-15'::date, 'thr-rls-a')",
        where_a: "mailbox_id = 920001 AND metric_day = '2026-06-15'::date AND thread_id = 'thr-rls-a'",
        update_set: "policy_version = policy_version",
        insert_a_sql: "INSERT INTO mail_work_metric_conversations (mailbox_id, metric_day, thread_id) VALUES (920001, '2026-06-16'::date, 'thr-rls-a')",
    },
    TableProbe {
        table: "mail_work_metric_daily",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_metric_daily (mailbox_id, metric_day) VALUES (920001, '2026-06-15'::date)",
        where_a: "mailbox_id = 920001 AND metric_day = '2026-06-15'::date",
        update_set: "conversation_count = conversation_count",
        insert_a_sql: "INSERT INTO mail_work_metric_daily (mailbox_id, metric_day) VALUES (920001, '2026-06-16'::date)",
    },
    TableProbe {
        table: "mail_work_notification_deliveries",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_work_notification_deliveries (outbox_id, user_id, event_id, category, channel, outcome, why) VALUES (900070, 910001, '91000100-0000-4000-8000-000000000040'::uuid, 'assignment', 'realtime', 'delivered', 'rls-test')",
        where_a: "outbox_id = 900070 AND user_id = 910001",
        update_set: "why = why",
        insert_a_sql: "INSERT INTO mail_work_notification_deliveries (outbox_id, user_id, event_id, category, channel, outcome, why) VALUES (900071, 910001, '91000100-0000-4000-8000-000000000040'::uuid, 'assignment', 'realtime', 'delivered', 'rls-ins')",
    },
    TableProbe {
        table: "mail_work_notification_rate_windows",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO mail_work_notification_rate_windows (user_id, window_start) VALUES (910001, '2026-06-15T12:00:00Z'::timestamptz)",
        where_a: "user_id = 910001 AND window_start = '2026-06-15T12:00:00Z'::timestamptz",
        update_set: "delivered_count = delivered_count",
        insert_a_sql: "INSERT INTO mail_work_notification_rate_windows (user_id, window_start) VALUES (910001, '2026-06-16T12:00:00Z'::timestamptz)",
    },
    TableProbe {
        table: "mail_work_operations",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_operations (operation_id, mailbox_id, actor_user_id, operation_kind, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000042'::uuid, 920001, 910001, 'work_set', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
        where_a: "operation_id = '91000100-0000-4000-8000-000000000042'::uuid",
        update_set: "operation_kind = operation_kind",
        insert_a_sql: "INSERT INTO mail_work_operations (operation_id, mailbox_id, actor_user_id, operation_kind, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000043'::uuid, 920001, 910001, 'work_set', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
    },
    TableProbe {
        table: "mail_work_sla_policies",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mail_work_sla_policies (mailbox_id) VALUES (920001)",
        where_a: "mailbox_id = 920001",
        update_set: "generation = generation",
        insert_a_sql: "INSERT INTO mail_work_sla_policies (mailbox_id) VALUES (920001)",
    },
    // --- 6. Approvals, Blobs, Migration, Guests ---
    TableProbe {
        table: "approval_delegations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO approval_delegations (id, delegator_user_id, delegate_user_id, starts_at, ends_at) VALUES (930070, 910001, 910003, now(), now() + interval '1 day')",
        where_a: "id = 930070",
        update_set: "delegate_user_id = delegate_user_id",
        insert_a_sql: "INSERT INTO approval_delegations (id, delegator_user_id, delegate_user_id, starts_at, ends_at) VALUES (939070, 910001, 910003, now(), now() + interval '2 days')",
    },
    TableProbe {
        table: "approval_requests",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO approval_requests (id, policy_id, consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at) VALUES (930071, 900010, 'drive.access', 910001, 'rls-appr-a', '{}'::jsonb, 'user', 910003, now() + interval '1 day')",
        where_a: "id = 930071",
        update_set: "subject = subject",
        insert_a_sql: "INSERT INTO approval_requests (id, policy_id, consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at) VALUES (939071, 900010, 'drive.access', 910001, 'rls-appr-ins', '{}'::jsonb, 'user', 910003, now() + interval '1 day')",
    },
    TableProbe {
        table: "held_inbound_messages",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO held_inbound_messages (id, approval_request_id, group_id, raw_ref, envelope, deliver_params) VALUES (930072, 930071, 900050, 'rls-546e/held-a', '{}'::jsonb, '{}'::jsonb)",
        where_a: "id = 930072",
        update_set: "raw_ref = raw_ref",
        insert_a_sql: "INSERT INTO held_inbound_messages (id, approval_request_id, group_id, raw_ref, envelope, deliver_params) VALUES (939072, 930071, 900050, 'rls-546e/held-ins', '{}'::jsonb, '{}'::jsonb)",
    },
    TableProbe {
        table: "hr_expense_receipts",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO hr_expense_receipts (id, approval_request_id, line_index, blob_sha256, filename) VALUES (930073, 930071, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'r1.pdf')",
        where_a: "id = 930073",
        update_set: "filename = filename",
        insert_a_sql: "INSERT INTO hr_expense_receipts (id, approval_request_id, line_index, blob_sha256, filename) VALUES (939073, 930071, 2, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'r2.pdf')",
    },
    TableProbe {
        table: "blob_user_charges",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO blob_user_charges (blob_sha256, user_id, size_bytes) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, 64)",
        where_a: "blob_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        update_set: "size_bytes = size_bytes",
        insert_a_sql: "INSERT INTO blob_user_charges (blob_sha256, user_id, size_bytes) VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 910001, 64)",
    },
    TableProbe {
        table: "blob_user_usage",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO blob_user_usage (user_id) VALUES (910001) ON CONFLICT (user_id) DO NOTHING",
        where_a: "user_id = 910001",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO blob_user_usage (user_id) VALUES (910001)",
    },
    TableProbe {
        table: "guest_accounts",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, profile_id) VALUES (910004, 'rls_guest_a@rls-matrix-546e.test', 'admin@rls-matrix-546e.test', 900001, 900030)",
        where_a: "user_id = 910004",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, profile_id) VALUES (910004, 'rls_guest_a@rls-matrix-546e.test', 'admin@rls-matrix-546e.test', 900001, 900030)",
    },
    TableProbe {
        table: "migration_jobs",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO migration_jobs (id, user_id, target_mailbox_id, source_type) VALUES (930080, 910001, 920001, 'imap')",
        where_a: "id = 930080",
        update_set: "source_type = source_type",
        insert_a_sql: "INSERT INTO migration_jobs (id, user_id, target_mailbox_id, source_type) VALUES (939080, 910001, 920001, 'imap')",
    },
    TableProbe {
        table: "migration_checkpoints",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO migration_checkpoints (job_id, scope_key, cursor_kind, cursor_value, source_generation) VALUES (930080, 'INBOX', 'imap_uid', '{}'::jsonb, 1)",
        where_a: "job_id = 930080 AND scope_key = 'INBOX' AND cursor_kind = 'imap_uid'",
        update_set: "source_generation = source_generation",
        insert_a_sql: "INSERT INTO migration_checkpoints (job_id, scope_key, cursor_kind, cursor_value, source_generation) VALUES (930080, 'Sent', 'imap_uid', '{}'::jsonb, 1)",
    },
    TableProbe {
        table: "migration_source_instances",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO migration_source_instances (id, job_id, source_type, source_mailbox_key, selector_digest) VALUES ('91000100-0000-4000-8000-000000000050'::uuid, 930080, 'imap', 'imap-key-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
        where_a: "id = '91000100-0000-4000-8000-000000000050'::uuid",
        update_set: "source_mailbox_key = source_mailbox_key",
        insert_a_sql: "INSERT INTO migration_source_instances (id, job_id, source_type, source_mailbox_key, selector_digest) VALUES ('91000100-0000-4000-8000-000000000051'::uuid, 930080, 'imap', 'imap-key-ins', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
    },
    TableProbe {
        table: "migration_object_operations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO migration_object_operations (operation_id, job_id, source_instance_id, object_type, source_object_id, source_change, state) VALUES ('91000100-0000-4000-8000-000000000052'::uuid, 930080, '91000100-0000-4000-8000-000000000050'::uuid, 'mail', 'obj-a1', 'upsert', 'accepted')",
        where_a: "operation_id = '91000100-0000-4000-8000-000000000052'::uuid",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO migration_object_operations (operation_id, job_id, source_instance_id, object_type, source_object_id, source_change, state) VALUES ('91000100-0000-4000-8000-000000000053'::uuid, 930080, '91000100-0000-4000-8000-000000000050'::uuid, 'mail', 'obj-a2', 'upsert', 'accepted')",
    },
    TableProbe {
        table: "migration_source_objects",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::BothRequired,
        seed_sql: "INSERT INTO migration_source_objects (source_instance_id, object_type, source_object_id, projection_state, applied_operation_id) VALUES ('91000100-0000-4000-8000-000000000050'::uuid, 'mail', 'obj-a1', 'tombstoned', '91000100-0000-4000-8000-000000000052'::uuid)",
        where_a: "source_instance_id = '91000100-0000-4000-8000-000000000050'::uuid AND object_type = 'mail' AND source_object_id = 'obj-a1'",
        update_set: "projection_state = projection_state",
        insert_a_sql: "INSERT INTO migration_source_objects (source_instance_id, object_type, source_object_id, projection_state, applied_operation_id) VALUES ('91000100-0000-4000-8000-000000000050'::uuid, 'mail', 'obj-a2', 'tombstoned', '91000100-0000-4000-8000-000000000052'::uuid)",
    },
    TableProbe {
        table: "migration_thread_reconcile_jobs",
        class: ManifestClass::MailboxScoped,
        guc_mode: GucMode::MailboxOnly,
        seed_sql: "INSERT INTO migration_thread_reconcile_jobs (job_id, target_mailbox_id) VALUES (930080, 920001)",
        where_a: "job_id = 930080",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO migration_thread_reconcile_jobs (job_id, target_mailbox_id) VALUES (930080, 920001)",
    },
    // --- 7. Drive (25 tables) + Office (4 tables) ---
    TableProbe {
        table: "drive_spaces",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_spaces (id, name, owner_user_id) OVERRIDING SYSTEM VALUE VALUES (930100, 'rls-space-a', 910001)",
        where_a: "id = 930100",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO drive_spaces (id, name, owner_user_id) OVERRIDING SYSTEM VALUE VALUES (939100, 'rls-space-ins', 910001)",
    },
    TableProbe {
        table: "drive_space_members",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_space_members (space_id, user_id, role, granted_by) VALUES (930100, 910001, 'manager', 910001)",
        where_a: "space_id = 930100 AND user_id = 910001",
        update_set: "role = role",
        insert_a_sql: "INSERT INTO drive_space_members (space_id, user_id, role, granted_by) VALUES (930100, 910003, 'viewer', 910001)",
    },
    TableProbe {
        table: "drive_nodes",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_nodes (id, space_id, kind, name, created_by) OVERRIDING SYSTEM VALUE VALUES (930101, 930100, 'file', 'doc-a.txt', 910001)",
        where_a: "id = 930101",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO drive_nodes (id, space_id, kind, name, created_by) OVERRIDING SYSTEM VALUE VALUES (939101, 930100, 'file', 'doc-ins.txt', 910001)",
    },
    TableProbe {
        table: "drive_files",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_files (node_id, space_id) VALUES (930101, 930100)",
        where_a: "node_id = 930101",
        update_set: "size_bytes = size_bytes",
        insert_a_sql: "INSERT INTO drive_files (node_id, space_id) VALUES (930101, 930100)",
    },
    TableProbe {
        table: "drive_file_versions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_file_versions (id, file_node_id, space_id, content_sha256, size_bytes, author_user_id) OVERRIDING SYSTEM VALUE VALUES (930102, 930101, 930100, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 64, 910001)",
        where_a: "id = 930102",
        update_set: "size_bytes = size_bytes",
        insert_a_sql: "INSERT INTO drive_file_versions (id, file_node_id, space_id, content_sha256, size_bytes, author_user_id) OVERRIDING SYSTEM VALUE VALUES (939102, 930101, 930100, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 64, 910001)",
    },
    TableProbe {
        table: "drive_file_branches",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_file_branches (id, file_node_id, space_id, name, head_version_id, forked_from_version_id, created_by) OVERRIDING SYSTEM VALUE VALUES (930103, 930101, 930100, 'br-a', 930102, 930102, 910001)",
        where_a: "id = 930103",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO drive_file_branches (id, file_node_id, space_id, name, head_version_id, forked_from_version_id, created_by) OVERRIDING SYSTEM VALUE VALUES (939103, 930101, 930100, 'br-ins', 930102, 930102, 910001)",
    },
    TableProbe {
        table: "drive_access_request_policies",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO drive_access_request_policies (id, approval_policy_id, space_id, capabilities, max_propagation, max_duration_minutes, created_by) OVERRIDING SYSTEM VALUE VALUES (930104, 900010, 930100, ARRAY['preview'], 'self', 60, 910001)",
        where_a: "id = 930104",
        update_set: "max_duration_minutes = max_duration_minutes",
        insert_a_sql: "INSERT INTO drive_access_request_policies (id, approval_policy_id, space_id, capabilities, max_propagation, max_duration_minutes, created_by) OVERRIDING SYSTEM VALUE VALUES (939104, 900011, 930100, ARRAY['preview'], 'self', 60, 910001)",
    },
    TableProbe {
        table: "drive_acl_grants",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_acl_grants (id, space_id, node_id, subject_kind, subject_user_id, preset, capabilities, propagation, created_by) OVERRIDING SYSTEM VALUE VALUES (930105, 930100, 930101, 'user', 910001, 'custom', ARRAY['preview','manage_acl'], 'self', 910001)",
        where_a: "id = 930105",
        update_set: "preset = preset",
        insert_a_sql: "INSERT INTO drive_acl_grants (id, space_id, node_id, subject_kind, subject_user_id, preset, capabilities, propagation, created_by) OVERRIDING SYSTEM VALUE VALUES (939105, 930100, 930101, 'user', 910001, 'custom', ARRAY['preview'], 'self', 910001)",
    },
    TableProbe {
        table: "drive_access_request_details",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_access_request_details (request_id, requester_user_id, policy_id, space_id, node_id, subject_kind, subject_user_id, requested_capabilities, requested_propagation, requested_expires_at, reason, expected_epoch, idempotency_key, request_digest) VALUES (930071, 910001, 930104, 930100, 930101, 'user', 910001, ARRAY['preview'], 'self', now() + interval '1 hour', 'rls matrix access request', 0, 'rls-546e-idem-a1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
        where_a: "request_id = 930071",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO drive_access_request_details (request_id, requester_user_id, policy_id, space_id, node_id, subject_kind, subject_user_id, requested_capabilities, requested_propagation, requested_expires_at, reason, expected_epoch, idempotency_key, request_digest) VALUES (930071, 910001, 930104, 930100, 930101, 'user', 910001, ARRAY['preview'], 'self', now() + interval '1 hour', 'rls matrix access ins', 0, 'rls-546e-idem-a2', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
    },
    TableProbe {
        table: "drive_access_use_leases",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_access_use_leases (id, grant_id, user_id, capability, idempotency_key, request_digest, expires_at) VALUES ('91000100-0000-4000-8000-000000000058'::uuid, 930105, 910001, 'preview', 'rls-546e-lease-a1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', now() + interval '5 minutes')",
        where_a: "id = '91000100-0000-4000-8000-000000000058'::uuid",
        update_set: "capability = capability",
        insert_a_sql: "INSERT INTO drive_access_use_leases (id, grant_id, user_id, capability, idempotency_key, request_digest, expires_at) VALUES ('91000100-0000-4000-8000-000000000059'::uuid, 930105, 910001, 'preview', 'rls-546e-lease-a2', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', now() + interval '5 minutes')",
    },
    TableProbe {
        table: "drive_acl_breaks",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_acl_breaks (space_id, node_id, created_by, expected_epoch) VALUES (930100, 930101, 910001, 0)",
        where_a: "space_id = 930100 AND node_id = 930101",
        update_set: "expected_epoch = expected_epoch",
        insert_a_sql: "INSERT INTO drive_acl_breaks (space_id, node_id, created_by, expected_epoch) VALUES (930100, 930101, 910001, 1)",
    },
    TableProbe {
        table: "drive_acl_generations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_acl_generations (space_id) VALUES (930100) ON CONFLICT (space_id) DO NOTHING",
        where_a: "space_id = 930100",
        update_set: "epoch = epoch",
        insert_a_sql: "INSERT INTO drive_acl_generations (space_id) VALUES (930100)",
    },
    TableProbe {
        table: "drive_audit_alarms",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO drive_audit_alarms (id, space_id, action_pattern, created_by) OVERRIDING SYSTEM VALUE VALUES (930107, 930100, 'download', 910001)",
        where_a: "id = 930107",
        update_set: "action_pattern = action_pattern",
        insert_a_sql: "INSERT INTO drive_audit_alarms (id, space_id, action_pattern, created_by) OVERRIDING SYSTEM VALUE VALUES (939107, 930100, 'delete', 910001)",
    },
    TableProbe {
        table: "drive_audit_log",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_audit_log (space_id, id, action) VALUES (930100, 930108, 'rls_test')",
        where_a: "space_id = 930100 AND id = 930108",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO drive_audit_log (space_id, id, action) VALUES (930100, 939108, 'rls_ins')",
    },
    TableProbe {
        table: "drive_changes",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_changes (space_id, seq, node_id, op) VALUES (930100, 1, 930101, 'create')",
        where_a: "space_id = 930100 AND seq = 1",
        update_set: "op = op",
        insert_a_sql: "INSERT INTO drive_changes (space_id, seq, node_id, op) VALUES (930100, 2, 930101, 'update')",
    },
    TableProbe {
        table: "drive_export_grants",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_export_grants (id, version_id, space_id, grantee, action, token_hash, minted_by, expires_at) OVERRIDING SYSTEM VALUE VALUES (930109, 930102, 930100, 910001, 'download', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, now() + interval '1 hour')",
        where_a: "id = 930109",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO drive_export_grants (id, version_id, space_id, grantee, action, token_hash, minted_by, expires_at) OVERRIDING SYSTEM VALUE VALUES (939109, 930102, 930100, 910001, 'download', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 910001, now() + interval '1 hour')",
    },
    TableProbe {
        table: "drive_file_locks",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_file_locks (node_id, space_id, user_id, version_id, expires_at) VALUES (930101, 930100, 910001, 930102, now() + interval '1 hour')",
        where_a: "node_id = 930101",
        update_set: "mode = mode",
        insert_a_sql: "INSERT INTO drive_file_locks (node_id, space_id, user_id, version_id, expires_at) VALUES (930101, 930100, 910001, 930102, now() + interval '2 hours')",
    },
    TableProbe {
        table: "drive_folder_admins",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_folder_admins (node_id, space_id, user_id, granted_by) VALUES (930101, 930100, 910001, 910001)",
        where_a: "node_id = 930101 AND user_id = 910001",
        update_set: "granted_by = granted_by",
        insert_a_sql: "INSERT INTO drive_folder_admins (node_id, space_id, user_id, granted_by) VALUES (930101, 930100, 910003, 910001)",
    },
    TableProbe {
        table: "drive_node_closure",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_node_closure (space_id, ancestor_id, descendant_id, depth) VALUES (930100, 930101, 930101, 0) ON CONFLICT (space_id, ancestor_id, descendant_id) DO NOTHING",
        where_a: "space_id = 930100 AND ancestor_id = 930101 AND descendant_id = 930101",
        update_set: "depth = depth",
        insert_a_sql: "INSERT INTO drive_node_closure (space_id, ancestor_id, descendant_id, depth) VALUES (930100, 930101, 930101, 0)",
    },
    TableProbe {
        table: "drive_upload_authorizations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_upload_authorizations (scope_key, sha256, user_id, space_id, target_node_id, acl_epoch) VALUES ('rls-546e-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, 930100, 930101, 0)",
        where_a: "scope_key = 'rls-546e-a' AND sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AND user_id = 910001 AND target_node_id = 930101",
        update_set: "acl_epoch = acl_epoch",
        insert_a_sql: "INSERT INTO drive_upload_authorizations (scope_key, sha256, user_id, space_id, target_node_id, acl_epoch) VALUES ('rls-546e-a', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 910001, 930100, 930101, 0)",
    },
    TableProbe {
        table: "drive_upload_claims",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_upload_claims (scope_key, sha256, user_id) VALUES ('rls-546e-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001)",
        where_a: "scope_key = 'rls-546e-a' AND sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AND user_id = 910001",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO drive_upload_claims (scope_key, sha256, user_id) VALUES ('rls-546e-a', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 910001)",
    },
    TableProbe {
        table: "drive_version_chunks",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_version_chunks (version_id, ordinal, scope_key, chunk_sha256) VALUES (930102, 0, 'rls-546e-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
        where_a: "version_id = 930102 AND stream = 'content' AND ordinal = 0",
        update_set: "ordinal = ordinal",
        insert_a_sql: "INSERT INTO drive_version_chunks (version_id, ordinal, scope_key, chunk_sha256) VALUES (930102, 1, 'rls-546e-a', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
    },
    TableProbe {
        table: "drive_version_labels",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_version_labels (version_id, label, created_by) VALUES (930102, 'v1', 910001)",
        where_a: "version_id = 930102 AND label = 'v1'",
        update_set: "label = label",
        insert_a_sql: "INSERT INTO drive_version_labels (version_id, label, created_by) VALUES (930102, 'v2', 910001)",
    },
    TableProbe {
        table: "drive_watches",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_watches (node_id, user_id) VALUES (930101, 910001)",
        where_a: "node_id = 930101 AND user_id = 910001",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO drive_watches (node_id, user_id) VALUES (930101, 910001)",
    },
    TableProbe {
        table: "office_editor_sessions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO office_editor_sessions (id, space_id, file_node_id, base_version_id, provider_id, cohort_key, lease_expires_at) VALUES ('91000100-0000-4000-8000-000000000060'::uuid, 930100, 930101, 930102, 'rls-546e-office', 'cohort-a', now() + interval '1 hour')",
        where_a: "id = '91000100-0000-4000-8000-000000000060'::uuid",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO office_editor_sessions (id, space_id, file_node_id, base_version_id, provider_id, cohort_key, lease_expires_at) VALUES ('91000100-0000-4000-8000-000000000061'::uuid, 930100, 930101, 930102, 'rls-546e-office', 'cohort-ins', now() + interval '1 hour')",
    },
    TableProbe {
        table: "office_editor_launches",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO office_editor_launches (id, session_id, space_id, file_node_id, actor_user_id, device_id, action, fence_generation, expires_at) VALUES ('91000100-0000-4000-8000-000000000062'::uuid, '91000100-0000-4000-8000-000000000060'::uuid, 930100, 930101, 910001, 'dev-a', 'edit_online', 1, now() + interval '1 hour')",
        where_a: "id = '91000100-0000-4000-8000-000000000062'::uuid",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO office_editor_launches (id, session_id, space_id, file_node_id, actor_user_id, device_id, action, fence_generation, expires_at) VALUES ('91000100-0000-4000-8000-000000000063'::uuid, '91000100-0000-4000-8000-000000000060'::uuid, 930100, 930101, 910001, 'dev-a', 'preview', 1, now() + interval '1 hour')",
    },
    TableProbe {
        table: "office_save_receipts",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO office_save_receipts (id, session_id, space_id, file_node_id, provider_id, operation_key, expected_base_id, content_sha256, response_class) OVERRIDING SYSTEM VALUE VALUES (930110, '91000100-0000-4000-8000-000000000060'::uuid, 930100, 930101, 'rls-546e-office', 'op-a1', 930102, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'accepted')",
        where_a: "id = 930110",
        update_set: "response_class = response_class",
        insert_a_sql: "INSERT INTO office_save_receipts (id, session_id, space_id, file_node_id, provider_id, operation_key, expected_base_id, content_sha256, response_class) OVERRIDING SYSTEM VALUE VALUES (939110, '91000100-0000-4000-8000-000000000060'::uuid, 930100, 930101, 'rls-546e-office', 'op-a2', 930102, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'accepted')",
    },
    TableProbe {
        table: "office_user_preferences",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO office_user_preferences (user_id, device_id, file_family, provider_id, mode) VALUES (910001, 'dev-a', 'word', 'rls-546e-office', 'edit_online')",
        where_a: "user_id = 910001 AND device_id = 'dev-a' AND file_family = 'word'",
        update_set: "mode = mode",
        insert_a_sql: "INSERT INTO office_user_preferences (user_id, device_id, file_family, provider_id, mode) VALUES (910001, 'dev-a', 'sheet', 'rls-546e-office', 'edit_online')",
    },
    // --- 8. Chat (13 tables) ---
    TableProbe {
        table: "chat_channels",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (930200, 'channel', 'private', 910001)",
        where_a: "id = 930200",
        update_set: "visibility = visibility",
        insert_a_sql: "INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (939200, 'channel', 'private', 910001)",
    },
    TableProbe {
        table: "chat_channel_members",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_channel_members (channel_id, user_id, role) VALUES (930200, 910001, 'owner')",
        where_a: "channel_id = 930200 AND user_id = 910001",
        update_set: "role = role",
        insert_a_sql: "INSERT INTO chat_channel_members (channel_id, user_id, role) VALUES (930200, 910003, 'member')",
    },
    TableProbe {
        table: "chat_messages",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_messages (id, channel_id, seq, author_id, body) OVERRIDING SYSTEM VALUE VALUES (930201, 930200, 1, 910001, 'hello a')",
        where_a: "id = 930201",
        update_set: "body = body",
        insert_a_sql: "INSERT INTO chat_messages (id, channel_id, seq, author_id, body) OVERRIDING SYSTEM VALUE VALUES (939201, 930200, 2, 910001, 'hello ins')",
    },
    TableProbe {
        table: "chat_mentions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_mentions (message_id, mentioned_user_id) VALUES (930201, 910001)",
        where_a: "message_id = 930201 AND mentioned_user_id = 910001",
        update_set: "mentioned_user_id = mentioned_user_id",
        insert_a_sql: "INSERT INTO chat_mentions (message_id, mentioned_user_id) VALUES (930201, 910001)",
    },
    TableProbe {
        table: "chat_message_attachments",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_message_attachments (id, channel_id, message_id, file_node_id, version_id, filename, size_bytes) OVERRIDING SYSTEM VALUE VALUES (930202, 930200, 930201, 930101, 930102, 'doc-a.txt', 64)",
        where_a: "id = 930202",
        update_set: "filename = filename",
        insert_a_sql: "INSERT INTO chat_message_attachments (id, channel_id, message_id, file_node_id, version_id, filename, size_bytes) OVERRIDING SYSTEM VALUE VALUES (939202, 930200, 930201, 930101, 930102, 'doc-ins.txt', 64)",
    },
    TableProbe {
        table: "chat_message_pins",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_message_pins (channel_id, message_id, pinned_by) VALUES (930200, 930201, 910001)",
        where_a: "channel_id = 930200 AND message_id = 930201",
        update_set: "pinned_by = pinned_by",
        insert_a_sql: "INSERT INTO chat_message_pins (channel_id, message_id, pinned_by) VALUES (930200, 930201, 910001)",
    },
    TableProbe {
        table: "chat_message_reactions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_message_reactions (message_id, user_id, emoji) VALUES (930201, 910001, '+1')",
        where_a: "message_id = 930201 AND user_id = 910001 AND emoji = '+1'",
        update_set: "emoji = emoji",
        insert_a_sql: "INSERT INTO chat_message_reactions (message_id, user_id, emoji) VALUES (930201, 910001, 'ok')",
    },
    TableProbe {
        table: "chat_message_revisions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_message_revisions (id, channel_id, message_id, prior_body, edited_by) OVERRIDING SYSTEM VALUE VALUES (930203, 930200, 930201, 'old body', 910001)",
        where_a: "id = 930203",
        update_set: "prior_body = prior_body",
        insert_a_sql: "INSERT INTO chat_message_revisions (id, channel_id, message_id, prior_body, edited_by) OVERRIDING SYSTEM VALUE VALUES (939203, 930200, 930201, 'old ins', 910001)",
    },
    TableProbe {
        table: "chat_polls",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_polls (id, message_id, channel_id, question, created_by) OVERRIDING SYSTEM VALUE VALUES (930204, 930201, 930200, 'q?', 910001)",
        where_a: "id = 930204",
        update_set: "question = question",
        insert_a_sql: "INSERT INTO chat_polls (id, message_id, channel_id, question, created_by) OVERRIDING SYSTEM VALUE VALUES (939204, 930201, 930200, 'q2?', 910001)",
    },
    TableProbe {
        table: "chat_poll_options",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_poll_options (id, poll_id, ordinal, label) OVERRIDING SYSTEM VALUE VALUES (930205, 930204, 1, 'Yes')",
        where_a: "id = 930205",
        update_set: "label = label",
        insert_a_sql: "INSERT INTO chat_poll_options (id, poll_id, ordinal, label) OVERRIDING SYSTEM VALUE VALUES (939205, 930204, 2, 'No')",
    },
    TableProbe {
        table: "chat_poll_votes",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_poll_votes (poll_id, option_id, user_id) VALUES (930204, 930205, 910001)",
        where_a: "poll_id = 930204 AND option_id = 930205 AND user_id = 910001",
        update_set: "option_id = option_id",
        insert_a_sql: "INSERT INTO chat_poll_votes (poll_id, option_id, user_id) VALUES (930204, 930205, 910001)",
    },
    TableProbe {
        table: "chat_saved_messages",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_saved_messages (user_id, message_id) VALUES (910001, 930201)",
        where_a: "user_id = 910001 AND message_id = 930201",
        update_set: "message_id = message_id",
        insert_a_sql: "INSERT INTO chat_saved_messages (user_id, message_id) VALUES (910001, 930201)",
    },
    TableProbe {
        table: "chat_send_counters",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO chat_send_counters (user_id, window_start) VALUES (910001, '2026-06-15T12:00:00Z'::timestamptz)",
        where_a: "user_id = 910001",
        update_set: "window_start = window_start",
        insert_a_sql: "INSERT INTO chat_send_counters (user_id, window_start) VALUES (910001, '2026-06-16T12:00:00Z'::timestamptz)",
    },
    // --- 9. Meetings (13 tables) + drive_meet_history_events ---
    TableProbe {
        table: "meetings",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserAuthSelectOwnerWrite,
        seed_sql: "INSERT INTO meetings (id, title, owner_user_id, room_name, slug) OVERRIDING SYSTEM VALUE VALUES (930300, 'Meet A', 910001, '91000100-0000-4000-8000-0000000000a0'::uuid, 'rls-546e-meet-a')",
        where_a: "id = 930300",
        update_set: "title = title",
        insert_a_sql: "INSERT INTO meetings (id, title, owner_user_id, room_name, slug) OVERRIDING SYSTEM VALUE VALUES (939300, 'Meet Ins', 910001, '91000100-0000-4000-8000-0000000000a1'::uuid, 'rls-546e-meet-ins')",
    },
    TableProbe {
        table: "meeting_participants",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_participants (id, meeting_id, identity, user_id, role) OVERRIDING SYSTEM VALUE VALUES (930301, 930300, 'u:910001', 910001, 'host')",
        where_a: "id = 930301",
        update_set: "role = role",
        insert_a_sql: "INSERT INTO meeting_participants (id, meeting_id, identity, user_id, role) OVERRIDING SYSTEM VALUE VALUES (939301, 930300, 'u:910003', 910003, 'member')",
    },
    TableProbe {
        table: "meeting_breakouts",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_breakouts (id, meeting_id, idx, room_name) OVERRIDING SYSTEM VALUE VALUES (930302, 930300, 1, '91000100-0000-4000-8000-0000000000a2'::uuid)",
        where_a: "id = 930302",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO meeting_breakouts (id, meeting_id, idx, room_name) OVERRIDING SYSTEM VALUE VALUES (939302, 930300, 2, '91000100-0000-4000-8000-0000000000a3'::uuid)",
    },
    TableProbe {
        table: "meeting_join_requests",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_join_requests (id, meeting_id, display_name) OVERRIDING SYSTEM VALUE VALUES (930303, 930300, 'Guest A')",
        where_a: "id = 930303",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO meeting_join_requests (id, meeting_id, display_name) OVERRIDING SYSTEM VALUE VALUES (939303, 930300, 'Guest Ins')",
    },
    TableProbe {
        table: "meeting_presentations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_presentations (id, meeting_id, drive_node_id, drive_version_id, source_sha256, manifest_digest, initiated_by) OVERRIDING SYSTEM VALUE VALUES (930304, 930300, 930101, 930102, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001)",
        where_a: "id = 930304",
        update_set: "status = status",
        insert_a_sql: "INSERT INTO meeting_presentations (id, meeting_id, drive_node_id, drive_version_id, source_sha256, manifest_digest, initiated_by) OVERRIDING SYSTEM VALUE VALUES (939304, 930300, 930101, 930102, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 910001)",
    },
    TableProbe {
        table: "meeting_presentation_annotations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_presentation_annotations (id, presentation_id, meeting_id, checkpoint_seq, presenter_generation, snapshot_path, content, content_sha256, byte_size) OVERRIDING SYSTEM VALUE VALUES (930305, 930304, 930300, 1, 1, 'annotations/p1-s1.json', '{}', encode(sha256(convert_to('{}','UTF8')),'hex'), 2)",
        where_a: "id = 930305",
        update_set: "checkpoint_seq = checkpoint_seq",
        insert_a_sql: "INSERT INTO meeting_presentation_annotations (id, presentation_id, meeting_id, checkpoint_seq, presenter_generation, snapshot_path, content, content_sha256, byte_size) OVERRIDING SYSTEM VALUE VALUES (939305, 930304, 930300, 2, 1, 'annotations/p1-s2.json', '{}', encode(sha256(convert_to('{}','UTF8')),'hex'), 2)",
    },
    TableProbe {
        table: "meeting_presentation_events",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_presentation_events (id, presentation_id, meeting_id, checkpoint_seq, presenter_generation, kind) OVERRIDING SYSTEM VALUE VALUES (930306, 930304, 930300, 1, 1, 'start')",
        where_a: "id = 930306",
        update_set: "kind = kind",
        insert_a_sql: "INSERT INTO meeting_presentation_events (id, presentation_id, meeting_id, checkpoint_seq, presenter_generation, kind) OVERRIDING SYSTEM VALUE VALUES (939306, 930304, 930300, 2, 1, 'ready')",
    },
    TableProbe {
        table: "meeting_recordings",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_recordings (id, meeting_id, started_by, egress_id) OVERRIDING SYSTEM VALUE VALUES (930307, 930300, 910001, 'rls-546e-eg-a')",
        where_a: "id = 930307",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO meeting_recordings (id, meeting_id, started_by, egress_id) OVERRIDING SYSTEM VALUE VALUES (939307, 930300, 910001, 'rls-546e-eg-ins')",
    },
    TableProbe {
        table: "meeting_semantic_recordings",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_semantic_recordings (id, meeting_id, started_by) OVERRIDING SYSTEM VALUE VALUES (930308, 930300, 910001)",
        where_a: "id = 930308",
        update_set: "rec_state = rec_state",
        insert_a_sql: "INSERT INTO meeting_semantic_recordings (id, meeting_id, started_by) OVERRIDING SYSTEM VALUE VALUES (939308, 930300, 910001)",
    },
    TableProbe {
        table: "meeting_local_capture_leases",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_local_capture_leases (id, meeting_id, recording_id, device_id, surfaces, producer, heartbeat_seconds, expires_at, started_by) OVERRIDING SYSTEM VALUE VALUES (930309, 930300, 930308, 'dev-a', '[\"audio\"]'::jsonb, '{}'::jsonb, 10, now() + interval '1 hour', 910001)",
        where_a: "id = 930309",
        update_set: "heartbeat_seconds = heartbeat_seconds",
        insert_a_sql: "INSERT INTO meeting_local_capture_leases (id, meeting_id, recording_id, device_id, surfaces, producer, heartbeat_seconds, expires_at, started_by) OVERRIDING SYSTEM VALUE VALUES (939309, 930300, 930308, 'dev-ins', '[\"audio\"]'::jsonb, '{}'::jsonb, 10, now() + interval '1 hour', 910001)",
    },
    TableProbe {
        table: "meeting_semantic_children",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_semantic_children (id, recording_id, child) OVERRIDING SYSTEM VALUE VALUES (930310, 930308, 'manifest.json')",
        where_a: "id = 930310",
        update_set: "child_state = child_state",
        insert_a_sql: "INSERT INTO meeting_semantic_children (id, recording_id, child) OVERRIDING SYSTEM VALUE VALUES (939310, 930308, 'timeline.ndjson')",
    },
    TableProbe {
        table: "meeting_semantic_exports",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_semantic_exports (id, recording_id, generation) OVERRIDING SYSTEM VALUE VALUES (930311, 930308, 1)",
        where_a: "id = 930311",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO meeting_semantic_exports (id, recording_id, generation) OVERRIDING SYSTEM VALUE VALUES (939311, 930308, 2)",
    },
    TableProbe {
        table: "meeting_semantic_segments",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO meeting_semantic_segments (id, recording_id, seq, state, start_ms, end_ms, wall_start_unix_ms, wall_end_unix_ms) OVERRIDING SYSTEM VALUE VALUES (930312, 930308, 1, 'capturing', 0, 1000, 1700000000000, 1700000001000)",
        where_a: "id = 930312",
        update_set: "seq = seq",
        insert_a_sql: "INSERT INTO meeting_semantic_segments (id, recording_id, seq, state, start_ms, end_ms, wall_start_unix_ms, wall_end_unix_ms) OVERRIDING SYSTEM VALUE VALUES (939312, 930308, 2, 'capturing', 1000, 2000, 1700000001000, 1700000002000)",
    },
    TableProbe {
        table: "drive_meet_history_events",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO drive_meet_history_events (id, source_kind, source_id, meeting_id, state, space_id, drive_node_id, drive_version_id, audit_id, audit_action) OVERRIDING SYSTEM VALUE VALUES (930313, 'presentation.pinned', 930304, 930300, 'emitted', 930100, 930101, 930102, 930108, 'pin')",
        where_a: "id = 930313",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO drive_meet_history_events (id, source_kind, source_id, meeting_id, state, space_id, drive_node_id, drive_version_id, audit_id, audit_action) OVERRIDING SYSTEM VALUE VALUES (939313, 'annotation.committed', 930305, 930300, 'emitted', 930100, 930101, 930102, 930108, 'ann')",
    },
    // --- 10. Devices, Auth, Sessions, MFA, Push, Webhooks, User Settings ---
    TableProbe {
        table: "devices",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO devices (id, user_id, fingerprint) VALUES (930400, 910001, 'fp-rls-a')",
        where_a: "id = 930400",
        update_set: "fingerprint = fingerprint",
        insert_a_sql: "INSERT INTO devices (id, user_id, fingerprint) VALUES (939400, 910001, 'fp-rls-ins')",
    },
    TableProbe {
        table: "device_enroll_events",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO device_enroll_events (id, device_id) OVERRIDING SYSTEM VALUE VALUES (930401, 930400)",
        where_a: "id = 930401",
        update_set: "device_id = device_id",
        insert_a_sql: "INSERT INTO device_enroll_events (id, device_id) OVERRIDING SYSTEM VALUE VALUES (939401, 930400)",
    },
    TableProbe {
        table: "device_events",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO device_events (id, device_id, event_type) VALUES (930402, 930400, 'checkin')",
        where_a: "id = 930402",
        update_set: "event_type = event_type",
        insert_a_sql: "INSERT INTO device_events (id, device_id, event_type) VALUES (939402, 930400, 'checkin')",
    },
    TableProbe {
        table: "device_policy",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO device_policy (id, device_id, policy_key, policy_value) VALUES (930403, 930400, 'k1', 'v1')",
        where_a: "id = 930403",
        update_set: "policy_value = policy_value",
        insert_a_sql: "INSERT INTO device_policy (id, device_id, policy_key, policy_value) VALUES (939403, 930400, 'k2', 'v2')",
    },
    TableProbe {
        table: "device_registry",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO device_registry (id, user_id, device_hash) VALUES (930404, 910001, 'dh-rls-a')",
        where_a: "id = 930404",
        update_set: "trust_tier = trust_tier",
        insert_a_sql: "INSERT INTO device_registry (id, user_id, device_hash) VALUES (939404, 910001, 'dh-rls-ins')",
    },
    TableProbe {
        table: "user_devices",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (930405, 910001, 'Laptop A', 'desktop')",
        where_a: "id = 930405",
        update_set: "device_name = device_name",
        insert_a_sql: "INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (939405, 910001, 'Laptop Ins', 'desktop')",
    },
    TableProbe {
        table: "managed_devices",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO managed_devices (device_hash, user_id) VALUES ('md-rls-a', 910001)",
        where_a: "device_hash = 'md-rls-a'",
        update_set: "compliance_status = compliance_status",
        insert_a_sql: "INSERT INTO managed_devices (device_hash, user_id) VALUES ('md-rls-ins', 910001)",
    },
    TableProbe {
        table: "mdm_device_state",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mdm_device_state (device_id, user_id, platform, compliance_status) VALUES ('91000100-0000-4000-8000-000000000070'::uuid, 910001, 'ios', 'compliant')",
        where_a: "device_id = '91000100-0000-4000-8000-000000000070'::uuid",
        update_set: "platform = platform",
        insert_a_sql: "INSERT INTO mdm_device_state (device_id, user_id, platform, compliance_status) VALUES ('91000100-0000-4000-8000-000000000071'::uuid, 910001, 'ios', 'compliant')",
    },
    TableProbe {
        table: "app_passwords",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO app_passwords (id, user_id, name, token_hash) VALUES (930410, 910001, 'ap-a', 'ap-hash-a')",
        where_a: "id = 930410",
        update_set: "name = name",
        insert_a_sql: "INSERT INTO app_passwords (id, user_id, name, token_hash) VALUES (939410, 910001, 'ap-ins', 'ap-hash-ins')",
    },
    TableProbe {
        table: "sessions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-a', 910001, 'sess-tok-rls-a', now() + interval '1 day')",
        where_a: "id = 'sess-rls-a'",
        update_set: "expires_at = expires_at",
        insert_a_sql: "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-ins', 910001, 'sess-tok-rls-ins', now() + interval '1 day')",
    },
    TableProbe {
        table: "session_activity",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO session_activity (jti, user_id) VALUES ('jti-rls-a', 910001)",
        where_a: "jti = 'jti-rls-a'",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO session_activity (jti, user_id) VALUES ('jti-rls-ins', 910001)",
    },
    TableProbe {
        table: "session_revocations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (930412, 910001, 'all', 'rls test', now() + interval '1 day')",
        where_a: "id = 930412",
        update_set: "reason = reason",
        insert_a_sql: "INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (939412, 910001, 'all', 'rls ins', now() + interval '1 day')",
    },
    TableProbe {
        table: "oauth_tokens",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO oauth_tokens (id, user_id, token_hash, token_type) VALUES (930413, 910001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 'access')",
        where_a: "id = 930413",
        update_set: "token_type = token_type",
        insert_a_sql: "INSERT INTO oauth_tokens (id, user_id, token_hash, token_type) VALUES (939413, 910001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 'access')",
    },
    TableProbe {
        table: "oidc_auth_requests",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO oidc_auth_requests (id, client_id, user_id, redirect_uri, state, scopes) VALUES ('oidc-req-rls-a', 'rls-546e-oidc-client', 910001, 'https://rls-matrix-546e.test/cb', 'st-a', ARRAY['openid'])",
        where_a: "id = 'oidc-req-rls-a'",
        update_set: "state = state",
        insert_a_sql: "INSERT INTO oidc_auth_requests (id, client_id, user_id, redirect_uri, state, scopes) VALUES ('oidc-req-rls-ins', 'rls-546e-oidc-client', 910001, 'https://rls-matrix-546e.test/cb', 'st-ins', ARRAY['openid'])",
    },
    TableProbe {
        table: "oidc_tokens",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at) VALUES ('oidc-tok-rls-a', 'rls-546e-oidc-client', 910001, 'sub-a', ARRAY['openid'], now() + interval '1 hour')",
        where_a: "id = 'oidc-tok-rls-a'",
        update_set: "subject = subject",
        insert_a_sql: "INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at) VALUES ('oidc-tok-rls-ins', 'rls-546e-oidc-client', 910001, 'sub-ins', ARRAY['openid'], now() + interval '1 hour')",
    },
    TableProbe {
        table: "passkey_credentials",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO passkey_credentials (id, user_id, public_key) VALUES (decode('a1a1a1a1','hex'), 910001, decode('010203','hex'))",
        where_a: "id = decode('a1a1a1a1','hex')",
        update_set: "public_key = public_key",
        insert_a_sql: "INSERT INTO passkey_credentials (id, user_id, public_key) VALUES (decode('a2a2a2a2','hex'), 910001, decode('010203','hex'))",
    },
    TableProbe {
        table: "password_history",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO password_history (id, user_id, password_hash) VALUES (930414, 910001, 'hash-a')",
        where_a: "id = 930414",
        update_set: "password_hash = password_hash",
        insert_a_sql: "INSERT INTO password_history (id, user_id, password_hash) VALUES (939414, 910001, 'hash-ins')",
    },
    TableProbe {
        table: "push_devices",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO push_devices (id, user_id, push_provider, push_token_enc) VALUES (930415, 910001, 'webpush', decode('010203','hex'))",
        where_a: "id = 930415",
        update_set: "push_provider = push_provider",
        insert_a_sql: "INSERT INTO push_devices (id, user_id, push_provider, push_token_enc) VALUES (939415, 910001, 'webpush', decode('040506','hex'))",
    },
    TableProbe {
        table: "push_mfa_challenges",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO push_mfa_challenges (id, user_id, challenge_code, nonce, expires_at) VALUES (930416, 910001, '123456', decode('010203','hex'), now() + interval '5 minutes')",
        where_a: "id = 930416",
        update_set: "challenge_code = challenge_code",
        insert_a_sql: "INSERT INTO push_mfa_challenges (id, user_id, challenge_code, nonce, expires_at) VALUES (939416, 910001, '654321', decode('040506','hex'), now() + interval '5 minutes')",
    },
    TableProbe {
        table: "mfa_reauth_step_ups",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO mfa_reauth_step_ups (token_hash, user_id, session_jti, expires_at, operation, proof_method, bound_factor_generation) VALUES ('mfa-reauth-a', 910001, 'jti-a', now() + interval '5 minutes', 'totp', 'password', 1)",
        where_a: "token_hash = 'mfa-reauth-a'",
        update_set: "operation = operation",
        insert_a_sql: "INSERT INTO mfa_reauth_step_ups (token_hash, user_id, session_jti, expires_at, operation, proof_method, bound_factor_generation) VALUES ('mfa-reauth-ins', 910001, 'jti-a', now() + interval '5 minutes', 'totp', 'password', 1)",
    },
    TableProbe {
        table: "totp_counter_claims",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO totp_counter_claims (user_id, secret_hash, last_counter) VALUES (910001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 1)",
        where_a: "user_id = 910001",
        update_set: "last_counter = last_counter",
        insert_a_sql: "INSERT INTO totp_counter_claims (user_id, secret_hash, last_counter) VALUES (910001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 2)",
    },
    TableProbe {
        table: "totp_pending_enrollments",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO totp_pending_enrollments (id, user_id, secret_enc, staged_by_jti, expires_at) VALUES ('91000100-0000-4000-8000-000000000078'::uuid, 910001, decode('010203','hex'), 'jti-a', now() + interval '10 minutes')",
        where_a: "id = '91000100-0000-4000-8000-000000000078'::uuid",
        update_set: "staged_by_jti = staged_by_jti",
        insert_a_sql: "INSERT INTO totp_pending_enrollments (id, user_id, secret_enc, staged_by_jti, expires_at) VALUES ('91000100-0000-4000-8000-000000000079'::uuid, 910001, decode('040506','hex'), 'jti-ins', now() + interval '10 minutes')",
    },
    TableProbe {
        table: "totp_removal_step_ups",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO totp_removal_step_ups (token_hash, user_id, session_jti, expires_at) VALUES ('totp-rem-a', 910001, 'jti-a', now() + interval '5 minutes')",
        where_a: "token_hash = 'totp-rem-a'",
        update_set: "session_jti = session_jti",
        insert_a_sql: "INSERT INTO totp_removal_step_ups (token_hash, user_id, session_jti, expires_at) VALUES ('totp-rem-ins', 910001, 'jti-ins', now() + interval '5 minutes')",
    },
    TableProbe {
        table: "webauthn_ceremonies",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO webauthn_ceremonies (challenge_hash, user_id, kind, operation, session_jti, expires_at) VALUES ('wa-ch-a', 910001, 'registration', 'add', 'jti-a', now() + interval '5 minutes')",
        where_a: "challenge_hash = 'wa-ch-a'",
        update_set: "operation = operation",
        insert_a_sql: "INSERT INTO webauthn_ceremonies (challenge_hash, user_id, kind, operation, session_jti, expires_at) VALUES ('wa-ch-ins', 910001, 'registration', 'add', 'jti-ins', now() + interval '5 minutes')",
    },
    TableProbe {
        table: "webauthn_login_replays",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO webauthn_login_replays (user_id, challenge_hash) VALUES (910001, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'))",
        where_a: "user_id = 910001 AND challenge_hash = decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex')",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO webauthn_login_replays (user_id, challenge_hash) VALUES (910001, decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'))",
    },
    TableProbe {
        table: "login_events",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO login_events (id, occurred_at, user_id, success) VALUES (930418, now(), 910001, TRUE)",
        where_a: "id = 930418",
        update_set: "success = success",
        insert_a_sql: "INSERT INTO login_events (id, occurred_at, user_id, success) VALUES (939418, now(), 910001, TRUE)",
    },
    TableProbe {
        table: "identity_auth_link_elevations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO identity_auth_link_elevations (flow_id, user_id, session_jti, session_hash, kind, provider_key, expires_at) VALUES ('91000100-0000-4000-8000-000000000080'::uuid, 910001, 'jti-a', decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'), 'oidc', 'prov-a', now() + interval '5 minutes')",
        where_a: "flow_id = '91000100-0000-4000-8000-000000000080'::uuid",
        update_set: "provider_key = provider_key",
        insert_a_sql: "INSERT INTO identity_auth_link_elevations (flow_id, user_id, session_jti, session_hash, kind, provider_key, expires_at) VALUES ('91000100-0000-4000-8000-000000000081'::uuid, 910001, 'jti-ins', decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'), 'oidc', 'prov-a', now() + interval '5 minutes')",
    },
    TableProbe {
        table: "identity_media_admissions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::DefaultDeny,
        seed_sql: "INSERT INTO identity_media_admissions (user_id, room_name, identity, expires_at) VALUES (910001, 'room-a', 'u:910001', now() + interval '30 seconds')",
        where_a: "user_id = 910001 AND room_name = 'room-a' AND identity = 'u:910001'",
        update_set: "room_name = room_name",
        insert_a_sql: "INSERT INTO identity_media_admissions (user_id, room_name, identity, expires_at) VALUES (910001, 'room-ins', 'u:910001', now() + interval '30 seconds')",
    },
    TableProbe {
        table: "terms_of_use_acceptance",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO terms_of_use_acceptance (user_id, tou_id, version) VALUES (910001, 900020, 1)",
        where_a: "user_id = 910001 AND tou_id = 900020",
        update_set: "version = version",
        insert_a_sql: "INSERT INTO terms_of_use_acceptance (user_id, tou_id, version) VALUES (910001, 900021, 1)",
    },
    TableProbe {
        table: "focus_sender_overrides",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO focus_sender_overrides (user_id, sender, focused) VALUES (910001, 's1@rls-matrix-546e.test', TRUE)",
        where_a: "user_id = 910001 AND sender = 's1@rls-matrix-546e.test'",
        update_set: "focused = focused",
        insert_a_sql: "INSERT INTO focus_sender_overrides (user_id, sender, focused) VALUES (910001, 's2@rls-matrix-546e.test', TRUE)",
    },
    TableProbe {
        table: "vip_senders",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO vip_senders (user_id, sender_email) VALUES (910001, 'vip1@rls-matrix-546e.test')",
        where_a: "user_id = 910001 AND sender_email = 'vip1@rls-matrix-546e.test'",
        update_set: "sender_email = sender_email",
        insert_a_sql: "INSERT INTO vip_senders (user_id, sender_email) VALUES (910001, 'vip2@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "sender_control_operations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO sender_control_operations (operation_id, user_id, generation, sender_address, sender_digest, action, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000090'::uuid, 910001, 1, 'sc@rls-matrix-546e.test', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'vip', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
        where_a: "operation_id = '91000100-0000-4000-8000-000000000090'::uuid",
        update_set: "action = action",
        insert_a_sql: "INSERT INTO sender_control_operations (operation_id, user_id, generation, sender_address, sender_digest, action, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000091'::uuid, 910001, 2, 'sc2@rls-matrix-546e.test', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'vip', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '{}'::jsonb)",
    },
    TableProbe {
        table: "sender_control_state",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO sender_control_state (user_id) VALUES (910001) ON CONFLICT (user_id) DO NOTHING",
        where_a: "user_id = 910001",
        update_set: "generation = generation",
        insert_a_sql: "INSERT INTO sender_control_state (user_id) VALUES (910001)",
    },
    TableProbe {
        table: "sender_list_operations",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO sender_list_operations (operation_id, user_id, generation, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000092'::uuid, 910001, 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{}'::jsonb)",
        where_a: "operation_id = '91000100-0000-4000-8000-000000000092'::uuid",
        update_set: "generation = generation",
        insert_a_sql: "INSERT INTO sender_list_operations (operation_id, user_id, generation, request_digest, result) VALUES ('91000100-0000-4000-8000-000000000093'::uuid, 910001, 2, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '{}'::jsonb)",
    },
    TableProbe {
        table: "user_app_entitlements",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_app_entitlements (user_id, app) VALUES (910001, 'mail')",
        where_a: "user_id = 910001 AND app = 'mail'",
        update_set: "app = app",
        insert_a_sql: "INSERT INTO user_app_entitlements (user_id, app) VALUES (910001, 'chat')",
    },
    TableProbe {
        table: "user_image_allow",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_image_allow (user_id, sender) VALUES (910001, 'img1@rls-matrix-546e.test')",
        where_a: "user_id = 910001 AND sender = 'img1@rls-matrix-546e.test'",
        update_set: "sender = sender",
        insert_a_sql: "INSERT INTO user_image_allow (user_id, sender) VALUES (910001, 'img2@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "user_imap_settings",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_imap_settings (user_id) VALUES (910001)",
        where_a: "user_id = 910001",
        update_set: "user_id = user_id",
        insert_a_sql: "INSERT INTO user_imap_settings (user_id) VALUES (910001)",
    },
    TableProbe {
        table: "user_notification_prefs",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_notification_prefs (id, user_id, device_fingerprint) VALUES (930420, 910001, '91000100-0000-4000-8000-0000000000b0'::uuid)",
        where_a: "id = 930420",
        update_set: "chat_notifications = chat_notifications",
        insert_a_sql: "INSERT INTO user_notification_prefs (id, user_id, device_fingerprint) VALUES (939420, 910001, '91000100-0000-4000-8000-0000000000b1'::uuid)",
    },
    TableProbe {
        table: "user_risk",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_risk (user_id) VALUES (910001)",
        where_a: "user_id = 910001",
        update_set: "score = score",
        insert_a_sql: "INSERT INTO user_risk (user_id) VALUES (910001)",
    },
    TableProbe {
        table: "user_sender_list",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_sender_list (user_id, sender, list_type) VALUES (910001, 'sl1@rls-matrix-546e.test', 'safe')",
        where_a: "user_id = 910001 AND sender = 'sl1@rls-matrix-546e.test' AND list_type = 'safe'",
        update_set: "sender = sender",
        insert_a_sql: "INSERT INTO user_sender_list (user_id, sender, list_type) VALUES (910001, 'sl2@rls-matrix-546e.test', 'safe')",
    },
    TableProbe {
        table: "user_signatures",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_signatures (id, user_id, alias_email) VALUES (930421, 910001, 'rls_a@rls-matrix-546e.test')",
        where_a: "id = 930421",
        update_set: "alias_email = alias_email",
        insert_a_sql: "INSERT INTO user_signatures (id, user_id, alias_email) VALUES (939421, 910001, 'rls_a2@rls-matrix-546e.test')",
    },
    TableProbe {
        table: "user_smime_certs",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (930422, 910001, 'cert-a', '-----BEGIN CERTIFICATE-----')",
        where_a: "id = 930422",
        update_set: "label = label",
        insert_a_sql: "INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (939422, 910001, 'cert-ins', '-----BEGIN CERTIFICATE-----')",
    },
    TableProbe {
        table: "recipient_smime_certs",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO recipient_smime_certs (id, owner_user_id, email, cert_pem, fingerprint, source) VALUES (930423, 910001, 'rcpt@rls-matrix-546e.test', '-----BEGIN CERTIFICATE-----', 'fp-cert-a', 'imported')",
        where_a: "id = 930423",
        update_set: "source = source",
        insert_a_sql: "INSERT INTO recipient_smime_certs (id, owner_user_id, email, cert_pem, fingerprint, source) VALUES (939423, 910001, 'rcpt2@rls-matrix-546e.test', '-----BEGIN CERTIFICATE-----', 'fp-cert-ins', 'imported')",
    },
    TableProbe {
        table: "user_spam_model",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO user_spam_model (user_id, model_bytes) VALUES (910001, decode('0102','hex'))",
        where_a: "user_id = 910001",
        update_set: "model_bytes = model_bytes",
        insert_a_sql: "INSERT INTO user_spam_model (user_id, model_bytes) VALUES (910001, decode('0304','hex'))",
    },
    TableProbe {
        table: "webhook_subscriptions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (930424, 910001, 'https://rls-matrix-546e.test/hook-a')",
        where_a: "id = 930424",
        update_set: "url = url",
        insert_a_sql: "INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (939424, 910001, 'https://rls-matrix-546e.test/hook-ins')",
    },
    TableProbe {
        table: "ws_subscriptions",
        class: ManifestClass::UserScoped,
        guc_mode: GucMode::UserOnly,
        seed_sql: "INSERT INTO ws_subscriptions (connection_id, session_id, user_id) VALUES ('ws-conn-rls-a', 'sess-a', 910001)",
        where_a: "connection_id = 'ws-conn-rls-a'",
        update_set: "session_id = session_id",
        insert_a_sql: "INSERT INTO ws_subscriptions (connection_id, session_id, user_id) VALUES ('ws-conn-rls-ins', 'sess-ins', 910001)",
    },
];

// ---------------------------------------------------------------------------
// `INSERT ... ON CONFLICT DO NOTHING / DO UPDATE` anti-oracle cases (ARCH-018:51)
// ---------------------------------------------------------------------------

struct OnConflictProbe {
    table: &'static str,
    /// SQL executed as Tenant B attempting `ON CONFLICT DO UPDATE` carrying Tenant A's scope.
    do_update_sql: &'static str,
    /// SQL executed as Tenant B attempting `ON CONFLICT DO NOTHING` carrying Tenant A's scope.
    do_nothing_sql: &'static str,
    /// Positive control: non-colliding `INSERT` carrying Tenant B's OWN scope under `setjoin_app`
    /// (proves `INSERT` is genuinely admitted on own scope, not merely denied by missing INSERT policy).
    own_scope_control_insert_sql: Option<&'static str>,
    /// Positive control: non-colliding `INSERT ... ON CONFLICT ... DO UPDATE` carrying Tenant B's
    /// OWN scope under `setjoin_app` (alongside `ON CONFLICT DO NOTHING`, proves the `ON CONFLICT`
    /// statement itself is genuinely admitted when non-colliding).
    own_scope_control_do_update_sql: Option<&'static str>,
    /// Own-scope anti-oracle `ON CONFLICT DO UPDATE`: Tenant B inserts with Tenant B's OWN
    /// `user_id`/`mailbox_id` colliding with Tenant A's PK or global unique key -> MUST fail `42501`.
    own_scope_do_update_sql: Option<&'static str>,
    /// Own-scope anti-oracle `ON CONFLICT DO NOTHING`: Tenant B inserts with Tenant B's OWN
    /// `user_id`/`mailbox_id` colliding with Tenant A's PK or global unique key -> MUST affect 0 rows
    /// or fail `42501` without mutating Tenant A.
    own_scope_do_nothing_sql: Option<&'static str>,
    /// Owner query returning a text sentinel verifying Tenant A's row was NEVER overwritten.
    verify_owner_sql: &'static str,
    expected_sentinel: &'static str,
}

const ON_CONFLICT_PROBES: &[OnConflictProbe] = &[
    OnConflictProbe {
        table: "users",
        do_update_sql: "INSERT INTO users (id, username, domain_id, email, display_name) VALUES (910001, 'rls_a_user', 900001, 'rls_a@rls-matrix-546e.test', 'PWNED') ON CONFLICT (id) DO UPDATE SET display_name = 'PWNED'",
        do_nothing_sql: "INSERT INTO users (id, username, domain_id, email, display_name) VALUES (910001, 'rls_a_user', 900001, 'rls_a@rls-matrix-546e.test', 'PWNED') ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: None,
        own_scope_do_nothing_sql: None,
        verify_owner_sql: "SELECT display_name FROM users WHERE id = 910001",
        expected_sentinel: "Tenant A",
    },
    OnConflictProbe {
        table: "mailboxes",
        do_update_sql: "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920001, 910001, 900001, 'rls_a@rls-matrix-546e.test', 'PWNED', TRUE) ON CONFLICT (id) DO UPDATE SET display_name = 'PWNED'",
        do_nothing_sql: "INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920001, 910001, 900001, 'rls_a@rls-matrix-546e.test', 'PWNED', TRUE) ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: Some("INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920001, 910002, 900001, 'rls_b_collide@rls-matrix-546e.test', 'PWNED', FALSE) ON CONFLICT (id) DO UPDATE SET display_name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, is_primary) VALUES (920001, 910002, 900001, 'rls_b_collide@rls-matrix-546e.test', 'PWNED', FALSE) ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT display_name FROM mailboxes WHERE id = 920001",
        expected_sentinel: "Tenant A Mailbox",
    },
    OnConflictProbe {
        table: "tags",
        do_update_sql: "INSERT INTO tags (mailbox_id, name, color) VALUES (920001, 'rls-tag-a', '#000000') ON CONFLICT (mailbox_id, name) DO UPDATE SET color = '#000000'",
        do_nothing_sql: "INSERT INTO tags (mailbox_id, name) VALUES (920001, 'rls-tag-a') ON CONFLICT (mailbox_id, name) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO tags (id, mailbox_id, name) VALUES (939002, 920002, 'rls-tag-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO tags (id, mailbox_id, name) VALUES (939002, 920002, 'rls-tag-b-ctrl') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"),
        own_scope_do_update_sql: Some("INSERT INTO tags (id, mailbox_id, name, color) VALUES (930002, 920002, 'rls-tag-b-collide', '#000000') ON CONFLICT (id) DO UPDATE SET name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO tags (id, mailbox_id, name) VALUES (930002, 920002, 'rls-tag-b-collide') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT name FROM tags WHERE id = 930002",
        expected_sentinel: "rls-tag-a",
    },
    OnConflictProbe {
        table: "contacts",
        do_update_sql: "INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES (930030, 'vcard-rls-a', 'PWNED') ON CONFLICT (addressbook_id, vcard_uid) DO UPDATE SET display_name = 'PWNED'",
        do_nothing_sql: "INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES (930030, 'vcard-rls-a', 'PWNED') ON CONFLICT (addressbook_id, vcard_uid) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (939031, 930039, 'vcard-rls-b-ctrl', 'Contact B')"),
        own_scope_control_do_update_sql: Some("INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (939031, 930039, 'vcard-rls-b-ctrl', 'Contact B') ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name"),
        own_scope_do_update_sql: Some("INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (930031, 930039, 'vcard-rls-b-col', 'PWNED') ON CONFLICT (id) DO UPDATE SET display_name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO contacts (id, addressbook_id, vcard_uid, display_name) VALUES (930031, 930039, 'vcard-rls-b-col', 'PWNED') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT display_name FROM contacts WHERE id = 930031",
        expected_sentinel: "Contact A",
    },
    OnConflictProbe {
        table: "calendars",
        do_update_sql: "INSERT INTO calendars (id, mailbox_id, name) VALUES (930040, 920001, 'PWNED') ON CONFLICT (id) DO UPDATE SET name = 'PWNED'",
        do_nothing_sql: "INSERT INTO calendars (id, mailbox_id, name) VALUES (930040, 920001, 'PWNED') ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO calendars (id, mailbox_id, name) VALUES (939040, 920002, 'cal-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO calendars (id, mailbox_id, name) VALUES (939040, 920002, 'cal-b-ctrl') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"),
        own_scope_do_update_sql: Some("INSERT INTO calendars (id, mailbox_id, name) VALUES (930040, 920002, 'PWNED') ON CONFLICT (id) DO UPDATE SET name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO calendars (id, mailbox_id, name) VALUES (930040, 920002, 'PWNED') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT name FROM calendars WHERE id = 930040",
        expected_sentinel: "cal-a",
    },
    OnConflictProbe {
        table: "folders",
        do_update_sql: "INSERT INTO folders (mailbox_id, name, path) VALUES (920001, 'PWNED', 'RlsInbox') ON CONFLICT (mailbox_id, path) DO UPDATE SET name = 'PWNED'",
        do_nothing_sql: "INSERT INTO folders (mailbox_id, name, path) VALUES (920001, 'PWNED', 'RlsInbox') ON CONFLICT (mailbox_id, path) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO folders (id, mailbox_id, name, path) VALUES (939001, 920002, 'RlsInboxB', 'RlsInboxB')"),
        own_scope_control_do_update_sql: Some("INSERT INTO folders (id, mailbox_id, name, path) VALUES (939001, 920002, 'RlsInboxB', 'RlsInboxB') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"),
        own_scope_do_update_sql: Some("INSERT INTO folders (id, mailbox_id, name, path) VALUES (930001, 920002, 'PWNED', 'RlsInboxBCol') ON CONFLICT (id) DO UPDATE SET name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO folders (id, mailbox_id, name, path) VALUES (930001, 920002, 'PWNED', 'RlsInboxBCol') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT name FROM folders WHERE id = 930001",
        expected_sentinel: "RlsInbox",
    },
    OnConflictProbe {
        table: "email_templates",
        do_update_sql: "INSERT INTO email_templates (mailbox_id, name, subject) VALUES (920001, 'tpl-a', 'PWNED') ON CONFLICT (mailbox_id, name) DO UPDATE SET subject = 'PWNED'",
        do_nothing_sql: "INSERT INTO email_templates (mailbox_id, name) VALUES (920001, 'tpl-a') ON CONFLICT (mailbox_id, name) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO email_templates (id, mailbox_id, name) VALUES (939014, 920002, 'tpl-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO email_templates (id, mailbox_id, name) VALUES (939014, 920002, 'tpl-b-ctrl') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"),
        own_scope_do_update_sql: Some("INSERT INTO email_templates (id, mailbox_id, name, subject) VALUES (930014, 920002, 'tpl-b-col', 'PWNED') ON CONFLICT (id) DO UPDATE SET subject = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO email_templates (id, mailbox_id, name) VALUES (930014, 920002, 'tpl-b-col') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT COALESCE(subject, 'clean') FROM email_templates WHERE id = 930014",
        expected_sentinel: "clean",
    },
    OnConflictProbe {
        table: "signatures",
        do_update_sql: "INSERT INTO signatures (mailbox_id, name, body_text) VALUES (920001, 'sig-a', 'PWNED') ON CONFLICT (mailbox_id, name) DO UPDATE SET body_text = 'PWNED'",
        do_nothing_sql: "INSERT INTO signatures (mailbox_id, name) VALUES (920001, 'sig-a') ON CONFLICT (mailbox_id, name) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO signatures (id, mailbox_id, name) VALUES (939013, 920002, 'sig-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO signatures (id, mailbox_id, name) VALUES (939013, 920002, 'sig-b-ctrl') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name"),
        own_scope_do_update_sql: Some("INSERT INTO signatures (id, mailbox_id, name, body_text) VALUES (930013, 920002, 'sig-b-col', 'PWNED') ON CONFLICT (id) DO UPDATE SET body_text = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO signatures (id, mailbox_id, name) VALUES (930013, 920002, 'sig-b-col') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT COALESCE(body_text, 'clean') FROM signatures WHERE id = 930013",
        expected_sentinel: "clean",
    },
    OnConflictProbe {
        table: "booking_pages",
        do_update_sql: "INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920001, 'rls-546e-bp-a', 'PWNED') ON CONFLICT (slug) DO UPDATE SET title = 'PWNED'",
        do_nothing_sql: "INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920001, 'rls-546e-bp-a', 'PWNED') ON CONFLICT (slug) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920002, 'rls-546e-bp-b-ctrl', 'Booking B')"),
        own_scope_control_do_update_sql: Some("INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920002, 'rls-546e-bp-b-ctrl', 'Booking B') ON CONFLICT (slug) DO UPDATE SET title = EXCLUDED.title"),
        own_scope_do_update_sql: Some("INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920002, 'rls-546e-bp-a', 'PWNED') ON CONFLICT (slug) DO UPDATE SET title = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO booking_pages (mailbox_id, slug, title) VALUES (920002, 'rls-546e-bp-a', 'PWNED') ON CONFLICT (slug) DO NOTHING"),
        verify_owner_sql: "SELECT title FROM booking_pages WHERE id = 930045",
        expected_sentinel: "Booking A",
    },
    OnConflictProbe {
        table: "reminders",
        do_update_sql: "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, title) VALUES (920001, 'task', 1, '2026-06-15T12:00:00Z'::timestamptz, 'PWNED') ON CONFLICT (mailbox_id, source_type, source_id, fire_at) DO UPDATE SET title = 'PWNED'",
        do_nothing_sql: "INSERT INTO reminders (mailbox_id, source_type, source_id, fire_at, title) VALUES (920001, 'task', 1, '2026-06-15T12:00:00Z'::timestamptz, 'PWNED') ON CONFLICT (mailbox_id, source_type, source_id, fire_at) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (939015, 920002, 'task', 2, '2026-06-15T13:00:00Z'::timestamptz, 'rem-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (939015, 920002, 'task', 2, '2026-06-15T13:00:00Z'::timestamptz, 'rem-b-ctrl') ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title"),
        own_scope_do_update_sql: Some("INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (930015, 920002, 'task', 2, '2026-06-15T13:00:00Z'::timestamptz, 'PWNED') ON CONFLICT (id) DO UPDATE SET title = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO reminders (id, mailbox_id, source_type, source_id, fire_at, title) VALUES (930015, 920002, 'task', 2, '2026-06-15T13:00:00Z'::timestamptz, 'PWNED') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT title FROM reminders WHERE id = 930015",
        expected_sentinel: "rem-a",
    },
    OnConflictProbe {
        table: "chat_channels",
        do_update_sql: "INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (930200, 'channel', 'public', 910001) ON CONFLICT (id) DO UPDATE SET visibility = 'public'",
        do_nothing_sql: "INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (930200, 'channel', 'public', 910001) ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: Some("INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (930200, 'channel', 'public', 910002) ON CONFLICT (id) DO UPDATE SET visibility = 'public'"),
        own_scope_do_nothing_sql: Some("INSERT INTO chat_channels (id, kind, visibility, created_by) OVERRIDING SYSTEM VALUE VALUES (930200, 'channel', 'public', 910002) ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT visibility FROM chat_channels WHERE id = 930200",
        expected_sentinel: "private",
    },
    OnConflictProbe {
        table: "chat_messages",
        do_update_sql: "INSERT INTO chat_messages (channel_id, seq, author_id, body) VALUES (930200, 1, 910001, 'PWNED') ON CONFLICT (channel_id, seq) DO UPDATE SET body = 'PWNED'",
        do_nothing_sql: "INSERT INTO chat_messages (channel_id, seq, author_id, body) VALUES (930200, 1, 910001, 'PWNED') ON CONFLICT (channel_id, seq) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: None,
        own_scope_do_nothing_sql: None,
        verify_owner_sql: "SELECT body FROM chat_messages WHERE id = 930201",
        expected_sentinel: "hello a",
    },
    OnConflictProbe {
        table: "drive_nodes",
        do_update_sql: "INSERT INTO drive_nodes (id, space_id, kind, name, created_by) OVERRIDING SYSTEM VALUE VALUES (930101, 930100, 'file', 'PWNED', 910001) ON CONFLICT (space_id, id) DO UPDATE SET name = 'PWNED'",
        do_nothing_sql: "INSERT INTO drive_nodes (id, space_id, kind, name, created_by) OVERRIDING SYSTEM VALUE VALUES (930101, 930100, 'file', 'PWNED', 910001) ON CONFLICT (space_id, id) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: None,
        own_scope_do_nothing_sql: None,
        verify_owner_sql: "SELECT name FROM drive_nodes WHERE id = 930101",
        expected_sentinel: "doc-a.txt",
    },
    OnConflictProbe {
        table: "drive_export_grants",
        do_update_sql: "INSERT INTO drive_export_grants (version_id, space_id, grantee, action, token_hash, minted_by, expires_at) VALUES (930102, 930100, 910001, 'print', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, now() + interval '1 hour') ON CONFLICT (token_hash) DO UPDATE SET action = 'print'",
        do_nothing_sql: "INSERT INTO drive_export_grants (version_id, space_id, grantee, action, token_hash, minted_by, expires_at) VALUES (930102, 930100, 910001, 'print', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 910001, now() + interval '1 hour') ON CONFLICT (token_hash) DO NOTHING",
        own_scope_control_insert_sql: None,
        own_scope_control_do_update_sql: None,
        own_scope_do_update_sql: None,
        own_scope_do_nothing_sql: None,
        verify_owner_sql: "SELECT action FROM drive_export_grants WHERE id = 930109",
        expected_sentinel: "download",
    },
    OnConflictProbe {
        table: "sessions",
        do_update_sql: "INSERT INTO sessions (id, user_id, token_hash, expires_at, auth_method) VALUES ('sess-rls-oc1', 910001, 'sess-tok-rls-a', now() + interval '1 day', 'totp') ON CONFLICT (token_hash) DO UPDATE SET auth_method = 'totp'",
        do_nothing_sql: "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-oc2', 910001, 'sess-tok-rls-a', now() + interval '1 day') ON CONFLICT (token_hash) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-b-ctrl', 910002, 'sess-tok-rls-b-ctrl', now() + interval '1 day')"),
        own_scope_control_do_update_sql: Some("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-b-ctrl', 910002, 'sess-tok-rls-b-ctrl', now() + interval '1 day') ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at"),
        own_scope_do_update_sql: Some("INSERT INTO sessions (id, user_id, token_hash, expires_at, auth_method) VALUES ('sess-rls-oc3', 910002, 'sess-tok-rls-a', now() + interval '1 day', 'totp') ON CONFLICT (token_hash) DO UPDATE SET auth_method = 'totp'"),
        own_scope_do_nothing_sql: Some("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('sess-rls-oc4', 910002, 'sess-tok-rls-a', now() + interval '1 day') ON CONFLICT (token_hash) DO NOTHING"),
        verify_owner_sql: "SELECT COALESCE(auth_method, 'clean') FROM sessions WHERE id = 'sess-rls-a'",
        expected_sentinel: "clean",
    },
    OnConflictProbe {
        table: "webhook_subscriptions",
        do_update_sql: "INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (930424, 910001, 'https://evil.example/pwn') ON CONFLICT (id) DO UPDATE SET url = 'https://evil.example/pwn'",
        do_nothing_sql: "INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (930424, 910001, 'https://evil.example/pwn') ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (939424, 910002, 'https://rls-matrix-546e.test/hook-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (939424, 910002, 'https://rls-matrix-546e.test/hook-b-ctrl') ON CONFLICT (id) DO UPDATE SET url = EXCLUDED.url"),
        own_scope_do_update_sql: Some("INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (930424, 910002, 'https://evil.example/pwn') ON CONFLICT (id) DO UPDATE SET url = 'https://evil.example/pwn'"),
        own_scope_do_nothing_sql: Some("INSERT INTO webhook_subscriptions (id, user_id, url) VALUES (930424, 910002, 'https://evil.example/pwn') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT url FROM webhook_subscriptions WHERE id = 930424",
        expected_sentinel: "https://rls-matrix-546e.test/hook-a",
    },
    OnConflictProbe {
        table: "user_smime_certs",
        do_update_sql: "INSERT INTO user_smime_certs (user_id, label, cert_pem) VALUES (910001, 'cert-a', 'PWNED') ON CONFLICT (user_id, label) DO UPDATE SET cert_pem = 'PWNED'",
        do_nothing_sql: "INSERT INTO user_smime_certs (user_id, label, cert_pem) VALUES (910001, 'cert-a', 'PWNED') ON CONFLICT (user_id, label) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (939422, 910002, 'cert-b-ctrl', '-----BEGIN CERTIFICATE-----B')"),
        own_scope_control_do_update_sql: Some("INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (939422, 910002, 'cert-b-ctrl', '-----BEGIN CERTIFICATE-----B') ON CONFLICT (id) DO UPDATE SET cert_pem = EXCLUDED.cert_pem"),
        own_scope_do_update_sql: Some("INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (930422, 910002, 'cert-b-col', 'PWNED') ON CONFLICT (id) DO UPDATE SET cert_pem = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO user_smime_certs (id, user_id, label, cert_pem) VALUES (930422, 910002, 'cert-b-col', 'PWNED') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT cert_pem FROM user_smime_certs WHERE id = 930422",
        expected_sentinel: "-----BEGIN CERTIFICATE-----",
    },
    OnConflictProbe {
        table: "devices",
        do_update_sql: "INSERT INTO devices (user_id, fingerprint, device_name) VALUES (910001, 'fp-rls-a', 'PWNED') ON CONFLICT (user_id, fingerprint) DO UPDATE SET device_name = 'PWNED'",
        do_nothing_sql: "INSERT INTO devices (user_id, fingerprint) VALUES (910001, 'fp-rls-a') ON CONFLICT (user_id, fingerprint) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO devices (id, user_id, fingerprint) VALUES (939400, 910002, 'fp-rls-b-ctrl')"),
        own_scope_control_do_update_sql: Some("INSERT INTO devices (id, user_id, fingerprint) VALUES (939400, 910002, 'fp-rls-b-ctrl') ON CONFLICT (id) DO UPDATE SET fingerprint = EXCLUDED.fingerprint"),
        own_scope_do_update_sql: Some("INSERT INTO devices (id, user_id, fingerprint, device_name) VALUES (930400, 910002, 'fp-rls-b-col', 'PWNED') ON CONFLICT (id) DO UPDATE SET device_name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO devices (id, user_id, fingerprint) VALUES (930400, 910002, 'fp-rls-b-col') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT COALESCE(device_name, 'clean') FROM devices WHERE id = 930400",
        expected_sentinel: "clean",
    },
    OnConflictProbe {
        table: "user_devices",
        do_update_sql: "INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (930405, 910001, 'PWNED', 'desktop') ON CONFLICT (id) DO UPDATE SET device_name = 'PWNED'",
        do_nothing_sql: "INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (930405, 910001, 'PWNED', 'desktop') ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (939405, 910002, 'Laptop B', 'desktop')"),
        own_scope_control_do_update_sql: Some("INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (939405, 910002, 'Laptop B', 'desktop') ON CONFLICT (id) DO UPDATE SET device_name = EXCLUDED.device_name"),
        own_scope_do_update_sql: Some("INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (930405, 910002, 'PWNED', 'desktop') ON CONFLICT (id) DO UPDATE SET device_name = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO user_devices (id, user_id, device_name, platform) VALUES (930405, 910002, 'PWNED', 'desktop') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT device_name FROM user_devices WHERE id = 930405",
        expected_sentinel: "Laptop A",
    },
    OnConflictProbe {
        table: "session_revocations",
        do_update_sql: "INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (930412, 910001, 'all', 'PWNED', now() + interval '1 day') ON CONFLICT (id) DO UPDATE SET reason = 'PWNED'",
        do_nothing_sql: "INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (930412, 910001, 'all', 'PWNED', now() + interval '1 day') ON CONFLICT (id) DO NOTHING",
        own_scope_control_insert_sql: Some("INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (939412, 910002, 'all', 'rls ctrl b', now() + interval '1 day')"),
        own_scope_control_do_update_sql: Some("INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (939412, 910002, 'all', 'rls ctrl b', now() + interval '1 day') ON CONFLICT (id) DO UPDATE SET reason = EXCLUDED.reason"),
        own_scope_do_update_sql: Some("INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (930412, 910002, 'all', 'PWNED', now() + interval '1 day') ON CONFLICT (id) DO UPDATE SET reason = 'PWNED'"),
        own_scope_do_nothing_sql: Some("INSERT INTO session_revocations (id, user_id, scope, reason, expires_at) VALUES (930412, 910002, 'all', 'PWNED', now() + interval '1 day') ON CONFLICT (id) DO NOTHING"),
        verify_owner_sql: "SELECT reason FROM session_revocations WHERE id = 930412",
        expected_sentinel: "rls test",
    },
];

// ---------------------------------------------------------------------------
// Query helpers on the live `setjoin_app` connection
// ---------------------------------------------------------------------------

async fn set_scope(app: &Client, user: Option<i64>, mailbox: Option<i64>) {
    app.batch_execute("BEGIN").await.expect("BEGIN");
    if let Some(u) = user {
        app.execute(
            "SELECT set_config('app.current_user_id', $1, true)",
            &[&u.to_string()],
        )
        .await
        .expect("set user GUC");
    }
    if let Some(m) = mailbox {
        app.execute(
            "SELECT set_config('app.current_mailbox_id', $1, true)",
            &[&m.to_string()],
        )
        .await
        .expect("set mailbox GUC");
    }
}

async fn set_empty_scope(app: &Client) {
    app.batch_execute(
        "BEGIN; \
         SELECT set_config('app.current_user_id', '', true); \
         SELECT set_config('app.current_mailbox_id', '', true);",
    )
    .await
    .expect("set empty GUCs");
}

async fn rollback_tx(app: &Client) {
    app.batch_execute("ROLLBACK").await.expect("ROLLBACK");
}

async fn select_count(client: &Client, table: &str, where_clause: &str) -> i64 {
    let sql = format!("SELECT count(*) FROM public.{table} WHERE {where_clause}");
    client
        .query_one(&sql, &[])
        .await
        .unwrap_or_else(|e| panic!("SELECT failed on {table}: {e}"))
        .get(0)
}

async fn assert_update_denied(app: &Client, probe: &TableProbe, ctx: &str) {
    app.batch_execute("SAVEPOINT sp_upd")
        .await
        .expect("SAVEPOINT sp_upd");
    let sql = format!(
        "UPDATE public.{} SET {} WHERE {}",
        probe.table, probe.update_set, probe.where_a
    );
    match app.execute(&sql, &[]).await {
        Ok(affected) => assert_eq!(
            affected, 0,
            "[{}] UPDATE under {ctx} must affect 0 rows, got {affected}",
            probe.table
        ),
        Err(e) => {
            let code = e.code().map(|c| c.code()).unwrap_or("");
            assert_eq!(
                code, "42501",
                "[{}] UPDATE under {ctx} failed with unexpected SQLSTATE {code}: {e}",
                probe.table
            );
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_upd")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_upd");
        }
    }
    app.batch_execute("RELEASE SAVEPOINT sp_upd")
        .await
        .expect("RELEASE SAVEPOINT sp_upd");
}

async fn assert_delete_denied(app: &Client, probe: &TableProbe, ctx: &str) {
    app.batch_execute("SAVEPOINT sp_del")
        .await
        .expect("SAVEPOINT sp_del");
    let sql = format!("DELETE FROM public.{} WHERE {}", probe.table, probe.where_a);
    match app.execute(&sql, &[]).await {
        Ok(affected) => assert_eq!(
            affected, 0,
            "[{}] DELETE under {ctx} must affect 0 rows, got {affected}",
            probe.table
        ),
        Err(e) => {
            let code = e.code().map(|c| c.code()).unwrap_or("");
            assert_eq!(
                code, "42501",
                "[{}] DELETE under {ctx} failed with unexpected SQLSTATE {code}: {e}",
                probe.table
            );
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_del")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_del");
        }
    }
    app.batch_execute("RELEASE SAVEPOINT sp_del")
        .await
        .expect("RELEASE SAVEPOINT sp_del");
}

async fn assert_insert_denied_42501(app: &Client, table: &str, insert_sql: &str, ctx: &str) {
    app.batch_execute("SAVEPOINT sp_ins")
        .await
        .expect("SAVEPOINT sp_ins");
    let res = app.execute(insert_sql, &[]).await;
    match res {
        Ok(n) => {
            let _ = app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins").await;
            panic!("[{table}] INSERT under {ctx} unexpectedly succeeded ({n} rows): {insert_sql}");
        }
        Err(e) => {
            let code = e.code().map(|c| c.code()).unwrap_or("");
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_ins");
            app.batch_execute("RELEASE SAVEPOINT sp_ins")
                .await
                .expect("RELEASE SAVEPOINT sp_ins");
            assert_eq!(
                code, "42501",
                "[{table}] INSERT under {ctx} expected SQLSTATE 42501 (RLS violation), got {code}: {e}\nSQL: {insert_sql}"
            );
        }
    }
}

async fn assert_insert_admitted_and_rollback(
    app: &Client,
    table: &str,
    insert_sql: &str,
    ctx: &str,
) {
    app.batch_execute("SAVEPOINT sp_ins_ctrl")
        .await
        .expect("SAVEPOINT sp_ins_ctrl");
    let res = app.execute(insert_sql, &[]).await;
    match res {
        Ok(n) => {
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins_ctrl")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_ins_ctrl");
            app.batch_execute("RELEASE SAVEPOINT sp_ins_ctrl")
                .await
                .expect("RELEASE SAVEPOINT sp_ins_ctrl");
            assert_eq!(
                n, 1,
                "[{table}] own-scope control INSERT under {ctx} expected 1 row, got {n}\nSQL: {insert_sql}"
            );
        }
        Err(e) => {
            let _ = app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins_ctrl").await;
            panic!(
                "[{table}] own-scope control INSERT under {ctx} unexpectedly failed: {e}\nSQL: {insert_sql}"
            );
        }
    }
}

async fn assert_insert_zero_or_42501(app: &Client, table: &str, insert_sql: &str, ctx: &str) {
    app.batch_execute("SAVEPOINT sp_ins_oc")
        .await
        .expect("SAVEPOINT sp_ins_oc");
    let res = app.execute(insert_sql, &[]).await;
    match res {
        Ok(n) => {
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins_oc")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_ins_oc");
            app.batch_execute("RELEASE SAVEPOINT sp_ins_oc")
                .await
                .expect("RELEASE SAVEPOINT sp_ins_oc");
            assert_eq!(
                n, 0,
                "[{table}] own-scope colliding ON CONFLICT DO NOTHING under {ctx} must affect 0 rows, got {n}\nSQL: {insert_sql}"
            );
        }
        Err(e) => {
            let code = e.code().map(|c| c.code()).unwrap_or("");
            app.batch_execute("ROLLBACK TO SAVEPOINT sp_ins_oc")
                .await
                .expect("ROLLBACK TO SAVEPOINT sp_ins_oc");
            app.batch_execute("RELEASE SAVEPOINT sp_ins_oc")
                .await
                .expect("RELEASE SAVEPOINT sp_ins_oc");
            assert_eq!(
                code, "42501",
                "[{table}] own-scope colliding ON CONFLICT DO NOTHING under {ctx} expected 0 rows or 42501, got {code}: {e}\nSQL: {insert_sql}"
            );
        }
    }
}

async fn cleanup_fixtures(owner: &Client) {
    // Follow crates/pg/DOX.md:141: keep FK cascades active; only append-only audit
    // deletion uses transaction-local replica mode.
    let is_super: bool = owner
        .query_one(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .map(|r| r.get(0))
        .unwrap_or(false);
    if is_super {
        owner
            .batch_execute(
                "BEGIN; \
                 SET LOCAL session_replication_role = replica; \
                 DELETE FROM public.mailbox_audit_log WHERE mailbox_id IN (920001, 920002); \
                 DELETE FROM public.drive_audit_log WHERE space_id = 930100; \
                 COMMIT;",
            )
            .await
            .expect("cleanup append-only audit rows");
    }
    owner.batch_execute("BEGIN").await.expect("cleanup BEGIN");
    for probe in PROBES.iter().rev() {
        if matches!(
            probe.table,
            "mailbox_audit_log" | "drive_audit_log" | "mailboxes" | "users"
        ) {
            continue;
        }
        let stmt = format!("DELETE FROM public.{} WHERE {}", probe.table, probe.where_a);
        if let Err(e) = owner.execute(&stmt, &[]).await {
            let _ = owner.batch_execute("ROLLBACK").await;
            panic!("cleanup failed on [{}]: {e:?}\nSQL: {stmt}", probe.table);
        }
    }
    for stmt in [
        "DELETE FROM public.mail_work_outbox WHERE id IN (900070, 900071)",
        "DELETE FROM public.mail_recovery_incidents WHERE id IN ('91000100-0000-4000-8000-000000000001'::uuid, '91000100-0000-4000-8000-000000000002'::uuid)",
        "DELETE FROM public.user_identity_links WHERE id = 900060",
        "DELETE FROM public.distribution_groups WHERE id = 900050",
        "DELETE FROM public.imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM public.tags WHERE mailbox_id IN (920001, 920002))",
        "DELETE FROM public.imap_membership_uid_backfill WHERE tag_id IN (SELECT id FROM public.tags WHERE mailbox_id IN (920001, 920002))",
        "DELETE FROM public.folders WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.tags WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.aliases WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.calendars WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.addressbooks WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.mailbox_address_claims WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.mailbox_lifecycle WHERE mailbox_id IN (920001, 920002)",
        "DELETE FROM public.mailboxes WHERE id IN (920001, 920002)",
        "DELETE FROM public.users WHERE id IN (910001, 910002, 910003, 910004)",
        "DELETE FROM public.identity_sources WHERE id = 900040",
        "DELETE FROM public.office_provider_policies WHERE provider_id = 'rls-546e-office'",
        "DELETE FROM public.guest_profiles WHERE id = 900030",
        "DELETE FROM public.oidc_clients WHERE id = 'rls-546e-oidc-client'",
        "DELETE FROM public.terms_of_use WHERE id IN (900020, 900021)",
        "DELETE FROM public.approval_policies WHERE id IN (900010, 900011)",
        "DELETE FROM public.drive_chunks WHERE scope_key = 'rls-546e-a'",
        "DELETE FROM public.blobs WHERE sha256 IN ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')",
        "DELETE FROM public.domains WHERE id = 900001",
    ] {
        if let Err(e) = owner.execute(stmt, &[]).await {
            let _ = owner.batch_execute("ROLLBACK").await;
            panic!("cleanup parent failed: {e:?}\nSQL: {stmt}");
        }
    }
    owner.batch_execute("COMMIT").await.expect("cleanup COMMIT");
}

// ---------------------------------------------------------------------------
// Manifest verification + 187-table live `setjoin_app` proof test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rls_full_matrix_187_scoped_tables_under_setjoin_app() {
    assert_ne!(
        USER_A, MAILBOX_A,
        "Tenant A user_id must diverge from mailbox_id"
    );
    assert_ne!(
        USER_B, MAILBOX_B,
        "Tenant B user_id must diverge from mailbox_id"
    );
    assert_ne!(USER_A, USER_B);
    assert_ne!(MAILBOX_A, MAILBOX_B);

    // 1. Parse `config/table-ownership-manifest.json` directly from repo root.
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../config/table-ownership-manifest.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", manifest_path.display()));
    let root = JsonParser::parse(&raw).expect("valid manifest JSON");
    let obj = root.as_obj().expect("manifest root object");

    assert_eq!(
        obj.get("legacy_rls_pending_ceiling")
            .and_then(JsonVal::as_i64),
        Some(0),
        "legacy_rls_pending_ceiling must be 0"
    );
    assert_eq!(
        obj.get("legacy_write_migration_ceiling")
            .and_then(JsonVal::as_i64),
        Some(0),
        "legacy_write_migration_ceiling must be 0"
    );
    assert!(
        obj.get("legacy_rls_pending_tables")
            .and_then(JsonVal::as_arr)
            .is_some_and(|a| a.is_empty()),
        "legacy_rls_pending_tables must be empty"
    );

    let tables_obj = obj
        .get("tables")
        .and_then(JsonVal::as_obj)
        .expect("manifest.tables object");
    let mut manifest_scoped: BTreeMap<String, ManifestClass> = BTreeMap::new();
    let mut mailbox_count = 0usize;
    let mut user_count = 0usize;
    for (name, spec) in tables_obj {
        let spec_obj = spec.as_obj().expect("table spec object");
        let cls = spec_obj
            .get("security_class")
            .and_then(JsonVal::as_str)
            .expect("security_class");
        let posture = spec_obj
            .get("rls_posture")
            .and_then(JsonVal::as_str)
            .expect("rls_posture");
        match cls {
            "mailbox_scoped" => {
                assert_eq!(
                    posture, "enforced",
                    "mailbox_scoped table {name} must have rls_posture=enforced"
                );
                mailbox_count += 1;
                manifest_scoped.insert(name.clone(), ManifestClass::MailboxScoped);
            }
            "user_scoped" => {
                assert_eq!(
                    posture, "enforced",
                    "user_scoped table {name} must have rls_posture=enforced"
                );
                user_count += 1;
                manifest_scoped.insert(name.clone(), ManifestClass::UserScoped);
            }
            _ => {}
        }
    }
    assert_eq!(mailbox_count, 66, "expected 66 mailbox_scoped tables");
    assert_eq!(user_count, 121, "expected 121 user_scoped tables");
    assert_eq!(manifest_scoped.len(), 187, "expected 187 scoped tables");

    // 2. Assert exact 1:1 coverage between manifest's 187 scoped tables and PROBES.
    let mut probe_set: BTreeSet<String> = BTreeSet::new();
    for p in PROBES {
        assert!(
            probe_set.insert(p.table.to_owned()),
            "duplicate probe entry for {}",
            p.table
        );
        let expected_cls = manifest_scoped
            .get(p.table)
            .unwrap_or_else(|| panic!("probe table {} is not a scoped table in manifest", p.table));
        assert_eq!(
            *expected_cls, p.class,
            "probe table {} security_class mismatch vs manifest",
            p.table
        );
    }
    let manifest_keys: BTreeSet<String> = manifest_scoped.keys().cloned().collect();
    let uncovered: Vec<&String> = manifest_keys.difference(&probe_set).collect();
    assert!(
        uncovered.is_empty(),
        "uncovered scoped tables in manifest (add live matrix probes): {uncovered:?}"
    );
    assert_eq!(PROBES.len(), 187);

    // 3. Connect to PostgreSQL (skip only when REQUIRE_DB unset and no DSN).
    let Some(owner_str) = owner_dsn() else {
        skip_or_fail(
            "rls_full_matrix_187_scoped_tables_under_setjoin_app",
            "no-dsn",
        );
        return;
    };
    let owner = match connect_raw(&owner_str).await {
        Ok(c) => c,
        Err(e) => {
            skip_or_fail(
                "rls_full_matrix_187_scoped_tables_under_setjoin_app",
                &format!("owner-connect-failed: {e}"),
            );
            return;
        }
    };
    // Safety guard: refuse to execute pre-seed/teardown DELETEs against a non-test database
    // unless explicitly opted in via ALLOW_RLS_FULL_MATRIX_DELETE=1.
    let db_name: String = owner
        .query_one("SELECT current_database()::text", &[])
        .await
        .expect("query current_database()")
        .get(0);
    let db_lower = db_name.to_ascii_lowercase();
    let looks_disposable = ["test", "e2e", "ci", "rls", "546"]
        .iter()
        .any(|marker| db_lower.contains(marker));
    let explicit_allow = std::env::var("ALLOW_RLS_FULL_MATRIX_DELETE").as_deref() == Ok("1");
    assert!(
        looks_disposable || explicit_allow,
        "refusing to run destructive fixture DELETEs on non-test database '{db_name}' \
         (name must contain one of test/e2e/ci/rls/546, or set ALLOW_RLS_FULL_MATRIX_DELETE=1)"
    );
    // Serialize concurrent runs against the same test DB; released automatically when `owner` drops.
    owner
        .execute(
            "SELECT pg_advisory_lock(hashtext('setjoin_rls_full_matrix_v1'))",
            &[],
        )
        .await
        .expect("acquire rls_full_matrix session advisory lock");
    let app_str = app_dsn(&owner_str);
    let app = match connect_raw(&app_str).await {
        Ok(c) => c,
        Err(e) => {
            skip_or_fail(
                "rls_full_matrix_187_scoped_tables_under_setjoin_app",
                &format!("app-connect-failed: {e}"),
            );
            return;
        }
    };
    // Fresh `setjoin_app` connection that NEVER executes `set_config` so truly-unset
    // (`NULL`) GUCs are verified independently of empty-string (`''`) GUCs.
    let app_unset = match connect_raw(&app_str).await {
        Ok(c) => c,
        Err(e) => {
            skip_or_fail(
                "rls_full_matrix_187_scoped_tables_under_setjoin_app",
                &format!("app-unset-connect-failed: {e}"),
            );
            return;
        }
    };
    let unset_ok: bool = app_unset
        .query_one(
            "SELECT current_setting('app.current_user_id', true) IS NULL \
                AND current_setting('app.current_mailbox_id', true) IS NULL",
            &[],
        )
        .await
        .expect("verify fresh setjoin_app connection has NULL GUCs")
        .get(0);
    assert!(
        unset_ok,
        "fresh setjoin_app connection must start with NULL app.current_user_id and app.current_mailbox_id"
    );

    // 4. Verify live role posture: `setjoin_app` MUST be NOSUPERUSER NOBYPASSRLS.
    let role_row = app
        .query_one(
            "SELECT current_user::text, r.rolsuper, r.rolbypassrls \
             FROM pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .expect("query current_user role posture");
    let role_name: String = role_row.get(0);
    let rolsuper: bool = role_row.get(1);
    let rolbypassrls: bool = role_row.get(2);
    assert_eq!(role_name, "setjoin_app", "matrix must run as setjoin_app");
    assert!(!rolsuper, "setjoin_app must have rolsuper = false");
    assert!(!rolbypassrls, "setjoin_app must have rolbypassrls = false");

    // 5. Verify `pg_class` has ALL 187 scoped tables with ENABLE + FORCE ROW LEVEL SECURITY
    //    and zero USING(true)/WITH CHECK(true) policies across all 187 tables.
    let scoped_names: Vec<String> = manifest_scoped.keys().cloned().collect();
    let rls_rows = owner
        .query(
            "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relname = ANY($1)",
            &[&scoped_names],
        )
        .await
        .expect("query pg_class RLS posture");
    assert_eq!(
        rls_rows.len(),
        187,
        "all 187 scoped tables must exist in pg_class"
    );
    for row in &rls_rows {
        let relname: String = row.get(0);
        let enabled: bool = row.get(1);
        let forced: bool = row.get(2);
        assert!(
            enabled && forced,
            "table {relname} must have ENABLE + FORCE RLS (enabled={enabled}, forced={forced})"
        );
    }

    let open_pol_rows = owner
        .query(
            "SELECT c.relname::text, p.polname::text, p.polcmd::text \
             FROM pg_policy p \
             JOIN pg_class c ON c.oid = p.polrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' \
               AND c.relname = ANY($1) \
               AND (pg_get_expr(p.polqual, p.polrelid) = 'true' \
                    OR pg_get_expr(p.polwithcheck, p.polrelid) = 'true') \
             ORDER BY c.relname, p.polname",
            &[&scoped_names],
        )
        .await
        .expect("query permissive true policies");
    let open_pols: Vec<(String, String, String)> = open_pol_rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert!(
        open_pols.is_empty(),
        "zero USING(true)/WITH CHECK(true) RLS policies allowed across all 187 scoped tables; found: {open_pols:?}"
    );

    // 6. Clean any leftover fixtures from an interrupted prior run, then seed all 187 tables.
    cleanup_fixtures(&owner).await;

    let matrix_result = std::panic::AssertUnwindSafe(run_live_187_matrix(&owner, &app, &app_unset));
    let outcome = futures_util::FutureExt::catch_unwind(matrix_result).await;

    // 7. Roll back any open transactions on `app` / `app_unset` before owner teardown so held
    //    locks cannot deadlock cleanup if a probe assertion failed mid-transaction.
    let _ = app.batch_execute("ROLLBACK").await;
    let _ = app_unset.batch_execute("ROLLBACK").await;
    cleanup_fixtures(&owner).await;

    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

async fn run_live_187_matrix(owner: &Client, app: &Client, app_unset: &Client) {
    // Seed non-scoped parent rows before users.
    owner
        .batch_execute(NON_SCOPED_PARENT_SETUP_BEFORE_USERS)
        .await
        .expect("seed non-scoped parents before users");

    // Seed all 187 scoped tables in topological FK order, inserting mid-graph non-scoped parents
    // right after `mailboxes` and `mail_thread_work_events`.
    for probe in PROBES {
        owner
            .batch_execute(probe.seed_sql)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "owner seed failed for [{}]: {e:?}\nSQL: {}",
                    probe.table, probe.seed_sql
                )
            });
        if probe.table == "mailboxes" {
            owner
                .batch_execute(NON_SCOPED_PARENT_SETUP_AFTER_MAILBOXES)
                .await
                .expect("seed Tenant B, Neutral C, and post-mailbox parents");
        }
        if probe.table == "mail_thread_work_events" {
            owner
                .batch_execute(NON_SCOPED_OUTBOX_SETUP)
                .await
                .expect("seed mail_work_outbox parent");
        }
    }

    // Probe every single one of the 187 scoped tables under `setjoin_app` (`NOBYPASSRLS`).
    let mut verified_count = 0usize;
    for probe in PROBES {
        // Precondition: owner sees Tenant A's seeded row.
        let owner_count = select_count(owner, probe.table, probe.where_a).await;
        assert_eq!(
            owner_count, 1,
            "[{}] expected 1 seeded Tenant A row as owner, got {owner_count}",
            probe.table
        );

        // (1) Cross-tenant Tenant B (USER_B, MAILBOX_B): SELECT, UPDATE, DELETE, INSERT.
        set_scope(app, Some(USER_B), Some(MAILBOX_B)).await;
        if probe.guc_mode != GucMode::UserAuthSelectOwnerWrite {
            let sel_b = select_count(app, probe.table, probe.where_a).await;
            assert_eq!(
                sel_b, 0,
                "[{}] Tenant B cross-tenant SELECT must return 0 rows, got {sel_b}",
                probe.table
            );
        }
        assert_update_denied(app, probe, "Tenant B").await;
        assert_delete_denied(app, probe, "Tenant B").await;
        assert_insert_denied_42501(app, probe.table, probe.insert_a_sql, "Tenant B").await;
        rollback_tx(app).await;

        // (2) Swapped-GUC / Divergent-ID proof (USER_A != MAILBOX_A, USER_B != MAILBOX_B).
        match probe.guc_mode {
            GucMode::MailboxOnly => {
                // (USER_A, MAILBOX_B): matching user_id must NOT unlock mailbox_scoped table!
                set_scope(app, Some(USER_A), Some(MAILBOX_B)).await;
                let sel_swapped = select_count(app, probe.table, probe.where_a).await;
                assert_eq!(
                    sel_swapped, 0,
                    "[{}] swapped GUC (USER_A, MAILBOX_B) must deny SELECT on mailbox-keyed table",
                    probe.table
                );
                assert_update_denied(app, probe, "swapped (USER_A, MAILBOX_B)").await;
                assert_delete_denied(app, probe, "swapped (USER_A, MAILBOX_B)").await;
                assert_insert_denied_42501(
                    app,
                    probe.table,
                    probe.insert_a_sql,
                    "swapped (USER_A, MAILBOX_B)",
                )
                .await;
                rollback_tx(app).await;

                // (USER_B, MAILBOX_A): proves app.current_mailbox_id is the active GUC.
                set_scope(app, Some(USER_B), Some(MAILBOX_A)).await;
                let sel_mb = select_count(app, probe.table, probe.where_a).await;
                assert_eq!(
                    sel_mb, 1,
                    "[{}] (USER_B, MAILBOX_A) must see Tenant A row via app.current_mailbox_id",
                    probe.table
                );
                rollback_tx(app).await;
            }
            GucMode::UserOnly => {
                // (USER_B, MAILBOX_A): matching mailbox_id must NOT unlock user-keyed table!
                set_scope(app, Some(USER_B), Some(MAILBOX_A)).await;
                let sel_swapped = select_count(app, probe.table, probe.where_a).await;
                assert_eq!(
                    sel_swapped, 0,
                    "[{}] swapped GUC (USER_B, MAILBOX_A) must deny SELECT on user-keyed table",
                    probe.table
                );
                assert_update_denied(app, probe, "swapped (USER_B, MAILBOX_A)").await;
                assert_delete_denied(app, probe, "swapped (USER_B, MAILBOX_A)").await;
                assert_insert_denied_42501(
                    app,
                    probe.table,
                    probe.insert_a_sql,
                    "swapped (USER_B, MAILBOX_A)",
                )
                .await;
                rollback_tx(app).await;

                // (owner_user, MAILBOX_B): proves app.current_user_id is the active GUC.
                let owner_u = if probe.table == "guest_accounts" {
                    USER_GUEST_A
                } else {
                    USER_A
                };
                set_scope(app, Some(owner_u), Some(MAILBOX_B)).await;
                let sel_u = select_count(app, probe.table, probe.where_a).await;
                assert_eq!(
                    sel_u, 1,
                    "[{}] ({owner_u}, MAILBOX_B) must see Tenant A row via app.current_user_id",
                    probe.table
                );
                rollback_tx(app).await;
            }
            GucMode::BothRequired => {
                // Both swapped combinations MUST fail closed.
                for (label, u, m) in [
                    ("swapped (USER_A, MAILBOX_B)", USER_A, MAILBOX_B),
                    ("swapped (USER_B, MAILBOX_A)", USER_B, MAILBOX_A),
                ] {
                    set_scope(app, Some(u), Some(m)).await;
                    let sel = select_count(app, probe.table, probe.where_a).await;
                    assert_eq!(sel, 0, "[{}] {label} must deny SELECT", probe.table);
                    assert_update_denied(app, probe, label).await;
                    assert_delete_denied(app, probe, label).await;
                    assert_insert_denied_42501(app, probe.table, probe.insert_a_sql, label).await;
                    rollback_tx(app).await;
                }
                // Matching BOTH GUCs unlocks Tenant A SELECT.
                set_scope(app, Some(USER_A), Some(MAILBOX_A)).await;
                assert_eq!(
                    select_count(app, probe.table, probe.where_a).await,
                    1,
                    "[{}] (USER_A, MAILBOX_A) must see Tenant A row",
                    probe.table
                );
                rollback_tx(app).await;
            }
            GucMode::MailboxOrOwnerUser => {
                // Verify (USER_B, MAILBOX_A) is denied on `mailboxes` INSERT.
                if probe.table == "mailboxes" {
                    set_scope(app, Some(USER_B), Some(MAILBOX_A)).await;
                    // mailboxes_app_insert requires user_id = current_user_id (USER_B != USER_A).
                    assert_insert_denied_42501(
                        app,
                        probe.table,
                        probe.insert_a_sql,
                        "swapped (USER_B, MAILBOX_A)",
                    )
                    .await;
                    rollback_tx(app).await;
                }
                set_scope(app, Some(USER_A), Some(MAILBOX_A)).await;
                assert_eq!(
                    select_count(app, probe.table, probe.where_a).await,
                    1,
                    "[{}] Tenant A must see own row",
                    probe.table
                );
                rollback_tx(app).await;
            }
            GucMode::DefaultDeny => {
                // Even Tenant A is denied on default-deny tables (zero policies for setjoin_app).
                set_scope(app, Some(USER_A), Some(MAILBOX_A)).await;
                assert_eq!(
                    select_count(app, probe.table, probe.where_a).await,
                    0,
                    "[{}] default-deny table must hide row even from Tenant A",
                    probe.table
                );
                assert_update_denied(app, probe, "default-deny Tenant A").await;
                assert_delete_denied(app, probe, "default-deny Tenant A").await;
                assert_insert_denied_42501(
                    app,
                    probe.table,
                    probe.insert_a_sql,
                    "default-deny Tenant A",
                )
                .await;
                rollback_tx(app).await;
            }
            GucMode::UserAuthSelectOwnerWrite => {
                // Intentional V134:63 org-visible lobby discovery on `meetings`: any authenticated
                // user (`USER_B`) can SELECT Tenant A's meeting, while writes remain strictly owner-only.
                set_scope(app, Some(USER_B), Some(MAILBOX_B)).await;
                assert_eq!(
                    select_count(app, probe.table, probe.where_a).await,
                    1,
                    "[{}] authenticated Tenant B must see org-visible row (V134:63)",
                    probe.table
                );
                rollback_tx(app).await;
                // Swapped (USER_B, MAILBOX_A) must deny UPDATE/DELETE/INSERT on owner_user_id.
                set_scope(app, Some(USER_B), Some(MAILBOX_A)).await;
                assert_update_denied(app, probe, "swapped (USER_B, MAILBOX_A)").await;
                assert_delete_denied(app, probe, "swapped (USER_B, MAILBOX_A)").await;
                assert_insert_denied_42501(
                    app,
                    probe.table,
                    probe.insert_a_sql,
                    "swapped (USER_B, MAILBOX_A)",
                )
                .await;
                rollback_tx(app).await;
                // (None, MAILBOX_A): mailbox_id alone must NOT satisfy current_user_id IS NOT NULL!
                set_scope(app, None, Some(MAILBOX_A)).await;
                assert_eq!(
                    select_count(app, probe.table, probe.where_a).await,
                    0,
                    "[{}] (None, MAILBOX_A) must deny SELECT when app.current_user_id is unset",
                    probe.table
                );
                rollback_tx(app).await;
            }
        }

        // (3a) Truly-unset GUCs (NULL on fresh connection `app_unset` that NEVER ran `set_config`).
        app_unset.batch_execute("BEGIN").await.expect("BEGIN unset");
        assert_eq!(
            select_count(app_unset, probe.table, probe.where_a).await,
            0,
            "[{}] truly-unset (NULL) GUCs must return 0 rows",
            probe.table
        );
        assert_update_denied(app_unset, probe, "truly-unset (NULL) GUCs").await;
        assert_delete_denied(app_unset, probe, "truly-unset (NULL) GUCs").await;
        assert_insert_denied_42501(
            app_unset,
            probe.table,
            probe.insert_a_sql,
            "truly-unset (NULL) GUCs",
        )
        .await;
        rollback_tx(app_unset).await;

        // (3b) Empty-string GUCs ('') on `app` also fail closed.
        set_empty_scope(app).await;
        assert_eq!(
            select_count(app, probe.table, probe.where_a).await,
            0,
            "[{}] empty ('') GUCs must return 0 rows",
            probe.table
        );
        assert_update_denied(app, probe, "empty ('') GUCs").await;
        assert_delete_denied(app, probe, "empty ('') GUCs").await;
        assert_insert_denied_42501(app, probe.table, probe.insert_a_sql, "empty ('') GUCs").await;
        rollback_tx(app).await;

        // (4) Owner integrity verification: Tenant A's row MUST still exist untouched.
        let owner_after = select_count(owner, probe.table, probe.where_a).await;
        assert_eq!(
            owner_after, 1,
            "[{}] Tenant A's row was mutated/deleted during cross-tenant probes!",
            probe.table
        );

        verified_count += 1;
    }
    assert_eq!(verified_count, 187, "must verify all 187 scoped tables");

    // Verify `app_unset` still has truly NULL GUCs after all 187 table probes.
    let still_unset: bool = app_unset
        .query_one(
            "SELECT current_setting('app.current_user_id', true) IS NULL \
                AND current_setting('app.current_mailbox_id', true) IS NULL",
            &[],
        )
        .await
        .expect("re-verify app_unset GUCs remain NULL")
        .get(0);
    assert!(
        still_unset,
        "app_unset connection must still have NULL GUCs after probing all 187 tables"
    );

    // (6) `INSERT ... ON CONFLICT DO NOTHING / DO UPDATE` anti-oracle proof (ARCH-018:51).
    let mut own_scope_verified = 0usize;
    for oc in ON_CONFLICT_PROBES {
        set_scope(app, Some(USER_B), Some(MAILBOX_B)).await;
        // Cross-tenant scope ON CONFLICT DO UPDATE & DO NOTHING must fail 42501.
        assert_insert_denied_42501(
            app,
            oc.table,
            oc.do_update_sql,
            "cross-scope ON CONFLICT DO UPDATE",
        )
        .await;
        assert_insert_denied_42501(
            app,
            oc.table,
            oc.do_nothing_sql,
            "cross-scope ON CONFLICT DO NOTHING",
        )
        .await;
        // Positive own-scope controls: proves `setjoin_app` genuinely admits non-colliding
        // `INSERT`, `INSERT ... ON CONFLICT DO NOTHING`, and `INSERT ... ON CONFLICT DO UPDATE`
        // on Tenant B's own scope (not merely denied by a missing INSERT policy).
        if let Some(ctrl_sql) = oc.own_scope_control_insert_sql {
            assert_insert_admitted_and_rollback(app, oc.table, ctrl_sql, "Tenant B own-scope")
                .await;
            let ctrl_do_nothing = format!("{ctrl_sql} ON CONFLICT DO NOTHING");
            assert_insert_admitted_and_rollback(
                app,
                oc.table,
                &ctrl_do_nothing,
                "Tenant B own-scope non-colliding ON CONFLICT DO NOTHING",
            )
            .await;
            let ctrl_do_update = oc.own_scope_control_do_update_sql.unwrap_or_else(|| {
                panic!("[{}] missing own_scope_control_do_update_sql", oc.table)
            });
            assert_insert_admitted_and_rollback(
                app,
                oc.table,
                ctrl_do_update,
                "Tenant B own-scope non-colliding ON CONFLICT DO UPDATE",
            )
            .await;
            own_scope_verified += 1;
        }
        // Own-scope colliding ON CONFLICT DO UPDATE -> MUST fail 42501.
        if let Some(own_upd_sql) = oc.own_scope_do_update_sql {
            assert_insert_denied_42501(
                app,
                oc.table,
                own_upd_sql,
                "own-scope colliding ON CONFLICT DO UPDATE",
            )
            .await;
        }
        // Own-scope colliding ON CONFLICT DO NOTHING -> MUST affect 0 rows or fail 42501.
        if let Some(own_nothing_sql) = oc.own_scope_do_nothing_sql {
            assert_insert_zero_or_42501(
                app,
                oc.table,
                own_nothing_sql,
                "own-scope colliding ON CONFLICT DO NOTHING",
            )
            .await;
        }
        rollback_tx(app).await;

        let sentinel: String = owner
            .query_one(oc.verify_owner_sql, &[])
            .await
            .unwrap_or_else(|e| panic!("[{}] owner sentinel query failed: {e}", oc.table))
            .get(0);
        assert_eq!(
            sentinel, oc.expected_sentinel,
            "[{}] ON CONFLICT probe mutated Tenant A's row!",
            oc.table
        );
    }
    assert_eq!(
        own_scope_verified, 14,
        "expected exact 14 own-scope ON CONFLICT positive-control + anti-oracle tables, got {own_scope_verified}"
    );
}
