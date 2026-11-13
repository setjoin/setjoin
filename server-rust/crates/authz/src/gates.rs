//! The database reads Go makes before the pilot methods run, issued on the same
//! credential Go's request pool uses (`DB_DSN`, `setjoin_app`), so their
//! answers are the ones Go sees.

use setjoin_pg::{ScopedExecutor, Type};

use super::token::Session;

/// `true` only when `flag`'s row is enabled. Runtime security gates are
/// installed by the gateway before adapter admission (#405). An absent row
/// is OFF, exactly as `toggle.FeatureFlags.Resolve` resolves it; any read
/// error or a missing/invalid registry state row is OFF too.
pub async fn route_enabled(exec: &ScopedExecutor, flag: &str) -> bool {
    admission_allowed(exec, Some(flag)).await
}

/// Shared security gates for a route that has no Go feature toggle.
pub(crate) async fn admission_allowed(exec: &ScopedExecutor, flag: Option<&str>) -> bool {
    let keys: Vec<String> = flag
        .into_iter()
        .map(str::to_owned)
        .collect();
    let Ok(rows) = exec
        .read(
            "SELECT s.mode::text, ft.key, ft.enabled \
               FROM feature_toggle_registry_state s \
               LEFT JOIN feature_toggles ft ON ft.key = ANY($1::text[]) \
              WHERE s.singleton",
            &[(&keys, Type::TEXT_ARRAY)],
        )
        .await
    else {
        return false;
    };
    let Some(first) = rows.first() else {
        return false;
    };
    if !matches!(
        first.get::<_, Option<String>>(0).as_deref(),
        Some("observe" | "enforce")
    ) {
        return false;
    }
    let on = |key: &str| {
        rows.iter().any(|r| {
            r.get::<_, Option<String>>(1).as_deref() == Some(key)
                && r.get::<_, Option<bool>>(2) == Some(true)
        })
    };
    flag.is_none_or(on)
}

/// Go's `sessionState` components (`sessionStateComponents` in
/// `mailserver/internal/jmap/statecodec.go`), in wire order. `identity` is
/// `users.updated_at` as unix seconds; the rest are the mailbox counters and
/// the satellite `MAX(jmap_state)` cursors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionState {
    pub email: i64,
    pub mailbox: i64,
    pub thread: i64,
    pub tag: i64,
    pub calendar: i64,
    pub contact: i64,
    pub task: i64,
    pub identity: i64,
}

impl SessionState {
    /// Go's `encodeSessionState`: the eight components dash-joined, base 10.
    pub fn encode(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}-{}-{}-{}",
            self.email,
            self.mailbox,
            self.thread,
            self.tag,
            self.calendar,
            self.contact,
            self.task,
            self.identity
        )
    }
}

/// What the verified caller may do here, by Go's own rules.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Caller {
    /// Not a guest, not revoked, primary mailbox `mailbox` reachable.
    Member { mailbox: i64, state: SessionState },
    /// Anything Go handles differently (guest belt, revoked session, no
    /// primary mailbox, suspended/detached mailbox, unreadable state).
    Defer,
}

/// One round trip: the guest satellite belt (`guest_account_status`), the
/// session denylist (`session_revocations`, the predicate of
/// `threat.SessionDenylist.IsRevoked`: `all` revokes `iat <= not_before`,
/// `jti`/`family` revoke a match, only rows with `expires_at > now()`), the
/// primary mailbox (`identity.ResolvePrimaryMailbox`), its lifecycle gate
/// (`mailbox_lifecycle_access_allowed`) and the pre-dispatch
/// `sessionState`. The mailbox comes from the verified `uid`, never from the
/// request.
pub(crate) async fn caller(exec: &ScopedExecutor, s: &Session) -> Caller {
    const SQL: &str = "SELECT \
        (SELECT count(*) FROM guest_account_status($1))::int8, \
        EXISTS (SELECT 1 FROM session_revocations r \
                 WHERE r.user_id = $1 AND r.expires_at > now() \
                   AND ((r.scope = 'all' AND r.not_before >= to_timestamp($2::float8)) \
                     OR (r.scope = 'jti' AND $3 <> '' AND r.jti = $3) \
                     OR (r.scope = 'family' AND $4 <> '' AND r.family_id = $4))), \
        p.id, p.allowed, \
        st.email, st.mailbox, st.thread, st.tag, st.calendar, st.contact, st.task, st.identity \
      FROM (SELECT 1) one \
      LEFT JOIN LATERAL ( \
        SELECT id, mailbox_lifecycle_access_allowed(id) AS allowed FROM mailboxes \
         WHERE user_id = $1 AND is_primary = TRUE LIMIT 1) p ON TRUE \
      LEFT JOIN LATERAL ( \
        SELECT m.jmap_email_state::int8 AS email, m.jmap_mailbox_state::int8 AS mailbox, \
               m.jmap_thread_state::int8 AS thread, m.jmap_tag_state::int8 AS tag, \
               COALESCE((SELECT MAX(jmap_state) FROM calendars WHERE mailbox_id = m.id), 0)::int8 AS calendar, \
               COALESCE((SELECT MAX(jmap_state) FROM addressbooks WHERE mailbox_id = m.id), 0)::int8 AS contact, \
               COALESCE((SELECT MAX(jmap_state) FROM tasks WHERE mailbox_id = m.id), 0)::int8 AS task, \
               floor(extract(epoch FROM u.updated_at))::int8 AS identity \
          FROM mailboxes m JOIN users u ON u.id = m.user_id \
         WHERE m.user_id = $1 AND m.is_primary = TRUE LIMIT 1) st ON TRUE";
    let iat = s.issued_at as f64;
    let rows = match exec
        .read(
            SQL,
            &[
                (&s.user_id, Type::INT8),
                (&iat, Type::FLOAT8),
                (&s.jti, Type::TEXT),
                (&s.family, Type::TEXT),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return Caller::Defer,
    };
    let Some(r) = rows.first() else {
        return Caller::Defer;
    };
    let guest_rows: i64 = r.get(0);
    let revoked: bool = r.get(1);
    let mailbox: Option<i64> = r.get(2);
    let allowed: Option<bool> = r.get(3);
    // Columns 4..=11 in `SessionState` field order; any NULL defers.
    let c = |i: usize| r.get::<_, Option<i64>>(i);
    let (
        Some(email),
        Some(mailbox_state),
        Some(thread),
        Some(tag),
        Some(calendar),
        Some(contact),
        Some(task),
        Some(identity),
    ) = (c(4), c(5), c(6), c(7), c(8), c(9), c(10), c(11))
    else {
        return Caller::Defer;
    };
    let state = SessionState {
        email,
        mailbox: mailbox_state,
        thread,
        tag,
        calendar,
        contact,
        task,
        identity,
    };
    match (guest_rows, revoked, mailbox, allowed) {
        (0, false, Some(mailbox), Some(true)) => Caller::Member { mailbox, state },
        _ => Caller::Defer,
    }
}

/// Active actor roles, using `shared/permissions.ResolveAuthority`'s live
/// assignment predicate. Never resolve a role from a token or request field.
/// Read errors defer the request rather than manufacturing empty authority.
pub(crate) async fn roles(exec: &ScopedExecutor, user: i64) -> Option<Vec<i64>> {
    let rows = exec
        .read(
            "SELECT ra.role_group_id FROM admin_role_assignments ra \
             JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
             WHERE ra.user_id = $1 \
               AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
               AND admin_assignment_active(ra.eligible, ra.activated_until) \
             ORDER BY ra.role_group_id",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    Some(rows.iter().map(|r| r.get(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_state_encodes_in_go_wire_order() {
        let s = SessionState {
            email: 1,
            mailbox: 2,
            thread: 3,
            tag: 4,
            calendar: 5,
            contact: 6,
            task: 7,
            identity: 1_761_700_000,
        };
        assert_eq!(s.encode(), "1-2-3-4-5-6-7-1761700000");
    }
}
