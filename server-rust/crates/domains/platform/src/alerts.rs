//! Platform slice `terms-remaining`, group `alerts`: health alert status, acknowledgement
//! and the `hc_`/`alert_` configuration namespace (`/admin/alerts*`), Go's `AlertsHandler`.
//!
//! Go writes through the pool with no audit row. Acknowledge and unsuppress are one
//! statement each. The configuration write is one pgx batch (one implicit transaction of
//! one upsert per key); it is mirrored by one `jsonb_each` upsert with the same effect.
use super::{command, deadline, done, envelope, invalid, nano, s, scope};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/alerts`: checks with at least three consecutive failures. A row whose
/// last error is NULL does not scan into Go's `string`, which ends the list there.
pub async fn list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    // `read` accepts only a statement that starts with SELECT, so the CTE sits in a subquery.
    let sql = format!(
        "SELECT name, consecutive, last_checked, details, sent, suppressed FROM (WITH ranked AS (
            SELECT check_name, status, checked_at,
                ROW_NUMBER() OVER (PARTITION BY check_name ORDER BY checked_at DESC) as rn
            FROM health_history
        ),
        streaks AS (
            SELECT check_name, COUNT(*) as consecutive, MAX(checked_at) as last_checked
            FROM ranked
            WHERE status = 'error'
              AND rn <= (
                  SELECT COUNT(*) FROM ranked r2
                  WHERE r2.check_name = ranked.check_name
                    AND r2.rn <= ranked.rn
                    AND r2.status = 'error'
              )
            GROUP BY check_name
        )
        SELECT s.check_name AS name, s.consecutive::bigint AS consecutive, {} AS last_checked, h.details AS details, {} AS sent,
               COALESCE(a.suppressed, false) AS suppressed, s.last_checked AS at
        FROM streaks s
        LEFT JOIN health_history h ON h.check_name = s.check_name AND h.checked_at = s.last_checked
        LEFT JOIN health_alerts a ON a.check_name = s.check_name
        WHERE s.consecutive >= 3) q
        ORDER BY at DESC",
        nano("s.last_checked"),
        nano("a.alert_sent_at")
    );
    let rows = exec.read(&sql, &[]).await?;
    let mut out = Vec::new();
    for row in &rows {
        let (Ok(name), Ok(consecutive), Ok(checked), Ok(Some(error)), Ok(sent), Ok(suppressed)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, i64>(1),
            row.try_get::<_, Option<String>>(2),
            row.try_get::<_, Option<String>>(3),
            row.try_get::<_, Option<String>>(4),
            row.try_get::<_, bool>(5),
        ) else {
            // pgx v5 turns a failed `Scan` into a fatal row error: iteration stops there
            // and Go answers the rows read so far.
            break;
        };
        let mut item = format!("{{\"checkName\":{},\"consecutive\":{consecutive}", s(&name));
        if !error.is_empty() {
            item += &format!(",\"lastError\":{}", s(&error));
        }
        if let Some(at) = checked {
            item += &format!(",\"lastChecked\":{}", s(&at));
        }
        if let Some(at) = sent {
            item += &format!(",\"alertSentAt\":{}", s(&at));
        }
        item += &format!(",\"suppressed\":{suppressed}}}");
        out.push(item);
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/alerts/config`: `hc_*` and `alert_*` rows as a key to jsonb-text map. The
/// patterns keep Go's unescaped `_`, a one-character wildcard.
pub async fn config(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT key, value::text FROM system_config WHERE key LIKE 'hc_%' OR key LIKE 'alert_%' ORDER BY key",
            &[],
        )
        .await?;
    let mut map = std::collections::BTreeMap::new();
    for row in &rows {
        let (Ok(key), Ok(value)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1))
        else {
            continue;
        };
        map.insert(key, value);
    }
    let items: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), s(v)))
        .collect();
    Ok(done(format!("{{{}}}", items.join(","))))
}

/// `POST /admin/alerts/ack`.
pub async fn acknowledge(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    check: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("alert_ack"),
        &envelope(&auth, operation, &format!("ack:{check}")),
        &auth,
        deadline(),
        "INSERT INTO health_alerts (check_name, suppressed, acknowledged_at) \
         SELECT $4::text, true, now() WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (check_name) DO UPDATE SET suppressed = true, acknowledged_at = now(), updated_at = now() \
         RETURNING check_name",
        &[(&check, Type::TEXT)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

/// `POST /admin/alerts/unsuppress`: answers 204 whether or not a row matched.
pub async fn unsuppress(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    check: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("alert_unsuppress"),
        &envelope(&auth, operation, &format!("unsuppress:{check}")),
        &auth,
        deadline(),
        "UPDATE health_alerts SET suppressed = false, updated_at = now() \
         WHERE check_name = $4::text AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         RETURNING check_name",
        &[(&check, Type::TEXT)],
        |rows| {
            if rows.len() <= 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

/// `PUT /admin/alerts/config`: every key is upserted with Go's `json.Marshal` of the
/// decoded value, or none is.
pub async fn set_config(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    values: &serde_json::Map<String, Value>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let items: Vec<String> = values
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), super::config::go_any(v)))
        .collect();
    let document = format!("{{{}}}", items.join(","));
    setjoin_pg::run_receipted_command(
        exec,
        command("alert_config_set"),
        &envelope(&auth, operation, &document),
        &auth,
        deadline(),
        "INSERT INTO system_config (key, value, description) \
         SELECT e.key, e.value, 'Health check configuration' FROM jsonb_each($4::text::jsonb) e \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() \
         RETURNING key",
        &[(&document, Type::TEXT)],
        |_| Ok(()),
    )
    .await
}
