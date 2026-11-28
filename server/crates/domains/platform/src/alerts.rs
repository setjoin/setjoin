//! Platform slice `terms-remaining`, group `alerts`: health alert status, acknowledgement
//! and the `hc_`/`alert_` configuration namespace (`/admin/alerts*`), Go's `AlertsHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET /admin/alerts`: checks with at least three consecutive failures. A row whose
/// last error is NULL does not scan into Go's `string`, which ends the list there.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ALERTS_LIST, &[])
        .await?;
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

/// `GET /admin/alerts/config`: `hc_*` and `alert_*` rows as a key to jsonb-text map.
pub async fn config(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ALERTS_CONFIG_GET, &[])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    check: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("ack:{check}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ALERTS_ACK,
            &[&check],
            Some(command("alert_ack")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// `POST /admin/alerts/unsuppress`: answers 204 whether or not a row matched.
pub async fn unsuppress(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    check: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("unsuppress:{check}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ALERTS_UNSUPPRESS,
            &[&check],
            Some(command("alert_unsuppress")),
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

/// `PUT /admin/alerts/config`.
pub async fn set_config(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    values: &serde_json::Map<String, Value>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let items: Vec<String> = values
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), super::config::go_any(v)))
        .collect();
    let document = format!("{{{}}}", items.join(","));
    let env = envelope(user.user(), user.generation(), operation, &document);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ALERTS_CONFIG_SET,
            &[&document],
            Some(command("alert_config_set")),
            |_| Ok(()),
        )
        .await
}
