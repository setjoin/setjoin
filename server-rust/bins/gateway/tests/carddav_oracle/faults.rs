//! Scoped reducer failures in the owned disposable schema, restored after each case.
use super::BoxError;
pub async fn install(
    c: &tokio_postgres::Client,
    route: &str,
    label: &str,
) -> Result<Vec<String>, BoxError> {
    if !matches!(label, "db-fault" | "unaccounted" | "bad-accounting") {
        return Ok(vec![]);
    }
    let signature = match route {
        "put" => "jmap_contact_set_create(bigint,jsonb)",
        "put-update" => "jmap_contact_set_update(bigint,jsonb)",
        "delete" => "jmap_contact_set_destroy(bigint,bigint[])",
        "sync" => "caldav_changes(bigint,text,bigint,text)",
        "gal-sync" => "gal_changes(bigint,bigint,bigint)",
        _ => return Err("unknown fault command".into()),
    };
    let original: String = c
        .query_one(
            "SELECT pg_get_functiondef($1::text::regprocedure)",
            &[&signature],
        )
        .await?
        .get(0);
    let (head, _) = original
        .split_once("$function$")
        .ok_or("function body marker")?;
    let body = match label {
        "db-fault" => {
            "BEGIN RAISE EXCEPTION 'gofree-cal5 scoped reducer fault' USING ERRCODE='XX000'; END"
        }
        "bad-accounting" => "BEGIN RETURN '{\"updated\":[\"not-an-id\"]}'::jsonb; END",
        _ => "BEGIN RETURN '{}'::jsonb; END",
    };
    c.batch_execute(&format!("{head}$function${body}$function$\n"))
        .await?;
    Ok(vec![original])
}
