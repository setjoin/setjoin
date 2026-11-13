//! The current authority: `$seen` through `jmap_email_set_update`, called the
//! way the Go gateway calls it (`shared/dbscope` RunScoped: one transaction,
//! `app.current_mailbox_id` set locally, then the reducer).
use tokio_postgres::types::Type;
use tokio_postgres::Client;

use setjoin_contracts::command::SetMessageSeen;

use crate::harness::BoxError;
use crate::mark_read::{SeenOutcome, SetSeen};

pub struct ReducerPath;

impl SetSeen for ReducerPath {
    fn name(&self) -> &'static str {
        "reducer jmap_email_set_update"
    }

    async fn set_seen(
        &self,
        client: &mut Client,
        cmd: SetMessageSeen,
    ) -> Result<SeenOutcome, BoxError> {
        let mailbox = cmd.mailbox.get();
        let message = cmd.message.decimal();
        let patch = format!(
            r#"{{"{message}": {{"keywords": {{"$seen": {}}}}}}}"#,
            cmd.seen
        );
        let tx = client.transaction().await?;
        tx.query_typed(
            "SELECT set_config('app.current_mailbox_id', $1, true)",
            &[(&cmd.mailbox.decimal(), Type::TEXT)],
        )
        .await?;
        let result: String = tx
            .query_typed(
                "SELECT jmap_email_set_update($1, $2::jsonb)::text",
                &[(&mailbox, Type::INT8), (&patch, Type::TEXT)],
            )
            .await?[0]
            .get(0);
        tx.commit().await?;
        classify(&result, &message)
    }
}

/// Map the reducer's JMAP-shaped result for one id onto [`SeenOutcome`].
fn classify(result: &str, message: &str) -> Result<SeenOutcome, BoxError> {
    let compact: String = result.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains(&format!(
        r#""notUpdated":{{"{message}":{{"type":"notFound"}}"#
    )) {
        return Ok(SeenOutcome::NotFound);
    }
    if compact.contains(r#""notUpdated":{}"#)
        && (compact.contains(&format!(r#""updated":[{message}]"#)))
    {
        return Ok(SeenOutcome::Updated);
    }
    Err(format!("unexpected reducer result: {result}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_updated_and_not_found() {
        let up = r#"{"updated": [7], "newState": "3", "oldState": "2", "accountId": "1", "notUpdated": {}}"#;
        assert_eq!(classify(up, "7").unwrap(), SeenOutcome::Updated);
        let nf = r#"{"updated": [], "newState": "2", "oldState": "2", "accountId": "1", "notUpdated": {"7": {"type": "notFound"}}}"#;
        assert_eq!(classify(nf, "7").unwrap(), SeenOutcome::NotFound);
        let bad = r#"{"updated": [], "notUpdated": {"7": {"type": "invalidArguments"}}}"#;
        assert!(classify(bad, "7").is_err());
    }
}
