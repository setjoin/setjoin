//! Faults change the owned disposable schema only, restored before observation.
use super::*;
fn table(action: &str) -> &'static str {
    match action {
        "policies" => "chat_retention_policies",
        "cases" => "ediscovery_cases",
        "holds" => "chat_case_holds",
        "overview" => "chat_channels",
        "preview" => "chat_retention_policies",
        _ => panic!("unsupported query fault"),
    }
}
pub async fn install(c: &tokio_postgres::Client, label: &str) -> Result<(), BoxError> {
    if label == "write-failure" {
        c.batch_execute("CREATE FUNCTION gofree_compl3_write_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'compl3 write fault';END;$$;CREATE TRIGGER gofree_compl3_write_fault BEFORE INSERT OR UPDATE OR DELETE ON chat_retention_policies FOR EACH ROW EXECUTE FUNCTION gofree_compl3_write_fault()").await?;
    }
    if label == "case-name-failure" {
        c.batch_execute("CREATE FUNCTION gofree_compl3_case_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$BEGIN IF NEW.action='chat_ediscovery_export' THEN ALTER TABLE ediscovery_cases RENAME TO gofree_compl3_case_fault;END IF;RETURN NEW;END;$$;CREATE TRIGGER gofree_compl3_case_fault AFTER INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl3_case_fault()").await?;
    }
    Ok(())
}
pub async fn rename(c: &tokio_postgres::Client, action: &str) -> Result<(), BoxError> {
    c.batch_execute(&format!(
        "ALTER TABLE {} RENAME TO gofree_compl3_query_fault",
        table(action)
    ))
    .await?;
    Ok(())
}
pub async fn restore(
    c: &tokio_postgres::Client,
    action: &str,
    label: &str,
) -> Result<(), BoxError> {
    if label == "query-failure" {
        c.batch_execute(&format!("DO $$BEGIN IF to_regclass('public.gofree_compl3_query_fault') IS NOT NULL THEN ALTER TABLE gofree_compl3_query_fault RENAME TO {};END IF;END;$$",table(action))).await?;
    }
    if label == "case-name-failure" {
        c.batch_execute("DO $$BEGIN IF to_regclass('public.gofree_compl3_case_fault') IS NOT NULL THEN ALTER TABLE gofree_compl3_case_fault RENAME TO ediscovery_cases;END IF;END;$$").await?;
    }
    Ok(())
}
pub async fn cleanup(
    c: &tokio_postgres::Client,
    action: &str,
    label: &str,
) -> Result<(), BoxError> {
    restore(c, action, label).await?;
    if label == "write-failure" {
        c.batch_execute("DROP TRIGGER IF EXISTS gofree_compl3_write_fault ON chat_retention_policies;DROP FUNCTION IF EXISTS gofree_compl3_write_fault()").await?;
    }
    if label == "case-name-failure" {
        c.batch_execute("DROP TRIGGER IF EXISTS gofree_compl3_case_fault ON admin_audit_log;DROP FUNCTION IF EXISTS gofree_compl3_case_fault()").await?;
    }
    Ok(())
}
