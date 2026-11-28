//! Explicit legacy-schema fixture. Runtime schema intentionally remains unchanged.
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;
pub async fn seed(c: &tokio_postgres::Client, a: &Account) -> Result<(), BoxError> {
    let present:bool=c.query_one("SELECT to_regclass('public.rule_templates') IS NOT NULL OR to_regclass('public.rule_template_visibility') IS NOT NULL",&[]).await?.get(0);
    if present {
        return Err("refusing to replace existing template tables".into());
    }
    c.batch_execute(concat!(
        "BEGIN;",
        include_str!("../../../../tests/conformance/rules/legacy-fixture.sql"),
        "COMMIT;"
    ))
    .await?;
    c.batch_execute("INSERT INTO rule_templates(id,name,description,category,conditions,actions,parameters,is_system,enabled,sort_order,created_at,updated_at) VALUES(961011,'Template one','Description one','general','[{\"field\":\"subject\",\"op\":\"contains\",\"value\":\"{{word}}\"}]','[{\"type\":\"mark_read\"}]','[{\"key\":\"word\",\"label\":\"Subject\",\"type\":\"text\"}]',false,true,1,'2026-10-01','2026-10-01'),(961012,'System template','Description system','security','[]','[]','[]',true,true,2,'2026-10-01','2026-10-01'),(961013,'Disabled template','Description disabled','general','[]','[]','[]',false,false,3,'2026-10-01','2026-10-01');SELECT setval('rule_templates_id_seq',962010);").await?;
    c.execute("INSERT INTO rule_template_visibility(template_id,user_id,hidden) VALUES(961011,$1,true),(961012,NULL,true)",&[&a.user]).await?;
    Ok(())
}
pub async fn snapshot(c: &tokio_postgres::Client, out: &mut Value) -> Result<(), BoxError> {
    let present: bool = c
        .query_one(
            "SELECT to_regclass('public.rule_templates') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    out["template_tables_present"] = json!(present);
    if present {
        for (key,sql) in [("templates","SELECT to_jsonb(t)::text FROM rule_templates t ORDER BY id"),("visibility","SELECT to_jsonb(v)::text FROM rule_template_visibility v ORDER BY template_id,user_id NULLS FIRST")] {
            let rows:Vec<Value>=c.query(sql,&[]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
            out[key]=json!(rows);
        }
    }
    Ok(())
}
pub async fn remove(c: &tokio_postgres::Client) -> Result<(), BoxError> {
    c.batch_execute("DROP TABLE public.rule_template_visibility;DROP TABLE public.rule_templates;")
        .await?;
    Ok(())
}
