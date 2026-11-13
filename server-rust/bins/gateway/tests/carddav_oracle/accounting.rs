//! Public command seam: a contact may disappear after the HTTP ownership read.
use super::{common, fixture, json, BoxError, Db};
pub async fn stale() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("cal5-stale-contact") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "cal5-stale").await?;
    let result=async {
        let book:i64=owner.query_one("INSERT INTO addressbooks(mailbox_id,name) VALUES($1,'CAL5 stale') RETURNING id",&[&a.mailbox]).await?.get(0);
        let contact:i64=owner.query_one("INSERT INTO contacts(addressbook_id,vcard_uid,display_name) VALUES($1,'cal5-stale','Stale') RETURNING id",&[&book]).await?.get(0);
        let exec=common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn),1)?;
        let keys=std::sync::Arc::new(common::recovery_keys());let mut headers=hyper::HeaderMap::new();headers.insert("authorization",format!("Bearer {}",common::recovery_token(a.user)).parse()?);
        let auth=setjoin_authz::authorize_user_request(&exec,&keys,"mailserver",&headers,"http").await.ok_or("authority")?;
        owner.execute("DELETE FROM contacts WHERE id=$1",&[&contact]).await?;
        use setjoin_calendar::carddav::{publish,Operation};
        for (kind,failed) in [(Operation::Update,"notUpdated"),(Operation::Delete,"notDestroyed")] {
            let payload=json!({contact.to_string():{"displayName":"Changed","addressbookId":book}}).to_string();
            let outcome=publish(&exec,auth.context(),book,contact,&payload,kind,{let mut id=[0;16];ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(),&mut id).map_err(|_|"random operation")?;id}).await;
            let setjoin_pg::CommandOutcome::Committed(raw)=outcome else{return Err("canonical missing contact was not accounted".into())};
            let raw:serde_json::Value=serde_json::from_str(&raw)?;
            if raw[failed][contact.to_string()]["type"]!="notFound" {return Err(format!("missing contact lost per-item accounting: {raw}").into())}
        }Ok::<_,BoxError>(())
    }.await;
    if let Err(error) = &result {
        eprintln!("stale-contact result before cleanup: {error}");
    }
    owner
        .execute(
            "DELETE FROM addressbooks WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM jmap_changes_journal WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?;
    common::remove_blob_account(&owner, &a).await?;
    result
}
