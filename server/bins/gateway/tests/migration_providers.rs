//! Provider protocol seams: real HTTPS source, authentication and bounded pages.
use setjoin_gateway::migration_runner::ews::{EwsConfig, EwsConnector};

#[tokio::test]
async fn ews_rejects_non_https_before_authentication() {
    let cfg = EwsConfig {
        server_url: "http://exchange.example/EWS".into(),
        ..Default::default()
    };
    assert_eq!(
        EwsConnector::new(cfg).err().unwrap(),
        "invalid EWS server URL: EWS server URL must use https scheme"
    );
}
mod common;
#[path = "common/fake_microsoft.rs"]
mod fake_microsoft;

#[tokio::test]
async fn ews_https_session_enumerates_mail_calendar_contacts_and_checkpoints(
) -> Result<(), common::BoxError> {
    let peer = fake_microsoft::Peer::start("127.0.0.1:0", "success").await?;
    let cfg = EwsConfig {
        server_url: format!("https://ews.mbox7.test:{}/EWS", peer.address.port()),
        username: "DOMAIN\\service".into(),
        password: "pw".into(),
        impersonate_as: "source@example.test".into(),
        ..Default::default()
    };
    let mut source = EwsConnector::with_client(cfg, peer.client.clone())?;
    source.test_connection().await?;
    let mut batches = vec![];
    while let Some(batch) = source.next_batch().await? {
        batches.push(batch);
    }
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].items[0].raw, fake_microsoft::MAIL.as_bytes());
    assert_eq!(batches[1].items[0].ics, fake_microsoft::ICS);
    assert_eq!(batches[2].items[0].vcf, fake_microsoft::VCF);
    assert_eq!(batches[0].items[0].object_id, "inbox-item");
    assert_eq!(batches[0].items[0].version, "v1");
    assert!(
        matches!(&batches[2].checkpoint, setjoin_gateway::migration_runner::Checkpoint::Delta {scope,kind,value,..} if scope=="contacts" && *kind=="ews_sync_state" && value=="state-contacts")
    );
    assert!(peer
        .seen
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["anchor"] == "source@example.test"));
    Ok(())
}

#[tokio::test]
async fn m365_https_session_uses_oauth_and_resolves_one_mailbox() -> Result<(), common::BoxError> {
    use setjoin_gateway::migration_runner::m365::{M365Config, M365Connector};
    let peer = fake_microsoft::Peer::start("127.0.0.87:443", "success").await?;
    let cfg = M365Config {
        client_id: "client".into(),
        client_secret: "secret".into(),
        tenant_id: "tenant".into(),
        cloud: "global".into(),
        source_email: "source@example.test".into(),
        source_user_id: String::new(),
    };
    let mut source = M365Connector::with_client(cfg, peer.client.clone());
    let identity = source.identity().await?;
    assert_eq!(identity.0, "m365:source-user");
    let mut items = vec![];
    while let Some(batch) = source.next_batch().await? {
        items.extend(batch.items);
    }
    assert_eq!(items.len(), 3);
    assert!(items
        .iter()
        .any(|i| i.raw == fake_microsoft::MAIL.as_bytes()));
    assert!(items.iter().any(|i| i.ics.contains("UID:graph-event\r\n")));
    assert!(items.iter().any(|i| i.vcf.contains("FN:Graph contact\r\n")));
    let seen = peer.seen.lock().unwrap();
    assert!(seen.iter().any(|r| r["path"]
        .as_str()
        .unwrap()
        .contains("/tenant/oauth2/v2.0/token")));
    assert_eq!(
        seen.iter()
            .filter(|r| r["path"]
                .as_str()
                .unwrap()
                .contains("/users/source%40example.test?"))
            .count(),
        1
    );
    assert!(seen
        .iter()
        .filter(|r| r["path"].as_str().unwrap().contains("/messages/"))
        .all(|r| r["prefer"] == "IdType=\"ImmutableId\""));
    Ok(())
}

#[tokio::test]
async fn ews_negotiates_connection_bound_authentication() -> Result<(), common::BoxError> {
    let peer = fake_microsoft::Peer::start("127.0.0.1:0", "negotiate").await?;
    let cfg = EwsConfig {
        server_url: format!("https://ews.mbox7.test:{}/EWS", peer.address.port()),
        username: "DOMAIN\\service".into(),
        password: "pw".into(),
        ..Default::default()
    };
    EwsConnector::with_client(cfg, peer.client.clone())?
        .test_connection()
        .await?;
    let seen = peer.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen
        .iter()
        .all(|r| r["connection"] == seen[0]["connection"]));
    assert!(seen[1]["authorization"]
        .as_str()
        .unwrap()
        .starts_with("Negotiate "));
    assert!(seen[2]["authorization"]
        .as_str()
        .unwrap()
        .starts_with("Negotiate "));
    // Every request uses the real HTTPS handshake and the recorded provider frame.
    Ok(())
}
