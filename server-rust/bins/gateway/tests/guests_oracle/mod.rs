use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{guests::GuestsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub async fn run(action: &str, kind: &str, mutant: bool) -> Result<(), BoxError> {
    let unfiltered = kind.ends_with("-unfiltered");
    let kind = kind.strip_suffix("-unfiltered").unwrap_or(kind);
    let Some(db) = Db::for_case("guests-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "guests1-admin").await?;
    let b = fixture::account(&owner, "guests1-other").await?;
    let (guest, guest_email) = seed_guest(&owner, &a).await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,ARRAY['guests.view','guests.manage'],$2) RETURNING id",&[&format!("guests1-{}",a.user),&a.domain]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let domain_name: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
        .await?
        .get(0);
    let other_domain_name: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&b.domain])
        .await?
        .get(0);
    let profile:i64=owner.query_one("INSERT INTO guest_profiles(host_domain_id,name,apps,created_at,updated_at) VALUES($1,'Profile <one>',ARRAY['chat'],'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z') RETURNING id",&[&a.domain]).await?.get(0);
    if kind == "foreign" {
        owner
            .execute(
                "UPDATE admin_role_groups SET domain_scope=$2 WHERE id=$1",
                &[&role, &b.domain],
            )
            .await?;
    }
    let enabled: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?;
    let result=async {
 let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
 let go=common::go_oracle::start_named(&db,s3,None,"gofree-guests1-http").await?;
 let recording=go.is_some();
 let adapter=GuestsRoute{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),lifecycle:None,delivery:None};
 let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
 for route in inventory["routes"].as_array_mut().ok_or("routes")? {if route["family"]=="F11"{route["state"]=json!(if recording{"OFF"}else{"ON"});route["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});route["oracle_commands"]=json!([""]);}}
 let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(probe::Probe{inner:adapter,changed_status:mutant,unfiltered}))?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
 let server=tokio::spawn(gateway.serve(listener));
 let path=if action=="sponsors"{"/admin/guests/{id}/sponsor-options"}else if action=="guest-get"{"/admin/guests/{id}"}else if action=="guests-list"{"/admin/guests"}else if action=="profile-domains"{"/admin/guest-profile-domains"}else if action=="profile-get"{"/admin/guest-profiles/{id}"}else{"/admin/guest-profiles"};
 let external_path=path.replace("{id}",&if kind=="invalid"{"bad".into()}else if matches!(action,"guest-get"|"sponsors"){guest.to_string()}else{profile.to_string()});
 let uri=format!("/api{external_path}{}",if kind=="invalid"&&matches!(action,"profiles-list"|"profile-domains"|"guests-list"){"?ignored=bad"}else{""});
 let uri=if kind.starts_with("long-query"){format!("{uri}?q={}","x".repeat(201))}else{uri};
 let response=common::send(address,Request::get(uri).header("host","mail.test").header("x-request-id","gofree-guests1-oracle").header("authorization",format!("Bearer {}",admin_token(a.user))).body(common::full(""))?).await;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();
 for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
 let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
 let wanted=if kind.starts_with("long-query"){400}else if matches!(action,"profile-get"|"guest-get")&&kind=="foreign"{404}else if matches!(action,"profile-get"|"guest-get"|"sponsors")&&kind=="invalid"{400}else{200};
 if recording && status!=wanted{return Err(format!("profile list expected 200, got {status}: {raw}").into());}
 let parsed:Value=serde_json::from_str(&raw)?;if action=="profiles-list" && ((kind=="foreign"&&parsed!=json!([]))||(kind!="foreign"&&(parsed[0]["id"]!=profile||parsed[0]["name"]!="Profile <one>"))){return Err(format!("profile fixture not visible: {raw}").into());}
 let (target,target_marker)=if matches!(action,"guest-get"|"sponsors"){(guest,"<guest>")}else{(profile,"<profile>")};
 let raw=raw.replace(&format!("/{target}\""),&format!("/{target_marker}\"")).replace(&format!("/{target}/"),&format!("/{target_marker}/"));
 let (primary,marker)=if action=="sponsors"{(a.user,"<admin>")}else if matches!(action,"guests-list"|"guest-get"){(guest,"<guest>")}else if action=="profile-domains"{(if kind=="foreign"{b.domain}else{a.domain},if kind=="foreign"{"<other-domain>"}else{"<domain>"})}else{(profile,"<profile>")};
 let raw=raw.replace(&format!("\"invitedBy\":{}",a.user),"\"invitedBy\":\"<admin>\"").replace(&guest_email,"guest@outside.test").replace(&format!("\"sponsorUserId\":{}",a.user),"\"sponsorUserId\":\"<admin>\"");
 let body=raw.replace(&domain_name,"host.test").replace(&other_domain_name,"other.test").replace(&format!("\"id\":{primary}"),&format!("\"id\":\"{marker}\"")).replace(&format!("\"hostDomainId\":{}",a.domain),"\"hostDomainId\":\"<domain>\"");
 if let Some(date)=headers.get_mut("date"){assert!(chrono::DateTime::parse_from_rfc2822(date[0].as_str().ok_or("date")?).is_ok());*date=json!(["<timestamp>"]);}
 if headers.contains_key("content-length"){headers.insert("content-length".into(),json!([body.len().to_string()]));}
 let mut observation=json!({"request":{"method":"GET","path":path,"external_path":format!("/api{path}")},"response":{"status":status,"headers":headers,"body":body},"effects":[],"audit":[],"notify":[]});
 if kind.starts_with("long-query"){observation["request"]["query"]=json!(format!("q={}","x".repeat(201)));}
 if !recording{probe::no_go(address).await?;}server.abort();
 let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/guests/goldens/{action}-{kind}.json"));
 if recording {record(&file,&json!({"format":1,"route":format!("GET {path}"),"case":kind,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;if mutant{probe::rejected(golden::compare(&expected["observation"],&observation).map_err(Into::into),&format!("GET {path}"))?;}else{golden::compare(&expected["observation"],&observation)?;}eprintln!("GOLDEN-REPLAY: GET {path} :: {kind}");}
 let _=mutant;Ok::<_,BoxError>(())
 }.await;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1",&[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner
        .execute("DELETE FROM guest_profiles WHERE id=$1", &[&profile])
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&enabled],
        )
        .await?;
    owner
        .execute("DELETE FROM users WHERE id=$1", &[&guest])
        .await?;
    common::remove_blob_account(&owner, &a).await?;
    common::remove_blob_account(&owner, &b).await?;
    result
}
fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
pub mod writes;

pub async fn seed_guest(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
) -> Result<(i64, String), BoxError> {
    seed_guest_state(c, a, "active").await
}
pub async fn seed_guest_state(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    state: &str,
) -> Result<(i64, String), BoxError> {
    let email: String = c
        .query_one(
            "SELECT 'guests1-'||gen_random_uuid()::text||'@outside.test'",
            &[],
        )
        .await?
        .get(0);
    let id:i64=c.query_one("WITH u AS(INSERT INTO users(username,email,domain_id,display_name,enabled) SELECT $1,$1,id,'Guest <one>',($4='active') FROM domains WHERE name='guest.invalid' RETURNING id), g AS(INSERT INTO guest_accounts(user_id,invited_email,invited_by,invited_by_email,sponsor_user_id,host_domain_id,status,expires_at,created_at,updated_at) SELECT u.id,$1,$2,(SELECT email FROM users WHERE id=$2),$2,$3,$4,'2099-11-01T12:00:00Z','2026-10-01T12:00:00Z','2026-10-01T12:00:00Z' FROM u RETURNING user_id) SELECT user_id FROM g",&[&email,&a.user,&a.domain,&state]).await?.get(0);
    Ok((id, email))
}
pub mod domains;
pub mod mail;
pub mod mutations;
pub mod submit;

pub mod probe;
pub mod worker;

/// Verification mode compares immutable Go observations instead of rewriting them.
pub fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
