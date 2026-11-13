//! Browser-authenticated Office provider routes, recorded through the front door.
mod common;
#[path = "common/office_fixture.rs"]
mod office_fixture;
#[path = "common/office_go.rs"]
mod office_go;
#[path = "common/office_provider.rs"]
mod office_provider;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
macro_rules! case {
    ($name:ident,$route:literal,$case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            run($route, $case, None).await
        }
    };
}
case!(
    admin_configure_unicode_audit_reason,
    "configure",
    "unicode-header"
);
case!(
    admin_configure_body_limit_after_value,
    "configure",
    "body-limit"
);
case!(admin_qualify_missing_key, "qualify", "missing-key");
case!(admin_activate_go_uuid_wrapper, "activate", "uuid-wrapper");
case!(admin_configure_go_json, "configure", "go-json");
case!(admin_activate_go_json_scope, "activate", "go-json");
case!(
    admin_configure_late_type_error,
    "configure",
    "late-type-error"
);
case!(
    admin_signed_nonadmin_is_denied,
    "configure",
    "signed-nonadmin"
);
case!(admin_list_success, "list", "success");
case!(admin_list_cross_tenant, "list", "foreign");
case!(admin_list_invalid_input, "list", "invalid");
case!(admin_configure_success, "configure", "success");
case!(admin_configure_cross_tenant, "configure", "foreign");
case!(admin_configure_invalid_input, "configure", "invalid");
case!(admin_configure_repeat, "configure", "repeat");
case!(admin_qualify_success, "qualify", "success");
case!(admin_qualify_cross_tenant, "qualify", "foreign");
case!(admin_qualify_invalid_input, "qualify", "invalid");
case!(admin_qualify_repeat, "qualify", "repeat");
case!(admin_activate_success, "activate", "success");
case!(admin_activate_cross_tenant, "activate", "foreign");
case!(admin_activate_invalid_input, "activate", "invalid");
case!(admin_activate_repeat, "activate", "repeat");
case!(admin_remove_success, "remove", "success");
case!(admin_remove_cross_tenant, "remove", "foreign");
case!(admin_remove_invalid_input, "remove", "invalid");
case!(admin_remove_repeat, "remove", "repeat");
async fn run(route: &str, case: &str, mutation: Option<&str>) -> Result<(), common::BoxError> {
    let _serial = office_fixture::SERIAL.lock().await;
    let mutant = mutation.is_some();
    let mut owned_schema = None;
    let Some(db) = Db::for_case("office-admin") else {
        return Ok(());
    };
    let (c, seed) = office_fixture::seed(&db).await?;
    let result=async{
 if route=="activate"{c.batch_execute("UPDATE office_provider_qualifications SET provider_generation=2 WHERE provider_id='office1'").await?;}
 if matches!(route,"configure"|"activate"){c.batch_execute("UPDATE office_provider_policies SET route_state='connected_inactive',enabled=false WHERE provider_id='office1'").await?;}
 let provider=if route=="qualify"{Some(if case=="missing-key"{office_provider::start_with_document(b"<wopi-discovery/>").await?}else{office_provider::start().await?})}else{None};let mut receipt=0i64;
 if let Some(provider)=&provider{
 let manifest=json!([{"sha256":"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882","size":10}]).to_string();
 c.query_one("SELECT office_save_accept($1::text::uuid,$2,'qualification-save',$3,repeat('c',64),10,'application/octet-stream',$4::text::jsonb,NULL)",&[&seed.launch["launchId"].as_str().unwrap(),&setjoin_office::token_hash(&seed.token),&seed.version,&manifest]).await?;
 receipt=c.query_one("SELECT id FROM office_save_receipts WHERE space_id=$1",&[&seed.space]).await?.get(0);
 let config=json!({"privateAllowHosts":[reqwest::Url::parse(&provider.origin)?.host_str().unwrap()],"privateAllowCidrs":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],"profile":"existing-provider","proofDiscoveryUrl":format!("{}/hosting/discovery",provider.origin),"editorUrl":format!("{}/browser/editor",provider.origin),"wopiPublicBaseUrl":"https://mail.test"}).to_string();
 c.execute("UPDATE office_provider_policies SET config=$1::text::jsonb,config_sha256=encode(digest(($1::text::jsonb)::text,'sha256'),'hex'),route_state='connected_inactive',enabled=false WHERE provider_id='office1'",&[&config]).await?;
 }
 if case=="foreign"{c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_role_assignments WHERE user_id={}; COMMIT;",seed.account.user)).await?;}
 let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;let oracle=office_go::start(&db,s3).await?;let recording=oracle.is_some();
 let command_dsn=if let Some(kind)=mutation.filter(|m|*m!="status"){let(dsn,schema)=office_fixture::mutant_dsn(&c,&db,kind).await?;owned_schema=Some(schema);dsn}else{db.app.as_deref().unwrap_or(&db.dsn).to_owned()};
 let exec=setjoin_pg::ScopedExecutor::from_dsn(&command_dsn,4).map_err(|e|e.0)?;
 let adapter=setjoin_gateway::office::OfficeAdminRoute{exec,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into(),provider_client:provider.as_ref().map(office_provider::client).transpose()?};
 let table=if recording{RouteTable::proxy_all()}else if mutation==Some("status"){RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)};
 let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for r in inventory["routes"].as_array_mut().unwrap(){if r["family"]=="F15"{r["state"]="ON".into();r["upstream"]="local-rust".into();}}
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
 let(method,pattern,mut body)=match route{
 "configure"=>("PUT","/admin/office/providers/{providerId}",json!({"expectedGeneration":2,"profile":"existing-provider","entitlementState":"valid","buildId":"test-1","config":{"editorUrl":"https://editor.test/browser","proofDiscoveryUrl":"https://editor.test/hosting/discovery","wopiPublicBaseUrl":"https://mail.test"}}).to_string()),
 "qualify"=>("POST","/admin/office/providers/{providerId}/qualify",json!({"expectedGeneration":2,"syntheticReceiptId":if case=="invalid"{0}else{receipt},"routeRevision":1}).to_string()),
 "activate"=>("POST","/admin/office/providers/{providerId}/activate",json!({"expectedGeneration":2,"qualificationId":if case=="invalid"{"invalid"}else{&seed.qualification},"scope":{}}).to_string()),
 "remove"=>("DELETE","/admin/office/providers/{providerId}",String::new()),_=>("GET","/admin/office",String::new())};
 if route=="activate"&&case=="uuid-wrapper"{body=format!(r#"{{"expectedGeneration":2,"qualificationId":"[{}]","scope":{{}}}}"#,seed.qualification);}
 if route=="configure"&&case=="body-limit"{body.push_str(&" ".repeat(65536));}
 if route=="configure"&&case=="go-json"{body=r#"{"ExpectedGeneration":2,"expectedGeneration":null,"PROFILE":"existing-provider","profile":null,"entitlementState":"valid","config":{"editorUrl":"https://editor.test/browser","proofDiscoveryUrl":"https://editor.test/hosting/discovery","wopiPublicBaseUrl":"https://mail.test"}}"#.into();}
 if route=="activate"&&case=="go-json"{body=format!(r#"{{"ExpectedGeneration":2,"qualificationId":"{}","ſcope":{{"parity":true}}}}"#,seed.qualification);}
 if route=="configure"&&case=="late-type-error"{body=r#"{"expectedGeneration":"bad","expectedGeneration":2,"profile":"existing-provider","entitlementState":"valid","config":{"editorUrl":"https://editor.test/browser","proofDiscoveryUrl":"https://editor.test/hosting/discovery","wopiPublicBaseUrl":"https://mail.test"}}"#.into();}
 if route=="configure"&&case=="invalid"{body="{".into();}
 if route=="list"&&case=="invalid"{body="not-json".into();}
 let reason=if case=="unicode-header"{"Office1 审核原因"}else if route=="remove"&&case=="invalid"{""}else{"Office1 parity"};
 let before=office_fixture::snapshot(&c,&seed).await?;let mut notifications=db.listen("office_provider_changed").await?;let mut responses=Vec::new();
 for index in 0..if case=="repeat"{2}else{1}{
 let uri=format!("/api{}{}",pattern.replace("{providerId}","office1"),if route=="list"&&case=="invalid"{"?limit=not-an-integer"}else{""});
 let response=common::send(address,Request::builder().method(method).uri(uri).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","office1-admin").header("x-audit-reason",reason).header("authorization",format!("Bearer {}",office_fixture::token(seed.account.user,case!="signed-nonadmin"))).body(common::full(body.clone()))?).await;
 let status=response.status().as_u16();let headers=office_fixture::headers(response.headers())?;let bytes=common::body_bytes(response).await;
 let expected=if matches!(case,"foreign"|"signed-nonadmin"){403}else if case=="missing-key"{409}else if matches!(case,"late-type-error"|"body-limit"){400}else if case=="invalid"&&route!="list"{400}else if case=="repeat"&&index==1&&matches!(route,"configure"|"activate"){409}else{200};
 if !mutant&&status!=expected{task.abort();return Err(format!("{route}/{case}/{index}: expected {expected}, got {status} {bytes:?}").into());}
 let mut value:Value=serde_json::from_slice(&bytes)?;normalize(&mut value,"");responses.push(json!({"status":status,"headers":headers,"body":value}));
 }
 let after=office_fixture::snapshot(&c,&seed).await?;task.abort();
 let notify:Vec<Value>=notifications.drain(&c).await?.iter().map(|raw|{let mut value=serde_json::from_str(raw).unwrap();normalize(&mut value,"");value}).collect();let effects=office_fixture::effects(&before,&after);
 let audit:Vec<_>=after["core_audit"].as_array().unwrap().iter().filter(|r|!before["core_audit"].as_array().unwrap().contains(r)).cloned().collect();
 let mut request_body=if matches!(case,"go-json"|"late-type-error"|"uuid-wrapper"|"body-limit"){Value::String(body.replace(&seed.qualification,"<qualification>"))}else{serde_json::from_str::<Value>(&body).unwrap_or_else(|_|body.clone().into())};if route=="activate"&&case!="invalid"&&case!="go-json"&&case!="uuid-wrapper"{request_body["qualificationId"]="<qualification>".into();}if route=="qualify"&&case!="invalid"{request_body["syntheticReceiptId"]="<synthetic-receipt>".into();}
 let mut observation=json!({"request":{"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"headers":{"authorization":"<verified-session>","x-audit-reason":reason,"host":"mail.test","origin":"http://mail.test"},"body":request_body},"response":responses[0],"responses":responses,"effects":effects,"audit":audit,"notify":notify});
 if let Some(provider)=&provider{observation["provider"]=serde_json::to_value(&*provider.requests.lock().unwrap())?;let hash:String=c.query_one("SELECT config_sha256 FROM office_provider_policies WHERE provider_id='office1'",&[]).await?.get(0);normalize_provider(&mut observation,&provider.origin,&hash);}
 office_fixture::compare_or_record(&format!("admin-{route}-{case}-wire{}",if route=="qualify"{"-v3"}else{""}),&format!("{method} {pattern}"),case,&observation,recording,route!="list")?;
 Ok::<_,common::BoxError>(())
 }.await;
    if let Some(schema) = owned_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    office_fixture::cleanup(&c, &seed).await?;
    result
}
fn normalize(value: &mut Value, key: &str) {
    match value {
        Value::Object(o) => {
            for (k, v) in o {
                normalize(v, k)
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize(v, key)
            }
        }
        Value::String(s)
            if matches!(
                key,
                "qualificationId" | "activeQualificationId" | "qualification_id"
            ) =>
        {
            assert!(setjoin_office::uuid(s).is_some());
            *s = "<qualification>".into()
        }
        Value::String(s)
            if matches!(key, "createdAt" | "updatedAt" | "expiresAt" | "observedAt") =>
        {
            chrono::DateTime::parse_from_rfc3339(s).expect("valid timestamp");
            *s = "<timestamp>".into()
        }
        _ => {}
    }
}
fn normalize_provider(value: &mut Value, origin: &str, hash: &str) {
    match value {
        Value::Object(o) => {
            for v in o.values_mut() {
                normalize_provider(v, origin, hash)
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_provider(v, origin, hash)
            }
        }
        Value::String(s) => {
            if s == hash {
                *s = "<provider-config-sha>".into()
            } else if reqwest::Url::parse(origin)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .as_deref()
                == Some(s.as_str())
            {
                *s = "<provider-host>".into()
            } else if s.contains(origin) {
                *s = s.replace(origin, "<provider-origin>")
            }
        }
        _ => {}
    }
}
struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::office::OfficeAdminRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        })
    }
}

macro_rules! mutant {
    ($name:ident,$route:literal,$pattern:literal,$method:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            let error = run($route, "success", Some("status"))
                .await
                .expect_err("changed status must fail Go golden");
            assert!(error.to_string().contains("/response/status"), "{error}");
            eprintln!(
                "MUTANT-REJECTED: {} {} :: changed-status",
                $method, $pattern
            );
            Ok(())
        }
    };
}
mutant!(
    list_oracle_rejects_changed_status,
    "list",
    "/admin/office",
    "GET"
);
mutant!(
    configure_oracle_rejects_changed_status,
    "configure",
    "/admin/office/providers/{providerId}",
    "PUT"
);
mutant!(
    qualify_oracle_rejects_changed_status,
    "qualify",
    "/admin/office/providers/{providerId}/qualify",
    "POST"
);
mutant!(
    activate_oracle_rejects_changed_status,
    "activate",
    "/admin/office/providers/{providerId}/activate",
    "POST"
);
mutant!(
    remove_oracle_rejects_changed_status,
    "remove",
    "/admin/office/providers/{providerId}",
    "DELETE"
);
macro_rules! family_mutant {
    ($name:ident,$kind:literal,$label:literal,$pointer:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            let error = run("configure", "success", Some($kind))
                .await
                .expect_err("executable SQL mutation must fail Go golden");
            assert!(error.to_string().contains($pointer), "{error}");
            eprintln!(
                "MUTANT-REJECTED: PUT /admin/office/providers/{{providerId}} :: {}",
                $label
            );
            Ok(())
        }
    };
}
family_mutant!(
    family_oracle_rejects_no_audit,
    "audit",
    "no-audit",
    "/audit"
);
family_mutant!(
    family_oracle_rejects_no_notify,
    "notify",
    "no-notify",
    "/notify"
);
family_mutant!(
    family_oracle_rejects_double_bump,
    "bump",
    "double-bump",
    "generation"
);
