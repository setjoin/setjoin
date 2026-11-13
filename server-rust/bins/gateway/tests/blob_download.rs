//! Blob ownership and bytes are observed through the front door.
mod common;

use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    blobs::{BlobCommands, BlobRoute},
    recovery_worker::S3Store,
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::test]
async fn user_downloads_an_attachment_from_their_mailbox_without_go() -> Result<(), common::BoxError>
{
    run_case(Case::Owned, false).await
}

#[tokio::test]
async fn foreign_user_cannot_fetch_another_mailboxs_blob() -> Result<(), common::BoxError> {
    run_case(Case::Foreign, false).await
}

#[tokio::test]
async fn a_cached_blob_uses_gos_serve_content_headers_on_repeat() -> Result<(), common::BoxError> {
    run_case(Case::Repeat, false).await
}

#[tokio::test]
async fn malformed_blob_identifier_is_hidden_as_not_found() -> Result<(), common::BoxError> {
    run_case(Case::Invalid, false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(BlobRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> Intercept for ChangedStatus<K> {
    fn matches(&self, req: &Request<Body>) -> bool {
        self.0.matches(req)
    }
    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.0.handle(req, ctx);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        })
    }
}

#[tokio::test]
async fn blob_download_oracle_rejects_a_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case(Case::Owned, true)
        .await
        .expect_err("changed Rust status must fail the frozen Go golden");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /blobs/{{sha256}} :: changed-status");
    Ok(())
}

#[derive(Clone, Copy)]
enum Case {
    Owned,
    Foreign,
    NoTenant,
    Repeat,
    Invalid,
    Head,
    Missing,
    Encoded,
    Large,
    Range,
    CachedRange,
}

#[tokio::test]
async fn head_returns_the_owned_blob_headers_without_body() -> Result<(), common::BoxError> {
    run_case(Case::Head, false).await
}

#[tokio::test]
async fn owned_blob_missing_from_storage_returns_gos_not_found() -> Result<(), common::BoxError> {
    run_case(Case::Missing, false).await
}

#[tokio::test]
async fn percent_encoded_blob_hash_uses_gos_decoded_path_value() -> Result<(), common::BoxError> {
    run_case(Case::Encoded, false).await
}

#[tokio::test]
async fn large_blob_streams_the_complete_owned_object() -> Result<(), common::BoxError> {
    run_case(Case::Large, false).await
}

#[tokio::test]
async fn cold_blob_range_returns_only_the_requested_bytes() -> Result<(), common::BoxError> {
    run_case(Case::Range, false).await
}

#[tokio::test]
async fn cached_blob_range_returns_only_the_requested_bytes() -> Result<(), common::BoxError> {
    run_case(Case::CachedRange, false).await
}

async fn run_case(case: Case, status_mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let foreign_caller = matches!(case, Case::Foreign | Case::NoTenant);
    let repeat = matches!(case, Case::Repeat | Case::CachedRange);
    let invalid_hash = matches!(case, Case::Invalid);
    let head = matches!(case, Case::Head);
    let missing = matches!(case, Case::Missing);
    let encoded = matches!(case, Case::Encoded);
    let large = matches!(case, Case::Large);
    let ranged = matches!(case, Case::Range | Case::CachedRange);
    let Some(db) = Db::for_case("blob-download-owned") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-download").await?;
    let foreign = if foreign_caller {
        Some(fixture::account(&owner, "blobs1-foreign").await?)
    } else {
        None
    };
    let caller = foreign.as_ref().unwrap_or(&account);
    let bytes = if large {
        "x".repeat(10 << 20)
    } else {
        format!("gofree-blobs1 object for {}", account.user)
    };
    let hash = format!("{:x}", Sha256::digest(bytes.as_bytes()));
    let size = bytes.len() as i64;
    let encoded_hash = format!("%{:02X}{}", hash.as_bytes()[0], &hash[1..]);
    let target = if invalid_hash {
        "not-a-sha256"
    } else if encoded {
        &encoded_hash
    } else {
        &hash
    };
    owner.execute("INSERT INTO blobs (sha256,minio_ref,size_bytes,content_type,ref_count) VALUES ($1,$1,$2,'text/plain',0)", &[&hash,&size]).await?;
    owner.execute("INSERT INTO message_attachments (message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes) SELECT id,received_at,$1,'file.txt','text/plain','attachment',$2 FROM messages WHERE id=$3 AND mailbox_id=$4", &[&hash,&size,&account.two_labels,&account.mailbox]).await?;
    let mut mutant_schema = None;
    let result = async {
        let content = bytes.clone();
        let endpoint = common::fake_upstream(move |request| {
            let content = content.clone();
            async move {
                if request.uri().query() == Some("location=") {
                    Response::new(common::full(
                        "<LocationConstraint>us-east-1</LocationConstraint>",
                    ))
                } else if missing {
                    Response::builder().status(404).header("content-type","application/xml")
                        .body(common::full("<Error><Code>NoSuchKey</Code><Message>missing object</Message></Error>")).unwrap()
                } else if request.headers().get("range").is_some() {
                    let value = request.headers()["range"].to_str().unwrap().strip_prefix("bytes=").unwrap();
                    let (start,end) = value.split_once('-').unwrap();
                    let start = start.parse::<usize>().unwrap();
                    let end = if end.is_empty() {content.len()-1} else {end.parse::<usize>().unwrap()};
                    let part = &content.as_bytes()[start..=end];
                    Response::builder().status(206).header("content-type","text/plain")
                        .header("content-length",part.len()).header("content-range",format!("bytes {start}-{end}/{}",content.len()))
                        .header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT")
                        .body(common::full(part.to_vec())).unwrap()
                } else {
                    Response::builder()
                        .header("content-type", "text/plain")
                        .header("content-length", content.len())
                        .header("last-modified", "Sat, 31 Oct 2026 00:00:00 GMT")
                        .body(common::full(if request.method() == hyper::Method::HEAD {
                            String::new()
                        } else {
                            content
                        }))
                        .unwrap()
                }
            }
        })
        .await;
        let store = Arc::new(S3Store::new(
            &format!("http://{endpoint}"),
            "mailblobs",
            "test-access",
            "test-secret",
        )?);
        let oracle = common::go_oracle::start(&db, endpoint).await?;
        let recording = oracle.is_some();
        let worker_dsn=if matches!(case,Case::NoTenant){
            let id:String=owner.query_one("SELECT replace(gen_random_uuid()::text,'-','')",&[]).await?.get(0);
            if id.len()!=32||!id.bytes().all(|b|b.is_ascii_hexdigit()){return Err("invalid mutant schema ID".into());}
            let schema=format!("gofree_blobs1_mutant_{id}");
            // Make the worker's mailbox predicate tautological, without
            // changing the request's verified identity or app credential.
            let projection:String=owner.query_one("SELECT string_agg(CASE WHEN attname='user_id' THEN $1::text||'::bigint AS user_id' ELSE quote_ident(attname) END,',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.mailboxes'::regclass AND attnum>0 AND NOT attisdropped",&[&caller.user.to_string()]).await?.get(0);
            owner.batch_execute(&format!("CREATE SCHEMA {schema}; CREATE VIEW {schema}.mailboxes AS SELECT {projection} FROM public.mailboxes; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; GRANT SELECT ON {schema}.mailboxes TO PUBLIC;")).await?;
            mutant_schema=Some(schema.clone());
            if db.dsn.contains("options="){return Err("mutant DSN already has options".into());}
            format!("{}{}options=-csearch_path%3D{schema}%2Cpublic",db.dsn,if db.dsn.contains('?'){'&'}else{'?'})
        }else{db.dsn.clone()};
        let adapter = BlobRoute(Arc::new(BlobCommands {
            exec: ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                .map_err(|e| e.0)?,
            worker_exec: ScopedExecutor::from_dsn(&worker_dsn, 4).map_err(|e| e.0)?,
            keys: common::recovery_keys(),
            issuer: "mailserver".into(),
            store,
        }));
        let mut inventory: serde_json::Value =
            serde_json::from_str(include_str!("../route-inventory.json"))?;
        let route = inventory["routes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| {
                r["family"] == "F16" && r["method"] == "GET" && r["path"] == "/blobs/{sha256}"
            })
            .unwrap();
        route["state"] = "ON".into();
        route["upstream"] = "local-rust".into();
        let gateway = Gateway::new(
            Config {
                upstream: oracle.as_ref().map(|oracle| format!("http://{}",oracle.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            if recording { RouteTable::proxy_all() } else if status_mutant { RouteTable::proxy_all().with(ChangedStatus(adapter)) } else { RouteTable::proxy_all().with(adapter) },
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let mut responses = Vec::new();
        if repeat {
            let first = common::send(
                address,
                Request::builder().method(if head {hyper::Method::HEAD} else {hyper::Method::GET}).uri(format!("/api/blobs/{target}"))
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("x-request-id","blobs1-download-oracle")
                    .header(
                        "authorization",
                        format!("Bearer {}", common::recovery_token(caller.user)),
                    )
                    .body(common::full(""))?,
            )
            .await;
            let status = first.status();
            let headers = first.headers().clone();
            let body = common::body_bytes(first).await;
            responses.push(snapshot(status, &headers, &body, &bytes, false)?);
            if status != 200 || body != bytes {
                server.abort();
                return Err("initial download failed".into());
            }
        }
        let mut request = Request::builder();
        if ranged {request=request.header("range","bytes=2-5");}
        let response = common::send(
            address,
            request.method(if head {hyper::Method::HEAD} else {hyper::Method::GET}).uri(format!("/api/blobs/{target}"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                    .header("x-request-id","blobs1-download-oracle")
                .header(
                    "authorization",
                    format!("Bearer {}", common::recovery_token(caller.user)),
                )
                .body(common::full(""))?,
        )
        .await;
        let status = response.status();
        let headers = response.headers().clone();
        let content_type = response.headers().get("content-type").cloned();
        let sandbox = response.headers().get("content-security-policy").cloned();
        let accept_ranges = response.headers().get("accept-ranges").cloned();
        let actual = common::body_bytes(response).await;
        responses.push(snapshot(status, &headers, &actual, &bytes, head)?);
        server.abort();
        if !status_mutant && !matches!(case,Case::NoTenant) {
        if repeat && accept_ranges.as_ref().is_none_or(|v| v != "bytes") {
            return Err(
                format!("cache-hit should advertise byte ranges: {accept_ranges:?}").into(),
            );
        }
        if foreign_caller || invalid_hash || missing {
            if status != 404 || actual != "blob not found\n" {
                return Err(format!("cross-mailbox download: {status} {actual:?}").into());
            }
        } else {
            if status != if ranged {206} else {200}
                || content_type
                    .as_ref()
                    .is_none_or(|value| value != "text/plain")
                || sandbox
                    .as_ref()
                    .is_none_or(|value| value != "default-src 'none'; sandbox")
                || if head {!actual.is_empty()} else if ranged {actual != bytes.as_bytes()[2..6]} else {actual != bytes}
            {
                return Err(format!(
                    "owned download: {status} {content_type:?} {sandbox:?} {actual:?}"
                )
                .into());
            }
        }
        }
        let case = if ranged {if repeat {"blob-download-cached-range"} else {"blob-download-cold-range"}} else if large { "blob-download-large" } else if encoded { "blob-download-encoded" } else if missing { "blob-download-missing" } else if head { "blob-download-head" } else if invalid_hash { "blob-download-invalid-hash" } else if foreign_caller { "blob-download-foreign" } else if repeat { "blob-download-repeat" } else { "blob-download-owned" };
        let observation = serde_json::json!({
            "request": {"method":"GET", "path":"/blobs/{sha256}", "external_path":"/api/blobs/{sha256}", "external_method":if head {"HEAD"} else {"GET"}, "headers":{"host":"mail.test", "origin":"http://mail.test", "authorization":"<fixture-access-token>"}, "body":""},
            "response":responses[0], "responses": responses, "effects":[], "audit":[], "notify":[],
        });
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/{case}.json"));
        let mut observation = observation;
        if ranged {observation["request"]["headers"]["range"]="bytes=2-5".into();}
        if !head {observation["request"].as_object_mut().unwrap().remove("external_method");}
        if recording {
            setjoin_conformance::golden::record(&path, &serde_json::json!({
                "format":1,"route":"GET /blobs/{sha256}","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,
                "normalization":["response date", "fixture body owner id and adjusted content-length", "fixture authorization and blob path"],
                "observation":observation,
            }))?;
        } else {
            let expected:serde_json::Value=serde_json::from_slice(&std::fs::read(path)?)?;
            setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
            eprintln!("GOLDEN-REPLAY: GET /blobs/{{sha256}} :: {case}");
        }
        Ok::<_, common::BoxError>(())
    }
    .await;
    if let Some(schema) = mutant_schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if let Some(foreign) = &foreign {
        common::remove_blob_account(&owner, foreign).await?;
    }
    common::remove_blob_account(&owner, &account).await?;
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&hash])
        .await?;
    result
}

fn snapshot(
    status: hyper::StatusCode,
    headers: &hyper::HeaderMap,
    body: &[u8],
    fixture: &str,
    head: bool,
) -> Result<serde_json::Value, common::BoxError> {
    let mut observed = serde_json::Map::new();
    for name in headers.keys() {
        let values: Result<Vec<_>, _> = headers
            .get_all(name)
            .iter()
            .map(|value| {
                value.to_str().map(|value| {
                    if name == "date" {
                        "<timestamp>".to_owned()
                    } else {
                        value.to_owned()
                    }
                })
            })
            .collect();
        observed.insert(name.to_string(), serde_json::json!(values?));
    }
    if let Some(range) = headers.get("content-range") {
        let value = range.to_str()?;
        let (bounds, total) = value.rsplit_once('/').ok_or("invalid content range")?;
        if total.parse::<usize>()? != fixture.len() {
            return Err("range total differs from object size".into());
        }
        observed.insert(
            "content-range".into(),
            serde_json::json!([format!("{bounds}/<object-size>")]),
        );
    }
    if let Some(length) = headers.get("content-length") {
        if length.to_str()?.parse::<usize>()? != if head { fixture.len() } else { body.len() } {
            return Err("response length differs from bytes".into());
        }
    }
    if fixture.len() >= 10 << 20 {
        return Ok(
            serde_json::json!({"status":status.as_u16(),"headers":observed,"body":{"sha256":format!("{:x}",Sha256::digest(body)),"length":body.len()}}),
        );
    }
    let mut normalized = String::from_utf8(body.to_vec())?;
    if head {
        observed.insert(
            "content-length".into(),
            serde_json::json!(["gofree-blobs1 object for <owner-user>".len().to_string()]),
        );
    }
    if body == fixture.as_bytes() {
        normalized = "gofree-blobs1 object for <owner-user>".into();
        if observed.contains_key("content-length") {
            observed.insert(
                "content-length".into(),
                serde_json::json!([normalized.len().to_string()]),
            );
        }
    }
    Ok(serde_json::json!({"status":status.as_u16(),"headers":observed,"body":normalized}))
}

#[tokio::test]
async fn blob_oracle_rejects_missing_tenant_filter() -> Result<(), common::BoxError> {
    let e = run_case(Case::NoTenant, false)
        .await
        .expect_err("unscoped mutant must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: GET /blobs/{{sha256}} :: no-tenant-filter");
    Ok(())
}
