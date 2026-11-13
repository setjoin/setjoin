//! Frozen-Go conditional/cache/range behavior at the F16 HTTP boundary.
mod common;
use hyper::{Method, Request, Response};
use serde_json::{Value, json};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    Config, Gateway, RouteTable, TrustedProxies,
    blobs::{BlobCommands, BlobRoute},
    recovery_worker::S3Store,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct Case {
    name: &'static str,
    headers: &'static [(&'static str, &'static str)],
    status: u16,
}
fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "cold-if-none",
            headers: &[("if-none-match", "*")],
            status: 200,
        },
        Case {
            name: "cold-if-match",
            headers: &[("if-match", "\"other\"")],
            status: 200,
        },
        Case {
            name: "cached-if-none",
            headers: &[("if-none-match", "*")],
            status: 304,
        },
        Case {
            name: "cached-if-match",
            headers: &[("if-match", "\"other\"")],
            status: 412,
        },
        Case {
            name: "cached-date",
            headers: &[("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")],
            status: 200,
        },
        Case {
            name: "streamed-modified",
            headers: &[
                ("range", "bytes=0-16"),
                ("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT"),
            ],
            status: 304,
        },
        Case {
            name: "streamed-unmodified",
            headers: &[
                ("range", "bytes=0-16"),
                ("if-unmodified-since", "Mon, 01 Jan 1900 00:00:00 GMT"),
            ],
            status: 412,
        },
        Case {
            name: "match-over-date",
            headers: &[
                ("range", "bytes=0-16"),
                ("if-match", "*"),
                ("if-unmodified-since", "Mon, 01 Jan 1900 00:00:00 GMT"),
            ],
            status: 206,
        },
        Case {
            name: "none-over-date",
            headers: &[
                ("range", "bytes=0-16"),
                ("if-none-match", "\"other\""),
                ("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT"),
            ],
            status: 206,
        },
        Case {
            name: "if-range-date",
            headers: &[
                ("range", "bytes=2-5"),
                ("if-range", "Sat, 31 Oct 2026 00:00:00 GMT"),
            ],
            status: 206,
        },
        Case {
            name: "if-range-old-date",
            headers: &[
                ("range", "bytes=2-5"),
                ("if-range", "Fri, 30 Oct 2026 00:00:00 GMT"),
            ],
            status: 200,
        },
        Case {
            name: "if-range-etag",
            headers: &[("range", "bytes=2-5"), ("if-range", "\"fixture\"")],
            status: 200,
        },
        Case {
            name: "none-before-invalid-range",
            headers: &[("range", "wrong"), ("if-none-match", "*")],
            status: 304,
        },
        Case {
            name: "cached-multipart",
            headers: &[("range", "bytes=0-1,14-16")],
            status: 206,
        },
        Case {
            name: "invalid-range",
            headers: &[("range", "bytes=wrong")],
            status: 416,
        },
        Case {
            name: "unsatisfiable-range",
            headers: &[("range", "bytes=99-")],
            status: 416,
        },
        Case {
            name: "range-head",
            headers: &[("range", "bytes=2-5")],
            status: 206,
        },
        Case {
            name: "empty-range",
            headers: &[("range", "bytes=99-")],
            status: 200,
        },
        Case {
            name: "zero-suffix",
            headers: &[("range", "bytes=-0")],
            status: 206,
        },
        Case {
            name: "wrong-range-unit",
            headers: &[("range", "items=0-1")],
            status: 416,
        },
        Case {
            name: "clamped-range",
            headers: &[("range", "bytes=12-999")],
            status: 206,
        },
        Case {
            name: "amplifying-ranges",
            headers: &[("range", "bytes=0-16,0-16")],
            status: 200,
        },
        Case {
            name: "empty-range-header",
            headers: &[("range", "")],
            status: 200,
        },
        Case {
            name: "empty-range-list",
            headers: &[("range", "bytes=,,")],
            status: 200,
        },
        Case {
            name: "http-date-rfc850",
            headers: &[
                ("range", "bytes=2-5"),
                ("if-modified-since", "Saturday, 31-Oct-26 00:00:00 GMT"),
            ],
            status: 304,
        },
        Case {
            name: "http-date-asctime",
            headers: &[
                ("range", "bytes=2-5"),
                ("if-range", "Sat Oct 31 00:00:00 2026"),
            ],
            status: 206,
        },
        Case {
            name: "http-date-1969",
            headers: &[
                ("range", "bytes=2-5"),
                ("if-unmodified-since", "Wednesday, 01-Jan-69 00:00:00 GMT"),
            ],
            status: 412,
        },
        Case {
            name: "http-date-invalid",
            headers: &[("range", "bytes=2-5"), ("if-modified-since", "not a date")],
            status: 206,
        },
        Case {
            name: "foreign-condition",
            headers: &[("range", "bytes=0-16"), ("if-none-match", "*")],
            status: 404,
        },
    ]
}

async fn run_case(case: &Case, mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("blobs3-read") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs3-read").await?;
    let foreign = fixture::account(&owner, "blobs3-read-foreign").await?;
    let caller = if case.name == "foreign-condition" {
        &foreign
    } else {
        &account
    };
    let bytes = if case.name == "empty-range" {
        Vec::new()
    } else {
        b"scoped attachment".to_vec()
    };
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let size = bytes.len() as i64;
    owner.execute("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$1,$2,'text/plain',0)",&[&hash,&size]).await?;
    owner.execute("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes) SELECT id,received_at,$1,'x.txt','text/plain','attachment',$2 FROM messages WHERE id=$3 AND mailbox_id=$4",&[&hash,&size,&account.two_labels,&account.mailbox]).await?;
    let result=async{
        let content=bytes.clone();
        let expected_hash=hash.clone();
        let endpoint=common::fake_upstream(move |r|{
            let content=content.clone();let expected_hash=expected_hash.clone();
            async move{
                if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"));}
                assert_eq!(r.uri().path(),format!("/mailblobs/{expected_hash}"));
                let mut builder=Response::builder().header("content-type","text/plain").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT").header("etag","\"fixture\"");
                let mut selected=content.as_slice();
                if r.method()==Method::GET {
                    if let Some(range)=r.headers().get("range"){
                        let (start,end)=range.to_str().unwrap().strip_prefix("bytes=").unwrap().split_once('-').unwrap();
                        let start=start.parse::<usize>().unwrap();
                        let end=if end.is_empty(){content.len()-1}else{end.parse::<usize>().unwrap()};
                        selected=&content[start..=end];
                        builder=builder.status(206).header("content-range",format!("bytes {start}-{end}/{}",content.len()));
                    }
                }
                builder.header("content-length",selected.len()).body(common::full(if r.method()==Method::HEAD{Vec::new()}else{selected.to_vec()})).unwrap()
            }
        }).await;
        let oracle=common::go_oracle::start_named(&db,endpoint,None,"gofree-blobs3").await?;
        let recording=oracle.is_some();
        let adapter=BlobRoute(Arc::new(BlobCommands{
            exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,
            worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),
            store:Arc::new(S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?),
        }));
        let routes=if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(IgnoreCondition(adapter))}else{RouteTable::proxy_all().with(adapter)};
        let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?
            .with_inventory(include_str!("../route-inventory.json"))?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let task=tokio::spawn(gateway.serve(listener));
        let mut observations=vec![];
        let request=|head:bool|Request::builder().method(if head{"HEAD"}else{"GET"}).uri(format!("/api/blobs/{hash}"))
            .header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs3-read-oracle")
            .header("authorization",format!("Bearer {}",common::recovery_token(caller.user)));
        if case.name.starts_with("cached-"){
            let response=common::send(address,request(false).body(common::full(""))?).await;
            assert_eq!(response.status(),200);
            observations.push(snapshot(response).await?);
        }
        let mut req=request(case.name.ends_with("-head"));
        for (name,value) in case.headers{req=req.header(*name,*value);}
        let response=common::send(address,req.body(common::full(""))?).await;
        let actual_status=response.status().as_u16();
        observations.push(snapshot(response).await?);
        if !recording{
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|s|s=="setjoin_gateway_proxied_to_go_total 0"){task.abort();let _=task.await;return Err(format!("blob read forwarded: {metrics}").into());}
        }
        task.abort();let _=task.await;
        let mut request=json!({"method":"GET","path":"/blobs/{sha256}","external_path":"/api/blobs/{sha256}","headers":case.headers.iter().copied().collect::<std::collections::BTreeMap<_,_>>()});
        if case.name.ends_with("-head"){request["external_method"]=json!("HEAD");}
        let observation=json!({"request":request,"response":observations.last().unwrap(),"responses":observations,"effects":[],"audit":[],"notify":[]});
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/blob-read-{}.json",case.name));
        if recording{
            assert_eq!(actual_status,case.status,"frozen Go case {}",case.name);
            setjoin_conformance::golden::record(&path,&json!({"format":1,"route":"GET /blobs/{sha256}","case":case.name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["HTTP Date","validated 60-hex multipart boundary"],"observation":observation}))?;
        }else{
            let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
            setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
            eprintln!("GOLDEN-REPLAY: GET /blobs/{{sha256}} :: {}",case.name);
        }
        Ok::<_,common::BoxError>(())
    }.await;
    common::remove_blob_account(&owner, &account).await?;
    common::remove_blob_account(&owner, &foreign).await?;
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&hash])
        .await?;
    result
}

async fn snapshot(response: Response<hyper::body::Incoming>) -> Result<Value, common::BoxError> {
    let status = response.status().as_u16();
    let boundary = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("multipart/byteranges; boundary="))
        .map(str::to_owned);
    if let Some(b) = &boundary {
        assert_eq!(b.len(), 60);
        assert!(b.bytes().all(|c| c.is_ascii_hexdigit()));
    }
    let mut headers = serde_json::Map::new();
    for name in response.headers().keys() {
        let values = response
            .headers()
            .get_all(name)
            .iter()
            .map(|v| {
                let value = v.to_str().unwrap();
                if name == "date" {
                    "<timestamp>".to_owned()
                } else if let Some(b) = &boundary {
                    value.replace(b, "<boundary>")
                } else {
                    value.to_owned()
                }
            })
            .collect::<Vec<_>>();
        headers.insert(name.to_string(), json!(values));
    }
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    let body = if let Some(b) = &boundary {
        body.replace(b, "<boundary>")
    } else {
        body
    };
    Ok(json!({"status":status,"headers":headers,"body":body}))
}

struct IgnoreCondition<K: setjoin_authz::token::KeySource + 'static>(BlobRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept
    for IgnoreCondition<K>
{
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        mut r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        r.headers_mut().remove("if-none-match");
        self.0.handle(r, c)
    }
}
#[tokio::test]
async fn blob_conditional_oracle_rejects_ignored_validator() -> Result<(), common::BoxError> {
    let case = Case {
        name: "cached-if-none",
        headers: &[("if-none-match", "*")],
        status: 304,
    };
    let error = run_case(&case, true)
        .await
        .expect_err("ignored validator must differ");
    assert!(error.to_string().contains("/response"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /blobs/{{sha256}} :: ignored-validator");
    Ok(())
}

macro_rules! blob_read_case {
    ($name:ident,$case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            let case = cases().into_iter().find(|c| c.name == $case).unwrap();
            run_case(&case, false).await
        }
    };
}
blob_read_case!(blob_read_cold_if_none, "cold-if-none");
blob_read_case!(blob_read_cold_if_match, "cold-if-match");
blob_read_case!(blob_read_cached_if_none, "cached-if-none");
blob_read_case!(blob_read_cached_if_match, "cached-if-match");
blob_read_case!(blob_read_cached_date, "cached-date");
blob_read_case!(blob_read_streamed_modified, "streamed-modified");
blob_read_case!(blob_read_streamed_unmodified, "streamed-unmodified");
blob_read_case!(blob_read_match_over_date, "match-over-date");
blob_read_case!(blob_read_none_over_date, "none-over-date");
blob_read_case!(blob_read_if_range_date, "if-range-date");
blob_read_case!(blob_read_if_range_old_date, "if-range-old-date");
blob_read_case!(blob_read_if_range_etag, "if-range-etag");
blob_read_case!(
    blob_read_none_before_invalid_range,
    "none-before-invalid-range"
);
blob_read_case!(blob_read_cached_multipart, "cached-multipart");
blob_read_case!(blob_read_invalid_range, "invalid-range");
blob_read_case!(blob_read_unsatisfiable_range, "unsatisfiable-range");
blob_read_case!(blob_read_range_head, "range-head");
blob_read_case!(blob_read_empty_range, "empty-range");
blob_read_case!(blob_read_zero_suffix, "zero-suffix");
blob_read_case!(blob_read_wrong_range_unit, "wrong-range-unit");
blob_read_case!(blob_read_clamped_range, "clamped-range");
blob_read_case!(blob_read_amplifying_ranges, "amplifying-ranges");
blob_read_case!(blob_read_empty_range_header, "empty-range-header");
blob_read_case!(blob_read_empty_range_list, "empty-range-list");
blob_read_case!(blob_read_foreign_condition, "foreign-condition");
blob_read_case!(blob_read_http_date_rfc850, "http-date-rfc850");
blob_read_case!(blob_read_http_date_asctime, "http-date-asctime");
blob_read_case!(blob_read_http_date_1969, "http-date-1969");
blob_read_case!(blob_read_http_date_invalid, "http-date-invalid");
