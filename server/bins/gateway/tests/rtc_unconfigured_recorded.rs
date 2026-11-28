//! #357: without LiveKit configuration frozen Go registers no `/rtc` handler, so its
//! root mux answers; the route's catch-all fallback answers the same bytes natively.
use crate::common;
use common::mux_oracle::{run, MuxCase, Website};
use common::BoxError;
use hyper::Request;
use setjoin_gateway::catchall::CatchallRoute;
use setjoin_gateway::rtc::{RtcRoute, SFU_SIGNAL};
use setjoin_gateway::RouteTable;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CORPUS: &str = "meet/goldens/rtc-unconfigured";

fn table(exec: setjoin_pg::ScopedExecutor, website: Website) -> RouteTable {
    let keys = Arc::new(common::recovery_keys());
    let mut catchall =
        CatchallRoute::new().with_auth(exec.clone(), keys.clone(), "mailserver".into());
    catchall.website = website;
    RouteTable::proxy_all()
        .with(
            RtcRoute::new(
                exec,
                keys,
                "mailserver".into(),
                false,
                SFU_SIGNAL.parse().expect("SFU signal address"),
            )
            .with_fallback(Arc::new(catchall.clone())),
        )
        .with_catchall(catchall)
}

macro_rules! case {
    ($name:ident, $method:literal, $uri:literal, $bearer:literal, $website:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            let case = MuxCase {
                name: stringify!($name),
                method: $method,
                uri: $uri,
                bearer: $bearer,
                website: $website,
            };
            run(CORPUS, &case, &[], &table).await
        }
    };
}

case!(rtc_unconfigured_root, "GET", "/rtc", false, false);
case!(
    rtc_unconfigured_signal,
    "GET",
    "/rtc/rtc/validate?access_token=x",
    false,
    false
);
case!(rtc_unconfigured_head, "HEAD", "/rtc/", false, false);
case!(rtc_unconfigured_post, "POST", "/rtc/x", false, false);
case!(rtc_unconfigured_member, "GET", "/rtc", true, false);
case!(rtc_unconfigured_website, "GET", "/rtc/x", false, true);

/// Without a catch-all fallback, unconfigured `/rtc` still answers 404 natively.
#[tokio::test]
async fn without_a_fallback_unconfigured_rtc_answers_404_natively() -> Result<(), BoxError> {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let upstream = common::fake_upstream(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        async { hyper::Response::new(common::full("go")) }
    })
    .await;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(
        "host=127.0.0.1 port=1 user=none dbname=none connect_timeout=1",
        1,
    )
    .map_err(|e| e.0)?;
    let rtc = RtcRoute::new(
        exec,
        Arc::new(common::recovery_keys()),
        "mailserver".into(),
        false,
        SFU_SIGNAL.parse()?,
    );
    let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(rtc)).await;
    let response = common::send(
        gw,
        Request::get("/rtc")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(response.status().as_u16(), 404);
    let bad_escape = common::send(
        gw,
        Request::get("/rtc/%ZZ")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(bad_escape.status().as_u16(), 400);
    let bad_plus = common::send(
        gw,
        Request::get("/rtc/%+a")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(bad_plus.status().as_u16(), 400);
    let encoded_dots = common::send(
        gw,
        Request::get("/rtc/%2e%2e/x")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(encoded_dots.status().as_u16(), 404);
    let unclean = common::send(
        gw,
        Request::get("/rtc//x")
            .header("host", "mail.test")
            .body(common::full(""))?,
    )
    .await;
    assert_eq!(unclean.status().as_u16(), 307);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}
