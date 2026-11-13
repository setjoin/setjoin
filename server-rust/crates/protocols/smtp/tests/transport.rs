//! Delivery policy is observed through seed + tick + remote wire and DB effects.
#[allow(dead_code)]
#[path = "support/outbound.rs"]
mod support;

#[tokio::test]
async fn dane_lookup_failure_defers_before_opening_a_remote_session_like_go() {
    support::replay_with(
        include_str!("../oracle/transport-dane-failure-go.json"),
        "dane-lookup-failure",
        None,
        &|worker, _| {
            worker.with_transport_security(std::sync::Arc::new(
                setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                    FailedLookup,
                )),
            ))
        },
    )
    .await;
}

struct FailedLookup;
impl setjoin_smtp::outbound::transport::TlsaLookup for FailedLookup {
    fn lookup<'a>(
        &'a self,
        _: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<setjoin_smtp::outbound::transport::TlsaAnswer, String>,
    > {
        Box::pin(async { Err("fixture TLSA lookup failure".into()) })
    }
}

#[tokio::test]
async fn dane_certificate_starttls_and_pool_decisions_match_recorded_go() {
    let corpus = include_str!("../oracle/transport-dane-go.json");
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for recorded in cases.as_array().unwrap() {
        if diverged(
            "transport-dane-go.json",
            recorded["case"]["name"].as_str().unwrap(),
        ) {
            continue;
        }
        support::replay_with(
            corpus,
            recorded["case"]["name"].as_str().unwrap(),
            None,
            &|worker, case| {
                worker.with_transport_security(std::sync::Arc::new(
                    setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                        Answers {
                            values: case["tlsa"].as_array().unwrap().clone(),
                            next: Default::default(),
                        },
                    )),
                ))
            },
        )
        .await;
    }
}
/// Recorded Go verdicts that were security bugs (`oracle/divergences.json`, #500).
fn diverged(corpus: &str, name: &str) -> bool {
    let records: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    records.as_array().unwrap().iter().any(|r| {
        r["case"] == name
            && r["go_replay"] == "skipped"
            && r["corpus"].as_array().unwrap().iter().any(|c| c == corpus)
    })
}

#[tokio::test]
async fn dane_certificate_decisions_require_chain_linkage_and_never_label_unmatched_sessions() {
    let corpus = include_str!("../oracle/secfix-transport.json");
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for recorded in cases.as_array().unwrap() {
        support::replay_with(
            corpus,
            recorded["case"]["name"].as_str().unwrap(),
            None,
            &|worker, case| {
                worker.with_transport_security(std::sync::Arc::new(
                    setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                        Answers {
                            values: case["tlsa"].as_array().unwrap().clone(),
                            next: Default::default(),
                        },
                    )),
                ))
            },
        )
        .await;
    }
}
struct Answers {
    values: Vec<serde_json::Value>,
    next: std::sync::atomic::AtomicUsize,
}
impl setjoin_smtp::outbound::transport::TlsaLookup for Answers {
    fn lookup<'a>(
        &'a self,
        _: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<setjoin_smtp::outbound::transport::TlsaAnswer, String>,
    > {
        use setjoin_smtp::outbound::transport::{TlsaAnswer, TlsaRecord};
        Box::pin(async move {
            let i = self
                .next
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .min(self.values.len() - 1);
            let v = &self.values[i];
            if v.is_string() {
                return Err("fixture TLSA lookup failure".into());
            }
            Ok(TlsaAnswer {
                authenticated: v["ad"].as_bool().unwrap(),
                rcode: v["rcode"].as_u64().unwrap() as u16,
                records: v["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        let mut parts = r.as_str().unwrap().split_whitespace();
                        let usage = parts.next().unwrap().parse().unwrap();
                        let selector = parts.next().unwrap().parse().unwrap();
                        let matching = parts.next().unwrap().parse().unwrap();
                        let bytes = parts.next().unwrap_or("").as_bytes();
                        let association = bytes
                            .chunks_exact(2)
                            .map(|c| {
                                u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()
                            })
                            .collect();
                        TlsaRecord {
                            usage,
                            selector,
                            matching,
                            association,
                        }
                    })
                    .collect(),
            })
        })
    }
}

#[tokio::test]
async fn persisted_mta_sts_mx_and_tls_requirements_match_recorded_go() {
    let corpus = include_str!("../oracle/transport-mta-cache-go.json");
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for recorded in cases.as_array().unwrap() {
        support::replay_with(
            corpus,
            recorded["case"]["name"].as_str().unwrap(),
            None,
            &|worker, case| {
                let mut security = setjoin_smtp::outbound::transport::TransportSecurity::new(
                    std::sync::Arc::new(FailedLookup),
                )
                .with_dane(false);
                if case["transport"]["feature.mta_sts"] == true {
                    security = security.with_mta_sts(
                        setjoin_pg::workers::WorkerDatabase::new(
                            &std::env::var("TEST_DB_DSN").unwrap(),
                        )
                        .unwrap(),
                    );
                }
                worker.with_transport_security(std::sync::Arc::new(security))
            },
        )
        .await;
    }
}

#[path = "support/auth_dns.rs"]
mod auth_dns;
struct PolicyResponse {
    body: String,
    status: u64,
    seen: std::sync::Mutex<Vec<String>>,
}
impl setjoin_smtp::outbound::PolicyFetch for PolicyResponse {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let (host, path) = url
                .strip_prefix("https://")
                .unwrap()
                .split_once('/')
                .unwrap();
            self.seen
                .lock()
                .unwrap()
                .push(format!("GET {host} /{path}"));
            if ![0, 200].contains(&self.status) {
                return Err(format!("HTTP {}", self.status));
            }
            Ok(self.body.as_bytes().to_vec())
        })
    }
}
#[tokio::test]
async fn fetched_mta_sts_persists_and_reuses_the_policy_like_go() {
    for corpus in [
        include_str!("../oracle/transport-mta-fetch-go.json"),
        include_str!("../oracle/transport-mta-errors-go.json"),
        include_str!("../oracle/transport-mta-gzip-go.json"),
    ] {
        let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
        for recorded in cases.as_array().unwrap() {
            let peer = std::sync::Arc::new(PolicyResponse {
                body: recorded["case"]["policy_body"].as_str().unwrap().into(),
                status: recorded["case"]["policy_status"].as_u64().unwrap_or(0),
                seen: Default::default(),
            });
            support::replay_with(
                corpus,
                recorded["case"]["name"].as_str().unwrap(),
                None,
                &|worker, case| {
                    worker.with_transport_security(std::sync::Arc::new(
                        setjoin_smtp::outbound::transport::TransportSecurity::new(
                            std::sync::Arc::new(FailedLookup),
                        )
                        .with_dane(false)
                        .with_policy_fetch(
                            setjoin_pg::workers::WorkerDatabase::new(
                                &std::env::var("TEST_DB_DSN").unwrap(),
                            )
                            .unwrap(),
                            std::sync::Arc::new(auth_dns::FixtureDns(case["dns"].clone())),
                            peer.clone(),
                        ),
                    ))
                },
            )
            .await;
            assert_eq!(
                serde_json::json!(*peer.seen.lock().unwrap()),
                recorded["policy_requests"],
                "{}: HTTPS policy I/O",
                recorded["case"]["name"]
            );
        }
    }
}

#[tokio::test]
async fn tls_rpt_aggregates_dane_failures_like_recorded_go() {
    support::replay_with(
        include_str!("../oracle/transport-report-go.json"),
        "tls-rpt-dane-failure-aggregates",
        None,
        &|worker, case| {
            worker.with_transport_security(std::sync::Arc::new(
                setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                    FailedLookup,
                ))
                .with_reporting(
                    setjoin_pg::workers::WorkerDatabase::new(
                        &std::env::var("TEST_DB_DSN").unwrap(),
                    )
                    .unwrap(),
                    std::sync::Arc::new(auth_dns::FixtureDns(case["dns"].clone())),
                ),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn tls_rpt_outcomes_and_uri_discovery_match_recorded_go() {
    let corpus = include_str!("../oracle/transport-report-matrix-go.json");
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for recorded in cases.as_array().unwrap() {
        support::replay_with(
            corpus,
            recorded["case"]["name"].as_str().unwrap(),
            None,
            &|worker, case| {
                let lookup: std::sync::Arc<dyn setjoin_smtp::outbound::transport::TlsaLookup> =
                    if let Some(values) = case["tlsa"].as_array() {
                        std::sync::Arc::new(Answers {
                            values: values.clone(),
                            next: Default::default(),
                        })
                    } else {
                        std::sync::Arc::new(FailedLookup)
                    };
                let db = setjoin_pg::workers::WorkerDatabase::new(
                    &std::env::var("TEST_DB_DSN").unwrap(),
                )
                .unwrap();
                let dns = std::sync::Arc::new(auth_dns::FixtureDns(case["dns"].clone()));
                let mut security =
                    setjoin_smtp::outbound::transport::TransportSecurity::new(lookup).with_dane(
                        case["transport"]["feature.dane"] == true
                            && case["transport"]["feature.dnssec"] == true,
                    );
                if case["transport"]["feature.mta_sts"] == true {
                    security = security.with_mta_sts(db.clone());
                }
                if case["transport"]["feature.tls_rpt"] == true {
                    security = security.with_reporting(db, dns);
                }
                worker.with_transport_security(std::sync::Arc::new(security))
            },
        )
        .await;
    }
}

#[tokio::test]
async fn live_dane_enable_rechecks_the_idle_pool_before_the_next_tick_like_go() {
    support::replay_with(
        include_str!("../oracle/transport-live-go.json"),
        "dane-live-enable-closes-idle-plaintext",
        None,
        &|worker, _| {
            worker.with_transport_security(std::sync::Arc::new(
                setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                    FailedLookup,
                ))
                .with_dane(false)
                .with_live_features(
                    setjoin_pg::workers::WorkerDatabase::new(
                        &std::env::var("TEST_DB_DSN").unwrap(),
                    )
                    .unwrap(),
                ),
            ))
        },
    )
    .await;
}

#[tokio::test]
async fn cached_mta_sts_json_aliases_nulls_and_type_errors_match_recorded_go() {
    let corpus = include_str!("../oracle/transport-mta-cache-edge-go.json");
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for recorded in cases.as_array().unwrap() {
        support::replay_with(
            corpus,
            recorded["case"]["name"].as_str().unwrap(),
            None,
            &|worker, _| {
                worker.with_transport_security(std::sync::Arc::new(
                    setjoin_smtp::outbound::transport::TransportSecurity::new(std::sync::Arc::new(
                        FailedLookup,
                    ))
                    .with_dane(false)
                    .with_mta_sts(
                        setjoin_pg::workers::WorkerDatabase::new(
                            &std::env::var("TEST_DB_DSN").unwrap(),
                        )
                        .unwrap(),
                    ),
                ))
            },
        )
        .await;
    }
}
