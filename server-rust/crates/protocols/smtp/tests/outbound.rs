//! Outbound worker recordings replay without Go.
#[path = "support/outbound.rs"]
mod support;
use serde_json::Value;
use support::replay;
#[tokio::test]
async fn delivered_and_repeated_tick_match_recorded_go() {
    replay(
        include_str!("../oracle/outbound-go.json"),
        "all-delivered-repeat",
    )
    .await
}

#[tokio::test]
async fn partial_delivery_names_the_accepted_recipient_like_go() {
    replay(
        include_str!("../oracle/outbound-partial-go.json"),
        "partial-first-rejected",
    )
    .await
}

#[tokio::test]
async fn failed_recipients_retry_and_bounce_with_go_backoff() {
    let corpus = include_str!("../oracle/outbound-retry-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        replay(corpus, case["case"]["name"].as_str().unwrap()).await
    }
}

#[tokio::test]
async fn invalid_inputs_data_failures_and_mx_fallback_match_go() {
    let corpus = include_str!("../oracle/outbound-errors-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        replay(corpus, case["case"]["name"].as_str().unwrap()).await
    }
}

#[tokio::test]
async fn starttls_and_admin_policy_match_recorded_go() {
    let corpus = include_str!("../oracle/outbound-tls-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        replay(corpus, case["case"]["name"].as_str().unwrap()).await
    }
}

#[tokio::test]
async fn oldest_ten_due_queue_items_deliver_concurrently_like_go() {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        replay(
            include_str!("../oracle/outbound-batch-go.json"),
            "oldest-ten-concurrent",
        ),
    )
    .await
    .expect("ten deliveries must reach the peer together");
}

#[tokio::test]
async fn envelope_controls_are_rejected_before_any_mail_command_like_go() {
    let corpus = include_str!("../oracle/outbound-envelope-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            replay(corpus, case["case"]["name"].as_str().unwrap()),
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn remote_command_and_data_timeouts_match_go() {
    let corpus = include_str!("../oracle/outbound-timeout-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            replay(corpus, case["case"]["name"].as_str().unwrap()),
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn lost_database_connections_preserve_go_independent_statements() {
    let corpus = include_str!("../oracle/outbound-db-fault-go.json");
    let cases: Value = serde_json::from_str(corpus).unwrap();
    for case in cases.as_array().unwrap() {
        replay(corpus, case["case"]["name"].as_str().unwrap()).await
    }
}

#[tokio::test]
async fn future_queue_backlog_and_admin_alerts_match_go() {
    replay(
        include_str!("../oracle/outbound-backlog-go.json"),
        "future-backlog-alert",
    )
    .await
}

#[tokio::test]
async fn observer_rejects_missing_attempt_wrong_recipient_double_attempt_and_missing_trace() {
    use futures_util::FutureExt;
    let corpus = include_str!("../oracle/outbound-go.json");
    for (table, action, body) in [
        ("delivery_attempts", "INSERT", "RETURN NULL;"),
        ("delivery_attempts", "INSERT", "NEW.recipient_email='wrong@dest.test'; RETURN NEW;"),
        ("outbound_queue", "UPDATE", "IF NEW.status='delivered' THEN NEW.attempt_count=NEW.attempt_count+1; END IF; RETURN NEW;"),
        ("message_trace", "INSERT", "RETURN NULL;"),
    ] {
        replay(corpus, "all-delivered-repeat").await;
        let install = format!("CREATE FUNCTION public.gofree_smtp3_mutant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} END $$; CREATE TRIGGER gofree_smtp3_mutant BEFORE {action} ON {table} FOR EACH ROW EXECUTE FUNCTION public.gofree_smtp3_mutant();");
        let result = std::panic::AssertUnwindSafe(support::replay_mutant(corpus, "all-delivered-repeat", &install)).catch_unwind().await;
        let panic = result.expect_err("observer accepted a changed worker effect");
        let message = panic.downcast_ref::<String>().map(String::as_str).or_else(||panic.downcast_ref::<&str>().copied()).unwrap_or("");
        assert!(message.contains("committed effects"), "a transport/setup error is not a rejected mutant: {message}");
    }
}
