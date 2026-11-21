//! #341 Rust-only device trust faults that frozen Go cannot record
//! deterministically: concurrent replay, an empty codec master, legacy re-seal
//! ordering/idempotence, oversize and unobservable policy bodies, the
//! event cap's pre-proof order, and check-in event insert failure.
//! Contract: identity-device/README.md.
#[allow(dead_code)]
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::Value;
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use std::sync::Arc;
use tokio_postgres::Client;

type Err = Box<dyn std::error::Error + Send + Sync>;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SECRET: &str = "c341c341c341c341c341c341c341c341c341c341c341c341c341c341c341c341";
const WRONG: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A body of unknown length that yields no bytes (chunked, nothing sent).
struct Unsized;
impl hyper::body::Body for Unsized {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>>> {
        std::task::Poll::Ready(None)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}

struct Case {
    c: Client,
    server: Arc<AuthServer>,
    exec: setjoin_pg::ScopedExecutor,
    master: String,
    user: fixture::Account,
    device: i64,
    receipts: Vec<String>,
}
impl Case {
    async fn open(legacy: bool) -> Result<Option<Self>, Err> {
        let Some(db) = Db::for_case("DEVICE341-faults") else {
            return Ok(None);
        };
        let app = db.app.clone().ok_or("DB_APP_DSN is required")?;
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        let receipts = common::receipt_ids(&c).await;
        let keys: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))?;
        let master = keys["secret"]
            .as_str()
            .ok_or("keys.json secret")?
            .to_owned();
        let user = fixture::account(&c, "device341-fault").await?;
        let enc = if legacy {
            None
        } else {
            Some(setjoin_config_secret::seal_column(
                SECRET.as_bytes(),
                master.as_bytes(),
                setjoin_config_secret::CryptoProfile::Standard,
            )?)
        };
        let plain = legacy.then_some(SECRET);
        let key = (!legacy).then_some("v1");
        let device: i64 = c
            .query_one(
                "INSERT INTO devices(user_id,fingerprint,hmac_secret,hmac_secret_enc,hmac_secret_key_id) VALUES($1,'gofree341-fault-fingerprint-0123456789abcdef',$2,$3,$4) RETURNING id",
                &[&user.user, &plain, &enc, &key],
            )
            .await?
            .get(0);
        let exec = setjoin_pg::ScopedExecutor::from_dsn(&app, 4).map_err(|e| e.0)?;
        let server =
            Arc::new(AuthServer::load(exec.clone(), Config::for_secret(master.clone())).await?);
        Ok(Some(Self {
            c,
            server,
            exec,
            master,
            user,
            device,
            receipts,
        }))
    }
    fn signed(
        &self,
        method: &str,
        uri: &str,
        payload: &str,
        nonce: &str,
        secret: &str,
        body: setjoin_auth::Body,
    ) -> Request<setjoin_auth::Body> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let hash = sha(payload.as_bytes());
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mac = hex(ring::hmac::sign(
            &key,
            format!("{}:{ts}:{method}:{uri}:{hash}:{nonce}", self.device).as_bytes(),
        )
        .as_ref());
        Request::builder()
            .method(method)
            .uri(uri)
            .header("x-device-timestamp", ts)
            .header("x-device-nonce", nonce)
            .header("x-device-body-sha256", hash)
            .header("x-device-hmac", mac)
            .body(body)
            .unwrap()
    }
    fn checkin(&self, payload: &str, nonce: &str, secret: &str) -> Request<setjoin_auth::Body> {
        self.signed(
            "POST",
            "/device/checkin",
            payload,
            nonce,
            secret,
            body(payload.to_owned()),
        )
    }
    async fn count(&self, sql: &str) -> Result<i64, Err> {
        Ok(self.c.query_one(sql, &[&self.device]).await?.get(0))
    }
    async fn nonces(&self) -> Result<i64, Err> {
        self.count("SELECT count(*) FROM device_auth_nonces WHERE device_id=$1")
            .await
    }
    async fn events(&self) -> Result<i64, Err> {
        self.count("SELECT count(*) FROM device_events WHERE device_id=$1")
            .await
    }
    async fn close(self) -> Result<(), Err> {
        let id = self.device;
        self.c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM device_auth_nonces WHERE device_id={id};DELETE FROM device_events WHERE device_id={id};DELETE FROM devices WHERE id={id};COMMIT;")).await?;
        fixture::remove(&self.c, &self.user).await?;
        common::restore_receipts(&self.c, &self.receipts).await;
        self.c
            .query_one(
                "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
                &[],
            )
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn concurrent_replay_spends_one_nonce() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let payload = format!(
        r#"{{"device_id":{},"events":[{{"type":"race"}}]}}"#,
        case.device
    );
    let (one, two) = tokio::join!(
        case.server
            .handle(case.checkin(&payload, "gofree341-race", SECRET)),
        case.server
            .handle(case.checkin(&payload, "gofree341-race", SECRET))
    );
    let mut statuses = [one.status().as_u16(), two.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 401]);
    assert_eq!(case.nonces().await.unwrap(), 1);
    assert_eq!(case.events().await.unwrap(), 1);
    case.close().await.unwrap();
}

#[tokio::test]
async fn empty_master_fails_closed() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let payload = format!(r#"{{"device_id":{}}}"#, case.device);
    let (parts, _) = case
        .checkin(&payload, "gofree341-empty-master", SECRET)
        .into_parts();
    let resolver = setjoin_authz::device::DeviceResolver::new(
        case.exec.clone(),
        Vec::new(),
        setjoin_config_secret::CryptoProfile::Standard,
    );
    let verified = resolver
        .verify_request(
            case.device,
            setjoin_authz::device::DeviceRequest {
                headers: &parts.headers,
                method: "POST",
                uri: "/device/checkin",
                body: payload.as_bytes(),
            },
        )
        .await;
    assert!(verified.is_none());
    assert_eq!(case.nonces().await.unwrap(), 0);
    case.close().await.unwrap();
}

#[tokio::test]
async fn empty_legacy_secret_is_refused_before_reseal() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(true).await.unwrap() else {
        return;
    };
    let outcome = async {
        case.c
            .execute(
                "UPDATE devices SET hmac_secret='' WHERE id=$1 AND user_id=$2",
                &[&case.device, &case.user.user],
            )
            .await?;
        let payload = format!(r#"{{"device_id":{}}}"#, case.device);
        let reply = case
            .server
            .handle(case.checkin(&payload, "gofree341-empty-secret", ""))
            .await;
        let (reply, reply_body) = reply.into_parts();
        let envelope_is_null: bool = case
            .c
            .query_one(
                "SELECT hmac_secret_enc IS NULL FROM devices WHERE id=$1 AND user_id=$2",
                &[&case.device, &case.user.user],
            )
            .await?
            .try_get(0)?;
        Ok::<_, Err>((
            reply.status.as_u16(),
            reply_body.collect().await?.to_bytes(),
            case.nonces().await?,
            envelope_is_null,
        ))
    }
    .await;
    case.close().await.unwrap();

    let (status, response, nonces, envelope_is_null) = outcome.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        &response[..],
        b"{\"error\":\"device authentication failed\"}\n"
    );
    assert_eq!(nonces, 0);
    assert!(envelope_is_null, "the empty secret must not be re-sealed");
}

#[tokio::test]
async fn legacy_reseal_precedes_hmac_and_is_idempotent() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(true).await.unwrap() else {
        return;
    };
    let payload = format!(r#"{{"device_id":{}}}"#, case.device);
    // Inherited #513: the re-seal runs before HMAC verification (Go's migration order).
    let refused = case
        .server
        .handle(case.checkin(&payload, "gofree341-legacy-1", WRONG))
        .await;
    assert_eq!(refused.status().as_u16(), 401);
    let row = case.c.query_one("SELECT hmac_secret IS NULL, hmac_secret_key_id, hmac_secret_enc FROM devices WHERE id=$1", &[&case.device]).await.unwrap();
    assert!(
        row.get::<_, bool>(0),
        "plaintext must be gone after the re-seal"
    );
    assert_eq!(row.get::<_, Option<String>>(1).as_deref(), Some("v1"));
    let sealed: Vec<u8> = row.get(2);
    assert_eq!(
        setjoin_config_secret::open_column(&sealed, case.master.as_bytes()).unwrap(),
        SECRET.as_bytes()
    );
    assert_eq!(case.nonces().await.unwrap(), 0);
    let ok = case
        .server
        .handle(case.checkin(&payload, "gofree341-legacy-2", SECRET))
        .await;
    assert_eq!(ok.status().as_u16(), 200);
    let after: Vec<u8> = case
        .c
        .query_one(
            "SELECT hmac_secret_enc FROM devices WHERE id=$1",
            &[&case.device],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after, sealed,
        "a sealed row is never re-sealed (idempotent)"
    );
    case.close().await.unwrap();
}

#[tokio::test]
async fn oversize_policy_body_is_refused() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let uri = format!("/device/policy?device_id={}", case.device);
    let big = "x".repeat((1 << 20) + 1);
    let reply = case
        .server
        .handle(case.signed(
            "GET",
            &uri,
            &big,
            "gofree341-oversize",
            SECRET,
            body(big.clone()),
        ))
        .await;
    assert_eq!(reply.status().as_u16(), 401);
    assert_eq!(case.nonces().await.unwrap(), 0);
    case.close().await.unwrap();
}

#[tokio::test]
async fn unobservable_empty_get_body_fails_closed() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let uri = format!("/device/policy?device_id={}", case.device);
    let unsized_req = case.signed(
        "GET",
        &uri,
        "",
        "gofree341-unsized",
        SECRET,
        Unsized.boxed(),
    );
    assert_eq!(case.server.handle(unsized_req).await.status().as_u16(), 401);
    assert_eq!(case.nonces().await.unwrap(), 0);
    let empty = case.signed("GET", &uri, "", "gofree341-empty", SECRET, body(""));
    assert_eq!(case.server.handle(empty).await.status().as_u16(), 200);
    assert_eq!(case.nonces().await.unwrap(), 1);
    case.close().await.unwrap();
}

#[tokio::test]
async fn checkin_cap_is_checked_before_the_proof() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let events = (0..101)
        .map(|_| r#"{"type":"burst"}"#)
        .collect::<Vec<_>>()
        .join(",");
    let payload = format!(r#"{{"device_id":{},"events":[{events}]}}"#, case.device);
    let reply = case
        .server
        .handle(case.checkin(&payload, "gofree341-cap", WRONG))
        .await;
    assert_eq!(reply.status().as_u16(), 400);
    let text = String::from_utf8(
        reply
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(text, "{\"error\":\"too many events\"}\n");
    assert_eq!(case.nonces().await.unwrap(), 0);
    assert_eq!(case.events().await.unwrap(), 0);
    case.close().await.unwrap();
}

#[tokio::test]
async fn checkin_event_insert_failure_spends_nonce() {
    let _s = SERIAL.lock().await;
    let Some(case) = Case::open(false).await.unwrap() else {
        return;
    };
    let payload = format!(
        r#"{{"device_id":{},"events":[{{"type":"gofree341-fail"}}]}}"#,
        case.device
    );
    let nonce = "gofree341-event-insert-failure";
    let outcome = async {
        case.c
            .batch_execute(
                "CREATE FUNCTION public.gofree341_event_fail() RETURNS trigger
                 LANGUAGE plpgsql AS $$
                 BEGIN
                     IF NEW.event_type = 'gofree341-fail' THEN
                         RAISE EXCEPTION 'gofree341 injected event failure';
                     END IF;
                     RETURN NEW;
                 END;
                 $$;
                 CREATE TRIGGER gofree341_event_fail BEFORE INSERT ON device_events
                 FOR EACH ROW EXECUTE FUNCTION public.gofree341_event_fail();",
            )
            .await?;
        let failed = case
            .server
            .handle(case.checkin(&payload, nonce, SECRET))
            .await;
        let (failed, failed_body) = failed.into_parts();
        let spent: bool = case
            .c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM device_auth_nonces WHERE device_id=$1 AND nonce=$2)",
                &[&case.device, &nonce],
            )
            .await?
            .try_get(0)?;
        let replay = case
            .server
            .handle(case.checkin(&payload, nonce, SECRET))
            .await;
        let (replay, replay_body) = replay.into_parts();
        Ok::<_, Err>((
            failed.status.as_u16(),
            failed_body.collect().await?.to_bytes(),
            failed.headers.contains_key("x-operation-id"),
            spent,
            replay.status.as_u16(),
            replay_body.collect().await?.to_bytes(),
            case.events().await?,
        ))
    }
    .await;
    // Remove the shared trigger and fixture before checking the outcome.
    let drop_fault = case
        .c
        .batch_execute(
            "DROP TRIGGER IF EXISTS gofree341_event_fail ON device_events;
             DROP FUNCTION IF EXISTS public.gofree341_event_fail();",
        )
        .await;
    let close = case.close().await;
    drop_fault.unwrap();
    close.unwrap();

    let (failed, failed_body, has_operation_id, spent, replay, replay_body, events) =
        outcome.unwrap();
    assert_eq!(failed, 500);
    assert_eq!(&failed_body[..], b"{\"error\":\"internal error\"}\n");
    assert!(!has_operation_id);
    assert!(spent, "the failed check-in must spend its nonce");
    assert_eq!(replay, 401);
    assert_eq!(
        &replay_body[..],
        b"{\"error\":\"device authentication failed\"}\n"
    );
    assert_eq!(events, 0);
}
