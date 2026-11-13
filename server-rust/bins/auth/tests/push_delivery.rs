//! Real auth HTTP -> encrypted native device -> signed approval -> one-use poll.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use std::{future::Future, pin::Pin};
type Error = Box<dyn std::error::Error + Send + Sync>;
struct Device(tokio::sync::mpsc::UnboundedSender<(String, String, Vec<u8>)>);
impl setjoin_identity::push_delivery::NativeDelivery for Device {
    fn send<'a>(
        &'a mut self,
        provider: &'a str,
        token: &'a str,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .send((provider.into(), token.into(), payload.into()))
                .map_err(|_| "device disconnected".into())
        })
    }
}
// Independent device decoder, first pinned to the pre-existing Go-produced wire.
fn open(secret: &p256::SecretKey, wire: &[u8]) -> Result<Vec<u8>, Error> {
    if wire.len() < 93 || wire[0] != 4 {
        return Err("invalid ECIES frame".into());
    }
    let ephemeral = p256::PublicKey::from_sec1_bytes(&wire[..65])?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let prk =
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(shared.raw_secret_bytes());
    let info = [b"push-challenge".as_slice()];
    let mut bytes = [0u8; 32];
    prk.expand(&info, ring::hkdf::HKDF_SHA256)
        .map_err(|_| "HKDF")?
        .fill(&mut bytes)
        .map_err(|_| "HKDF")?;
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &bytes).map_err(|_| "AEAD key")?,
    );
    let mut encrypted = wire[77..].to_vec();
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&wire[65..77]).map_err(|_| "nonce")?;
    let plain = key
        .open_in_place(nonce, ring::aead::Aad::empty(), &mut encrypted)
        .map_err(|_| "device rejected tag")?;
    Ok(plain.to_vec())
}
#[test]
fn device_decoder_accepts_existing_go_ecies_golden() {
    use p256::pkcs8::DecodePrivateKey;
    let decode = |s: &str| {
        let mut out = vec![];
        for i in (0..s.len()).step_by(2) {
            out.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
        }
        out
    };
    // Frozen cross-end constants: PUSH_ECIES_CONTRACT.md and guard-core/ecdh_golden.rs.
    let der=decode("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420ec1604f867dc08e17a4688f251adce508d6827bb72e952bf14666820febb08d5a144034200043ffa8457dbd2917d7ab2555efa3b1c1669079eef5933ecc4bd5fa6b1701787d3ee4d370c8e54b99ca7f14fdf08329eb19fc87d33e83108a3e9577d6709b8fc75");
    let mut wire=decode("0484d4083d3cce31d97122787043abdff18a900a421e471747e0aa0cad7ba4c00b78422c16286d6f57ddd9d2cbaa429ee04efce4ffb5d944a3571bb7c38f9670b1a4ff6b6dfd563c638179f6fa93db6bc2399d727d12c0f9c07916870c5a44");
    let secret = p256::SecretKey::from_pkcs8_der(&der).unwrap();
    assert_eq!(open(&secret, &wire).unwrap(), b"42");
    wire[94] ^= 1;
    assert!(open(&secret, &wire).is_err());
}
#[tokio::test]
async fn native_device_completes_login_only_after_signed_approval() {
    let db = Db::for_case("IDMFA3-native-delivery").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idmfa3-delivery").await.unwrap();
    let b = fixture::account(&c, "idmfa3-delivery-foreign")
        .await
        .unwrap();
    let rate: Option<bool> = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    use p256::elliptic_curve::sec1::ToSec1Point;
    let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
    let mut device_id = 0;
    for (user, token, revoked, bad) in [
        (a.user, "device", false, false),
        (a.user, "revoked", true, false),
        (a.user, "bad-envelope", false, true),
        (b.user, "foreign", false, false),
    ] {
        let id:i64=c.query_one("INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key,revoked_at) VALUES($1,'fcm',CASE WHEN $5 THEN decode('11','hex') ELSE pgp_sym_encrypt($2,$3) END,$4,CASE WHEN $6 THEN now() ELSE NULL END) RETURNING id",&[&user,&token,&"2".repeat(64),&public,&bad,&revoked]).await.unwrap().get(0);
        if token == "device" {
            device_id = id;
        }
    }
    c.execute("INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key) VALUES($1,'fcm',pgp_sym_encrypt('bad-key',$2),decode('11','hex'))",&[&a.user,&"2".repeat(64)]).await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let mut cfg = Config::for_secret(f["secret"].as_str().unwrap().into());
    cfg.dsn = db.dsn.clone();
    cfg.signing_alg = "ES256".into();
    cfg.db_encryption_key = "2".repeat(64);
    cfg.vapid_private_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into();
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let server = AuthServer::load(exec.clone(), cfg)
        .await
        .unwrap()
        .with_native_push(Device(tx));
    let result=async{
  let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
  let claims=json!({"uid":a.user,"typ":"mfa_pending","jti":"idmfa3-delivery","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+300});
  let pending=setjoin_authz::legacy_jwt::sign_hs256(f["secret"].as_str().unwrap().as_bytes(),&claims.to_string());
  let reply=server.handle(Request::post("/auth/mfa/push/send").body(body(json!({"mfa_token":pending}).to_string()))?).await;
  if reply.status()!=200{return Err("challenge creation failed".into());}
  let reply:Value=serde_json::from_slice(&reply.into_body().collect().await?.to_bytes())?;assert!(reply.get("code").is_none());
  let (provider,device,wire)=tokio::time::timeout(std::time::Duration::from_secs(2),rx.recv()).await?.ok_or("device transport closed")?;
  assert_eq!(provider,"fcm");assert_eq!(device,"device");let plain:Value=serde_json::from_slice(&open(&secret,&wire)?)?;
  let row=c.query_one("SELECT challenge_code,floor(EXTRACT(EPOCH FROM expires_at))::bigint FROM push_mfa_challenges WHERE user_id=$1 AND nonce=decode($2,'hex')",&[&a.user,&reply["nonce"].as_str().unwrap()]).await?;
  let code:String=row.get(0);let expires:i64=row.get(1);
  assert_eq!(plain,json!({"type":"push_mfa","protocol":"setjoin.push-approval.v1","nonce":reply["nonce"],"code":code,"device_id":device_id,"user_id":a.user,"session_id":pending,"expires_at":expires}));
  assert!(tokio::time::timeout(std::time::Duration::from_millis(200),rx.recv()).await.is_err(),"revoked, unreadable and foreign devices must receive nothing");
  let rng=ring::rand::SystemRandom::new();let signing=ring::signature::EcdsaKeyPair::from_private_key_and_public_key(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,&[7u8;32],&public,&rng).unwrap();
  let canonical=json!({"code":code,"decision":"approve","device_id":device_id,"expires_at":expires,"issued_at":now,"nonce":reply["nonce"],"protocol":"setjoin.push-approval.v1","session_id":pending,"user_id":a.user}).to_string();
  use base64::Engine;let signature=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.sign(&rng,canonical.as_bytes()).unwrap().as_ref());
  let reply_approval=server.handle(Request::post("/auth/mfa/approve").body(body(json!({"nonce":reply["nonce"],"code":code,"device_id":device_id,"decision":"approve","issued_at":now,"expires_at":expires,"signature":signature}).to_string()))?).await;
  assert_eq!(reply_approval.status(),204);
  let poll=json!({"mfa_token":pending,"nonce":reply["nonce"]}).to_string();
  let issued=server.handle(Request::post("/auth/push/status").body(body(poll.clone()))?).await;assert_eq!(issued.status(),200);
  let issued:Value=serde_json::from_slice(&issued.into_body().collect().await?.to_bytes())?;
  let keys=setjoin_authz::signing_keys::KeySet::load(&exec,f["secret"].as_str().unwrap().as_bytes(),setjoin_config_secret::CryptoProfile::Standard).await?;
  let legacy=setjoin_authz::legacy_jwt::LegacyKeys::new(f["secret"].as_str().unwrap().as_bytes(),&["authserver-hmac-1"],None)?;
  for (field,typ) in [("access_token","access"),("refresh_token","refresh")]{let proof=setjoin_identity::session::Session::verify(issued[field].as_str().ok_or("no issued token")?,Some(&keys),&legacy,"mailserver").ok_or("invalid issued signature")?;assert_eq!(proof.user(),a.user);assert_eq!(proof.text("typ"),typ);}
  let replay=server.handle(Request::post("/auth/push/status").body(body(poll))?).await;assert_eq!(replay.status(),200);assert_eq!(serde_json::from_slice::<Value>(&replay.into_body().collect().await?.to_bytes())?,json!({"approved":false}));
  Ok::<(),Error>(())
 }.await;
    drop(server);
    for uid in [a.user, b.user] {
        for table in [
            "push_mfa_challenges",
            "push_devices",
            "auth_event_log",
            "login_events",
            "sessions",
            "oauth_tokens",
        ] {
            c.execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await
                .unwrap();
        }
    }
    common::restore_receipts(&c, &receipts).await;
    fixture::remove(&c, &a).await.unwrap();
    fixture::remove(&c, &b).await.unwrap();
    if let Some(rate) = rate {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&rate],
        )
        .await
        .unwrap();
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap();
    }
    result.unwrap();
}
