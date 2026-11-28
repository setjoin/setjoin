use hmac::{Hmac, Mac};
use serde_json::json;
use setjoin_authz::{
    device::{DeviceRequest, DeviceResolver},
    jwks::Jwks,
    legacy_jwt::{sign_hs256, LegacyKeys},
    runtime::Proof,
};
use setjoin_config_secret::CryptoProfile;
use setjoin_conformance::{
    fixture,
    harness::{BoxError, Db},
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
#[tokio::test]
async fn device_proof_binds_the_body_and_consumes_nonce_once() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("authzgates-device-proof") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authzgates-proof").await?;
    let device:i64=owner.query_one("INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state) VALUES($1,'authzgates-proof','fixture-device-secret','approved') RETURNING id",&[&a.user]).await?.get(0);
    let keys = Jwks::with_fetch(Box::new(|| Box::pin(async { panic!("HS256 JWKS lookup") })))
        .with_legacy_keys(
            LegacyKeys::new(
                b"authzgates-test-secret-32-bytes-long",
                &["authserver-hmac-1"],
                None,
            )
            .unwrap(),
        );
    let token=sign_hs256(b"authzgates-test-secret-32-bytes-long",&json!({"uid":a.user,"typ":"access","iat":1700000000,"exp":4102444800i64,"iss":"mailserver","aud":["mailserver-gateway"]}).to_string());
    let proof = Proof::verify(&token, "mailserver", 1_800_000_000.0, &keys, false)
        .await
        .unwrap();
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
    let resolver = DeviceResolver::new(
        exec,
        b"authzgates-test-master-secret-32".to_vec(),
        CryptoProfile::Standard,
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let hash = format!("{:x}", Sha256::digest(b"payload"));
    let challenge = format!("{device}:{timestamp}:POST:/x?query=1:{hash}:fixture-nonce");
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fixture-device-secret").unwrap();
    mac.update(challenge.as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes());
    let mut headers = hyper::HeaderMap::new();
    for (k, v) in [
        ("x-device-id", device.to_string()),
        ("x-device-timestamp", timestamp),
        ("x-device-body-sha256", hash),
        ("x-device-nonce", "fixture-nonce".into()),
        ("x-device-hmac", signature),
    ] {
        headers.insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes())?,
            v.parse()?,
        );
    }
    let result = async {
        let bad = resolver
            .resolve(
                &proof,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/x?query=1",
                    body: b"substituted",
                },
            )
            .await;
        if bad.bound {
            return Err("substituted request body authenticated".into());
        }
        let first = resolver
            .resolve(
                &proof,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/x?query=1",
                    body: b"payload",
                },
            )
            .await;
        if !first.bound || first.enroll_state != "approved" {
            return Err(format!("valid device rejected: {first:?}").into());
        }
        let replay = resolver
            .resolve(
                &proof,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/x?query=1",
                    body: b"payload",
                },
            )
            .await;
        if replay.bound {
            return Err("single-use proof replay authenticated".into());
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .execute(
            "DELETE FROM devices WHERE id=$1 AND user_id=$2",
            &[&device, &a.user],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

/// Owner-approved security fix 2026-11-05 (#499): a foreign caller's request for
/// someone else's device is refused BEFORE the single-use nonce is consumed.
#[tokio::test]
async fn foreign_device_request_does_not_burn_the_owners_nonce() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secfix3-device-nonce") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "secfix3-nonce-a").await?;
    let b = fixture::account(&owner, "secfix3-nonce-b").await?;
    let device:i64=owner.query_one("INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state) VALUES($1,'secfix3-nonce','fixture-device-secret','approved') RETURNING id",&[&a.user]).await?.get(0);
    let keys = Jwks::with_fetch(Box::new(|| Box::pin(async { panic!("HS256 JWKS lookup") })))
        .with_legacy_keys(
            LegacyKeys::new(
                b"authzgates-test-secret-32-bytes-long",
                &["authserver-hmac-1"],
                None,
            )
            .unwrap(),
        );
    let proof_for = |uid: i64| {
        let token=sign_hs256(b"authzgates-test-secret-32-bytes-long",&json!({"uid":uid,"typ":"access","iat":1700000000,"exp":4102444800i64,"iss":"mailserver","aud":["mailserver-gateway"]}).to_string());
        let keys = &keys;
        async move {
            Proof::verify(&token, "mailserver", 1_800_000_000.0, keys, false)
                .await
                .unwrap()
        }
    };
    let (pa, pb) = (proof_for(a.user).await, proof_for(b.user).await);
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| db.dsn.clone());
    let worker = ScopedExecutor::from_dsn(&worker_dsn, 2).map_err(|e| e.0)?;
    let resolver = DeviceResolver::new(
        exec,
        b"authzgates-test-master-secret-32".to_vec(),
        CryptoProfile::Standard,
    )
    .with_worker(worker);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let hash = format!("{:x}", Sha256::digest(b"payload"));
    let challenge = format!("{device}:{timestamp}:POST:/x:{hash}:secfix3-nonce");
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fixture-device-secret").unwrap();
    mac.update(challenge.as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes());
    let mut headers = hyper::HeaderMap::new();
    for (k, v) in [
        ("x-device-id", device.to_string()),
        ("x-device-timestamp", timestamp),
        ("x-device-body-sha256", hash),
        ("x-device-nonce", "secfix3-nonce".into()),
        ("x-device-hmac", signature),
    ] {
        headers.insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes())?,
            v.parse()?,
        );
    }
    let request = || DeviceRequest {
        headers: &headers,
        method: "POST",
        uri: "/x",
        body: b"payload",
    };
    let foreign = resolver.resolve(&pb, request()).await;
    let owned = resolver.resolve(&pa, request()).await;
    owner
        .execute(
            "DELETE FROM device_auth_nonces WHERE device_id=$1",
            &[&device],
        )
        .await
        .ok();
    owner
        .execute("DELETE FROM devices WHERE id=$1", &[&device])
        .await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    assert!(
        !foreign.bound,
        "foreign caller must not be bound to the device"
    );
    assert!(
        owned.bound,
        "the owner's nonce was burned by the foreign request: {owned:?}"
    );
    Ok(())
}

/// Owner-approved security fix 2026-11-05 (#513 item 1): a successful proof against a legacy
/// plaintext secret re-seals it even under app RLS (frozen Go's UPDATE ran with no user GUC,
/// matched no row, and left the plaintext in the table).
#[tokio::test]
async fn legacy_plaintext_secret_is_resealed_under_app_rls() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secfix5-device-reseal") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "secfix5-reseal").await?;
    let device:i64=owner.query_one("INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state) VALUES($1,'secfix5-reseal','fixture-device-secret','approved') RETURNING id",&[&a.user]).await?.get(0);
    let keys = Jwks::with_fetch(Box::new(|| Box::pin(async { panic!("HS256 JWKS lookup") })))
        .with_legacy_keys(
            LegacyKeys::new(
                b"authzgates-test-secret-32-bytes-long",
                &["authserver-hmac-1"],
                None,
            )
            .unwrap(),
        );
    let token=sign_hs256(b"authzgates-test-secret-32-bytes-long",&json!({"uid":a.user,"typ":"access","iat":1700000000,"exp":4102444800i64,"iss":"mailserver","aud":["mailserver-gateway"]}).to_string());
    let proof = Proof::verify(&token, "mailserver", 1_800_000_000.0, &keys, false)
        .await
        .unwrap();
    // The request credential WITHOUT row-security bypass: the app role.
    let app = db
        .app
        .as_deref()
        .ok_or("DB_APP_DSN is required for the app-RLS case")?;
    let exec = ScopedExecutor::from_dsn(app, 2).map_err(|e| e.0)?;
    let resolver = DeviceResolver::new(
        exec,
        b"authzgates-test-master-secret-32".to_vec(),
        CryptoProfile::Standard,
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let hash = format!("{:x}", Sha256::digest(b"payload"));
    let challenge = format!("{device}:{timestamp}:POST:/x?query=1:{hash}:reseal-nonce");
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fixture-device-secret").unwrap();
    mac.update(challenge.as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes());
    let mut headers = hyper::HeaderMap::new();
    for (k, v) in [
        ("x-device-id", device.to_string()),
        ("x-device-timestamp", timestamp),
        ("x-device-body-sha256", hash),
        ("x-device-nonce", "reseal-nonce".into()),
        ("x-device-hmac", signature),
    ] {
        headers.insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes())?,
            v.parse()?,
        );
    }
    let result = async {
        let first = resolver
            .resolve(&proof, DeviceRequest { headers: &headers, method: "POST", uri: "/x?query=1", body: b"payload" })
            .await;
        if !first.bound {
            return Err(format!("valid legacy-secret proof rejected: {first:?}").into());
        }
        let row = owner.query_one("SELECT hmac_secret IS NOT NULL, hmac_secret_enc IS NOT NULL, hmac_secret_key_id FROM devices WHERE id=$1", &[&device]).await?;
        let (plain, sealed, key): (bool, bool, Option<String>) = (row.get(0), row.get(1), row.get(2));
        if plain {
            return Err("plaintext device secret survived a successful proof under app RLS".into());
        }
        if !sealed || key.as_deref() != Some("v1") {
            return Err("device secret was not re-sealed under key v1".into());
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .execute(
            "DELETE FROM device_auth_nonces WHERE device_id=$1",
            &[&device],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM devices WHERE id=$1 AND user_id=$2",
            &[&device, &a.user],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn resolve_for_user_binds_owned_device_and_rejects_foreign_invalid_and_missing_headers(
) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("auth-device-resolve-for-user") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "resolve-user-a").await?;
    let b = fixture::account(&owner, "resolve-user-b").await?;
    let device: i64 = owner
        .query_one(
            "INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state) VALUES($1,'resolve-user-fp','fixture-device-secret','approved') RETURNING id",
            &[&a.user],
        )
        .await?
        .get(0);
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
    let resolver = DeviceResolver::new(
        exec,
        b"authzgates-test-master-secret-32".to_vec(),
        CryptoProfile::Standard,
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let hash = format!("{:x}", Sha256::digest(b"login-body"));
    let challenge = format!("{device}:{timestamp}:POST:/auth/login:{hash}:resolve-user-nonce");
    let mut mac = Hmac::<Sha256>::new_from_slice(b"fixture-device-secret").unwrap();
    mac.update(challenge.as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes());
    let mut headers = hyper::HeaderMap::new();
    for (k, v) in [
        ("x-device-id", device.to_string()),
        ("x-device-timestamp", timestamp),
        ("x-device-body-sha256", hash),
        ("x-device-nonce", "resolve-user-nonce".into()),
        ("x-device-hmac", signature),
    ] {
        headers.insert(
            hyper::header::HeaderName::from_bytes(k.as_bytes())?,
            v.parse()?,
        );
    }

    let result = async {
        let missing = resolver
            .resolve_for_user(
                a.user,
                DeviceRequest {
                    headers: &hyper::HeaderMap::new(),
                    method: "POST",
                    uri: "/auth/login",
                    body: b"login-body",
                },
            )
            .await;
        if missing.bound {
            return Err("missing headers must not bind".into());
        }

        let mut bad_sig_headers = headers.clone();
        bad_sig_headers.insert("x-device-hmac", "0".repeat(64).parse()?);
        let bad_sig = resolver
            .resolve_for_user(
                a.user,
                DeviceRequest {
                    headers: &bad_sig_headers,
                    method: "POST",
                    uri: "/auth/login",
                    body: b"login-body",
                },
            )
            .await;
        if bad_sig.bound {
            return Err("invalid hmac must not bind".into());
        }

        let foreign = resolver
            .resolve_for_user(
                b.user,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/auth/login",
                    body: b"login-body",
                },
            )
            .await;
        if foreign.bound {
            return Err("foreign user must not bind".into());
        }

        let owned = resolver
            .resolve_for_user(
                a.user,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/auth/login",
                    body: b"login-body",
                },
            )
            .await;
        if !owned.bound || owned.device_id != device || owned.enroll_state != "approved" {
            return Err(
                format!("expected bound device after foreign attempt, got {owned:?}").into(),
            );
        }

        let replay = resolver
            .resolve_for_user(
                a.user,
                DeviceRequest {
                    headers: &headers,
                    method: "POST",
                    uri: "/auth/login",
                    body: b"login-body",
                },
            )
            .await;
        if replay.bound {
            return Err("replayed nonce must not bind".into());
        }
        Ok::<_, BoxError>(())
    }
    .await;

    owner
        .execute(
            "DELETE FROM device_auth_nonces WHERE device_id=$1",
            &[&device],
        )
        .await
        .ok();
    owner
        .execute("DELETE FROM devices WHERE id=$1", &[&device])
        .await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}
