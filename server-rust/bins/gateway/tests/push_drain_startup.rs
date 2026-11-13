//! #408: the executable takes `push-intent-drain` only once Go's copy is
//! switched off, drains the cross-tenant queue on the worker credential
//! (never the request DSN) and decrypts device tokens under the deployment
//! encryption key.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(
    request_dsn: &str,
    worker_dsn: &str,
    rust_on: &str,
    go_off: &str,
) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", request_dsn),
        ("DB_WORKER_DSN", worker_dsn),
        ("DB_ENCRYPTION_KEY", "gofree-drain-startup-key"),
        ("RUST_WORKERS_ON", rust_on),
        ("GO_WORKERS_OFF", go_off),
    ] {
        command.env(k, v);
    }
    // The legacy device-token passphrase is deliberately short; EK01 uses
    // its separately configured, valid startup key rather than that passphrase.
    command.env("IDENTITY_CONFIG_SECRET_KEY", "22".repeat(32));
    command.spawn_boot()
}

fn stop(child: &mut crate::common::boot::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

#[tokio::test]
async fn refuses_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("push-drain-startup") else {
        return Ok(());
    };
    for off in ["", "notify-intent-drain", "push-intent-drain-other"] {
        let child = gateway(&db.dsn, &db.dsn, "push-intent-drain", off)?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains("GO_WORKERS_OFF=push-intent-drain") {
            return Err(
                format!("expected refusal for {off:?}, got {:?}: {err}", out.status).into(),
            );
        }
    }
    println!("GOLDEN-REPLAY: worker push-intent-drain :: refuses-without-go-off");
    Ok(())
}

/// Boot uses the restricted request role; queue effects use the worker role. The intent is
/// finished (gate, payload and encrypted device resolution all ran on the
/// worker credential) and the unconfigured provider is skipped, not failed.
#[tokio::test]
async fn drains_on_the_worker_credential() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("push-drain-startup") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM mailboxes WHERE email='gofree-drain-start@gofree-drain-start.test'; DELETE FROM users WHERE username='gofree-drain-start'; DELETE FROM domains WHERE name='gofree-drain-start.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-drain-start.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ('gofree-drain-start',$1,'gofree-drain-start@gofree-drain-start.test','S') RETURNING id", &[&domain]).await?.get(0);
    let mailbox: i64 = owner.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,'gofree-drain-start@gofree-drain-start.test','S',true) RETURNING id", &[&user, &domain]).await?.get(0);
    owner
        .execute(
            "INSERT INTO push_devices(user_id,push_provider,push_token_enc) VALUES ($1,'fcm',pgp_sym_encrypt('tok','gofree-drain-startup-key')::bytea)",
            &[&user],
        )
        .await?;
    let message: i64 = owner.query_one("INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,from_name,thread_id,raw_ref,size_bytes,subject,received_at) VALUES ($1,1,'<s@x.test>','a@x.test','A','t','r',1,'start','2026-10-25 10:00:00+00') RETURNING id", &[&mailbox]).await?.get(0);
    owner
        .execute(
            "INSERT INTO push_intents(mailbox_id,message_id,received_at) VALUES ($1,$2,'2026-10-25 10:00:00+00')",
            &[&mailbox, &message],
        )
        .await?;
    let mut child = gateway(
        db.app.as_deref().expect("restricted boot request role"),
        &db.dsn,
        "push-intent-drain",
        "push-intent-drain",
    )?;
    let mut state = String::new();
    for _ in 0..80 {
        state = owner
            .query_one("SELECT status||':'||attempts||':'||coalesce(last_error,'') FROM push_intents WHERE mailbox_id=$1", &[&mailbox])
            .await?
            .get(0);
        if state.starts_with("done") || child.try_wait()?.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    stop(&mut child);
    let _ = owner.batch_execute(&format!(
        "DELETE FROM push_intents WHERE mailbox_id={mailbox}; DELETE FROM push_devices WHERE user_id={user}; DELETE FROM messages WHERE mailbox_id={mailbox}; DELETE FROM mailboxes WHERE id={mailbox}; DELETE FROM users WHERE id={user}; DELETE FROM domains WHERE id={domain}"
    )).await;
    assert_eq!(state, "done:1:");
    Ok(())
}
