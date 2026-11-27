use super::{
    http::{problem, user_envelope},
    reply,
    token::KeySource,
    JmapCommands,
};
use crate::{recovery_worker::ObjectStore, Body, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use setjoin_pg::MailboxAuthContext;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn upload(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        auth: &MailboxAuthContext,
        authorized: &setjoin_authz::Authorized,
        id: &str,
    ) -> Response<Body> {
        let services = self.services.as_ref().unwrap();
        let fail = |s, k, d| problem(s, k, d, ctx, id);
        let raw = &req.uri().path()[13..];
        let account = String::from_utf8(crate::inventory::unescape(raw)).unwrap_or_default();
        let Some(account_id) = account.parse::<i64>().ok().filter(|n| *n > 0) else {
            return fail(400, "accountNotFound", "invalid accountId");
        };
        let Some(tx) = self.tx_factory() else {
            return fail(500, "serverFail", "upload failed");
        };
        let Ok(user) = tx
            .mint_user_from_authorized(authorized, &ctx.identity.client_ip.to_string())
            .await
        else {
            return fail(500, "serverFail", "upload failed");
        };
        let primary_mailbox = auth.mailbox_optional().map(|m| m.get());
        if !setjoin_jmap::http_blob::account_read(&tx, &user, primary_mailbox, account_id)
            .await
            .unwrap_or(false)
        {
            return fail(403, "accountNotFound", "account not found");
        }
        let Some(store) = &services.store else {
            return fail(500, "serverFail", "upload failed");
        };
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let Ok(operation) = super::random_bytes() else {
            return fail(500, "serverFail", "upload failed");
        };
        let temp = format!(
            "{}{}",
            crate::blob_retention::BLOB_STAGING_PREFIX,
            &reply::hex(&operation)[..16]
        );
        let path =
            std::env::temp_dir().join(format!("setjoin-jmap-upload-{}", reply::hex(&operation)));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let Ok(mut file) = options.open(&path).await else {
            return fail(500, "serverFail", "upload failed");
        };
        let temporary = Temporary(path);
        let mut size = 0i64;
        let mut hash = Sha256::new();
        let cap = if services.max_upload > 0 {
            services.max_upload
        } else {
            100 << 20
        };
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return fail(500, "serverFail", "upload failed");
            };
            if let Ok(bytes) = frame.into_data() {
                size = size.saturating_add(bytes.len() as i64);
                if size > cap || file.write_all(&bytes).await.is_err() {
                    return fail(500, "serverFail", "upload failed");
                }
                hash.update(bytes);
            }
        }
        let digest: [u8; 32] = hash.finalize().into();
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if file.flush().await.is_err()
            || store
                .put_file(&temp, &temporary.0, size as u64, &ct)
                .await
                .is_err()
        {
            return fail(500, "serverFail", "upload failed");
        }
        let envelope = user_envelope(&user, operation, digest);
        let (promote_work_item_id, verify_work_item_id) =
            match setjoin_jmap::http_blob::account_upload(
                &tx,
                &user,
                &envelope,
                &hash,
                &store.blob_reference(&hash),
                size,
                &ct,
                services.grace,
                services.quota,
                Some(&temp),
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => {
                    let parsed = serde_json::from_str::<serde_json::Value>(&raw).ok();
                    let promote_id = parsed
                        .as_ref()
                        .and_then(|v| v.get("promoteWorkItemId"))
                        .and_then(serde_json::Value::as_i64);
                    let verify_id = parsed
                        .as_ref()
                        .and_then(|v| v.get("verifyWorkItemId"))
                        .and_then(serde_json::Value::as_i64);
                    (promote_id, verify_id)
                }
                setjoin_pg::CommandOutcome::RolledBack(e) => {
                    let _ = store
                        .delete_blob_checked(&temp, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                        .await;
                    return if e.log_summary().contains("BZ001") {
                        fail(413, "overQuota", "storage quota exceeded")
                    } else {
                        fail(500, "serverFail", "upload failed")
                    };
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut r = fail(503, "serverUnavailable", "upload outcome unknown");
                    if let Ok(val) = setjoin_pg::operation_hex(operation).parse() {
                        r.headers_mut().insert("x-operation-id", val);
                    }
                    return r;
                }
            };
        if store.promote(&temp, &hash).await.is_err() {
            return fail(500, "serverFail", "upload failed");
        }
        let cancelled_recover = match promote_work_item_id {
            Some(wid) => setjoin_blobs::complete_promote_recover(
                &tx, &user, wid, &hash, &temp, operation,
            )
            .await
            .unwrap_or(false),
            None => true,
        };
        if verify_work_item_id.is_none() && cancelled_recover {
            let _ = store
                .delete_blob_checked(&temp, crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT)
                .await;
        }
        let body = reply::go_compact(
            &serde_json::json!({"accountId":account,"blobId":hash,"size":size,"type":ct})
                .to_string(),
        )
        .unwrap()
            + "\n";
        let mut r = reply::response(body, ctx.identity.proto, id.into());
        *r.status_mut() = hyper::StatusCode::CREATED;
        r
    }
}
struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
