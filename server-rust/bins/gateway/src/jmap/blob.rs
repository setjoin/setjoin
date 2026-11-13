//! RFC 9404 method projection. Go scopes by actor-owned attachments and echoes
//! account strings; Blob/copy performs no database or object-store write.
use super::{envelope, reply};
use serde::Deserialize;
use serde_json::json;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Get {
    account_id: Option<String>,
    ids: Option<Vec<Option<String>>>,
    #[allow(dead_code)]
    properties: Option<Vec<Option<String>>>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Copy {
    from_account_id: Option<String>,
    to_account_id: Option<String>,
    ids: Option<Vec<Option<String>>>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lookup {
    account_id: Option<String>,
    hashes: Option<Vec<Option<String>>>,
    #[allow(dead_code)]
    type_names: Option<Vec<Option<String>>>,
}
struct Args {
    account: String,
    to: String,
    ids: Vec<String>,
}
pub struct Request {
    pub method: &'static str,
    pub client_id: String,
    args: Result<Args, ()>,
}
fn decode<T: Default + serde::de::DeserializeOwned>(v: &str) -> Result<T, ()> {
    serde_json::from_str(v).map_err(|_| ())
}
fn strings(v: Option<Vec<Option<String>>>) -> Vec<String> {
    v.unwrap_or_default()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect()
}
pub fn classify(body: &[u8]) -> Option<Request> {
    for method in ["Blob/get", "Blob/copy", "Blob/lookup"] {
        if let Some(call) =
            envelope::single_call_with_capability(body, method, "urn:ietf:params:jmap:blob")
        {
            let known: &[&str] = match method {
                "Blob/get" => &["accountId", "ids", "properties"],
                "Blob/copy" => &["fromAccountId", "toAccountId", "ids"],
                _ => &["accountId", "hashes", "typeNames"],
            };
            let raw = if call.args.is_object() || call.args.is_null() {
                serde_json::to_string(&envelope::struct_arguments(&call.raw_args, known)?).ok()?
            } else {
                call.raw_args
            };
            let args = match method {
                "Blob/get" => decode::<Get>(&raw).map(|a| Args {
                    account: a.account_id.unwrap_or_default(),
                    to: String::new(),
                    ids: strings(a.ids),
                }),
                "Blob/copy" => decode::<Copy>(&raw).map(|a| Args {
                    account: a.from_account_id.unwrap_or_default(),
                    to: a.to_account_id.unwrap_or_default(),
                    ids: strings(a.ids),
                }),
                _ => decode::<Lookup>(&raw).map(|a| Args {
                    account: a.account_id.unwrap_or_default(),
                    to: String::new(),
                    ids: strings(a.hashes),
                }),
            };
            return Some(Request {
                method,
                client_id: call.client_id,
                args,
            });
        }
    }
    None
}
pub async fn response(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    session: &str,
    request: &Request,
) -> Option<String> {
    let a = match &request.args {
        Ok(a) => a,
        Err(()) => {
            return Some(reply::method_error(
                session,
                "invalidArguments",
                400,
                "",
                &request.client_id,
            ))
        }
    };
    let empty = a.ids.is_empty() || (request.method != "Blob/lookup" && a.ids.len() > 256);
    let found = if empty {
        Default::default()
    } else {
        match setjoin_jmap::blob::owned(exec, auth, &a.ids).await {
            Ok(found) => found,
            Err(_) => {
                return Some(reply::method_error(
                    session,
                    "serverFail",
                    500,
                    "",
                    &request.client_id,
                ))
            }
        }
    };
    let raw = match request.method {
        "Blob/get" if empty => json!({"accountId":a.account,"list":[],"notFound":[]}).to_string(),
        "Blob/get" => {
            let mut list = Vec::new();
            let mut missing = Vec::new();
            for id in &a.ids {
                if let Some(info) = found.get(id) {
                    // Go's blobInfo is a struct: retain its declared field order.
                    let q = crate::problem::go_string;
                    list.push(format!(
                        r#"{{"id":{},"blobId":{},"size":{},"contentType":{},"accountId":{}}}"#,
                        q(id),
                        q(id),
                        info.size,
                        q(&info.content_type),
                        q(&a.account)
                    ));
                } else {
                    missing.push(id);
                }
            }
            format!(
                r#"{{"accountId":{},"list":[{}],"notFound":{},"state":"0"}}"#,
                crate::problem::go_string(&a.account),
                list.join(","),
                serde_json::to_string(&missing).ok()?
            )
        }
        "Blob/copy" => {
            let mut list = Vec::new();
            let mut missing = Vec::new();
            if !empty {
                for id in &a.ids {
                    if found.contains_key(id) {
                        list.push(json!({"id":id,"blobId":id,"type":"application/octet-stream"}));
                    } else {
                        missing.push(
                            json!({"id":id,"type":"blobNotFound","description":"blob not found"}),
                        );
                    }
                }
            }
            json!({"fromAccountId":a.account,"toAccountId":a.to,"list":list,"notCopied":missing})
                .to_string()
        }
        _ => {
            let list: Vec<_> = a
                .ids
                .iter()
                .filter(|id| found.contains_key(*id))
                .map(|id| json!({"hash":id,"blobId":id}))
                .collect();
            json!({"accountId":a.account,"list":list}).to_string()
        }
    };
    reply::method_response(session, request.method, &raw, &request.client_id)
}
