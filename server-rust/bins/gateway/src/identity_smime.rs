//! Mailserver-local user S/MIME metadata. Authority stays in the identity
//! database boundary; the gateway composes the existing certificate parser.
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, RequestContext};
use chrono::Datelike;
use hyper::{Method, Request, Response};
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_identity::{issuance::object, self_service as db};
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};

pub(crate) fn matches(r: &Request<Body>) -> bool {
    (*r.method()==Method::DELETE && crate::inventory::path_score("/auth/me/smime/recipient-certs/{id}",r.uri().path()).is_some())
        || (matches!(*r.method(),Method::GET|Method::HEAD|Method::POST) && crate::inventory::path_score("/auth/me/smime/recipient-certs",r.uri().path()).is_some())
        || (*r.method() == Method::POST && crate::inventory::path_score("/auth/me/smime/certs/{id}/default", r.uri().path()).is_some())
        || (matches!(*r.method(), Method::GET | Method::HEAD | Method::POST)
        && crate::inventory::path_score("/auth/me/smime/certs", r.uri().path()).is_some())
        || (*r.method() == Method::DELETE
            && crate::inventory::path_score("/auth/me/smime/certs/{id}", r.uri().path()).is_some())
}

struct Form {
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    label: Vec<u8>,
}

async fn parse_form(r: &mut Request<Body>, cap: usize) -> Result<Form, ()> {
    use http_body_util::BodyExt;
    let boundary = r.headers().get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()).and_then(|v| multer::parse_boundary(v).ok()).ok_or(())?;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            if data.len() > cap - bytes.len() { return Err(()); }
            bytes.extend_from_slice(&data);
        }
    }
    let stream = futures_util::stream::once(async move { Ok::<_, std::convert::Infallible>(bytes::Bytes::from(bytes)) });
    let mut multipart = multer::Multipart::new(stream, boundary);
    let (mut cert, mut key, mut label) = (None, None, None);
    while let Some(field) = multipart.next_field().await.map_err(|_| ())? {
        let name = field.name().map(str::to_owned);
        let file = field.file_name().is_some_and(|v| !v.is_empty());
        let data = field.bytes().await.map_err(|_| ())?.to_vec();
        match (name.as_deref(), file) {
            (Some("cert"), true) if cert.is_none() => cert = Some(data),
            (Some("key"), true) if key.is_none() => key = Some(data),
            (Some("label"), false) if label.is_none() => label = Some(data),
            _ => {}
        }
    }
    let query = r.uri().query().unwrap_or("");
    if crate::mail_security_smime::bad_query(query) { return Err(()); }
    // Go's FormValue gives the first query value precedence over multipart
    // fields. Keep bytes so invalid UTF-8 gets Go's later store failure.
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |text: &str| percent_encoding::percent_decode_str(&text.replace('+', " ")).collect::<Vec<u8>>();
        if decode(name) == b"label" {
            label = Some(decode(value));
            break;
        }
    }
    Ok(Form { cert, key, label: label.unwrap_or_default() })
}

pub(crate) async fn handle(
    exec: &ScopedExecutor, actor: &AuthContext, mut r: Request<Body>,
    c: &RequestContext, id: String, operation: [u8; 16],
) -> Response<Body> {
    if r.uri().path().contains("/recipient-certs") {
        if r.method()==Method::DELETE {
            let Ok(target)=crate::mailboxes::segment(r.uri().path(),5).parse::<i64>() else {return bare(400,"invalid cert id",c,&id);};
            return match db::recipient_certificate_delete(exec,actor,target,operation).await {
                CommandOutcome::Committed(())=>crate::jmap::reply::response("{\"status\":\"deleted\"}\n".into(),c.identity.proto,id),
                CommandOutcome::Unknown {operation}=>unknown_outcome(operation,c,&id),
                CommandOutcome::RolledBack(Rejection::Unavailable)=>bare(500,"tx failed",c,&id),
                CommandOutcome::RolledBack(Rejection::CommitRefused(_))=>bare(500,"commit failed",c,&id),
                CommandOutcome::RolledBack(Rejection::Statement(error)) if error.sqlstate.is_none() && error.message=="not-found"=>bare(404,"certificate not found",c,&id),
                _=>bare(500,"failed to delete certificate",c,&id),
            };
        }
        if r.method()==Method::POST {
            let Ok(form)=parse_form(&mut r,2<<20).await else { return bare(400,"failed to parse form",c,&id); };
            let Some(cert)=form.cert else { return bare(400,"missing cert file",c,&id); };
            let Some((before,after))=setjoin_mail_security::smime::first_certificate_dates(&cert) else {
                return bare(400,"Invalid certificate format. Ensure it is PEM-encoded.",c,&id);
            };
            if after != -62135596800 && chrono::DateTime::from_timestamp(after,0).is_some_and(|expiry| expiry<chrono::Utc::now()) {return bare(400,"Certificate is expired.",c,&id);}
            let Some(email)=setjoin_mail_security::smime::first_certificate_email(&cert) else {
                return bare(400,"Certificate has no email address in subject-alternative-name.",c,&id);
            };
            if !setjoin_mail_security::smime::first_certificate_encrypt_capable(&cert) {
                return bare(400,"Certificate is not encryption-capable (signing-only or EC key).",c,&id);
            }
            let fingerprint=setjoin_mail_security::smime::fingerprint(&setjoin_mail_security::smime::first_pem_bytes(&cert).expect("parsed first certificate"));
            let (Ok(cert),Ok(label))=(String::from_utf8(cert),String::from_utf8(form.label)) else {
                return bare(500,"failed to store certificate",c,&id);
            };
            return match db::recipient_certificate_store(exec,actor,&email,&cert,&fingerprint,before,after,label.trim(),operation).await {
                CommandOutcome::Committed(())=>crate::jmap::reply::response(object(&[("email",json!(email)),("status",json!("stored"))])+"\n",c.identity.proto,id),
                CommandOutcome::Unknown {operation}=>unknown_outcome(operation,c,&id),
                _=>bare(500,"failed to store certificate",c,&id),
            };
        }
        let Ok(certs) = db::recipient_certificates(exec,actor).await else { return bare(500,"database error",c,&id); };
        let mut values = Vec::new();
        for cert in certs {
            let mut fields=vec![("id",json!(cert.id)),("email",json!(cert.email))];
            if !cert.label.is_empty() { fields.push(("label",json!(cert.label))); }
            fields.push(("source",json!(cert.source)));
            if let Some(value)=cert.before { fields.push(("notBefore",json!(value))); }
            if let Some(value)=cert.after { fields.push(("notAfter",json!(value))); }
            fields.push(("fingerprint",json!(cert.fingerprint)));
            fields.push(("isEncryptCapable",json!(setjoin_mail_security::smime::first_certificate_encrypt_capable(cert.pem.as_bytes()))));
            values.push(object(&fields));
        }
        let list=if values.is_empty() { "null".into() } else { format!("[{}]",values.join(",")) };
        return crate::jmap::reply::response(format!("{{\"certs\":{list}}}\n"),c.identity.proto,id);
    }
    if r.method() == Method::POST && r.uri().path().ends_with("/default") {
        let Ok(target) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() else {
            return bare(400, "bad id", c, &id);
        };
        return match db::user_certificate_default(exec, actor, target, operation).await {
            CommandOutcome::Committed(()) => crate::jmap::reply::response("{\"ok\":true}\n".into(), c.identity.proto, id),
            CommandOutcome::Unknown { operation } => unknown_outcome(operation,c,&id),
            CommandOutcome::RolledBack(Rejection::Unavailable) => bare(500,"tx failed",c,&id),
            CommandOutcome::RolledBack(Rejection::CommitRefused(_)) => bare(500,"commit failed",c,&id),
            CommandOutcome::RolledBack(Rejection::Statement(error)) => match error.message.as_str() {
                "not-found" => bare(404,"certificate not found",c,&id),
                "lookup" => bare(500,"lookup failed",c,&id),
                _ => bare(500,"update failed",c,&id),
            },
            _ => bare(500,"update failed",c,&id),
        };
    }
    if r.method() == Method::DELETE {
        let Ok(target) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() else {
            return bare(400, "invalid cert id", c, &id);
        };
        return match db::user_certificate_delete(exec, actor, target, operation).await {
            CommandOutcome::Committed(()) => crate::jmap::reply::response("{\"status\":\"deleted\"}\n".into(),c.identity.proto,id),
            CommandOutcome::Unknown { operation } => unknown_outcome(operation,c,&id),
            CommandOutcome::RolledBack(Rejection::Unavailable) => bare(500,"tx failed",c,&id),
            CommandOutcome::RolledBack(Rejection::CommitRefused(_)) => bare(500,"commit failed",c,&id),
            CommandOutcome::RolledBack(Rejection::Statement(error)) if error.message == "promote" => bare(500,"failed to promote survivor cert",c,&id),
            _ => bare(500,"failed to delete cert",c,&id),
        };
    }
    if r.method() == Method::POST {
        let Ok(form) = parse_form(&mut r, 5 << 20).await else {
            return bare(400, "failed to parse form", c, &id);
        };
        let Some(cert) = form.cert else { return bare(400, "missing cert file", c, &id); };
        let Some(key) = form.key else { return bare(400, "missing key file", c, &id); };
        let Some((before, after)) = setjoin_mail_security::smime::first_certificate_dates(&cert) else {
            return bare(400, "Invalid certificate format. Ensure the certificate is PEM-encoded.", c, &id);
        };
        if !setjoin_mail_security::smime::first_pem_bytes(&key).is_some_and(|der| db::smime_private_key_parses(&der)) {
            return bare(400, "Invalid private key format. Ensure the key is PEM-encoded and not encrypted.", c, &id);
        }
        let (Ok(cert), Ok(key), Ok(label)) = (String::from_utf8(cert), String::from_utf8(key), String::from_utf8(form.label)) else {
            return bare(500, "failed to store certificate", c, &id);
        };
        let label = label.trim();
        let label = if label.is_empty() { "default" } else { label };
        return match db::user_certificate_store(exec, actor, label, &cert, &key, before, after, operation).await {
            CommandOutcome::Committed(()) => crate::jmap::reply::response(
                object(&[("label", json!(label)), ("status", json!("stored"))]) + "\n", c.identity.proto, id),
            CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, &id),
            _ => bare(500, "failed to store certificate", c, &id),
        };
    }
    let Ok(certs) = db::user_certificates(exec, actor).await else {
        return bare(500, "database error", c, &id);
    };
    let mut values = Vec::new();
    for cert in certs {
        let mut fields = vec![("id", json!(cert.id)), ("label", json!(cert.label))];
        if let Some((before, after)) = setjoin_mail_security::smime::first_certificate_dates(cert.pem.as_bytes()) {
            for (name, seconds) in [("issuedAt", before), ("expiresAt", after)] {
                if seconds > 0 {
                    if let Some(date) = chrono::DateTime::from_timestamp(seconds, 0) {
                        if name != "expiresAt" || date.year() < 9999 {
                            fields.push((name, json!(date.format("%Y-%m-%dT%H:%M:%SZ").to_string())));
                        }
                    }
                }
            }
        }
        fields.push(("isDefault", json!(cert.is_default)));
        values.push(object(&fields));
    }
    let certs = if values.is_empty() { "null".into() } else { format!("[{}]", values.join(",")) };
    crate::jmap::reply::response(format!("{{\"certs\":{certs}}}\n"), c.identity.proto, id)
}
