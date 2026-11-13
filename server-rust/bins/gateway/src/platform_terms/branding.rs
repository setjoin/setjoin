//! Group `branding`: Go's `BrandingHandler` (`/admin/branding`). The read needs
//! `requireMailPerm`, the update `mail.pipeline`. The update reads a multipart form the way
//! `ParseMultipartForm(2 MiB)` does (query values count too), stores an optional logo under
//! `branding/logo` and answers `{"status":"ok"}` whatever happened to the config writes.
use super::{Action, Env};
use crate::recovery_worker::ObjectStore as _;
use crate::{Body, Response};
use hyper::Request;
use setjoin_platform::branding;

const CAP: usize = 2 << 20;

/// `url.ParseQuery` reports an error for a `;` or a bad percent escape in any pair.
fn query_error(uri: &hyper::Uri) -> bool {
    let valid = |text: &str| {
        let b = text.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
                {
                    return false;
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        true
    };
    uri.query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
        .any(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            pair.contains(';') || !valid(key) || !valid(value)
        })
}

struct Form {
    names: Vec<String>,
    logo: Option<(Vec<u8>, String)>,
}

async fn parse(r: &mut Request<Body>) -> Result<Form, ()> {
    use http_body_util::BodyExt;
    let boundary = r
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| multer::parse_boundary(v).ok())
        .ok_or(())?;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > CAP - bytes.len() {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let stream = futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(bytes))
    });
    let mut form = multer::Multipart::new(stream, boundary);
    let mut out = Form {
        names: vec![],
        logo: None,
    };
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        let name = field.name().unwrap_or("").to_owned();
        let file = field.file_name().is_some_and(|n| !n.is_empty());
        let kind = field
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let data = field.bytes().await.map_err(|_| ())?;
        if name.is_empty() {
            continue;
        }
        if file {
            if name == "logo" && out.logo.is_none() {
                out.logo = Some((data.to_vec(), kind));
            }
        } else if name == "name" {
            out.names.push(crate::guests_input::go_utf8(&data));
        }
    }
    Ok(out)
}

pub(super) async fn run(what: Action, mut r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    if what == Action::BrandingGet {
        return e.reply(branding::get(e.exec).await, 200);
    }
    let query_failed = query_error(r.uri());
    let query_name = crate::admin_identity_input::query(r.uri(), "name");
    let Ok(form) = parse(&mut r).await else {
        return e.bare(400, "invalid multipart form");
    };
    if query_failed {
        return e.bare(400, "invalid multipart form");
    }
    let name = query_name
        .or_else(|| form.names.first().cloned())
        .unwrap_or_default();
    if !name.is_empty() {
        let _ = branding::set(e.exec, e.actor, "brand_name", &name, e.operation).await;
    }
    if let Some((bytes, kind)) = form.logo {
        let kind = if kind.is_empty() {
            "image/png"
        } else {
            kind.as_str()
        };
        let stored = match e.store {
            Some(store) => store.put("branding/logo", &bytes, kind).await,
            None => Err("object storage is not configured".into()),
        };
        if stored.is_err() {
            return e.bare(500, "logo upload failed");
        }
        let Some(next) = crate::jmap::random() else {
            return e.bare(503, "service unavailable");
        };
        let _ = branding::set(
            e.exec,
            e.actor,
            "brand_logo_url",
            "/blob/branding/logo",
            next,
        )
        .await;
    }
    e.reply(setjoin_platform::done("{\"status\":\"ok\"}".into()), 200)
}
