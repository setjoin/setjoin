//! Detached Chat preview protocol. Message IDs originate in committed sends.
use crate::recovery_worker::{ObjectStore, S3Store};
use setjoin_authz::AuthContext;
use setjoin_chat::members::{self, FetchedPreview};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub struct Unfurl {
    exec: ScopedExecutor,
    store: Arc<S3Store>,
    client: reqwest::Client,
    admission: Mutex<HashMap<i64, (Instant, u8)>>,
}
impl Unfurl {
    pub fn new(exec: ScopedExecutor, store: Arc<S3Store>, client: reqwest::Client) -> Self {
        Self {
            exec,
            store,
            client,
            admission: Mutex::new(HashMap::new()),
        }
    }
    /// Production always uses the shared DNS/dial policy and manual redirects.
    pub fn production(exec: ScopedExecutor, store: Arc<S3Store>) -> Self {
        Self::new(
            exec,
            store,
            crate::webhook::safe_http_client(Duration::from_secs(10)),
        )
    }
    /// Called only with the result of this verified actor's committed send.
    /// Every successful send consumes the Go per-sender 30/minute budget,
    /// including sends without a URL or with enrichment disabled.
    pub fn trigger(self: &Arc<Self>, actor: &AuthContext, sent: &str, body: &str) {
        let now = Instant::now();
        {
            let mut windows = self.admission.lock().expect("unfurl admission");
            let (start, count) = windows.entry(actor.user_id()).or_insert((now, 0));
            if now.duration_since(*start) >= Duration::from_secs(60) {
                *start = now;
                *count = 0;
            }
            if *count >= 30 {
                return;
            }
            *count += 1;
        }
        static URL: OnceLock<regex::Regex> = OnceLock::new();
        let Some(found) = URL
            .get_or_init(|| {
                regex::Regex::new(r#"https?://[^\t\n\f\r <>"']+"#).expect("URL expression")
            })
            .find(body)
        else {
            return;
        };
        let url = found
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"']);
        if !valid_fetch_url(url) {
            return;
        }
        let Some(message) = serde_json::from_str::<serde_json::Value>(sent)
            .ok()
            .and_then(|v| v["messageId"].as_i64())
            .filter(|id| *id != 0)
        else {
            return;
        };
        let (work, actor, url) = (self.clone(), actor.clone(), url.to_owned());
        tokio::spawn(async move {
            if work.exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='chat.unfurl'),false)",&[]).await.is_ok_and(|rows|rows[0].get::<_,bool>(0)) {
                work.process(&actor,message,&url).await;
            }
        });
    }
    pub async fn process(&self, actor: &AuthContext, message: i64, url: &str) {
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(url.as_bytes()));
        let Ok(cache) = members::unfurl_lookup(&self.exec, actor, &hash).await else {
            return;
        };
        if let Some(cache) = cache.filter(|cache| !cache.is_null()) {
            if cache["status"] == "ok" {
                self.apply(actor, message, &hash).await;
            }
            return;
        }
        let Some(operation) = crate::jmap::random() else {
            return;
        };
        if !matches!(
            members::unfurl_claim(&self.exec, actor, &hash, url, operation).await,
            CommandOutcome::Committed(serde_json::Value::Bool(true))
        ) {
            return;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let fetched = tokio::time::timeout_at(deadline, self.fetch_text(url))
            .await
            .ok()
            .and_then(Result::ok);
        let preview = match fetched {
            Some((title, description, image_url)) => {
                let image = if image_url.is_empty() {
                    None
                } else {
                    tokio::time::timeout_at(deadline, self.fetch_image(actor, &image_url))
                        .await
                        .ok()
                        .and_then(Result::ok)
                };
                FetchedPreview {
                    ok: true,
                    title: nonempty(title),
                    description: nonempty(description),
                    image,
                }
            }
            None => FetchedPreview {
                ok: false,
                title: None,
                description: None,
                image: None,
            },
        };
        let Some(operation) = crate::jmap::random() else {
            return;
        };
        if matches!(
            members::unfurl_write(&self.exec, actor, &hash, &preview, operation).await,
            CommandOutcome::Committed(_)
        ) && preview.ok
        {
            self.apply(actor, message, &hash).await;
        }
    }
    async fn apply(&self, actor: &AuthContext, message: i64, hash: &str) {
        if let Some(operation) = crate::jmap::random() {
            let _ = members::unfurl_apply(&self.exec, actor, message, hash, operation).await;
        }
    }
    async fn fetch_text(&self, url: &str) -> Result<(String, String, String), ()> {
        if !valid_fetch_url(url) {
            return Err(());
        }
        let response = self.follow_redirects(url).await?;
        if !response
            .headers()
            .get("content-type")
            .is_some_and(|h| h.as_bytes().starts_with(b"text/html"))
        {
            return Err(());
        }
        let html = read_response(response, 2 << 20).await?;
        use html5gum::{
            emitters::callback::{CallbackEmitter, CallbackEvent},
            Span, Tokenizer,
        };
        let mut title = String::new();
        let mut description = String::new();
        let mut image = String::new();
        let mut in_title = false;
        let (mut tag, mut property, mut name, mut content) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut attribute = 0;
        let mut seen = [false; 3];
        let mut emitter = CallbackEmitter::new(
            |event: CallbackEvent<'_>, _: Span<()>| -> Option<std::convert::Infallible> {
                match event {
                    CallbackEvent::OpenStartTag { name: tag_name } => {
                        tag = tag_name.to_vec();
                        property.clear();
                        name.clear();
                        content.clear();
                        seen.fill(false);
                        if tag == b"title" {
                            in_title = true;
                        }
                    }
                    CallbackEvent::AttributeName { name: key } => {
                        attribute = match key {
                            b"property" => 1,
                            b"name" => 2,
                            b"content" => 3,
                            _ => 0,
                        };
                        if attribute > 0 {
                            let index = attribute - 1;
                            if seen[index] {
                                attribute = 0;
                            } else {
                                seen[index] = true;
                            }
                        }
                    }
                    CallbackEvent::AttributeValue { value } => match attribute {
                        1 => property.extend_from_slice(value),
                        2 => name.extend_from_slice(value),
                        3 => content.extend_from_slice(value),
                        _ => {}
                    },
                    CallbackEvent::CloseStartTag { .. } if tag == b"meta" => {
                        let key = if property.is_empty() {
                            name.as_slice()
                        } else {
                            property.as_slice()
                        };
                        match key {
                            b"og:title" => title = crate::chat::go_utf8(&content),
                            b"og:image" | b"og:image:url" => {
                                if let Ok(value) = url::Url::parse(url)
                                    .and_then(|base| base.join(&crate::chat::go_utf8(&content)))
                                {
                                    image = value.into();
                                }
                            }
                            b"og:description" | b"description" if description.is_empty() => {
                                description = crate::chat::go_utf8(&content)
                            }
                            _ => {}
                        }
                    }
                    CallbackEvent::EndTag { name } if name == b"title" => in_title = false,
                    CallbackEvent::String { value } if in_title && title.is_empty() => {
                        title = crate::chat::go_utf8(value).trim().to_owned()
                    }
                    _ => {}
                }
                None
            },
        );
        emitter.naively_switch_states(true);
        let _ = Tokenizer::new_with_emitter(html.as_slice(), emitter).finish();
        if title.is_empty() && description.is_empty() && image.is_empty() {
            Err(())
        } else {
            Ok((title, description, image))
        }
    }
    async fn follow_redirects(&self, url: &str) -> Result<reqwest::Response, ()> {
        let mut current = url.to_owned();
        for hop in 0.. {
            if !valid_fetch_url(&current) {
                return Err(());
            }
            let response = self
                .client
                .get(&current)
                .header("user-agent", "Go-http-client/1.1")
                .header("accept-encoding", "gzip")
                .send()
                .await
                .map_err(|_| ())?;
            if !(300..400).contains(&response.status().as_u16()) {
                return Ok(response);
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .ok_or(())?
                .to_owned();
            drop(response);
            if hop >= 3 {
                return Err(());
            }
            current = url::Url::parse(&current)
                .and_then(|base| base.join(&location))
                .map_err(|_| ())?
                .into();
        }
        unreachable!()
    }
    async fn fetch_image(&self, actor: &AuthContext, url: &str) -> Result<String, ()> {
        if !valid_fetch_url(url) {
            return Err(());
        }
        let response = self.follow_redirects(url).await?;
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .ok_or(())?
            .to_owned();
        if !content_type.starts_with("image/") {
            return Err(());
        }
        let bytes = read_response(response, 5 << 20).await?;
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(&bytes));
        self.store
            .put(&hash, &bytes, &content_type)
            .await
            .map_err(|_| ())?;
        let operation = crate::jmap::random().ok_or(())?;
        match members::unfurl_blob(
            &self.exec,
            actor,
            &hash,
            &self.store.blob_reference(&hash),
            bytes.len() as i64,
            &content_type,
            operation,
        )
        .await
        {
            CommandOutcome::Committed(_) => Ok(hash),
            _ => Err(()),
        }
    }
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

// Literal destinations and URL credentials are rejected before using the safe
// client. DNS answers are checked by the production client's resolver.
fn valid_fetch_url(raw: &str) -> bool {
    // Go url.Parse validates escaped path/fragment, but retains RawQuery.
    let (resource, fragment) = raw
        .split_once('#')
        .map_or((raw, None), |(head, tail)| (head, Some(tail)));
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f)
        || !valid_escapes(resource.split('?').next().unwrap_or(resource))
        || fragment.is_some_and(|value| !valid_escapes(value))
    {
        return false;
    }
    crate::ssrf::valid_url(raw)
        && raw.split_once("://").is_some_and(|(_, rest)| {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            !authority.contains(['@', '\\'])
        })
}
fn valid_escapes(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.iter().enumerate().all(|(at, value)| {
        *value != b'%'
            || bytes
                .get(at + 1..at + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
    })
}

// Go's transport decodes gzip before the page/image LimitReader. Bound the
// decoded output while streaming, including concatenated RFC 1952 members.
async fn read_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ()> {
    use std::io::Write;
    let output = BoundedBytes {
        bytes: Vec::new(),
        limit,
    };
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"))
    {
        let mut decoder = flate2::write::MultiGzDecoder::new(output);
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            decoder.write_all(&chunk).map_err(|_| ())?;
        }
        Ok(decoder.finish().map_err(|_| ())?.bytes)
    } else {
        let mut output = output;
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            output.write_all(&chunk).map_err(|_| ())?;
        }
        Ok(output.bytes)
    }
}
struct BoundedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl std::io::Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(std::io::Error::other("unfurl response exceeds size cap"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
