//! Token-bearing guest delivery. Credentials live only in memory and MIME storage.
use crate::recovery_worker::ObjectStore;
use setjoin_authz::AuthContext;
use setjoin_guests::Prepared;
use setjoin_pg::ScopedExecutor;

pub fn credential() -> Option<(String, String)> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).ok()?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    Some((
        token.clone(),
        format!("{:x}", Sha256::digest(token.as_bytes())),
    ))
}
pub async fn send(
    exec: &ScopedExecutor,
    store: Option<&dyn ObjectStore>,
    actor: &AuthContext,
    invite: &Prepared,
    token: &str,
) -> bool {
    let Some(store) = store else { return false };
    let Ok(addresses) = mailparse::addrparse(&invite.email) else {
        return false;
    };
    if addresses.len() != 1 {
        return false;
    }
    let Some((_, domain)) = invite.from.rsplit_once('@') else {
        return false;
    };
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(n) => n.as_nanos() as u64,
        Err(_) => return false,
    };
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut previous = LAST.load(std::sync::atomic::Ordering::Relaxed);
    let nanos = loop {
        let Some(next) = previous.checked_add(1).map(|next| next.max(nanos)) else {
            return false;
        };
        match LAST.compare_exchange_weak(
            previous,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => break next,
            Err(actual) => previous = actual,
        }
    };
    let message = format!("<invite/{nanos}@{domain}>");
    let normalize = |s: &str| {
        s.replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', " ")
    };
    let name = normalize(&invite.org);
    let name = if name.is_ascii() {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        qencode(&name)
    };
    let subject = qencode(&normalize(&format!(
        "You've been invited to {}",
        invite.org
    )));
    let accept = format!(
        "{}/guest-invite/accept?token={token}",
        invite.base.trim_end_matches('/')
    );
    let text=format!("You've been invited to join {} as an external guest.\n\nClick the link below to set your password and activate your account:\n{accept}\n\nThis link expires in {} day(s).\n\nIf you did not expect this invitation, you may ignore this email.\n",invite.org,invite.ttl);
    let body = quoted_printable(
        &(text
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', "\r\n")
            + "\r\n"),
    );
    let mime=format!("From: {name} <{}>\r\nTo: <{}>\r\nSubject: {subject}\r\nMessage-ID: {message}\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{body}",invite.from,invite.email,chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000"));
    use sha2::{Digest, Sha256};
    let key = format!(
        "invite/{}.eml",
        format!("{:x}", Sha256::digest(mime.as_bytes()))
    );
    let stored = put_retrying(store, &key, mime.as_bytes(), "message/rfc822").await;
    if !stored {
        return false;
    }
    let Some(operation) = crate::jmap::random() else {
        return false;
    };
    matches!(
        setjoin_guests::enqueue(
            exec,
            actor,
            &message,
            &invite.from,
            &invite.email,
            &key,
            operation
        )
        .await,
        setjoin_pg::CommandOutcome::Committed(())
    )
}
/// Frozen MinIO's `PutObject` retry (ten attempts, transient HTTP statuses
/// only, jittered backoff). Shared by every system mail that stores a message
/// object before queueing it (guest invites, #408's guest digest).
pub(crate) async fn put_retrying(
    store: &dyn ObjectStore,
    key: &str,
    bytes: &[u8],
    content_type: &str,
) -> bool {
    for attempt in 0..10 {
        match store.put(key, bytes, content_type).await {
            Ok(()) => return true,
            Err(error) => {
                let transient = [
                    "HTTP 408", "HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504",
                ]
                .iter()
                .any(|code| error.contains(code));
                if !transient {
                    return false;
                }
                // Frozen MinIO's MaxJitter timer sleeps after every failed
                // attempt, including the final one: uniform [0, min(1s,200ms*2^n)].
                let bound = (200_000_000u64 << attempt.min(9)).min(1_000_000_000);
                let mut random = [0; 8];
                let _ = getrandom::getrandom(&mut random);
                let fraction = u64::from_ne_bytes(random) >> 11;
                let delay = bound - ((u128::from(fraction) * u128::from(bound)) >> 53) as u64;
                tokio::time::sleep(std::time::Duration::from_nanos(delay)).await;
            }
        }
    }
    false
}
pub(crate) fn qencode(value: &str) -> String {
    if value.bytes().all(|b| (32..127).contains(&b)) {
        return value.to_owned();
    }
    let mut out = String::from("=?utf-8?q?");
    for b in value.bytes() {
        match b {
            b' ' => out.push('_'),
            33..=126 if !matches!(b, b'=' | b'?' | b'_') => out.push(b as char),
            _ => out.push_str(&format!("={b:02X}")),
        }
    }
    out.push_str("?=");
    out
}
pub(crate) fn quoted_printable(text: &str) -> String {
    let mut out = String::new();
    let mut column = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            out.push_str("\r\n");
            column = 0;
            i += 2;
            continue;
        }
        let trailing =
            matches!(b, b' ' | b'\t') && matches!(bytes.get(i + 1), None | Some(b'\r' | b'\n'));
        let piece =
            if ((33..=126).contains(&b) && b != b'=') || (matches!(b, b' ' | b'\t') && !trailing) {
                (b as char).to_string()
            } else {
                format!("={b:02X}")
            };
        if column + piece.len() > 75 {
            out.push_str("=\r\n");
            column = 0
        }
        out.push_str(&piece);
        column += piece.len();
        i += 1;
    }
    out
}
pub fn expiry(value: &str) -> Option<String> {
    let t = chrono::DateTime::parse_from_rfc3339(value)
        .ok()?
        .with_timezone(&chrono::Utc);
    let mut out = t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    out.pop();
    while out.ends_with('0') {
        out.pop();
    }
    if out.ends_with('.') {
        out.pop();
    }
    out.push('Z');
    Some(out)
}
