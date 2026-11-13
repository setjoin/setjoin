//! What one mark-read reply means to the client, and response parity.
//!
//! The webmail treats a `200` whose `Email/set` lists the id in `updated` as
//! success; everything else is a failure of some kind. An unknown commit
//! outcome (Rust's `serverFail` naming an operation to look up) is its own
//! class: it is neither success nor a known failure.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `200`, the id is in `updated`.
    Updated,
    /// `200`, the id is in `notUpdated` (e.g. notFound).
    NotUpdated,
    /// `200` with a JMAP `serverFail` that names an operation to look up.
    Unknown,
    /// `200` with any other method-level error.
    MethodError,
    /// A non-200 HTTP status.
    Http(u16),
    /// No HTTP reply at all (connect refused, reset, timeout).
    Transport,
}

impl Outcome {
    pub fn classify(status: u16, body: &str, message: i64) -> Outcome {
        if status != 200 {
            return Outcome::Http(status);
        }
        if body.contains("commit outcome unknown") {
            return Outcome::Unknown;
        }
        if body.contains(&format!("\"updated\":[{message}]")) {
            return Outcome::Updated;
        }
        if body.contains(&format!("\"notUpdated\":{{\"{message}\"")) {
            return Outcome::NotUpdated;
        }
        Outcome::MethodError
    }

    pub fn is_success(self) -> bool {
        self == Outcome::Updated
    }

    /// Stable label for CSV/JSON.
    pub fn label(self) -> String {
        match self {
            Outcome::Updated => "updated".into(),
            Outcome::NotUpdated => "not_updated".into(),
            Outcome::Unknown => "unknown".into(),
            Outcome::MethodError => "method_error".into(),
            Outcome::Http(s) => format!("http_{s}"),
            Outcome::Transport => "transport".into(),
        }
    }

    pub fn parse(label: &str) -> Option<Outcome> {
        Some(match label {
            "updated" => Outcome::Updated,
            "not_updated" => Outcome::NotUpdated,
            "unknown" => Outcome::Unknown,
            "method_error" => Outcome::MethodError,
            "transport" => Outcome::Transport,
            other => Outcome::Http(other.strip_prefix("http_")?.parse().ok()?),
        })
    }
}

/// A reply with the message id and every state string replaced, so two
/// replies for equivalent messages at different states compare equal
/// exactly when their structure and every other byte agree.
pub fn normalize(body: &str, message: i64) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    // sessionState/oldState/newState: replace each "...State":"<v>" value with S.
    while let Some(i) = rest.find("State\":\"") {
        let (head, tail) = rest.split_at(i + "State\":\"".len());
        out.push_str(head);
        let end = tail.find('"').unwrap_or(tail.len());
        out.push('S');
        rest = &tail[end..];
    }
    out.push_str(rest);
    replace_number(&out, message, "ID")
}

/// Replaces `n` where it stands as a whole number (not inside a longer one).
fn replace_number(s: &str, n: i64, with: &str) -> String {
    let needle = n.to_string();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(&needle)
            && (i == 0 || !b[i - 1].is_ascii_digit())
            && b.get(i + needle.len()).is_none_or(|c| !c.is_ascii_digit())
        {
            out.push_str(with);
            i += needle.len();
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Literal replies captured on the #215 real stack (Go and Rust).
    const GO: &str = "{\"sessionState\":\"9-0-0-5-0-0-0-1793288169\",\"methodResponses\":[[\"Email/set\",{\"accountId\":\"16\",\"newState\":\"10\",\"notUpdated\":{},\"oldState\":\"9\",\"updated\":[29]},\"0\"]]}\n";
    const RS: &str = "{\"sessionState\":\"10-0-0-5-0-0-0-1793288169\",\"methodResponses\":[[\"Email/set\",{\"accountId\":\"16\",\"newState\":\"11\",\"notUpdated\":{},\"oldState\":\"10\",\"updated\":[30]},\"0\"]]}\n";

    #[test]
    fn classifies_the_replies_a_client_can_see() {
        assert_eq!(Outcome::classify(200, GO, 29), Outcome::Updated);
        assert_eq!(Outcome::classify(200, GO, 30), Outcome::MethodError);
        let nf = r#"{"methodResponses":[["Email/set",{"notUpdated":{"7":{"type":"notFound"}},"updated":[]},"0"]]}"#;
        assert_eq!(Outcome::classify(200, nf, 7), Outcome::NotUpdated);
        let unk = r#"{"methodResponses":[["error",{"type":"urn:ietf:params:jmap:error:serverFail","status":500,"detail":"commit outcome unknown; look up operation ab"},"0"]]}"#;
        assert_eq!(Outcome::classify(200, unk, 7), Outcome::Unknown);
        assert_eq!(Outcome::classify(502, "", 7), Outcome::Http(502));
        assert!(Outcome::Updated.is_success() && !Outcome::Unknown.is_success());
    }

    #[test]
    fn labels_round_trip() {
        for o in [
            Outcome::Updated,
            Outcome::NotUpdated,
            Outcome::Unknown,
            Outcome::MethodError,
            Outcome::Http(503),
            Outcome::Transport,
        ] {
            assert_eq!(Outcome::parse(&o.label()), Some(o));
        }
        assert_eq!(Outcome::parse("http_x"), None);
    }

    #[test]
    fn go_and_rust_replies_for_equivalent_messages_normalise_equal() {
        assert_eq!(normalize(GO, 29), normalize(RS, 30));
        assert_eq!(
            normalize(GO, 29),
            "{\"sessionState\":\"S\",\"methodResponses\":[[\"Email/set\",{\"accountId\":\"16\",\"newState\":\"S\",\"notUpdated\":{},\"oldState\":\"S\",\"updated\":[ID]},\"0\"]]}\n"
        );
    }

    #[test]
    fn normalisation_still_sees_a_different_byte() {
        let other_account = RS.replace("\"16\"", "\"17\"");
        assert_ne!(normalize(GO, 29), normalize(&other_account, 30));
        // 29 inside 290 is not the id.
        assert_eq!(replace_number("[29,290]", 29, "ID"), "[ID,290]");
    }
}
