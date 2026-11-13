//! The one `httputil.Problem` encoder every Rust family uses (#364, #394).
//!
//! Go writes a problem with `json.Encoder` from a struct, so the bytes have a
//! fixed key order (`type,title,status,detail,instance,invalid-params,
//! remediation,remediation_tou_id,code,retryable,holderId`), HTML-escaped
//! strings and a trailing newline. The title defaults to Go's
//! `http.StatusText`, which differs from hyper's table for 413, 414 and 416.

/// Go's `http.StatusText` (net/http/status.go, Go 1.26); empty when unknown.
pub fn title(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// Go's key order; a body whose keys are not an in-order subset is wrong.
pub const KEY_ORDER: [&str; 11] = [
    "type",
    "title",
    "status",
    "detail",
    "instance",
    "invalid-params",
    "remediation",
    "remediation_tou_id",
    "code",
    "retryable",
    "holderId",
];

/// A JSON string as `encoding/json` writes it (HTML escapes included).
pub fn go_string(value: &str) -> String {
    serde_json::to_string(value)
        .expect("string JSON")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Frozen JMAP's ProblemDetails projection. Its struct omits an empty detail
/// and carries no title or instance. The caller adds the transport newline.
pub fn jmap(status: u16, kind: &str, detail: &str) -> String {
    let mut body = format!(
        "{{\"type\":{},\"status\":{status}",
        go_string(&format!("urn:ietf:params:jmap:error:{kind}"))
    );
    if !detail.is_empty() {
        body.push_str(&format!(",\"detail\":{}", go_string(detail)));
    }
    body.push('}');
    body
}

/// The `httputil.Problem` fields a Rust route sets; omitted fields are
/// dropped exactly like Go's `omitempty`.
pub struct Problem<'a> {
    pub kind: &'a str,
    pub status: u16,
    /// `None` means `http.StatusText(status)`.
    pub title: Option<&'a str>,
    pub detail: &'a str,
    pub instance: &'a str,
    pub remediation: Option<&'a str>,
    pub code: Option<&'a str>,
    pub retryable: Option<bool>,
    pub holder_id: Option<i64>,
}

impl<'a> Problem<'a> {
    pub fn new(status: u16, detail: &'a str) -> Self {
        Self {
            kind: "about:blank",
            status,
            title: None,
            detail,
            instance: "",
            remediation: None,
            code: None,
            retryable: None,
            holder_id: None,
        }
    }
    pub fn kind(mut self, kind: &'a str) -> Self {
        self.kind = kind;
        self
    }
    pub fn instance(mut self, instance: &'a str) -> Self {
        self.instance = instance;
        self
    }
    pub fn title(mut self, title: &'a str) -> Self {
        self.title = Some(title);
        self
    }
    pub fn remediation(mut self, remediation: &'a str) -> Self {
        self.remediation = Some(remediation).filter(|s| !s.is_empty());
        self
    }
    pub fn code(mut self, code: &'a str) -> Self {
        self.code = Some(code).filter(|s| !s.is_empty());
        self
    }
    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = Some(retryable);
        self
    }
    pub fn holder_id(mut self, holder: i64) -> Self {
        self.holder_id = Some(holder).filter(|n| *n != 0);
        self
    }
    /// The response body: Go's key order, HTML escapes, trailing newline.
    pub fn body(&self) -> String {
        let mut out = format!(
            "{{\"type\":{},\"title\":{},\"status\":{},\"detail\":{},\"instance\":{}",
            go_string(self.kind),
            go_string(self.title.unwrap_or_else(|| title(self.status))),
            self.status,
            go_string(self.detail),
            go_string(self.instance),
        );
        if let Some(text) = self.remediation {
            out += &format!(",\"remediation\":{}", go_string(text));
        }
        if let Some(code) = self.code {
            out += &format!(",\"code\":{}", go_string(code));
        }
        if let Some(retryable) = self.retryable {
            out += &format!(",\"retryable\":{retryable}");
        }
        if let Some(holder) = self.holder_id {
            out += &format!(",\"holderId\":{holder}");
        }
        out + "}\n"
    }
}

/// Replace a response's body (keeps the status and headers it carries).
pub fn set_body(response: &mut hyper::Response<crate::Body>, text: String) {
    use http_body_util::BodyExt;
    *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(text))
        .map_err(|never| match never {})
        .boxed();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_follow_go_status_text_not_hyper() {
        assert_eq!(title(413), "Request Entity Too Large");
        assert_eq!(title(414), "Request URI Too Long");
        assert_eq!(title(416), "Requested Range Not Satisfiable");
        assert_eq!(title(422), "Unprocessable Entity");
        assert_eq!(title(507), "Insufficient Storage");
        assert_eq!(title(599), "");
        for code in 100..=599u16 {
            let hyper = hyper::StatusCode::from_u16(code)
                .ok()
                .and_then(|s| s.canonical_reason());
            if let (Some(h), "") = (hyper, title(code)) {
                // Go simply has no text for these (e.g. 306, 509).
                assert!(matches!(code, 306 | 509), "Go lacks {code} ({h})");
            }
        }
    }

    #[test]
    fn a_413_problem_carries_the_go_title_in_go_key_order() {
        let body = Problem::new(413, "too big").instance("/x").body();
        assert_eq!(
            body,
            "{\"type\":\"about:blank\",\"title\":\"Request Entity Too Large\",\"status\":413,\"detail\":\"too big\",\"instance\":\"/x\"}\n"
        );
    }

    #[test]
    fn full_problem_keeps_go_order_and_escapes_html() {
        let body = Problem::new(409, "a<b&c")
            .kind("https://setjoin.com/problems/reducer/bz192")
            .instance("/p")
            .remediation("retry")
            .code("BZ192")
            .retryable(false)
            .holder_id(7)
            .body();
        assert_eq!(
            body,
            "{\"type\":\"https://setjoin.com/problems/reducer/bz192\",\"title\":\"Conflict\",\"status\":409,\"detail\":\"a\\u003cb\\u0026c\",\"instance\":\"/p\",\"remediation\":\"retry\",\"code\":\"BZ192\",\"retryable\":false,\"holderId\":7}\n"
        );
    }
}

/// shared/middleware.denyJSON uses a sorted map, unlike httputil.Problem.
/// Preserve that distinct frozen wire contract for credential-route CSRF.
pub fn middleware(status: u16, title: &str, detail: &str) -> String {
    format!(
        "{{\"detail\":{},\"status\":{status},\"title\":{},\"type\":\"about:blank\"}}\n",
        go_string(detail),
        go_string(title)
    )
}

/// `shared/middleware.denyJSONRemediation` is a sorted map, and always carries
/// remediation (including the empty string). It is distinct from Problem.
pub fn runtime_block(detail:&str,remediation:&str,terms_id:i64)->String{
    let mut body=format!("{{\"detail\":{},\"remediation\":{}",go_string(detail),go_string(remediation));
    if terms_id!=0{body+=&format!(",\"remediation_tou_id\":{terms_id}");}
    body+",\"status\":403,\"title\":\"access_blocked\",\"type\":\"about:blank\"}\n"
}

pub fn runtime_binding()->String{
    format!("{{\"code\":\"dpop_admission\",\"detail\":{},\"status\":401,\"title\":\"token_binding_failed\",\"type\":\"about:blank\"}}\n",go_string("Token binding verification failed."))
}
