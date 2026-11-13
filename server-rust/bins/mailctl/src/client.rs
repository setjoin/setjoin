use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, io::Read};

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Config {
    #[serde(deserialize_with = "null_as_zero")]
    pub server: String,
    #[serde(deserialize_with = "null_as_zero")]
    pub auth: Auth,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Auth {
    #[serde(deserialize_with = "null_as_zero")]
    pub token: String,
    #[serde(deserialize_with = "null_as_zero")]
    pub api_key: String,
    #[serde(deserialize_with = "null_as_zero")]
    pub mode: String,
    #[serde(deserialize_with = "null_as_zero")]
    pub refresh_token: String,
}

/// Go's yaml.v3 leaves a field at its zero value for a YAML null (`~`,
/// `null`, or nothing after the colon).
fn null_as_zero<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub code: i32,
    pub status: u16,
    pub problem_code: String,
    pub problem_type: String,
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            code: 1,
            status: 0,
            problem_code: String::new(),
            problem_type: String::new(),
        }
    }
}
impl From<&str> for Failure {
    fn from(s: &str) -> Self {
        s.to_owned().into()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl Failure {
    pub fn exit(mut self, code: i32) -> Self {
        self.code = code;
        self
    }
}

pub struct Api {
    server: String,
    token: String,
    http: Client,
}

impl Api {
    pub(super) fn override_server(mut self, server: &str) -> Self {
        if !server.is_empty() {
            self.server = server.to_owned();
        }
        self
    }
    pub fn at_server(server: &str) -> Result<Self, String> {
        Ok(Self {
            server: server.into(),
            token: String::new(),
            http: Client::builder().build().map_err(|e| e.to_string())?,
        })
    }
    pub fn load() -> Result<Self, String> {
        let path = account_home().join(".mailctl/config.yaml");
        let cfg: Config = match std::fs::read(&path) {
            Ok(data) => parse_config(&data).map_err(|e| {
                format!(
                    "Config error: parse {}: {e}\nRun 'mailctl login <server>' first.",
                    path.display()
                )
            })?,
            Err(_) => Config::default(),
        };
        let server = nonempty("MAILCTL_SERVER").unwrap_or(cfg.server);
        let token = nonempty("MAILCTL_TOKEN")
            .or_else(|| nonempty("MAILCTL_API_KEY"))
            .unwrap_or(if cfg.auth.token.is_empty() {
                cfg.auth.api_key
            } else {
                cfg.auth.token
            });
        Ok(Self {
            server,
            token,
            http: Client::builder().build().map_err(|e| e.to_string())?,
        })
    }

    pub fn stream_get(&self, path: &str) -> Result<reqwest::blocking::Response, Failure> {
        let mut req = self.http.get(format!("{}{}", self.server, api_path(path)));
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        checked_response(req.send().map_err(|e| format!("http: {e}"))?)
    }
    pub fn raw_json(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        decode: bool,
    ) -> Result<Value, Failure> {
        let mut req = self
            .http
            .request(
                method.parse().unwrap(),
                format!("{}{}", self.server, api_path(path)),
            )
            .header("Content-Type", "application/json")
            .body(body);
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        decode_response(req.send().map_err(|e| format!("http: {e}"))?, decode, 0)
    }
    pub fn bytes(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
        headers: &[(&str, String)],
        limit: u64,
    ) -> Result<(Vec<u8>, reqwest::header::HeaderMap), Failure> {
        let mut req = self.http.request(
            method.parse().unwrap(),
            format!("{}{}", self.server, api_path(path)),
        );
        if let Some(t) = content_type {
            req = req.header("Content-Type", t);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        if !self.token.is_empty() {
            req = req.bearer_auth(&self.token);
        }
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let response = checked_response(req.send().map_err(|e| format!("http: {e}"))?)?;
        let headers = response.headers().clone();
        let mut data = Vec::new();
        response
            .take(if limit > 0 { limit + 1 } else { u64::MAX })
            .read_to_end(&mut data)
            .map_err(|e| format!("read response: {e}"))?;
        if limit > 0 && data.len() as u64 > limit {
            return Err(format!("response exceeded the {limit}-byte client limit").into());
        }
        Ok((data, headers))
    }
    pub fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        decode: bool,
    ) -> Result<Value, String> {
        self.request(method, path, body, decode)
            .map_err(|e| e.message)
    }
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        decode: bool,
    ) -> Result<Value, Failure> {
        self.with_headers(method, path, body, decode, &[], 0)
    }
    pub fn with_headers(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        decode: bool,
        headers: &[(&str, String)],
        limit: u64,
    ) -> Result<Value, Failure> {
        let path = api_path(path);
        let url = format!("{}{path}", self.server);
        let verb = format!("{}{}", &method[..1], method[1..].to_ascii_lowercase());
        if !url.starts_with("http://") && !url.starts_with("https://") {
            let scheme = url.split_once(':').map(|(s, _)| s).unwrap_or("");
            return Err(
                format!("http: {verb} {url:?}: unsupported protocol scheme {scheme:?}").into(),
            );
        }
        let mut request = self
            .http
            .request(method.parse().unwrap(), format!("{}{path}", self.server))
            .header("Content-Type", "application/json");
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        for (k, v) in headers {
            request = request.header(*k, v);
        }
        if let Some(body) = body {
            request = request.body(go_json(&body, false));
        }
        let response = request.send().map_err(|e| format!("http: {e}"))?;
        decode_response(response, decode, limit)
    }
}
fn nonempty(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn go_json(v: &Value, pretty: bool) -> String {
    encode_json(v, pretty, false)
}
pub fn go_json_generic(v: &Value, pretty: bool) -> String {
    encode_json(v, pretty, true)
}
fn encode_json(v: &Value, pretty: bool, generic: bool) -> String {
    let value = GoJson { value: v, generic };
    let s = if pretty {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    }
    .unwrap();
    s.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
struct GoJson<'a> {
    value: &'a Value,
    generic: bool,
}
impl Serialize for GoJson<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.value {
            Value::Null => s.serialize_none(),
            Value::Bool(v) => s.serialize_bool(*v),
            Value::String(v) => s.serialize_str(v),
            Value::Array(values) => {
                let mut seq = s.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&GoJson {
                        value,
                        generic: self.generic,
                    })?;
                }
                seq.end()
            }
            Value::Object(values) => {
                let mut map = s.serialize_map(Some(values.len()))?;
                for (k, value) in values {
                    map.serialize_entry(
                        k,
                        &GoJson {
                            value,
                            generic: self.generic,
                        },
                    )?;
                }
                map.end()
            }
            Value::Number(n) => {
                if !self.generic {
                    if let Some(n) = n.as_i64() {
                        return s.serialize_i64(n);
                    }
                    if let Some(n) = n.as_u64() {
                        return s.serialize_u64(n);
                    }
                }
                let f = n.as_f64().unwrap();
                let number = if f != 0.0 && (f.abs() < 1e-6 || f.abs() >= 1e21) {
                    let raw = format!("{f:e}");
                    let (m, e) = raw.split_once('e').unwrap();
                    let e = e.parse::<i32>().unwrap();
                    format!("{m}e{}{e}", if e >= 0 { "+" } else { "" })
                } else {
                    f.to_string()
                };
                serde_json::value::RawValue::from_string(number)
                    .unwrap()
                    .serialize(s)
            }
        }
    }
}

pub fn go_value(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".to_owned(),
        Value::String(s) => s.clone(),
        Value::Array(a) => format!("[{}]", a.iter().map(go_value).collect::<Vec<_>>().join(" ")),
        Value::Object(o) => format!(
            "map[{}]",
            o.iter()
                .map(|(k, v)| format!("{k}:{}", go_value(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::Number(n) => {
            let n = n.as_f64().unwrap();
            if n != 0.0 && (n.abs() >= 1e6 || n.abs() < 1e-4) {
                let scientific = format!("{n:e}");
                let (mantissa, exponent) = scientific.split_once('e').unwrap();
                format!("{mantissa}e{:+03}", exponent.parse::<i32>().unwrap())
            } else {
                n.to_string()
            }
        }
        _ => v.to_string(),
    }
}

// Frozen cross-builds use os/user's pure-Go Unix lookup: passwd before HOME.
/// Decodes `~/.mailctl/config.yaml` (the shape Go's `mailctl` writes).
pub(super) fn parse_config(raw: &[u8]) -> Result<Config, String> {
    serde_saphyr::from_slice(raw).map_err(|e| e.to_string())
}

pub(super) fn account_home() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(metadata), Ok(passwd)) = (
            std::fs::metadata("/proc/self"),
            std::fs::read_to_string("/etc/passwd"),
        ) {
            for line in passwd.lines() {
                let fields: Vec<_> = line.split(':').collect();
                if fields.len() >= 6 && fields[2].parse::<u32>().ok() == Some(metadata.uid()) {
                    return fields[5].into();
                }
            }
        }
    }
    env::var_os("HOME").unwrap_or_default().into()
}

fn api_path(path: &str) -> String {
    const PINNED: &[&str] = &[
        "/auth",
        "/jmap",
        "/.well-known",
        "/caldav",
        "/carddav",
        "/scim",
        "/rtc",
        "/setup",
        "/approvals/email",
        "/link-protect",
        "/admin/migration/m365",
        "/updates",
        "/downloads",
        "/health",
        "/ready",
        "/metrics",
        "/api",
        "/terms",
        "/favicon.ico",
    ];
    let path_only = path.split('?').next().unwrap();
    if PINNED
        .iter()
        .any(|p| path_only == *p || path_only.starts_with(&format!("{p}/")))
    {
        path.to_owned()
    } else {
        format!("/api{path}")
    }
}

fn checked_response(
    response: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response, Failure> {
    if response.status().as_u16() >= 400 {
        let status = response.status();
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut bytes = Vec::new();
        response
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("HTTP {}: read problem response: {e}", status.as_u16()))?;
        let mut code = String::new();
        let mut problem_type = String::new();
        let detail;
        let mut remediation = String::new();
        let mut retry = retry;
        if bytes.len() > 1_048_576 {
            detail = "problem response exceeded the 1 MiB client limit".to_owned();
            retry.clear();
        } else if let Ok(value) = serde_json::from_slice::<Option<Problem>>(&bytes) {
            let value = value.unwrap_or_default();
            code = value.code;
            problem_type = value.problem_type;
            detail = if value.detail.is_empty() {
                status.canonical_reason().unwrap_or("").to_owned()
            } else {
                one_line(&value.detail)
            };
            remediation = one_line(&value.remediation);
            if retry.is_empty() {
                retry = value.retry_after;
            }
        } else {
            let d = one_line(&String::from_utf8_lossy(&bytes));
            detail = if d.is_empty() {
                status.canonical_reason().unwrap_or("").to_owned()
            } else {
                d
            };
        }
        let mut error = format!("HTTP {}", status.as_u16());
        if !code.is_empty() {
            error.push_str(&format!(" {code}"));
        }
        if !detail.is_empty() {
            error.push_str(&format!(": {detail}"));
        }
        if !remediation.is_empty() {
            error.push_str(&format!(" (remediation: {remediation})"));
        }
        if !retry.is_empty() {
            error.push_str(&format!(" (retry after: {})", one_line(&retry)));
        }
        return Err(Failure {
            message: error,
            code: 1,
            status: status.as_u16(),
            problem_code: code,
            problem_type,
        });
    }
    Ok(response)
}

fn decode_response(
    response: reqwest::blocking::Response,
    decode: bool,
    limit: u64,
) -> Result<Value, Failure> {
    let response = checked_response(response)?;
    if !decode {
        return Ok(Value::Null);
    }
    let mut bytes = Vec::new();
    response
        .take(if limit > 0 { limit + 1 } else { u64::MAX })
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if limit > 0 && bytes.len() as u64 > limit {
        return Err(format!("response exceeded the {limit}-byte client limit").into());
    }
    let data = String::from_utf8_lossy(&bytes);
    if limit > 0 {
        return serde_json::from_str(&data).map_err(|e| json_error(&data, &e, false).into());
    }
    let mut stream = serde_json::Deserializer::from_str(&data).into_iter::<Value>();
    stream
        .next()
        .unwrap_or_else(|| Err(serde_json::from_str::<Value>("").unwrap_err()))
        .map_err(|e| json_error(&data, &e, true).into())
}

pub(super) fn json_error(raw: &str, error: &serde_json::Error, decoder: bool) -> String {
    if error.is_eof() {
        return if decoder {
            if raw.trim().is_empty() {
                "EOF"
            } else {
                "unexpected EOF"
            }
        } else {
            "unexpected end of JSON input"
        }
        .into();
    }
    if !error.is_syntax() {
        return error.to_string();
    }
    let prefix = raw
        .split_inclusive('\n')
        .take(error.line().saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let index = (prefix + error.column().saturating_sub(1)).min(raw.len().saturating_sub(1));
    let byte = raw.as_bytes().get(index).copied().unwrap_or(b'?');
    let quoted = format!("{:?}", byte as char);
    let msg = error.to_string();
    let context = if msg.starts_with("key must be a string") {
        "looking for beginning of object key string"
    } else if msg.starts_with("expected `:`") {
        "after object key"
    } else if msg.starts_with("expected `,` or `}`") {
        "after object key:value pair"
    } else if msg.starts_with("expected `,` or `]`") {
        "after array element"
    } else if msg.starts_with("trailing characters") {
        "after top-level value"
    } else if msg.starts_with("invalid escape") {
        "in string escape code"
    } else if msg.starts_with("control character") {
        "in string literal"
    } else if msg.starts_with("expected ident") {
        let bytes = raw.as_bytes();
        let mut start = index;
        while start > 0 && bytes[start - 1].is_ascii_alphabetic() {
            start -= 1;
        }
        let literal = match bytes.get(start) {
            Some(b't') => "true",
            Some(b'f') => "false",
            Some(b'n') => "null",
            _ => return format!("invalid character {quoted} looking for beginning of value"),
        };
        let expected = literal
            .as_bytes()
            .get(index - start)
            .copied()
            .unwrap_or(b'?') as char;
        return format!("invalid character {quoted} in literal {literal} (expecting {expected:?})");
    } else if msg.starts_with("expected value") {
        "looking for beginning of value"
    } else {
        return error.to_string();
    };
    format!("invalid character {quoted} {context}")
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Problem {
    #[serde(rename = "type", deserialize_with = "crate::models::null_default")]
    problem_type: String,
    #[serde(deserialize_with = "crate::models::null_default")]
    code: String,
    #[serde(deserialize_with = "crate::models::null_default")]
    detail: String,
    #[serde(rename = "instance", deserialize_with = "crate::models::null_default")]
    _instance: String,
    #[serde(rename = "retryable")]
    _retryable: Option<bool>,
    #[serde(deserialize_with = "crate::models::null_default")]
    remediation: String,
    #[serde(deserialize_with = "crate::models::null_default")]
    retry_after: String,
}

#[cfg(test)]
mod tests {
    use super::parse_config;

    /// `(server, token, api_key, mode, refresh_token)`, or `None` = parse error.
    fn parsed(raw: &str) -> Option<[String; 5]> {
        parse_config(raw.as_bytes()).ok().map(|c| {
            [
                c.server,
                c.auth.token,
                c.auth.api_key,
                c.auth.mode,
                c.auth.refresh_token,
            ]
        })
    }

    /// Every document decodes as frozen Go's `yaml.v3` decodes it into
    /// `mailctl.Config` (recorded with `gopkg.in/yaml.v3` v3.0.1 in the CI
    /// image, #388): same fields, or a parse error where Go has one. Error
    /// text is not compared (`Config error: parse <path>: <text>`; no oracle
    /// records it and every decoder words it differently).
    #[test]
    fn config_documents_decode_as_go_decodes_them() {
        #[rustfmt::skip]
        let cases: &[(&str, Option<[&str; 5]>)] = &[
            ("server: https://a.test\nauth:\n  token: cfg-token\n  api_key: cfg-key\n", Some(["https://a.test", "cfg-token", "cfg-key", "", ""])),
            ("server: \"https://a.test\"\nauth: { token: cfg-token }\n", Some(["https://a.test", "cfg-token", "", "", ""])),
            ("server: https://example.test\nauth:\n    mode: jwt\n    api_key: retained-key\n    token: old-access\n    refresh_token: old-refresh\n", Some(["https://example.test", "old-access", "retained-key", "jwt", "old-refresh"])),
            ("server: s\nextra: 1\nauth:\n  other: 2\n  token: t\n", Some(["s", "t", "", "", ""])),
            ("", Some(["", "", "", "", ""])),
            ("\n", Some(["", "", "", "", ""])),
            ("# only a comment\n", Some(["", "", "", "", ""])),
            ("---\n", Some(["", "", "", "", ""])),
            ("~\n", Some(["", "", "", "", ""])),
            ("null\n", Some(["", "", "", "", ""])),
            ("# c\nserver: s # trailing\n", Some(["s", "", "", "", ""])),
            ("server: \"a\\\tb\\u00e9\"\n", Some(["a\tb\u{e9}", "", "", "", ""])),
            ("server: 'it''s'\n", Some(["it's", "", "", "", ""])),
            ("server: 8080\n", Some(["8080", "", "", "", ""])),
            ("server: 1.5\n", Some(["1.5", "", "", "", ""])),
            ("server: 0x1F\n", Some(["0x1F", "", "", "", ""])),
            ("server: 1e3\n", Some(["1e3", "", "", "", ""])),
            ("auth: {token: true}\n", Some(["", "true", "", "", ""])),
            ("server: yes\n", Some(["yes", "", "", "", ""])),
            ("server: ~\n", Some(["", "", "", "", ""])),
            ("server: null\n", Some(["", "", "", "", ""])),
            ("server:\n", Some(["", "", "", "", ""])),
            ("server: !!str 1\n", Some(["1", "", "", "", ""])),
            ("server: !custom x\n", Some(["x", "", "", "", ""])),
            ("a: &x tok\nserver: *x\n", Some(["tok", "", "", "", ""])),
            ("server: |\n  line1\n  line2\n", Some(["line1\nline2\n", "", "", "", ""])),
            ("server: >\n  folded\n  text\n", Some(["folded text\n", "", "", "", ""])),
            ("server: [unclosed\n", None),
            ("- list\n", None),
            ("auth: str\n", None),
            ("server: [a, b]\n", None),
            ("server: {a: b}\n", None),
            ("server: a\nserver: b\n", None),
            ("server: a\n---\nserver: b\n", Some(["a", "", "", "", ""])),
            ("\u{feff}server: bom\n", Some(["bom", "", "", "", ""])),
            ("server:\ta\n", Some(["a", "", "", "", ""])),
            ("\tserver: a\n", None),
            ("server: a:b\n", Some(["a:b", "", "", "", ""])),
            ("server: http://h:1/p?q#f\n", Some(["http://h:1/p?q#f", "", "", "", ""])),
            ("server: \"\"\n", Some(["", "", "", "", ""])),
            ("auth:\n  token:\n", Some(["", "", "", "", ""])),
            ("auth: ~\n", Some(["", "", "", "", ""])),
            ("auth: {}\n", Some(["", "", "", "", ""])),
            ("{server: flow, auth: {api_key: k}}\n", Some(["flow", "", "k", "", ""])),
            ("server: -1\n", Some(["-1", "", "", "", ""])),
            ("server: .inf\n", Some([".inf", "", "", "", ""])),
            ("server: 0o17\n", Some(["0o17", "", "", "", ""])),
            ("server: 012\n", Some(["012", "", "", "", ""])),
            ("server: True\n", Some(["True", "", "", "", ""])),
            ("server: \"x\" trailing\n", None),
            ("server: a\n  b\n", Some(["a b", "", "", "", ""])),
            ("? server\n: complex\n", Some(["complex", "", "", "", ""])),
            ("%YAML 1.2\n---\nserver: directive\n", None),
            ("server: a\n...\n", Some(["a", "", "", "", ""])),
            ("server: 99999999999999999999999\n", Some(["99999999999999999999999", "", "", "", ""])),
            ("auth:\n", Some(["", "", "", "", ""])),
            ("server: a\nauth:\n", Some(["a", "", "", "", ""])),
            ("server: \"~\"\n", Some(["~", "", "", "", ""])),
            ("auth:\n  token: ~\n  api_key: null\n  mode: jwt\n", Some(["", "", "", "jwt", ""])),
        ];
        // Where serde-saphyr is not Go, pinned to what Rust does. The file is
        // what `mailctl login` writes (four-space indent, one document); the
        // `serde_yaml` decoder this replaced also diverged on cases 1 and 3.
        #[rustfmt::skip]
        let rust_differs: &[(&str, Option<[&str; 5]>)] = &[
            // Go decodes only the first document; serde-saphyr refuses several.
            ("server: a\n---\nserver: b\n", None),
            // Go refuses a tab before a block key; serde-saphyr accepts it.
            ("\tserver: a\n", Some(["a", "", "", "", ""])),
            // yaml.v3 accepts only `%YAML 1.1`; serde-saphyr accepts 1.2.
            ("%YAML 1.2\n---\nserver: directive\n", Some(["directive", "", "", "", ""])),
        ];
        for (raw, _) in rust_differs {
            assert!(
                cases.iter().any(|(c, _)| c == raw),
                "{raw:?} is a recorded case"
            );
        }
        let mismatches: Vec<String> = cases
            .iter()
            .map(
                |(raw, go)| match rust_differs.iter().find(|(r, _)| r == raw) {
                    Some(pinned) => *pinned,
                    None => (*raw, *go),
                },
            )
            .filter_map(|(raw, expected)| {
                let (got, expected) = (parsed(raw), expected.map(|f| f.map(str::to_owned)));
                (got != expected).then(|| format!("{raw:?}: got {got:?}, want {expected:?}"))
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }
}
