//! A `log/slog` JSON-handler lookalike: one JSON object per line on stdout.
//! Never pass transcripts, bearer tokens or JWTs to it.

use serde_json::Value;
use std::io::Write;

/// One line, keys in `slog.JSONHandler` order: time, level, msg, then attributes as given.
fn render(time: &str, level: &str, msg: &str, fields: &[(&str, Value)]) -> String {
    let mut line = format!(
        "{{\"time\":{},\"level\":{},\"msg\":{}",
        json(time),
        json(level),
        json(msg)
    );
    for (key, value) in fields {
        line.push(',');
        line.push_str(&json(key));
        line.push(':');
        line.push_str(&serde_json::to_string(value).unwrap_or_else(|_| "null".into()));
    }
    line.push('}');
    line
}

fn json(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

fn emit(level: &str, msg: &str, fields: &[(&str, Value)]) {
    let time = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, false);
    let mut line = render(&time, level, msg, fields).into_bytes();
    line.push(b'\n');
    let _ = std::io::stdout().lock().write_all(&line);
}

pub fn info(msg: &str, fields: &[(&str, Value)]) {
    emit("INFO", msg, fields);
}

pub fn warn(msg: &str, fields: &[(&str, Value)]) {
    emit("WARN", msg, fields);
}

pub fn error(msg: &str, fields: &[(&str, Value)]) {
    emit("ERROR", msg, fields);
}

pub fn s(value: impl AsRef<str>) -> Value {
    Value::String(value.as_ref().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_slog_order_not_alphabetical() {
        let line = render(
            "T",
            "INFO",
            "asrbotd listening",
            &[("addr", s("a")), ("max_meetings", Value::from(2))],
        );
        assert_eq!(
            line,
            r#"{"time":"T","level":"INFO","msg":"asrbotd listening","addr":"a","max_meetings":2}"#
        );
    }
}
