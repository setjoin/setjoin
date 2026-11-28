//! Comparison of recorded observations. The paths are JSON Pointers so a
//! difference identifies the response or effect a reviewer must inspect.
use serde_json::Value;

/// Create a golden once; an existing recording is never replaced.
pub fn record(path: &std::path::Path, observation: &Value) -> std::io::Result<()> {
    use std::io::Write;
    let mut bytes = serde_json::to_vec_pretty(observation)?;
    bytes.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

/// Replace only declared volatile scalar fields, failing if a rule is stale
/// or the observed value is not of the declared kind.
pub fn normalize(observation: &Value, rules: &Value) -> Result<Value, String> {
    let rules = rules
        .as_array()
        .ok_or("normalization rules must be an array")?;
    let mut normalized = observation.clone();
    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        let text = |name: &str| -> Result<&str, String> {
            rule.get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| format!("normalization needs a nonempty {name}"))
        };
        let (field, kind, placeholder) = (text("field")?, text("kind")?, text("placeholder")?);
        if !field.starts_with('/') || !seen.insert(field) {
            return Err(format!("invalid or duplicate normalization field {field}"));
        }
        let value = normalized
            .pointer_mut(field)
            .ok_or_else(|| format!("normalization field {field} is missing"))?;
        let valid = match kind {
            "id" => {
                value.as_u64().is_some_and(|n| n > 0)
                    || value
                        .as_str()
                        .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
            }
            "timestamp" => value.as_str().is_some_and(|s| !s.is_empty()),
            _ => return Err(format!("unknown normalization kind {kind} at {field}")),
        };
        if !valid {
            return Err(format!("invalid {kind} at {field}: {value}"));
        }
        *value = Value::String(placeholder.to_owned());
    }
    Ok(normalized)
}

/// Compare every field and array entry, returning all differing paths.
pub fn compare(expected: &Value, actual: &Value) -> Result<(), String> {
    let mut differences = Vec::new();
    diff("", Some(expected), Some(actual), &mut differences);
    report(differences)
}

/// Apply only exact, reviewed per-case differences; an invalid record fails
/// the whole run, including when it names a different case.
pub fn compare_reviewed(
    route: &str,
    case: &str,
    expected: &Value,
    actual: &Value,
    records: &Value,
) -> Result<(), String> {
    // A whole-golden security re-baseline (`baseline`/`expectation`, see the gateway tests'
    // `common::golden_doc`) is not a per-field record.
    let records = records
        .as_array()
        .ok_or("divergences must be an array")?
        .iter()
        .filter(|r| r.get("baseline").is_none())
        .cloned()
        .collect::<Vec<_>>();
    let records = &records;
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        let field = |name: &str| -> Result<&str, String> {
            record
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| format!("divergence needs a nonempty {name}"))
        };
        let key = (field("route")?, field("case")?, field("field")?);
        if !key.2.starts_with('/') {
            return Err("divergence field must be a JSON Pointer".into());
        }
        field("reason")?;
        field("reviewer")?;
        if record.get("reviewed") != Some(&Value::Bool(true)) {
            return Err("divergence must be explicitly reviewed".into());
        }
        if record.get("from").is_none() || record.get("to").is_none() {
            return Err("divergence needs both from and to values".into());
        }
        if !seen.insert(key) {
            return Err(format!(
                "duplicate divergence {} {} {}",
                key.0, key.1, key.2
            ));
        }
    }
    let mut differences = Vec::new();
    diff("", Some(expected), Some(actual), &mut differences);
    differences.retain(|d| {
        !records.iter().any(|r| {
            r["route"] == route
                && r["case"] == case
                && r["field"] == d.path
                && r.get("from") == d.expected.as_ref()
                && r.get("to") == d.actual.as_ref()
        })
    });
    report(differences)
}

struct Difference {
    path: String,
    expected: Option<Value>,
    actual: Option<Value>,
}

fn report(differences: Vec<Difference>) -> Result<(), String> {
    if differences.is_empty() {
        return Ok(());
    }
    let display =
        |value: Option<&Value>| value.map_or_else(|| "<missing>".to_owned(), Value::to_string);
    Err(differences
        .iter()
        .map(|d| {
            format!(
                "{}: expected {}, got {}",
                d.path,
                display(d.expected.as_ref()),
                display(d.actual.as_ref())
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn diff(path: &str, expected: Option<&Value>, actual: Option<&Value>, out: &mut Vec<Difference>) {
    match (expected, actual) {
        (Some(Value::Object(a)), Some(Value::Object(b))) => {
            let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                diff(&format!("{path}/{escaped}"), a.get(key), b.get(key), out);
            }
        }
        (Some(Value::Array(a)), Some(Value::Array(b))) => {
            for i in 0..a.len().max(b.len()) {
                diff(&format!("{path}/{i}"), a.get(i), b.get(i), out);
            }
        }
        (a, b) if a == b => {}
        (a, b) => out.push(Difference {
            path: if path.is_empty() { "/" } else { path }.to_owned(),
            expected: a.cloned(),
            actual: b.cloned(),
        }),
    }
}
