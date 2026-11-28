//! Load frozen Go contract recordings for family-level parity tests.
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub struct VectorCase {
    pub name: String,
    pub input: Value,
    pub output: Value,
}

/// Load cases without transforming byte-bearing strings in their input or output.
pub fn load_vectors(bytes: &[u8], contract: &str) -> Result<Vec<VectorCase>, String> {
    let root: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if root.get("contract").and_then(Value::as_str) != Some(contract) {
        return Err("contract does not match fixture".into());
    }
    let cases = root
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases")?;
    if cases.is_empty() {
        return Err("empty cases".into());
    }
    let mut names = std::collections::HashSet::new();
    cases
        .iter()
        .map(|case| {
            let name = case
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or("missing case name")?;
            if !names.insert(name) {
                return Err("duplicate case name".into());
            }
            Ok(VectorCase {
                name: name.to_owned(),
                input: case.get("input").ok_or("missing case input")?.clone(),
                output: case.get("output").ok_or("missing case output")?.clone(),
            })
        })
        .collect()
}
