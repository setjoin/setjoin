//! Frozen Go's admin CSV writer format (encoding/csv + EscapeCSVCell).
/// Data cells receive Go's literal apostrophe prefix before CSV encoding.
pub fn escape_formula(value: &str) -> String {
    if matches!(
        value.as_bytes().first(),
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r' | b'\'')
    ) {
        format!("'{value}")
    } else {
        value.to_owned()
    }
}
/// Default comma delimiter and LF records, including Go's leading-space and
/// PostgreSQL terminator quoting. Metadata cells bypass formula escaping.
pub fn record(cells: &[String]) -> String {
    cells
        .iter()
        .map(|cell| {
            if cell == "\\."
                || cell.contains([',', '"', '\r', '\n'])
                || cell.chars().next().is_some_and(char::is_whitespace)
            {
                format!("\"{}\"", cell.replace('"', "\"\""))
            } else {
                cell.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
        + "\n"
}
