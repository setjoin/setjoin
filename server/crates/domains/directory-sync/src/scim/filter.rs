//! Go `scim.parseFilter` / `nodeToSQL` / `attributeToColumn`, byte for byte.

pub struct Node {
    pub attribute: String,
    pub operator: String,
    pub value: String,
}

/// Go `strings.TrimSpace`: Unicode White_Space.
pub fn trim_space(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{85}' || c == '\u{a0}')
}

pub fn parse(filter: &str) -> Result<Node, ()> {
    let filter = trim_space(filter);
    if filter.is_empty() {
        return Err(());
    }
    // SplitN(filter, " ", 3)
    let mut parts = filter.splitn(3, ' ');
    let attr = parts.next().unwrap_or("");
    let Some(op) = parts.next() else {
        return Err(());
    };
    let rest = parts.next();
    match op {
        "eq" | "co" | "sw" => {
            let value = trim_space(rest.ok_or(())?);
            let value = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                &value[1..value.len() - 1]
            } else {
                value
            };
            if value.is_empty() {
                return Err(());
            }
            Ok(Node {
                attribute: attr.into(),
                operator: op.into(),
                value: value.into(),
            })
        }
        "pr" => Ok(Node {
            attribute: attr.into(),
            operator: op.into(),
            value: String::new(),
        }),
        _ => Err(()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Bool,
    Int,
}

/// Strict allowlist; unknown attributes are rejected (RFC 7644 invalidFilter).
pub fn column(attr: &str) -> Option<(&'static str, Kind)> {
    Some(match attr {
        "userName" => ("u.username", Kind::Text),
        "externalId" => ("l.external_subject", Kind::Text),
        "displayName" => ("u.display_name", Kind::Text),
        "name.givenName" => ("u.first_name", Kind::Text),
        "name.familyName" => ("u.last_name", Kind::Text),
        "emails" | "emails.value" => ("u.email", Kind::Text),
        "title" => ("u.job_title", Kind::Text),
        "phoneNumbers.value" => ("u.phone", Kind::Text),
        "active" => ("u.enabled", Kind::Bool),
        "id" => ("u.id", Kind::Int),
        _ => return None,
    })
}

pub enum Where {
    /// SQL fragment over `$1` (when `value` is Some) and the parameter text.
    Clause(String, Option<String>),
    /// PostgreSQL rejects the clause (ILIKE on a non-text column): Go answers 500.
    Rejected,
}

/// `Err` is the unsupported-attribute case.
pub fn to_sql(node: &Node) -> Result<Where, ()> {
    let (col, kind) = column(&node.attribute).ok_or(())?;
    // The value arrives as an unknown-typed parameter in Go, so PostgreSQL parses
    // it as the column's type; the text cast reproduces that input conversion.
    let cast = match kind {
        Kind::Text => "$1",
        Kind::Bool => "$1::text::boolean",
        Kind::Int => "$1::text::bigint",
    };
    Ok(match node.operator.as_str() {
        "eq" => Where::Clause(format!("{col} = {cast}"), Some(node.value.clone())),
        "co" | "sw" if kind != Kind::Text => Where::Rejected,
        "co" => Where::Clause(format!("{col} ILIKE $1"), Some(format!("%{}%", node.value))),
        "sw" => Where::Clause(format!("{col} ILIKE $1"), Some(format!("{}%", node.value))),
        "pr" => Where::Clause(format!("{col} IS NOT NULL"), None),
        _ => Where::Clause("1=1".into(), None),
    })
}
