//! Go `patch.go`: user PATCH operations applied to the current resource, and the
//! group PATCH operation plan. Paths compare lower-cased, as Go's `ToLower`.
use super::wire::{self, Op, User};
use std::collections::BTreeSet;

/// A SCIM error answer (status, detail, scimType).
#[derive(Debug, Clone)]
pub struct HttpError {
    pub status: u16,
    pub detail: String,
    pub scim_type: &'static str,
}
pub fn http(status: u16, detail: impl Into<String>, scim_type: &'static str) -> HttpError {
    HttpError {
        status,
        detail: detail.into(),
        scim_type,
    }
}

/// Go's per-rune `unicode.ToLower` (U+0130 maps to plain `i`).
pub fn lower(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c == '\u{130}' {
                vec!['i']
            } else {
                let mut it = c.to_lowercase();
                let first = it.next().unwrap_or(c);
                if it.next().is_some() {
                    vec![c]
                } else {
                    vec![first]
                }
            }
        })
        .collect()
}

const DEPARTMENT: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:department";

pub type Touched = BTreeSet<String>;

fn canonical(path: &str) -> String {
    let path = lower(path);
    match path.as_str() {
        "" | "active" => "active".into(),
        "displayname" => "displayName".into(),
        "title" => "title".into(),
        "name.givenname" => "givenName".into(),
        "name.familyname" => "familyName".into(),
        "emails" => "emails".into(),
        "phonenumbers" | "phonenumbers.value" => "phoneNumbers".into(),
        p if p.starts_with(DEPARTMENT) => "department".into(),
        _ => path,
    }
}

fn invalid(what: &str) -> HttpError {
    http(400, format!("Invalid value for {what}"), "invalidValue")
}

pub fn apply_user(user: &mut User, ops: &[Op]) -> Result<Touched, HttpError> {
    let mut touched = Touched::new();
    for op in ops {
        match op.op.as_str() {
            "replace" | "add" => replace(user, &op.path, op.value.as_ref())?,
            "remove" => remove(user, &op.path)?,
            other => {
                return Err(http(
                    400,
                    format!("Unsupported PATCH operation: {other}"),
                    "invalidValue",
                ))
            }
        }
        touched.insert(canonical(&op.path));
    }
    Ok(touched)
}

fn replace(
    user: &mut User,
    raw_path: &str,
    value: Option<&serde_json::Value>,
) -> Result<(), HttpError> {
    let path = lower(raw_path);
    match path.as_str() {
        "" | "active" => {
            let active = wire::raw_bool(value).map_err(|_| invalid("active"))?;
            user.active = Some(active);
        }
        "displayname" => {
            user.display_name = wire::raw_string(value).map_err(|_| invalid("displayName"))?;
        }
        "title" => user.title = wire::raw_string(value).map_err(|_| invalid("title"))?,
        "name.givenname" | "name.familyname" => {
            let given = path == "name.givenname";
            let text = wire::raw_string(value).map_err(|_| {
                invalid(if given {
                    "name.givenName"
                } else {
                    "name.familyName"
                })
            })?;
            let name = user.name.get_or_insert_with(Default::default);
            if given {
                name.given = text;
            } else {
                name.family = text;
            }
        }
        "emails" => {
            let emails = match value {
                None => Err(()),
                Some(v) => wire::emails(v),
            }
            .map_err(|_| invalid("emails"))?;
            if emails.first().is_some_and(|e| !e.value.is_empty()) {
                user.emails = emails;
            }
        }
        "phonenumbers" => {
            let phones = match value {
                None => Err(()),
                Some(v) => wire::phones(v),
            }
            .map_err(|_| invalid("phoneNumbers"))?;
            if !phones.is_empty() {
                user.phones = phones;
            }
        }
        p if p.starts_with(DEPARTMENT) => {
            let text = wire::raw_string(value).map_err(|_| invalid("department"))?;
            user.enterprise
                .get_or_insert_with(Default::default)
                .department = text;
        }
        _ => {
            return Err(http(
                400,
                format!("Unsupported PATCH path: {raw_path}"),
                "invalidPath",
            ))
        }
    }
    Ok(())
}

fn remove(user: &mut User, raw_path: &str) -> Result<(), HttpError> {
    match lower(raw_path).as_str() {
        "" | "active" => Err(http(
            400,
            "Cannot remove required attribute: active",
            "noTarget",
        )),
        "phonenumbers" | "phonenumbers.value" => {
            user.phones.clear();
            Ok(())
        }
        "title" => {
            user.title.clear();
            Ok(())
        }
        _ => Err(http(
            400,
            format!("Cannot remove attribute via PATCH: {raw_path}"),
            "noTarget",
        )),
    }
}

/// One planned group reducer call (executed in order, each autocommit as in Go).
pub enum GroupStep {
    /// `scim_upsert_group(.., ext_id, name)`; must return the PATCHed group id.
    Rename(String),
    Replace(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
}

fn external_ids(members: Vec<wire::Member>) -> Vec<String> {
    members.into_iter().map(|m| m.value).collect()
}

/// Go validates and runs operations one at a time, so an invalid later operation
/// is only reported after earlier ones have written. The caller therefore asks
/// for one step at a time.
pub fn group_step(op: &Op) -> Result<GroupStep, HttpError> {
    let path = lower(&op.path);
    match op.op.as_str() {
        "replace" => match path.as_str() {
            "displayname" => Ok(GroupStep::Rename(
                wire::raw_string(op.value.as_ref()).map_err(|_| invalid("displayName"))?,
            )),
            "members" => {
                let members = match &op.value {
                    None => Err(()),
                    Some(v) => wire::members(v),
                }
                .map_err(|_| invalid("members"))?;
                Ok(GroupStep::Replace(external_ids(members)))
            }
            _ => Err(http(
                400,
                format!("Unsupported PATCH path: {}", op.path),
                "invalidPath",
            )),
        },
        "add" | "remove" => {
            let remove = op.op == "remove";
            if !path.starts_with("members") {
                return Err(if remove {
                    http(
                        400,
                        format!("Cannot remove attribute: {}", op.path),
                        "noTarget",
                    )
                } else {
                    http(
                        400,
                        format!("Unsupported PATCH path: {}", op.path),
                        "invalidPath",
                    )
                });
            }
            let ids = group_member_ids(op.value.as_ref())?;
            Ok(if remove {
                GroupStep::Remove(ids)
            } else {
                GroupStep::Add(ids)
            })
        }
        other => Err(http(
            400,
            format!("Unsupported PATCH operation: {other}"),
            "invalidValue",
        )),
    }
}

fn group_member_ids(value: Option<&serde_json::Value>) -> Result<Vec<String>, HttpError> {
    let bad = || http(400, "Invalid value for members", "invalidValue");
    let value = value.ok_or_else(bad)?;
    if let Ok(list) = wire::members(value) {
        return Ok(external_ids(list));
    }
    wire::member(value)
        .map(|m| vec![m.value])
        .map_err(|_| bad())
}
