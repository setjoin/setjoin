//! SCIM resources as Go's `encoding/json` writes and reads them (RFC 7643).
//! Output keeps struct field order, `omitempty` and HTML escaping; input follows
//! `json.Decoder.Decode`: case-folded keys, `null` is a no-op, a type mismatch
//! fails the whole decode.
use crate::go_escape;
use serde_json::Value;

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCHEMA_ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const CONTENT_TYPE: &str = "application/scim+json";

pub fn quote(text: &str) -> String {
    go_escape(&serde_json::to_string(text).expect("string"))
}

/// Ordered object builder that applies `omitempty` for strings.
#[derive(Default)]
pub struct Obj(Vec<String>);
impl Obj {
    pub fn raw(&mut self, key: &str, json: String) -> &mut Self {
        self.0.push(format!("{}:{json}", quote(key)));
        self
    }
    pub fn text(&mut self, key: &str, value: &str) -> &mut Self {
        if !value.is_empty() {
            self.raw(key, quote(value));
        }
        self
    }
    pub fn finish(&self) -> String {
        format!("{{{}}}", self.0.join(","))
    }
}

#[derive(Default, Clone, Debug)]
pub struct Name {
    pub formatted: String,
    pub family: String,
    pub given: String,
}
#[derive(Default, Clone, Debug)]
pub struct Email {
    pub value: String,
    pub display: String,
    pub kind: String,
    pub primary: Option<bool>,
}
#[derive(Default, Clone, Debug)]
pub struct Phone {
    pub value: String,
    pub kind: String,
}
#[derive(Default, Clone, Debug)]
pub struct Meta {
    pub resource_type: String,
    pub created: String,
    pub last_modified: String,
    pub location: String,
}
#[derive(Default, Clone, Debug)]
pub struct Enterprise {
    pub department: String,
    pub manager: Option<String>,
}
#[derive(Default, Clone, Debug)]
pub struct User {
    pub id: String,
    pub external_id: String,
    pub user_name: String,
    pub name: Option<Name>,
    pub display_name: String,
    pub emails: Vec<Email>,
    pub phones: Vec<Phone>,
    pub title: String,
    pub active: Option<bool>,
    pub meta: Option<Meta>,
    pub enterprise: Option<Enterprise>,
}
#[derive(Default, Clone, Debug)]
pub struct Member {
    pub value: String,
    pub display: String,
    pub reference: String,
    pub kind: String,
}
#[derive(Default, Clone, Debug)]
pub struct Group {
    pub id: String,
    pub external_id: String,
    pub display_name: String,
    pub members: Vec<Member>,
    pub meta: Option<Meta>,
}

fn schemas(list: &[&str]) -> String {
    format!(
        "[{}]",
        list.iter().map(|s| quote(s)).collect::<Vec<_>>().join(",")
    )
}

fn meta_json(meta: &Meta) -> String {
    let mut o = Obj::default();
    o.text("resourceType", &meta.resource_type)
        .text("created", &meta.created)
        .text("lastModified", &meta.last_modified)
        .text("location", &meta.location);
    o.finish()
}

impl User {
    pub fn json(&self) -> String {
        let mut o = Obj::default();
        o.raw("schemas", schemas(&[SCHEMA_USER, SCHEMA_ENTERPRISE]))
            .text("id", &self.id)
            .text("externalId", &self.external_id)
            .text("userName", &self.user_name);
        if let Some(name) = &self.name {
            let mut n = Obj::default();
            n.text("formatted", &name.formatted)
                .text("familyName", &name.family)
                .text("givenName", &name.given);
            o.raw("name", n.finish());
        }
        o.text("displayName", &self.display_name);
        if !self.emails.is_empty() {
            let items: Vec<String> = self
                .emails
                .iter()
                .map(|e| {
                    let mut x = Obj::default();
                    x.text("value", &e.value)
                        .text("display", &e.display)
                        .text("type", &e.kind);
                    if let Some(p) = e.primary {
                        x.raw("primary", p.to_string());
                    }
                    x.finish()
                })
                .collect();
            o.raw("emails", format!("[{}]", items.join(",")));
        }
        if !self.phones.is_empty() {
            let items: Vec<String> = self
                .phones
                .iter()
                .map(|p| {
                    let mut x = Obj::default();
                    x.text("value", &p.value).text("type", &p.kind);
                    x.finish()
                })
                .collect();
            o.raw("phoneNumbers", format!("[{}]", items.join(",")));
        }
        o.text("title", &self.title);
        if let Some(active) = self.active {
            o.raw("active", active.to_string());
        }
        if let Some(meta) = &self.meta {
            o.raw("meta", meta_json(meta));
        }
        if let Some(ent) = &self.enterprise {
            let mut e = Obj::default();
            e.text("department", &ent.department);
            if let Some(manager) = &ent.manager {
                let mut m = Obj::default();
                m.text("value", manager);
                e.raw("manager", m.finish());
            }
            o.raw(SCHEMA_ENTERPRISE, e.finish());
        }
        o.finish()
    }
}

impl Group {
    pub fn json(&self) -> String {
        let mut o = Obj::default();
        o.raw("schemas", schemas(&[SCHEMA_GROUP]))
            .text("id", &self.id)
            .text("externalId", &self.external_id)
            .text("displayName", &self.display_name);
        if !self.members.is_empty() {
            let items: Vec<String> = self
                .members
                .iter()
                .map(|m| {
                    let mut x = Obj::default();
                    x.text("value", &m.value)
                        .text("display", &m.display)
                        .text("$ref", &m.reference)
                        .text("type", &m.kind);
                    x.finish()
                })
                .collect();
            o.raw("members", format!("[{}]", items.join(",")));
        }
        if let Some(meta) = &self.meta {
            o.raw("meta", meta_json(meta));
        }
        o.finish()
    }
}

/// `ListResponse`; an empty page marshals its nil slice as `null`.
pub fn list_json(total: i64, start: i64, resources: &[String]) -> String {
    let items = if resources.is_empty() {
        "null".to_owned()
    } else {
        format!("[{}]", resources.join(","))
    };
    let mut o = Obj::default();
    o.raw("schemas", schemas(&[SCHEMA_LIST]))
        .raw("totalResults", total.to_string())
        .raw("startIndex", start.to_string())
        .raw("itemsPerPage", resources.len().to_string())
        .raw("Resources", items);
    o.finish()
}

/// Go's `NewSCIMError` encoded with `json.Encoder` (trailing newline).
pub fn error_json(status: u16, detail: &str, scim_type: &str) -> String {
    let mut o = Obj::default();
    o.raw("schemas", schemas(&[SCHEMA_ERROR]))
        .raw("detail", quote(detail))
        .raw("status", quote(&status.to_string()))
        .text("scimType", scim_type);
    o.finish() + "\n"
}

// ---- Go json.Unmarshal semantics ------------------------------------------------

type Decoded<T> = Result<T, ()>;

fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            'ſ' => 's',
            '\u{212a}' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}

/// `null` leaves the field untouched; any other non-string is a type error.
fn text_into(target: &mut String, value: &Value) -> Decoded<()> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            *target = s.clone();
            Ok(())
        }
        _ => Err(()),
    }
}
fn flag_into(target: &mut Option<bool>, value: &Value) -> Decoded<()> {
    match value {
        Value::Null => {
            *target = None;
            Ok(())
        }
        Value::Bool(b) => {
            *target = Some(*b);
            Ok(())
        }
        _ => Err(()),
    }
}
/// An object (or `null`, which is a no-op) whose fields are walked case-folded.
fn object<'a>(value: &'a Value) -> Decoded<Option<&'a serde_json::Map<String, Value>>> {
    match value {
        Value::Null => Ok(None),
        Value::Object(map) => Ok(Some(map)),
        _ => Err(()),
    }
}
/// Array (or `null` = nil) of elements decoded one by one; a `null` element is
/// the zero value.
fn array<T: Default>(value: &Value, mut one: impl FnMut(&Value) -> Decoded<T>) -> Decoded<Vec<T>> {
    match value {
        Value::Null => Ok(vec![]),
        Value::Array(items) => items
            .iter()
            .map(|v| {
                if v.is_null() {
                    Ok(T::default())
                } else {
                    one(v)
                }
            })
            .collect(),
        _ => Err(()),
    }
}
fn ignore_strings(value: &Value, keys: &[&str]) -> Decoded<()> {
    if let Some(map) = object(value)? {
        for (k, v) in map {
            if keys.contains(&fold(k).as_str()) {
                text_into(&mut String::new(), v)?;
            }
        }
    }
    Ok(())
}

fn email(value: &Value) -> Decoded<Email> {
    let mut e = Email::default();
    if let Some(map) = object(value)? {
        for (k, v) in map {
            match fold(k).as_str() {
                "value" => text_into(&mut e.value, v)?,
                "display" => text_into(&mut e.display, v)?,
                "type" => text_into(&mut e.kind, v)?,
                "primary" => flag_into(&mut e.primary, v)?,
                _ => {}
            }
        }
    }
    Ok(e)
}
fn phone(value: &Value) -> Decoded<Phone> {
    let mut p = Phone::default();
    if let Some(map) = object(value)? {
        for (k, v) in map {
            match fold(k).as_str() {
                "value" => text_into(&mut p.value, v)?,
                "type" => text_into(&mut p.kind, v)?,
                _ => {}
            }
        }
    }
    Ok(p)
}
pub fn member(value: &Value) -> Decoded<Member> {
    let mut m = Member::default();
    if let Some(map) = object(value)? {
        for (k, v) in map {
            match fold(k).as_str() {
                "value" => text_into(&mut m.value, v)?,
                "display" => text_into(&mut m.display, v)?,
                "$ref" => text_into(&mut m.reference, v)?,
                "type" => text_into(&mut m.kind, v)?,
                _ => {}
            }
        }
    }
    Ok(m)
}
pub fn emails(value: &Value) -> Decoded<Vec<Email>> {
    array(value, email)
}
pub fn phones(value: &Value) -> Decoded<Vec<Phone>> {
    array(value, phone)
}
pub fn members(value: &Value) -> Decoded<Vec<Member>> {
    array(value, member)
}
fn strings(value: &Value) -> Decoded<()> {
    array::<String>(value, |v| match v {
        Value::String(s) => Ok(s.clone()),
        _ => Err(()),
    })
    .map(|_| ())
}

/// `json.Unmarshal(raw, &string)` for a RawMessage that may be absent.
pub fn raw_string(value: Option<&Value>) -> Decoded<String> {
    match value {
        None => Err(()),
        Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(()),
    }
}
/// `json.Unmarshal(raw, &bool)`: absent and non-bool fail, `null` leaves `false`.
pub fn raw_bool(value: Option<&Value>) -> Decoded<bool> {
    match value {
        None => Err(()),
        Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(()),
    }
}

pub fn decode_user(value: &Value) -> Decoded<User> {
    let mut user = User::default();
    let Some(map) = object(value)? else {
        return Ok(user);
    };
    for (key, v) in map {
        let folded = fold(key);
        match folded.as_str() {
            "schemas" => strings(v)?,
            "id" => text_into(&mut user.id, v)?,
            "externalid" => text_into(&mut user.external_id, v)?,
            "username" => text_into(&mut user.user_name, v)?,
            "displayname" => text_into(&mut user.display_name, v)?,
            "title" => text_into(&mut user.title, v)?,
            "active" => flag_into(&mut user.active, v)?,
            "emails" => user.emails = emails(v)?,
            "phonenumbers" => user.phones = phones(v)?,
            "groups" => {
                array::<()>(v, |g| {
                    ignore_strings(g, &["value", "display", "$ref", "type"])
                })?;
            }
            "name" => match object(v)? {
                None => user.name = None,
                Some(fields) => {
                    let mut name = user.name.take().unwrap_or_default();
                    for (k, x) in fields {
                        match fold(k).as_str() {
                            "formatted" => text_into(&mut name.formatted, x)?,
                            "familyname" => text_into(&mut name.family, x)?,
                            "givenname" => text_into(&mut name.given, x)?,
                            "middlename" | "honorificprefix" | "honorificsuffix" => {
                                text_into(&mut String::new(), x)?
                            }
                            _ => {}
                        }
                    }
                    user.name = Some(name);
                }
            },
            "meta" => ignore_strings(
                v,
                &[
                    "resourcetype",
                    "created",
                    "lastmodified",
                    "location",
                    "version",
                ],
            )?,
            other if other == fold(SCHEMA_ENTERPRISE) => match object(v)? {
                None => user.enterprise = None,
                Some(fields) => {
                    let mut ent = user.enterprise.take().unwrap_or_default();
                    for (k, x) in fields {
                        match fold(k).as_str() {
                            "employeenumber" => text_into(&mut String::new(), x)?,
                            "department" => text_into(&mut ent.department, x)?,
                            "manager" => match object(x)? {
                                None => ent.manager = None,
                                Some(m) => {
                                    let mut value = ent.manager.take().unwrap_or_default();
                                    for (mk, mv) in m {
                                        match fold(mk).as_str() {
                                            "value" => text_into(&mut value, mv)?,
                                            "displayname" | "$ref" => {
                                                text_into(&mut String::new(), mv)?
                                            }
                                            _ => {}
                                        }
                                    }
                                    ent.manager = Some(value);
                                }
                            },
                            _ => {}
                        }
                    }
                    user.enterprise = Some(ent);
                }
            },
            _ => {}
        }
    }
    Ok(user)
}

pub fn decode_group(value: &Value) -> Decoded<Group> {
    let mut group = Group::default();
    let Some(map) = object(value)? else {
        return Ok(group);
    };
    for (key, v) in map {
        match fold(key).as_str() {
            "schemas" => strings(v)?,
            "id" => text_into(&mut group.id, v)?,
            "externalid" => text_into(&mut group.external_id, v)?,
            "displayname" => text_into(&mut group.display_name, v)?,
            "members" => group.members = members(v)?,
            "meta" => ignore_strings(
                v,
                &[
                    "resourcetype",
                    "created",
                    "lastmodified",
                    "location",
                    "version",
                ],
            )?,
            _ => {}
        }
    }
    Ok(group)
}

pub struct Op {
    pub op: String,
    pub path: String,
    pub value: Option<Value>,
}
/// `PatchRequest`: only `Operations` is consumed.
pub fn decode_patch(value: &Value) -> Decoded<Vec<Op>> {
    let mut ops = vec![];
    let Some(map) = object(value)? else {
        return Ok(ops);
    };
    for (key, v) in map {
        match fold(key).as_str() {
            "schemas" => strings(v)?,
            "operations" => {
                ops = match v {
                    Value::Null => vec![],
                    Value::Array(items) => items
                        .iter()
                        .map(|item| {
                            let mut op = Op {
                                op: String::new(),
                                path: String::new(),
                                value: None,
                            };
                            if let Some(fields) = object(item)? {
                                for (k, x) in fields {
                                    match fold(k).as_str() {
                                        "op" => text_into(&mut op.op, x)?,
                                        "path" => text_into(&mut op.path, x)?,
                                        "value" => op.value = Some(x.clone()),
                                        _ => {}
                                    }
                                }
                            }
                            Ok(op)
                        })
                        .collect::<Decoded<Vec<_>>>()?,
                    _ => return Err(()),
                };
            }
            _ => {}
        }
    }
    Ok(ops)
}
