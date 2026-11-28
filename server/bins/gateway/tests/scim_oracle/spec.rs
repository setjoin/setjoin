//! Request shapes per (route action, case label). Placeholders in goldens use
//! names (`<alice>`); the real ids are substituted here.
use super::World;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    A,
    Hard,
    B,
    Expired,
    Legacy,
}
pub enum Auth {
    Token(Tok),
    Raw(String),
    None,
}
pub struct Request {
    pub method: &'static str,
    pub target: String,
    pub content_type: Option<String>,
    pub auth: Auth,
    pub body: String,
}
pub struct Case {
    pub request: Request,
    pub method_name: &'static str,
    pub pattern: &'static str,
    pub query_label: String,
    pub body_label: String,
    pub status: u16,
    /// Expected welcome mails and authserver revocation calls.
    pub welcome: usize,
    pub revokes: usize,
}

const SCIM: &str = "application/scim+json";

struct B<'a> {
    w: &'a World,
}

pub fn spec(action: &str, label: &str, w: &World) -> Case {
    let mut case = build(action, label, w);
    match (action, label) {
        ("users-list", "sync") => {
            case.query_label = "syncToken=<source-a>|2026-10-01T12:00:02Z".into()
        }
        ("users-list", "sync-foreign") => {
            case.query_label = "syncToken=<source-b>|2026-10-01T12:00:00Z".into()
        }
        ("users-list", "filter-id") => case.query_label = "filter=id%20eq%20<alice>".into(),
        ("users-create", "too-large") => case.body_label = "<userName of 1 MiB + 10 bytes>".into(),
        _ => {}
    }
    case
}

fn build(action: &str, label: &str, w: &World) -> Case {
    let b = B { w };
    let (alice, bob, group) = (w.alice, w.bob, w.group_a);
    // (method, pattern, path, query, body, token, status, welcome, revokes)
    let user = |id: &str| format!("/scim/v2/Users/{id}");
    let grp = |id: &str| format!("/scim/v2/Groups/{id}");
    let sync_token = |source: i64, at: &str| {
        URL_SAFE_NO_PAD.encode(format!(
            "{{\"sourceId\":\"{source}\",\"updatedAt\":\"{at}\"}}"
        ))
    };
    let mk = |method: &'static str,
              pattern: &'static str,
              path: String,
              query: &str,
              body: &str,
              tok: Tok,
              status: u16,
              welcome: usize,
              revokes: usize| {
        let target = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        Case {
            request: Request {
                method,
                target,
                content_type: if matches!(method, "GET" | "DELETE") && body.is_empty() {
                    None
                } else {
                    Some(SCIM.into())
                },
                auth: Auth::Token(tok),
                body: body.to_owned(),
            },
            method_name: method,
            pattern,
            query_label: query.to_owned(),
            body_label: body.to_owned(),
            status,
            welcome,
            revokes,
        }
    };
    let _ = &b;
    let new_user = |ext: &str| {
        format!(
            "{{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"externalId\":\"{ext}\",\"userName\":\"{ext}-{}@{}\",\"name\":{{\"givenName\":\"New\",\"familyName\":\"Person\"}},\"displayName\":\"New <Person>\",\"emails\":[{{\"value\":\"{ext}-{}@{}\",\"primary\":true}}],\"phoneNumbers\":[{{\"value\":\"555\"}}],\"title\":\"Analyst\",\"active\":true,\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\":{{\"department\":\"\"}}}}",
            w.unique, w.domain, w.unique, w.domain
        )
    };
    let patch = |ops: &str| {
        format!("{{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":{ops}}}")
    };
    let name = |n: &str| w_id(w, n).to_string();
    let _ = &name;

    const USERS: &str = "/scim/v2/Users";
    const USER: &str = "/scim/v2/Users/{id}";
    const GROUPS: &str = "/scim/v2/Groups";
    const GROUP: &str = "/scim/v2/Groups/{id}";
    const SP: &str = "/scim/v2/ServiceProviderConfig";
    let alice_id = alice.to_string();
    let bob_id = bob.to_string();
    let group_id = group.to_string();
    let filter = |f: &str| format!("filter={}", urlencode(f));
    match (action, label) {
        // ServiceProviderConfig
        ("sp", "success") => mk("GET", SP, SP.into(), "", "", Tok::A, 200, 0, 0),
        ("sp", "foreign") => mk("GET", SP, SP.into(), "", "", Tok::B, 200, 0, 0),
        ("sp", "invalid") => none_auth(mk("GET", SP, SP.into(), "", "", Tok::A, 401, 0, 0)),
        ("sp", "bad-token") => raw_auth(mk("GET", SP, SP.into(), "", "", Tok::A, 401, 0, 0), "Bearer not-a-token"),
        ("sp", "expired") => mk("GET", SP, SP.into(), "", "", Tok::Expired, 401, 0, 0),
        ("sp", "legacy") => mk("GET", SP, SP.into(), "", "", Tok::Legacy, 200, 0, 0),
        ("sp", "empty-bearer") => raw_auth(mk("GET", SP, SP.into(), "", "", Tok::A, 401, 0, 0), "Bearer "),
        ("sp", "wrong-scheme") => raw_auth(mk("GET", SP, SP.into(), "", "", Tok::A, 401, 0, 0), "Basic abc"),
        // Users list
        ("users-list", "success") => mk("GET", USERS, USERS.into(), "", "", Tok::A, 200, 0, 0),
        ("users-list", "foreign") => mk("GET", USERS, USERS.into(), "", "", Tok::B, 200, 0, 0),
        ("users-list", "invalid") => mk("GET", USERS, USERS.into(), "filter=bogus", "", Tok::A, 400, 0, 0),
        ("users-list", "filter-eq") => mk("GET", USERS, USERS.into(), &filter(&format!("userName eq \"alice-{}\"", w.unique)), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-co") => mk("GET", USERS, USERS.into(), &filter("displayName co \"b\""), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-sw") => mk("GET", USERS, USERS.into(), &filter("externalId sw ext-b"), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-pr") => mk("GET", USERS, USERS.into(), &filter("title pr"), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-id") => mk("GET", USERS, USERS.into(), &filter(&format!("id eq {alice_id}")), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-active") => mk("GET", USERS, USERS.into(), &filter("active eq true"), "", Tok::A, 200, 0, 0),
        ("users-list", "filter-unsupported") => mk("GET", USERS, USERS.into(), &filter("password_hash eq x"), "", Tok::A, 400, 0, 0),
        ("users-list", "filter-bad-op") => mk("GET", USERS, USERS.into(), &filter("userName gt x"), "", Tok::A, 400, 0, 0),
        ("users-list", "filter-co-bool") => mk("GET", USERS, USERS.into(), &filter("active co tr"), "", Tok::A, 500, 0, 0),
        ("users-list", "filter-bad-bool") => mk("GET", USERS, USERS.into(), &filter("active eq maybe"), "", Tok::A, 500, 0, 0),
        ("users-list", "filter-empty") => mk("GET", USERS, USERS.into(), &filter("userName eq nobody"), "", Tok::A, 200, 0, 0),
        ("users-list", "page") => mk("GET", USERS, USERS.into(), "startIndex=2&count=1", "", Tok::A, 200, 0, 0),
        ("users-list", "page-bad") => mk("GET", USERS, USERS.into(), "startIndex=0&count=abc", "", Tok::A, 200, 0, 0),
        ("users-list", "sync") => mk("GET", USERS, USERS.into(), &format!("syncToken={}", sync_token(w.src_a, "2026-10-01T12:00:02Z")), "", Tok::A, 200, 0, 0),
        ("users-list", "sync-bad") => mk("GET", USERS, USERS.into(), "syncToken=%25%25", "", Tok::A, 500, 0, 0),
        ("users-list", "sync-foreign") => mk("GET", USERS, USERS.into(), &format!("syncToken={}", sync_token(w.src_b, "2026-10-01T12:00:00Z")), "", Tok::A, 500, 0, 0),
        ("users-list", "legacy") => mk("GET", USERS, USERS.into(), "", "", Tok::Legacy, 200, 0, 0),
        // Users create
        ("users-create", "success") => mk("POST", USERS, USERS.into(), "", &new_user("new-one"), Tok::A, 201, 1, 0),
        ("users-create", "foreign") => mk("POST", USERS, USERS.into(), "", &format!("{{\"externalId\":\"new-x\",\"userName\":\"alice-{}@{}\",\"displayName\":\"Hijack\"}}", w.unique, w.domain), Tok::B, 500, 0, 0),
        ("users-create", "invalid") => mk("POST", USERS, USERS.into(), "", "{\"externalId\":\"new-two\"}", Tok::A, 400, 0, 0),
        ("users-create", "invalid-json") => mk("POST", USERS, USERS.into(), "", "{\"userName\":", Tok::A, 400, 0, 0),
        ("users-create", "wrong-type") => mk("POST", USERS, USERS.into(), "", "{\"userName\":5}", Tok::A, 400, 0, 0),
        ("users-create", "no-external") => mk("POST", USERS, USERS.into(), "", &format!("{{\"userName\":\"noext-{}@{}\"}}", w.unique, w.domain), Tok::A, 400, 0, 0),
        ("users-create", "bad-content-type") => with_ct(mk("POST", USERS, USERS.into(), "", "{}", Tok::A, 400, 0, 0), Some("text/plain")),
        ("users-create", "no-content-type") => with_ct(mk("POST", USERS, USERS.into(), "", "{}", Tok::A, 400, 0, 0), None),
        ("users-create", "json-content-type") => with_ct(mk("POST", USERS, USERS.into(), "", &new_user("new-json"), Tok::A, 201, 1, 0), Some("application/json; charset=utf-8")),
        ("users-create", "too-large") => mk("POST", USERS, USERS.into(), "", &format!("{{\"userName\":\"{}\"}}", "x".repeat((1 << 20) + 10)), Tok::A, 413, 0, 0),
        ("users-create", "repeat") => mk("POST", USERS, USERS.into(), "", &new_user("new-one"), Tok::A, 201, 1, 0),
        ("users-create", "disabled-on-create") => mk("POST", USERS, USERS.into(), "", &new_user("new-off").replace("\"active\":true", "\"active\":false"), Tok::A, 500, 0, 0),
        // Users get
        ("users-get", "success") => mk("GET", USER, user(&alice_id), "", "", Tok::A, 200, 0, 0),
        ("users-get", "foreign") => mk("GET", USER, user(&alice_id), "", "", Tok::B, 404, 0, 0),
        ("users-get", "invalid") => mk("GET", USER, user("abc"), "", "", Tok::A, 400, 0, 0),
        ("users-get", "missing") => mk("GET", USER, user("999999999"), "", "", Tok::A, 404, 0, 0),
        ("users-get", "signed-id") => mk("GET", USER, user(&format!("%2B{alice_id}")), "", "", Tok::A, 200, 0, 0),
        // Users replace
        ("users-put", "success") => mk("PUT", USER, user(&alice_id), "", &format!("{{\"userName\":\"alice-{}@{}\",\"externalId\":\"ext-alice\",\"displayName\":\"Alice Replaced\",\"name\":{{\"givenName\":\"Alicia\",\"familyName\":\"Anderson\"}},\"title\":\"Lead\",\"active\":true}}", w.unique, w.domain), Tok::A, 200, 0, 0),
        ("users-put", "foreign") => mk("PUT", USER, user(&alice_id), "", "{\"userName\":\"x\"}", Tok::B, 404, 0, 0),
        ("users-put", "invalid") => mk("PUT", USER, user(&alice_id), "", "{\"displayName\":\"x\"}", Tok::A, 400, 0, 0),
        ("users-put", "bad-id") => mk("PUT", USER, user("abc"), "", "{\"userName\":\"x\"}", Tok::A, 400, 0, 0),
        ("users-put", "mismatch") => mk("PUT", USER, user(&alice_id), "", "{\"userName\":\"x\",\"externalId\":\"other\"}", Tok::A, 409, 0, 0),
        ("users-put", "disable") => mk("PUT", USER, user(&bob_id), "", &format!("{{\"userName\":\"bob-{}@{}\",\"active\":false}}", w.unique, w.domain), Tok::A, 200, 0, 1),
        ("users-put", "repeat") => mk("PUT", USER, user(&alice_id), "", &format!("{{\"userName\":\"alice-{}@{}\",\"displayName\":\"Alice Replaced\"}}", w.unique, w.domain), Tok::A, 200, 0, 0),
        // Users patch
        ("users-patch", "success") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Alice P\"},{\"op\":\"replace\",\"path\":\"name.givenName\",\"value\":\"Al\"},{\"op\":\"add\",\"path\":\"title\",\"value\":\"CTO\"}]"), Tok::A, 200, 0, 0),
        ("users-patch", "foreign") => mk("PATCH", USER, user(&alice_id), "", &patch("[]"), Tok::B, 404, 0, 0),
        ("users-patch", "invalid") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"move\",\"path\":\"title\"}]"), Tok::A, 400, 0, 0),
        ("users-patch", "bad-path") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"replace\",\"path\":\"nickName\",\"value\":\"x\"}]"), Tok::A, 400, 0, 0),
        ("users-patch", "bad-id") => mk("PATCH", USER, user("abc"), "", &patch("[]"), Tok::A, 400, 0, 0),
        ("users-patch", "bad-json") => mk("PATCH", USER, user(&alice_id), "", "[", Tok::A, 400, 0, 0),
        ("users-patch", "deactivate") => mk("PATCH", USER, user(&bob_id), "", &patch("[{\"op\":\"replace\",\"path\":\"active\",\"value\":false}]"), Tok::A, 200, 0, 1),
        ("users-patch", "null-active") => mk("PATCH", USER, user(&bob_id), "", &patch("[{\"op\":\"replace\",\"value\":null}]"), Tok::A, 200, 0, 1),
        ("users-patch", "object-active") => mk("PATCH", USER, user(&bob_id), "", &patch("[{\"op\":\"replace\",\"value\":{\"active\":false}}]"), Tok::A, 400, 0, 0),
        ("users-patch", "remove-title") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"remove\",\"path\":\"title\"}]"), Tok::A, 200, 0, 0),
        ("users-patch", "remove-active") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"remove\",\"path\":\"active\"}]"), Tok::A, 400, 0, 0),
        ("users-patch", "emails-phones") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"replace\",\"path\":\"emails\",\"value\":[{\"value\":\"alice.new@example.test\"}]},{\"op\":\"replace\",\"path\":\"phoneNumbers\",\"value\":[{\"value\":\"777\"}]}]"), Tok::A, 200, 0, 0),
        ("users-patch", "department") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"replace\",\"path\":\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department\",\"value\":\"Platform\"}]"), Tok::A, 200, 0, 0),
        ("users-patch", "empty-ops") => mk("PATCH", USER, user(&alice_id), "", &patch("[]"), Tok::A, 200, 0, 0),
        ("users-patch", "repeat") => mk("PATCH", USER, user(&alice_id), "", &patch("[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Alice P\"}]"), Tok::A, 200, 0, 0),
        // Users delete
        ("users-delete", "success") => mk("DELETE", USER, user(&bob_id), "", "", Tok::A, 204, 0, 1),
        ("users-delete", "foreign") => mk("DELETE", USER, user(&bob_id), "", "", Tok::B, 404, 0, 0),
        ("users-delete", "invalid") => mk("DELETE", USER, user("abc"), "", "", Tok::A, 400, 0, 0),
        ("users-delete", "hard") => mk("DELETE", USER, user(&bob_id), "", "", Tok::Hard, 409, 0, 0),
        ("users-delete", "missing") => mk("DELETE", USER, user("999999999"), "", "", Tok::A, 404, 0, 0),
        ("users-delete", "repeat") => mk("DELETE", USER, user(&bob_id), "", "", Tok::A, 204, 0, 1),
        // Groups list
        ("groups-list", "success") => mk("GET", GROUPS, GROUPS.into(), "", "", Tok::A, 200, 0, 0),
        ("groups-list", "foreign") => mk("GET", GROUPS, GROUPS.into(), "", "", Tok::B, 200, 0, 0),
        ("groups-list", "invalid") => none_auth(mk("GET", GROUPS, GROUPS.into(), "", "", Tok::A, 401, 0, 0)),
        ("groups-list", "page") => mk("GET", GROUPS, GROUPS.into(), "startIndex=2&count=1", "", Tok::A, 200, 0, 0),
        ("groups-list", "page-bad") => mk("GET", GROUPS, GROUPS.into(), "startIndex=x&count=5000", "", Tok::A, 200, 0, 0),
        // Groups create
        ("groups-create", "success") => mk("POST", GROUPS, GROUPS.into(), "", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"externalId\":\"new-team\",\"displayName\":\"New <Team>\",\"members\":[{\"value\":\"ext-alice\"},{\"value\":\"ext-bob\"}]}", Tok::A, 201, 0, 0),
        ("groups-create", "foreign") => mk("POST", GROUPS, GROUPS.into(), "", "{\"externalId\":\"new-team\",\"displayName\":\"Other\",\"members\":[{\"value\":\"ext-alice\"}]}", Tok::B, 403, 0, 0),
        ("groups-create", "invalid") => mk("POST", GROUPS, GROUPS.into(), "", "{\"externalId\":\"new-team\"}", Tok::A, 400, 0, 0),
        ("groups-create", "invalid-json") => mk("POST", GROUPS, GROUPS.into(), "", "nope", Tok::A, 400, 0, 0),
        ("groups-create", "unknown-member") => mk("POST", GROUPS, GROUPS.into(), "", "{\"externalId\":\"new-team\",\"displayName\":\"T\",\"members\":[{\"value\":\"ext-ghost\"}]}", Tok::A, 403, 0, 0),
        ("groups-create", "rls-members") => mk("POST", GROUPS, GROUPS.into(), "", "{\"externalId\":\"new-team\",\"displayName\":\"T\",\"members\":[{\"value\":\"ext-alice\"}]}", Tok::A, 403, 0, 0),
        ("groups-create", "repeat") => mk("POST", GROUPS, GROUPS.into(), "", "{\"externalId\":\"new-team\",\"displayName\":\"New <Team>\",\"members\":[{\"value\":\"ext-alice\"}]}", Tok::A, 201, 0, 0),
        // Groups get
        ("groups-get", "success") => mk("GET", GROUP, grp(&group_id), "", "", Tok::A, 200, 0, 0),
        ("groups-get", "foreign") => mk("GET", GROUP, grp(&group_id), "", "", Tok::B, 404, 0, 0),
        ("groups-get", "invalid") => mk("GET", GROUP, grp("abc"), "", "", Tok::A, 400, 0, 0),
        // Groups patch
        ("groups-patch", "success") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"ext-bob\"}]},{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Team Renamed\"}]"), Tok::A, 200, 0, 0),
        ("groups-patch", "foreign") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[]"), Tok::B, 404, 0, 0),
        ("groups-patch", "invalid") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"copy\",\"path\":\"members\"}]"), Tok::A, 400, 0, 0),
        ("groups-patch", "bad-path") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"replace\",\"path\":\"externalId\",\"value\":\"x\"}]"), Tok::A, 400, 0, 0),
        ("groups-patch", "remove-members") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\"ext-alice\"}]}]"), Tok::A, 200, 0, 0),
        ("groups-patch", "replace-members") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"replace\",\"path\":\"members\",\"value\":[{\"value\":\"ext-bob\"}]}]"), Tok::A, 200, 0, 0),
        ("groups-patch", "single-member") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"add\",\"path\":\"members\",\"value\":{\"value\":\"ext-bob\"}}]"), Tok::A, 200, 0, 0),
        ("groups-patch", "unknown-member") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"ext-ghost\"}]}]"), Tok::A, 403, 0, 0),
        ("groups-patch", "bad-id") => mk("PATCH", GROUP, grp("abc"), "", &patch("[]"), Tok::A, 400, 0, 0),
        ("groups-patch", "rls-members") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"ext-bob\"}]}]"), Tok::A, 403, 0, 0),
        ("groups-patch", "repeat") => mk("PATCH", GROUP, grp(&group_id), "", &patch("[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"ext-bob\"}]}]"), Tok::A, 200, 0, 0),
        // Groups delete
        ("groups-delete", "success") => mk("DELETE", GROUP, grp(&group_id), "", "", Tok::A, 204, 0, 0),
        ("groups-delete", "foreign") => mk("DELETE", GROUP, grp(&group_id), "", "", Tok::B, 404, 0, 0),
        ("groups-delete", "invalid") => mk("DELETE", GROUP, grp("abc"), "", "", Tok::A, 400, 0, 0),
        ("groups-delete", "repeat") => mk("DELETE", GROUP, grp(&group_id), "", "", Tok::A, 404, 0, 0),
        _ => panic!("unknown SCIM case {action}/{label}"),
    }
}

fn w_id(_w: &World, _n: &str) -> i64 {
    0
}
fn none_auth(mut c: Case) -> Case {
    c.request.auth = Auth::None;
    c
}
fn raw_auth(mut c: Case, v: &str) -> Case {
    c.request.auth = Auth::Raw(v.into());
    c
}
fn with_ct(mut c: Case, ct: Option<&str>) -> Case {
    c.request.content_type = ct.map(str::to_owned);
    c
}
fn urlencode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
