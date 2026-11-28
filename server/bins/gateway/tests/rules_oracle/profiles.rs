//! Authored HTTP inputs and committed seeds for F09 qualification.
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

pub fn persona(action: &str, label: &str) -> (Vec<&'static str>, bool) {
    let denied = label == "denied" || (label == "foreign" && action.starts_with("template-"));
    let scoped = label == "scoped" || (label == "foreign" && action.starts_with("admin-"));
    (
        if denied {
            vec!["users.read"]
        } else if label == "read-console" {
            vec!["domains.read"]
        } else {
            vec!["mail.pipeline"]
        },
        scoped,
    )
}
pub async fn seed(
    c: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<(), BoxError> {
    match label {
        "expired" => {
            c.execute(
                "UPDATE admin_role_assignments SET expires_at='2026-10-01' WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        }
        "eligible" => {
            c.execute("UPDATE admin_role_assignments SET eligible=true,activated_until=NULL WHERE user_id=$1",&[&a.user]).await?;
        }
        "revoked" => {
            c.execute(
                "DELETE FROM admin_role_assignments WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        }
        "transport" => {
            c.batch_execute("INSERT INTO rules(id,mailbox_id,name,is_transport_rule,conditions,actions,created_at,updated_at) VALUES(961003,NULL,'Transport rule',true,'[]','[]','2026-10-01','2026-10-01')").await?;
        }
        "program" => {
            c.batch_execute("UPDATE rules SET conditions='[{\"field\":\"subject\",\"op\":\"contains\",\"value\":\"news<&>\"}]',actions='[{\"type\":\"mark_read\"}]' WHERE id=961001").await?;
        }
        "rule-limit" => {
            c.execute("INSERT INTO rules(id,mailbox_id,name,conditions,actions,created_at,updated_at) SELECT 961100+k,$1,'Limit rule '||k,'[]','[]','2026-10-01','2026-10-01' FROM generate_series(0,98) k",&[&a.mailbox]).await?;
        }
        "inflight-limit" => {
            for n in 2..=4 {
                let id = format!("96100000-0000-4000-8000-{n:012}");
                c.execute("INSERT INTO scheduled_actions(id,action_kind,mailbox_id,fire_at,payload,status,created_at) VALUES($1::text::uuid,'rules_retro',$2,'2030-10-01','{}','pending','2026-10-01')",&[&id,&a.mailbox]).await?;
            }
        }
        "pending" if action == "retro-status" => {
            c.batch_execute("UPDATE scheduled_actions SET status='pending',payload='{}' WHERE id='96100000-0000-4000-8000-000000000001'").await?;
        }
        "bad-payload" if action == "retro-status" => {
            c.batch_execute("UPDATE scheduled_actions SET payload='{\"processed\":\"bad\"}' WHERE id='96100000-0000-4000-8000-000000000001'").await?;
        }
        "null-description" => {
            c.batch_execute("UPDATE rule_templates SET description=NULL WHERE id=961011")
                .await?;
        }
        "empty-list" if action.starts_with("template-") => {
            c.batch_execute("UPDATE rule_templates SET enabled=false")
                .await?;
        }
        "visibility-many" => {
            c.execute("INSERT INTO rule_template_visibility(template_id,user_id,hidden) VALUES(961011,$1,true)",&[&b.user]).await?;
        }
        _ => {}
    }
    Ok(())
}
fn set(body: &mut String, key: &str, value: Value) {
    let mut v: Value = serde_json::from_str(body).expect("authored base object");
    v[key] = value;
    *body = v.to_string();
}
fn remove(body: &mut String, keys: &[&str]) {
    let mut v: Value = serde_json::from_str(body).expect("authored base object");
    for key in keys {
        v.as_object_mut().unwrap().remove(*key);
    }
    *body = v.to_string();
}

pub fn request(
    action: &str,
    label: &str,
    a: &Account,
    b: &Account,
    mut body: String,
    mut path: String,
    mut query: String,
) -> (String, String, String) {
    let target = if action.starts_with("template-") {
        "961011"
    } else {
        "961001"
    };
    let method = super::route(action).0;
    if label == "foreign" {
        if matches!(
            action,
            "personal-update" | "personal-delete" | "retro-apply"
        ) {
            path = path.replace(target, "961002");
        }
        if action == "personal-list" {
            query = format!("?mailboxId={}", b.mailbox);
        }
        if action == "template-personal-list" {
            query = format!("?userId={}", b.user);
        }
    }
    match label {
        "invalid" => {
            if action == "retro-status" {
                path = path.replace("96100000-0000-4000-8000-000000000001", "bad");
            } else if method == "DELETE"
                || action == "admin-test"
                || (method == "GET" && path.contains(target))
            {
                path = path.replace(target, "bad");
            } else if method == "GET" {
                query = "?mailboxId=not-a-number&ignored=bad".into();
            } else {
                body = "{".into();
            }
        }
        "missing" | "foreign-rule" => {
            path = path.replace(
                target,
                if label == "missing" {
                    "99999999"
                } else {
                    "961002"
                },
            );
        }
        "transport" if path.contains("961001") => {
            path = path.replace("961001", "961003");
        }
        "system" => {
            path = path.replace("961011", "961012");
        }
        "disabled" => {
            path = path.replace("961011", "961013");
        }
        "empty-body" => {
            body = "{}".into();
        }
        "null-body" => {
            body = "null".into();
        }
        "bad-type" => {
            body = if action == "template-visibility-set" {
                r#"{"hidden":3}"#
            } else if action == "retro-apply" {
                r#"{"window":3}"#
            } else {
                r#"{"name":3}"#
            }
            .into();
        }
        "trailing" => {
            body.push_str(" ignored trailing bytes");
        }
        "folded" => {
            for (a, b) in [
                ("name", "NaMe"),
                ("conditions", "CONDITIONS"),
                ("actions", "AcTiOnS"),
                ("mailboxId", "MAILBOXID"),
                ("type", "TyPe"),
            ] {
                body = body.replace(&format!("\"{a}\""), &format!("\"{b}\""));
            }
        }
        "duplicate" => {
            body = body.trim_end_matches('}').to_owned() + ",\"NAME\":\"Last rule\",\"name\":null}";
        }
        "name-long" => set(&mut body, "name", json!("x".repeat(201))),
        "name-utf8" => set(&mut body, "name", json!("界".repeat(67))),
        "name-200" => set(&mut body, "name", json!("x".repeat(200))),
        "blank-name" => set(&mut body, "name", json!(" ")),
        "body-size" => set(&mut body, "name", json!("x".repeat(70 << 10))),
        "program-size" => set(
            &mut body,
            "conditions",
            json!([{"type":"contains","value":"x".repeat(17<<10)}]),
        ),
        "actions-size" => set(
            &mut body,
            "actions",
            json!([{"type":"mark_read","value":"x".repeat(17<<10)}]),
        ),
        "many-actions" => set(
            &mut body,
            "actions",
            json!(vec![json!({"type":"mark_read"}); 21]),
        ),
        "many-conditions" => set(
            &mut body,
            "conditions",
            json!(vec![json!({"type":"contains"}); 21]),
        ),
        "object-conditions" => set(&mut body, "conditions", json!({"any":true})),
        "object-actions" => set(&mut body, "actions", json!({"type":"mark_read"})),
        "scalar-entry" => set(&mut body, "conditions", json!([1])),
        "type-number" => set(&mut body, "actions", json!([{"type":3}])),
        "null-entry" => set(&mut body, "conditions", json!([null])),
        "null-program" => set(&mut body, "conditions", Value::Null),
        "missing-program" => remove(&mut body, &["conditions", "actions"]),
        "bad-run-on" => set(&mut body, "runOn", json!("bogus")),
        "bad-priority" => set(&mut body, "priority", json!(101)),
        "huge-priority" => set(&mut body, "priority", json!(1i64 << 40)),
        "bad-category" => set(&mut body, "category", json!("bogus")),
        "sort-overflow" => set(&mut body, "sortOrder", json!(1i64 << 40)),
        "transport-body" => {
            set(&mut body, "mailboxId", Value::Null);
            set(&mut body, "isTransportRule", json!(true));
        }
        "foreign-mailbox" => set(&mut body, "mailboxId", json!(b.mailbox)),
        "missing-mailbox" => set(&mut body, "mailboxId", json!(99999999)),
        "window-all" => body = r#"{"window":"all"}"#.into(),
        "window-1y" => body = r#"{"window":"1y"}"#.into(),
        "bad-window" => body = r#"{"window":"never"}"#.into(),
        "global-hide" => body = r#"{"userId":null,"hidden":true}"#.into(),
        "global-show" => {
            path = path.replace("961011", "961012");
            body = r#"{"userId":null,"hidden":false}"#.into();
        }
        "show-user" => body = format!(r#"{{"userId":{},"hidden":false}}"#, a.user),
        "unknown-user" => body = r#"{"userId":99999999,"hidden":true}"#.into(),
        "raw-surrogate" => {
            body = body.replace(
                "\"conditions\":[]",
                r#""conditions":[{"field":"subject","value":"\ud800"}]"#,
            );
        }
        "string-surrogate" => {
            body = body.replace("\"name\":\"Created rule\"", r#""name":"bad \ud800""#);
        }
        "encoded-id" => {
            path = path.replace(target, &format!("%2B{target}"));
        }
        "encoded-suffix" => {
            for (plain, encoded) in [
                ("/visibility", "/%76isibility"),
                ("/resolve", "/%72esolve"),
                ("/test", "/%74est"),
                ("/apply", "/%61pply"),
            ] {
                path = path.replace(plain, encoded);
            }
        }
        "mailbox-own" => query = format!("?mailboxId={}", a.mailbox),
        "mailbox-other" => query = format!("?mailboxId={}", b.mailbox),
        l if l.starts_with("block-") => set(
            &mut body,
            "actions",
            json!([{"type":l.strip_prefix("block-").unwrap()}]),
        ),
        _ => {}
    }
    if label.starts_with("from-template") {
        match label {
            "from-template-invalid" => body = "{".into(),
            "from-template-type" => body = r#"{"word":3}"#.into(),
            "from-template-null" => body = "null".into(),
            "from-template-unresolved" => body = "{}".into(),
            "from-template-missing" => query = "?from_template=99999999".into(),
            "from-template-bad-id" => query = "?from_template=bad".into(),
            "from-template-disabled" => query = "?from_template=961013".into(),
            "from-template-spoof" => {
                body = format!(
                    r#"{{"word":"news","mailboxId":"{}","isTransportRule":"true"}}"#,
                    b.mailbox
                )
            }
            _ => {}
        }
    }
    (body, path, query)
}
