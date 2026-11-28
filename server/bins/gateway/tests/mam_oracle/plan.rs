//! Independent MAM HTTP requests and disposable two-domain seed.
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;
pub struct Fx {
    pub a: Account,
    pub b: Account,
    role: i64,
    a_domain: String,
    b_domain: String,
    saved: String,
    saved_groups: String,
}
pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub query: String,
    pub body: String,
    pub recorded_body: String,
    pub repeat: bool,
    pub head: bool,
}
pub fn is_read(action: &str) -> bool {
    matches!(action, "policies" | "devices" | "events")
}
impl Fx {
    pub async fn build(c: &Client, label: &str, action: &str) -> Result<Self, BoxError> {
        let a = fixture::account(c, "dev2-admin").await?;
        let b = fixture::account(c, "dev2-other").await?;
        let a_domain = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
            .await?
            .get(0);
        let b_domain = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&b.domain])
            .await?
            .get(0);
        let perm = match label {
            "denied" => "users.read",
            "wrong-perm" if is_read(action) => "mam.write",
            "wrong-perm" => "mam.read",
            _ if is_read(action) => "mam.read",
            _ => "mam.write",
        };
        let domain = matches!(
            label,
            "foreign" | "scoped" | "rls-scoped" | "scope-error" | "evidence-scope-error"
        )
        .then_some(a.domain);
        let role=c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,ARRAY[$2::text],$3) RETURNING id", &[&format!("dev2-role-{}",a.user),&perm,&domain]).await?.get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        let saved = c
            .query_one(
                "SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text FROM device_policy p",
                &[],
            )
            .await?
            .get(0);
        let saved_groups=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text FROM device_policy_groups p", &[]).await?.get(0);
        c.batch_execute("DELETE FROM device_policy; DELETE FROM device_policy_groups")
            .await?;
        Ok(Self {
            a,
            b,
            role,
            a_domain,
            b_domain,
            saved,
            saved_groups,
        })
    }
    pub async fn seed(&self, c: &Client, action: &str, label: &str) -> Result<(), BoxError> {
        if matches!(
            action,
            "devices" | "events" | "lock" | "unlock" | "device-set" | "device-delete"
        ) && label != "empty"
        {
            let a = self.a.user;
            let b = self.b.user;
            c.batch_execute(&format!("INSERT INTO devices(id,user_id,fingerprint,hmac_secret,device_name,platform) VALUES (984001,{a},'00000000-0000-4000-8000-00000000e001','secret','Own phone','ios'),(983001,{b},'00000000-0000-4000-8000-00000000e002','secret','Other phone','android'); INSERT INTO device_registry(id,user_id,device_hash,device_fingerprint,first_seen,last_seen) VALUES(983001,{a},'own','00000000-0000-4000-8000-00000000e001',now()-interval '3 days',now()-interval '2 hours'),(983002,{b},'other','00000000-0000-4000-8000-00000000e002',now()-interval '4 days',now()-interval '1 hour'),(983003,{a},'collision','00000000-0000-4000-8000-00000000e002',now()-interval '2 days',now()-interval '3 hours'),(983004,{a},'no-fingerprint',NULL,now()-interval '1 day',now()-interval '4 hours'); INSERT INTO mdm_device_state(device_id,user_id,platform,device_name,os_version,app_version,compliance_status,wipe_requested,last_checkin_at,created_at) VALUES('00000000-0000-4000-8000-00000000e001',{a},'ios','Own <phone> & device','17.2','2.1','compliant','none',now()-interval '30 minutes',now()-interval '2 days'),('00000000-0000-4000-8000-00000000e002',{b},'android','Other phone','14','2.0','non_compliant','pending',now()-interval '1 hour',now()-interval '3 days'); INSERT INTO device_events(device_id,event_type,severity,details,occurred_at) VALUES(984001,'device_locked','warn','{{\"locked_by\":\"seed\"}}',now()-interval '2 hours'),(984001,'device_unlocked','info','{{}}',now()-interval '1 hour'),(983001,'device_locked','warn','{{\"private\":true}}',now()-interval '3 hours'); INSERT INTO device_policy(id,device_id,policy_key,policy_value,updated_at) VALUES(981002,984001,'require_pin','true',now()-interval '1 day'),(981003,983001,'private','other',now()-interval '1 day');")).await?;
        }
        if label != "empty" {
            c.batch_execute("INSERT INTO device_policy(id,policy_key,policy_value,updated_at) VALUES(981001,'require_pin','true',now()-interval '1 day'); INSERT INTO device_policy_groups(id,policy_key,policy_value,group_type,group_id,updated_at) VALUES(982001,'pin_length','6','role',5,now()-interval '1 day'); SELECT setval(pg_get_serial_sequence('device_policy','id'),981100,false); SELECT setval(pg_get_serial_sequence('device_policy_groups','id'),982100,false);").await?;
        }
        if label == "numeric-details" {
            c.batch_execute(r#"INSERT INTO device_events(device_id,event_type,severity,details,occurred_at) VALUES(984001,'device_locked','warn','{"whole":1.0,"big":9007199254740993,"small":0.0000001,"fixed":100000000000000000000,"scientific":1000000000000000000000,"nested":[1.0,{"minus":-0.0}]}',now()-interval '30 minutes')"#).await?;
        }
        if label == "no-events" {
            c.batch_execute("DELETE FROM device_events WHERE device_id=984001")
                .await?;
        }
        if label == "escaped-key" {
            if action == "group-delete" {
                c.batch_execute("INSERT INTO device_policy_groups(policy_key,policy_value,group_type,group_id) VALUES('pin/a+b <&>','yes','role',5)").await?;
            } else {
                c.batch_execute("INSERT INTO device_policy(device_id,policy_key,policy_value) VALUES(984001,'pin/a+b <&>','yes')").await?;
            }
        }
        Ok(())
    }
    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        c.batch_execute("DELETE FROM device_policy; DELETE FROM device_policy_groups")
            .await?;
        c.execute("INSERT INTO device_policy SELECT * FROM jsonb_populate_recordset(NULL::device_policy,$1::text::jsonb)",&[&self.saved]).await?;
        c.execute("INSERT INTO device_policy_groups SELECT * FROM jsonb_populate_recordset(NULL::device_policy_groups,$1::text::jsonb)",&[&self.saved_groups]).await?;
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&self.role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }
    pub fn ids(&self) -> Vec<(&'static str, i64, String)> {
        vec![
            ("user_id", self.a.user, "<admin>".into()),
            ("user_id", self.b.user, "<other>".into()),
            ("actor_id", self.a.user, "<admin>".into()),
        ]
    }
    pub fn names(&self, text: &str) -> String {
        text.replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test")
    }
}
pub fn plan(action: &str, label: &str, _fx: &Fx) -> Plan {
    let (method, pattern) = match action {
        "policies" => ("GET", "/admin/mam/policies"),
        "global" => ("PUT", "/admin/mam/policies"),
        "group" => ("PUT", "/admin/mam/policies/group"),
        "group-delete" => ("DELETE", "/admin/mam/policies/group/{type}/{id}/{key}"),
        "devices" => ("GET", "/admin/mam/devices"),
        "events" => ("GET", "/admin/mam/devices/{device_id}/events"),
        "lock" => ("POST", "/admin/mam/devices/{device_id}/lock"),
        "unlock" => ("POST", "/admin/mam/devices/{device_id}/unlock"),
        "device-set" => ("PUT", "/admin/mam/devices/{device_id}/policy"),
        "device-delete" => ("DELETE", "/admin/mam/devices/{device_id}/policy/{key}"),
        _ => unreachable!("{action}"),
    };
    let mut body = match action {
        "global" => r#"{"policies":{"require_pin":"false"}}"#.to_owned(),
        "group" => r#"{"group_type":"role","group_id":5,"policies":{"pin_length":"8"}}"#.to_owned(),
        "device-set" => r#"{"policies":{"require_pin":"false","pin_length":"6"}}"#.to_owned(),
        _ => String::new(),
    };
    let map_body = |map: &str| {
        if action == "group" {
            format!(r#"{{"group_type":"role","group_id":5,"policies":{map}}}"#)
        } else {
            format!(r#"{{"policies":{map}}}"#)
        }
    };
    match label {
        "duplicate-null"=>body=r#"{"group_type":"role","group_type":null,"group_id":5,"group_id":null,"policies":{"pin_length":"8"}}"#.into(),
        "unicode-field"=>body=map_body(r#"{"require_pin":"false"}"#).replace("policies","policieſ"),
        "null" => body = "null".into(),
        "empty-map" => body = map_body("{}"),
        "missing-map" => body = "{}".into(),
        "typed-map" => body = map_body("[]"),
        "typed-value" => body = map_body(r#"{"require_pin":5}"#),
        "null-value" => body = map_body(r#"{"require_pin":null}"#),
        "case-keys" => body = map_body(r#"{"require_pin":"false"}"#).replace("policies", "POLICIES"),
        "duplicate-fields" => body = r#"{"policies":{"require_pin":"true"},"POLICIES":{"pin_length":"8","require_pin":"false"}}"#.into(),
        "trailing" => body.push_str(" trailing bytes"),
        "html" => body = map_body(r#"{"require_pin":"<b>&é</b>\u2028"}"#),
        "bad-json" => body = "{".into(),
        "ignored-body" => body = "not JSON at all".into(),
        "spoofed-owner" => body = r#"{"user_id":9999999,"device_id":983002,"domain_scope":0,"policies":{"require_pin":"false"}}"#.into(),
        "no-type" => body = r#"{"policies":{"x":"y"}}"#.into(),
        "bad-type" if action == "group" => body = body.replace("role", "security_group"),
        "zero-id" if action == "group" => body = body.replace(":5,", ":0,"),
        "negative-id" if action == "group" => body = body.replace(":5,", ":-5,"),
        "typed-id" => body = body.replace(":5,", ":\"5\","),
        "invalid" if action == "global" || action == "group" => body = "{".into(),
        _ => {},
    }
    let device = match label {
        "foreign" => "983002",
        "registry-only" => "983003",
        "no-fingerprint" => "983004",
        "missing" => "999999999",
        "zero-id" => "0",
        "negative-id" => "-1",
        "plus-id" => "%2B983001",
        "invalid" => "bad-id",
        _ => "983001",
    };
    let mut path = pattern
        .replace("{device_id}", device)
        .replace("{type}", "role")
        .replace("{id}", "5")
        .replace("{key}", "require_pin");
    if action == "group-delete" {
        path = "/admin/mam/policies/group/role/5/pin_length".into();
        match label {
            "invalid" => path = path.replace("/5/", "/bad-id/"),
            "missing" => path = path.replace("pin_length", "missing"),
            "bad-type" => path = path.replace("/role/", "/invalid/"),
            "plus-id" => path = path.replace("/5/", "/%2B5/"),
            _ => {}
        }
    }
    if label == "missing-key" {
        path = path.replace("require_pin", "missing");
    }
    if label == "escaped-key" {
        let key = if action == "group-delete" {
            "pin_length"
        } else {
            "require_pin"
        };
        path = path.replace(key, "pin%2Fa%2Bb%20%3C%26%3E");
    }
    let query = match label {
        "invalid" if is_read(action) && action != "events" => "?limit=garbage",
        "limit-one" => "?limit=1",
        "limit-bad" => "?limit=garbage",
        "limit-big" => "?limit=201",
        "offset" => "?limit=1&offset=100",
        _ => "",
    };
    Plan {
        method,
        pattern,
        path,
        query: query.into(),
        recorded_body: body.clone(),
        body,
        repeat: label == "repeat",
        head: label == "head",
    }
}
