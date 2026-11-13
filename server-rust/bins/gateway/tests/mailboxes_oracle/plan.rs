//! Fixtures and the request each (action, label) case sends.
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub const MISSING: i64 = 999_999_999;

pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub tu: i64,
    pub tm: i64,
    pub s: i64,
    pub u2: i64,
    pub ub: i64,
    pub guest: i64,
    pub proj: i64,
    pub child: i64,
    pub tf: i64,
    pub role: i64,
    pub a_domain: String,
    pub b_domain: String,
    /// Global admins who request purges (`req` in A, `reqb` in B) and the designated approver.
    pub req: i64,
    pub reqb: i64,
    pub appr: i64,
    /// A user whose only mailbox is primary: the reconnect cases retain and rebind it.
    pub ru: i64,
    pub rm: i64,
    pub req_role: i64,
    /// Lifecycle generations and the scheduled purge, known after `seed`.
    pub gen_s: i64,
    pub gen_b: i64,
    pub preview: String,
    pub purge: String,
    pub approval: i64,
    /// Schedule bodies embed a per-run preview digest, so their request digest is unverifiable.
    pub hide_request_digest: bool,
}

pub const KEY: &str = "5f0c1a52-8d3e-4b7a-9c61-0e2d4f6a8b10";
pub const KEY2: &str = "6a1d2b63-9e4f-4c8b-8d72-1f3e5a7b9c21";
pub const REASON: &str = "scheduled maintenance";

/// A retained mailbox has no owner, so previewing or scheduling a purge for it takes an
/// organization-wide admin; the cross-tenant and denial cases stay domain scoped.
pub fn needs_global(action: &str, label: &str) -> bool {
    match action {
        "purge" => !matches!(label, "foreign" | "denied" | "wrong-perm"),
        "preview" => label == "retained",
        _ => false,
    }
}

pub fn is_lifecycle(action: &str) -> bool {
    matches!(
        action,
        "preview"
            | "retained"
            | "parity"
            | "transition"
            | "purge"
            | "approval"
            | "execute"
            | "cancel"
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Mailbox,
    Folder,
}

pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub query: String,
    pub recorded_query: String,
    pub body: String,
    pub recorded_body: String,
    pub lifecycle: bool,
    pub language: Option<&'static str>,
    /// Whether a response `id` names a folder (else a mailbox).
    pub id_is_folder: bool,
    /// Extra request headers (sent form; the key and reason are fixed text).
    pub headers: Vec<(&'static str, String)>,
    /// Send the request once before the observed one.
    pub repeat: bool,
}

/// Governed permissions and domain scope of the admin for a case.
pub fn access(action: &str, label: &str) -> (Vec<&'static str>, bool) {
    if is_lifecycle(action) {
        let perms = match label {
            "denied" => vec!["users.read"],
            "wrong-perm" => vec!["users.create"],
            _ => vec!["users.delete"],
        };
        return (
            perms,
            !label.starts_with("global") && !needs_global(action, label),
        );
    }
    let read = matches!(action, "list" | "get" | "folders");
    let perms = match label {
        "denied" => vec!["users.read"],
        "wrong-perm" => {
            if read {
                vec!["users.create"]
            } else {
                vec!["domains.read"]
            }
        }
        _ if read => vec!["domains.read"],
        _ => vec!["users.create"],
    };
    let global = label.starts_with("global") || label == "missing-global";
    (perms, !global)
}

async fn user(c: &Client, domain: i64, email: &str, name: &str) -> Result<i64, BoxError> {
    Ok(c.query_one(
        "INSERT INTO users (username, domain_id, email, display_name, password_hash) VALUES ($1,$2,$1,$3,'x') RETURNING id",
        &[&email, &domain, &name],
    )
    .await?
    .get(0))
}

impl Fx {
    pub async fn build(c: &Client, label: &str, action: &str) -> Result<Fx, BoxError> {
        let a = fixture::account(c, "mbox1-admin").await?;
        let b = fixture::account(c, "mbox1-other").await?;
        let a_domain: String = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
            .await?
            .get(0);
        let b_domain: String = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&b.domain])
            .await?
            .get(0);
        let tu = user(c, a.domain, &format!("mbox1-t@{a_domain}"), "Target").await?;
        let tm: i64 = c.query_one("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'Target','personal',TRUE) RETURNING id",
            &[&tu, &a.domain, &format!("mbox1-t@{a_domain}")]).await?.get(0);
        let s: i64 = c.query_one("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'Secondary','personal',FALSE) RETURNING id",
            &[&tu, &a.domain, &format!("mbox1-s@{a_domain}")]).await?.get(0);
        let folder = |mb: i64, parent: Option<i64>, name: &'static str, path: &'static str| {
            let c = c;
            async move {
                let id: i64 = c.query_one("INSERT INTO folders (mailbox_id,parent_id,name,path) VALUES ($1,$2,$3,$4) RETURNING id", &[&mb, &parent, &name, &path]).await?.get(0);
                Ok::<i64, BoxError>(id)
            }
        };
        let proj = folder(s, None, "Projects", "Projects").await?;
        let child = folder(s, Some(proj), "2026", "Projects/2026").await?;
        let tf = folder(tm, None, "Elsewhere", "Elsewhere").await?;
        for (mb, name) in [(s, "Projects"), (s, "2026"), (tm, "Elsewhere")] {
            c.execute("INSERT INTO tags (mailbox_id,name,tag_type,sort_order,imap_expose) VALUES ($1,$2,'user',100,TRUE)", &[&mb, &name]).await?;
        }
        c.execute(
            "INSERT INTO aliases (mailbox_id,email,domain_id) VALUES ($1,$2,$3)",
            &[&s, &format!("mbox1-alias@{a_domain}"), &a.domain],
        )
        .await?;
        let inbox: i64 = c
            .query_one(
                "SELECT id FROM tags WHERE mailbox_id=$1 AND name='Inbox'",
                &[&s],
            )
            .await?
            .get(0);
        fixture::message(c, s, inbox, &[inbox], false).await?;
        // The frozen Go process recomputes used_bytes at startup; set what it would (the
        // replay has no Go process, and the list responses show the value).
        c.execute(
            "UPDATE mailboxes SET used_bytes=COALESCE((SELECT sum(size_bytes) FROM messages WHERE mailbox_id=mailboxes.id),0) WHERE domain_id=ANY($1)",
            &[&vec![a.domain, b.domain]],
        )
        .await?;
        // The frozen Go process recomputes used_bytes at startup; set what it would (the
        // replay has no Go process, and the list responses show the value).
        c.execute("UPDATE mailboxes SET used_bytes=COALESCE((SELECT sum(size_bytes) FROM messages WHERE mailbox_id=mailboxes.id),0) WHERE domain_id=ANY($1)", &[&vec![a.domain, b.domain]]).await?;
        let ru = user(
            c,
            a.domain,
            &format!("mbox1-ru@{a_domain}"),
            "Reconnect Owner",
        )
        .await?;
        let rm: i64 = c.query_one("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'Reconnect','personal',TRUE) RETURNING id",
            &[&ru, &a.domain, &format!("mbox1-rm@{a_domain}")]).await?.get(0);
        let u2 = user(c, a.domain, &format!("mbox1-u2@{a_domain}"), "Second User").await?;
        let ub = user(c, b.domain, &format!("mbox1-ub@{b_domain}"), "Other User").await?;
        let guest = user(c, a.domain, &format!("mbox1-guest@{a_domain}"), "Guest").await?;
        c.execute("INSERT INTO guest_accounts (user_id,invited_email,invited_by_email,host_domain_id) VALUES ($1,$2,$2,$3)", &[&guest, &format!("mbox1-guest@{a_domain}"), &a.domain]).await?;
        let req = user(c, a.domain, &format!("mbox1-req@{a_domain}"), "Requester").await?;
        let reqb = user(
            c,
            b.domain,
            &format!("mbox1-reqb@{b_domain}"),
            "Other Requester",
        )
        .await?;
        let appr = user(c, a.domain, &format!("mbox1-appr@{a_domain}"), "Approver").await?;
        let req_role: i64 = c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,NULL) RETURNING id", &[&format!("mbox1-req-role-{}", a.user), &vec!["users.delete".to_owned(), "users.read".to_owned()]]).await?.get(0);
        for who in [req, reqb] {
            c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)", &[&who, &req_role]).await?;
        }
        c.execute(
            "INSERT INTO user_lifecycle_authorities(user_id,authority_kind) VALUES($1,'local')",
            &[&u2],
        )
        .await?;
        let (perms, scoped) = access(action, label);
        let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let scope: Option<i64> = scoped.then_some(a.domain);
        let role: i64 = c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id", &[&format!("mbox1-role-{}", a.user), &perms, &scope]).await?.get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        Ok(Fx {
            a,
            b,
            tu,
            tm,
            s,
            u2,
            ub,
            guest,
            proj,
            child,
            tf,
            role,
            a_domain,
            b_domain,
            req,
            reqb,
            appr,
            ru,
            rm,
            req_role,
            gen_s: 0,
            gen_b: 0,
            preview: String::new(),
            purge: String::new(),
            approval: 0,
            hide_request_digest: false,
        })
    }

    async fn generation(c: &Client, mailbox: i64) -> Result<i64, BoxError> {
        Ok(c.query_one(
            "SELECT generation FROM mailbox_lifecycle WHERE mailbox_id=$1",
            &[&mailbox],
        )
        .await?
        .get(0))
    }

    /// Run one lifecycle transition the way an operator would (seed state, not under test).
    async fn lifecycle_step(
        c: &Client,
        actor: i64,
        mailbox: i64,
        action: &str,
    ) -> Result<(), BoxError> {
        let generation = Self::generation(c, mailbox).await?;
        c.query_one(
            "SELECT mailbox_lifecycle_transition($1,$2,gen_random_uuid(),$3,$4,repeat('a',64),'seed lifecycle reason',NULL,NULL,NULL,NULL,NULL,now(),NULL,NULL)::text",
            &[&actor, &mailbox, &action, &generation],
        )
        .await?;
        Ok(())
    }

    async fn schedule(
        &mut self,
        c: &Client,
        mailbox: i64,
        requester: i64,
        approver: i64,
    ) -> Result<(), BoxError> {
        let generation = Self::generation(c, mailbox).await?;
        let digest: String = c
            .query_one(
                "SELECT mailbox_lifecycle_preview($1,$2)->>'previewDigest'",
                &[&requester, &mailbox],
            )
            .await?
            .get(0);
        let row = c.query_one(
            "SELECT (r->>'purgeRequestId'), (r->>'approvalRequestId')::bigint FROM (SELECT mailbox_purge_schedule($1,$2,gen_random_uuid(),$3,$4,repeat('b',64),'seed purge reason',$5) r) x",
            &[&requester, &mailbox, &generation, &digest, &approver],
        )
        .await?;
        self.purge = row.get(0);
        self.approval = row.get(1);
        Ok(())
    }

    /// The database state a lifecycle case starts from (seeded the way an operator would).
    pub async fn seed(&mut self, c: &Client, action: &str, label: &str) -> Result<(), BoxError> {
        if !is_lifecycle(action) {
            return Ok(());
        }
        let (s, b) = (self.s, self.b.mailbox);
        let (req, reqb, appr, admin) = (self.req, self.reqb, self.appr, self.a.user);
        match (action, label) {
            ("preview", "retained") | ("retained", "success" | "global") => {
                Self::lifecycle_step(c, req, s, "detach_retain").await?
            }
            ("retained", "foreign") => Self::lifecycle_step(c, reqb, b, "detach_retain").await?,
            ("transition", "resume" | "resume-disabled") => {
                Self::lifecycle_step(c, req, s, "suspend").await?
            }
            ("transition", "idem-conflict") => {
                let generation = Self::generation(c, s).await?;
                c.query_one(
                    "SELECT mailbox_lifecycle_transition($1,$2,$3::text::uuid,'suspend',$4,repeat('c',64),'seed lifecycle reason',NULL,NULL,NULL,NULL,NULL,now(),NULL,NULL)::text",
                    &[&req, &s, &KEY, &generation],
                )
                .await?;
            }
            ("transition", l) if l.starts_with("reconnect") => {
                Self::lifecycle_step(c, req, self.rm, "detach_retain").await?
            }
            ("transition", "not-bound") => Self::lifecycle_step(c, req, s, "detach_retain").await?,
            ("purge", "not-retained") => {}
            ("purge", "foreign") => {
                Self::lifecycle_step(c, req, s, "detach_retain").await?;
                Self::lifecycle_step(c, reqb, b, "detach_retain").await?;
            }
            ("purge", _) => Self::lifecycle_step(c, req, s, "detach_retain").await?,
            ("approval", l) => {
                Self::lifecycle_step(c, req, s, "detach_retain").await?;
                let approver = if l == "foreign" { appr } else { admin };
                self.schedule(c, s, req, approver).await?;
            }
            ("execute", l) => {
                let (mailbox, requester) = if l == "foreign" { (b, reqb) } else { (s, req) };
                Self::lifecycle_step(c, requester, mailbox, "detach_retain").await?;
                let approver = if l == "self-approved" { admin } else { appr };
                self.schedule(c, mailbox, requester, approver).await?;
                if l != "not-approved" {
                    c.query_one(
                        "SELECT mailbox_purge_approval_apply($1,$2,'approve','')::text",
                        &[&self.approval, &approver],
                    )
                    .await?;
                }
                if l != "not-eligible" {
                    c.execute("UPDATE mailbox_purge_requests SET eligible_at=now()-interval '1 hour' WHERE id=$1::text::uuid", &[&self.purge]).await?;
                }
            }
            ("cancel", l) => {
                let (mailbox, requester) = if l == "foreign" { (b, reqb) } else { (s, req) };
                Self::lifecycle_step(c, requester, mailbox, "detach_retain").await?;
                self.schedule(c, mailbox, requester, appr).await?;
                if l == "uncancellable" {
                    c.execute("UPDATE mailbox_purge_requests SET state='completed' WHERE id=$1::text::uuid", &[&self.purge]).await?;
                }
            }
            _ => {}
        }
        let reconnecting = action == "transition" && label.starts_with("reconnect");
        self.gen_s = Self::generation(c, if reconnecting { self.rm } else { s })
            .await
            .unwrap_or(0);
        self.gen_b = Self::generation(c, b).await.unwrap_or(0);
        let target = if label == "foreign" { b } else { s };
        self.preview = c
            .query_one(
                "SELECT COALESCE((SELECT mailbox_lifecycle_preview($1,$2)->>'previewDigest'),'')",
                &[&req, &target],
            )
            .await
            .map(|r| r.get(0))
            .unwrap_or_default();
        Ok(())
    }

    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        for role in [self.role, self.req_role] {
            c.execute(
                "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
                &[&role],
            )
            .await?;
            c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
                .await?;
        }
        let domains = vec![self.a.domain, self.b.domain];
        // Lifecycle bookkeeping of this fixture's actors, including purges that already
        // deleted their mailbox.
        let actors = [self.a.user, self.req, self.reqb]
            .map(|u| u.to_string())
            .join(",");
        let ops = format!("SELECT operation_id FROM mailbox_lifecycle_operations WHERE actor_user_id IN ({actors}) OR operation_id IN ('{KEY}','{KEY2}')");
        c.batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM mailbox_lifecycle_effect_targets WHERE operation_id IN ({ops}); \
             DELETE FROM mailbox_lifecycle_effects WHERE operation_id IN ({ops}); \
             DELETE FROM mailbox_lifecycle_outbox WHERE operation_id IN ({ops}); \
             DELETE FROM mailbox_purge_requests WHERE requested_by IN ({actors}); \
             DELETE FROM approval_requests WHERE consumer_type='mailbox.purge' AND requester_user_id IN ({actors}); \
             DELETE FROM mailbox_binding_history WHERE actor_user_id IN ({actors}) OR operation_id IN ({ops}); \
             DELETE FROM mailbox_lifecycle_operations WHERE operation_id IN ({ops}); \
             DELETE FROM mailbox_tombstones WHERE purged_by IN ({actors}); COMMIT;"
        ))
        .await?;
        let keep = vec![self.a.mailbox, self.b.mailbox];
        c.execute(
            "DELETE FROM guest_accounts WHERE user_id=$1",
            &[&self.guest],
        )
        .await?;
        let rows = c
            .query(
                "SELECT id FROM mailboxes WHERE domain_id=ANY($1) AND id<>ALL($2)",
                &[&domains, &keep],
            )
            .await?;
        let extra: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
        c.execute("DELETE FROM messages WHERE mailbox_id=ANY($1)", &[&extra])
            .await?;
        let lock_free = "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY(ARRAY[";
        let list = extra
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if !extra.is_empty() {
            c.batch_execute(&format!("{lock_free}{list}]::bigint[]); COMMIT;"))
                .await?;
        }
        let users = [
            self.tu, self.u2, self.ub, self.guest, self.req, self.reqb, self.appr, self.ru,
        ]
        .map(|u| u.to_string())
        .join(",");
        // The deferred primary-mailbox rule needs mailboxes and their users gone in one commit.
        c.batch_execute(&format!(
            "BEGIN; DELETE FROM mailboxes WHERE id=ANY(ARRAY[{list}]::bigint[]); DELETE FROM users WHERE id IN ({users}); COMMIT;"
        ))
        .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }

    /// `(key, id, placeholder)`: every id a response, audit row or snapshot may carry.
    pub async fn ids(
        &self,
        c: &Client,
        id_is_folder: bool,
    ) -> Result<Vec<(&'static str, i64, String)>, BoxError> {
        let mut out: Vec<(&'static str, i64, String)> = vec![];
        let users = [
            (self.a.user, "<admin>"),
            (self.b.user, "<other>"),
            (self.tu, "<target>"),
            (self.u2, "<second>"),
            (self.ub, "<other-user>"),
            (self.guest, "<guest>"),
            (self.req, "<requester>"),
            (self.reqb, "<other-requester>"),
            (self.appr, "<approver>"),
            (self.ru, "<reconnect-owner>"),
        ];
        for key in [
            "userId",
            "user_id",
            "actor_id",
            "bound_user_id",
            "boundUserId",
            "target_user_id",
            "from_user_id",
            "to_user_id",
            "approverUserId",
            "updated_by",
            "created_by",
            "requested_by",
            "approved_by",
            "actor_user_id",
            "purged_by",
            "requester_user_id",
            "approver_ref",
        ] {
            for (id, name) in users {
                out.push((key, id, name.to_string()));
            }
        }
        let domains = vec![self.a.domain, self.b.domain];
        let mailboxes = c
            .query(
                "SELECT id, email FROM mailboxes WHERE domain_id=ANY($1)",
                &[&domains],
            )
            .await?;
        for row in &mailboxes {
            let (id, email): (i64, String) = (row.get(0), row.get(1));
            let name = format!(
                "<mailbox {}>",
                email
                    .replace(&self.a_domain, "host-a.test")
                    .replace(&self.b_domain, "host-b.test")
                    .replace(&self.a_email_domain(), "host-a.test")
            );
            for key in [
                "mailboxId",
                "mailbox_id",
                "target_id",
                "targetId",
                "target_mailbox_id",
            ] {
                out.push((key, id, name.clone()));
            }
            if !id_is_folder {
                out.push(("id", id, name));
            }
        }
        let folders = c.query("SELECT f.id, m.email, f.path FROM folders f JOIN mailboxes m ON m.id=f.mailbox_id WHERE m.domain_id=ANY($1)", &[&domains]).await?;
        for row in &folders {
            let (id, email, path): (i64, String, String) = (row.get(0), row.get(1), row.get(2));
            let name = format!(
                "<folder {}:{path}>",
                email
                    .replace(&self.a_domain, "host-a.test")
                    .replace(&self.b_domain, "host-b.test")
            );
            out.push(("parentId", id, name.clone()));
            if id_is_folder {
                out.push(("id", id, name));
            }
        }
        let requesters = vec![self.a.user, self.req, self.reqb];
        let approvals = c
            .query(
                "SELECT id FROM approval_requests WHERE consumer_type='mailbox.purge' AND requester_user_id=ANY($1)",
                &[&requesters],
            )
            .await?;
        for row in &approvals {
            let id: i64 = row.get(0);
            for key in ["approvalRequestId", "approval_request_id"] {
                out.push((key, id, "<approval>".to_string()));
            }
        }
        Ok(out)
    }

    fn a_email_domain(&self) -> String {
        self.a_domain.clone()
    }

    /// Domain names carry a per-run suffix.
    pub fn names(&self, text: &str) -> String {
        let text = text
            .replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test");
        if self.purge.is_empty() {
            text
        } else {
            text.replace(&self.purge, "<purge>")
        }
    }
}

fn get(pattern: &'static str, path: String) -> Plan {
    Plan {
        method: "GET",
        pattern,
        path,
        query: String::new(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        lifecycle: false,
        language: None,
        id_is_folder: false,
        headers: Vec::new(),
        repeat: false,
    }
}
fn with_body(
    method: &'static str,
    pattern: &'static str,
    path: String,
    body: impl Into<String>,
) -> Plan {
    let body = body.into();
    Plan {
        method,
        recorded_body: body.clone(),
        body,
        ..get(pattern, path)
    }
}

/// The request of an (action, label) case. Bodies use `<name>` tokens for ids; the sent
/// form substitutes real ids, the recorded form keeps the token.
pub fn plan(action: &str, label: &str, fx: &Fx) -> Plan {
    let mailbox_target = match label {
        "global" if action == "delete" => fx.s,
        "foreign" | "global" => fx.b.mailbox,
        "missing" | "missing-scoped" | "missing-global" => MISSING,
        "invalid" | "bad-id" => 0,
        _ => fx.s,
    };
    let sub = |text: &str| -> (String, String) {
        let real = text
            .replace("<s>", &fx.s.to_string())
            .replace("<t>", &fx.tu.to_string())
            .replace("<u2>", &fx.u2.to_string())
            .replace("<ub>", &fx.ub.to_string())
            .replace("<guest>", &fx.guest.to_string())
            .replace("<proj>", &fx.proj.to_string())
            .replace("<a-domain>", &fx.a_domain)
            .replace("<key2>", KEY2)
            .replace("<key>", KEY)
            .replace(
                "<gen>",
                &(if label == "foreign" && action != "execute" {
                    fx.gen_b
                } else {
                    fx.gen_s
                })
                .to_string(),
            )
            .replace("<digest>", &fx.preview)
            .replace("<approver>", &fx.appr.to_string())
            .replace("<admin>", &fx.a.user.to_string())
            .replace("<reason>", REASON)
            .replace("<other-admin>", &fx.b.user.to_string());
        (real, text.to_owned())
    };
    let json_body = |method: &'static str, pattern: &'static str, path: String, body: &str| {
        let (real, recorded) = sub(body);
        Plan {
            method,
            pattern,
            path,
            query: String::new(),
            recorded_query: String::new(),
            body: real,
            recorded_body: recorded,
            lifecycle: false,
            language: None,
            id_is_folder: false,
            headers: Vec::new(),
            repeat: false,
        }
    };
    let with_query = |mut p: Plan, query: &str| {
        let (real, recorded) = sub(query);
        p.query = real;
        p.recorded_query = recorded;
        p
    };
    let mut p = plan_inner(
        action,
        label,
        fx,
        &sub,
        &json_body,
        &with_query,
        mailbox_target,
    );
    if label == "repeat" {
        p.repeat = true;
    }
    p
}

fn plan_inner(
    action: &str,
    label: &str,
    fx: &Fx,
    sub: &dyn Fn(&str) -> (String, String),
    json_body: &dyn Fn(&'static str, &'static str, String, &str) -> Plan,
    with_query: &dyn Fn(Plan, &str) -> Plan,
    mailbox_target: i64,
) -> Plan {
    match action {
        "list" => {
            let p = get("/admin/mailboxes", "/admin/mailboxes".to_owned());
            let q = match label {
                "q" | "global-q" => "?q=mbox1-s",
                "q-escape" => "?q=%25%5F",
                "user" => "?user_id=<t>",
                "user-bad" => "?user_id=abc",
                "user-wins" => "?user_id=<t>&q=nothing-matches",
                "foreign" => "?user_id=<ub>",
                "invalid" => "?limit=abc&offset=-1",
                "paging" => "?limit=1&offset=1",
                "big-limit" => "?limit=1000",
                "big-offset" => "?offset=99999999999999999999",
                _ => "",
            };
            with_query(p, q)
        }
        "get" => get(
            "/admin/mailboxes/{id}",
            format!(
                "/admin/mailboxes/{}",
                match label {
                    "invalid" => "abc".into(),
                    "zero" => "0".into(),
                    "plus" => format!("+{}", fx.s),
                    _ => mailbox_target.to_string(),
                }
            ),
        ),
        "create" => {
            let body = match label {
                "success" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","displayName":"New Box","quotaBytes":1000}"#
                }
                "no-quota" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","displayName":"New Box"}"#
                }
                "display-email" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","quotaBytes":5}"#
                }
                "zero-quota" => r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","quotaBytes":0}"#,
                "foreign" => r#"{"userId":<ub>,"email":"mbox1-new@<a-domain>","quotaBytes":1000}"#,
                "invalid" => r#"{"userId":0,"email":""}"#,
                "bad-json" => r#"{"userId":"#,
                "typed" => r#"{"userId":"1","email":"x@y.test"}"#,
                "bad-email" => r#"{"userId":<t>,"email":"not-an-email","quotaBytes":1}"#,
                "dots" => r#"{"userId":<t>,"email":"a..b@example.test","quotaBytes":1}"#,
                "leading-dot" => r#"{"userId":<t>,"email":".ab@example.test","quotaBytes":1}"#,
                "no-dot-domain" => r#"{"userId":<t>,"email":"ab@localhost","quotaBytes":1}"#,
                "underscore-domain" => {
                    r#"{"userId":<t>,"email":"ab@ex_ample.test","quotaBytes":1}"#
                }
                "long-email" => {
                    return json_body(
                        "POST",
                        "/admin/mailboxes",
                        "/admin/mailboxes".into(),
                        &format!(
                            r#"{{"userId":<t>,"email":"{}@<a-domain>","quotaBytes":1}}"#,
                            "x".repeat(260)
                        ),
                    )
                }
                "type-group" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","type":"group","quotaBytes":1}"#
                }
                "type-personal" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","type":"personal","quotaBytes":1}"#
                }
                "unknown-user" => {
                    r#"{"userId":999999999,"email":"mbox1-new@<a-domain>","quotaBytes":1}"#
                }
                "guest" => r#"{"userId":<guest>,"email":"mbox1-new@<a-domain>","quotaBytes":1}"#,
                "no-primary" => {
                    r#"{"userId":<u2>,"email":"mbox1-new@<a-domain>","quotaBytes":1000}"#
                }
                "dup" => r#"{"userId":<t>,"email":"mbox1-s@<a-domain>","quotaBytes":1}"#,
                "folded" => {
                    r#"{"USERID":<t>,"Email":"mbox1-new@<a-domain>","QUOTABYTES":7,"extra":null}"#
                }
                "unicode-name" => {
                    r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","displayName":"<b>&é","quotaBytes":1}"#
                }
                _ => r#"{"userId":<t>,"email":"mbox1-new@<a-domain>","quotaBytes":1000}"#,
            };
            json_body("POST", "/admin/mailboxes", "/admin/mailboxes".into(), body)
        }
        "update" => {
            let body = match label {
                "success" | "global-success" | "foreign" | "missing" | "denied" | "wrong-perm" => {
                    r#"{"displayName":"Renamed","quotaBytes":2048,"enabled":false,"litigationHold":true,"deletedPurgeDays":30,"spamPurgeDays":7}"#
                }
                "partial" => r#"{"displayName":"Only Name"}"#,
                "empty" => r#"{}"#,
                "bad-json" => r#"{"displayName":"#,
                "typed" => r#"{"enabled":"yes"}"#,
                "huge-purge" => r#"{"deletedPurgeDays":3000000000}"#,
                "huge-purge-missing" => r#"{"deletedPurgeDays":3000000000}"#,
                "negative-quota" => r#"{"quotaBytes":-1}"#,
                "folded" => r#"{"DISPLAYNAME":"Folded","ENABLED":true,"unknown":1}"#,
                "null-fields" => {
                    r#"{"displayName":null,"quotaBytes":null,"deletedPurgeDays":null}"#
                }
                _ => r#"{"displayName":"Renamed"}"#,
            };
            let target = match label {
                "invalid" => "abc".to_string(),
                "huge-purge-missing" => MISSING.to_string(),
                _ => mailbox_target.to_string(),
            };
            json_body(
                "PUT",
                "/admin/mailboxes/{id}",
                format!("/admin/mailboxes/{target}"),
                body,
            )
        }
        "delete" => {
            let target = if label == "invalid" {
                "abc".to_string()
            } else {
                mailbox_target.to_string()
            };
            let mut p = get(
                "/admin/mailboxes/{id}",
                format!("/admin/mailboxes/{target}"),
            );
            p.method = "DELETE";
            p.lifecycle = label == "gate";
            p
        }
        "folders" => {
            let target = match label {
                "invalid" => "abc".to_string(),
                "zero" => "0".to_string(),
                _ => mailbox_target.to_string(),
            };
            let mut p = get(
                "/admin/mailboxes/{id}/folders",
                format!("/admin/mailboxes/{target}/folders"),
            );
            // Each listed folder's `id` names a folder, not the mailbox.
            p.id_is_folder = true;
            p
        }
        "folder-create" => {
            let target = match label {
                "invalid-mailbox" => "0".to_string(),
                _ => mailbox_target.to_string(),
            };
            let body = match label {
                "success" => r#"{"name":"Archive2"}"#,
                "parent" => r#"{"name":"Fresh","parentId":<proj>}"#,
                "parent-missing" => r#"{"name":"Fresh","parentId":999999999}"#,
                "parent-zero" => r#"{"name":"Fresh","parentId":0}"#,
                "parent-negative" => r#"{"name":"Fresh","parentId":-1}"#,
                "invalid" | "bad-json" => r#"{"name":"#,
                "name-empty" => r#"{"name":""}"#,
                "dup" => r#"{"name":"Projects"}"#,
                "path-clash" => r#"{"name":"Projects/2026"}"#,
                "typed" => r#"{"name":5}"#,
                "slash" => r#"{"name":"a/b"}"#,
                _ => r#"{"name":"Archive2"}"#,
            };
            let mut p = json_body(
                "POST",
                "/admin/mailboxes/{id}/folders",
                format!("/admin/mailboxes/{target}/folders"),
                body,
            );
            p.id_is_folder = true;
            p
        }
        "folder-update" | "folder-delete" => {
            let target = match label {
                "invalid-mailbox" => "0".to_string(),
                _ => mailbox_target.to_string(),
            };
            let folder = match label {
                "invalid" | "invalid-folder" => "0".to_string(),
                "bad-folder" => "abc".to_string(),
                "missing-folder" => MISSING.to_string(),
                "other-mailbox" => fx.tf.to_string(),
                "child" => fx.child.to_string(),
                _ => fx.proj.to_string(),
            };
            let pattern = "/admin/mailboxes/{id}/folders/{folderId}";
            let path = format!("/admin/mailboxes/{target}/folders/{folder}");
            if action == "folder-delete" {
                let mut p = get(pattern, path);
                p.method = "DELETE";
                p
            } else {
                let body = match label {
                    "success" | "foreign" | "denied" | "wrong-perm" | "missing-folder"
                    | "other-mailbox" | "global" => r#"{"name":"Work"}"#,
                    "child" => r#"{"name":"2027"}"#,
                    "collision" => r#"{"name":"Inbox"}"#,
                    "tag-clash" => r#"{"name":"2026"}"#,
                    "name-empty" => r#"{"name":""}"#,
                    "bad-json" => r#"{"name":"#,
                    "typed" => r#"{"name":true}"#,
                    "backslash" => r#"{"name":"a\\1b"}"#,
                    _ => r#"{"name":"Work"}"#,
                };
                json_body("PUT", pattern, path, body)
            }
        }
        "preview" | "retained" | "parity" | "transition" | "purge" | "approval" | "execute"
        | "cancel" => {
            let mut p = lifecycle_plan(action, label, fx, &json_body, &with_query);
            p.lifecycle = label != "disabled";
            p
        }
        _ => panic!("unknown mailboxes action {action}"),
    }
}

fn lifecycle_plan(
    action: &str,
    label: &str,
    fx: &Fx,
    json_body: &dyn Fn(&'static str, &'static str, String, &str) -> Plan,
    _with_query: &dyn Fn(Plan, &str) -> Plan,
) -> Plan {
    let target = match label {
        "foreign" => fx.b.mailbox.to_string(),
        "missing" => MISSING.to_string(),
        "invalid" => "0".to_string(),
        "bad-id" => "abc".to_string(),
        l if action == "transition" && l.starts_with("reconnect") => fx.rm.to_string(),
        _ => fx.s.to_string(),
    };
    let reason_header = REASON.to_string();
    let mut headers: Vec<(&'static str, String)> = vec![
        ("x-audit-reason", reason_header.clone()),
        ("idempotency-key", KEY.to_string()),
    ];
    match label {
        "reason-mismatch" => headers[0].1 = "a different reason".into(),
        "key-mismatch" => headers[1].1 = KEY2.into(),
        "key-missing" => {
            headers.pop();
        }
        "reason-short" => headers[0].1 = "short".into(),
        "key-bad" => headers[1].1 = "not-a-uuid".into(),
        "key-nil" => headers[1].1 = "00000000-0000-0000-0000-000000000000".into(),
        "key-urn" => headers[1].1 = format!("urn:uuid:{}", KEY.to_uppercase()),
        _ => {}
    }
    let key_text = match label {
        "key-mismatch" => KEY.to_string(),
        "key-bad" => "not-a-uuid".to_string(),
        "key-nil" => "00000000-0000-0000-0000-000000000000".to_string(),
        "key-urn" => format!("urn:uuid:{}", KEY.to_uppercase()),
        _ => KEY.to_string(),
    };
    let reason_text = match label {
        "reason-short" => "short",
        "reason-mismatch" => REASON,
        _ => REASON,
    };
    let with = |mut p: Plan| {
        p.headers = headers.clone();
        p
    };
    let jb = |method: &'static str, pattern: &'static str, path: String, body: String| {
        with(json_body(method, pattern, path, &body))
    };
    let shape = |body: String| -> String {
        match label {
            "bad-json" => "{\"action\":".into(),
            "null-body" => "null".into(),
            "array-body" => "[]".into(),
            "trailing" => format!("{body} {{}}"),
            "trailing-ws" => format!("{body} \n\t "),
            "unknown-field" => body.replacen('{', "{\"extra\":1,", 1),
            "folded" => body
                .replace("\"action\"", "\"ACTION\"")
                .replace("\"expectedGeneration\"", "\"EXPECTEDGENERATION\"")
                .replace("\"idempotencyKey\"", "\"IDEMPOTENCYKEY\"")
                .replace("\"reason\"", "\"REASON\""),
            "oversize" => format!("{body}{}", " ".repeat(70_000)),
            _ => body,
        }
    };
    match action {
        "preview" => with(get_with(
            "/admin/mailboxes/{id}/lifecycle/preview",
            format!("/admin/mailboxes/{target}/lifecycle/preview"),
        )),
        "retained" => with(get_with(
            "/admin/mailboxes/retained",
            "/admin/mailboxes/retained".into(),
        )),
        "parity" => with(get_with(
            "/admin/mailboxes/lifecycle/parity",
            "/admin/mailboxes/lifecycle/parity".into(),
        )),
        "transition" => {
            let (act, extra) = match label {
                "resume" | "resume-disabled" | "not-bound" => ("resume", String::new()),
                "detach" | "detach-rejecting" | "disabled" => ("detach_retain", if label == "detach-rejecting" { ",\"delivery\":\"rejecting\"".to_string() } else { String::new() }),
                "reconnect" => ("reconnect", ",\"targetUserId\":\"<u2>\",\"evidenceKind\":\"local_user\"".into()),
                "reconnect-link" => ("reconnect", ",\"targetUserId\":\"<u2>\",\"evidenceKind\":\"identity_link\",\"identityLinkId\":\"1\",\"linkGeneration\":\"1\"".into()),
                "reconnect-none" => ("reconnect", ",\"targetUserId\":\"<u2>\"".into()),
                "reconnect-primary" => ("reconnect", ",\"targetUserId\":\"<t>\",\"evidenceKind\":\"local_user\"".into()),
                "reconnect-bad-target" => ("reconnect", ",\"targetUserId\":\"x\"".into()),
                "evidence-bad" => ("suspend", ",\"identityLinkId\":\"0\"".into()),
                "delivery-bad" => ("suspend", ",\"delivery\":\"maybe\"".into()),
                "delivery-ok" => ("suspend", ",\"delivery\":\"accepting\"".into()),
                "redirect-set" => ("suspend", ",\"redirectAddress\":\"x@y.test\"".into()),
                "action-bad" => ("explode", String::new()),
                "idem-conflict" => ("resume", String::new()),
                _ => ("suspend", String::new()),
            };
            let generation = match label {
                "gen-bad" => "\"abc\"".to_string(),
                "gen-zero" => "\"0\"".into(),
                "stale" => "\"999\"".into(),
                _ => "\"<gen>\"".into(),
            };
            let body = format!(
                "{{\"action\":\"{act}\",\"expectedGeneration\":{generation},\"idempotencyKey\":\"{key_text}\",\"reason\":\"{reason_text}\"{extra}}}"
            );
            let mut p = jb(
                "POST",
                "/admin/mailboxes/{id}/lifecycle",
                format!("/admin/mailboxes/{target}/lifecycle"),
                shape(body),
            );
            p.repeat = label == "repeat";
            p
        }
        "purge" => {
            let (generation, digest, approver) = match label {
                "stale-gen" => ("999", "<digest>".to_string(), "<approver>"),
                "stale-digest" => ("<gen>", "f".repeat(64), "<approver>"),
                "short-digest" => ("<gen>", "abc".to_string(), "<approver>"),
                "upper-digest" => ("<gen>", "<digest-upper>".to_string(), "<approver>"),
                "same-approver" => ("<gen>", "<digest>".to_string(), "<admin>"),
                "approver-zero" => ("<gen>", "<digest>".to_string(), "0"),
                _ => ("<gen>", "<digest>".to_string(), "<approver>"),
            };
            let body = format!(
                "{{\"expectedGeneration\":\"{generation}\",\"previewDigest\":\"{digest}\",\"idempotencyKey\":\"{key_text}\",\"reason\":\"{reason_text}\",\"approverUserId\":\"{approver}\"}}"
            );
            let mut p = jb(
                "POST",
                "/admin/mailboxes/{id}/purge",
                format!("/admin/mailboxes/{target}/purge"),
                shape(body),
            );
            if label == "upper-digest" {
                p.body = p.body.replace("<digest-upper>", &fx.preview.to_uppercase());
                p.recorded_body = p.recorded_body.replace("<digest-upper>", "<DIGEST>");
            }
            p
        }
        "approval" => {
            let id = match label {
                "missing" => MISSING.to_string(),
                "invalid" => "0".into(),
                "bad-id" => "abc".into(),
                _ => fx.approval.to_string(),
            };
            let body = match label {
                "deny" => "{\"decision\":\"deny\",\"comment\":\"not now\"}".to_string(),
                "bad-decision" => "{\"decision\":\"maybe\"}".into(),
                "comment-long" => format!(
                    "{{\"decision\":\"approve\",\"comment\":\"{}\"}}",
                    "x".repeat(1025)
                ),
                _ => "{\"decision\":\"approve\",\"comment\":\"looks fine\"}".into(),
            };
            let body = match label {
                "bad-json" => "{\"decision\":".to_string(),
                "unknown-field" => body.replacen('{', "{\"extra\":1,", 1),
                _ => body,
            };
            let mut p = jb(
                "POST",
                "/admin/mailbox-purge-approvals/{id}",
                format!("/admin/mailbox-purge-approvals/{id}"),
                body,
            );
            p.headers.clear();
            p.repeat = label == "repeat";
            p
        }
        _ => {
            // execute / cancel
            let id = match label {
                "invalid" => "not-a-uuid".to_string(),
                "nil-uuid" => "00000000-0000-0000-0000-000000000000".into(),
                "missing" if action == "execute" => "7b7b7b7b-1111-4222-8333-444444444444".into(),
                "missing" => "7b7b7b7b-1111-4222-8333-444444444444".into(),
                _ => fx.purge.clone(),
            };
            let body =
                format!("{{\"idempotencyKey\":\"{key_text}\",\"reason\":\"{reason_text}\"}}");
            let pattern: &'static str = if action == "execute" {
                "/admin/mailbox-purges/{id}/execute"
            } else {
                "/admin/mailbox-purges/{id}/cancel"
            };
            let path = format!("/admin/mailbox-purges/{id}/{action}");
            let mut p = jb("POST", pattern, path, shape(body));
            p.repeat = label == "repeat";
            p
        }
    }
}

fn get_with(pattern: &'static str, path: String) -> Plan {
    get(pattern, path)
}
