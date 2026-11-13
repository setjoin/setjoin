//! Cases of the mailbox import/export oracle: one request each, over fixtures
//! built per case (admin `a` and target mailboxes in domain A, a foreign account
//! `b`), with the message bytes the import posts and the messages the export
//! finds already stored.
use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;

pub struct Fx {
    pub a: Account,
    pub b: Account,
    pub tu: i64,
    /// Secondary mailbox of the target user: folder "Projects" and a tag of that name.
    pub s: i64,
    /// Owner-less (shared) mailbox of domain A.
    pub shared: i64,
    pub folder: i64,
    pub role: i64,
    pub a_domain: String,
}

async fn user(c: &Client, domain: i64, email: &str) -> Result<i64, BoxError> {
    Ok(c.query_one(
        "INSERT INTO users (username, domain_id, email, display_name, password_hash) VALUES ($1,$2,$1,'T','x') RETURNING id",
        &[&email, &domain],
    )
    .await?
    .get(0))
}

impl Fx {
    pub async fn build(c: &Client, perms: &[&str], scoped: bool) -> Result<Fx, BoxError> {
        let a = fixture::account(c, "mbox5-admin").await?;
        let b = fixture::account(c, "mbox5-other").await?;
        let a_domain: String = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
            .await?
            .get(0);
        let tu = user(c, a.domain, &format!("mbox5-t@{a_domain}")).await?;
        c.execute("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'Target','personal',TRUE)", &[&tu, &a.domain, &format!("mbox5-t@{a_domain}")]).await?;
        let s: i64 = c.query_one("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,'Secondary','personal',FALSE) RETURNING id",
            &[&tu, &a.domain, &format!("mbox5-s@{a_domain}")]).await?.get(0);
        let shared: i64 = c.query_one("INSERT INTO mailboxes (user_id,domain_id,email,display_name,type,is_primary) VALUES (NULL,$1,$2,'Shared','personal',FALSE) RETURNING id",
            &[&a.domain, &format!("mbox5-shared@{a_domain}")]).await?.get(0);
        let folder: i64 = c.query_one("INSERT INTO folders (mailbox_id,name,path) VALUES ($1,'Projects','Projects') RETURNING id", &[&s]).await?.get(0);
        c.execute("INSERT INTO tags (mailbox_id,name,tag_type,sort_order,imap_expose) VALUES ($1,'Projects','user',100,TRUE)", &[&s]).await?;
        let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
        let scope: Option<i64> = scoped.then_some(a.domain);
        let role: i64 = c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ($1,$2,$3) RETURNING id", &[&format!("mbox5-role-{}", a.user), &perms, &scope]).await?.get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        Ok(Fx {
            a,
            b,
            tu,
            s,
            shared,
            folder,
            role,
            a_domain,
        })
    }

    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&self.role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        let rows = c
            .query(
                "SELECT id FROM mailboxes WHERE domain_id=ANY($1) AND id<>ALL($2)",
                &[
                    &vec![self.a.domain, self.b.domain],
                    &vec![self.a.mailbox, self.b.mailbox],
                ],
            )
            .await?;
        let extra: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
        c.execute("DELETE FROM messages WHERE mailbox_id=ANY($1)", &[&extra])
            .await?;
        let list = extra
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if !extra.is_empty() {
            c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY(ARRAY[{list}]::bigint[]); COMMIT;")).await?;
        }
        let tu = self.tu;
        let mut sql = String::from("BEGIN;");
        if !extra.is_empty() {
            sql.push_str(&format!(
                "DELETE FROM mailboxes WHERE id=ANY(ARRAY[{list}]::bigint[]);"
            ));
        }
        sql.push_str(&format!("DELETE FROM users WHERE id={tu}; COMMIT;"));
        c.batch_execute(&sql).await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum Target {
    Mine,
    Shared,
    Foreign,
    Missing,
    Raw(&'static str),
}

/// A message already in the mailbox before an export: `(message_id, body, tag, stored, date)`.
pub struct Seed {
    pub message_id: &'static str,
    pub body: Vec<u8>,
    pub tag: Option<&'static str>,
    pub stored: bool,
    pub date: &'static str,
}

pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub target: Target,
    pub query: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub perms: Vec<&'static str>,
    pub scoped: bool,
    pub seeds: Vec<Seed>,
    pub repeat: bool,
    pub want: u16,
    pub summary: serde_json::Value,
}

const B: &str = "----mbox5boundary";

pub fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
    let mut body = Vec::new();
    for (name, file, data) in parts {
        body.extend_from_slice(
            format!("--{B}\r\nContent-Disposition: form-data; name=\"{name}\"").as_bytes(),
        );
        if let Some(file) = file {
            body.extend_from_slice(
                format!("; filename=\"{file}\"\r\nContent-Type: application/octet-stream")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{B}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={B}"), body)
}

const PLAIN: &str = "From: Alice <alice@example.com>\r\nTo: bob@example.com, \"C, D\" <c@d.co>\r\nCc: e@f.co\r\nSubject: Hello\r\nMessage-ID: <plain-1@example.com>\r\nDate: Mon, 02 Jan 2006 15:04:05 GMT\r\n\r\nHello body\r\n\r\nsecond para\r\n";
const NOID: &str = "From: carol@example.com\r\nSubject: No id, no date\r\n\r\nbody without ids\r\n";
const MULTI: &str = "From: =?UTF-8?Q?J=C3=BCrgen?= <j@example.de>\r\nTo: x@y.co\r\nSubject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=\r\nMessage-ID: <multi-1@example.com>\r\nDate: Sunday, 06-Nov-94 08:49:37 GMT\r\nContent-Type: multipart/alternative; boundary=XYZ\r\n\r\npreamble\r\n--XYZ\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain part\r\n--XYZ\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>html part</p>\r\n--XYZ--\r\nepilogue\r\n";

fn latin2() -> Vec<u8> {
    let mut m = b"From: p@example.pl\r\nSubject: =?ISO-8859-1?Q?caf=E9?=\r\nMessage-ID: <latin2-1@example.pl>\r\nContent-Type: text/plain; charset=ISO-8859-2\r\n\r\n".to_vec();
    m.extend_from_slice(b"\xb1\xe6\xea body");
    m
}
fn sjis() -> Vec<u8> {
    let mut m = b"From: j@example.jp\r\nMessage-ID: <sjis-1@example.jp>\r\nContent-Type: multipart/mixed; boundary=S\r\n\r\n--S\r\nContent-Type: text/plain; charset=shift_jis\r\n\r\n".to_vec();
    m.extend_from_slice(b"\x93\xfa\x96\x7b");
    m.extend_from_slice(b"\r\n--S--\r\n");
    m
}

fn eml_upload(name: &str, data: &[u8]) -> (String, Vec<u8>) {
    multipart(&[("file", Some(name), data)])
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    // Stored entries, written by hand so the fixture does not depend on a ZIP crate.
    let mut out = Vec::new();
    let mut dir = Vec::new();
    for (name, data) in entries {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let off = out.len() as u32;
        out.extend_from_slice(&0x04034b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        dir.extend_from_slice(&0x02014b50u32.to_le_bytes());
        dir.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        dir.extend_from_slice(&crc.sum().to_le_bytes());
        dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
        dir.extend_from_slice(&(data.len() as u32).to_le_bytes());
        dir.extend_from_slice(&(name.len() as u16).to_le_bytes());
        dir.extend_from_slice(&[0; 12]);
        dir.extend_from_slice(&off.to_le_bytes());
        dir.extend_from_slice(name.as_bytes());
    }
    let start = out.len() as u32;
    out.extend_from_slice(&dir);
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(dir.len() as u32).to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn mbox(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(b"From sender@example.com Mon Jan  2 15:04:05 2006\n");
        out.extend_from_slice(p);
        if !p.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    out
}

fn lf(s: &str) -> Vec<u8> {
    s.replace("\r\n", "\n").into_bytes()
}

fn import(label: &str) -> Plan {
    let (ct, body, summary): (String, Vec<u8>, &str) = match label {
        "success-eml" | "repeat" | "cross-tenant" | "invalid-id" | "zero-id" | "missing"
        | "denied" | "wrong-perm" | "shared" | "global" | "bad-query" | "folder-query" => {
            let (c, b) = eml_upload("one.eml", PLAIN.as_bytes());
            (c, b, "eml plain")
        }
        "success-mbox" => {
            let (c, b) = eml_upload(
                "box.mbox",
                &mbox(&[
                    PLAIN.as_bytes(),
                    NOID.as_bytes(),
                    MULTI.as_bytes(),
                    b"   \n",
                    &latin2(),
                    &sjis(),
                ]),
            );
            (c, b, "mbox six")
        }
        "success-zip" => {
            let z = zip_of(&[
                ("a.eml", PLAIN.as_bytes()),
                ("dir/b.EML", NOID.as_bytes()),
                ("notes.txt", b"skipped"),
                ("c.eml", MULTI.as_bytes()),
            ]);
            let (c, b) = eml_upload("mail.ZIP", &z);
            (c, b, "zip three eml")
        }
        "zip-corrupt" => {
            let (c, b) = eml_upload("bad.zip", b"PK\x03\x04 definitely not a zip");
            (c, b, "zip corrupt")
        }
        "zip-bad-entry" => {
            let mut z = zip_of(&[("a.eml", PLAIN.as_bytes()), ("b.eml", NOID.as_bytes())]);
            // Flip a payload byte of the first entry: its CRC no longer matches.
            let at = z.windows(5).position(|w| w == b"Hello").unwrap();
            z[at] ^= 0x20;
            let (c, b) = eml_upload("crc.zip", &z);
            (c, b, "zip crc mismatch")
        }
        "zip-empty" => {
            let (c, b) = eml_upload("empty.zip", &zip_of(&[]));
            (c, b, "zip no entries")
        }
        "zip-odd-name" => {
            let z = zip_of(&[("caf\u{e9}<&>.eml", PLAIN.as_bytes())]);
            let (c, b) = eml_upload("odd.zip", &z);
            (c, b, "zip utf8 name with markup")
        }
        "charsets" => {
            let (c, b) = eml_upload("cs.mbox", &mbox(&[&latin2(), &sjis(), b"From: g@example.cn\r\nMessage-ID: <gbk-1@e.cn>\r\nContent-Type: text/plain; charset=gbk\r\n\r\n\xc4\xe3\xba\xc3\r\n", b"From: k@example.ru\r\nMessage-ID: <koi-1@e.ru>\r\nContent-Type: text/plain; charset=koi8-r\r\n\r\n\xf0\xd2\xc9\xd7\xc5\xd4\r\n", b"From: u@example.com\r\nMessage-ID: <bogus-1@e.com>\r\nContent-Type: text/plain; charset=bogus\r\n\r\ncaf\xe9\r\n"]));
            (c, b, "mbox charsets")
        }
        "headers" => {
            let m = "From: \"Doe, John\" <john@example.com> (ignored)\r\nTo: undisclosed-recipients:;\r\nCc: a@b.co, ???, c@d.co\r\nBcc: Hidden <h@d.co>\r\nSubject: =?UTF-8?Q?caf=C3=A9_au_lait?=\r\nIn-Reply-To: <a@b>\r\nReferences: <a@b>\r\n <c@d>\r\nMessage-ID: <headers-1@e.com>\r\nDate: Sun Nov  6 08:49:37 1994\r\nList-Id: <list.example.com>\r\n\r\nbody\r\n";
            let (c, b) = eml_upload("h.eml", m.as_bytes());
            (c, b, "eml headers")
        }
        "headers-odd" => {
            let m = "From: a@[192.168.0.1]\r\nTo: Zo\u{eb} <z@ex\u{e4}mple.com>\r\nSubject: Re: =?bogus?Q?x?=\r\nMessage-ID: <odd-1@e.com>\r\nDate: Mon, 02 Jan 2006 15:04:05 -0700\r\n\r\nrfc2822 date is not an http date\r\n";
            let (c, b) = eml_upload("odd.eml", m.as_bytes());
            (c, b, "eml odd headers")
        }
        "lf-eml" => {
            let (c, b) = eml_upload("lf.eml", &lf(MULTI));
            (c, b, "eml lf multipart")
        }
        "nul-body" => {
            let (c, b) = eml_upload(
                "nul.eml",
                b"From: n@e.com\r\nSubject: nul\r\nMessage-ID: <nul-1@e.com>\r\n\r\nab\x00cd",
            );
            (c, b, "eml nul byte")
        }
        "invalid-utf8" => {
            let (c, b) = eml_upload(
                "bad.eml",
                b"From: n@e.com\r\nSubject: caf\xe9\r\nMessage-ID: <u8-1@e.com>\r\n\r\nbody",
            );
            (c, b, "eml invalid utf-8 subject")
        }
        "empty-eml" => {
            let (c, b) = eml_upload("empty.eml", b"");
            (c, b, "eml empty")
        }
        "mbox-empty" => {
            let (c, b) = eml_upload("empty.mbox", b"");
            (c, b, "mbox empty")
        }
        "mbox-no-separator" => {
            let (c, b) = eml_upload("plain.mbox", PLAIN.as_bytes());
            (c, b, "mbox without From_ line")
        }
        "mbox-short-from" => {
            let (c, b) = eml_upload("short.mbox", b"From \nSubject: x\n\nbody\nFrom a b\nSubject: y\nMessage-ID: <y@e.com>\n\nbody y\n");
            (c, b, "mbox short from lines")
        }
        "unsupported" => {
            let (c, b) = eml_upload("notes.txt", b"text");
            (c, b, "unsupported type")
        }
        "trailing-slash-name" => {
            let (c, b) = eml_upload("dir/inside.eml/", PLAIN.as_bytes());
            (c, b, "filename with slashes")
        }
        "no-file" => {
            let (c, b) = multipart(&[("other", None, b"x")]);
            (c, b, "no file part")
        }
        "file-without-name" => {
            let (c, b) = multipart(&[("file", None, PLAIN.as_bytes())]);
            (c, b, "file part without filename")
        }
        "bad-multipart" => ("application/json".into(), b"{}".to_vec(), "json body"),
        "folder" | "folder-form" | "folder-missing" | "folder-zero" => {
            let (c, b) = match label {
                "folder-form" => multipart(&[
                    ("folder_id", None, b"__FOLDER__"),
                    ("file", Some("f.eml"), PLAIN.as_bytes()),
                ]),
                _ => eml_upload("f.eml", PLAIN.as_bytes()),
            };
            (c, b, "eml with folder")
        }
        other => panic!("unknown import case {other}"),
    };
    let (perms, scoped): (Vec<&'static str>, bool) = match label {
        "denied" => (vec![], true),
        "wrong-perm" => (vec!["users.read"], true),
        "global" | "shared" => (vec!["users.create"], false),
        _ => (vec!["users.create"], true),
    };
    let target = match label {
        "cross-tenant" => Target::Foreign,
        "invalid-id" => Target::Raw("abc"),
        "zero-id" => Target::Raw("0"),
        "missing" => Target::Missing,
        "shared" => Target::Shared,
        _ => Target::Mine,
    };
    let want = match label {
        "cross-tenant" | "denied" | "wrong-perm" => 403,
        "invalid-id" | "zero-id" | "unsupported" | "no-file" | "file-without-name"
        | "bad-multipart" | "bad-query" => 400,
        "missing" => 404,
        _ => 200,
    };
    let query = match label {
        "folder" => "?folder_id=__FOLDER__".into(),
        "folder-query" => "?folder_id=__FOLDER__".into(),
        "folder-missing" => "?folder_id=999999999".into(),
        "folder-zero" => "?folder_id=0".into(),
        "bad-query" => "?folder_id=%zz".into(),
        _ => String::new(),
    };
    Plan {
        method: "POST",
        pattern: "/admin/mailboxes/{id}/import",
        target,
        query,
        content_type: ct,
        body,
        perms,
        scoped,
        seeds: vec![],
        repeat: label == "repeat",
        want,
        summary: serde_json::json!(summary),
    }
}

fn seed(
    message_id: &'static str,
    body: &str,
    tag: Option<&'static str>,
    stored: bool,
    date: &'static str,
) -> Seed {
    Seed {
        message_id,
        body: body.as_bytes().to_vec(),
        tag,
        stored,
        date,
    }
}

fn export(label: &str) -> Plan {
    let mut seeds = vec![
        seed(
            "<e1@example.com>",
            "Subject: one\r\n\r\nfirst message\r\n",
            None,
            true,
            "2026-01-01T10:00:00Z",
        ),
        seed(
            "<e2@example.com>",
            "Subject: two\r\n\r\nsecond message\r\n",
            Some("Projects"),
            true,
            "2026-01-02T10:00:00Z",
        ),
        seed(
            "<e3/odd:id\\x@example.com>",
            "Subject: three\r\n\r\nthird with a slash in its id\r\n",
            None,
            true,
            "2026-01-03T10:00:00Z",
        ),
    ];
    let mut query = String::new();
    let mut target = Target::Mine;
    let (mut perms, mut scoped): (Vec<&'static str>, bool) = (vec!["mail.export"], true);
    match label {
        "success-mbox" => query = "?format=mbox".into(),
        "success-zip" => query = "?format=eml".into(),
        "unknown-format" => query = "?format=tar".into(),
        "folder" => query = "?folder_id=__FOLDER__".into(),
        "mbox-folder" => query = "?format=mbox&folder_id=__FOLDER__".into(),
        "folder-missing" => query = "?folder_id=999999999".into(),
        "empty-mbox" => {
            query = "?format=mbox".into();
            seeds.clear();
        }
        "empty-zip" => seeds.clear(),
        "missing-object" => seeds[1].stored = false,
        "missing-object-mbox" => {
            query = "?format=mbox".into();
            seeds[1].stored = false;
        }
        "long-id" => {
            seeds = vec![seed(
                "<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com>",
                "Subject: long\r\n\r\nlong id\r\n",
                None,
                true,
                "2026-01-01T10:00:00Z",
            )]
        }
        "large" => {
            seeds = (0..40)
                .map(|i| {
                    let id: &'static str = Box::leak(format!("<bulk-{i}@example.com>").into_boxed_str());
                    Seed {
                        message_id: id,
                        body: format!("Subject: bulk {i}\r\n\r\n{}\r\n", "lorem ipsum dolor sit amet ".repeat(30)).into_bytes(),
                        tag: None,
                        stored: true,
                        date: Box::leak(format!("2026-{:02}-{:02}T10:00:00Z", 2 + i / 28, i % 28 + 1).into_boxed_str()),
                    }
                })
                .collect();
        }
        "shared" => {
            target = Target::Shared;
            seeds[1].tag = None;
            scoped = false;
        }
        "global" => scoped = false,
        "cross-tenant" => target = Target::Foreign,
        "invalid-id" => target = Target::Raw("abc"),
        "zero-id" => target = Target::Raw("0"),
        "missing" => target = Target::Missing,
        "denied" => perms = vec![],
        "wrong-perm" => perms = vec!["users.create"],
        "success-eml" => {}
        other => panic!("unknown export case {other}"),
    }
    let want = match label {
        "cross-tenant" | "denied" | "wrong-perm" => 403,
        "invalid-id" | "zero-id" => 400,
        "missing" => 404,
        _ => 200,
    };
    Plan {
        method: "GET",
        pattern: "/admin/mailboxes/{id}/export",
        target,
        query,
        content_type: String::new(),
        body: vec![],
        perms,
        scoped,
        seeds: if want == 200 { seeds } else { vec![] },
        repeat: false,
        want,
        summary: serde_json::json!(label),
    }
}

pub fn plan(action: &str, label: &str) -> Plan {
    match action {
        "import" => import(label),
        _ => export(label),
    }
}
