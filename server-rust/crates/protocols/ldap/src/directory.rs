//! Directory reads mirror frozen Go. People visibility is reducer-owned and
//! keyed by the authenticated principal's primary mailbox (never the base DN).
use super::{result, Server};
use ldap3_proto::{control::LdapControl, proto::*};
use setjoin_pg::{Param, Row, Type};

pub fn base(domain: &str) -> String {
    domain
        .split('.')
        .map(|x| format!("dc={x}"))
        .collect::<Vec<_>>()
        .join(",")
}
pub fn ou(dn: &str, base: &str) -> String {
    let dn = dn.to_lowercase();
    let suffix = format!(",{}", base.to_lowercase());
    let dn = dn.strip_suffix(&suffix).unwrap_or(&dn);
    for ou in ["people", "groups", "resources", "contacts"] {
        if dn == format!("ou={ou}") || dn.contains(&format!(",ou={ou}")) {
            return ou.into();
        }
    }
    if dn.is_empty() {
        "root".into()
    } else {
        String::new()
    }
}
pub fn rdn(dn: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    dn.to_lowercase()
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_default()
}
fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\5C"),
            ',' => out.push_str("\\2C"),
            '+' => out.push_str("\\2B"),
            '"' => out.push_str("\\22"),
            '<' => out.push_str("\\3C"),
            '>' => out.push_str("\\3E"),
            ';' => out.push_str("\\3B"),
            _ => out.push(c),
        }
    }
    if out.starts_with('#') {
        out.replace_range(..1, "\\23");
    }
    if out.ends_with(' ') {
        out.pop();
        out.push_str("\\20");
    }
    out
}
fn attr(
    entry: &mut LdapSearchResultEntry,
    request: &LdapSearchRequest,
    name: &str,
    values: &[&str],
    force: bool,
) {
    let defaults = ["cn", "mail", "displayName", "objectClass"];
    let accepted = if request.attrs.is_empty() {
        defaults.iter().any(|a| a.eq_ignore_ascii_case(name))
    } else {
        request.attrs.iter().any(|a| a.eq_ignore_ascii_case(name))
    };
    if force || accepted {
        entry.attributes.push(LdapPartialAttribute {
            atype: name.into(),
            vals: if request.typesonly {
                vec![]
            } else {
                values.iter().map(|v| v.as_bytes().to_vec()).collect()
            },
        })
    }
}
fn entry(dn: String) -> LdapSearchResultEntry {
    LdapSearchResultEntry {
        dn,
        attributes: vec![],
    }
}
impl Server {
    pub(crate) async fn mailbox(&self, user: i64) -> Result<i64, ()> {
        self.db
            .as_ref()
            .ok_or(())?
            .read(
                "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=TRUE LIMIT 1",
                &[(&user, Type::INT8)],
            )
            .await
            .map_err(|_| ())?
            .first()
            .ok_or(())?
            .try_get(0)
            .map_err(|_| ())
    }
    pub(crate) async fn search(
        &self,
        user: i64,
        request: LdapSearchRequest,
        controls: &[LdapControl],
    ) -> Vec<LdapOp> {
        match self.search_inner(user, &request, controls).await {
            Ok(ops) => ops,
            Err(()) => vec![LdapOp::SearchResultDone(result(
                LdapResultCode::OperationsError,
            ))],
        }
    }
    async fn search_inner(
        &self,
        user: i64,
        request: &LdapSearchRequest,
        controls: &[LdapControl],
    ) -> Result<Vec<LdapOp>, ()> {
        let db = self.db.as_ref().ok_or(())?;
        let base = base(&self.domain);
        let kind = ou(&request.base, &base);
        if kind == "root" {
            let mut ops = vec![];
            if request.scope == LdapSearchScope::Base {
                let mut e = entry(request.base.clone());
                attr(
                    &mut e,
                    request,
                    "objectClass",
                    &["top", "dcObject", "organization"],
                    true,
                );
                let dc = request
                    .base
                    .split(',')
                    .next()
                    .unwrap_or_default()
                    .strip_prefix("dc=")
                    .unwrap_or_else(|| request.base.split(',').next().unwrap_or_default());
                attr(&mut e, request, "dc", &[dc], true);
                attr(&mut e, request, "o", &[&self.domain], true);
                ops.push(LdapOp::SearchResultEntry(e));
            } else if request.scope == LdapSearchScope::OneLevel {
                for name in ["People", "Groups", "Resources", "Contacts"] {
                    let mut e = entry(format!("ou={name},{}", request.base));
                    attr(
                        &mut e,
                        request,
                        "objectClass",
                        &["top", "organizationalUnit"],
                        true,
                    );
                    attr(&mut e, request, "ou", &[name], true);
                    ops.push(LdapOp::SearchResultEntry(e));
                }
            }
            ops.push(LdapOp::SearchResultDone(result(LdapResultCode::Success)));
            return Ok(ops);
        }
        if kind.is_empty() {
            return Ok(vec![
                LdapOp::SearchResultEntry(entry(request.base.clone())),
                LdapOp::SearchResultDone(result(LdapResultCode::Success)),
            ]);
        }
        if kind == "groups" {
            return self.search_groups(request).await;
        }
        if kind == "resources" {
            return self.search_resources(request).await;
        }
        if kind == "contacts" {
            return self.search_contacts(request).await;
        }
        if kind != "people" {
            return Ok(vec![LdapOp::SearchResultDone(result(
                LdapResultCode::Success,
            ))]);
        }
        let mailbox = self.mailbox(user).await?;
        let mut limit = i64::from(if request.sizelimit <= 0 || request.sizelimit > 1000 {
            1000
        } else {
            request.sizelimit
        });
        let offset = 0i64;
        for control in controls {
            if let LdapControl::SimplePagedResults { size, .. } = control {
                limit = if *size <= 0 || *size > 1000 {
                    1000
                } else {
                    *size
                };
                // Go's asn1 struct expects a context-specific cookie tag [4].
                // Standard RFC 2696 OCTET STRING cookies are ignored. The Go
                // listener also emits no response control/continuation cookie.
                break;
            }
        }
        let query_limit = limit + 1;
        let mut query="SELECT v.email,v.display_name,COALESCE(v.first_name,''),COALESCE(v.last_name,''),COALESCE(v.phone,''),COALESCE(v.job_title,''),COALESCE(v.dept_name,''),COALESCE(v.avatar_sha256,'') FROM directory_visible_users($1) v LEFT JOIN departments d ON d.id=v.department_id WHERE TRUE".to_string();
        let mut params: Vec<Param<'_>> = vec![(&mailbox, Type::INT8)];
        let cn = rdn(&request.base, "cn");
        if request.scope == LdapSearchScope::Base {
            if cn.is_empty() {
                return Ok(vec![LdapOp::SearchResultDone(result(
                    LdapResultCode::Success,
                ))]);
            }
            query+=" AND (LOWER(v.display_name)=LOWER($2) OR EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) address WHERE LOWER(SPLIT_PART(address->>'email','@',1))=LOWER($2) OR LOWER(address->>'email')=LOWER($2)))";
            params.push((&cn, Type::TEXT));
            query += " LIMIT 1";
        }
        let mut filter_values = vec![];
        if request.scope == LdapSearchScope::Subtree {
            let dn = request.base.to_lowercase();
            let suffix = format!(",{}", base.to_lowercase());
            let dn = dn.strip_suffix(&suffix).unwrap_or(&dn);
            if let Some(at) = dn.find("ou=people") {
                let mut parts = dn[..at]
                    .trim_end_matches(',')
                    .split(',')
                    .map(str::trim)
                    .filter_map(|p| p.strip_prefix("ou="))
                    .collect::<Vec<_>>();
                parts.reverse();
                let path = parts.join("/");
                if !path.is_empty() {
                    query += " AND (d.path=$2 OR d.path LIKE $3)";
                    filter_values.push(path.clone());
                    filter_values.push(format!("{path}/%"));
                }
            }
        }
        if request.scope != LdapSearchScope::Base {
            let condition = super::filter::sql(&request.filter, "people", 1, &mut filter_values);
            if !condition.is_empty() {
                query += &format!(" AND ({condition})");
            }
            for value in &filter_values {
                params.push((value, Type::TEXT));
            }
        }
        if request.scope != LdapSearchScope::Base {
            query += &format!(
                " ORDER BY v.display_name LIMIT ${} OFFSET ${}",
                params.len() + 1,
                params.len() + 2
            );
            params.push((&query_limit, Type::INT8));
            params.push((&offset, Type::INT8));
        }
        let rows = db.read(&query, &params).await.map_err(|_| ())?;
        let mut ops = vec![];
        let too_many = rows.len() > limit as usize;
        for row in rows.iter().take(limit as usize) {
            ops.push(LdapOp::SearchResultEntry(person(row, &base, request)?));
        }
        ops.push(LdapOp::SearchResultDone(result(if too_many {
            LdapResultCode::SizeLimitExceeded
        } else {
            LdapResultCode::Success
        })));
        Ok(ops)
    }
}
fn person(row: &Row, base: &str, r: &LdapSearchRequest) -> Result<LdapSearchResultEntry, ()> {
    let values = (0..8)
        .map(|i| row.try_get::<_, String>(i).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let (email, display, first, last, phone, title, dept, avatar) = (
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        &values[7],
    );
    let local = email.split('@').next().unwrap_or_default();
    let mut dn = format!("cn={},", escape(local));
    if !dept.is_empty() {
        dn += &format!("ou={},", dept.replace('\\', "\\5c").replace('/', "\\2f"));
    }
    dn += &format!("ou=People,{base}");
    let mut e = entry(dn);
    attr(
        &mut e,
        r,
        "objectClass",
        &["top", "person", "organizationalPerson", "inetOrgPerson"],
        false,
    );
    attr(&mut e, r, "cn", &[local], false);
    if r.scope == LdapSearchScope::Base {
        attr(&mut e, r, "mail", &[email], false);
        attr(&mut e, r, "displayname", &[display], false);
        return Ok(e);
    }
    attr(&mut e, r, "displayname", &[display], false);
    attr(&mut e, r, "givenname", &[first], false);
    attr(&mut e, r, "sn", &[last], false);
    attr(&mut e, r, "mail", &[email], false);
    if !phone.is_empty() {
        attr(&mut e, r, "telephonenumber", &[phone], false)
    }
    if !title.is_empty() {
        attr(&mut e, r, "title", &[title], false)
    }
    if !dept.is_empty() {
        attr(&mut e, r, "ou", &[dept], false);
        attr(&mut e, r, "department", &[dept], false)
    }
    if !avatar.is_empty() {
        attr(&mut e, r, "jpegPhoto", &[&format!("/blobs/{avatar}")], true)
    }
    Ok(e)
}

impl Server {
    pub(crate) async fn compare(&self, user: i64, r: &LdapCompareRequest) -> LdapResultCode {
        let cn = rdn(&r.dn, "cn");
        if cn.is_empty() {
            return LdapResultCode::NoSuchObject;
        }
        let Some(db) = &self.db else {
            return LdapResultCode::OperationsError;
        };
        let kind = ou(&r.dn, &base(&self.domain));
        if kind != "people" {
            return self.compare_other(&kind, r, &cn).await;
        }
        let Ok(mailbox) = self.mailbox(user).await else {
            return LdapResultCode::OperationsError;
        };
        let query="SELECT LOWER(v.display_name),LOWER(v.email),COALESCE(LOWER(v.last_name),''),COALESCE(LOWER(v.first_name),''),COALESCE(LOWER(v.phone),''),COALESCE(LOWER(v.job_title),''),EXISTS(SELECT 1 FROM jsonb_array_elements(v.addresses) asserted WHERE LOWER(asserted->>'email')=LOWER($3)) FROM directory_visible_users($1) v WHERE LOWER(v.display_name)=LOWER($2) OR EXISTS(SELECT 1 FROM jsonb_array_elements(v.addresses) address WHERE LOWER(SPLIT_PART(address->>'email','@',1))=LOWER($2) OR LOWER(address->>'email')=LOWER($2)) LIMIT 1";
        let value = String::from_utf8_lossy(&r.val).to_string();
        let Ok(rows) = db
            .read(
                query,
                &[
                    (&mailbox, Type::INT8),
                    (&cn, Type::TEXT),
                    (&value, Type::TEXT),
                ],
            )
            .await
        else {
            return LdapResultCode::NoSuchAttribute;
        };
        let Some(row) = rows.first() else {
            return LdapResultCode::NoSuchAttribute;
        };
        let name = r.atype.to_lowercase();
        let matched = if name == "mail" {
            row.get::<_, bool>(6)
        } else {
            let index = match name.as_str() {
                "sn" => 2,
                "givenname" => 3,
                "telephonenumber" => 4,
                "title" => 5,
                _ => 0,
            };
            let Ok(actual) = row.try_get::<_, String>(index) else {
                return LdapResultCode::NoSuchAttribute;
            };
            if actual.is_empty() {
                return LdapResultCode::NoSuchAttribute;
            }
            actual == value.to_lowercase()
        };
        if matched {
            LdapResultCode::CompareTrue
        } else {
            LdapResultCode::CompareFalse
        }
    }
}

impl Server {
    async fn search_groups(&self, r: &LdapSearchRequest) -> Result<Vec<LdapOp>, ()> {
        let base = base(&self.domain);
        let (rows, cap) = self.other_rows(r, "groups").await?;
        let mut ops = vec![];
        for row in rows.iter().take(cap as usize) {
            let (Ok(name), Ok(email)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1))
            else {
                continue;
            };
            let mut e = entry(format!("cn={},ou=Groups,{base}", escape(&name)));
            attr(&mut e, r, "objectClass", &["top", "groupOfNames"], false);
            attr(&mut e, r, "cn", &[&name], false);
            if r.scope != LdapSearchScope::Base {
                attr(&mut e, r, "displayname", &[&name], false);
            }
            if !email.is_empty() {
                attr(&mut e, r, "mail", &[&email], false)
            }
            ops.push(LdapOp::SearchResultEntry(e));
        }
        ops.push(LdapOp::SearchResultDone(result(
            if rows.len() > cap as usize {
                LdapResultCode::SizeLimitExceeded
            } else {
                LdapResultCode::Success
            },
        )));
        Ok(ops)
    }
}

impl Server {
    async fn search_resources(&self, r: &LdapSearchRequest) -> Result<Vec<LdapOp>, ()> {
        let base = base(&self.domain);
        let (rows, cap) = self.other_rows(r, "resources").await?;
        let mut ops = vec![];
        for row in rows.iter().take(cap as usize) {
            let (Ok(name), Ok(email)) = (row.try_get::<_, String>(0), row.try_get::<_, String>(1))
            else {
                continue;
            };
            let mut e = entry(format!("cn={},ou=Resources,{base}", escape(&name)));
            attr(
                &mut e,
                r,
                "objectClass",
                &["top", "room", "inetOrgPerson"],
                false,
            );
            attr(&mut e, r, "cn", &[&name], false);
            if r.scope != LdapSearchScope::Base {
                attr(&mut e, r, "displayname", &[&name], false);
            }
            if !email.is_empty() {
                attr(&mut e, r, "mail", &[&email], false)
            }
            ops.push(LdapOp::SearchResultEntry(e));
        }
        ops.push(LdapOp::SearchResultDone(result(
            if rows.len() > cap as usize {
                LdapResultCode::SizeLimitExceeded
            } else {
                LdapResultCode::Success
            },
        )));
        Ok(ops)
    }
}

impl Server {
    async fn search_contacts(&self, r: &LdapSearchRequest) -> Result<Vec<LdapOp>, ()> {
        let base = base(&self.domain);
        let cn = rdn(&r.base, "cn");
        if r.scope == LdapSearchScope::Base && cn.is_empty() {
            return Ok(vec![LdapOp::SearchResultDone(result(
                LdapResultCode::Success,
            ))]);
        }
        let (rows, cap) = self.other_rows(r, "contacts").await?;
        let mut ops = vec![];
        for row in rows.iter().take(cap as usize) {
            let Ok(v) = (0..7)
                .map(|i| row.try_get::<_, String>(i))
                .collect::<Result<Vec<_>, _>>()
            else {
                continue;
            };
            let mut e = entry(format!("cn={},ou=Contacts,{base}", escape(&v[0])));
            attr(
                &mut e,
                r,
                "objectClass",
                &["top", "person", "organizationalPerson", "inetOrgPerson"],
                false,
            );
            attr(&mut e, r, "cn", &[&v[0]], false);
            attr(&mut e, r, "displayname", &[&v[0]], false);
            if r.scope != LdapSearchScope::Base {
                attr(&mut e, r, "givenname", &[&v[1]], false);
                attr(&mut e, r, "sn", &[&v[2]], false);
                for (index, name) in [(3, "o"), (4, "title"), (5, "department")] {
                    if !v[index].is_empty() {
                        attr(&mut e, r, name, &[&v[index]], false)
                    }
                }
                if !v[6].is_empty() {
                    attr(&mut e, r, "jpegPhoto", &[&format!("/blobs/{}", v[6])], true)
                }
            }
            ops.push(LdapOp::SearchResultEntry(e));
        }
        ops.push(LdapOp::SearchResultDone(result(
            if rows.len() > cap as usize {
                LdapResultCode::SizeLimitExceeded
            } else {
                LdapResultCode::Success
            },
        )));
        Ok(ops)
    }
}

impl Server {
    async fn compare_other(&self, kind: &str, r: &LdapCompareRequest, cn: &str) -> LdapResultCode {
        let Some(db) = &self.db else {
            return LdapResultCode::OperationsError;
        };
        let query=match kind {
   "groups"=>"SELECT LOWER(m.display_name),LOWER(m.email),'','','','' FROM distribution_groups dg JOIN mailboxes m ON m.id=dg.mailbox_id WHERE m.display_name ILIKE $1 LIMIT 1",
   "resources"=>"SELECT LOWER(display_name),LOWER(email),'','','','' FROM mailboxes WHERE resource_type IS NOT NULL AND enabled=TRUE AND display_name ILIKE $1 LIMIT 1",
   "contacts"=>"SELECT LOWER(c.display_name),'',COALESCE(LOWER(c.last_name),''),COALESCE(LOWER(c.first_name),''),COALESCE(LOWER(c.company),''),COALESCE(LOWER(c.job_title),'') FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id WHERE c.display_name ILIKE $1 AND ab.is_shared=TRUE LIMIT 1",
   _=>return LdapResultCode::NoSuchObject,
  };
        let Ok(rows) = db.read(query, &[(&cn, Type::TEXT)]).await else {
            return LdapResultCode::NoSuchAttribute;
        };
        let Some(row) = rows.first() else {
            return LdapResultCode::NoSuchAttribute;
        };
        let index = match r.atype.to_lowercase().as_str() {
            "mail" => 1,
            "sn" => 2,
            "givenname" => 3,
            "telephonenumber" => 4,
            "title" => 5,
            _ => 0,
        };
        let Ok(actual) = row.try_get::<_, String>(index) else {
            return LdapResultCode::NoSuchAttribute;
        };
        if actual.is_empty() {
            return LdapResultCode::NoSuchAttribute;
        }
        if actual == String::from_utf8_lossy(&r.val).to_lowercase() {
            LdapResultCode::CompareTrue
        } else {
            LdapResultCode::CompareFalse
        }
    }
}

impl Server {
    async fn other_rows(&self, r: &LdapSearchRequest, kind: &str) -> Result<(Vec<Row>, i64), ()> {
        let db = self.db.as_ref().ok_or(())?;
        let (select,source,name)=match kind {
   "groups"=>("m.display_name,m.email","distribution_groups dg JOIN mailboxes m ON m.id=dg.mailbox_id WHERE TRUE","m.display_name"),
   "resources"=>("display_name,email","mailboxes WHERE resource_type IS NOT NULL AND enabled=TRUE","display_name"),
   "contacts"=>("c.display_name,COALESCE(c.first_name,''),COALESCE(c.last_name,''),COALESCE(c.company,''),COALESCE(c.job_title,''),COALESCE(c.department,''),COALESCE(c.avatar_sha256,'')","contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes m ON m.id=ab.mailbox_id WHERE ab.is_shared=TRUE","c.display_name"),
   _=>return Err(()),
  };
        let cap = i64::from(if r.sizelimit <= 0 || r.sizelimit > 1000 {
            1000
        } else {
            r.sizelimit
        });
        let fetch = cap + 1;
        let offset = 0i64;
        let mut query = format!("SELECT {select} FROM {source}");
        let mut values = vec![];
        let mut params: Vec<Param<'_>> = vec![];
        if r.scope == LdapSearchScope::Base {
            let cn = rdn(&r.base, "cn");
            if cn.is_empty() {
                return Ok((vec![], cap));
            }
            values.push(cn);
            query += &format!(" AND {name} ILIKE $1 LIMIT 1");
            for value in &values {
                params.push((value, Type::TEXT));
            }
        } else {
            let condition = super::filter::sql(&r.filter, kind, 0, &mut values);
            if !condition.is_empty() {
                query += &format!(" AND ({condition})");
            }
            for value in &values {
                params.push((value, Type::TEXT));
            }
            query += &format!(
                " ORDER BY {name} LIMIT ${} OFFSET ${}",
                params.len() + 1,
                params.len() + 2
            );
            params.push((&fetch, Type::INT8));
            params.push((&offset, Type::INT8));
        }
        Ok((
            db.read_iterated(&query, &params).await.map_err(|_| ())?,
            cap,
        ))
    }
}
