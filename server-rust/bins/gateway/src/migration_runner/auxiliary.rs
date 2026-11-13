//! Provider config merge, calendar/contact projection and uploaded ICS/VCF phases.
use super::*;
use ews::EwsConfig;
fn string(v: &Value, key: &str) -> String {
    codec::field(v, key).unwrap_or_default()
}
fn strings(v: &Value, key: &str) -> Vec<String> {
    codec::list_field(v, key).unwrap_or_default()
}
fn bool_(v: &Value, key: &str) -> bool {
    codec::bool_field(v, key).unwrap_or_default()
}
impl Inner {
    async fn global(&self, db: &Db, key: &str, name: &str) -> Result<Value, String> {
        let rows = db
            .query(
                "SELECT value::text,encrypted FROM system_config WHERE key=$1",
                &[(&key, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("no global {name} config: {e}"))?;
        let row = rows
            .first()
            .ok_or_else(|| format!("no global {name} config: no rows in result set"))?;
        if !row.get::<_, bool>(1) {
            return Err(format!("{name} global config is not encrypted"));
        }
        let raw: String = row.get(0);
        match codec::unseal(&raw, &self.root) {
            codec::Unsealed::Plain(value) => Ok(value),
            codec::Unsealed::BadWrapper => {
                Err(format!("parse {name} config wrapper: invalid JSON"))
            }
            codec::Unsealed::BadBase64 => Err(format!(
                "decode {name} config: illegal base64 data at input byte 0"
            )),
            _ => Err(format!(
                "decrypt global {name} config: cipher: message authentication failed"
            )),
        }
    }
    pub(super) async fn ews_config(
        &self,
        db: &Db,
        job: &Value,
        global: bool,
    ) -> Result<EwsConfig, String> {
        let inner = job
            .get("ews")
            .filter(|v| !v.is_null())
            .or_else(|| job.get("imap").filter(|v| !v.is_null()))
            .or_else(|| job.get("m365").filter(|v| !v.is_null()))
            .unwrap_or(job);
        let global_value = if global {
            Some(
                self.global(db, "ews.global", "EWS")
                    .await
                    .map_err(|e| format!("merge global config: {e}"))?,
            )
        } else {
            None
        };
        let value = global_value.as_ref().unwrap_or(inner);
        let mut cfg = EwsConfig {
            server_url: string(value, "serverURL"),
            username: string(value, "username"),
            password: string(value, "password"),
            impersonate_as: if global {
                String::new()
            } else {
                string(value, "impersonateAs")
            },
            insecure_skip_verify: bool_(value, "insecureSkipVerify"),
            private_hosts: strings(value, "privateHosts"),
            private_cidrs: strings(value, "privateCIDRs"),
        };
        if global {
            let marker=job.get("self_service").and_then(Value::as_bool).ok_or("merge global config: legacy migration job predates credential provenance; re-create the job")?;
            if marker {
                if string(inner, "username").is_empty() || string(inner, "password").is_empty() {
                    return Err("merge global config: self-service EWS migration requires the caller's username and password".into());
                }
                cfg.username = string(inner, "username");
                cfg.password = string(inner, "password");
            } else {
                if string(value, "authMode") == "per_user" && !string(inner, "username").is_empty()
                {
                    cfg.username = string(inner, "username");
                    cfg.password = string(inner, "password");
                }
                if string(value, "authMode") == "impersonation" {
                    cfg.impersonate_as = string(inner, "impersonateAs");
                }
            }
            if cfg.server_url.is_empty() {
                return Err("merge global config: EWS server URL is required".into());
            }
        } else if !cfg.private_hosts.is_empty() || !cfg.private_cidrs.is_empty() {
            return Err("migration private-network policy is administrator-owned; per-job privateHosts/privateCIDRs are not accepted".into());
        }
        Ok(cfg)
    }
    pub(super) async fn m365_config(
        &self,
        db: &Db,
        job: &Value,
        global: bool,
    ) -> Result<m365::M365Config, String> {
        let inner = job.get("m365").filter(|v| !v.is_null()).unwrap_or(job);
        let mut cfg = if global {
            let v = self
                .global(db, "m365.app", "M365")
                .await
                .map_err(|e| format!("merge global config: {e}"))?;
            codec::M365::from_value(&v)
                .map_err(|_| "merge global config: parse global M365 config")?
        } else {
            codec::M365::from_value(inner).map_err(|_| "decrypt m365 config")?
        };
        if global {
            for (field, target) in [
                ("client_id", &mut cfg.client_id),
                ("client_secret", &mut cfg.client_secret),
                ("tenant_id", &mut cfg.tenant_id),
            ] {
                let value = string(inner, field);
                if !value.is_empty() {
                    *target = value;
                }
            }
            if job.get("m365").is_some_and(|v| !v.is_null()) {
                cfg.source_email = string(inner, "source_email");
                cfg.source_user_id = string(inner, "source_user_id");
            }
        }
        Ok(cfg)
    }
    pub(super) async fn load_delta(&self, db: &Db, id: i64) -> BTreeMap<String, String> {
        let rows = db
            .query(
                "SELECT COALESCE(resume_cursor,'{}') FROM migration_jobs WHERE id=$1",
                &[(&id, Type::INT8)],
            )
            .await
            .unwrap_or_default();
        let value = rows
            .first()
            .map(|r| r.get::<_, String>(0))
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .unwrap_or_default();
        value
            .get("delta")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.into())))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn cards(data: &str) -> (Vec<crate::contacts_vcard::VCard>, Vec<String>) {
    let mut cards = vec![];
    let mut errors = vec![];
    for block in crate::contacts_vcard::split(data) {
        match crate::contacts_vcard::parse(&block) {
            Ok(card) => cards.push(card),
            Err(e) => errors.push(format!("vcard parse: {e}")),
        }
    }
    (cards, errors)
}
fn card_json(c: &crate::contacts_vcard::VCard) -> Value {
    use crate::contacts_vcard as v;
    let mut out = json!({"uid":c.uid,"displayName":c.fn_,"firstName":v::first_name(&c.n),"lastName":v::last_name(&c.n),"company":c.org,"jobTitle":c.title,"emails":serde_json::from_str::<Value>(&v::values_json(&c.emails,"address")).unwrap(),"phones":serde_json::from_str::<Value>(&v::values_json(&c.phones,"number")).unwrap(),"urls":serde_json::from_str::<Value>(&v::values_json(&c.urls,"url")).unwrap(),"instantMessengers":serde_json::from_str::<Value>(&v::values_json(&c.impps,"value")).unwrap(),"addresses":serde_json::from_str::<Value>(&v::addresses_json(&c.addresses)).unwrap(),"notes":c.note});
    if let Some(value) = &c.birthday {
        out["birthday"] = json!(value);
    }
    if let Some(value) = &c.anniversary {
        out["anniversary"] = json!(value);
    }
    out
}
fn events(data: &str) -> (Vec<crate::ics::Event>, Vec<String>) {
    let mut events = vec![];
    let mut errors = vec![];
    for block in crate::ics::split_components(data) {
        match crate::ics::parse_component(&block) {
            Ok(event) => events.push(event),
            Err(error) => errors.push(format!("parse error: {error}")),
        }
    }
    (events, errors)
}
impl Inner {
    pub(super) async fn import_aux_item(
        &self,
        db: &Db,
        id: i64,
        mailbox: i64,
        item: &SourceItem,
        identity: bool,
    ) -> Result<String, String> {
        if !identity {
            let errors = if item.kind == ItemKind::Calendar {
                // #536 (owner-approved divergence): frozen Go passed the mailbox ID as the
                // calendar ID, so another tenant's calendar could be probed and written.
                // The target is the mailbox's own default calendar, and every statement
                // below carries the calendar-belongs-to-mailbox predicate.
                let (calendar, owner) = if setjoin_contracts::mutants::on("m365-aux-mailbox-as-calendar") {
                    (mailbox, 0)
                } else {
                    let rows=db.query("SELECT id FROM calendars WHERE mailbox_id=$1 AND is_default=true ORDER BY id LIMIT 1",&[(&mailbox,Type::INT8)]).await.map_err(|e|format!("resolve default calendar for mailbox {mailbox}: {e}"))?;
                    let calendar: i64 = rows
                        .first()
                        .ok_or_else(|| {
                            format!("migration target mailbox {mailbox} has no default calendar")
                        })?
                        .get(0);
                    (calendar, mailbox)
                };
                self.import_ics(db, &item.ics, calendar, owner, "", "skip")
                    .await
                    .2
            } else {
                let rows=db.query("SELECT id FROM addressbooks WHERE mailbox_id=$1 AND is_default=true LIMIT 1",&[(&mailbox,Type::INT8)]).await.map_err(|e|format!("resolve default address book for mailbox {mailbox}: {e}"))?;
                let book: i64 = rows
                    .first()
                    .ok_or_else(|| {
                        format!("migration target mailbox {mailbox} has no default address book")
                    })?
                    .get(0);
                self.import_vcf(db, &item.vcf, book, mailbox, "skip")
                    .await
                    .2
            };
            return errors.first().map_or(Ok(String::new()), |e| Err(e.clone()));
        }
        let payload = if item.kind == ItemKind::Calendar {
            &item.ics
        } else {
            &item.vcf
        };
        use sha2::{Digest, Sha256};
        let hash =
            (item.change != Change::Delete).then(|| imap::hex(&Sha256::digest(payload.as_bytes())));
        let (objects, parse_error) = if item.kind == ItemKind::Calendar {
            let (events, errors) = events(payload);
            (
                crate::ics::events_to_json(&events),
                (!errors.is_empty() || events.len() != 1).then_some(
                    "calendar source object must contain exactly one valid event".to_owned(),
                ),
            )
        } else {
            let (cards, errors) = cards(payload);
            (
                Value::Array(cards.iter().map(card_json).collect()).to_string(),
                errors.first().cloned().or_else(|| {
                    (cards.len() != 1).then_some(
                        "contact source object must contain exactly one valid vCard".into(),
                    )
                }),
            )
        };
        let op = operation_id(id, item);
        let kind = item.kind.as_str();
        let change = item.change.as_str();
        let rows=db.query("SELECT rust_migration_apply_aux_object($1,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9::text::jsonb,$10)::text",&[(&id,Type::INT8),(&op,Type::TEXT),(&kind,Type::TEXT),(&item.object_id,Type::TEXT),(&item.version,Type::TEXT),(&item.folder_id,Type::TEXT),(&change,Type::TEXT),(&hash,Type::TEXT),(&objects,Type::TEXT),(&parse_error,Type::TEXT)]).await.map_err(|e|if parse_error.as_ref().is_some_and(|p|e.contains(p)){parse_error.clone().unwrap()}else if e.contains("projection reducer did not create an object"){ "projection reducer did not create an object".into() }else{e})?;
        let value: Value =
            serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|e| e.to_string())?;
        Ok(value["outcome"].as_str().unwrap_or_default().into())
    }
    async fn import_ics(
        &self,
        db: &Db,
        data: &str,
        calendar: i64,
        owner: i64,
        email: &str,
        strategy: &str,
    ) -> (i64, i64, Vec<String>) {
        let (mut events, mut errors) = events(data);
        let (mut imported, mut skipped) = (0, 0);
        for event in &mut events {
            if let Err(e) = self
                .legacy_conflict(
                    db,
                    "calendar_events",
                    "calendar_id",
                    "uid",
                    calendar,
                    &mut event.uid,
                    owner,
                    strategy,
                )
                .await
            {
                if e == "skip" {
                    skipped += 1;
                    continue;
                }
                errors.push(e);
                continue;
            }
            let mut value: Value =
                serde_json::from_str(&crate::ics::events_to_json(std::slice::from_ref(event)))
                    .unwrap();
            let mut obj = value[0].take();
            if let Some(map) = obj.as_object_mut() {
                map.extend(event.migration.clone());
            }
            obj["component"] = json!(event.component);
            obj["exdate"] = json!(event
                .exdates
                .iter()
                .filter_map(|n| chrono::DateTime::from_timestamp(*n, 0))
                .map(|t| t.to_rfc3339())
                .collect::<Vec<_>>());
            if let Some(t) = event
                .recurrence_id
                .and_then(|n| chrono::DateTime::from_timestamp(n, 0))
            {
                obj["recurrence_id"] = json!(t.to_rfc3339());
            }
            if obj["organizer_email"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && !s.eq_ignore_ascii_case(email))
            {
                obj["organizer_email"] = json!(email);
            }
            let text = obj.to_string();
            let query="INSERT INTO calendar_events(calendar_id,uid,component_type,title,description,location,start_at,end_at,all_day,timezone,rrule,rdate,exdate,status,priority,percent_complete,completed_at,due_at,organizer_email,organizer_name,recurrence_id) SELECT $1,x->>'uid',x->>'component',x->>'title',x->>'description',x->>'location',(x->>'start')::timestamptz,(x->>'end')::timestamptz,(x->>'isAllDay')::boolean,x->>'timeZone',x->>'recurrenceRule',NULLIF(ARRAY(SELECT v::timestamptz FROM jsonb_array_elements_text(COALESCE(x->'rdate','[]')) v),ARRAY[]::timestamptz[]),NULLIF(ARRAY(SELECT v::timestamptz FROM jsonb_array_elements_text(COALESCE(x->'exdate','[]')) v),ARRAY[]::timestamptz[]),$3,NULLIF((x->>'priority')::int,0),COALESCE((x->>'percent_complete')::int,0),(x->>'completed_at')::timestamptz,(x->>'due_at')::timestamptz,NULLIF(x->>'organizer_email',''),NULLIF(x->>'organizer_name',''),(x->>'recurrence_id')::timestamptz FROM (SELECT $2::text::jsonb x) q WHERE EXISTS(SELECT 1 FROM calendars c WHERE c.id=$1 AND ($4<=0 OR c.mailbox_id=$4)) RETURNING id";
            match db
                .query(
                    query,
                    &[
                        (&calendar, Type::INT8),
                        (&text, Type::TEXT),
                        (&event.status, Type::TEXT),
                        (&owner, Type::INT8),
                    ],
                )
                .await
            {
                Ok(r) if r.is_empty() => errors.push(format!(
                    "event {}: calendar not owned by verified mailbox",
                    event.uid
                )),
                Ok(_) => imported += 1,
                Err(e) => errors.push(format!("event {}: {e}", event.uid)),
            }
        }
        (imported, skipped, errors)
    }
    async fn legacy_conflict(
        &self,
        db: &Db,
        table: &str,
        parent: &str,
        uidcol: &str,
        parent_id: i64,
        uid: &mut String,
        mailbox: i64,
        strategy: &str,
    ) -> Result<(), String> {
        if !matches!(strategy, "skip" | "rename" | "overwrite") {
            return Ok(());
        }
        let ownership = if mailbox > 0 {
            if table == "calendar_events" {
                " AND EXISTS(SELECT 1 FROM calendars a WHERE a.id=t.calendar_id AND a.mailbox_id=$3)"
            } else {
                " AND EXISTS(SELECT 1 FROM addressbooks a WHERE a.id=t.addressbook_id AND a.mailbox_id=$3)"
            }
        } else {
            " AND $3::bigint>=0"
        };
        let sql=format!("SELECT EXISTS(SELECT 1 FROM {table} t WHERE t.{parent}=$1 AND t.{uidcol}=$2{ownership})");
        if strategy == "overwrite" {
            let sql =
                format!("DELETE FROM {table} t WHERE t.{parent}=$1 AND t.{uidcol}=$2{ownership}");
            let _ = db
                .query(
                    &sql,
                    &[
                        (&parent_id, Type::INT8),
                        (&*uid, Type::TEXT),
                        (&mailbox, Type::INT8),
                    ],
                )
                .await;
            return Ok(());
        }
        loop {
            // A failed probe is a row error. Treating it as "no conflict" (as Go's bool-only
            // `exists` does) would let the insert proceed past a conflict it never checked.
            let probed = db
                .query(
                    &sql,
                    &[
                        (&parent_id, Type::INT8),
                        (&*uid, Type::TEXT),
                        (&mailbox, Type::INT8),
                    ],
                )
                .await;
            // Mutant `m365-probe-error-ignored`: frozen Go's bool-only exists() reads an error as
            // "no conflict".
            let rows = match probed {
                Err(_) if setjoin_contracts::mutants::on("m365-probe-error-ignored") => Vec::new(),
                other => other.map_err(|e| format!("conflict probe for {uid}: {e}"))?,
            };
            let exists = rows.first().is_some_and(|r| r.get::<_, bool>(0));
            if !exists {
                return Ok(());
            }
            if strategy == "skip" {
                return Err("skip".into());
            }
            uid.push_str("-migrated");
        }
    }
    async fn import_vcf(
        &self,
        db: &Db,
        data: &str,
        book: i64,
        mailbox: i64,
        strategy: &str,
    ) -> (i64, i64, Vec<String>) {
        let (mut cards, mut errors) = cards(data);
        let (mut imported, mut skipped) = (0, 0);
        for card in &mut cards {
            if let Err(e) = self
                .legacy_conflict(
                    db,
                    "contacts",
                    "addressbook_id",
                    "vcard_uid",
                    book,
                    &mut card.uid,
                    mailbox,
                    strategy,
                )
                .await
            {
                if e == "skip" {
                    skipped += 1;
                    continue;
                }
                errors.push(e);
                continue;
            }
            let mut obj = card_json(card);
            if card.fn_.is_empty() {
                obj["displayName"] = json!(card.n);
            }
            let text = obj.to_string();
            let query="INSERT INTO contacts(addressbook_id,vcard_uid,display_name,first_name,last_name,company,job_title,emails,phones,urls,instant_msgs,addresses,notes,birthday,anniversary) SELECT $1,x->>'uid',x->>'displayName',x->>'firstName',x->>'lastName',x->>'company',x->>'jobTitle',x->'emails',x->'phones',x->'urls',x->'instantMessengers',x->'addresses',x->>'notes',(x->>'birthday')::date,(x->>'anniversary')::date FROM (SELECT $2::text::jsonb x) q WHERE EXISTS(SELECT 1 FROM addressbooks a WHERE a.id=$1 AND ($3<=0 OR a.mailbox_id=$3)) RETURNING id";
            match db
                .query(
                    query,
                    &[
                        (&book, Type::INT8),
                        (&text, Type::TEXT),
                        (&mailbox, Type::INT8),
                    ],
                )
                .await
            {
                Ok(r) if r.is_empty() => errors.push(format!(
                    "contact {}: address book not owned by verified mailbox",
                    card.uid
                )),
                Ok(_) => imported += 1,
                Err(e) => errors.push(format!("contact {}: {e}", card.uid)),
            }
        }
        (imported, skipped, errors)
    }
    pub(super) async fn upload_phase(&self, db: &Db, id: i64, job: &JobRow, phase: &str) {
        let key = format!("migration/upload/{id}/{phase}");
        let data = self.store.read(&key, 64 << 20).await.unwrap_or_default();
        let (imported, skipped, errors) = if data.is_empty() {
            (
                0,
                0,
                vec![format!(
                    "{phase}: no uploaded {} data",
                    phase.to_uppercase()
                )],
            )
        } else {
            let table = if phase == "ics" {
                "calendars"
            } else {
                "addressbooks"
            };
            let query=format!("SELECT t.id FROM {table} t JOIN mailboxes m ON m.id=t.mailbox_id WHERE m.user_id=$1 AND t.is_default=true LIMIT 1");
            let target = db
                .query(&query, &[(&job.user_id, Type::INT8)])
                .await
                .ok()
                .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)))
                .unwrap_or(0);
            if target == 0 {
                (
                    0,
                    0,
                    vec![format!(
                        "{phase}: no {} found for user",
                        if phase == "ics" {
                            "calendar"
                        } else {
                            "address book"
                        }
                    )],
                )
            } else if phase == "ics" {
                let email = db
                    .query(
                        "SELECT email FROM users WHERE id=$1",
                        &[(&job.user_id, Type::INT8)],
                    )
                    .await
                    .ok()
                    .and_then(|r| r.first().map(|r| r.get::<_, String>(0)))
                    .unwrap_or_default();
                self.import_ics(
                    db,
                    &String::from_utf8_lossy(&data),
                    target,
                    0,
                    &email,
                    &job.conflict_strategy,
                )
                .await
            } else {
                self.import_vcf(
                    db,
                    &String::from_utf8_lossy(&data),
                    target,
                    0,
                    &job.conflict_strategy,
                )
                .await
            }
        };
        for error in &errors {
            let _ = self
                .orchestrate(db, id, "progress", Some(json!({"errors":[error]})))
                .await;
        }
        if data.is_empty()
            || errors
                .first()
                .is_some_and(|e| e.starts_with(&format!("{phase}: no ")))
        {
            return;
        }
        self.update_progress(
            db,
            id,
            phase,
            json!({"imported":imported,"skipped":skipped}),
        )
        .await;
    }
}
