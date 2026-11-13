//! F17 slice `contacts` HTTP adapter (#297): contacts CSV/vCard import and export
//! (`/contacts/import/*`, `/contacts/export/*`, mounted at `/api`).
//!
//! Frozen Go dispatches on the path suffix, so `/api/contacts/import/x/import/csv`
//! is the CSV import. Authentication and the `contacts` entitlement stay with Go
//! (a refusal and its audit are forwarded); everything after them is served here.
//! Every write is one statement in its own receipted transaction, as Go runs each
//! statement on its own pool call, with the gate-verified mailbox in its WHERE.
use crate::contacts_csv::{self as csv, Mapping};
use crate::contacts_vcard as vcard;
use crate::problem::Problem;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_calendar::contacts as db;
use setjoin_pg::{ScopedExecutor, StatementFailure};
use std::sync::Arc;

pub struct ContactsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

/// Go's `maxUploadBytes`.
const CAP: usize = 10 << 20;

fn external(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

/// Go's `url.ParseQuery`: pairs in order, bad pairs dropped, and whether any was.
fn parse_query(raw: Option<&str>) -> (Vec<(String, String)>, bool) {
    fn unquote(text: &str) -> Option<String> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
                    let (a, b) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)));
                    out.push((a? * 16 + b?) as u8);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Some(crate::guests_input::go_utf8(&out))
    }
    let (mut pairs, mut bad) = (Vec::new(), false);
    for pair in raw.unwrap_or("").split('&') {
        if pair.is_empty() {
            continue;
        }
        if pair.contains(';') {
            bad = true;
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match (unquote(key), unquote(value)) {
            (Some(key), Some(value)) => pairs.push((key, value)),
            _ => bad = true,
        }
    }
    (pairs, bad)
}

fn first<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// The multipart form of Go's `ParseMultipartForm`: value parts in order and the
/// first part named `file` that carries a filename.
struct Upload {
    values: Vec<(String, String)>,
    file: Option<Vec<u8>>,
}

async fn upload(r: &mut Request<Body>) -> Result<Upload, ()> {
    use http_body_util::BodyExt;
    let boundary = r
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| multer::parse_boundary(v).ok())
        .ok_or(())?;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > CAP - bytes.len() {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let stream = futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(bytes))
    });
    let mut form = multer::Multipart::new(stream, boundary);
    let mut out = Upload {
        values: Vec::new(),
        file: None,
    };
    let mut parts = 0;
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        parts += 1;
        if parts > 1000 {
            return Err(());
        }
        let name = field.name().unwrap_or("").to_owned();
        let filename = field.file_name().is_some_and(|n| !n.is_empty());
        let data = field.bytes().await.map_err(|_| ())?;
        if name.is_empty() {
            continue;
        }
        if filename {
            if name == "file" && out.file.is_none() {
                out.file = Some(data.to_vec());
            }
        } else {
            out.values
                .push((name, String::from_utf8_lossy(&data).into_owned()));
        }
    }
    Ok(out)
}

struct Out<'a> {
    c: &'a RequestContext,
    id: String,
}

impl Out<'_> {
    fn ok(&self, body: String) -> Response<Body> {
        crate::jmap::reply::response(body, self.c.identity.proto, self.id.clone())
    }
    /// Go's `httputil.WriteError`.
    fn bare(&self, status: u16, detail: &str) -> Response<Body> {
        let mut r = self.ok(Problem::new(status, detail).body());
        *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        r.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static("application/problem+json"),
        );
        r
    }
    fn download(&self, content_type: &'static str, filename: &str, body: String) -> Response<Body> {
        let mut r = self.ok(body);
        let h = r.headers_mut();
        h.insert(
            "content-type",
            hyper::header::HeaderValue::from_static(content_type),
        );
        if let Ok(v) =
            hyper::header::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        {
            h.insert("content-disposition", v);
        }
        r
    }
}

fn quote(text: &str) -> String {
    crate::problem::go_string(text)
}

fn strings_json(items: &[String]) -> String {
    format!(
        "[{}]",
        items.iter().map(|s| quote(s)).collect::<Vec<_>>().join(",")
    )
}

/// Go's `json.Unmarshal` of the optional `mapping` field into a `Mapping`.
fn parse_mapping(raw: &str, base: Mapping) -> Option<Mapping> {
    struct Fields(Mapping);
    impl<'de> serde::Deserialize<'de> for Fields {
        fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Fields;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<Fields, E> {
                    Ok(Fields(Mapping::empty()))
                }
                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Fields, M::Error> {
                    // Go starts from the caller's value and overwrites in document order.
                    let mut m = Mapping::empty();
                    m.full_name = i64::MIN;
                    let mut seen: [Option<i64>; 8] = [None; 8];
                    while let Some(key) = map.next_key::<String>()? {
                        let slot = match crate::guests_input::fold(&key).as_str() {
                            "fullname" => Some(0),
                            "firstname" => Some(1),
                            "lastname" => Some(2),
                            "email" => Some(3),
                            "company" => Some(4),
                            "jobtitle" => Some(5),
                            "phone" => Some(6),
                            "notes" => Some(7),
                            _ => None,
                        };
                        match slot {
                            Some(i) => {
                                if let Some(v) = map.next_value::<Option<i64>>()? {
                                    seen[i] = Some(v);
                                }
                            }
                            None => {
                                let _: serde::de::IgnoredAny = map.next_value()?;
                            }
                        }
                    }
                    let _ = m;
                    Ok(Fields(Mapping {
                        full_name: seen[0].unwrap_or(i64::MIN),
                        first_name: seen[1].unwrap_or(i64::MIN),
                        last_name: seen[2].unwrap_or(i64::MIN),
                        email: seen[3].unwrap_or(i64::MIN),
                        company: seen[4].unwrap_or(i64::MIN),
                        job_title: seen[5].unwrap_or(i64::MIN),
                        phone: seen[6].unwrap_or(i64::MIN),
                        notes: seen[7].unwrap_or(i64::MIN),
                    }))
                }
            }
            decoder.deserialize_any(V)
        }
    }
    let Fields(set) = serde_json::from_str::<Fields>(raw).ok()?;
    let pick = |new: i64, old: i64| if new == i64::MIN { old } else { new };
    Some(Mapping {
        full_name: pick(set.full_name, base.full_name),
        first_name: pick(set.first_name, base.first_name),
        last_name: pick(set.last_name, base.last_name),
        email: pick(set.email, base.email),
        company: pick(set.company, base.company),
        job_title: pick(set.job_title, base.job_title),
        phone: pick(set.phone, base.phone),
        notes: pick(set.notes, base.notes),
    })
}

/// What pgx prints for a failed statement.
fn pgx_text(f: &StatementFailure) -> String {
    match &f.sqlstate {
        Some(code) => format!("ERROR: {} (SQLSTATE {code})", f.message),
        None => f.message.clone(),
    }
}

const NOT_OWNED: &str = "address book not owned by verified mailbox";

/// The outcome of one import statement: `Ok(())` written, `Err(text)` Go's `err.Error()`.
fn written(outcome: Result<i64, StatementFailure>) -> Result<(), String> {
    match outcome {
        Ok(0) => Err(NOT_OWNED.into()),
        Ok(_) => Ok(()),
        Err(f) => Err(pgx_text(&f)),
    }
}

struct Ctx<'a> {
    exec: &'a ScopedExecutor,
    owner: i64,
    book: i64,
}

impl Ctx<'_> {
    async fn write(&self, vc: &vcard::VCard, upsert: bool) -> Result<(), String> {
        let emails = vcard::values_json(&vc.emails, "address");
        let phones = vcard::values_json(&vc.phones, "number");
        let urls = vcard::values_json(&vc.urls, "url");
        let impps = vcard::values_json(&vc.impps, "value");
        let addresses = vcard::addresses_json(&vc.addresses);
        let display = if vc.fn_.is_empty() { &vc.n } else { &vc.fn_ };
        let (first, last) = (vcard::first_name(&vc.n), vcard::last_name(&vc.n));
        let contact = db::NewContact {
            uid: &vc.uid,
            display_name: display,
            first_name: &first,
            last_name: &last,
            company: &vc.org,
            job_title: &vc.title,
            emails: &emails,
            phones: &phones,
            urls: &urls,
            instant_msgs: &impps,
            addresses: &addresses,
            notes: &vc.note,
            birthday: vc.birthday.as_deref(),
            anniversary: vc.anniversary.as_deref(),
        };
        written(db::write_contact(self.exec, self.owner, self.book, &contact, upsert).await)
    }

    async fn remove(&self, uid: &str) {
        let _ = db::remove_contact(self.exec, self.owner, self.book, uid).await;
    }

    async fn exists(&self, uid: &str) -> bool {
        db::exists(self.exec, self.book, uid, self.owner).await
    }

    /// Go's best-effort `notify_contact_state`.
    async fn notify(&self) {
        let _ = db::notify_import(self.exec, self.owner).await;
    }
}

fn import_result(imported: usize, skipped: usize, errors: &[String]) -> String {
    let errors = if errors.is_empty() {
        "null".to_owned()
    } else {
        strings_json(errors)
    };
    format!("{{\"imported\":{imported},\"skipped\":{skipped},\"errors\":{errors}}}\n")
}

impl<K: KeySource + 'static> ContactsRoute<K> {
    fn clone_parts(&self) -> Self {
        Self {
            exec: self.exec.clone(),
            keys: self.keys.clone(),
            issuer: self.issuer.clone(),
        }
    }

    async fn preview(&self, mut r: Request<Body>, out: &Out<'_>) -> Response<Body> {
        let (_, bad_query) = parse_query(r.uri().query());
        let form = upload(&mut r).await;
        let Ok(form) = form.and_then(|f| if bad_query { Err(()) } else { Ok(f) }) else {
            return out.bare(400, "invalid upload");
        };
        let Some(file) = form.file else {
            return out.bare(400, "missing file");
        };
        if csv::text(&file).trim().is_empty() {
            return out.bare(400, "empty csv");
        }
        let Ok(Some(header)) = csv::Reader::new(&file).read() else {
            return out.bare(400, "could not parse csv header");
        };
        let headers: Vec<String> = header.iter().map(|f| csv::text(f)).collect();
        let mapping = csv::detect_mapping(&headers);
        let sample = match csv::Reader::new(&file).read_all() {
            Ok(records) => {
                let rows: Vec<String> = records
                    .iter()
                    .skip(1)
                    .take(3)
                    .map(|row| strings_json(&row.iter().map(|f| csv::text(f)).collect::<Vec<_>>()))
                    .collect();
                format!("[{}]", rows.join(","))
            }
            Err(_) => "null".to_owned(),
        };
        out.ok(format!(
            "{{\"headers\":{},\"mapping\":{},\"sample\":{}}}\n",
            strings_json(&headers),
            mapping.json(),
            sample
        ))
    }

    /// The shared head of both imports: upload, `addressBookId`, `strategy` and
    /// the ownership gate. `Err` is the response.
    async fn begin(
        &self,
        r: &mut Request<Body>,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
        csv_only: bool,
    ) -> Result<(Upload, Vec<(String, String)>, i64, String, i64), Response<Body>> {
        let _ = (csv_only, actor);
        let (query, bad_query) = parse_query(r.uri().query());
        let form = upload(r).await;
        let Ok(form) = form.and_then(|f| if bad_query { Err(()) } else { Ok(f) }) else {
            return Err(out.bare(400, "invalid upload"));
        };
        if form.file.is_none() {
            return Err(out.bare(400, "missing file"));
        }
        let value = |name: &str| -> String {
            first(&query, name)
                .or_else(|| first(&form.values, name))
                .unwrap_or("")
                .to_owned()
        };
        let book = match value("addressBookId").parse::<i64>() {
            Ok(id) if id > 0 => id,
            _ => return Err(out.bare(400, "invalid addressBookId")),
        };
        let strategy = value("strategy");
        let others = query
            .iter()
            .chain(form.values.iter())
            .cloned()
            .collect::<Vec<_>>();
        Ok((form, others, book, strategy, 0))
    }

    async fn gate(
        &self,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
        book: i64,
    ) -> Result<i64, Response<Body>> {
        match db::owned_mailbox_for_book(&self.exec, book, actor.user_id()).await {
            Err(_) => Err(out.bare(500, "database error")),
            Ok(None) => Err(out.bare(403, "address book not found")),
            Ok(Some(owner)) => Ok(owner),
        }
    }

    async fn import_csv(
        &self,
        mut r: Request<Body>,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
    ) -> Response<Body> {
        let (form, all, book, strategy, _) = match self.begin(&mut r, out, actor, true).await {
            Ok(x) => x,
            Err(response) => return response,
        };
        let value = |name: &str| first(&all, name).unwrap_or("").to_owned();
        let dialect = value("dialect");
        if !dialect.is_empty() && dialect != "setjoin" {
            return out.bare(400, "invalid dialect");
        }
        let mut mapping = Mapping::empty();
        mapping.full_name = 0;
        mapping.first_name = 0;
        mapping.last_name = 0;
        mapping.company = 0;
        mapping.job_title = 0;
        mapping.phone = 0;
        mapping.notes = 0;
        let raw = value("mapping");
        if !raw.trim().is_empty() {
            match parse_mapping(&raw, mapping) {
                Some(m) => mapping = m,
                None => return out.bare(400, "invalid mapping"),
            }
        }
        let owner = match self.gate(out, actor, book).await {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let data = form.file.unwrap_or_default();
        let ctx = Ctx {
            exec: &self.exec,
            owner,
            book,
        };
        let (imported, skipped, errors) = self
            .run_csv(&ctx, &data, mapping, &strategy, &dialect)
            .await;
        if imported > 0 {
            ctx.notify().await;
        }
        out.ok(import_result(imported, skipped, &errors))
    }

    async fn run_csv(
        &self,
        ctx: &Ctx<'_>,
        data: &[u8],
        mut mapping: Mapping,
        strategy: &str,
        dialect: &str,
    ) -> (usize, usize, Vec<String>) {
        let records = match csv::Reader::new(data).read_all() {
            Ok(records) => records,
            Err(e) => return (0, 0, vec![format!("csv parse: {e}")]),
        };
        if records.is_empty() {
            return (0, 0, vec!["empty csv".into()]);
        }
        let headers: Vec<String> = records[0].iter().map(|f| csv::text(f)).collect();
        let detected = csv::detect_mapping(&headers);
        if mapping.email < 0 {
            mapping = detected;
        }
        let canonical = |s: &str| setjoin_directory_sync::ldap::canonical_address(s);
        let (mut imported, mut skipped, mut errors) = (0, 0, Vec::new());
        for (i, record) in records.iter().skip(1).enumerate() {
            let mut row: Vec<String> = record.iter().map(|f| csv::text(f)).collect();
            if dialect == "setjoin" {
                for cell in &mut row {
                    *cell = csv::unescape_cell(cell);
                }
            }
            if mapping.email >= 0
                && (mapping.email as usize) < row.len()
                && row[mapping.email as usize].trim().is_empty()
            {
                skipped += 1;
                continue;
            }
            let vc = csv::row_to_vcard(&mapping, &row, ctx.book, &canonical);
            if vc.uid.is_empty() {
                skipped += 1;
                continue;
            }
            match strategy {
                "skip" => {
                    if ctx.exists(&vc.uid).await {
                        skipped += 1;
                        continue;
                    }
                }
                "overwrite" => {
                    match ctx.write(&vc, true).await {
                        Ok(()) => imported += 1,
                        Err(e) => errors.push(format!("row {}: {e}", i + 2)),
                    }
                    continue;
                }
                _ => {}
            }
            match ctx.write(&vc, false).await {
                Ok(()) => imported += 1,
                Err(e) => errors.push(format!("row {}: {e}", i + 2)),
            }
        }
        (imported, skipped, errors)
    }

    async fn import_vcf(
        &self,
        mut r: Request<Body>,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
    ) -> Response<Body> {
        let (form, _, book, strategy, _) = match self.begin(&mut r, out, actor, false).await {
            Ok(x) => x,
            Err(response) => return response,
        };
        let owner = match self.gate(out, actor, book).await {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let data = csv::text(&form.file.unwrap_or_default());
        let ctx = Ctx {
            exec: &self.exec,
            owner,
            book,
        };
        let (mut imported, mut skipped, mut errors) = (0, 0, Vec::new());
        let mut cards = Vec::new();
        for block in vcard::split(&data) {
            match vcard::parse(&block) {
                Ok(card) => cards.push(card),
                Err(e) => errors.push(format!("vcard parse: {e}")),
            }
        }
        for mut vc in cards {
            match strategy.as_str() {
                "skip" => {
                    if ctx.exists(&vc.uid).await {
                        skipped += 1;
                        continue;
                    }
                }
                "overwrite" => ctx.remove(&vc.uid).await,
                "rename" => {
                    while ctx.exists(&vc.uid).await {
                        vc.uid.push_str("-migrated");
                    }
                }
                _ => {}
            }
            match ctx.write(&vc, false).await {
                Ok(()) => imported += 1,
                Err(e) => errors.push(format!("contact {}: {e}", vc.uid)),
            }
        }
        if imported > 0 {
            ctx.notify().await;
        }
        out.ok(import_result(imported, skipped, &errors))
    }

    async fn export_book(
        &self,
        r: &Request<Body>,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
        vcf: bool,
    ) -> Response<Body> {
        let (query, _) = parse_query(r.uri().query());
        let book = match first(&query, "addressBookId").unwrap_or("").parse::<i64>() {
            Ok(id) if id > 0 => id,
            _ => return out.bare(400, "invalid addressBookId"),
        };
        if let Err(response) = self.gate(out, actor, book).await {
            return response;
        }
        let user = actor.user_id();
        if vcf {
            let Ok(rows) = db::export_vcard_rows(&self.exec, book, user).await else {
                return out.bare(500, "export failed");
            };
            let mut body = String::new();
            for row in &rows {
                match vcard::render(row) {
                    Some(card) => body.push_str(&card),
                    None => return out.bare(500, "export failed"),
                }
            }
            return out.download("text/vcard; charset=utf-8", "contacts.vcf", body);
        }
        let Ok(rows) = db::export_csv_rows(&self.exec, book, user).await else {
            return out.bare(500, "export failed");
        };
        let mut body = String::new();
        csv::write_record(&mut body, &csv::EXPORT_HEADER.map(str::to_owned));
        for row in &rows {
            let first = |text: &str, keys: &[&str]| -> Option<String> {
                let items = vcard::decode_any_objects(text)?;
                let Some(head) = items.first() else {
                    return Some(String::new());
                };
                for key in keys {
                    if let Some(serde_json::Value::String(s)) = head.get(*key) {
                        if !s.is_empty() {
                            return Some(s.clone());
                        }
                    }
                }
                Some(String::new())
            };
            let (Some(email), Some(phone)) = (
                first(&row[5], &["address"]),
                first(&row[6], &["number", "value"]),
            ) else {
                return out.bare(500, "export failed");
            };
            let cells = [
                row[0].clone(),
                row[1].clone(),
                row[2].clone(),
                email,
                row[3].clone(),
                row[4].clone(),
                phone,
                row[7].clone(),
            ]
            .map(|c| csv::escape_cell(&c));
            csv::write_record(&mut body, &cells);
        }
        out.download("text/csv; charset=utf-8", "contacts.csv", body)
    }

    async fn export_contact(
        &self,
        r: &Request<Body>,
        out: &Out<'_>,
        actor: &setjoin_authz::AuthContext,
    ) -> Response<Body> {
        let (query, _) = parse_query(r.uri().query());
        let contact = match first(&query, "contactId").unwrap_or("").parse::<i64>() {
            Ok(id) if id > 0 => id,
            _ => return out.bare(400, "invalid contactId"),
        };
        match db::owns_contact(&self.exec, contact, actor.user_id()).await {
            Err(_) => return out.bare(500, "database error"),
            Ok(false) => return out.bare(403, "contact not found"),
            Ok(true) => {}
        }
        let row = match db::export_vcard_row(&self.exec, contact, actor.user_id()).await {
            Err(_) => return out.bare(500, "export failed"),
            Ok(None) => return out.bare(404, "contact not found"),
            Ok(Some(row)) => row,
        };
        let Some(card) = vcard::render(&row) else {
            return out.bare(500, "export failed");
        };
        out.download(
            "text/vcard; charset=utf-8",
            &vcard::filename(&row.display_name),
            card,
        )
    }
}

impl<K: KeySource + 'static> Intercept for ContactsRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        let path = r.uri().path();
        path.starts_with("/api/contacts/import/") || path.starts_with("/api/contacts/export/")
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let this = self.clone_parts();
        Box::pin(async move {
            let Some(auth) = setjoin_authz::authorize_request(
                &this.exec,
                &this.keys,
                &this.issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            // Go's RequireApp("contacts"): a refusal and its audit stay with Go.
            match setjoin_calendar::entitled_app(&this.exec, auth.context(), "contacts").await {
                Ok(true) => {}
                _ => return c.upstream.forward(r, &c.identity).await,
            }
            let Some(operation) = crate::jmap::random() else {
                let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), [0; 16]);
                return crate::jmap::reply::response(
                    Problem::new(503, "service unavailable").body(),
                    c.identity.proto,
                    id,
                );
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let out = Out { c: &c, id };
            let path = external(r.uri().path());
            let actor = auth.context();
            let (get, post) = (*r.method() == Method::GET, *r.method() == Method::POST);
            if post && path.ends_with("/import/csv/preview") {
                this.preview(r, &out).await
            } else if post && path.ends_with("/import/csv") {
                this.import_csv(r, &out, actor).await
            } else if post && path.ends_with("/import/vcf") {
                this.import_vcf(r, &out, actor).await
            } else if get && path.ends_with("/export/csv") {
                this.export_book(&r, &out, actor, false).await
            } else if get && path.ends_with("/export/vcf") {
                let (query, _) = parse_query(r.uri().query());
                if first(&query, "contactId").is_some_and(|v| !v.is_empty()) {
                    this.export_contact(&r, &out, actor).await
                } else {
                    this.export_book(&r, &out, actor, true).await
                }
            } else {
                out.bare(404, "not found")
            }
        })
    }
}
