//! F13 `sub-router-c` (#288): the four local-capture routes (lease, heartbeat,
//! stop, register), the two semantic-recording reads and the admin recordings
//! registry. Frozen Go is the oracle. No peripheral is called: the reducers own
//! every decision, and a local package is only ever a receipt, never bytes.
use super::{meet_problem, Authed, Kind};
use crate::chat::Fields;
use crate::chat_channels::fold;
use crate::{Body, Response};
use hyper::Request;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type Pairs = Vec<(String, Box<RawValue>)>;

const MAX_SEGMENTS: usize = 10_000;

/// Every occurrence of a field, in document order (Go folds key case).
fn occurrences<'a>(pairs: &'a Pairs, name: &'a str) -> impl Iterator<Item = &'a RawValue> + 'a {
    pairs
        .iter()
        .filter(move |(k, _)| fold(k) == name)
        .map(|(_, v)| &**v)
}

fn is_null(v: &RawValue) -> bool {
    v.get() == "null"
}

/// A non-pointer field: null leaves the earlier (or zero) value.
fn scalar<T: DeserializeOwned + Default>(pairs: &Pairs, name: &str) -> Result<T, ()> {
    let mut out = T::default();
    for v in occurrences(pairs, name) {
        if !is_null(v) {
            out = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(out)
}

/// A pointer field: null resets it.
fn pointer<T: DeserializeOwned>(pairs: &Pairs, name: &str) -> Result<Option<T>, ()> {
    let mut out = None;
    for v in occurrences(pairs, name) {
        out = serde_json::from_str::<Option<T>>(v.get()).map_err(|_| ())?;
    }
    Ok(out)
}

/// A nested struct: null is a no-op and repeated objects merge field by field.
fn nested(pairs: &Pairs, name: &str) -> Result<Pairs, ()> {
    let mut out = Vec::new();
    for v in occurrences(pairs, name) {
        if !is_null(v) {
            let Fields(inner) = serde_json::from_str(v.get()).map_err(|_| ())?;
            out.extend(inner);
        }
    }
    Ok(out)
}

/// A slice of structs: null empties it; a null element is a zero struct.
fn elements(pairs: &Pairs, name: &str) -> Result<Vec<Pairs>, ()> {
    let mut out = Vec::new();
    for v in occurrences(pairs, name) {
        let list: Option<Vec<Box<RawValue>>> = serde_json::from_str(v.get()).map_err(|_| ())?;
        out = Vec::new();
        for item in list.unwrap_or_default() {
            if is_null(&item) {
                out.push(Vec::new());
            } else {
                let Fields(inner) = serde_json::from_str(item.get()).map_err(|_| ())?;
                out.push(inner);
            }
        }
    }
    Ok(out)
}

#[derive(Default, Clone, Copy)]
struct Interval {
    start: i64,
    end: i64,
}

fn interval(pairs: &Pairs) -> Result<Interval, ()> {
    Ok(Interval {
        start: scalar(pairs, "STARTMS")?,
        end: scalar(pairs, "ENDMS")?,
    })
}

fn intervals(pairs: &Pairs, name: &str) -> Result<Vec<Interval>, ()> {
    elements(pairs, name)?.iter().map(interval).collect()
}

struct Segment {
    seq: i64,
    state: String,
    sha: Option<String>,
    bytes: Option<i64>,
    mime: Option<String>,
    codec: Option<String>,
    container: Option<String>,
    interval: Interval,
    wall_start: i64,
    wall_end: i64,
    reason: Option<String>,
}

struct Descriptor {
    schema: String,
    meeting: i64,
    recording: Option<i64>,
    package_state: String,
    capture_mode: String,
    policy_mode: String,
    surfaces: Vec<String>,
    platform: String,
    api_version: String,
    started: i64,
    ended: Option<i64>,
    registered: Option<i64>,
    segments: Vec<Segment>,
    uploaded: Option<bool>,
    available: Vec<Interval>,
    gaps: Vec<Interval>,
    digest: Option<String>,
}

/// Go's `json.Unmarshal` into `localPackageDescriptor`; any failure is 400.
fn descriptor(pairs: &Pairs) -> Result<Descriptor, ()> {
    let producer = nested(pairs, "PRODUCER")?;
    let coverage = nested(pairs, "COVERAGE")?;
    let mut segments = Vec::new();
    for s in elements(pairs, "SEGMENTS")? {
        segments.push(Segment {
            seq: scalar(&s, "SEQ")?,
            state: scalar(&s, "STATE")?,
            sha: pointer(&s, "CONTENTSHA256")?,
            bytes: pointer(&s, "BYTESIZE")?,
            mime: pointer(&s, "MIMETYPE")?,
            codec: pointer(&s, "CODEC")?,
            container: pointer(&s, "CONTAINER")?,
            interval: interval(&nested(&s, "INTERVAL")?)?,
            wall_start: scalar(&s, "WALLSTARTUNIXMS")?,
            wall_end: scalar(&s, "WALLENDUNIXMS")?,
            reason: pointer(&s, "INTERRUPTREASON")?,
        });
    }
    Ok(Descriptor {
        schema: scalar(pairs, "SCHEMA")?,
        meeting: scalar(pairs, "MEETINGID")?,
        recording: pointer(pairs, "RECORDINGID")?,
        package_state: scalar(pairs, "PACKAGESTATE")?,
        capture_mode: scalar(pairs, "CAPTUREMODE")?,
        policy_mode: scalar(pairs, "POLICYMODE")?,
        surfaces: strings(pairs, "SURFACES")?,
        platform: scalar(&producer, "PLATFORM")?,
        api_version: scalar(&producer, "CAPTUREAPIVERSION")?,
        started: scalar(pairs, "STARTEDATUNIXMS")?,
        ended: pointer(pairs, "ENDEDATUNIXMS")?,
        registered: pointer(pairs, "REGISTEREDATUNIXMS")?,
        segments,
        uploaded: pointer(pairs, "UPLOADEDTODRIVE")?,
        available: intervals(&coverage, "AVAILABLE")?,
        gaps: intervals(&coverage, "GAPS")?,
        digest: pointer(pairs, "INTEGRITYDIGEST")?,
    })
}

/// A `[]string` field: null empties it and a null element is "".
fn strings(pairs: &Pairs, name: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    for v in occurrences(pairs, name) {
        let list: Option<Vec<Option<String>>> = serde_json::from_str(v.get()).map_err(|_| ())?;
        out = list
            .unwrap_or_default()
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect();
    }
    Ok(out)
}

fn go_quote(text: &str) -> String {
    setjoin_admin_identity::scope_sets::go_quote(text)
}

/// `presentation.MediaSegment.Validate` for one sealed segment.
fn validate_segment(s: &Segment, meeting: i64, recording: i64) -> Result<(), String> {
    if recording <= 0 || meeting <= 0 {
        return Err("segment missing meeting/recording identity".into());
    }
    if s.seq < 1 {
        return Err("segment sequence numbers from 1".into());
    }
    let (start, end) = (s.interval.start, s.interval.end);
    if end <= start {
        return Err(format!(
            "segment {} interval [{start},{end}) is not a positive interval",
            s.seq
        ));
    }
    if s.wall_end < s.wall_start {
        return Err("segment wall-clock anchors run backwards".into());
    }
    let sha = s.sha.as_deref().unwrap_or("");
    let valid_sha = |text: &str| -> Result<(), String> {
        if text.len() != 64 {
            return Err(format!("sha256 {} is not 64 hex chars", go_quote(text)));
        }
        if let Some(bad) = text.bytes().find(|b| !b.is_ascii_hexdigit()) {
            return Err(format!(
                "sha256 {} is not hex: encoding/hex: invalid byte: {}",
                go_quote(text),
                go_unicode(bad as char)
            ));
        }
        Ok(())
    };
    match s.state.as_str() {
        "capturing" => unreachable!("rejected before validation"),
        "verified" => {
            valid_sha(sha).map_err(|e| format!("verified segment {} digest: {e}", s.seq))?;
            if s.bytes.unwrap_or(0) <= 0 {
                return Err(format!("verified segment {} carries no byte size", s.seq));
            }
            let empty = |v: &Option<String>| v.as_deref().unwrap_or("").is_empty();
            if empty(&s.mime) || empty(&s.codec) || empty(&s.container) {
                return Err(format!(
                    "verified segment {} missing actual MIME/codec/container",
                    s.seq
                ));
            }
        }
        "interrupted" | "failed" => {
            if !sha.is_empty() {
                valid_sha(sha).map_err(|e| format!("segment {} observed digest: {e}", s.seq))?;
            }
            if s.reason.as_deref().unwrap_or("").is_empty() {
                return Err(format!(
                    "{} segment {} must name why it stopped (truthful partial result)",
                    s.state, s.seq
                ));
            }
        }
        other => {
            return Err(format!(
                "unknown segment state {} fails closed",
                go_quote(other)
            ))
        }
    }
    Ok(())
}

/// Go's `%#U`: `U+0067 'g'`, the quoted form only for a printable rune.
fn go_unicode(c: char) -> String {
    let quoted = go_quote(&c.to_string());
    let inner = &quoted[1..quoted.len() - 1];
    let printable = !inner.starts_with('\\') || matches!(c, '"' | '\\');
    let shown = if c == '"' {
        "\"".to_owned()
    } else {
        inner.to_owned()
    };
    let shown = if c == '\\' { "\\".to_owned() } else { shown };
    if printable {
        format!("U+{:04X} '{shown}'", c as u32)
    } else {
        format!("U+{:04X}", c as u32)
    }
}

/// Go's `validateLocalDescriptor`, message for message.
fn validate(d: &Descriptor, meeting: i64, recording: i64) -> Result<(), String> {
    if d.schema != "sjrec-local-v1" {
        return Err(format!(
            "descriptor schema {} is not sjrec-local-v1",
            go_quote(&d.schema)
        ));
    }
    if d.capture_mode != "local_registered" {
        return Err(format!(
            "descriptor captureMode {} is not local_registered",
            go_quote(&d.capture_mode)
        ));
    }
    if d.uploaded.is_none_or(|v| v) {
        return Err("descriptor claims an upload path that does not exist".into());
    }
    if !matches!(
        d.policy_mode.as_str(),
        "local_preferred" | "server_only" | "local_only" | "disabled"
    ) {
        return Err("unknown policy mode fails closed".into());
    }
    if d.meeting != meeting {
        return Err(format!(
            "descriptor binds meeting {}, not {meeting}",
            d.meeting
        ));
    }
    if let Some(bound) = d.recording {
        if bound != recording {
            return Err(format!(
                "descriptor binds recording {bound}, not {recording}"
            ));
        }
    }
    if !matches!(
        d.package_state.as_str(),
        "finalized" | "interrupted" | "registered"
    ) {
        return Err(format!(
            "a {} descriptor is not a sealed package",
            go_quote(&d.package_state)
        ));
    }
    let Some(ended) = d.ended else {
        return Err(format!(
            "a {} descriptor must carry its end time",
            d.package_state
        ));
    };
    if d.started <= 0 {
        return Err("descriptor missing start time".into());
    }
    if ended < d.started {
        return Err("descriptor ends before it starts".into());
    }
    if d.package_state == "registered" && d.registered.is_none() {
        return Err("a registered descriptor must carry its registration time".into());
    }
    if d.platform.is_empty() || d.api_version.is_empty() {
        return Err("descriptor producer must pin platform and captureApiVersion".into());
    }
    if d.surfaces.is_empty() {
        return Err("descriptor covers no capture surface".into());
    }
    let mut seen = Vec::new();
    for s in &d.surfaces {
        if s != "microphone" && s != "systemAudio" {
            return Err(format!(
                "descriptor surface {} is not a capture surface",
                go_quote(s)
            ));
        }
        if seen.contains(&s) {
            return Err(format!("descriptor surface {} is duplicated", go_quote(s)));
        }
        seen.push(s);
    }
    if d.segments.is_empty() || d.segments.len() > MAX_SEGMENTS {
        return Err(format!("descriptor segments must number 1..{MAX_SEGMENTS}"));
    }
    for s in &d.segments {
        if s.state == "capturing" {
            return Err(format!(
                "sealed descriptor segment {} carries state capturing",
                s.seq
            ));
        }
        validate_segment(s, meeting, recording)?;
    }
    // Coverage truthfulness: recompute and refuse any drift from the claim.
    let max_end = d.segments.iter().map(|s| s.interval.end).max().unwrap_or(0);
    let mut verified: Vec<&Segment> = d
        .segments
        .iter()
        .filter(|s| s.state == "verified")
        .collect();
    verified.sort_by_key(|s| s.interval.start);
    for pair in verified.windows(2) {
        let (a, b) = (pair[0].interval, pair[1].interval);
        if b.start < a.end && a.start < b.end {
            return Err(format!(
                "verified segments {} and {} overlap \u{2014} duplicate media fails closed",
                pair[0].seq, pair[1].seq
            ));
        }
    }
    let mut available: Vec<(i64, i64)> = Vec::new();
    for s in &verified {
        let (start, end) = (s.interval.start.max(0), s.interval.end.min(max_end));
        if end <= start {
            continue;
        }
        match available.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => available.push((start, end)),
        }
    }
    let mut gaps = Vec::new();
    let mut cursor = 0;
    for (start, end) in &available {
        if *start > cursor {
            gaps.push((cursor, *start));
        }
        if *end > cursor {
            cursor = *end;
        }
    }
    if cursor < max_end {
        gaps.push((cursor, max_end));
    }
    let same = |computed: &[(i64, i64)], claimed: &[Interval]| {
        computed.len() == claimed.len()
            && computed
                .iter()
                .zip(claimed)
                .all(|(c, k)| c.0 == k.start && c.1 == k.end)
    };
    if !same(&available, &d.available) || !same(&gaps, &d.gaps) {
        return Err("descriptor coverage does not match its segments (fabricated coverage)".into());
    }
    Ok(())
}

/// ECMAScript `JSON.stringify` string escaping, as the client canonicalises.
fn canonical_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Recursively key-sorted JSON with number literals kept verbatim.
fn canonical(raw: &RawValue, out: &mut String) -> Result<(), ()> {
    let text = raw.get();
    match text.as_bytes().first().ok_or(())? {
        b'{' => {
            let Fields(pairs) = serde_json::from_str(text).map_err(|_| ())?;
            let map: BTreeMap<String, Box<RawValue>> = pairs.into_iter().collect();
            canonical_map(&map, out)
        }
        b'[' => {
            let items: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        b'"' => {
            let value: String = serde_json::from_str(text).map_err(|_| ())?;
            canonical_string(out, &value);
            Ok(())
        }
        _ => {
            out.push_str(text);
            Ok(())
        }
    }
}

fn canonical_map(map: &BTreeMap<String, Box<RawValue>>, out: &mut String) -> Result<(), ()> {
    out.push('{');
    for (i, (key, value)) in map.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        canonical_string(out, key);
        out.push(':');
        canonical(value, out)?;
    }
    out.push('}');
    Ok(())
}

/// Go's `verifyDescriptorDigest`: sha256 over the canonical bytes with the
/// seal cleared to null, compared with the claimed digest.
fn verify_digest(text: &str, claimed: &str) -> Result<(), String> {
    let Fields(pairs) = serde_json::from_str(text).map_err(|_| "descriptor is not valid JSON")?;
    let mut map: BTreeMap<String, Box<RawValue>> = pairs.into_iter().collect();
    if !map.contains_key("integrityDigest") {
        return Err("descriptor carries no integrityDigest field".into());
    }
    map.insert(
        "integrityDigest".into(),
        RawValue::from_string("null".into()).expect("null literal"),
    );
    let mut sealed = String::new();
    canonical_map(&map, &mut sealed)
        .map_err(|()| "descriptor carries a value canonical form cannot pin".to_string())?;
    if claimed.is_empty() {
        return Err("descriptor carries no sealed integrity digest".into());
    }
    let sum = Sha256::digest(sealed.as_bytes());
    let hex: String = sum.iter().map(|b| format!("{b:02x}")).collect();
    if hex != claimed {
        return Err("descriptor integrity digest does not seal its own bytes".into());
    }
    Ok(())
}

impl Authed<'_> {
    fn new_operation(&self) -> Result<[u8; 16], Response<Body>> {
        crate::jmap::random().ok_or_else(|| self.problem(500, "request failed"))
    }

    fn numeric(&self, text: &str, what: &str) -> Result<i64, Response<Body>> {
        text.parse::<i64>()
            .map_err(|_| self.problem(400, &format!("invalid {what} id")))
    }

    /// Go's `WriteProblem` 413: instance kept, title `http.StatusText(413)`.
    fn too_large(&self) -> Response<Body> {
        let raw = crate::chat::go_problem_json(
            "about:blank",
            "Request Entity Too Large",
            413,
            "request body exceeds the allowed size",
            self.path,
            None,
        );
        let mut reply = crate::jmap::reply::response(raw, self.c.identity.proto, self.id.clone());
        *reply.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
        reply.headers_mut().insert(
            "content-type",
            hyper::header::HeaderValue::from_static("application/problem+json"),
        );
        if let Ok(tag) = self.language.parse() {
            reply.headers_mut().insert("content-language", tag);
        }
        reply
    }

    fn unprocessable(&self, detail: &str) -> Response<Body> {
        self.problem(422, detail)
    }

    pub(super) async fn run_c(
        &self,
        kind: Kind,
        meeting: &str,
        recording: Option<&str>,
        mut r: Request<Body>,
    ) -> Response<Body> {
        match self.dispatch_c(kind, meeting, recording, &mut r).await {
            Ok(reply) | Err(reply) => reply,
        }
    }

    async fn dispatch_c(
        &self,
        kind: Kind,
        meeting: &str,
        recording: Option<&str>,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let (exec, actor) = (self.exec, self.actor);
        // Committed-state reads are never flag-gated; every local-capture route is
        // new intent behind feature.meet_local_recording (OFF is a plain 404).
        if !matches!(kind, Kind::SemPackage | Kind::SemReplay) {
            match setjoin_meet::flag(exec, "feature.meet_local_recording", false).await {
                Ok(true) => {}
                Ok(false) => return Err(self.plain(404, "not found")),
                Err(_) => return Err(self.plain(500, "internal error")),
            }
        }
        let id = self.numeric(meeting, "meeting")?;
        if kind == Kind::LocalLease {
            return self.lease(id, r).await;
        }
        let rid = self.numeric(recording.unwrap_or(""), "semantic recording")?;
        match kind {
            Kind::SemPackage | Kind::SemReplay => {
                let out = if kind == Kind::SemPackage {
                    setjoin_meet::semantic_package(exec, actor, id, rid).await
                } else {
                    setjoin_meet::semantic_replay(exec, actor, id, rid).await
                };
                match out {
                    Ok(raw) => Ok(self.json(200, &raw)),
                    Err(e) => Err(super::failure(
                        &e,
                        self.path,
                        self.c,
                        self.id.clone(),
                        self.language,
                    )),
                }
            }
            Kind::LocalHeartbeat => self.heartbeat(id, rid, r).await,
            Kind::LocalStop => self.stop(id, rid, r).await,
            Kind::LocalRegister => self.register(id, rid, r).await,
            _ => unreachable!("not a sub-router-c route"),
        }
    }

    async fn lease(
        &self,
        id: i64,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let fields = self.fields(r).await?;
        let invalid = |()| self.problem(400, "invalid JSON");
        let Fields(pairs) = fields;
        let device: String = scalar(&pairs, "DEVICEID").map_err(invalid)?;
        let surfaces = strings(&pairs, "SURFACES").map_err(invalid)?;
        let producer = nested(&pairs, "PRODUCER").map_err(invalid)?;
        let platform: String = scalar(&producer, "PLATFORM").map_err(invalid)?;
        let version: String = scalar(&producer, "PLATFORMVERSION").map_err(invalid)?;
        let api: String = scalar(&producer, "CAPTUREAPIVERSION").map_err(invalid)?;
        let seconds: Option<i64> = pointer(&pairs, "HEARTBEATSECONDS").map_err(invalid)?;
        if device.is_empty() || device.len() > 256 {
            return Err(self.unprocessable("deviceId must be 1..256 characters"));
        }
        if surfaces.is_empty() {
            return Err(self.unprocessable("surfaces must cover at least one capture surface"));
        }
        let mut seen: Vec<&str> = Vec::new();
        for s in &surfaces {
            if s != "microphone" && s != "systemAudio" {
                return Err(self.unprocessable("surfaces must be microphone/systemAudio only"));
            }
            if seen.contains(&s.as_str()) {
                return Err(self.unprocessable("surfaces must not repeat a surface"));
            }
            seen.push(s);
        }
        if platform.is_empty() || api.is_empty() {
            return Err(self.unprocessable("producer must pin platform and captureApiVersion"));
        }
        let seconds = seconds.unwrap_or(10);
        if !(5..=60).contains(&seconds) {
            return Err(self.unprocessable("heartbeatSeconds must be 5..60"));
        }
        let surfaces_json = serde_json::to_string(&surfaces).expect("strings");
        // Go marshals a map: keys sorted, HTML characters escaped.
        let producer_json = setjoin_admin_identity::go_escape(
            &serde_json::json!({
                "platform": platform,
                "platformVersion": version,
                "captureApiVersion": api,
            })
            .to_string(),
        );
        let raw = self.commit(
            setjoin_meet::local_lease_acquire(
                self.exec,
                self.actor,
                id,
                &device,
                &setjoin_admin_identity::go_escape(&surfaces_json),
                &producer_json,
                seconds,
                self.new_operation()?,
            )
            .await,
        )?;
        Ok(self.json(201, &raw))
    }

    async fn heartbeat(
        &self,
        id: i64,
        rid: i64,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let Fields(pairs) = self.fields(r).await?;
        let invalid = |()| self.problem(400, "invalid JSON");
        let generation: i64 = scalar(&pairs, "LEASEGENERATION").map_err(invalid)?;
        let seq: i64 = scalar(&pairs, "SEQ").map_err(invalid)?;
        let state: String = scalar(&pairs, "CAPTURESTATE").map_err(invalid)?;
        let disk: Option<i64> = pointer(&pairs, "DISKFREEBYTES").map_err(invalid)?;
        if !matches!(state.as_str(), "" | "capturing" | "stopping" | "stopped") {
            return Err(self.unprocessable("captureState must be capturing/stopping/stopped"));
        }
        if seq < 1 {
            return Err(self.unprocessable("seq numbers from 1"));
        }
        let state = if state.is_empty() {
            "capturing"
        } else {
            &state
        };
        let raw = self.commit(
            setjoin_meet::local_lease_heartbeat(
                self.exec,
                self.actor,
                id,
                rid,
                generation,
                seq,
                state,
                disk,
                self.new_operation()?,
            )
            .await,
        )?;
        Ok(self.json(200, &raw))
    }

    async fn stop(
        &self,
        id: i64,
        rid: i64,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let Fields(pairs) = self.fields(r).await?;
        let invalid = |()| self.problem(400, "invalid JSON");
        let generation: Option<i64> = pointer(&pairs, "LEASEGENERATION").map_err(invalid)?;
        let reason: String = scalar(&pairs, "REASON").map_err(invalid)?;
        let reason = if reason.is_empty() {
            "user_stop".to_owned()
        } else {
            reason
        };
        if !matches!(reason.as_str(), "user_stop" | "revoked") {
            return Err(self.unprocessable("a lease stop names user_stop or revoked"));
        }
        let raw = self.commit(
            setjoin_meet::local_lease_stop(
                self.exec,
                self.actor,
                id,
                rid,
                generation,
                &reason,
                self.new_operation()?,
            )
            .await,
        )?;
        Ok(self.json(200, &raw))
    }

    async fn register(
        &self,
        id: i64,
        rid: i64,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        use crate::chat_channels::{read_body, ReadError};
        let bytes = match read_body(r).await {
            Ok(bytes) => bytes,
            Err(ReadError::TooLarge) => return Err(self.too_large()),
            Err(ReadError::Transport) => return Err(self.problem(400, "invalid JSON")),
        };
        let text = crate::chat::go_json_text(&bytes);
        let invalid = || self.problem(400, "invalid JSON");
        let mut decoder = serde_json::Deserializer::from_str(&text);
        let Fields(pairs) =
            <Fields as serde::Deserialize>::deserialize(&mut decoder).map_err(|_| invalid())?;
        decoder.end().map_err(|_| invalid())?;
        let parsed = descriptor(&pairs).map_err(|()| invalid())?;
        let not_admitted = |detail: &str| {
            meet_problem(
                403,
                detail,
                "local-package-not-admitted",
                "local-package-not-admitted",
                self.path,
                self.c,
                self.id.clone(),
                self.language,
            )
        };
        // The slug here is Go's literal `Code`/`Type` pair, not a reducer code.
        validate(&parsed, id, rid).map_err(|e| not_admitted(&e))?;
        verify_digest(&text, parsed.digest.as_deref().unwrap_or(""))
            .map_err(|e| not_admitted(&e))?;
        // The reducer receives the exact received bytes; Postgres refuses invalid
        // UTF-8 there, which Go reports as an unclassified 500.
        let Ok(exact) = String::from_utf8(bytes) else {
            return Err(self.problem(500, "request failed"));
        };
        let raw = self.commit(
            setjoin_meet::local_register(
                self.exec,
                self.actor,
                id,
                rid,
                &exact,
                self.new_operation()?,
            )
            .await,
        )?;
        Ok(self.json(200, &raw))
    }
}

/// `GET /admin/meet/recordings`: Go's `drive.view`-gated, audited registry read.
/// Shared authorization already passed; this is the permission, the filters and
/// the worker-credential read.
pub(super) async fn registry(
    exec: &setjoin_pg::ScopedExecutor,
    worker: &setjoin_pg::ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    r: &Request<Body>,
    c: &crate::RequestContext,
    id: String,
    language: &str,
    path: &str,
) -> Response<Body> {
    let Some(operation) = crate::jmap::random() else {
        return super::plain(503, "service unavailable", c, id);
    };
    let Ok(authority) = setjoin_admin_identity::authority(exec, actor).await else {
        return super::plain(500, "internal error", c, id);
    };
    if !authority.allows_any(&["drive.view"]) {
        let _ = setjoin_admin_identity::console_denied(exec, actor, path, "drive.view", operation)
            .await;
        return super::plain(403, "Forbidden", c, id);
    }
    let query = r.uri().query().unwrap_or("");
    let value = |name: &str| query_value(query, name).filter(|v| !v.is_empty());
    let state = value("state");
    let meeting = match value("meetingId") {
        None => None,
        Some(text) => match text.parse::<i64>() {
            Ok(v) => Some(v),
            Err(_) => return super::problem(400, "invalid meetingId", path, c, id, language),
        },
    };
    let rows = match setjoin_meet::registry_list(worker, state.as_deref(), meeting).await {
        Ok(rows) => rows,
        Err(_) => return super::problem(500, "request failed", path, c, id, language),
    };
    // Audited read; a failure only matters to Go's log, never to the caller.
    let ip = c.identity.client_ip.to_string();
    let _ = setjoin_meet::registry_audit(exec, actor, &ip, operation).await;
    let text =
        |v: &str| setjoin_admin_identity::go_escape(&serde_json::to_string(v).expect("text"));
    let items: Vec<String> = rows
        .iter()
        .map(|row| {
            let mut out = format!(
                "{{\"id\":{},\"meetingId\":{},\"meetingTitle\":{},\"state\":{},\"startedBy\":{},\"startedAt\":{}",
                row.id,
                row.meeting,
                text(&row.title),
                text(&row.state),
                row.started_by,
                text(&row.started_at)
            );
            if let Some(v) = &row.stopped_at {
                out += &format!(",\"stoppedAt\":{}", text(v));
            }
            for (key, v) in [
                ("durationMs", row.duration_ms),
                ("sizeBytes", row.size_bytes),
                ("fileNodeId", row.file_node),
                ("versionId", row.version),
            ] {
                if let Some(v) = v {
                    out += &format!(",\"{key}\":{v}");
                }
            }
            if let Some(v) = &row.error {
                out += &format!(",\"error\":{}", text(v));
            }
            out + "}"
        })
        .collect();
    super::json_reply(200, format!("[{}]\n", items.join(",")), c, id)
}

/// Go's `r.URL.Query().Get`: first match, `;` pairs and bad escapes dropped.
fn query_value(raw: &str, name: &str) -> Option<String> {
    fn decode(s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let (mut out, mut i) = (Vec::new(), 0);
        while i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' => {
                    let a = (*bytes.get(i + 1)? as char).to_digit(16)?;
                    let b = (*bytes.get(i + 2)? as char).to_digit(16)?;
                    out.push((a * 16 + b) as u8);
                    i += 3;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }
    for pair in raw.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (decode(k), decode(v)) else {
            continue;
        };
        if k == name {
            return Some(v);
        }
    }
    None
}
