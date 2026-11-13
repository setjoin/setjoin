//! F13 `sub-router-b` (#287): recording and captions start/stop, the eleven
//! presentation routes and the two annotation routes. The reducers own every
//! decision; LiveKit Egress and the ASR bot are peripherals that only follow a
//! committed reducer fact, and a failure is reported, never allowed to undo it.
use super::{meet_problem, Authed, Kind};
use crate::chat_channels::{bool_field, number_field, optional_field, text_field};
use crate::{Body, Response};
use hyper::Request;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Go's checkpoint refresh budget: 5 per second sustained, burst of 2, per user.
const REFRESH_PER_SECOND: f64 = 5.0;
const REFRESH_BURST: f64 = 2.0;
const MIN_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);
const MAX_SNAPSHOT: usize = 16 << 10;
const MAX_PAGES: i64 = 500;

/// Go's `presentationThrottle`: an in-process politeness bound, never authority.
#[derive(Default)]
pub struct Throttle(Mutex<HashMap<i64, (f64, Instant)>>, Option<Instant>);

impl Throttle {
    /// A throttle whose clock never advances, so a test that sends requests back to back on a
    /// slow host sees the burst, never the refill (#421). Only the clock is pinned.
    pub fn pinned() -> Self {
        Self(Mutex::default(), Some(Instant::now()))
    }

    /// `Ok` when one refresh is admitted, else the clamped back-off.
    fn admit(&self, user: i64) -> Result<(), Duration> {
        let now = self.1.unwrap_or_else(Instant::now);
        let mut buckets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > 1024 {
            buckets.retain(|_, (_, last)| now.duration_since(*last) <= MAX_RETRY);
        }
        let (tokens, last) = buckets.entry(user).or_insert((REFRESH_BURST, now));
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        if elapsed > 0.0 {
            *tokens = REFRESH_BURST.min(*tokens + elapsed * REFRESH_PER_SECOND);
        }
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            return Ok(());
        }
        let wait = Duration::from_secs_f64((1.0 - *tokens) / REFRESH_PER_SECOND)
            .clamp(MIN_RETRY, MAX_RETRY);
        Err(wait)
    }
}

/// The committed fact every mutating presentation reducer returns.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Fact {
    #[serde(rename = "presentationId")]
    id: i64,
    status: String,
    #[serde(rename = "checkpointSeq")]
    seq: i64,
    #[serde(rename = "presenterGeneration")]
    generation: i64,
    #[serde(rename = "pageIndex")]
    page: i64,
    #[serde(rename = "manifestGeneration")]
    manifest: i64,
    annotation: Option<Annotation>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
struct Annotation {
    #[serde(rename = "snapshotRef")]
    reference: String,
    sha256: String,
    #[serde(rename = "byteSize")]
    size: i64,
}

impl Annotation {
    fn json(&self) -> String {
        format!(
            "{{\"snapshotRef\":{},\"sha256\":{},\"byteSize\":{}}}",
            js(&self.reference),
            js(&self.sha256),
            self.size
        )
    }
}

fn js(text: &str) -> String {
    serde_json::Value::String(text.into()).to_string()
}

fn admitted_reference(r: &str) -> bool {
    let Some(rest) = r.strip_prefix("annotations/p") else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(".json") else {
        return false;
    };
    let Some((p, s)) = rest.split_once("-s") else {
        return false;
    };
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    digits(p) && digits(s)
}

/// The versioned envelope; Go's `Encode` refuses a malformed or oversized frame
/// and the caller then omits the field (committed state stays committed).
fn frame(fact: &Fact, kind: &str, payload: Option<String>) -> Option<String> {
    let valid = match kind {
        "page.changed" => (0..MAX_PAGES).contains(&fact.page),
        "annotation.committed" => fact.annotation.as_ref().is_some_and(|a| {
            admitted_reference(&a.reference)
                && a.sha256.len() == 64
                && a.sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                && (1..=MAX_SNAPSHOT as i64).contains(&a.size)
        }),
        _ => true,
    } && fact.seq >= 0
        && fact.generation >= 0;
    if !valid {
        return None;
    }
    let sent = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let payload = payload.map_or(String::new(), |p| format!(",\"payload\":{p}"));
    let text = format!(
        "{{\"t\":\"presentation\",\"v\":1,\"presentationId\":\"{}\",\"checkpointSeq\":{},\"presenterGeneration\":{},\"kind\":{}{payload},\"sentAt\":\"{sent}\"}}",
        fact.id,
        fact.seq,
        fact.generation,
        js(kind)
    );
    (text.len() <= 14000).then_some(text)
}

impl Authed<'_> {
    fn flag_off_reply(&self) -> Response<Body> {
        self.plain(404, "not found")
    }

    /// feature.meet_document_presentation and feature.drive must both be ON.
    async fn presentation_on(&self) -> Result<(), Response<Body>> {
        for key in ["feature.meet_document_presentation", "feature.drive"] {
            match setjoin_meet::flag(self.exec, key, false).await {
                Ok(true) => {}
                Ok(false) => return Err(self.flag_off_reply()),
                Err(_) => return Err(self.plain(500, "internal error")),
            }
        }
        Ok(())
    }

    async fn gate(&self, keys: &[&str]) -> Result<(), Response<Body>> {
        for key in keys {
            match setjoin_meet::flag(self.exec, key, false).await {
                Ok(true) => {}
                Ok(false) => return Err(self.flag_off_reply()),
                Err(_) => return Err(self.plain(500, "internal error")),
            }
        }
        Ok(())
    }

    fn unconfigured(&self, detail: &str) -> Response<Body> {
        super::unconfigured_with(detail, self.path, self.c, self.id.clone(), self.language)
    }

    fn operation(&self) -> Result<[u8; 16], Response<Body>> {
        crate::jmap::random().ok_or_else(|| self.problem(500, "request failed"))
    }

    fn id_of(&self, text: &str, what: &str) -> Result<i64, Response<Body>> {
        text.parse::<i64>()
            .map_err(|_| self.problem(400, &format!("invalid {what} id")))
    }

    pub(super) async fn run_b(
        &self,
        kind: Kind,
        meeting: &str,
        pres: Option<&str>,
        mut r: Request<Body>,
    ) -> Response<Body> {
        match self.dispatch_b(kind, meeting, pres, &mut r).await {
            Ok(reply) | Err(reply) => reply,
        }
    }

    async fn dispatch_b(
        &self,
        kind: Kind,
        meeting: &str,
        pres: Option<&str>,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let (exec, actor, livekit) = (self.exec, self.actor, self.livekit);
        match kind {
            Kind::RecStart => {
                self.gate(&["feature.meet_recording", "feature.drive"])
                    .await?;
                let id = self.id_of(meeting, "meeting")?;
                if !livekit.egress() {
                    return Err(
                        self.unconfigured("recording is not configured (egress runtime missing)")
                    );
                }
                let recording = self.commit(
                    setjoin_meet::recording_start(exec, actor, id, self.operation()?).await,
                )?;
                let failed = async |reason: &str| {
                    // Best effort, exactly as Go's bindFailed: a failure is only logged.
                    if let Ok(op) = self.operation() {
                        let _ = setjoin_meet::recording_bind(
                            exec,
                            actor,
                            recording,
                            None,
                            Some(reason),
                            op,
                        )
                        .await;
                    }
                };
                let room = match setjoin_meet::room_name(exec, actor, id).await {
                    Ok(room) => room,
                    Err(_) => {
                        failed("internal: room lookup failed").await;
                        return Err(self.plain(500, "internal error"));
                    }
                };
                let key = format!("meet-egress/{recording}-{room}.mp4");
                match livekit.start_room_composite(&room, &key).await {
                    Ok(egress) => {
                        self.commit(
                            setjoin_meet::recording_bind(
                                exec,
                                actor,
                                recording,
                                Some((&egress, &key)),
                                None,
                                self.operation()?,
                            )
                            .await,
                        )?;
                        Ok(super::json_reply(
                            201,
                            format!("{{\"recordingId\":{recording}}}\n"),
                            self.c,
                            self.id.clone(),
                        ))
                    }
                    Err(crate::meet_livekit::PeripheralError::Busy) => {
                        failed("egress_busy").await;
                        Err(meet_problem(
                            503,
                            "recording capacity is in use; try again shortly",
                            "egress-busy",
                            "egressBusy",
                            self.path,
                            self.c,
                            self.id.clone(),
                            self.language,
                        ))
                    }
                    Err(_) => {
                        failed("egress start failed").await;
                        Err(self.plain(502, "could not start the recording"))
                    }
                }
            }
            Kind::RecStop => {
                let id = self.id_of(meeting, "meeting")?;
                if !livekit.egress() {
                    return Err(
                        self.unconfigured("recording is not configured (egress runtime missing)")
                    );
                }
                let raw = self.commit(
                    setjoin_meet::recording_stop(exec, actor, id, self.operation()?).await,
                )?;
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Stop {
                    #[serde(rename = "egressId")]
                    egress: Option<String>,
                }
                let stop: Stop =
                    serde_json::from_str(&raw).map_err(|_| self.plain(500, "internal error"))?;
                if let Some(egress) = stop.egress {
                    if livekit.stop_egress(&egress).await.is_err() {
                        return Err(self.plain(
                            502,
                            "stopping, but the egress stop call failed; will be retried",
                        ));
                    }
                }
                Ok(super::empty_reply(204, self.c, self.id.clone()))
            }
            Kind::CapStart => {
                self.gate(&["feature.meet_captions"]).await?;
                let id = self.id_of(meeting, "meeting")?;
                if !livekit.captions_configured() {
                    return Err(
                        self.unconfigured("captions is not configured (ASR runtime missing)")
                    );
                }
                let spec = self.commit(
                    setjoin_meet::captions_set(exec, actor, id, true, self.operation()?).await,
                )?;
                let Some(spec) = spec else {
                    return Ok(super::empty_reply(204, self.c, self.id.clone()));
                };
                let rollback = async || {
                    if let Ok(op) = self.operation() {
                        let _ = setjoin_meet::captions_set(exec, actor, id, false, op).await;
                    }
                };
                let spec = match self.grant(&spec) {
                    Ok(spec) => spec,
                    Err(reply) => return Err(reply),
                };
                let token = match livekit.mint(&spec) {
                    Ok((token, _)) => token,
                    Err(()) => {
                        rollback().await;
                        return Err(self.plain(500, "internal error"));
                    }
                };
                match livekit.captions_start(&spec.room, &token).await {
                    Ok(()) => Ok(super::empty_reply(204, self.c, self.id.clone())),
                    Err(error) => {
                        rollback().await;
                        if error == crate::meet_livekit::PeripheralError::Busy {
                            Err(meet_problem(
                                503,
                                "caption capacity is in use; try again shortly",
                                "captions-busy",
                                "captionsBusy",
                                self.path,
                                self.c,
                                self.id.clone(),
                                self.language,
                            ))
                        } else {
                            Err(self.plain(502, "could not start captions"))
                        }
                    }
                }
            }
            Kind::CapStop => {
                let id = self.id_of(meeting, "meeting")?;
                self.commit(
                    setjoin_meet::captions_set(exec, actor, id, false, self.operation()?).await,
                )?;
                if !livekit.captions_configured() {
                    return Ok(super::empty_reply(204, self.c, self.id.clone()));
                }
                let Ok(room) = setjoin_meet::room_name(exec, actor, id).await else {
                    return Err(self.plain(500, "internal error"));
                };
                if livekit.captions_stop(&room).await.is_err() {
                    return Err(self.plain(
                        502,
                        "stopping, but the captions stop call failed; will be retried",
                    ));
                }
                Ok(super::empty_reply(204, self.c, self.id.clone()))
            }
            Kind::Prepare => {
                self.presentation_on().await?;
                let id = self.id_of(meeting, "meeting")?;
                let fields = self.fields(r).await?;
                let invalid = |()| self.problem(400, "invalid JSON");
                let node = number_field(&fields, "NODEID").map_err(invalid)?;
                let version = number_field(&fields, "VERSIONID").map_err(invalid)?;
                let digest = text_field(&fields, "MANIFESTDIGEST").map_err(invalid)?;
                let created = self.commit(
                    setjoin_meet::presentation_prepare(
                        exec,
                        actor,
                        id,
                        node,
                        version,
                        &digest,
                        self.operation()?,
                    )
                    .await,
                )?;
                Ok(super::json_reply(
                    201,
                    format!(
                        "{{\"checkpointSeq\":0,\"presentationId\":{created},\"status\":\"PREPARING\"}}\n"
                    ),
                    self.c,
                    self.id.clone(),
                ))
            }
            Kind::Checkpoint | Kind::AnnRead => {
                let id = self.id_of(meeting, "meeting")?;
                let pid = self.id_of(pres.unwrap_or(""), "presentation")?;
                if kind == Kind::Checkpoint {
                    if let Err(wait) = self.throttle.admit(actor.user_id()) {
                        let mut reply = meet_problem(
                            429,
                            "checkpoint refresh throttled; retry after the Retry-After window",
                            "checkpoint-refresh-throttled",
                            "checkpointRefreshThrottled",
                            self.path,
                            self.c,
                            self.id.clone(),
                            self.language,
                        );
                        reply.headers_mut().insert(
                            "retry-after",
                            ((wait.as_secs_f64() + 0.999) as i64)
                                .to_string()
                                .parse()
                                .expect("numeric header"),
                        );
                        return Err(reply);
                    }
                }
                let out = if kind == Kind::Checkpoint {
                    setjoin_meet::presentation_checkpoint(exec, actor, id, pid).await
                } else {
                    setjoin_meet::presentation_annotation_read(exec, actor, id, pid).await
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
            _ => self.verb(kind, meeting, pres.unwrap_or(""), r).await,
        }
    }

    /// The verbs that commit one presentation fact and answer it with a frame.
    async fn verb(
        &self,
        kind: Kind,
        meeting: &str,
        pres: &str,
        r: &mut Request<Body>,
    ) -> Result<Response<Body>, Response<Body>> {
        let (exec, actor) = (self.exec, self.actor);
        // Drain verbs are never flag-gated: a toggle gates new intent only.
        if !matches!(kind, Kind::PresEnd | Kind::Revoke) {
            self.presentation_on().await?;
        }
        let id = self.id_of(meeting, "meeting")?;
        let pid = self.id_of(pres, "presentation")?;
        let fields = self.fields(r).await?;
        let invalid = |()| self.problem(400, "invalid JSON");
        let op = self.operation()?;
        let required = |detail: &str| self.problem(400, detail);
        let (outcome, frame_kind, payload): (_, &str, fn(&Fact) -> Option<String>) = match kind {
            Kind::Ready => {
                let digest =
                    optional_field::<String>(&fields, "MANIFESTDIGEST").map_err(invalid)?;
                (
                    setjoin_meet::presentation_ready(exec, actor, id, pid, digest.as_deref(), op)
                        .await,
                    "ready",
                    |_| None,
                )
            }
            Kind::PresStart => {
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                (
                    setjoin_meet::presentation_start(exec, actor, id, pid, gen, op).await,
                    "start",
                    |_| None,
                )
            }
            Kind::Page => {
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                let seq = optional_field::<i64>(&fields, "CHECKPOINTSEQ").map_err(invalid)?;
                let page = optional_field::<i64>(&fields, "PAGEINDEX").map_err(invalid)?;
                let (Some(gen), Some(seq), Some(page)) = (gen, seq, page) else {
                    return Err(required(
                        "presenterGeneration, checkpointSeq and pageIndex are required",
                    ));
                };
                (
                    setjoin_meet::presentation_page(exec, actor, id, pid, gen, seq, page, op).await,
                    "page.changed",
                    |f| Some(format!("{{\"pageIndex\":{}}}", f.page)),
                )
            }
            Kind::Presenter => {
                let target = number_field(&fields, "TARGETPARTICIPANTID").map_err(invalid)?;
                let takeover = bool_field(&fields, "TAKEOVER").map_err(invalid)?;
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                (
                    setjoin_meet::presentation_presenter(
                        exec, actor, id, pid, target, takeover, gen, op,
                    )
                    .await,
                    if takeover {
                        "presenter.takeover"
                    } else {
                        "presenter.granted"
                    },
                    |_| None,
                )
            }
            Kind::Source => {
                let node = number_field(&fields, "NODEID").map_err(invalid)?;
                let version = number_field(&fields, "VERSIONID").map_err(invalid)?;
                let digest = text_field(&fields, "MANIFESTDIGEST").map_err(invalid)?;
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                let seq = optional_field::<i64>(&fields, "CHECKPOINTSEQ").map_err(invalid)?;
                (
                    setjoin_meet::presentation_source(
                        exec, actor, id, pid, node, version, &digest, gen, seq, op,
                    )
                    .await,
                    "source.switched",
                    |f| {
                        Some(format!(
                            "{{\"manifestGeneration\":{},\"pageIndex\":{}}}",
                            f.manifest, f.page
                        ))
                    },
                )
            }
            Kind::Degrade => {
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                let reason = optional_field::<String>(&fields, "REASON").map_err(invalid)?;
                (
                    setjoin_meet::presentation_degrade(
                        exec,
                        actor,
                        id,
                        pid,
                        gen,
                        reason.as_deref(),
                        op,
                    )
                    .await,
                    "fallback.changed",
                    |_| None,
                )
            }
            Kind::Recover => {
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                (
                    setjoin_meet::presentation_recover(exec, actor, id, pid, gen, op).await,
                    "fallback.changed",
                    |_| None,
                )
            }
            Kind::PresEnd => {
                let gen = optional_field::<i64>(&fields, "PRESENTERGENERATION").map_err(invalid)?;
                (
                    setjoin_meet::presentation_end(exec, actor, id, pid, gen, op).await,
                    "end",
                    |_| None,
                )
            }
            Kind::Revoke => {
                let reason = optional_field::<String>(&fields, "REASON").map_err(invalid)?;
                (
                    setjoin_meet::presentation_revoke(exec, actor, id, pid, reason.as_deref(), op)
                        .await,
                    "end",
                    |_| None,
                )
            }
            Kind::AnnCommit => return self.annotation(id, pid, &fields, op).await,
            _ => unreachable!("not a presentation verb"),
        };
        let raw = self.commit(outcome)?;
        let fact: Fact =
            serde_json::from_str(&raw).map_err(|_| self.plain(500, "internal error"))?;
        Ok(self.fact_reply(&fact, frame_kind, payload(&fact), None))
    }

    fn fact_reply(
        &self,
        fact: &Fact,
        kind: &str,
        payload: Option<String>,
        annotation: Option<&Annotation>,
    ) -> Response<Body> {
        let mut parts = Vec::new();
        if let Some(a) = annotation {
            parts.push(format!("\"annotation\":{}", a.json()));
        }
        parts.push(format!("\"checkpointSeq\":{}", fact.seq));
        if let Some(frame) = frame(fact, kind, payload) {
            parts.push(format!("\"frame\":{frame}"));
        }
        parts.push(format!("\"manifestGeneration\":{}", fact.manifest));
        parts.push(format!("\"pageIndex\":{}", fact.page));
        parts.push(format!("\"presentationId\":{}", fact.id));
        parts.push(format!("\"presenterGeneration\":{}", fact.generation));
        parts.push(format!("\"status\":{}", js(&fact.status)));
        self.json(200, &format!("{{{}}}", parts.join(",")))
    }

    async fn annotation(
        &self,
        id: i64,
        pid: i64,
        fields: &crate::chat::Fields,
        op: [u8; 16],
    ) -> Result<Response<Body>, Response<Body>> {
        let invalid = |()| self.problem(400, "invalid JSON");
        let gen = optional_field::<i64>(fields, "PRESENTERGENERATION").map_err(invalid)?;
        let seq = optional_field::<i64>(fields, "CHECKPOINTSEQ").map_err(invalid)?;
        let clear = bool_field(fields, "CLEAR").map_err(invalid)?;
        let snapshot = optional_field::<String>(fields, "SNAPSHOT").map_err(invalid)?;
        let (Some(gen), Some(seq)) = (gen, seq) else {
            return Err(self.problem(400, "presenterGeneration and checkpointSeq are required"));
        };
        if clear == snapshot.is_some() {
            return Err(self.problem(400, "exactly one of clear or snapshot is required"));
        }
        if let Some(text) = &snapshot {
            if text.is_empty() || text.len() > MAX_SNAPSHOT {
                return Err(meet_problem(
                    403,
                    "annotation snapshot is not an admissible committed shape (empty, or over the stored-object bound)",
                    "annotation-not-admitted",
                    "annotation-not-admitted",
                    self.path,
                    self.c,
                    self.id.clone(),
                    self.language,
                ));
            }
        }
        let raw = self.commit(
            setjoin_meet::presentation_annotation(
                self.exec,
                self.actor,
                id,
                pid,
                gen,
                seq,
                snapshot.as_deref(),
                op,
            )
            .await,
        )?;
        let fact: Fact =
            serde_json::from_str(&raw).map_err(|_| self.plain(500, "internal error"))?;
        if snapshot.is_some() {
            let Some(annotation) = fact.annotation.clone() else {
                return Err(self.plain(500, "internal error"));
            };
            // Go marshals the payload map with sorted keys.
            let sorted = format!(
                "{{\"byteSize\":{},\"sha256\":{},\"snapshotRef\":{}}}",
                annotation.size,
                js(&annotation.sha256),
                js(&annotation.reference)
            );
            Ok(self.fact_reply(
                &fact,
                "annotation.committed",
                Some(sorted),
                Some(&annotation),
            ))
        } else {
            Ok(self.fact_reply(&fact, "annotation.cleared", None, None))
        }
    }
}
