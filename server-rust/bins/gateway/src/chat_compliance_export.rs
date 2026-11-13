//! Bounded ZIP producer. The audit command commits before this read snapshot.
use crate::{Body, RequestContext};
use async_zip::{base::write::ZipFileWriter, Compression, ZipEntryBuilder};
use futures_lite::io::AsyncWriteExt;
use serde::Serialize;
use setjoin_compliance::chat_export::{Begin, Snapshot};
use setjoin_pg::workers::WorkerDatabase;
use sha2::{Digest, Sha256};
const DISCLAIMERS:[&str;3]=[
"Chain heads pin the per-channel audit-chain state at export time; verify with the chain verifier and retain off-box.",
"This record begins above the recorded purge floors. lastPurgedSeq is provenance only, never a replayable cursor (seq is re-stamped on edit).",
"The audit chain proves what the destroyedElems leaves say and nothing more: it does not prove that a specific held message was not destroyed, and no claim is made about records that never existed."];
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest<'a> {
    case_id: i64,
    case_name: &'a str,
    query: &'a serde_json::Value,
    exported_by: i64,
    executed_at: String,
    search_id: i64,
    channels: Vec<setjoin_compliance::chat_export::ManifestChannel>,
    messages_sha256: String,
    disclaimers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    federated_rooms: Vec<setjoin_compliance::chat_export::Room>,
}
pub(crate) async fn response(
    database: WorkerDatabase,
    store: Option<std::sync::Arc<crate::recovery_worker::S3Store>>,
    head: bool,
    case: i64,
    actor: i64,
    query: serde_json::Value,
    begin: Begin,
    c: &RequestContext,
    id: String,
) -> hyper::Response<Body> {
    let snapshot = match Snapshot::open(&database, case).await {
        Ok(v) => v,
        Err(_) => {
            return crate::chat::problem(
                500,
                "database error",
                "/admin/chat-ediscovery/export",
                c,
                id,
            )
        }
    };
    let disposition = format!(
        "attachment; filename=chat-ediscovery-case{case}-{}.zip",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    crate::compliance_export::stream(
        head,
        "application/zip",
        disposition,
        c,
        id,
        move |mut out| async move {
            let (write, mut read) = tokio::io::duplex(65536);
            let producer = async move {
                let _ = archive(write, snapshot, store, case, actor, query, begin).await;
                Ok::<_, String>(())
            };
            let consumer = async move {
                use tokio::io::AsyncReadExt;
                let mut buffer = [0; 16384];
                loop {
                    let n = read.read(&mut buffer).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    out.write(bytes::Bytes::copy_from_slice(&buffer[..n]))
                        .await?;
                }
                out.finish();
                Ok::<_, String>(())
            };
            let _ = tokio::try_join!(producer, consumer);
        },
    )
    .await
}
async fn archive(
    write: tokio::io::DuplexStream,
    snapshot: Snapshot,
    store: Option<std::sync::Arc<crate::recovery_worker::S3Store>>,
    case: i64,
    actor: i64,
    query: serde_json::Value,
    begin: Begin,
) -> Result<(), String> {
    let mut zip = ZipFileWriter::with_tokio(tokio::io::BufWriter::with_capacity(4096, write));
    let mut messages = zip
        .write_entry_stream(ZipEntryBuilder::new(
            "messages.jsonl".into(),
            Compression::Deflate,
        ))
        .await
        .map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut channels = Vec::new();
    let mut rooms = Vec::new();
    let (mut hub, mut dm) = (false, false);
    let mut spoke_hubs = std::collections::BTreeSet::new();
    for channel in &begin.channels {
        let mut rows = snapshot.messages(channel.channel_id).await?;
        let mut count = 0;
        while let Some(row) = rows.next().await? {
            let raw: String = row.try_get(0).map_err(|e| e.to_string())?;
            messages
                .write_all(raw.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            messages.write_all(b"\n").await.map_err(|e| e.to_string())?;
            hash.update(raw.as_bytes());
            hash.update(b"\n");
            count += 1;
        }
        drop(rows);
        let mut scheduled = snapshot.scheduled(channel.channel_id).await?;
        let mut scheduled_count = 0;
        while let Some(row) = scheduled.next().await? {
            let raw = setjoin_compliance::chat_export::scheduled_line(&row, channel.channel_id)?;
            let raw = crate::jmap::reply::go_compact(&raw).ok_or("invalid scheduled line")? + "\n";
            messages
                .write_all(raw.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            hash.update(raw.as_bytes());
            scheduled_count += 1;
        }
        drop(scheduled);
        channels.push(
            snapshot
                .manifest_channel(channel, count, scheduled_count)
                .await?,
        );
        let federation = snapshot
            .federation(channel.channel_id, coverage_time)
            .await?;
        dm |= federation.dm;
        if let Some(room) = federation.room {
            if room.is_hub {
                hub = true;
            } else {
                spoke_hubs.insert(room.hub_domain.clone());
            }
            rooms.push(room);
        }
    }
    messages.close().await.map_err(|e| e.to_string())?;
    if query["includeAttachments"] == true {
        for (sha, version) in snapshot.attachments(&begin.channels).await? {
            let chunks = snapshot.chunks(version).await?;
            let mut entry = zip
                .write_entry_stream(ZipEntryBuilder::new(
                    format!("attachments/{sha}").into(),
                    Compression::Deflate,
                ))
                .await
                .map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            for key in chunks {
                let mut object = store
                    .as_ref()
                    .ok_or("object storage absent")?
                    .compliance_object(&key)
                    .await?;
                while let Some(chunk) = object.chunk().await.map_err(|e| e.to_string())? {
                    entry.write_all(&chunk).await.map_err(|e| e.to_string())?;
                    hash.update(&chunk);
                }
            }
            if format!("{:x}", hash.finalize()) != sha {
                return Err("attachment hash mismatch".into());
            }
            entry.close().await.map_err(|e| e.to_string())?;
        }
    }
    let mut disclaimers: Vec<String> = DISCLAIMERS.iter().map(|s| s.to_string()).collect();
    if !spoke_hubs.is_empty() {
        disclaimers
            .push(SPOKE.replace("%s", &spoke_hubs.into_iter().collect::<Vec<_>>().join(", ")));
    }
    if hub {
        disclaimers.push(HUB.into());
    }
    if hub || dm || !rooms.is_empty() {
        disclaimers.push(OUTBOX.into());
        disclaimers.push(TYPING.into());
    }
    let manifest = Manifest {
        case_id: case,
        case_name: &snapshot.case_name,
        query: &query,
        exported_by: actor,
        executed_at: coverage_time(
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        )?,
        search_id: begin.search_id,
        channels,
        messages_sha256: format!("{:x}", hash.finalize()),
        disclaimers,
        federated_rooms: rooms,
    };
    let bytes = serde_json::to_string(&manifest).map_err(|e| e.to_string())?;
    let bytes = crate::jmap::reply::go_compact(&bytes).ok_or("invalid manifest")? + "\n";
    let mut entry = zip
        .write_entry_stream(ZipEntryBuilder::new(
            "manifest.json".into(),
            Compression::Deflate,
        ))
        .await
        .map_err(|e| e.to_string())?;
    entry
        .write_all(bytes.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    entry.close().await.map_err(|e| e.to_string())?;
    let mut writer = zip.close().await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    snapshot.close().await
}

fn coverage_time(raw: &str) -> Result<String, String> {
    let time = crate::go_time::parse_rfc3339(raw)?;
    let mut text = time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    if let Some(dot) = text.find('.') {
        let end = dot + 10;
        let fraction = text[dot + 1..end].trim_end_matches('0').to_owned();
        text.replace_range(
            dot..end,
            &if fraction.is_empty() {
                String::new()
            } else {
                format!(".{fraction}")
            },
        );
    }
    Ok(text)
}

const SPOKE:&str="One or more exported channels are spoke mirrors of federated multi-org rooms. This archive is THIS organization's copy of every message it accepted while actively receiving, from its join date forward; delivery gaps (if any) are listed per member organization in this manifest. Other member organizations hold independent copies governed by their own retention. The hub organization (%s) holds the hub's record of messages it accepted and relayed.";

const HUB:&str="One or more exported channels are federated multi-org rooms for which THIS organization is the hub. This archive is the hub's record of messages it accepted and relayed (messages refused at ingest never entered it); member organizations hold independent copies of what each accepted while actively receiving, governed by their own retention — per-member coverage boundaries are listed in this manifest.";

const OUTBOX:&str="Federation transport queues are delivery residue, not an archive: they may retain redacted delivery envelopes, and undelivered message bodies queued to unreachable member organizations, after local purge; see the retention policy.";

const TYPING: &str =
    "Ephemeral typing signals are not archived and are excluded from eDiscovery by design.";
