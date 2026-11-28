//! Bounded ZIP producer. The audit command commits before this read snapshot.
use crate::{Body, RequestContext};
use async_zip::{base::write::ZipFileWriter, Compression, ZipEntryBuilder};
use futures_lite::io::AsyncWriteExt;
use serde::Serialize;
use serde_json::value::RawValue;
use setjoin_compliance::chat_export::{
    Begin, ChainHead, Channel, Epoch, Federation, Interval, ManifestChannel, Member, Room,
};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase, WorkerRows},
    Type,
};
use sha2::{Digest, Sha256};

/// Explicitly authorized, organization-wide worker snapshot for chat eDiscovery export.
struct Snapshot {
    connection: WorkerConnection,
    case_name: String,
}

impl Snapshot {
    async fn open(database: &WorkerDatabase, case: i64) -> Result<Self, String> {
        let connection = database.connect().await.map_err(|e| e.to_string())?;
        connection
            .batch("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await?;
        let rows = connection
            .query(
                "SELECT name FROM ediscovery_cases WHERE id=$1",
                &[(&case, Type::INT8)],
            )
            .await?;
        let name = rows
            .first()
            .ok_or("case disappeared")?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            connection,
            case_name: name,
        })
    }

    async fn messages(&self, channel: i64) -> Result<WorkerRows, String> {
        self.connection
            .rows(
                "SELECT chat_ediscovery_message_json(m.id)::text FROM chat_messages m WHERE m.channel_id=$1 ORDER BY m.id",
                &[(&channel, Type::INT8)],
            )
            .await
    }

    async fn scheduled(&self, channel: i64) -> Result<WorkerRows, String> {
        self.connection
            .rows(
                "SELECT sa.id::text,(sa.payload->>'userId')::bigint,sa.status,rtrim(rtrim(to_char(sa.fire_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',sa.payload->>'body' FROM scheduled_actions sa WHERE sa.action_kind='chat_send' AND sa.status IN ('pending','enqueued','failed') AND (sa.payload->>'channelId')::bigint=$1 ORDER BY sa.id",
                &[(&channel, Type::INT8)],
            )
            .await
    }

    async fn manifest_channel(
        &self,
        ch: &Channel,
        messages: usize,
        scheduled: usize,
    ) -> Result<ManifestChannel, String> {
        let r = self
            .connection
            .query(
                "SELECT (SELECT count(*) FROM chat_message_revisions rv JOIN chat_messages m ON m.id=rv.message_id WHERE m.channel_id=$1),(SELECT count(*) FROM chat_message_attachments a JOIN chat_messages m ON m.id=a.message_id WHERE m.channel_id=$1),last_purged_seq FROM chat_channels WHERE id=$1",
                &[(&ch.channel_id, Type::INT8)],
            )
            .await?;
        let r = r.first().ok_or("channel disappeared")?;
        let head = self
            .connection
            .query(
                "SELECT a.id,a.after_state->>'_checksum' FROM chat_audit_log a WHERE a.channel_id=$1 ORDER BY a.id DESC LIMIT 1",
                &[(&ch.channel_id, Type::INT8)],
            )
            .await?;
        let head = head.first().ok_or("missing export chain")?;
        let acts = self
            .connection
            .query(
                "SELECT COALESCE(jsonb_agg(jsonb_build_object('actId',pa.id,'idFrom',(pa.after_state->>'idFrom')::bigint,'idTo',(pa.after_state->>'idTo')::bigint,'purgedCount',(pa.after_state->>'purgedCount')::int) ORDER BY pa.id),'[]'::jsonb)::text FROM chat_audit_log pa WHERE pa.channel_id=$1 AND pa.action='purge.execute'",
                &[(&ch.channel_id, Type::INT8)],
            )
            .await?;
        let acts_raw: String = acts
            .first()
            .ok_or("missing purge acts")?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        Ok(ManifestChannel {
            channel_id: ch.channel_id,
            message_count: messages,
            revision_count: r.try_get(0).map_err(|e| e.to_string())?,
            scheduled_count: scheduled,
            attachment_count: r.try_get(1).map_err(|e| e.to_string())?,
            chain_head: ChainHead {
                id: head.try_get(0).map_err(|e| e.to_string())?,
                checksum: head.try_get(1).map_err(|e| e.to_string())?,
            },
            last_purged_seq: r.try_get(2).map_err(|e| e.to_string())?,
            purge_acts: RawValue::from_string(acts_raw).map_err(|e| e.to_string())?,
            export_act_id: ch.export_act_id,
        })
    }

    async fn federation(
        &self,
        channel: i64,
        parse: fn(&str) -> Result<String, String>,
    ) -> Result<Federation, String> {
        let binding = self
            .connection
            .query(
                "SELECT federated_room_id,federated_peer_domain FROM chat_channels WHERE id=$1",
                &[(&channel, Type::INT8)],
            )
            .await?;
        let binding = binding.first().ok_or("channel disappeared")?;
        let peer: Option<String> = binding.try_get(1).map_err(|e| e.to_string())?;
        let Some(room) = binding
            .try_get::<_, Option<String>>(0)
            .map_err(|e| e.to_string())?
        else {
            return Ok(Federation {
                room: None,
                dm: peer.is_some(),
            });
        };
        let hub = self
            .connection
            .query(
                "SELECT hub_domain FROM federation_rooms WHERE room_id=$1",
                &[(&room, Type::TEXT)],
            )
            .await?;
        let hub: String = hub
            .first()
            .ok_or("room disappeared")?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        let rows = self
            .connection
            .query(
                "SELECT member_domain,rtrim(rtrim(to_char(invited_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',rtrim(rtrim(to_char(left_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',left_reason,coverage_epochs::text FROM federation_room_members WHERE room_id=$1 ORDER BY member_domain",
                &[(&room, Type::TEXT)],
            )
            .await?;
        let mut members = Vec::new();
        for row in rows {
            let raw: String = row.try_get(4).map_err(|e| e.to_string())?;
            let epochs = serde_json::from_str::<Option<Vec<Option<Epoch>>>>(&raw)
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            let mut gaps = Vec::new();
            for epoch in epochs {
                let epoch = epoch.unwrap_or_default();
                gaps.push(Interval {
                    from: epoch
                        .parked_at
                        .as_deref()
                        .map(parse)
                        .transpose()?
                        .unwrap_or_else(|| "0001-01-01T00:00:00Z".into()),
                    to: epoch.resumed_at.as_deref().map(parse).transpose()?,
                    reason: epoch.reason.unwrap_or_default(),
                });
            }
            members.push(Member {
                domain: row.try_get(0).map_err(|e| e.to_string())?,
                joined_at: row.try_get(1).map_err(|e| e.to_string())?,
                removed_at: row.try_get(2).map_err(|e| e.to_string())?,
                removed_reason: row
                    .try_get::<_, Option<String>>(3)
                    .map_err(|e| e.to_string())?
                    .unwrap_or_default(),
                known_missing_intervals: gaps,
            });
        }
        Ok(Federation {
            room: Some(Room {
                channel_id: channel,
                room_id: room,
                hub_domain: hub,
                is_hub: peer.is_none(),
                members: (!members.is_empty()).then_some(members),
            }),
            dm: false,
        })
    }

    async fn attachments(&self, channels: &[Channel]) -> Result<Vec<(String, i64)>, String> {
        let ids: Vec<i64> = channels.iter().map(|ch| ch.channel_id).collect();
        let rows = self
            .connection
            .query(
                "SELECT DISTINCT ON(v.content_sha256) v.content_sha256,v.id FROM chat_message_attachments a JOIN chat_messages m ON m.id=a.message_id JOIN drive_file_versions v ON v.id=a.version_id WHERE m.channel_id=ANY($1) ORDER BY v.content_sha256,v.id",
                &[(&ids, Type::INT8_ARRAY)],
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get(0).map_err(|e| e.to_string())?,
                    r.try_get(1).map_err(|e| e.to_string())?,
                ))
            })
            .collect()
    }

    async fn chunks(&self, version: i64) -> Result<Vec<String>, String> {
        let rows = self
            .connection
            .query(
                "SELECT c.storage_ref FROM drive_version_chunks vc JOIN drive_chunks c ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256 WHERE vc.version_id=$1 AND vc.stream='content' ORDER BY vc.ordinal",
                &[(&version, Type::INT8)],
            )
            .await?;
        rows.iter()
            .map(|r| r.try_get(0).map_err(|e| e.to_string()))
            .collect()
    }

    async fn close(self) -> Result<(), String> {
        self.connection.batch("ROLLBACK").await
    }
}
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
