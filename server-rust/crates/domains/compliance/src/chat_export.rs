//! The explicitly authorized, organization-wide frozen-Go export snapshot.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase, WorkerRows},
    Type,
};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Begin {
    pub search_id: i64,
    pub channels: Vec<Channel>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub channel_id: i64,
    pub export_act_id: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainHead {
    pub id: i64,
    pub checksum: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestChannel {
    pub channel_id: i64,
    pub message_count: usize,
    pub revision_count: i64,
    pub scheduled_count: usize,
    pub attachment_count: i64,
    pub chain_head: ChainHead,
    pub last_purged_seq: i64,
    pub purge_acts: Box<RawValue>,
    pub export_act_id: i64,
}
pub struct Snapshot {
    connection: WorkerConnection,
    pub case_name: String,
}
impl Snapshot {
    pub async fn open(database: &WorkerDatabase, case: i64) -> Result<Self, String> {
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
    pub async fn messages(&self, channel: i64) -> Result<WorkerRows, String> {
        self.connection.rows("SELECT chat_ediscovery_message_json(m.id)::text FROM chat_messages m WHERE m.channel_id=$1 ORDER BY m.id",&[(&channel,Type::INT8)]).await
    }
    pub async fn scheduled(&self, channel: i64) -> Result<WorkerRows, String> {
        self.connection.rows("SELECT sa.id::text,(sa.payload->>'userId')::bigint,sa.status,rtrim(rtrim(to_char(sa.fire_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',sa.payload->>'body' FROM scheduled_actions sa WHERE sa.action_kind='chat_send' AND sa.status IN ('pending','failed') AND (sa.payload->>'channelId')::bigint=$1 ORDER BY sa.id",&[(&channel,Type::INT8)]).await
    }
    pub async fn manifest_channel(
        &self,
        ch: &Channel,
        messages: usize,
        scheduled: usize,
    ) -> Result<ManifestChannel, String> {
        let r=self.connection.query("SELECT (SELECT count(*) FROM chat_message_revisions rv JOIN chat_messages m ON m.id=rv.message_id WHERE m.channel_id=$1),(SELECT count(*) FROM chat_message_attachments a JOIN chat_messages m ON m.id=a.message_id WHERE m.channel_id=$1),last_purged_seq FROM chat_channels WHERE id=$1",&[(&ch.channel_id,Type::INT8)]).await?;
        let r = r.first().ok_or("channel disappeared")?;
        let head=self.connection.query("SELECT a.id,a.after_state->>'_checksum' FROM chat_audit_log a WHERE a.channel_id=$1 ORDER BY a.id DESC LIMIT 1",&[(&ch.channel_id,Type::INT8)]).await?;
        let head = head.first().ok_or("missing export chain")?;
        let acts=self.connection.query("SELECT COALESCE(jsonb_agg(jsonb_build_object('actId',pa.id,'idFrom',(pa.after_state->>'idFrom')::bigint,'idTo',(pa.after_state->>'idTo')::bigint,'purgedCount',(pa.after_state->>'purgedCount')::int) ORDER BY pa.id),'[]'::jsonb)::text FROM chat_audit_log pa WHERE pa.channel_id=$1 AND pa.action='purge.execute'",&[(&ch.channel_id,Type::INT8)]).await?;
        Ok(ManifestChannel {
            channel_id: ch.channel_id,
            message_count: messages,
            revision_count: r.get(0),
            scheduled_count: scheduled,
            attachment_count: r.get(1),
            chain_head: ChainHead {
                id: head.get(0),
                checksum: head.get(1),
            },
            last_purged_seq: r.get(2),
            purge_acts: RawValue::from_string(acts[0].get(0)).map_err(|e| e.to_string())?,
            export_act_id: ch.export_act_id,
        })
    }
    pub async fn close(self) -> Result<(), String> {
        self.connection.batch("ROLLBACK").await
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Scheduled {
    r#type: &'static str,
    scheduled_action_id: String,
    channel_id: i64,
    author_id: Option<i64>,
    status: String,
    fire_at: String,
    body: Option<String>,
}
pub fn scheduled_line(row: &setjoin_pg::Row, channel: i64) -> Result<String, String> {
    let get = |i| row.try_get::<_, String>(i).map_err(|e| e.to_string());
    serde_json::to_string(&Scheduled {
        r#type: "scheduledSend",
        scheduled_action_id: get(0)?,
        channel_id: channel,
        author_id: row.try_get(1).map_err(|e| e.to_string())?,
        status: get(2)?,
        fire_at: get(3)?,
        body: row.try_get(4).map_err(|e| e.to_string())?,
    })
    .map_err(|e| e.to_string())
}

pub struct Federation {
    pub room: Option<Room>,
    pub dm: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Room {
    pub channel_id: i64,
    pub room_id: String,
    pub hub_domain: String,
    pub is_hub: bool,
    pub members: Option<Vec<Member>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub domain: String,
    pub joined_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub removed_reason: String,
    pub known_missing_intervals: Vec<Interval>,
}
#[derive(Serialize)]
pub struct Interval {
    pub from: String,
    pub to: Option<String>,
    pub reason: String,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Epoch {
    parked_at: Option<String>,
    resumed_at: Option<String>,
    reason: Option<String>,
}
impl Snapshot {
    pub async fn federation(
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
        let peer: Option<String> = binding.get(1);
        let Some(room) = binding.get::<_, Option<String>>(0) else {
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
        let hub: String = hub.first().ok_or("room disappeared")?.get(0);
        let rows=self.connection.query("SELECT member_domain,rtrim(rtrim(to_char(invited_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',rtrim(rtrim(to_char(left_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z',left_reason,coverage_epochs::text FROM federation_room_members WHERE room_id=$1 ORDER BY member_domain",&[(&room,Type::TEXT)]).await?;
        let mut members = Vec::new();
        for row in rows {
            let raw: String = row.get(4);
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
                domain: row.get(0),
                joined_at: row.get(1),
                removed_at: row.get(2),
                removed_reason: row.get::<_, Option<String>>(3).unwrap_or_default(),
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
}
impl Snapshot {
    pub async fn attachments(&self, channels: &[Channel]) -> Result<Vec<(String, i64)>, String> {
        let ids: Vec<i64> = channels.iter().map(|ch| ch.channel_id).collect();
        let rows=self.connection.query("SELECT DISTINCT ON(v.content_sha256) v.content_sha256,v.id FROM chat_message_attachments a JOIN chat_messages m ON m.id=a.message_id JOIN drive_file_versions v ON v.id=a.version_id WHERE m.channel_id=ANY($1) ORDER BY v.content_sha256,v.id",&[(&ids,Type::INT8_ARRAY)]).await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get(0).map_err(|e| e.to_string())?,
                    r.try_get(1).map_err(|e| e.to_string())?,
                ))
            })
            .collect()
    }
    pub async fn chunks(&self, version: i64) -> Result<Vec<String>, String> {
        let rows=self.connection.query("SELECT c.storage_ref FROM drive_version_chunks vc JOIN drive_chunks c ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256 WHERE vc.version_id=$1 AND vc.stream='content' ORDER BY vc.ordinal",&[(&version,Type::INT8)]).await?;
        rows.iter()
            .map(|r| r.try_get(0).map_err(|e| e.to_string()))
            .collect()
    }
}
