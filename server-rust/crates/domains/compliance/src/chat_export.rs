//! Pure data structures and JSONL projection for organization-wide chat eDiscovery export.
//! Worker snapshot execution lives in `bins/gateway/src/chat_compliance_export.rs`.
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
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
pub struct Epoch {
    pub parked_at: Option<String>,
    pub resumed_at: Option<String>,
    pub reason: Option<String>,
}
