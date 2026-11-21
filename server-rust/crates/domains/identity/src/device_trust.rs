//! #341 device trust accept side (frozen authserver/internal/device/checkin.go):
//! effective-policy resolution, Go's content-hash policy version and the
//! check-in reducer. Callers hold a `VerifiedDevice`; HTTP framing is in auth.
use serde_json::{json, Value};
use setjoin_authz::device::VerifiedDevice;
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{CommandOutcome, ScopedExecutor, Type};
use std::collections::BTreeMap;

/// Owner-approved security bound (#341): Go accepted any count in 64 KiB.
pub const EVENT_CAP: usize = 100;

/// One reported event after Go's struct decode; absent or null fields are "".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub kind: String,
    pub data: String,
}

/// `mdm_effective_policy`'s merged device > department > global layers and
/// the device row's wipe flag; never raw policy rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    pub policies: BTreeMap<String, String>,
    pub wipe_requested: bool,
}

/// A check-in that did not commit (`Failed`) or whose COMMIT was unacknowledged.
#[derive(Debug)]
pub enum CheckinError {
    Failed,
    Unknown(OperationId),
}

impl Effective {
    fn decode(text: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(text).ok()?;
        let mut policies = BTreeMap::new();
        match value.get("policies") {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (key, v) in map {
                    policies.insert(key.clone(), v.as_str()?.to_owned());
                }
            }
            Some(_) => return None,
        }
        let wipe_requested = match value.get("wipe_requested") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        Some(Self {
            policies,
            wipe_requested,
        })
    }

    /// Frozen `policyVersion`: FNV-1a 64 over sorted keys, each key and value
    /// prefixed by its 8-byte big-endian length, then the wipe byte; Go's int64 cast.
    pub fn version(&self) -> i64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        for (key, value) in &self.policies {
            for field in [key, value] {
                feed(&(field.len() as u64).to_be_bytes());
                feed(field.as_bytes());
            }
        }
        feed(&[u8::from(self.wipe_requested)]);
        hash as i64
    }
}

/// GET /device/policy: the trusted evaluator on the request credential.
pub async fn effective_policy(exec: &ScopedExecutor, device: &VerifiedDevice) -> Option<Effective> {
    let id = device.id();
    let rows = exec
        .read(
            "SELECT mdm_effective_policy($1)::text",
            &[(&id, Type::INT8)],
        )
        .await
        .ok()?;
    Effective::decode(&rows.first()?.get::<_, Option<String>>(0)?)
}

/// POST /device/checkin effects in one acknowledged transaction: the reducer
/// and its receipt commit together, COMMIT is sent only after both succeed
/// inside the statement deadline, so a client timeout can never commit late.
pub async fn checkin(
    exec: &ScopedExecutor,
    device: &VerifiedDevice,
    events: &[Event],
) -> Result<Effective, CheckinError> {
    let id = device.id();
    let events = Value::Array(
        events
            .iter()
            .map(|e| json!({"type": e.kind, "data": e.data}))
            .collect(),
    )
    .to_string();
    let outcome = exec
        .run_protocol_command(
            &format!("device:{id}"),
            OperationId(*uuid::Uuid::new_v4().as_bytes()),
            setjoin_pg::ReceiptCommand {
                family: "F21",
                command: "device-checkin",
            },
            "SELECT rust_device_checkin($1,$2::text::jsonb)::text",
            &[(&id, Type::INT8), (&events, Type::TEXT)],
            |rows| Ok(rows.first().and_then(|r| r.get::<_, Option<String>>(0))),
        )
        .await;
    match outcome {
        CommandOutcome::Committed(Some(text)) => {
            Effective::decode(&text).ok_or(CheckinError::Failed)
        }
        CommandOutcome::Unknown { operation } => Err(CheckinError::Unknown(operation)),
        _ => Err(CheckinError::Failed),
    }
}

/// `time.Now().UTC()` as encoding/json writes it (RFC3339Nano, zeros trimmed).
pub fn go_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.subsec_nanos();
    let at = chrono::DateTime::from_timestamp(now.as_secs() as i64, nanos).unwrap_or_default();
    let mut text = at.format("%Y-%m-%dT%H:%M:%S").to_string();
    if nanos != 0 {
        text.push('.');
        text.push_str(format!("{nanos:09}").trim_end_matches('0'));
    }
    text.push('Z');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    fn effective(pairs: &[(&str, &str)], wipe: bool) -> Effective {
        Effective {
            policies: pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            wipe_requested: wipe,
        }
    }
    #[test]
    fn policy_version_is_go_fnv_content_hash() {
        assert_eq!(effective(&[], false).version(), -5808590958014384161);
        assert_eq!(effective(&[], true).version(), -5808592057526012372);
        let base = effective(
            &[("lock_timeout", "300"), ("wipe_on_jailbreak", "true")],
            false,
        );
        assert_eq!(base.version(), -6696073713852873232);
        assert_ne!(
            effective(
                &[("lock_timeout", "300"), ("wipe_on_jailbreak", "fals")],
                false
            )
            .version(),
            base.version()
        );
        assert_ne!(
            effective(&[("lock_timeout", "300")], false).version(),
            base.version()
        );
        assert_ne!(
            effective(&[("ab", "c")], false).version(),
            effective(&[("a", "bc")], false).version()
        );
        assert_ne!(
            effective(
                &[("lock_timeout", "300"), ("wipe_on_jailbreak", "true")],
                true
            )
            .version(),
            base.version()
        );
    }
    #[test]
    fn evaluator_payload_decodes_like_go() {
        assert_eq!(
            Effective::decode(r#"{"policies":{"b":"2","a":"1"},"wipe_requested":true}"#),
            Some(effective(&[("a", "1"), ("b", "2")], true))
        );
        assert_eq!(
            Effective::decode(r#"{"policies":null}"#),
            Some(effective(&[], false))
        );
        assert_eq!(Effective::decode(r#"{"policies":{"a":1}}"#), None);
    }
    #[test]
    fn updated_at_is_go_rfc3339nano_utc() {
        let t = go_now();
        let body = t.strip_suffix('Z').expect("UTC");
        if let Some((_, frac)) = body.split_once('.') {
            assert!(
                !frac.is_empty() && !frac.ends_with('0') && frac.len() <= 9,
                "{t}"
            );
        }
    }
}
