//! Group `alerts`: Go's `AlertsHandler` (`/admin/alerts*`). Reads need `audit.read`
//! (`requireLogsPerm`, refused to a domain-scoped principal), writes `security.write`.
//! Every refusal is `httputil.WriteError`, a minimal problem.
use super::{Action, Env};
use crate::{Body, Response};
use hyper::Request;
use serde_json::Value;
use setjoin_pg::CommandOutcome;
use setjoin_platform::alerts;

/// `{"checkName": ..}` decoded like Go: case-folded keys, a wrongly typed value fails,
/// `null` keeps what is there, the last string wins.
struct CheckName(String);
impl<'de> serde::Deserialize<'de> for CheckName {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CheckName;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<CheckName, E> {
                Ok(CheckName(String::new()))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<CheckName, M::Error> {
                let mut name = String::new();
                while let Some(key) = map.next_key::<String>()? {
                    if crate::guests_input::fold(&key) == "checkname" {
                        if let Some(v) = map.next_value::<Option<String>>()? {
                            name = v;
                        }
                    } else {
                        let _: serde::de::IgnoredAny = map.next_value()?;
                    }
                }
                Ok(CheckName(name))
            }
        }
        decoder.deserialize_any(V)
    }
}

async fn check_name(r: &mut Request<Body>) -> Result<String, ()> {
    super::json_body::<CheckName>(r, 1 << 30).await.map(|c| c.0)
}

pub(super) async fn run(what: Action, mut r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    match what {
        Action::AlertList => match alerts::list(e.exec).await {
            Ok(body) => e.reply(body, 200),
            Err(_) => e.bare(500, "database error"),
        },
        Action::AlertConfigGet => match alerts::config(e.exec).await {
            Ok(body) => e.reply(body, 200),
            Err(_) => e.bare(500, "database error"),
        },
        Action::AlertAck | Action::AlertUnsuppress => {
            let Ok(name) = check_name(&mut r).await else {
                return e.bare(400, "invalid JSON");
            };
            if name.is_empty() {
                return e.bare(400, "checkName required");
            }
            let outcome = if what == Action::AlertAck {
                alerts::acknowledge(e.exec, e.actor, &name, e.operation).await
            } else {
                alerts::unsuppress(e.exec, e.actor, &name, e.operation).await
            };
            match outcome {
                CommandOutcome::Committed(()) => e.no_content(),
                CommandOutcome::RolledBack(_) => e.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
        _ => {
            let Ok(value) = super::json_body::<Value>(&mut r, 1 << 30).await else {
                return e.bare(400, "invalid JSON");
            };
            let map = match value {
                Value::Object(map) => map,
                Value::Null => serde_json::Map::new(),
                _ => return e.bare(400, "invalid JSON"),
            };
            if let Some(key) = map
                .keys()
                .find(|k| !k.starts_with("hc_") && !k.starts_with("alert_"))
            {
                return e.bare(
                    400,
                    &format!("config key not writable via alerts API: {key}"),
                );
            }
            match alerts::set_config(e.exec, e.actor, &map, e.operation).await {
                CommandOutcome::Committed(()) => e.no_content(),
                CommandOutcome::RolledBack(_) => e.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
    }
}
