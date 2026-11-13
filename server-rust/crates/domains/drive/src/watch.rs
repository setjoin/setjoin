//! drive-watch system worker: fans each committed `drive` NOTIFY out to the
//! watchers' own `drive-watch:<uid>` channels. Only the explicit worker DSN
//! (cross-tenant ancestor resolution) is used; the dedupe cache is
//! process-local exactly like Go's.
use serde_json::Value;
use std::{
    collections::HashMap,
    future::Future,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio_postgres::{types::Type, NoTls};
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Go's per-(user,node,op) live-push dedupe window.
const WINDOW: Duration = Duration::from_secs(60);

pub struct DriveWatch {
    dsn: String,
    recent: Mutex<HashMap<(i64, i64, String), Instant>>,
}

/// Case-insensitive field lookup with Go's decode typing: `None` outer means a
/// type error (Go drops the event), `Some(None)` is absent/null.
fn field<T>(
    map: &serde_json::Map<String, Value>,
    name: &str,
    pick: impl Fn(&Value) -> Option<T>,
) -> Option<Option<T>> {
    let mut out = None;
    for (key, value) in map {
        if key.eq_ignore_ascii_case(name) {
            out = if value.is_null() {
                None
            } else {
                Some(pick(value)?)
            };
        }
    }
    Some(out)
}

impl DriveWatch {
    pub fn new(worker_dsn: String) -> Self {
        Self {
            dsn: worker_dsn,
            recent: Mutex::new(HashMap::new()),
        }
    }

    fn should_send(&self, user: i64, node: i64, op: &str) -> bool {
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap();
        let key = (user, node, op.to_owned());
        if recent
            .get(&key)
            .is_some_and(|t| now.duration_since(*t) < WINDOW)
        {
            return false;
        }
        recent.insert(key, now);
        true
    }

    /// One `drive` payload, best effort like Go: errors are dropped.
    pub async fn tick(&self, payload: &str) -> Result<(), Error> {
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(payload) else {
            return Ok(());
        };
        let int = |v: &Value| v.as_i64().filter(|_| v.is_i64() || v.is_u64());
        let text = |v: &Value| v.as_str().map(str::to_owned);
        let (Some(space), Some(seq), Some(kind), Some(node)) = (
            field(&map, "spaceId", int),
            field(&map, "seq", int),
            field(&map, "kind", text),
            field(&map, "nodeId", int),
        ) else {
            return Ok(());
        };
        let space = space.unwrap_or(0);
        let (client, connection) = tokio_postgres::connect(&self.dsn, NoTls).await?;
        let driver = tokio::spawn(connection);
        let result = async {
            let (node, op) = if let Some(seq) = seq {
                let rows = client
                    .query_typed(
                        "SELECT node_id, op FROM drive_changes WHERE space_id = $1 AND seq = $2",
                        &[(&space, Type::INT8), (&seq, Type::INT8)],
                    )
                    .await?;
                let Some(row) = rows.first() else {
                    return Ok::<_, Error>(());
                };
                (row.get::<_, i64>(0), row.get::<_, String>(1))
            } else if kind.as_deref() == Some("lock") && node.is_some() {
                (node.unwrap(), "lock".to_owned())
            } else {
                return Ok(());
            };
            let users = client
                .query_typed(
                    "SELECT DISTINCT wa.user_id FROM drive_nodes n \
                     JOIN drive_node_closure c ON c.space_id = n.space_id AND c.descendant_id = n.id \
                     JOIN drive_watches wa ON wa.node_id = c.ancestor_id \
                     WHERE n.id = $1 AND (wa.ops IS NULL OR $2 = ANY(wa.ops)) \
                     AND public.drive_runtime_has_node_capability(wa.user_id, n.id, 'read_metadata')",
                    &[(&node, Type::INT8), (&op, Type::TEXT)],
                )
                .await?;
            let out = format!("{{\"nodeId\":{node},\"op\":{},\"spaceId\":{space}}}", serde_json::to_string(&op)?);
            for row in users {
                let user: i64 = row.get(0);
                if !self.should_send(user, node, &op) {
                    continue;
                }
                let channel = format!("drive-watch:{user}");
                let _ = client
                    .query_typed(
                        "SELECT pg_notify($1, $2)",
                        &[(&channel, Type::TEXT), (&out, Type::TEXT)],
                    )
                    .await;
            }
            Ok(())
        }
        .await;
        drop(client);
        let _ = driver.await;
        result
    }

    /// Direct LISTEN on `drive`; cancellation closes the owned connection.
    pub async fn run_until(self, direct: String, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        loop {
            let listener = tokio::select! {_=&mut stop=>return,result=setjoin_pg::workers::DirectListener::connect(&direct,"drive")=>result};
            match listener {
                Ok(mut listener) => loop {
                    let event = tokio::select! {_=&mut stop=>{let _=listener.close().await;return},event=listener.recv()=>event};
                    let Some(event) = event else {
                        let _ = listener.close().await;
                        break;
                    };
                    tokio::select! {_=&mut stop=>{let _=listener.close().await;return},result=self.tick(event.payload())=>{if result.is_err(){eprintln!("drive watch: event failed");}}}
                },
                Err(_) => eprintln!("drive watch: listener disconnected"),
            }
            tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
        }
    }
}
