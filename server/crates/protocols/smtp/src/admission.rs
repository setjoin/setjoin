//! Frozen Go's per-IP database budget. These are system counters keyed only
//! from the socket peer, on the explicit worker credential.
use crate::Server;
use setjoin_pg::Type;
pub async fn allow(server: &Server, ip: &str) -> bool {
    let Some(db) = &server.db else { return true };
    let Ok(conn) = db.connect().await else {
        return true;
    };
    let key = format!("smtp:conn:{ip}");
    let allowed=conn.query("SELECT count < $1 FROM rate_limit_counters WHERE key=$2 AND window_start>now()-INTERVAL '1 minute' UNION ALL SELECT TRUE LIMIT 1",&[(&20i32,Type::INT4),(&key,Type::TEXT)]).await
  .ok().and_then(|rows|rows.first().map(|r|r.get::<_,bool>(0))).unwrap_or(true);
    if !allowed {
        return false;
    }
    // Intentionally retain Go's expired-window count, and its separate check/write.
    let _=conn.execute("INSERT INTO rate_limit_counters(key,count,window_start) VALUES ($1,1,now()) ON CONFLICT(key) DO UPDATE SET count=rate_limit_counters.count+1,window_start=CASE WHEN rate_limit_counters.window_start<now()-INTERVAL '1 minute' THEN now() ELSE rate_limit_counters.window_start END",&[(&key,Type::TEXT)]).await;
    true
}

pub fn session_id(ip: &str) -> String {
    use sha2::{Digest, Sha256};
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let hash = Sha256::digest(format!("{ip}:{:?}:{n}", std::time::SystemTime::now()));
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}
pub async fn open(server: &Server, id: &str, ip: &str) {
    if let Some(db) = &server.db {
        if let Ok(db) = db.connect().await {
            let _=db.execute("INSERT INTO smtp_sessions(id,remote_ip,state,bytes_received) VALUES ($1,$2::inet,'greeting',0)",&[(&id,Type::TEXT),(&ip,Type::TEXT)]).await;
        }
    }
}
pub async fn close(server: &Server, id: &str) {
    if let Some(db) = &server.db {
        if let Ok(db) = db.connect().await {
            let _ = db
                .execute(
                    "DELETE FROM smtp_sessions WHERE id=$1",
                    &[(&id, Type::TEXT)],
                )
                .await;
        }
    }
}
