//! Generic bounded streaming content-addressed blob storage for encrypted
//! offline stores. There is no mail, receipt, JMAP, or recovery policy here.
use crate::{OfflineCore, OfflineError};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const MAX_BLOB_CHUNK: usize = 256 * 1024;
pub const MAX_BLOB_SIZE: u64 = 8 * 1024 * 1024 * 1024;

const BLOB_DDL: &str = "
CREATE TABLE IF NOT EXISTS oc_blob_write_handles (
  handle TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  next_offset INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oc_blob_write_chunks (
  handle TEXT NOT NULL, offset INTEGER NOT NULL, bytes BLOB NOT NULL,
  PRIMARY KEY(handle,offset));
CREATE TABLE IF NOT EXISTS oc_recovery_blobs (
  sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, ref_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, last_read INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oc_recovery_blob_chunks (
  sha256 TEXT NOT NULL, offset INTEGER NOT NULL, bytes BLOB NOT NULL,
  PRIMARY KEY(sha256,offset));
CREATE TABLE IF NOT EXISTS oc_blob_read_handles (
  handle TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  created_at INTEGER NOT NULL);";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl OfflineCore {
    fn with_blob_conn<T>(
        &self,
        app_key: &str,
        f: impl FnOnce(&Connection) -> Result<T, OfflineError>,
    ) -> Result<T, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        conn.execute_batch(BLOB_DDL)?;
        f(conn)
    }
}

#[uniffi::export]
impl OfflineCore {
    /// Begin or resume a write for one declared digest/size. Returns a stable
    /// handle and acknowledged offset; only bounded chunks cross the bridge.
    pub fn blob_write_begin(
        &self,
        app_key: String,
        sha256: String,
        size: u64,
    ) -> Result<String, OfflineError> {
        if !valid_sha(&sha256) || size == 0 || size > MAX_BLOB_SIZE {
            return Err(OfflineError::Integrity(
                "invalid declared blob hash/size".into(),
            ));
        }
        self.with_blob_conn(&app_key, |conn| {
            if let Some((handle, next_offset)) = conn.query_row(
                "SELECT handle,next_offset FROM oc_blob_write_handles WHERE sha256=?1 AND size=?2 ORDER BY created_at DESC LIMIT 1",
                params![sha256, size as i64], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            ).optional()? {
                return Ok(serde_json::json!({"handle":handle,"nextOffset":next_offset}).to_string());
            }
            let handle = Uuid::new_v4().to_string();
            conn.execute("INSERT INTO oc_blob_write_handles(handle,sha256,size,next_offset,created_at) VALUES(?1,?2,?3,0,?4)",
                params![handle, sha256, size as i64, now_ms()])?;
            Ok(serde_json::json!({"handle":handle,"nextOffset":0}).to_string())
        })
    }

    /// Accept one chunk exactly at the acknowledged offset. Exact replay of a
    /// previously accepted chunk is idempotent; overlap/out-of-order is denied.
    pub fn blob_write_chunk(
        &self,
        app_key: String,
        handle: String,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<u64, OfflineError> {
        if bytes.is_empty() || bytes.len() > MAX_BLOB_CHUNK {
            return Err(OfflineError::Integrity(
                "blob chunk must be 1..262144 bytes".into(),
            ));
        }
        self.with_blob_conn(&app_key, |conn| {
            let (size, next): (i64, i64) = conn.query_row(
                "SELECT size,next_offset FROM oc_blob_write_handles WHERE handle=?1", [&handle],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(|_| OfflineError::Integrity("unknown blob write handle".into()))?;
            let end = offset.checked_add(bytes.len() as u64)
                .ok_or_else(|| OfflineError::Integrity("blob offset overflow".into()))?;
            if end > size as u64 { return Err(OfflineError::Integrity("blob chunk exceeds declared size".into())); }
            if offset < next as u64 {
                let prior: Option<Vec<u8>> = conn.query_row(
                    "SELECT bytes FROM oc_blob_write_chunks WHERE handle=?1 AND offset=?2",
                    params![handle, offset as i64], |row| row.get(0),
                ).optional()?;
                if prior.as_deref() == Some(bytes.as_slice()) { return Ok(next as u64); }
                return Err(OfflineError::Integrity("overlapping blob chunk".into()));
            }
            if offset != next as u64 { return Err(OfflineError::Integrity("out-of-order blob chunk".into())); }
            // Insert + offset advance are ONE atomic step (OFFSTORE-BLOB-NONATOMIC-ADVANCE):
            // a crash between the two autocommit statements used to wedge the
            // resume path (chunk stored, handle offset stale). Same SAVEPOINT
            // idiom as blob_write_commit; the advance's next_offset guard plus a
            // changed-rows check refuses to acknowledge an unapplied advance.
            conn.execute_batch("SAVEPOINT oc_blob_chunk")?;
            let result = (|| -> Result<(), OfflineError> {
                conn.execute("INSERT INTO oc_blob_write_chunks(handle,offset,bytes) VALUES(?1,?2,?3)",
                    params![handle, offset as i64, bytes])?;
                let advanced = conn.execute("UPDATE oc_blob_write_handles SET next_offset=?1 WHERE handle=?2 AND next_offset=?3",
                    params![end as i64, handle, next])?;
                if advanced != 1 {
                    return Err(OfflineError::Integrity("blob offset advance did not apply".into()));
                }
                Ok(())
            })();
            match result {
                Ok(()) => conn.execute_batch("RELEASE oc_blob_chunk")?,
                Err(error) => { conn.execute_batch("ROLLBACK TO oc_blob_chunk; RELEASE oc_blob_chunk")?; return Err(error); }
            }
            Ok(end)
        })
    }

    /// Validate size and SHA-256 by streaming ordered chunks, then atomically
    /// publish the content-addressed blob. Uses a SAVEPOINT so TS may wrap this
    /// call plus receipt metadata/ref creation in one outer transaction.
    pub fn blob_write_commit(
        &self,
        app_key: String,
        handle: String,
    ) -> Result<String, OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            let (sha, size, next): (String, i64, i64) = conn.query_row(
                "SELECT sha256,size,next_offset FROM oc_blob_write_handles WHERE handle=?1", [&handle],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).map_err(|_| OfflineError::Integrity("unknown blob write handle".into()))?;
            if size != next { return Err(OfflineError::Integrity("blob write is incomplete".into())); }
            let mut stmt = conn.prepare("SELECT offset,bytes FROM oc_blob_write_chunks WHERE handle=?1 ORDER BY offset")?;
            let mut rows = stmt.query([&handle])?;
            let mut expected = 0i64;
            let mut hasher = Sha256::new();
            while let Some(row) = rows.next()? {
                let offset: i64 = row.get(0)?;
                let bytes: Vec<u8> = row.get(1)?;
                if offset != expected { return Err(OfflineError::Integrity("blob chunk sequence has a gap".into())); }
                expected += bytes.len() as i64;
                hasher.update(&bytes);
            }
            drop(rows); drop(stmt);
            if expected != size || hex::encode(hasher.finalize()) != sha {
                return Err(OfflineError::Integrity("blob hash/size verification failed".into()));
            }
            conn.execute_batch("SAVEPOINT oc_blob_commit")?;
            let result = (|| -> Result<(), OfflineError> {
                conn.execute("INSERT OR IGNORE INTO oc_recovery_blobs(sha256,size,ref_count,created_at,last_read) VALUES(?1,?2,0,?3,?3)",
                    params![sha, size, now_ms()])?;
                let stored_size: i64 = conn.query_row("SELECT size FROM oc_recovery_blobs WHERE sha256=?1", [&sha], |r| r.get(0))?;
                if stored_size != size { return Err(OfflineError::Integrity("content hash reused with different size".into())); }
                conn.execute("INSERT OR IGNORE INTO oc_recovery_blob_chunks(sha256,offset,bytes) SELECT ?1,offset,bytes FROM oc_blob_write_chunks WHERE handle=?2",
                    params![sha, handle])?;
                conn.execute("DELETE FROM oc_blob_write_chunks WHERE handle=?1", [&handle])?;
                conn.execute("DELETE FROM oc_blob_write_handles WHERE handle=?1", [&handle])?;
                Ok(())
            })();
            match result {
                Ok(()) => conn.execute_batch("RELEASE oc_blob_commit")?,
                Err(error) => { conn.execute_batch("ROLLBACK TO oc_blob_commit; RELEASE oc_blob_commit")?; return Err(error); }
            }
            Ok(sha)
        })
    }

    pub fn blob_write_abort(&self, app_key: String, handle: String) -> Result<(), OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            conn.execute(
                "DELETE FROM oc_blob_write_chunks WHERE handle=?1",
                [&handle],
            )?;
            conn.execute(
                "DELETE FROM oc_blob_write_handles WHERE handle=?1",
                [&handle],
            )?;
            Ok(())
        })
    }

    pub fn blob_read_open(&self, app_key: String, sha256: String) -> Result<String, OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            let size: i64 = conn.query_row("SELECT size FROM oc_recovery_blobs WHERE sha256=?1", [&sha256], |r| r.get(0))
                .map_err(|_| OfflineError::Database("blob not found".into()))?;
            let handle = Uuid::new_v4().to_string();
            conn.execute("INSERT INTO oc_blob_read_handles(handle,sha256,size,created_at) VALUES(?1,?2,?3,?4)",
                params![handle, sha256, size, now_ms()])?;
            Ok(serde_json::json!({"handle":handle,"size":size}).to_string())
        })
    }

    pub fn blob_read_chunk(
        &self,
        app_key: String,
        handle: String,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, OfflineError> {
        if length == 0 || length as usize > MAX_BLOB_CHUNK {
            return Err(OfflineError::Integrity(
                "read length must be 1..262144".into(),
            ));
        }
        self.with_blob_conn(&app_key, |conn| {
            let (sha, size): (String, i64) = conn.query_row(
                "SELECT sha256,size FROM oc_blob_read_handles WHERE handle=?1", [&handle],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).map_err(|_| OfflineError::Database("unknown blob read handle".into()))?;
            if offset >= size as u64 { return Ok(Vec::new()); }
            let end = offset.saturating_add(length as u64).min(size as u64);
            let mut stmt = conn.prepare("SELECT offset,bytes FROM oc_recovery_blob_chunks WHERE sha256=?1 AND offset<?3 AND offset+length(bytes)>?2 ORDER BY offset")?;
            let mut rows = stmt.query(params![sha, offset as i64, end as i64])?;
            let mut out = Vec::with_capacity((end-offset) as usize);
            while let Some(row) = rows.next()? {
                let chunk_offset: i64 = row.get(0)?;
                let bytes: Vec<u8> = row.get(1)?;
                let from = offset.saturating_sub(chunk_offset as u64) as usize;
                let to = ((end.saturating_sub(chunk_offset as u64)) as usize).min(bytes.len());
                if from < to { out.extend_from_slice(&bytes[from..to]); }
            }
            if out.len() != (end-offset) as usize { return Err(OfflineError::Integrity("stored blob has a chunk gap".into())); }
            conn.execute("UPDATE oc_recovery_blobs SET last_read=?1 WHERE sha256=?2", params![now_ms(), sha])?;
            Ok(out)
        })
    }

    pub fn blob_read_close(&self, app_key: String, handle: String) -> Result<(), OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            conn.execute(
                "DELETE FROM oc_blob_read_handles WHERE handle=?1",
                [&handle],
            )?;
            Ok(())
        })
    }

    pub fn blob_ref(&self, app_key: String, sha256: String) -> Result<u64, OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            let changed = conn.execute(
                "UPDATE oc_recovery_blobs SET ref_count=ref_count+1 WHERE sha256=?1",
                [&sha256],
            )?;
            if changed != 1 {
                return Err(OfflineError::Database("blob not found".into()));
            }
            Ok(conn.query_row(
                "SELECT ref_count FROM oc_recovery_blobs WHERE sha256=?1",
                [&sha256],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    pub fn blob_unref(&self, app_key: String, sha256: String) -> Result<u64, OfflineError> {
        self.with_blob_conn(&app_key, |conn| {
            conn.execute_batch("SAVEPOINT oc_blob_unref")?;
            let changed = conn.execute("UPDATE oc_recovery_blobs SET ref_count=ref_count-1 WHERE sha256=?1 AND ref_count>0", [&sha256])?;
            if changed != 1 { conn.execute_batch("ROLLBACK TO oc_blob_unref; RELEASE oc_blob_unref")?; return Err(OfflineError::Integrity("blob refcount underflow or missing blob".into())); }
            let refs: i64 = conn.query_row("SELECT ref_count FROM oc_recovery_blobs WHERE sha256=?1", [&sha256], |r| r.get(0))?;
            if refs == 0 {
                conn.execute("DELETE FROM oc_recovery_blob_chunks WHERE sha256=?1", [&sha256])?;
                conn.execute("DELETE FROM oc_recovery_blobs WHERE sha256=?1", [&sha256])?;
            }
            conn.execute_batch("RELEASE oc_blob_unref")?;
            Ok(refs as u64)
        })
    }
}
