//! The database seam. Federation tables are FORCE-RLS deny-all to the request
//! role, so every call here runs on the worker credential (`DB_WORKER_DSN`,
//! falling back to `DB_DSN` like Go's `workerPool`). Statements are the
//! reducers' own, bound over the unnamed protocol.

use bytes::BytesMut;
use setjoin_pg::{workers::WorkerConnection, workers::WorkerDatabase, Param, Row};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio_postgres::types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Query access for the protocol components; tests may substitute stubs.
pub trait FedDb: Send + Sync {
    fn query<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [Param<'a>],
    ) -> BoxFut<'a, Result<Vec<Row>, String>>;
}

/// A lazily (re)connected worker-credential connection.
pub struct WorkerPool {
    db: WorkerDatabase,
    conn: tokio::sync::Mutex<Option<Arc<WorkerConnection>>>,
}

impl WorkerPool {
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            conn: tokio::sync::Mutex::new(None),
        }
    }
    async fn connection(&self) -> Result<Arc<WorkerConnection>, String> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            return Ok(c.clone());
        }
        let c = Arc::new(self.db.connect().await.map_err(|e| e.to_string())?);
        *g = Some(c.clone());
        Ok(c)
    }
    async fn discard(&self, c: &Arc<WorkerConnection>) {
        let mut g = self.conn.lock().await;
        if g.as_ref().is_some_and(|x| Arc::ptr_eq(x, c)) {
            *g = None;
        }
    }
}

impl FedDb for WorkerPool {
    fn query<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [Param<'a>],
    ) -> BoxFut<'a, Result<Vec<Row>, String>> {
        Box::pin(async move {
            let c = self.connection().await?;
            match c.query(sql, params).await {
                Ok(rows) => Ok(rows),
                Err(e) => {
                    // A server-reported error leaves the session usable; a
                    // transport error does not.
                    if sqlstate(&e).is_none() {
                        self.discard(&c).await;
                    }
                    Err(e)
                }
            }
        })
    }
}

/// The SQLSTATE the shared error formatter appends: `... (SQLSTATE BZ202)`.
pub fn sqlstate(err: &str) -> Option<&str> {
    let i = err.rfind("(SQLSTATE ")?;
    let rest = &err[i + 10..];
    rest.strip_suffix(')')
}

/// Go's `reducererr.IsCode`.
pub fn is_code(err: &str, code: &str) -> bool {
    sqlstate(err) == Some(code)
}

/// A `jsonb` parameter carrying the caller's bytes verbatim (jsonb binary
/// format: version byte then the text), exactly what pgx sends for a
/// `[]byte` argument.
#[derive(Debug)]
pub struct RawJsonb<'a>(pub &'a [u8]);

impl ToSql for RawJsonb<'_> {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        out.extend_from_slice(&[1]);
        out.extend_from_slice(self.0);
        Ok(IsNull::No)
    }
    fn accepts(ty: &Type) -> bool {
        *ty == Type::JSONB
    }
    to_sql_checked!();
}

/// A `jsonb` result column as its stored text bytes.
pub struct JsonbText(pub Vec<u8>);

impl<'a> FromSql<'a> for JsonbText {
    fn from_sql(
        _ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match raw.split_first() {
            Some((1, rest)) => Ok(JsonbText(rest.to_vec())),
            _ => Err("unsupported jsonb version".into()),
        }
    }
    fn accepts(ty: &Type) -> bool {
        *ty == Type::JSONB
    }
}
