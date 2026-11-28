//! Test-only PostgreSQL statement mutation, through the real transport. The
//! driver still authenticates directly to the assigned database; no auth bytes
//! are interpreted or logged. Dropping the listener aborts its owned relays.
use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};

pub struct Wire {
    pub dsn: String,
    pub hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub async fn no_tenant_filter(dsn: &str) -> Result<Wire, crate::common::BoxError> {
    let cfg: tokio_postgres::Config = dsn.parse()?;
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err("TCP fixture required".into()),
    };
    let port = *cfg.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut dsn = format!(
        "host=127.0.0.1 port={} sslmode=disable",
        listener.local_addr()?.port()
    );
    for (key, value) in [
        ("user", cfg.get_user().map(str::to_owned)),
        (
            "password",
            cfg.get_password()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
        ),
        ("dbname", cfg.get_dbname().map(str::to_owned)),
    ] {
        if let Some(v) = value {
            dsn.push_str(&format!(
                " {key}='{}'",
                v.replace('\\', "\\\\").replace('\'', "\\'")
            ));
        }
    }
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{let Ok((client,_))=accepted else{break};let host=host.clone();let hits=counter.clone();children.spawn(async move{let _=relay(client,host,port,hits).await;});},
                _=children.join_next(),if !children.is_empty()=>{}
            }
        }
    });
    Ok(Wire { dsn, hits, task })
}
async fn relay(
    mut client: TcpStream,
    host: String,
    port: u16,
    hits: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut server = TcpStream::connect((host.as_str(), port)).await?;
    let len = client.read_u32().await?;
    if !(8..=65536).contains(&len) {
        return Err(io::Error::other("startup length"));
    }
    let mut startup = vec![0; len as usize - 4];
    client.read_exact(&mut startup).await?;
    server.write_u32(len).await?;
    server.write_all(&startup).await?;
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let requests = async move {
        loop {
            let tag = cr.read_u8().await?;
            let len = cr.read_u32().await?;
            if !(4..=16777216).contains(&len) {
                return Err(io::Error::other("packet length"));
            }
            let mut data = vec![0; len as usize - 4];
            cr.read_exact(&mut data).await?;
            if tag == b'P' {
                let start = data
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| io::Error::other("statement name"))?
                    + 1;
                let end = start
                    + data[start..]
                        .iter()
                        .position(|b| *b == 0)
                        .ok_or_else(|| io::Error::other("statement SQL"))?;
                let sql = std::str::from_utf8(&data[start..end])
                    .map_err(|_| io::Error::other("SQL encoding"))?;
                if sql.contains("FROM calendar_events ce")
                    && sql.contains("ce.uid=$2")
                    && sql.contains("mb.user_id=$3")
                {
                    let changed = sql.replace("mb.user_id=$3", "$3::bigint>0");
                    if changed != sql {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut packet = data[..start].to_vec();
                        packet.extend_from_slice(changed.as_bytes());
                        packet.extend_from_slice(&data[end..]);
                        data = packet;
                    }
                }
            }
            sw.write_u8(tag).await?;
            sw.write_u32(data.len() as u32 + 4).await?;
            sw.write_all(&data).await?;
        }
    };
    tokio::select! {r=requests=>r,r=tokio::io::copy(&mut sr,&mut cw)=>r.map(|_|())}
}
