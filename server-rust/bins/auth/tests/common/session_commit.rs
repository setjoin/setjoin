//! Multi-connection PG wire cut: independent Go-style audit uses another lease.
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    Before,
    After,
}
pub async fn armable(
    dsn: &str,
    cut: Cut,
    nth: usize,
) -> (String, JoinHandle<io::Result<Cut>>, Arc<AtomicBool>) {
    let active = Arc::new(AtomicBool::new(false));
    let (dsn, task) = inner(dsn, cut, nth, active.clone()).await;
    (dsn, task, active)
}
async fn inner(
    dsn: &str,
    cut: Cut,
    nth: usize,
    active: Arc<AtomicBool>,
) -> (String, JoinHandle<io::Result<Cut>>) {
    let cfg: tokio_postgres::Config = dsn.parse().unwrap();
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => panic!("TCP fixture DSN required"),
    };
    let port = *cfg.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut proxied = format!(
        "host=127.0.0.1 port={}",
        listener.local_addr().unwrap().port()
    );
    let mut add = |key: &str, value: &str| {
        proxied.push_str(&format!(
            " {key}='{}'",
            value.replace('\\', "\\\\").replace('\'', "\\'")
        ));
    };
    if let Some(v) = cfg.get_user() {
        add("user", v);
    }
    if let Some(v) = cfg.get_password() {
        add("password", std::str::from_utf8(v).unwrap());
    }
    if let Some(v) = cfg.get_dbname() {
        add("dbname", v);
    }
    if let Some(v) = cfg.get_options() {
        add("options", v);
    }
    let task = tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let count = Arc::new(AtomicUsize::new(0));
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                got=rx.recv()=>return got.unwrap_or_else(||Err(io::Error::other("wire cut channel closed"))),
                accepted=listener.accept()=>{let (client,_)=accepted?;let server=TcpStream::connect((host.as_str(),port)).await?;let tx=tx.clone();let count=count.clone();let active=active.clone();connections.spawn(async move {let result=connection(client,server,cut,nth,count,active).await;if let Ok(Some(cut))=result{let _=tx.send(Ok(cut));}});}
            }
        }
    });
    (proxied, task)
}
async fn connection(
    client: TcpStream,
    server: TcpStream,
    cut: Cut,
    nth: usize,
    count: Arc<AtomicUsize>,
    active: Arc<AtomicBool>,
) -> io::Result<Option<Cut>> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let len = cr.read_u32().await?;
    if !(8..=65536).contains(&len) {
        return Err(io::Error::other("startup length"));
    }
    let mut data = vec![0; len as usize - 4];
    cr.read_exact(&mut data).await?;
    sw.write_u32(len).await?;
    sw.write_all(&data).await?;
    let pending = Arc::new(AtomicBool::new(false));
    let pending_response = pending.clone();
    let requests = async move {
        loop {
            let tag = cr.read_u8().await?;
            let len = cr.read_u32().await?;
            if !(4..=16_777_216).contains(&len) {
                return Err(io::Error::other("request length"));
            }
            let mut data = vec![0; len as usize - 4];
            cr.read_exact(&mut data).await?;
            if tag == b'Q'
                && data.eq_ignore_ascii_case(b"COMMIT\0")
                && active.load(Ordering::SeqCst)
                && count.fetch_add(1, Ordering::SeqCst) + 1 == nth
            {
                if cut == Cut::Before {
                    return Ok(Some(cut));
                }
                pending.store(true, Ordering::SeqCst);
            }
            sw.write_u8(tag).await?;
            sw.write_u32(len).await?;
            sw.write_all(&data).await?;
        }
    };
    let responses = async move {
        loop {
            let tag = sr.read_u8().await?;
            let len = sr.read_u32().await?;
            if !(4..=16_777_216).contains(&len) {
                return Err(io::Error::other("response length"));
            }
            let mut data = vec![0; len as usize - 4];
            sr.read_exact(&mut data).await?;
            if tag == b'C'
                && data.eq_ignore_ascii_case(b"COMMIT\0")
                && pending_response.swap(false, Ordering::SeqCst)
            {
                return Ok(Some(cut));
            }
            cw.write_u8(tag).await?;
            cw.write_u32(len).await?;
            cw.write_all(&data).await?;
        }
    };
    tokio::select! {r=requests=>r,r=responses=>r}
}
