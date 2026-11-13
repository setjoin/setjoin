//! Deliver one real row, then a real PostgreSQL protocol error to the client.
//! Both recorded Go and native replay use this owned, read-only fault seam.
use std::{
    collections::HashSet,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
pub async fn partial_rows(dsn: &str) -> (String, Arc<AtomicBool>, JoinHandle<()>) {
    let config: tokio_postgres::Config = dsn.parse().unwrap();
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => panic!("TCP fixture required"),
    };
    let port = *config.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let mut proxied = format!("host=127.0.0.1 port={proxy_port} sslmode=disable");
    for (key, value) in [
        ("user", config.get_user().map(str::to_owned)),
        (
            "password",
            config
                .get_password()
                .map(|v| String::from_utf8(v.to_vec()).unwrap()),
        ),
        ("dbname", config.get_dbname().map(str::to_owned)),
    ] {
        if let Some(v) = value {
            proxied.push_str(&format!(
                " {key}='{}'",
                v.replace('\\', "\\\\").replace('\'', "\\'")
            ));
        }
    }
    let armed = Arc::new(AtomicBool::new(false));
    let enabled = armed.clone();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{let Ok((client,_))=accepted else{break};let host=host.clone();let enabled=enabled.clone();children.spawn(async move{let _=relay(client,&host,port,enabled).await;});},
                _=children.join_next(),if !children.is_empty()=>{}
            }
        }
    });
    (proxied, armed, task)
}
async fn relay(
    mut client: TcpStream,
    host: &str,
    port: u16,
    armed: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut server = TcpStream::connect((host, port)).await?;
    let len = client.read_u32().await?;
    if !(8..=65536).contains(&len) {
        return Err(io::Error::other("startup length"));
    }
    let mut startup = vec![0; len as usize - 4];
    client.read_exact(&mut startup).await?;
    server.write_u32(len).await?;
    server.write_all(&startup).await?;
    let (cr, mut cw) = client.into_split();
    let (sr, mut sw) = server.into_split();
    let mut cr = cr;
    let mut sr = sr;
    let target = Arc::new(AtomicBool::new(false));
    let request_target = target.clone();
    let statements = Mutex::new(HashSet::<Vec<u8>>::new());
    let requests = async move {
        loop {
            let tag = cr.read_u8().await?;
            let len = cr.read_u32().await?;
            if !(4..=16777216).contains(&len) {
                return Err(io::Error::other("request length"));
            }
            let mut data = vec![0; len as usize - 4];
            cr.read_exact(&mut data).await?;
            if tag == b'P' {
                let mut parts = data.split(|b| *b == 0);
                let name = parts.next().unwrap_or(&[]).to_vec();
                let sql = parts.next().unwrap_or(&[]);
                let hit = sql
                    .windows(b"FROM calendar_acls".len())
                    .any(|v| v == b"FROM calendar_acls");
                let mut statements = statements.lock().unwrap();
                if hit {
                    statements.insert(name);
                } else {
                    statements.remove(&name);
                }
                request_target.store(hit, Ordering::SeqCst);
            }
            if tag == b'B' {
                let name = data.split(|b| *b == 0).nth(1).unwrap_or(&[]);
                request_target.store(statements.lock().unwrap().contains(name), Ordering::SeqCst);
            }
            if tag == b'Q' {
                request_target.store(
                    data.windows(b"FROM calendar_acls".len())
                        .any(|v| v == b"FROM calendar_acls"),
                    Ordering::SeqCst,
                );
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
            if !(4..=16777216).contains(&len) {
                return Err(io::Error::other("response length"));
            }
            let mut data = vec![0; len as usize - 4];
            sr.read_exact(&mut data).await?;
            cw.write_u8(tag).await?;
            cw.write_u32(len).await?;
            cw.write_all(&data).await?;
            if tag == b'D' && target.load(Ordering::SeqCst) && armed.load(Ordering::SeqCst) {
                let error = b"SERROR\0VERROR\0CP0001\0Mdrive1 partial wire fault\0\0";
                cw.write_u8(b'E').await?;
                cw.write_u32(error.len() as u32 + 4).await?;
                cw.write_all(error).await?;
                cw.flush().await?;
                return Ok(());
            }
            if tag == b'Z' {
                target.store(false, Ordering::SeqCst);
            }
        }
    };
    tokio::select! {r=requests=>r,r=responses=>r}
}
