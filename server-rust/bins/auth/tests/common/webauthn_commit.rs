//! Receipt-marked PostgreSQL COMMIT loss; skip preceding scoped read transactions.
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitCut {
    BeforeCommit,
    AfterCommit,
}

/// A one-connection wire proxy that cuts exactly at COMMIT. For the
/// committed case, PostgreSQL's CommandComplete is intercepted before it
/// reaches the client; for the absent case, COMMIT never reaches PostgreSQL.
pub async fn commit_cut_proxy(
    dsn: &str,
    cut: CommitCut,
    command: &'static str,
) -> (String, JoinHandle<io::Result<CommitCut>>) {
    let config: tokio_postgres::Config = dsn.parse().unwrap();
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        None => "127.0.0.1".into(),
        _ => panic!("commit-loss test needs a TCP DB_APP_DSN"),
    };
    let port = *config.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let mut proxied = format!("host=127.0.0.1 port={proxy_port}");
    // Reconstruct a libpq DSN so URI and keyword inputs both work; never
    // print it, since it can contain the app credential.
    let mut add = |key: &str, value: &str| {
        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
        proxied.push_str(&format!(" {key}='{escaped}'"));
    };
    if let Some(user) = config.get_user() {
        add("user", user);
    }
    if let Some(password) = config.get_password() {
        add(
            "password",
            std::str::from_utf8(password).expect("DB password is not UTF-8"),
        );
    }
    if let Some(database) = config.get_dbname() {
        add("dbname", database);
    }
    if let Some(options) = config.get_options() {
        add("options", options);
    }

    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let server = TcpStream::connect((host.as_str(), port)).await?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();

        // The first PostgreSQL packet is a length-prefixed startup packet,
        // without a message tag; the executor uses NoTls.
        let startup_len = client_read.read_u32().await?;
        if !(8..=65_536).contains(&startup_len) {
            return Err(io::Error::other("invalid PostgreSQL startup packet"));
        }
        let mut startup = vec![0; startup_len as usize - 4];
        client_read.read_exact(&mut startup).await?;
        server_write.write_u32(startup_len).await?;
        server_write.write_all(&startup).await?;

        let armed = std::sync::atomic::AtomicBool::new(false);
        let requests = async {
            loop {
                let tag = client_read.read_u8().await?;
                let len = client_read.read_u32().await?;
                if !(4..=1_048_576).contains(&len) {
                    return Err(io::Error::other("invalid PostgreSQL request"));
                }
                let mut body = vec![0; len as usize - 4];
                client_read.read_exact(&mut body).await?;
                if body.windows(command.len()).any(|w| w == command.as_bytes()) {
                    armed.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if armed.load(std::sync::atomic::Ordering::SeqCst)
                    && tag == b'Q'
                    && body == b"COMMIT\0"
                    && cut == CommitCut::BeforeCommit
                {
                    return Ok(CommitCut::BeforeCommit);
                }
                server_write.write_u8(tag).await?;
                server_write.write_u32(len).await?;
                server_write.write_all(&body).await?;
            }
        };
        let responses = async {
            loop {
                let tag = server_read.read_u8().await?;
                let len = server_read.read_u32().await?;
                if !(4..=1_048_576).contains(&len) {
                    return Err(io::Error::other("invalid PostgreSQL response"));
                }
                let mut body = vec![0; len as usize - 4];
                server_read.read_exact(&mut body).await?;
                if armed.load(std::sync::atomic::Ordering::SeqCst)
                    && tag == b'C'
                    && body == b"COMMIT\0"
                    && cut == CommitCut::AfterCommit
                {
                    return Ok(CommitCut::AfterCommit);
                }
                client_write.write_u8(tag).await?;
                client_write.write_u32(len).await?;
                client_write.write_all(&body).await?;
            }
        };
        tokio::select! { result = requests => result, result = responses => result }
    });
    (proxied, task)
}

/// Recovery has distinct revocation-reader and command pools. Each connection
/// uses the same byte-level proxy; only the selected command's COMMIT cuts the
/// whole fixture. Other connections are cancelled and reaped before returning.
#[allow(dead_code)]
pub async fn multiplex_commit_cut_proxy(dsn:&str,cut:CommitCut,command:&'static str)->(String,JoinHandle<io::Result<CommitCut>>){
    let config:tokio_postgres::Config=dsn.parse().unwrap();
    let listener=TcpListener::bind(("127.0.0.1",0)).await.unwrap();
    let mut proxied=format!("host=127.0.0.1 port={}",listener.local_addr().unwrap().port());
    let mut add=|key:&str,value:&str|{let escaped=value.replace('\\',"\\\\").replace('\'',"\\'");proxied.push_str(&format!(" {key}='{escaped}'"));};
    if let Some(v)=config.get_user(){add("user",v);}
    if let Some(v)=config.get_password(){add("password",std::str::from_utf8(v).unwrap());}
    if let Some(v)=config.get_dbname(){add("dbname",v);}
    if let Some(v)=config.get_options(){add("options",v);}
    let dsn=dsn.to_owned();
    struct Inner(JoinHandle<io::Result<CommitCut>>);
    impl Drop for Inner{fn drop(&mut self){self.0.abort();}}
    let task=tokio::spawn(async move{
        let mut connections=tokio::task::JoinSet::new();
        loop{tokio::select!{
            accepted=listener.accept()=>{
                let(mut client,_)=accepted?;let dsn=dsn.clone();
                connections.spawn(async move{
                    let(local,task)=commit_cut_proxy(&dsn,cut,command).await;
                    let cfg:tokio_postgres::Config=local.parse().unwrap();
                    let mut server=TcpStream::connect(("127.0.0.1",cfg.get_ports()[0])).await?;
                    let mut inner=Inner(task);
                    tokio::select!{
                        result=&mut inner.0=>result.map_err(io::Error::other)?,
                        result=tokio::io::copy_bidirectional(&mut client,&mut server)=>{
                            result?;Err(io::Error::other("unselected PostgreSQL connection closed"))
                        }
                    }
                });
            }
            result=connections.join_next(),if !connections.is_empty()=>{
                if let Some(Ok(Ok(observed)))=result{
                    connections.abort_all();while connections.join_next().await.is_some(){}
                    return Ok(observed);
                }
            }
        }}
    });
    (proxied,task)
}
