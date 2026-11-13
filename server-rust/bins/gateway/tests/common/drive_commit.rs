//! PostgreSQL wire loss at the transaction boundary; copied from the foundation fault seam.
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

    let write_commit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
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

        let requests = async {
            let mut readonly = true;
            loop {
                let tag = client_read.read_u8().await?;
                let len = client_read.read_u32().await?;
                if !(4..=1_048_576).contains(&len) {
                    return Err(io::Error::other("invalid PostgreSQL request"));
                }
                let mut body = vec![0; len as usize - 4];
                client_read.read_exact(&mut body).await?;
                if tag == b'Q' && body.starts_with(b"BEGIN") {
                    readonly = body.windows(9).any(|w| w == b"READ ONLY");
                }
                if tag == b'Q' && body == b"COMMIT\0" && !readonly {
                    write_commit.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if tag == b'Q' && body == b"COMMIT\0" && !readonly && cut == CommitCut::BeforeCommit
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
                if tag == b'C'
                    && body == b"COMMIT\0"
                    && write_commit.swap(false, std::sync::atomic::Ordering::SeqCst)
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
