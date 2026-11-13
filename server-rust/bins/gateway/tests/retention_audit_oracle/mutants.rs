//! Planted changes at the running HTTP/database boundary; normal oracle comparison.
use super::*;
use setjoin_gateway::{Body, BoxFuture, Intercept, RequestContext};
pub struct Status<K: setjoin_authz::token::KeySource + 'static> {
    pub inner: setjoin_gateway::retention_audit::RetentionAuditRoute<K>,
    pub change: bool,
}
impl<K: setjoin_authz::token::KeySource + 'static> Intercept for Status<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let f = self.inner.handle(r, c);
        let change = self.change;
        Box::pin(async move {
            let mut r = f.await;
            if change {
                *r.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            r
        })
    }
}
pub async fn reject(action: &str, name: &str) -> Result<(), BoxError> {
    let label = if name == "no-tenant-filter" {
        "foreign"
    } else {
        "success"
    };
    let error = run(action, label, name)
        .await
        .expect_err("planted mutation survived")
        .to_string();
    let expected = match name {
        "status" | "no-tenant-filter" => "/response/status",
        "no-audit" => "/audit",
        "no-notify" => "/notify",
        "double-bump" => "/effects",
        _ => panic!("unknown mutant"),
    };
    if !error.contains(expected) {
        return Err(format!("wrong mutation failure: {error}").into());
    }
    let (method, path) = route(action);
    eprintln!("MUTANT-REJECTED: {method} {path} :: {name}");
    Ok(())
}

pub struct Proxy {
    pub dsn: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub async fn tenant_proxy(dsn: &str) -> Result<Proxy, BoxError> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let config: tokio_postgres::Config = dsn.parse()?;
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err("TCP DB needed".into()),
    };
    let port = *config.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?.port();
    let mut proxied = format!("host=127.0.0.1 port={local}");
    for (key, value) in [
        ("user", config.get_user()),
        (
            "password",
            config
                .get_password()
                .and_then(|p| std::str::from_utf8(p).ok()),
        ),
        ("dbname", config.get_dbname()),
    ] {
        if let Some(value) = value {
            proxied += &format!(
                " {key}='{}'",
                value.replace('\\', "\\\\").replace('\'', "\\'")
            );
        }
    }
    let task = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let Ok((mut client,_))=accepted else{break;};let host=host.clone();peers.spawn(async move{
             let mut server=TcpStream::connect((host.as_str(),port)).await?;
             let n=client.read_u32().await?;if !(8..=65536).contains(&n){return Err(std::io::Error::other("startup"));}let mut startup=vec![0;n as usize-4];client.read_exact(&mut startup).await?;server.write_u32(n).await?;server.write_all(&startup).await?;
             let(mut cr,mut cw)=client.into_split();let(mut sr,mut sw)=server.into_split();
             let requests=async {loop{let tag=cr.read_u8().await?;let len=cr.read_u32().await?;if !(4..=1048576).contains(&len){return Err(std::io::Error::other("message"));}let mut body=vec![0;len as usize-4];cr.read_exact(&mut body).await?;
              if tag==b'P'{let name=body.iter().position(|b|*b==0).ok_or_else(||std::io::Error::other("Parse name"))?+1;let end=name+body[name..].iter().position(|b|*b==0).ok_or_else(||std::io::Error::other("Parse SQL"))?;let sql=String::from_utf8_lossy(&body[name..end]).replace("MIN(COALESCE(ra.domain_override,rg.domain_scope))","NULL::bigint");body.splice(name..end,sql.bytes());}
              sw.write_u8(tag).await?;sw.write_u32((body.len()+4) as u32).await?;sw.write_all(&body).await?;
             }};
             tokio::select!{r=requests=>r,r=tokio::io::copy(&mut sr,&mut cw)=>r.map(|_|())}
            });},_=peers.join_next(),if !peers.is_empty()=>{}}
        }
    });
    Ok(Proxy { dsn: proxied, task })
}
