//! Mutate the running adapter/DB boundary, then use the unmodified comparator.
use super::*;
use setjoin_gateway::{Body, BoxFuture, Intercept, RequestContext};
pub struct Status<K: setjoin_authz::token::KeySource + 'static> {
    pub inner: ComplianceRoute<K>,
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
pub struct Proxy {
    pub dsn: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn bind_first_hex_param(
    body: &[u8],
    receipt_stmts: &std::collections::HashSet<Vec<u8>>,
) -> Option<String> {
    let portal_end = body.iter().position(|&b| b == 0)?;
    let stmt_start = portal_end + 1;
    let stmt_rel_end = body.get(stmt_start..)?.iter().position(|&b| b == 0)?;
    let stmt_name = &body[stmt_start..stmt_start + stmt_rel_end];
    if !receipt_stmts.contains(stmt_name) {
        return None;
    }
    let mut pos = stmt_start + stmt_rel_end + 1;
    let fmt_count = u16::from_be_bytes(body.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos = pos.checked_add(2)?.checked_add(fmt_count.checked_mul(2)?)?;
    let val_count = u16::from_be_bytes(body.get(pos..pos + 2)?.try_into().ok()?) as usize;
    pos = pos.checked_add(2)?;
    if val_count == 0 {
        return None;
    }
    let len = i32::from_be_bytes(body.get(pos..pos + 4)?.try_into().ok()?);
    pos = pos.checked_add(4)?;
    if len != 32 {
        return None;
    }
    let param = body.get(pos..pos + 32)?;
    if !param.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    std::str::from_utf8(param).ok().map(str::to_owned)
}

pub async fn db_proxy(
    dsn: &str,
    rewrite_tenant: bool,
    recorded_ops: Arc<std::sync::Mutex<Vec<String>>>,
) -> Result<Proxy, BoxError> {
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
            tokio::select! {accepted=listener.accept()=>{let Ok((mut client,_))=accepted else{break;};let host=host.clone();let recorded_ops=recorded_ops.clone();peers.spawn(async move{
             let mut server=TcpStream::connect((host.as_str(),port)).await?;
             let n=client.read_u32().await?;if !(8..=65536).contains(&n){return Err(std::io::Error::other("startup"));}let mut startup=vec![0;n as usize-4];client.read_exact(&mut startup).await?;server.write_u32(n).await?;server.write_all(&startup).await?;
             let(mut cr,mut cw)=client.into_split();let(mut sr,mut sw)=server.into_split();
             let mut receipt_stmts = std::collections::HashSet::<Vec<u8>>::new();
             let requests=async {loop{let tag=cr.read_u8().await?;let len=cr.read_u32().await?;if !(4..=1048576).contains(&len){return Err(std::io::Error::other("message"));}let mut body=vec![0;len as usize-4];cr.read_exact(&mut body).await?;
              if tag==b'P'{let name=body.iter().position(|b|*b==0).ok_or_else(||std::io::Error::other("Parse name"))?;let stmt_name=body[..name].to_vec();let sql_start=name+1;let end=sql_start+body[sql_start..].iter().position(|b|*b==0).ok_or_else(||std::io::Error::other("Parse SQL"))?;let rewritten={let sql_str=String::from_utf8_lossy(&body[sql_start..end]);if sql_str.contains("INSERT INTO")&&sql_str.contains("rust_operation_receipts"){receipt_stmts.insert(stmt_name);}else{receipt_stmts.remove(&stmt_name);}rewrite_tenant.then(||sql_str.replace("MIN(COALESCE(ra.domain_override,rg.domain_scope))","NULL::bigint").replace("COALESCE(ra.domain_override, rg.domain_scope) AS eff_scope","NULL::bigint AS eff_scope"))};if let Some(rewritten)=rewritten{body.splice(sql_start..end,rewritten.bytes());}}
              else if tag==b'C'&&body.first()==Some(&b'S'){if let Some(end)=body.get(1..).and_then(|s|s.iter().position(|b|*b==0)){receipt_stmts.remove(&body[1..1+end]);}}
              else if tag==b'B'{if let Some(op)=bind_first_hex_param(&body,&receipt_stmts){recorded_ops.lock().unwrap().push(op);}}
              sw.write_u8(tag).await?;sw.write_u32((body.len()+4) as u32).await?;sw.write_all(&body).await?;
             }};
             tokio::select!{r=requests=>r,r=tokio::io::copy(&mut sr,&mut cw)=>r.map(|_|())}
            });},_=peers.join_next(),if !peers.is_empty()=>{}}
        }
    });
    Ok(Proxy { dsn: proxied, task })
}
pub async fn reject(action: &str, name: &str) -> Result<(), BoxError> {
    let label = if name == "no-tenant-filter" {
        "foreign"
    } else {
        "success"
    };
    let error = run_with(action, label, name)
        .await
        .expect_err("planted mutation survived")
        .to_string();
    let expected = match name {
        "status" => "/response/status",
        "no-audit" => "/audit",
        "double-bump" => "/effects",
        "no-tenant-filter" => "/response/status",
        _ => panic!("unknown mutant"),
    };
    if !error.contains(expected) {
        return Err(format!("wrong mutation failure: {error}").into());
    }
    let path = match action {
        "list" => "/admin/ediscovery/cases",
        "get" | "update" | "delete" => "/admin/ediscovery/cases/{id}",
        "create" => "/admin/ediscovery/cases",
        "close" => "/admin/ediscovery/cases/{id}/close",
        "associate" => "/admin/ediscovery/cases/associate",
        "start" => "/admin/ediscovery/search",
        "search" => "/admin/ediscovery/{id}",
        "export" => "/admin/ediscovery/export",
        "hold" => "/admin/ediscovery/hold",
        "release" => "/admin/ediscovery/release",
        _ => panic!("route"),
    };
    let method = match action {
        "list" | "get" | "search" | "export" => "GET",
        "delete" => "DELETE",
        "update" => "PUT",
        _ => "POST",
    };
    eprintln!("MUTANT-REJECTED: {method} {path} :: {name}");
    Ok(())
}
