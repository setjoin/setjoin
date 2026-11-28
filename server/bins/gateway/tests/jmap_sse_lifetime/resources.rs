//! Mixed WS/SSE presence and the default shared1000 connection budget.
use crate::{common, BoxError, Frames};
use futures_util::{SinkExt, StreamExt};
use hyper::{body::Incoming, Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::fixture;
use std::{net::SocketAddr, time::Duration};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub async fn presence(address: SocketAddr, user: i64) -> Result<bool, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/api/chat/presence?userIds={user}"))
            .header(
                "authorization",
                format!("Bearer {}", common::recovery_token(user)),
            )
            .body(common::full(""))?,
    )
    .await;
    if response.status() != 200 {
        return Err(format!("presence failed: {}", response.status()).into());
    }
    let value: Value = serde_json::from_slice(&common::body_bytes(response).await)?;
    value[user.to_string()]
        .as_bool()
        .ok_or_else(|| "presence value missing".into())
}
async fn ws(address: SocketAddr, user: i64) -> Result<Socket, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request.headers_mut().insert(
        "cookie",
        format!("access_token={}", common::recovery_token(user)).parse()?,
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    socket
        .send(Message::Text(r#"{"@type":"ready"}"#.into()))
        .await?;
    tokio::time::timeout(Duration::from_secs(15), socket.next())
        .await?
        .ok_or("WS ended before ready")??;
    Ok(socket)
}
async fn sse(address: SocketAddr, user: i64, query: &str) -> Result<Response<Incoming>, BoxError> {
    Ok(common::send(
        address,
        Request::builder()
            .uri(format!("http://{address}/jmap/eventsource?{query}"))
            .header(
                "authorization",
                format!("Bearer {}", common::recovery_token(user)),
            )
            .body(common::full(""))?,
    )
    .await)
}
async fn close(socket: &mut Socket) -> Result<(), BoxError> {
    socket.close(None).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(frame) = socket.next().await {
            match frame {
                Ok(Message::Ping(_)) => socket.flush().await?,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok::<_, BoxError>(())
    })
    .await??;
    Ok(())
}
pub async fn observe(
    case: &str,
    address: SocketAddr,
    a: &fixture::Account,
    response: Response<Incoming>,
    before: Option<bool>,
) -> Result<(String, Value), BoxError> {
    let mut first = Frames {
        body: response.into_body(),
        buffer: Vec::new(),
    };
    let body = first.next().await?;
    if case == "resource-presence" {
        let mut states = vec![
            before.ok_or("missing before presence")?,
            presence(address, a.user).await?,
        ];
        let mut socket = ws(address, a.user).await?;
        drop(first);
        states.push(presence(address, a.user).await?);
        close(&mut socket).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while presence(address, a.user).await? {
            if tokio::time::Instant::now() >= deadline {
                return Err("last push connection stayed present".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        states.push(false);
        return Ok((body, json!({"presence":states})));
    }
    let (stop, receive) = tokio::sync::watch::channel(false);
    let mut clients = tokio::task::JoinSet::new();
    let mut controls = Vec::new();
    for _ in 0..998 {
        let mut socket = ws(address, a.user).await?;
        let (release, released) = tokio::sync::oneshot::channel();
        controls.push(release);
        let mut receive = receive.clone();
        clients.spawn(async move {
   tokio::pin!(released);
   loop {tokio::select!{
    _=&mut released=>return close(&mut socket).await,
    _=receive.changed()=>return close(&mut socket).await,
    frame=socket.next()=>match frame {Some(Ok(Message::Ping(_)))=>socket.flush().await?,Some(Ok(_))=>{},Some(Err(error))=>return Err(error.into()),None=>return Err("WS closed before budget test finished".into())},
   }}
  });
    }
    let response = sse(address, a.user, "closeafter=no").await?;
    if response.status() != 200 {
        return Err("connection1000 was rejected".into());
    }
    let mut last = Frames {
        body: response.into_body(),
        buffer: Vec::new(),
    };
    if last.next().await? != body {
        return Err("connection1000 state changed".into());
    }
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request.headers_mut().insert(
        "cookie",
        format!("access_token={}", common::recovery_token(a.user)).parse()?,
    );
    let ws_denied = match tokio_tungstenite::connect_async(request).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            json!({"status":response.status().as_u16(),"body":String::from_utf8(response.body().clone().unwrap_or_default())?})
        }
        _ => return Err("WS connection1001 was admitted".into()),
    };
    let denied = sse(address, a.user, "closeafter=state").await?;
    let sse_status = denied.status().as_u16();
    let denied_body = String::from_utf8(common::body_bytes(denied).await.to_vec())?;
    controls
        .remove(0)
        .send(())
        .map_err(|_| "budget client ended before release")?;
    clients
        .join_next()
        .await
        .ok_or("missing released client")???;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let recovered = loop {
        let response = sse(address, a.user, "closeafter=state").await?;
        let status = response.status().as_u16();
        let bytes = common::body_bytes(response).await;
        if status == 200 {
            if bytes.as_ref() != body.as_bytes() {
                return Err("recovered state changed".into());
            }
            break status;
        }
        if status != 503 || tokio::time::Instant::now() >= deadline {
            return Err("released push budget did not recover".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let _ = stop.send(true);
    while let Some(client) = clients.join_next().await {
        client??;
    }
    drop(last);
    drop(first);
    Ok((
        body,
        json!({"websocket":ws_denied,"sse":{"status":sse_status,"body":denied_body},"recovered":recovered}),
    ))
}
