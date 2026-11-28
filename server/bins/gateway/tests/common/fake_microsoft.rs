//! Owned HTTPS providers; their names resolve only inside the oracle fixture.
use crate::common::{full, BoxError};
use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;
use tokio_rustls::{
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
    TlsAcceptor,
};

pub const MAIL: &str = "From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nMessage-ID: <m7@example.test>\r\nSubject: Provider mail\r\n\r\nhello\r\n";
pub const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:m7-event\r\nSUMMARY:Provider event\r\nDTSTART:20261107T100000Z\r\nDTEND:20261107T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
pub const VCF: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:m7-contact\r\nFN:Provider contact\r\nN:Contact;Provider;;;\r\nEMAIL:person@example.test\r\nEND:VCARD\r\n";

pub struct Peer {
    pub address: SocketAddr,
    pub ca: String,
    pub client: reqwest::Client,
    pub seen: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Peer {
    pub async fn start(bind: &str, scenario: &str) -> Result<Self, BoxError> {
        let names = [
            "ews.mbox7.test",
            "graph.microsoft.com",
            "login.microsoftonline.com",
            "microsoftgraph.chinacloudapi.cn",
            "login.chinacloudapi.cn",
        ];
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )?;
        let ca = cert.pem();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes())?);
        for name in names {
            builder = builder.resolve(name, address);
        }
        let client = builder.build()?;
        let seen = Arc::new(Mutex::new(vec![]));
        let log = seen.clone();
        let scenario = scenario.to_owned();
        let task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            while let Ok((socket, remote)) = listener.accept().await {
                let (acceptor, seen, scenario) = (acceptor.clone(), log.clone(), scenario.clone());
                sessions.spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else { return; };
                    let service = hyper::service::service_fn(move |r: Request<hyper::body::Incoming>| {
                        let (seen, scenario) = (seen.clone(), scenario.clone());
                        async move {
                            let path = r.uri().to_string();
                            // Continuation links stay on the cloud the request came to, as the real
                            // Graph answers (#536: a china run must not be sent to the global host).
                            // `wrong-cloud-link` keeps the old behaviour on purpose: china requests are
                            // answered with global links, which the connector must refuse (secfix9).
                            let graph = if r.headers().get("host").and_then(|v|v.to_str().ok()).is_some_and(|h| h.starts_with("microsoftgraph.chinacloudapi.cn")) && scenario != "wrong-cloud-link" {"https://microsoftgraph.chinacloudapi.cn"} else {"https://graph.microsoft.com"};
                            let auth = r.headers().get("authorization").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
                            let prefer = r.headers().get("prefer").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
                            let anchor = r.headers().get("x-anchormailbox").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
                            let body = r.into_body().collect().await.unwrap().to_bytes();
                            let body = String::from_utf8_lossy(&body);
                            let operation = if body.contains("<m:GetFolder>") {"GetFolder"} else if body.contains("<m:SyncFolderItems>") {"SyncFolderItems"} else if body.contains("<m:GetItem>") {"GetItem"} else {""};
                            seen.lock().unwrap().push(json!({"path":path,"operation":operation,"authorization":auth,"prefer":prefer,"anchor":anchor,"connection":remote.port()}));
                            if scenario=="negotiate" {
                                let token=auth.strip_prefix("Negotiate ").and_then(|v|STANDARD.decode(v).ok());
                                let kind=token.as_ref().and_then(|b|b.get(8..12)).and_then(|b|b.try_into().ok()).map(u32::from_le_bytes);
                                if kind!=Some(3){
                                    let value=if kind==Some(1){format!("Negotiate {}",STANDARD.encode(challenge()))}else{"Negotiate".into()};
                                    return Ok::<_,std::convert::Infallible>(Response::builder().status(401).header("www-authenticate",value).body(full("")).unwrap());
                                }
                            }
                            let mut status = 200;
                            let response = if scenario == "http-error" { status = 403; "refused".into() }
                            else if operation == "GetFolder" {
                                let folder = ["inbox", "calendar", "contacts"].into_iter().filter(|f|scenario!="contacts-only"||*f!="calendar").find(|f| body.contains(&format!("Id=\"{f}\"")));
                                match folder { Some(f) => format!("<t:FolderId Id=\"{f}\"/>"), None => {status=404; String::new()} }
                            } else if operation == "SyncFolderItems" {
                                let f = ["inbox", "calendar", "contacts"].into_iter().find(|f| body.contains(&format!("Id=\"{f}\""))).unwrap();
                                format!("<m:SyncState>state-{f}</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><t:Create><t:ItemId Id=\"{f}-item\" ChangeKey=\"v1\"/></t:Create>")
                            } else if operation == "GetItem" {
                                let (f, tag, payload) = if body.contains("calendar-item") {("calendar", "CalendarItem", ICS)} else if body.contains("contacts-item") {("contacts", "Contact", VCF)} else {("inbox", "Message", MAIL)};
                                format!("<t:{tag}><t:ItemId Id=\"{f}-item\" ChangeKey=\"v1\"/><t:MimeContent>{}</t:MimeContent></t:{tag}>", STANDARD.encode(payload))
                            } else if path.contains("/oauth2/v2.0/token") {
                                if scenario == "token-error" {status=400; json!({"error":"invalid_client","error_description":"fixture rejected client"}).to_string()}
                                else {json!({"access_token":"fixture-token","token_type":"Bearer","expires_in":3600}).to_string()}
                            } else if scenario == "next-link" && path.contains("/contactFolders?") {
                                // #536: a continuation pointing at another origin.
                                json!({"value":[{"id":"book"}],"@odata.nextLink":"https://evil.example.test/v1.0/steal-next"}).to_string()
                            } else if path.contains("/contactFolders?") {json!({"value":[{"id":"book"}]}).to_string()}
                            else if path.ends_with("/$value") { MAIL.into() }
                            else if (path.contains("/contacts/delta") || path.contains("/contacts?")) && matches!(scenario.as_str(),"empty-contacts"|"mail-only") {json!({"value":[],"@odata.deltaLink":format!("{graph}/v1.0/done/contacts")}).to_string()}
                            else if path.contains("/contacts/delta") || path.contains("/contacts?") {
                                json!({"value":[{"id":"contact-1","changeKey":"c1","displayName":"Graph contact","givenName":"Graph","surname":"Contact","emailAddresses":[{"address":"graph@example.test"}]}],"@odata.deltaLink":format!("{graph}/v1.0/done/contacts")}).to_string()
                            } else if path.contains("/events?") && scenario=="mail-only" {json!({"value":[]}).to_string()}
                            else if path.contains("/events?") {
                                json!({"value":[{"id":"event-1","changeKey":"e1","iCalUId":"graph-event","subject":"Graph event","start":{"dateTime":"2026-11-07T10:00:00","timeZone":"UTC"},"end":{"dateTime":"2026-11-07T11:00:00","timeZone":"UTC"}}]}).to_string()
                            } else if path.contains("/messages/delta") {
                                let value = if path.contains("/inbox/") {json!([{"id":"mail-1","changeKey":"m1","parentFolderId":"inbox"}])} else {json!([])};
                                json!({"value":value,"@odata.deltaLink":format!("{graph}/v1.0/done/messages")}).to_string()
                            } else if path.contains("/users?") {if scenario=="empty-users" {json!({"value":[]}).to_string()} else {json!({"value":[{"id":"source-user"}]}).to_string()}}
                            else {json!({"id":"source-user","mail":"source@example.test","userPrincipalName":"source@example.test"}).to_string()};
                            Ok::<_, std::convert::Infallible>(Response::builder().status(status).header("content-type", if operation.is_empty() {"application/json"} else {"text/xml"}).body(full(response)).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls),service).await;
                });
            }
        });
        Ok(Self {
            address,
            ca,
            client,
            seen,
            task,
        })
    }
}

// A provider challenge frame, not a crypto implementation. Frozen Go consumes
// this same frame during recording; all client secret-dependent work is external.
fn challenge() -> Vec<u8> {
    let name: Vec<u8> = "DOMAIN".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = b"NTLMSSP\0".to_vec();
    out.extend(2u32.to_le_bytes());
    out.extend((name.len() as u16).to_le_bytes());
    out.extend((name.len() as u16).to_le_bytes());
    out.extend(48u32.to_le_bytes());
    out.extend(0x0088_0205u32.to_le_bytes());
    out.extend([0x12; 8]);
    out.extend([0; 8]);
    out.extend(4u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend((48u32 + name.len() as u32).to_le_bytes());
    out.extend(name);
    out.extend([0; 4]);
    out
}
