//! Real SSH protocol peer: authenticate the fixture key, capture commands, never execute.
use crate::common::{self, BoxError};
use russh::{
    keys::{Algorithm, PrivateKey, PublicKey},
    server::{self, Server as _, VerifiedPublicKey},
    Channel, ChannelId,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
#[derive(Clone)]
struct Handler {
    node: usize,
    client: PublicKey,
    commands: Arc<Mutex<Vec<(usize, String)>>>,
    hold: bool,
    signal: bool,
    output: Option<Vec<u8>>,
}
impl server::Server for Handler {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if user == "root" && key.public_key.key_data() == self.client.key_data() {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        _: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.commands.lock().unwrap().push((
            self.node,
            String::from_utf8(data.to_vec()).expect("fixture commands UTF8"),
        ));
        session.channel_success(channel)?;
        if !self.hold {
            session.data(
                channel,
                self.output.clone().unwrap_or_else(|| b"ok\n".to_vec()),
            )?;
            if self.signal {
                session.exit_signal_request(
                    channel,
                    russh::Sig::TERM,
                    false,
                    "gofree-plat2b signal",
                    "en",
                )?;
            } else {
                session.exit_status_request(channel, if self.output.is_some() { 1 } else { 0 })?;
            }
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}
pub struct Peer {
    pub addresses: Vec<String>,
    pub private_key: String,
    pub host_key: String,
    commands: Arc<Mutex<Vec<(usize, String)>>>,
    stops: Vec<server::RunningServerHandle>,
    tasks: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Peer {
    pub async fn start(mode: &str) -> Result<Self, BoxError> {
        use std::io::Write;
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Owned gofree-plat2b fake SSH listeners (in-process, stopped by Drop)"
            )?;
        }
        let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let client = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let certificates = if mode == "host-cert" {
            let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
                &mut rand::rng(),
                host.public_key(),
                0,
                u64::MAX,
            )?;
            builder.serial(455)?;
            builder.key_id("gofree-plat2b-peer")?;
            builder.cert_type(ssh_key::certificate::CertType::Host)?;
            builder.valid_principal("mail.test")?;
            vec![builder.sign(&host)?]
        } else {
            vec![]
        };
        let pinned = match certificates.first() {
            Some(cert) => cert.to_openssh()?,
            None => host.public_key().to_openssh()?,
        };
        let private_key = if mode == "rsa" {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/conformance/platform/ssh/client-rsa.pem"
            ))
            .to_owned()
        } else {
            client
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)?
                .to_string()
        };
        let client_public = if mode == "rsa" {
            PublicKey::from_openssh(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/conformance/platform/ssh/client-rsa.pub"
            )))?
        } else {
            client.public_key().clone()
        };
        let mut peer = Self {
            addresses: vec![],
            private_key,
            host_key: pinned,
            commands: Arc::new(Mutex::new(vec![])),
            stops: vec![],
            tasks: vec![],
        };
        let config = Arc::new(server::Config {
            keys: vec![host],
            certificates,
            auth_rejection_time: std::time::Duration::ZERO,
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });
        for node in 0..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            peer.addresses.push(listener.local_addr()?.to_string());
            let mut handler=Handler{node,client:client_public.clone(),commands:peer.commands.clone(),hold:mode=="hold",signal:mode=="signal",output:match mode {"invalid-utf8"=>Some(vec![0xff,0xfe]),"truncated-utf8"=>Some("界".repeat(1400).into_bytes()),"redact"=>Some(format!("{}\ngofree-plat2b-node-password\nhealth_check_password = 'unshared-secret'\n",peer.private_key).into_bytes()),_=>None}};
            let config = config.clone();
            let (starter, ready) = tokio::sync::oneshot::channel();
            peer.tasks.push(tokio::spawn(async move {
                let server = handler.run_on_socket(config, &listener);
                let _ = starter.send(server.handle());
                server.await
            }));
            peer.stops.push(ready.await?);
        }
        Ok(peer)
    }
    pub fn command_count(&self) -> usize {
        self.commands.lock().unwrap().len()
    }
    pub fn environment(&self) -> Vec<(&'static str, String)> {
        vec![
            ("DEPLOY_HOST_KEY", self.host_key.clone()),
            ("DEPLOY_SEAWEEDFS_SHA256", "a".repeat(64)),
        ]
    }
    pub fn body(&self, body: &str) -> Result<String, BoxError> {
        let mut out = body.replace(
            "\"{{ssh-inline-key}}\"",
            &serde_json::to_string(&self.private_key)?,
        );
        for (i, address) in self.addresses.iter().enumerate() {
            out = out.replace(&format!("{{{{ssh-node-{}}}}}", i + 1), address);
        }
        Ok(out)
    }
    pub fn names(&self, text: &str) -> String {
        let mut out = text.replace(&self.host_key, "ssh-ed25519 <pinned-host-key>");
        for (i, address) in self.addresses.iter().enumerate() {
            out = out.replace(address, &format!("<node-{}>", i + 1));
        }
        out
    }
    pub fn observation(&self) -> Result<Value, BoxError> {
        let commands = self.commands.lock().unwrap();
        let pattern = regex::Regex::new("health_check_password\\s*=\\s*'([0-9a-f]{32})'")?;
        let passwords = commands
            .iter()
            .filter_map(|(_, cmd)| pattern.captures(cmd).map(|m| m[1].to_owned()))
            .collect::<Vec<_>>();
        if passwords
            .chunks(3)
            .any(|run| run.iter().any(|value| Some(value) != run.first()))
        {
            return Err("pgpool did not use one shared generated password".into());
        }
        Ok(json!(commands
            .iter()
            .map(|(node, command)| {
                let mut cmd = self.names(command);
                for password in &passwords {
                    cmd = cmd.replace(password, "<verified-pgpool-password>");
                }
                json!({"node":node+1,"command":cmd})
            })
            .collect::<Vec<_>>()))
    }
    pub fn assert_public(&self, text: &str) -> Result<(), BoxError> {
        if text.contains("-----BEGIN") || text.contains("gofree-plat2b-node-password") {
            return Err("wizard status exposed node credential material".into());
        }
        Ok(())
    }
    pub async fn state_wire(
        &self,
        address: std::net::SocketAddr,
        bearer: &str,
    ) -> Result<String, BoxError> {
        let response = common::send(
            address,
            hyper::Request::get("/api/admin/deploy/status")
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {bearer}"))
                .body(common::full(""))?,
        )
        .await;
        if response.status() != 200 {
            return Err("status probe was refused".into());
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        self.assert_public(&raw)?;
        Ok(raw)
    }
    pub async fn state(
        &self,
        address: std::net::SocketAddr,
        bearer: &str,
    ) -> Result<Value, BoxError> {
        Ok(serde_json::from_str(
            &self.state_wire(address, bearer).await?,
        )?)
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        for stop in &self.stops {
            stop.shutdown("owned gofree-plat2b fixture ended".into());
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}
