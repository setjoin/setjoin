//! Read-only LDAP GAL protocol listener. Transport is owned here; ldap3_proto
//! is solely the BER codec. No TCP proxy or per-command Go fallback.
mod cancel;
mod directory;
mod filter;
mod wire;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::{proto::*, LdapCodec};
use std::{io, sync::Arc};
use tokio_util::codec::Framed;
pub(crate) fn result(code: LdapResultCode) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message: String::new(),
        referral: vec![],
    }
}
use tokio::{net::TcpListener, sync::watch};
/// Disabled is an explicit unwired configuration; listeners refuse to serve it.
#[derive(Clone, Default)]
pub enum ThreatPolicy {
    Enforced(Arc<dyn setjoin_threat::ThreatGate>),
    #[default]
    Disabled,
}
#[derive(Clone)]
pub struct Server {
    tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    threat: ThreatPolicy,
    db: Option<setjoin_pg::ScopedExecutor>,
    domain: String,
    starttls: bool,
    max_connections: Option<usize>,
    inflight: Arc<tokio::sync::Semaphore>,
}
impl Default for Server {
    fn default() -> Self {
        Self {
            tls: None,
            threat: ThreatPolicy::Disabled,
            db: None,
            domain: String::new(),
            starttls: false,
            max_connections: None,
            inflight: Arc::new(tokio::sync::Semaphore::new(128)),
        }
    }
}
impl Server {
    pub fn with_threat_gate(mut self,gate:Arc<dyn setjoin_threat::ThreatGate>)->Self{self.threat=ThreatPolicy::Enforced(gate);self}

    pub fn with_threat_policy(mut self, policy: ThreatPolicy) -> Self {
        self.threat = policy;
        self
    }

    pub fn with_max_inflight(mut self, total: usize) -> Self {
        self.inflight = Arc::new(tokio::sync::Semaphore::new(if total == 0 {
            128
        } else {
            total
        }));
        self
    }

    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    pub fn with_starttls(mut self, tls: Arc<tokio_rustls::rustls::ServerConfig>) -> Self {
        self.tls = Some(tls);
        self.starttls = true;
        self
    }

    pub fn new(db: setjoin_pg::ScopedExecutor, domain: impl Into<String>) -> Self {
        Self {
            db: Some(db),
            domain: domain.into(),
            ..Self::default()
        }
    }
    pub fn with_tls(mut self, tls: Arc<tokio_rustls::rustls::ServerConfig>) -> Self {
        self.tls = Some(tls);
        self
    }
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> io::Result<()> {
        if !matches!(self.threat, ThreatPolicy::Enforced(_)) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "LDAP listener requires ThreatPolicy::Enforced"));
        }
        let mut sessions = tokio::task::JoinSet::new();
        let cap = self.max_connections.unwrap_or(100);
        let slots = if cap == 0 {
            None
        } else {
            Some(Arc::new(tokio::sync::Semaphore::new(cap)))
        };
        loop {
            while sessions.try_join_next().is_some() {}
            let permit = tokio::select! {biased;
                _=stop.changed()=>break,
                p=async {match &slots{Some(slots)=>slots.clone().acquire_owned().await.ok(),None=>None}}=>p,
            };
            let (socket, peer) =
                tokio::select! {biased;_=stop.changed()=>break,accept=listener.accept()=>accept?};
            let server = self.clone();
            sessions.spawn(async move {
                let _permit = permit;
                if let Some(tls) = server.tls.as_ref().filter(|_| !server.starttls) {
                    if let Ok(Ok(socket)) = tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        tokio_rustls::TlsAcceptor::from(tls.clone()).accept(socket),
                    )
                    .await
                    {
                        let _ = server.session(socket, true, &peer.ip().to_canonical().to_string()).await;
                    }
                } else {
                    let _ = server.session(socket, false, &peer.ip().to_canonical().to_string()).await;
                }
            });
        }
        sessions.shutdown().await;
        Ok(())
    }
    fn normalize(&self,email:&str)->String{
        let mut email = email.to_string();
        if email.contains('=') {
            let first = email.split(',').next().unwrap_or_default();
            if first.to_lowercase().starts_with("cn=") {
                let local = first.strip_prefix("cn=").unwrap_or(first);
                let local = local.strip_prefix("CN=").unwrap_or(local);
                email = format!("{local}@{}", self.domain);
            }
        }
        email
    }
    async fn authenticate(&self,email:&str,password:String,peer:&str)->Option<i64>{
        use setjoin_threat::{ConnectionMeta,ThreatAction};
        let email=self.normalize(email);
        let mut meta=ConnectionMeta{source_ip:peer.into(),username:email.clone(),protocol:"ldap".into(),..Default::default()};
        if let ThreatPolicy::Enforced(gate)=&self.threat{
            let(action,delay)=gate.intercept(&meta).await;
            if action!=ThreatAction::Allow{
                if matches!(action,ThreatAction::Reject|ThreatAction::Tarpitted)&&!delay.is_zero(){tokio::time::sleep(delay).await;}
                return None;
            }
        }
        let result=self.credential(&email,password).await;
        if let ThreatPolicy::Enforced(gate)=&self.threat{
            gate.record_result(&meta,result.is_some(),result.unwrap_or(0)).await;
            #[cfg(not(feature = "oracle-mutants"))]
            if let Some(user)=result {
                meta.user_id=user;
                if gate.evaluate_post_auth(&mut meta).await.0==ThreatAction::Reject{return None}
            }
        }
        result
    }
    async fn credential(&self,email:&str,password:String)->Option<i64>{
        let db = self.db.as_ref()?;
        let rows=db.read("SELECT u.id,u.password_hash FROM users u JOIN domains d ON d.id=u.domain_id WHERE u.email=$1 AND u.enabled=TRUE", &[(&email,setjoin_pg::Type::TEXT)]).await.ok()?;
        let row = rows.first()?;
        let id: i64 = row.get(0);
        let hash: String = row.try_get(1).ok()?;
        let verified_hash = hash.clone();
        let (valid, upgrade) = tokio::task::spawn_blocking(move || {
            let valid = setjoin_authz::password::verify(&hash, &password);
            let upgrade = if valid {
                setjoin_authz::password::standard_upgrade(&hash, &password)
            } else {
                None
            };
            (valid, upgrade)
        })
        .await
        .ok()?;
        if !valid {
            return None;
        }
        if let Some(upgrade) = upgrade {
            let _ = db
                .upgrade_legacy_protocol_password(id, &email, &verified_hash, &upgrade)
                .await;
        }
        let guest = db
            .read(
                "SELECT is_guest_account($1)",
                &[(&id, setjoin_pg::Type::INT8)],
            )
            .await
            .ok()?;
        if guest.first()?.get::<_, bool>(0) {
            return None;
        }
        Some(id)
    }
    async fn session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        socket: S,
        secure: bool,
        peer: &str,
    ) -> io::Result<()> {
        use futures_util::{stream::FuturesUnordered, FutureExt};
        use std::sync::atomic::AtomicI64;
        type Batch = (
            Vec<wire::Response>,
            tokio::sync::OwnedSemaphorePermit,
            Option<tokio::sync::OwnedSemaphorePermit>,
        );
        let framed = Framed::new(
            socket,
            wire::Codec(LdapCodec::new(Some((1 << 20) + 6), Some(40))),
        );
        let (mut sink, mut stream) = framed.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Batch>(16);
        let writer = async {
            while let Some((responses, _connection, _global)) = rx.recv().await {
                for response in responses {
                    tokio::time::timeout(std::time::Duration::from_secs(30), sink.send(response))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "LDAP response write deadline")
                        })??;
                }
            }
            Ok::<_, io::Error>(())
        };
        let reader = async {
            let bound = AtomicI64::new(0);
            let registry = Arc::new(cancel::Registry::default());
            let slots = Arc::new(tokio::sync::Semaphore::new(16));
            let mut pending = FuturesUnordered::new();
            let mut held: Option<LdapMsg> = None;
            let mut binding = false;
            loop {
                tokio::select! {
                    _=tx.closed()=>return Err(io::Error::new(io::ErrorKind::BrokenPipe,"LDAP writer closed")),
                    permit=slots.clone().acquire_owned(),if !binding && held.as_ref().is_some_and(|m| !matches!(m.op,LdapOp::BindRequest(_)) || pending.is_empty())=>{
                        let message=held.take().expect("held frame");let permit=permit.expect("connection admission open");
                        if matches!(message.op,LdapOp::BindRequest(_)) && !cfg!(feature = "oracle-mutants") {
                            // Bind is exclusive, but keep polling the transport so
                            // disconnect/Unbind drops its future and admission permits.
                            // Clear again after draining a previous Bind, even if
                            // global admission will reject this one as Busy.
                            bound.store(0,std::sync::atomic::Ordering::SeqCst);
                            binding = true;
                            pending.push(self.admitted(message,secure,&bound,permit,&registry,peer).boxed());
                        } else if matches!(message.op,LdapOp::AbandonRequest(_)){release_abandon(permit);}else{pending.push(self.admitted(message,secure,&bound,permit,&registry,peer).boxed());}
                    }
                    message=stream.next(),if held.is_none()=>{
                        let Some(message)=message else{return Ok(())};let message=message?;
                        if matches!(message.op,LdapOp::UnbindRequest){return Ok(())}
                        if matches!(message.op,LdapOp::BindRequest(_)) && !cfg!(feature = "oracle-mutants") {
                            // Invalidate even if global admission returns Busy.
                            bound.store(0,std::sync::atomic::Ordering::SeqCst);
                            held=Some(message);
                            continue;
                        }
                        if binding {
                            held=Some(message);
                            continue;
                        }
                        match slots.clone().try_acquire_owned(){
                            Ok(permit)=>{
                                if matches!(message.op,LdapOp::AbandonRequest(_)) {
                                    // Abandon has no response; release its admission
                                    // immediately (owner-approved security fix).
                                    release_abandon(permit);
                                }else{pending.push(self.admitted(message,secure,&bound,permit,&registry,peer).boxed());}
                            }
                            Err(_)=>held=Some(message),
                        }
                    }
                    responses=pending.next(),if !pending.is_empty()=>{
                        // An active Bind is the only outstanding operation.
                        binding = false;
                        tx.send(responses.expect("nonempty operations")).await.map_err(|_|io::Error::new(io::ErrorKind::BrokenPipe,"LDAP writer closed"))?;
                    }
                }
            }
        };
        tokio::select! {result=reader=>result,result=writer=>result}
    }
    async fn admitted(
        &self,
        message: LdapMsg,
        secure: bool,
        bound: &std::sync::atomic::AtomicI64,
        connection: tokio::sync::OwnedSemaphorePermit,
        registry: &Arc<cancel::Registry>,
        peer: &str,
    ) -> (
        Vec<wire::Response>,
        tokio::sync::OwnedSemaphorePermit,
        Option<tokio::sync::OwnedSemaphorePermit>,
    ) {
        let (_registration, mut cancelled) = registry.register(&message);
        match self.inflight.clone().try_acquire_owned() {
            Ok(global) => {
                let id = message.msgid;
                let cancelled_op = if matches!(message.op, LdapOp::CompareRequest(_)) {
                    LdapOp::CompareResult(result(LdapResultCode::NoSuchAttribute))
                } else {
                    LdapOp::SearchResultDone(result(LdapResultCode::OperationsError))
                };
                let responses = tokio::select! {
                    response=self.operation(message,secure,bound,registry,peer)=>response,
                    _=cancelled.changed()=>vec![wire::Response{message:LdapMsg{msgid:id,op:cancelled_op,ctrl:vec![]},generic:false}],
                };
                (responses, connection, Some(global))
            }
            Err(_) => (vec![busy(message)], connection, None),
        }
    }
    async fn operation(
        &self,
        message: LdapMsg,
        secure: bool,
        bound: &std::sync::atomic::AtomicI64,
        registry: &Arc<cancel::Registry>,
        peer: &str,
    ) -> Vec<wire::Response> {
        use std::sync::atomic::Ordering;
        let principal = bound.load(Ordering::SeqCst);
        let mut generic = false;
        let op = match message.op {
            LdapOp::UnbindRequest | LdapOp::AbandonRequest(_) => return vec![],
            LdapOp::BindRequest(request) => {
                // A Bind starts a fresh authentication exchange. Retaining the
                // previous user on failure leaks their directory (Go bug).
                #[cfg(not(feature = "oracle-mutants"))]
                bound.store(0, Ordering::SeqCst);
                let password = match request.cred {
                    LdapBindCred::Simple(p) => p,
                    _ => String::new(),
                };
                let code = if request.dn.is_empty() && password.is_empty() || !secure {
                    LdapResultCode::InappropriateAuthentication
                } else if let Some(user) = self.authenticate(&request.dn, password, peer).await {
                    bound.store(user, Ordering::SeqCst);
                    LdapResultCode::Success
                } else {
                    LdapResultCode::InvalidCredentials
                };
                LdapOp::BindResponse(LdapBindResponse {
                    res: result(code),
                    saslcreds: None,
                })
            }
            LdapOp::SearchRequest(request) if principal > 0 => {
                return self
                    .search(principal, request, &message.ctrl)
                    .await
                    .into_iter()
                    .map(|op| wire::Response {
                        message: LdapMsg {
                            msgid: message.msgid,
                            op,
                            ctrl: vec![],
                        },
                        generic: false,
                    })
                    .collect()
            }
            LdapOp::SearchRequest(_) => {
                LdapOp::SearchResultDone(result(LdapResultCode::InsufficentAccessRights))
            }
            LdapOp::CompareRequest(request) if principal > 0 => {
                LdapOp::CompareResult(result(self.compare(principal, &request).await))
            }
            LdapOp::CompareRequest(_) => {
                LdapOp::CompareResult(result(LdapResultCode::InsufficentAccessRights))
            }
            LdapOp::AddRequest(_) | LdapOp::DelRequest(_) | LdapOp::ModifyRequest(_) => {
                generic = true;
                let mut res = result(LdapResultCode::UnwillingToPerform);
                res.message =
                    "LDAP GAL is read-only; use admin console or JMAP for provisioning".into();
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res,
                    name: None,
                    value: None,
                })
            }
            LdapOp::ExtendedRequest(request) if request.name == cancel::OID => {
                let res = match cancel::target(request.value.as_deref()) {
                    Ok(id) => result(registry.cancel(id)),
                    Err(error) => {
                        let mut res = result(LdapResultCode::ProtocolError);
                        res.message = error;
                        res
                    }
                };
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res,
                    name: None,
                    value: None,
                })
            }
            LdapOp::ExtendedRequest(request) if request.name.is_empty() => {
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res: result(LdapResultCode::UnwillingToPerform),
                    name: None,
                    value: None,
                })
            }
            _ => {
                generic = true;
                let mut res = result(LdapResultCode::UnwillingToPerform);
                res.message = "Operation not implemented by server".into();
                LdapOp::ExtendedResponse(LdapExtendedResponse {
                    res,
                    name: None,
                    value: None,
                })
            }
        };
        vec![wire::Response {
            message: LdapMsg {
                msgid: message.msgid,
                op,
                ctrl: vec![],
            },
            generic,
        }]
    }
}

fn busy(message: LdapMsg) -> wire::Response {
    let mut res = result(LdapResultCode::Busy);
    res.message = "server busy: pool-wide in-flight limit".into();
    let mut generic = false;
    let op = match message.op {
        LdapOp::BindRequest(_) => LdapOp::BindResponse(LdapBindResponse {
            res,
            saslcreds: None,
        }),
        LdapOp::SearchRequest(_) => LdapOp::SearchResultDone(res),
        LdapOp::CompareRequest(_) => {
            res.message.clear();
            LdapOp::CompareResult(res)
        }
        LdapOp::ExtendedRequest(_) => LdapOp::ExtendedResponse(LdapExtendedResponse {
            res,
            name: None,
            value: None,
        }),
        _ => {
            generic = true;
            LdapOp::ExtendedResponse(LdapExtendedResponse {
                res,
                name: None,
                value: None,
            })
        }
    };
    wire::Response {
        message: LdapMsg {
            msgid: message.msgid,
            op,
            ctrl: vec![],
        },
        generic,
    }
}

fn release_abandon(permit:tokio::sync::OwnedSemaphorePermit){
    #[cfg(feature = "oracle-mutants")]
    permit.forget();
    #[cfg(not(feature = "oracle-mutants"))]
    drop(permit);
}
