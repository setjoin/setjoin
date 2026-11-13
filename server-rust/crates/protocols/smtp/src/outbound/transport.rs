//! Transport security decisions use resolver answers, never injected verdicts.
use futures_util::future::BoxFuture;
use std::sync::{Arc, RwLock};

/// A raw DNS response retains AD and RCODE; authenticated absence differs from failure.
#[derive(Clone, Default)]
pub struct TlsaAnswer {
    pub authenticated: bool,
    pub rcode: u16,
    pub records: Vec<TlsaRecord>,
}
#[derive(Clone)]
pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub association: Vec<u8>,
}
pub trait TlsaLookup: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<TlsaAnswer, String>>;
}
#[derive(Clone, Copy)]
struct Features {
    dane: bool,
    dnssec: bool,
    mta: bool,
    report: bool,
}
impl Default for Features {
    fn default() -> Self {
        Self {
            dane: true,
            dnssec: true,
            mta: true,
            report: true,
        }
    }
}
pub struct TransportSecurity {
    tlsa: Arc<dyn TlsaLookup>,
    features: RwLock<Features>,
    live: Option<setjoin_pg::workers::WorkerDatabase>,
    mta: Option<super::mtasts::MtaSts>,
    reporter: Option<super::tlsrpt::Reporter>,
}
impl TransportSecurity {
    pub fn new(tlsa: Arc<dyn TlsaLookup>) -> Self {
        Self {
            tlsa,
            features: RwLock::new(Features::default()),
            live: None,
            mta: None,
            reporter: None,
        }
    }
    pub fn with_dane(mut self, enabled: bool) -> Self {
        self.features.get_mut().unwrap().dane = enabled;
        self
    }
    pub fn with_live_features(mut self, db: setjoin_pg::workers::WorkerDatabase) -> Self {
        self.live = Some(db);
        self
    }
    pub(super) async fn refresh(&self) -> Result<(), String> {
        let Some(db) = &self.live else { return Ok(()) };
        let loaded=async {
            let connection=db.connect_session().await.map_err(|e|e.to_string())?;
            let rows=connection.query("SELECT ft.key,ft.enabled,s.mode FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON ft.key IN ('feature.dane','feature.dnssec','feature.mta_sts','feature.tls_rpt') WHERE s.singleton",&[]).await?;
            if rows.is_empty() {return Err("feature toggle registry state row is missing".to_string())}
            let mut features=Features::default();
            for row in rows {
                let mode:String=row.try_get(2).map_err(|e|e.to_string())?;
                if !matches!(mode.as_str(),"observe"|"enforce") {return Err("invalid feature toggle registry mode".into())}
                let (key,enabled):(Option<String>,Option<bool>)=(row.try_get(0).map_err(|e|e.to_string())?,row.try_get(1).map_err(|e|e.to_string())?);
                if let (Some(key),Some(enabled))=(key,enabled) {match key.as_str(){"feature.dane"=>features.dane=enabled,"feature.dnssec"=>features.dnssec=enabled,"feature.mta_sts"=>features.mta=enabled,"feature.tls_rpt"=>features.report=enabled,_=>{}}}
            }
            Ok::<_,String>(features)
        }.await;
        match loaded {
            Ok(features) => {
                *self.features.write().unwrap() = features;
                Ok(())
            }
            Err(error) => {
                eprintln!("SMTP transport feature reload: {error}");
                // Frozen toggle.Reload's conservative failure map: positive
                // DNSSEC/DANE stay on; MTA-STS/report product gates go off.
                *self.features.write().unwrap() = Features {
                    dane: true,
                    dnssec: true,
                    mta: false,
                    report: false,
                };
                Err(error)
            }
        }
    }
    pub(super) async fn initialize_cache(&self) {
        if let Some(mta) = &self.mta {
            mta.initialize().await;
        }
    }

    pub fn with_mta_sts(mut self, db: setjoin_pg::workers::WorkerDatabase) -> Self {
        self.mta = Some(super::mtasts::MtaSts::new(db));
        self
    }
    pub fn with_policy_fetch(
        mut self,
        db: setjoin_pg::workers::WorkerDatabase,
        dns: Arc<dyn crate::mail_auth::Dns>,
        fetch: Arc<dyn super::PolicyFetch>,
    ) -> Self {
        self.mta = Some(super::mtasts::MtaSts::new(db).with_network(dns, fetch));
        self
    }
    pub fn with_reporting(
        mut self,
        db: setjoin_pg::workers::WorkerDatabase,
        dns: Arc<dyn crate::mail_auth::Dns>,
    ) -> Self {
        self.reporter = Some(super::tlsrpt::Reporter::new(db, dns));
        self
    }
    pub(super) async fn report_uri(&self, domain: &str) -> String {
        if !self.features.read().unwrap().report {
            return String::new();
        }
        match &self.reporter {
            Some(r) => r.discover(domain).await,
            None => String::new(),
        }
    }
    pub(super) async fn record_session(
        &self,
        domain: &str,
        host: &str,
        uri: &str,
        error: Option<&str>,
    ) {
        if !self.features.read().unwrap().report {
            return;
        }
        if let Some(r) = &self.reporter {
            r.record(domain, host, uri, error).await;
        }
    }
    pub(super) fn dane_enabled(&self) -> bool {
        let features = self.features.read().unwrap();
        features.dane && features.dnssec
    }
    pub(super) async fn mta_policy(&self, domain: &str) -> Option<super::mtasts::Policy> {
        if !self.features.read().unwrap().mta {
            return None;
        }
        match &self.mta {
            Some(mta) => mta.lookup(domain).await,
            None => None,
        }
    }
    async fn answer(&self, host: &str) -> Result<TlsaAnswer, String> {
        let answer = self
            .tlsa
            .lookup(host)
            .await
            .map_err(|_| unavailable(host))?;
        if !answer.authenticated && !matches!(answer.rcode, 0 | 3) {
            return Err(unavailable(host));
        }
        Ok(answer)
    }
    /// The authenticated TLSA policy of `host`, when DANE applies to it. One answer
    /// serves both the pool decision and the handshake verifier, so a record that
    /// changes between two lookups cannot split the decision.
    pub(super) async fn dane_policy(
        &self,
        host: &str,
    ) -> Result<Option<Arc<super::dane::Policy>>, String> {
        if !self.dane_enabled() {
            return Ok(None);
        }
        let answer = self.answer(host).await?;
        Ok((answer.authenticated && !answer.records.is_empty())
            .then(|| Arc::new(super::dane::Policy::new(answer.records))))
    }
}
fn unavailable(host: &str) -> String {
    format!("DANE: server {host} unreachable — TLSA lookup failed per RFC 7672 §2.1")
}

/// Frozen Go sends one UDP query to the first configured resolver, with DO/RD.
/// Hickory owns query IDs, source-port selection and response matching.
pub struct SystemTlsa {
    nameserver: std::net::SocketAddr,
}
impl SystemTlsa {
    pub fn from_nameserver(nameserver: std::net::SocketAddr) -> Self {
        Self { nameserver }
    }
    pub fn new() -> Self {
        let nameserver = std::fs::read_to_string("/etc/resolv.conf")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    let mut fields = line.split_whitespace();
                    if fields.next() != Some("nameserver") {
                        return None;
                    }
                    fields.next()?.parse::<std::net::IpAddr>().ok()
                })
            })
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        Self::from_nameserver(std::net::SocketAddr::new(nameserver, 53))
    }
}
impl Default for SystemTlsa {
    fn default() -> Self {
        Self::new()
    }
}
impl TlsaLookup for SystemTlsa {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<TlsaAnswer, String>> {
        use futures_util::StreamExt;
        use hickory_net::{
            runtime::TokioRuntimeProvider, udp::UdpClientStream, xfer::DnsRequestSender,
        };
        use hickory_resolver::proto::{
            op::{DnsRequest, DnsRequestOptions, Query},
            rr::{Name, RData, RecordType},
        };
        Box::pin(async move {
            let name = Name::from_ascii(format!(
                "_25._tcp.{}.",
                host.strip_suffix('.').unwrap_or(host)
            ))
            .map_err(|e| e.to_string())?;
            let mut options = DnsRequestOptions::default();
            options.edns_payload_len = 1232;
            options.edns_set_dnssec_ok = true;
            let request = DnsRequest::from_query(Query::query(name, RecordType::TLSA), options);
            let mut client =
                UdpClientStream::builder(self.nameserver, TokioRuntimeProvider::default())
                    .with_max_retries(0)
                    .with_timeout(Some(std::time::Duration::from_secs(5)))
                    .build();
            let response = client
                .send_message(request)
                .next()
                .await
                .ok_or("TLSA lookup: nil response")?
                .map_err(|e| e.to_string())?;
            Ok(TlsaAnswer {
                authenticated: response.metadata.authentic_data,
                rcode: response.metadata.response_code.into(),
                records: response
                    .answers
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::TLSA(t) => Some(TlsaRecord {
                            usage: t.cert_usage.into(),
                            selector: t.selector.into(),
                            matching: t.matching.into(),
                            association: t.cert_data.clone(),
                        }),
                        _ => None,
                    })
                    .collect(),
            })
        })
    }
}
