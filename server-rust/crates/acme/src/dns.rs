//! Frozen Go's DNS provider settings and API mutations. The zero propagation timeout in
//! dns_providers.go is intentionally preserved: successful Present is followed by CleanUp,
//! and the managed attempt fails before notifying the CA (ARCH-029).
use base64::Engine;
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        rdata::{tsig::TsigAlgorithm, TXT},
        DNSClass, Name, RData, Record, RecordType, TSigner,
    },
};
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    TokioResolver,
};
type AwsSigner = reqsign_core::Signer<reqsign_aws_v4::Credential>;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Test endpoints replace external peripherals only; production uses provider defaults.
#[derive(Default, Clone)]
pub struct Endpoints {
    pub cloudflare: Option<String>,
    pub route53: Option<String>,
}
#[derive(Clone)]
pub struct Provider(Arc<Inner>);
struct Inner {
    kind: Kind,
    resolver: TokioResolver,
    http: reqwest::Client,
    endpoints: Endpoints,
    zones: Mutex<HashMap<String, String>>,
}
enum Kind {
    Cloudflare(String),
    Route53 {
        signer: AwsSigner,
        api: String,
    },
    Rfc2136 {
        server: String,
        signer: Option<TsigKey>,
    },
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Credentials {
    #[serde(rename = "CF_API_TOKEN")]
    cf_token: String,
    #[serde(rename = "AWS_ACCESS_KEY_ID")]
    aws_id: String,
    #[serde(rename = "AWS_SECRET_ACCESS_KEY")]
    aws_secret: String,
    #[serde(rename = "AWS_REGION")]
    aws_region: String,
    #[serde(rename = "RFC2136_NAMESERVER")]
    server: String,
    #[serde(rename = "RFC2136_TSIG_KEY")]
    key: String,
    #[serde(rename = "RFC2136_TSIG_SECRET")]
    secret: String,
    #[serde(rename = "RFC2136_TSIG_ALGORITHM")]
    algorithm: String,
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn fqdn(s: &str) -> String {
    format!("{}.", s.trim_end_matches('.'))
}
fn endpoint(s: &str) -> String {
    if s.parse::<SocketAddr>().is_ok() {
        s.into()
    } else if s.starts_with('[') {
        format!("{s}:53")
    } else if s.contains(':') {
        s.into()
    } else {
        format!("{s}:53")
    }
}
impl Provider {
    pub fn new(provider: &str, config: &str, resolvers: &[String]) -> Result<Self, String> {
        Self::with_endpoints(provider, config, resolvers, Endpoints::default())
    }
    pub fn with_endpoints(
        provider: &str,
        config: &str,
        resolvers: &[String],
        endpoints: Endpoints,
    ) -> Result<Self, String> {
        if !["cloudflare", "route53", "rfc2136"].contains(&provider) {
            return Err(format!(
                "unknown DNS provider: {provider:?} (supported: cloudflare, route53, rfc2136)"
            ));
        }
        let c: Credentials =
            serde_json::from_str(config).map_err(|e| format!("{provider} config: {e}"))?;
        let kind = match provider {
            "cloudflare" => {
                if c.cf_token.is_empty() {
                    return Err("cloudflare: CF_API_TOKEN is required".into());
                }
                Kind::Cloudflare(c.cf_token)
            }
            "route53" => {
                let io = AwsIo(
                    reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .build()
                        .map_err(err)?,
                );
                let ctx = reqsign_core::Context::new()
                    .with_env(reqsign_core::OsEnv)
                    .with_file_read(io.clone())
                    .with_http_send(io.clone())
                    .with_command_execute(io);
                let region = if c.aws_region.is_empty() {
                    "us-east-1"
                } else {
                    &c.aws_region
                };
                let override_url = endpoints
                    .route53
                    .clone()
                    .or_else(|| {
                        std::env::var("AWS_ENDPOINT_URL_ROUTE_53")
                            .ok()
                            .filter(|s| !s.is_empty())
                    })
                    .or_else(|| {
                        std::env::var("AWS_ENDPOINT_URL")
                            .ok()
                            .filter(|s| !s.is_empty())
                    });
                let (api, signing_region) = match override_url {
                    Some(url) => (url, region.to_owned()),
                    None => route53_default_target(region),
                };
                let builder = reqsign_aws_v4::RequestSigner::new("route53", &signing_region);
                let signer = if !c.aws_id.is_empty() && !c.aws_secret.is_empty() {
                    AwsSigner::new(
                        ctx,
                        reqsign_aws_v4::StaticCredentialProvider::new(&c.aws_id, &c.aws_secret),
                        builder,
                    )
                } else {
                    AwsSigner::new(
                        ctx,
                        reqsign_aws_v4::DefaultCredentialProvider::new(),
                        builder,
                    )
                };
                Kind::Route53 { signer, api }
            }
            _ => {
                if c.server.is_empty() {
                    return Err("dnsupdate: nameserver missing".into());
                }
                let algorithm = match c.algorithm.trim_end_matches('.') {
                    "" | "hmac-sha256" => TsigAlgorithm::HmacSha256,
                    "hmac-sha1" => TsigAlgorithm::HmacSha1,
                    "hmac-sha224" => TsigAlgorithm::HmacSha224,
                    "hmac-sha384" => TsigAlgorithm::HmacSha384,
                    "hmac-sha512" => TsigAlgorithm::HmacSha512,
                    _ => {
                        return Err(format!(
                            "dnsupdate: unsupported TSIG algorithm: {}",
                            fqdn(&c.algorithm)
                        ))
                    }
                };
                let signer = if c.key.is_empty() || c.secret.is_empty() {
                    None
                } else {
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(c.secret)
                        .map_err(err)?;
                    let name = Name::from_ascii(fqdn(&c.key.to_lowercase())).map_err(err)?;
                    Some(match algorithm {
                        TsigAlgorithm::HmacSha1 | TsigAlgorithm::HmacSha224 => {
                            TsigKey::Legacy(LegacyTsig {
                                key: openssl::pkey::PKey::hmac(&secret).map_err(err)?,
                                algorithm,
                                name,
                            })
                        }
                        _ => TsigKey::Standard(
                            TSigner::new(secret, algorithm, name, 300).map_err(err)?,
                        ),
                    })
                };
                Kind::Rfc2136 {
                    server: endpoint(&c.server),
                    signer,
                }
            }
        };
        let resolver = if resolvers.is_empty() {
            TokioResolver::builder_tokio()
                .map_err(err)?
                .build()
                .map_err(err)?
        } else {
            let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
            for s in resolvers {
                let address: SocketAddr = endpoint(s).parse().map_err(err)?;
                let mut ns = NameServerConfig::udp_and_tcp(address.ip());
                for conn in &mut ns.connections {
                    conn.port = address.port();
                }
                config.add_name_server(ns);
            }
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()
                .map_err(err)?
        };
        Ok(Self(Arc::new(Inner {
            kind,
            resolver,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(err)?,
            endpoints,
            zones: Mutex::new(HashMap::new()),
        })))
    }
    /// The effective challenge FQDN follows CNAMEs, as lego's GetChallengeInfo does.
    pub async fn record(&self, domain: &str, value: String) -> Result<RecordSpec, String> {
        let mut name = fqdn(&format!(
            "_acme-challenge.{}",
            domain.strip_prefix("*.").unwrap_or(domain)
        ));
        let mut seen = std::collections::HashSet::new();
        while seen.insert(name.clone()) {
            let Ok(answer) = self
                .0
                .resolver
                .lookup(name.as_str(), RecordType::CNAME)
                .await
            else {
                break;
            };
            let next = answer.answers().iter().find_map(|rr| {
                if let RData::CNAME(n) = &rr.data {
                    Some(n.0.to_utf8())
                } else {
                    None
                }
            });
            match next {
                Some(n) if n != name => name = n,
                _ => break,
            }
            if seen.len() > 50 {
                return Err("DNS CNAME chain too long".into());
            }
        }
        Ok(RecordSpec { name, value })
    }
    async fn zone(&self, name: &str) -> Result<String, String> {
        let mut current = Name::from_ascii(name).map_err(err)?;
        loop {
            if let Ok(result) = self
                .0
                .resolver
                .lookup(current.clone(), RecordType::SOA)
                .await
            {
                if let Some(rr) = result
                    .answers()
                    .iter()
                    .find(|rr| matches!(rr.data, RData::SOA(_)))
                {
                    return Ok(rr.name.to_utf8());
                }
            }
            if current.is_root() {
                return Err(format!("could not find zone for {name}"));
            }
            current = current.base_name();
        }
    }
    pub async fn present(&self, record: &RecordSpec) -> Result<(), String> {
        self.change(record, false).await
    }
    pub async fn clean_up(&self, record: &RecordSpec) -> Result<(), String> {
        self.change(record, true).await
    }
    pub(crate) fn sequential(&self) -> bool {
        matches!(&self.0.kind, Kind::Rfc2136 { .. })
    }
    async fn change(&self, r: &RecordSpec, remove: bool) -> Result<(), String> {
        match &self.0.kind {
            Kind::Cloudflare(token) => self.cloudflare(token, r, remove).await,
            Kind::Route53 { signer, api } => self.route53(signer, api, r, remove).await,
            Kind::Rfc2136 { server, signer } => {
                self.rfc2136(server, signer.as_ref(), r, remove).await
            }
        }
    }
    async fn cf_request(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let api = self
            .0
            .endpoints
            .cloudflare
            .as_deref()
            .unwrap_or("https://api.cloudflare.com/client/v4");
        let mut request = self
            .0
            .http
            .request(method, format!("{api}{path}"))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body)
        }
        let response: Value = request
            .send()
            .await
            .map_err(err)?
            .error_for_status()
            .map_err(err)?
            .json()
            .await
            .map_err(err)?;
        if response["success"] != true {
            return Err(format!("cloudflare: API error: {}", response["errors"]));
        }
        Ok(response["result"].clone())
    }
    async fn cloudflare(&self, token: &str, r: &RecordSpec, remove: bool) -> Result<(), String> {
        let zone = self.zone(&r.name).await?;
        let cached = self.0.zones.lock().unwrap().get(&zone).cloned();
        let id = match cached {
            Some(id) => id,
            None => {
                let result = self
                    .cf_request(
                        token,
                        reqwest::Method::GET,
                        &format!("/zones?name={}", zone.trim_end_matches('.')),
                        None,
                    )
                    .await?;
                let id = result[0]["id"]
                    .as_str()
                    .ok_or("cloudflare: zone not found")?
                    .to_owned();
                self.0.zones.lock().unwrap().insert(zone, id.clone());
                id
            }
        };
        let slot = format!("record:{}:{}", r.name, r.value);
        if remove {
            let record_id = self
                .0
                .zones
                .lock()
                .unwrap()
                .remove(&slot)
                .ok_or("cloudflare: no record ID")?;
            self.cf_request(
                token,
                reqwest::Method::DELETE,
                &format!("/zones/{id}/dns_records/{record_id}"),
                None,
            )
            .await?;
        } else {
            let record=self.cf_request(token,reqwest::Method::POST,&format!("/zones/{id}/dns_records"),Some(json!({"type":"TXT","name":r.name.trim_end_matches('.'),"content":format!("\"{}\"",r.value),"ttl":120}))).await?;
            let id = record["id"]
                .as_str()
                .ok_or("cloudflare: no record ID")?
                .to_owned();
            self.0.zones.lock().unwrap().insert(slot, id);
        }
        Ok(())
    }
    async fn aws(
        &self,
        signer: &AwsSigner,
        api: &str,
        method: &str,
        path: &str,
        body: String,
    ) -> Result<String, String> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("{api}{path}"));
        if !body.is_empty() {
            builder = builder.header("content-type", "application/xml");
        }
        let mut parts = builder
            .header(
                "x-amz-content-sha256",
                format!("{:x}", Sha256::digest(body.as_bytes())),
            )
            .body(())
            .map_err(err)?
            .into_parts()
            .0;
        signer.sign(&mut parts, None).await.map_err(err)?;
        self.0
            .http
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(err)?
            .error_for_status()
            .map_err(err)?
            .text()
            .await
            .map_err(err)
    }
    async fn route53(
        &self,
        signer: &AwsSigner,
        api: &str,
        r: &RecordSpec,
        remove: bool,
    ) -> Result<(), String> {
        let zone = self.zone(&r.name).await?;
        let zones = self
            .aws(
                signer,
                api,
                "GET",
                &format!(
                    "/2013-04-01/hostedzonesbyname?dnsname={}",
                    zone.trim_end_matches('.')
                ),
                String::new(),
            )
            .await?;
        let zones: Zones = quick_xml::de::from_str(&zones).map_err(err)?;
        let id = zones
            .zones
            .items
            .iter()
            .find(|z| z.name == zone && !z.config.private)
            .ok_or("route53: zone not found")?
            .id
            .trim_start_matches("/hostedzone/");
        let path = format!("/2013-04-01/hostedzone/{id}/rrset");
        let existing = self
            .aws(
                signer,
                api,
                "GET",
                &format!("{path}?name={}&type=TXT", r.name),
                String::new(),
            )
            .await?;
        let sets: Sets = quick_xml::de::from_str(&existing).map_err(err)?;
        let old = sets
            .sets
            .items
            .into_iter()
            .find(|s| s.name == r.name && s.kind == "TXT")
            .map(|s| {
                s.records
                    .items
                    .into_iter()
                    .map(|v| v.value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let quoted = format!("\"{}\"", r.value);
        let mut values = old.clone();
        let action = if remove {
            if old.is_empty() {
                return Ok(());
            }
            values.retain(|v| v != &quoted);
            if values.is_empty() {
                values = old;
                "DELETE"
            } else {
                "UPSERT"
            }
        } else {
            if !values.contains(&quoted) {
                values.push(quoted)
            }
            "UPSERT"
        };
        let escape = quick_xml::escape::escape;
        let rr = values
            .iter()
            .map(|v| {
                format!(
                    "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                    escape(v)
                )
            })
            .collect::<String>();
        let body=format!("<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Comment>Managed by Lego</Comment><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{}</Name><Type>TXT</Type><TTL>0</TTL><ResourceRecords>{rr}</ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>",escape(&r.name));
        self.aws(signer, api, "POST", &path, body).await?;
        Ok(())
    }
    async fn rfc2136(
        &self,
        server: &str,
        signer: Option<&TsigKey>,
        r: &RecordSpec,
        remove: bool,
    ) -> Result<(), String> {
        let zone = Name::from_ascii(self.zone(&r.name).await?).map_err(err)?;
        let name = Name::from_ascii(&r.name).map_err(err)?;
        let mut message = Message::query();
        message.metadata.op_code = OpCode::Update;
        message.metadata.recursion_desired = false;
        message.add_query(Query::query(zone, RecordType::SOA));
        let mut record =
            Record::from_rdata(name.clone(), 0, RData::TXT(TXT::new(vec![r.value.clone()])));
        if remove {
            record.dns_class = DNSClass::NONE;
        } else {
            let mut clear = Record::update0(name, 0, RecordType::TXT);
            clear.dns_class = DNSClass::ANY;
            message.add_authority(clear);
        }
        message.add_authority(record);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(err)?
            .as_secs();
        let mut verifier = signer.map(|key| key.sign(&mut message, now)).transpose()?;
        let packet = message.to_vec().map_err(err)?;
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let remote = tokio::net::lookup_host(server)
                .await
                .map_err(err)?
                .next()
                .ok_or("dnsupdate: nameserver unresolved")?;
            let socket = tokio::net::UdpSocket::bind(if remote.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            })
            .await
            .map_err(err)?;
            socket.connect(remote).await.map_err(err)?;
            socket.send(&packet).await.map_err(err)?;
            let mut data = vec![0; 65535];
            let n = socket.recv(&mut data).await.map_err(err)?;
            data.truncate(n);
            let answer = Message::from_vec(&data).map_err(err)?;
            if answer.metadata.id != message.metadata.id
                || answer.metadata.op_code != OpCode::Update
            {
                return Err("dnsupdate: mismatched response".into());
            }
            if let Some(verifier) = &mut verifier {
                verifier(&data)?;
            }
            if answer.metadata.response_code != ResponseCode::NoError {
                return Err(format!(
                    "dnsupdate: server replied {}",
                    answer.metadata.response_code
                ));
            }
            Ok(())
        })
        .await
        .map_err(err)?;
        result
    }
}
#[derive(Clone)]
pub struct RecordSpec {
    pub name: String,
    pub value: String,
}
#[derive(Deserialize)]
struct Zones {
    #[serde(rename = "HostedZones")]
    zones: ZoneList,
}
#[derive(Deserialize)]
struct ZoneList {
    #[serde(rename = "HostedZone", default)]
    items: Vec<Zone>,
}
#[derive(Deserialize)]
struct Zone {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Config")]
    config: ZoneConfig,
}
#[derive(Deserialize)]
struct ZoneConfig {
    #[serde(rename = "PrivateZone")]
    private: bool,
}
#[derive(Deserialize)]
struct Sets {
    #[serde(rename = "ResourceRecordSets")]
    sets: SetList,
}
#[derive(Deserialize)]
struct SetList {
    #[serde(rename = "ResourceRecordSet", default)]
    items: Vec<Set>,
}
#[derive(Deserialize)]
struct Set {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "ResourceRecords")]
    records: Values,
}
#[derive(Deserialize)]
struct Values {
    #[serde(rename = "ResourceRecord", default)]
    items: Vec<TxtValue>,
}
#[derive(Deserialize)]
struct TxtValue {
    #[serde(rename = "Value")]
    value: String,
}

// Runtime adapters for reqsign's standard AWS credential chain (env, profiles,
// web identity, ECS/IMDS and credential_process). The crate owns resolution,
// cache/expiry and signing; no credential parser or signing primitive lives here.
#[derive(Clone, Debug)]
struct AwsIo(reqwest::Client);
impl reqsign_core::FileRead for AwsIo {
    async fn file_read(&self, path: &str) -> reqsign_core::Result<Vec<u8>> {
        tokio::fs::read(path)
            .await
            .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))
    }
}
impl reqsign_core::HttpSend for AwsIo {
    async fn http_send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> reqsign_core::Result<http::Response<bytes::Bytes>> {
        let (parts, body) = request.into_parts();
        let response = self
            .0
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))?;
        let mut builder = http::Response::builder().status(response.status());
        for (key, value) in response.headers() {
            builder = builder.header(key, value);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))?;
        builder
            .body(bytes)
            .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))
    }
}
impl reqsign_core::CommandExecute for AwsIo {
    async fn command_execute<'a>(
        &'a self,
        program: &'a str,
        args: &'a [&'a str],
    ) -> reqsign_core::Result<reqsign_core::CommandOutput> {
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(program)
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))?
        .map_err(|e| reqsign_core::Error::unexpected(e.to_string()))?;
        Ok(reqsign_core::CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

// Hickory handles TSIG framing and SHA256/384/512 exchanges. Go also accepts
// SHA1/SHA224; Hickory intentionally omits these MAC backends. Their wire
// encoding still comes from Hickory, with OpenSSL HMAC/constant-time verification.
enum TsigKey {
    Standard(TSigner),
    Legacy(LegacyTsig),
}
#[derive(Clone)]
struct LegacyTsig {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    algorithm: TsigAlgorithm,
    name: Name,
}
type Verify = Box<dyn FnMut(&[u8]) -> Result<(), String> + Send>;
impl LegacyTsig {
    fn mac(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let digest = match self.algorithm {
            TsigAlgorithm::HmacSha1 => openssl::hash::MessageDigest::sha1(),
            TsigAlgorithm::HmacSha224 => openssl::hash::MessageDigest::sha224(),
            _ => return Err("unexpected TSIG MAC algorithm".into()),
        };
        let mut mac = openssl::sign::Signer::new(digest, &self.key).map_err(err)?;
        mac.update(data).map_err(err)?;
        mac.sign_to_vec().map_err(err)
    }
}
impl TsigKey {
    fn sign(&self, message: &mut Message, now: u64) -> Result<Verify, String> {
        use hickory_proto::rr::rdata::tsig::{
            make_tsig_record, message_tbs, signed_bitmessage_to_buf, TSIG,
        };
        match self {
            Self::Standard(signer) => {
                let (sig, verifier) = signer.sign_message(message, now).map_err(err)?;
                message.set_signature(sig);
                let mut verifier = verifier.ok_or("missing TSIG verifier")?;
                Ok(Box::new(move |bytes| {
                    verifier.verify(bytes).map(|_| ()).map_err(err)
                }))
            }
            Self::Legacy(key) => {
                let id = message.metadata.id;
                let mut sig = TSIG::new(key.algorithm.clone(), now, 300, vec![], id, None, vec![]);
                let tag = key.mac(&message_tbs(message, &sig, &key.name).map_err(err)?)?;
                sig.mac = tag.clone();
                message.set_signature(Box::new(make_tsig_record(key.name.clone(), sig)));
                let key = key.clone();
                Ok(Box::new(move |bytes| {
                    let (tbs, response) =
                        signed_bitmessage_to_buf(bytes, Some(&tag), true).map_err(err)?;
                    let clock = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(err)?
                        .as_secs();
                    if response.name != key.name
                        || response.data.algorithm != key.algorithm
                        || response.data.oid != id
                        || response.data.error.is_some()
                        || response.data.time.abs_diff(clock) > u64::from(response.data.fudge)
                    {
                        return Err("invalid TSIG response metadata".into());
                    }
                    let expected = key.mac(&tbs)?;
                    if expected.len() != response.data.mac.len()
                        || !openssl::memcmp::eq(&expected, &response.data.mac)
                    {
                        return Err("invalid TSIG response MAC".into());
                    }
                    Ok(())
                }))
            }
        }
    }
}

/// Route53 is a global service; its default endpoint/signing region is SDK-defined.
pub fn route53_default_target(region: &str) -> (String, String) {
    let (endpoint, signing) = if region.starts_with("cn-") {
        ("https://route53.amazonaws.com.cn", "cn-northwest-1")
    } else if region.starts_with("us-gov-") {
        ("https://route53.us-gov.amazonaws.com", "us-gov-west-1")
    } else if region.starts_with("us-isob-") {
        ("https://route53.sc2s.sgov.gov", "us-isob-east-1")
    } else if region.starts_with("us-isof-") {
        ("https://route53.csp.hci.ic.gov", "us-isof-south-1")
    } else if region.starts_with("us-iso-") {
        ("https://route53.c2s.ic.gov", "us-iso-east-1")
    } else if region.starts_with("eu-isoe-") {
        ("https://route53.cloud.adc-e.uk", "eu-isoe-west-1")
    } else if region.starts_with("eusc-") {
        ("https://route53.amazonaws.eu", "eusc-de-east-1")
    } else {
        ("https://route53.amazonaws.com", "us-east-1")
    };
    (endpoint.into(), signing.into())
}
