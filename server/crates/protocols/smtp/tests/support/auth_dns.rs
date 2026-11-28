use futures_util::future::BoxFuture;
use setjoin_smtp::mail_auth::{Dns, DnsError, DnsType};
pub struct FixtureDns(pub serde_json::Value);
impl Dns for FixtureDns {
    fn lookup<'a>(
        &'a self,
        kind: DnsType,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            let kind = match kind {
                DnsType::Txt => "txt",
                DnsType::Ip => "ip",
                DnsType::Mx => "mx",
                DnsType::Ptr => "ptr",
            };
            let value = &self.0[format!("{kind}:{name}")];
            if let Some(values) = value.as_array() {
                Ok(values
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect())
            } else if value.is_null() || value == "nxdomain" {
                Err(DnsError::NotFound)
            } else {
                Err(DnsError::Temporary)
            }
        })
    }
}
