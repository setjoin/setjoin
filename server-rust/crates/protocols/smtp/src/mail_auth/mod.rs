//! Frozen-Go mail authentication policy over injectable DNS and audited crypto.
mod bridge;
mod dkim;
mod dmarc;
mod dns;
pub use dkim::DkimVerification;
mod signing;
mod spf;
pub use dns::{Dns, DnsError, DnsType, SystemDns};
pub use signing::{load_signer, outbound_data_frame, sign_outbound, Loaded};
use std::sync::Arc;

#[derive(Clone, Copy, Default)]
pub struct Features {
    pub spf: bool,
    pub dkim: bool,
    pub dmarc: bool,
    pub arc: bool,
}
#[derive(Clone)]
pub struct MailAuth {
    pub(crate) dns: Arc<dyn Dns>,
    pub(crate) features: Features,
}
pub(crate) fn relaxed_aligned(child: &str,parent: &str)->bool { dmarc::relaxed_aligned(child,parent) }
impl MailAuth {
    /// The same DNS with the live per-session feature switches.
    pub fn with_features(mut self, features: Features) -> Self {
        self.features = features;
        self
    }
    pub(crate) async fn delivery_dmarc(
        &self,
        db: &setjoin_pg::workers::WorkerDatabase,
        from: &str,
        message_id: &str,
        spf: &str,
        envelope: &str,
        dkim: &DkimVerification,
    ) -> dmarc::Outcome {
        if !self.features.dmarc {
            return Default::default();
        }
        let domain = from.rsplit_once('@').map_or("", |(_, d)| d);
        let spf_domain = envelope.rsplit_once('@').map_or("", |(_, d)| d);
        dmarc::check(
            self.dns.as_ref(),
            db,
            domain,
            message_id,
            spf,
            spf_domain,
            dkim,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn delivery_arc(
        &self,
        db: &setjoin_pg::workers::WorkerDatabase,
        raw: &[u8],
        from: &str,
        envelope: &str,
        spf: &str,
        dmarc: &str,
        helo: &str,
        ip: &str,
        recipient: &str,
    ) -> Option<Vec<u8>> {
        if !self.features.arc || !self.features.dmarc {
            return None;
        }
        let domain = from.rsplit_once('@').map_or("", |(_, d)| d);
        signing::seal_inbound(
            self.dns.as_ref(),
            db,
            raw,
            &signing::ArcInputs {
                ip,
                helo,
                mail_from: envelope,
                spf,
                dmarc,
                from_domain: domain,
                seal_domain: recipient.rsplit_once('@').map_or("", |(_, d)| d),
            },
        )
        .await
    }
    pub async fn verify_dkim(&self, raw: &[u8]) -> DkimVerification {
        dkim::verify(self.dns.as_ref(), raw).await
    }
    pub(crate) async fn delivery_dkim(&self, raw: &[u8]) -> DkimVerification {
        if self.features.dkim {
            self.verify_dkim(raw).await
        } else {
            DkimVerification::default()
        }
    }
    pub fn new(features: Features, dns: Arc<dyn Dns>) -> Self {
        Self { features, dns }
    }
    pub async fn check_spf(
        &self,
        domain: &str,
        ip: &str,
        sender: &str,
        helo: &str,
    ) -> &'static str {
        spf::check(self.dns.as_ref(), domain, ip, sender, helo).await
    }
    pub(crate) async fn mail_from(&self, sender: &[u8], helo: &str, ip: &str) -> &'static str {
        if !self.features.spf {
            return "none";
        }
        let sender = setjoin_mime::go_lossy(sender);
        let domain = if sender.is_empty() || sender == "<>" {
            helo
        } else {
            sender.rsplit_once('@').map_or("", |(_, d)| d)
        };
        self.check_spf(domain, ip, &sender, helo).await
    }
}
