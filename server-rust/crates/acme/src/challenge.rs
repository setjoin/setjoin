//! Pending RFC 8737 responses; no certificate issuance happens on the TLS serving path.
use crate::{keys::CertKey, normalize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
pub struct TlsAlpnStore(Arc<Mutex<HashMap<String, Arc<Vec<u8>>>>>);

/// Withdrawal is synchronous even if the renewal future is cancelled during validation.
pub struct PendingAlpn {
    store: TlsAlpnStore,
    name: String,
    blob: Arc<Vec<u8>>,
}
impl Drop for PendingAlpn {
    fn drop(&mut self) {
        let mut map = self.store.0.lock().unwrap();
        if map
            .get(&self.name)
            .is_some_and(|v| Arc::ptr_eq(v, &self.blob))
        {
            map.remove(&self.name);
        }
    }
}
impl TlsAlpnStore {
    pub fn get(&self, name: &str) -> Option<Arc<Vec<u8>>> {
        self.0.lock().unwrap().get(&normalize(name)).cloned()
    }
    pub fn present(&self, domain: &str, key_authorization: &str) -> Result<PendingAlpn, String> {
        let name = normalize(domain);
        let key = CertKey::generate()?;
        let mut params =
            rcgen::CertificateParams::new(vec![domain.to_owned()]).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ACME Challenge TEMP");
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        let now = x509_parser::time::ASN1Time::now().to_datetime();
        params.not_before = now;
        // Go time.AddDate normalizes Feb 29 to Mar 1 in a non-leap year.
        params.not_after = now.replace_year(now.year() + 1).unwrap_or_else(|_| {
            now.replace_day(1)
                .unwrap()
                .replace_month(now.month().next())
                .unwrap()
                .replace_year(now.year() + 1)
                .unwrap()
        });
        let mut serial = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut serial)
            .map_err(|e| e.to_string())?;
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        params
            .custom_extensions
            .push(rcgen::CustomExtension::new_acme_identifier(
                &Sha256::digest(key_authorization.as_bytes()),
            ));
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let blob = Arc::new(format!("{}{}", key.to_pem(), cert.pem()).into_bytes());
        self.0.lock().unwrap().insert(name.clone(), blob.clone());
        Ok(PendingAlpn {
            store: self.clone(),
            name,
            blob,
        })
    }
}
