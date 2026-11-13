//! Country resolution from the same validated MMDB input as frozen Go.
use maxminddb::{geoip2, Reader};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub struct CountryDb(Reader<Vec<u8>>);
impl CountryDb {
    pub fn from_bytes(bytes: Vec<u8>, download_cache: bool, pin: &str) -> Result<Self, String> {
        if download_cache && pin.trim().is_empty() {
            return Err("download-cache path requires GEOIP_DB_SHA256".into());
        }
        if !pin.is_empty() && !format!("{:x}", Sha256::digest(&bytes)).eq_ignore_ascii_case(pin) {
            return Err("GeoIP SHA-256 digest mismatch".into());
        }
        let reader = Reader::from_source(bytes).map_err(|e| format!("invalid GeoIP MMDB: {e}"))?;
        if reader.metadata().database_type.trim().is_empty() {
            return Err("GeoIP database_type missing".into());
        }
        Ok(Self(reader))
    }
    /// The downloader/bootstrap owner may populate the default cache before
    /// this reader starts. An operator file is never fetched or replaced here.
    pub fn from_env() -> Option<Self> {
        let configured = std::env::var("GEOIP_DB_PATH").unwrap_or_default();
        let cache = configured.is_empty();
        let path = if cache {
            "/var/lib/setjoin/geoip.mmdb"
        } else {
            &configured
        };
        let pin = std::env::var("GEOIP_DB_SHA256").unwrap_or_default();
        let loaded = (|| {
            if cache && pin.trim().is_empty() {
                return Err("download-cache path requires GEOIP_DB_SHA256".to_owned());
            }
            let bytes = std::fs::read(path).map_err(|e| format!("read GeoIP MMDB: {e}"))?;
            Self::from_bytes(bytes, cache, &pin)
        })();
        match loaded {
            Ok(db) => Some(db),
            Err(error) => {
                eprintln!("geoip: country resolution NOT armed: {error}");
                None
            }
        }
    }
    pub fn country(&self, ip: IpAddr) -> String {
        self.0
            .lookup(ip)
            .ok()
            .and_then(|r| r.decode::<geoip2::Country>().ok().flatten())
            .and_then(|r| r.country.iso_code)
            .unwrap_or("")
            .to_owned()
    }
}
