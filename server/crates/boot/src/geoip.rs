//! The two Go path topologies retain their different integrity authority.
use crate::log;
use setjoin_authz::geoip::CountryDb;
use std::path::Path;

pub async fn ensure(
    path: &Path,
    cache: bool,
    pin: &str,
    block_countries: &str,
) -> Option<CountryDb> {
    if pin.is_empty() {
        log(
            "WARN",
            if cache {
                "geoip: no trusted digest authority configured (GEOIP_DB_SHA256 unset) — the download-cache path refuses to arm, and a file already at the default cache path is remote-channel input that does NOT arm without a pinned digest either; to supply a database under operator authority, configure GEOIP_DB_PATH explicitly"
            } else {
                "geoip: operator-provided database accepted without a digest pin (GEOIP_DB_SHA256 unset) — structural validation only, on the operator's own authority (residual risk recorded)"
            },
        );
    }
    let ensured = if cache && pin.is_empty() {
        Err("download-cache path requires GEOIP_DB_SHA256".into())
    } else if !cache || path.metadata().is_ok() {
        open(path, cache, pin).map(|_| ())
    } else {
        download(path, pin).await
    };
    match ensured {
        Ok(()) => log(
            "INFO",
            if cache {
                "geoip: cached database file present and matching the pinned digest"
            } else {
                "geoip: operator database file present"
            },
        ),
        Err(error) => {
            log("ERROR", "geoip: database unavailable — country resolution cannot arm (geo-block and country conditional-access conditions will not fire)");
            eprintln!("geoip input: {error}");
        }
    }
    // Re-read and validate exactly the bytes retained by the armed reader.
    match open(path, cache, pin) {
        Ok(reader) => {
            log("INFO", "geoip: country resolution armed");
            Some(reader)
        }
        Err(error) => {
            log("ERROR", "geoip: country resolution NOT armed — GEO_BLOCK_COUNTRIES and country conditional-access conditions cannot fire");
            eprintln!("geoip input: {error}");
            if block_countries.split(',').any(|s| !s.trim().is_empty()) {
                log("ERROR", "geoip: GEO_BLOCK_COUNTRIES is configured but non-enforcing without a valid database — supply a validated database at the path above or unset GEO_BLOCK_COUNTRIES to acknowledge the gap");
            }
            None
        }
    }
}

fn open(path: &Path, cache: bool, pin: &str) -> Result<CountryDb, String> {
    // Reject unpinned cache topology BEFORE reading it, including a planted file.
    if cache && pin.trim().is_empty() {
        return Err("download-cache path requires GEOIP_DB_SHA256".into());
    }
    CountryDb::from_bytes(std::fs::read(path).map_err(|e| e.to_string())?, cache, pin)
}

async fn download(path: &Path, pin: &str) -> Result<(), String> {
    use chrono::{Datelike, Days, Utc};
    use futures_util::StreamExt;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let parent = path.parent().ok_or("GeoIP path has no parent")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(parent)
        .map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                return attempt.error("geoip: stopped after 3 redirects");
            }
            if let Some(first) = attempt.previous().first() {
                if attempt.url().host_str() != first.host_str()
                    || attempt.url().port() != first.port()
                {
                    return attempt.error("geoip: refusing off-host redirect");
                }
            }
            attempt.follow()
        }))
        .build()
        .map_err(|e| e.to_string())?;
    let now = Utc::now().date_naive();
    // Go AddDate normalizes a day absent in the preceding month.
    let (year, month) = if now.month() == 1 {
        (now.year() - 1, 12)
    } else {
        (now.year(), now.month() - 1)
    };
    let previous = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap()
        + Days::new(u64::from(now.day() - 1));
    let mut last = "no download attempted".to_string();
    for date in [now, previous] {
        let attempt = async {
            let response = client
                .get(format!(
                    "https://download.db-ip.com/free/dbip-country-lite-{}-{:02}.mmdb",
                    date.year(),
                    date.month()
                ))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if response.status() != 200 {
                return Err(format!("unexpected status {}", response.status()));
            }
            let mut stream = response.bytes_stream();
            let mut bytes = Vec::new();
            const LIMIT: usize = 100 << 20;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| e.to_string())?;
                bytes.extend_from_slice(&chunk[..chunk.len().min(LIMIT - bytes.len())]);
                if bytes.len() == LIMIT {
                    break;
                }
            }
            CountryDb::from_bytes(bytes.clone(), true, pin)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())
        }
        .await;
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) => last = error,
        }
    }
    Err(last)
}
