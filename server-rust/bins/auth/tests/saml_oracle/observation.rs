//! Mechanical route qualification of immutable Go wire/effect observations.
use super::*;
use setjoin_conformance::golden;
pub(super) fn qualified(actual: &Value) -> Vec<Value> {
    let route = actual["route"].as_str().unwrap();
    let mut values = vec![actual.clone()];
    if let Some(command) = match route {
        "GET /auth/saml/{idp}/login" => Some("login"),
        "GET /auth/saml/{idp}/metadata" => Some("metadata"),
        "POST /auth/saml/{idp}/acs" => Some("acs"),
        "POST /auth/saml/{idp}/link" => Some("link"),
        _ => None,
    } {
        let mut alias = actual.clone();
        alias["route"] = json!(format!("* /auth/saml/ {command}"));
        values.push(alias);
    }
    for value in &mut values {
        let route = value["route"].as_str().unwrap().to_owned();
        let parts = route.split(' ').collect::<Vec<_>>();
        let r = &mut value["observation"]["request"];
        if r.get("wire_method").is_none() {
            r["wire_method"] = r["method"].clone();
        }
        if r.get("wire_path").is_none() {
            r["wire_path"] = r["path"].clone();
        }
        r["method"] = json!(parts[0]);
        r["path"] = json!(parts[1]);
    }
    values
}
pub(super) fn name(value: &Value) -> String {
    let group = match value["route"].as_str().unwrap() {
        "GET /auth/saml/{idp}/login" => "login",
        "GET /auth/saml/{idp}/metadata" => "metadata",
        "POST /auth/saml/{idp}/acs" => "acs",
        "POST /auth/saml/{idp}/link" => "link",
        "GET /auth/saml/{idp}/link" => "alias",
        "GET /auth/identity-links" => "list",
        "DELETE /auth/identity-links/{id}" => "unlink",
        "* /auth/saml/ login" => "gateway-login",
        "* /auth/saml/ metadata" => "gateway-metadata",
        "* /auth/saml/ acs" => "gateway-acs",
        "* /auth/saml/ link" => "gateway-link",
        "* /auth/saml/ mux" => "gateway-mux",
        _ => panic!("unknown SAML qualification route"),
    };
    format!("{group}--{}", value["case"].as_str().unwrap())
}
pub(super) fn compare(actual: &Value, mutant: bool) -> Result<(), Err> {
    if mutant && actual["observation"]["response"]["status"] != 599 {
        return Err("status mutant did not reach the native HTTP handler".into());
    }
    for value in qualified(actual) {
        let stem = name(&value);
        let path = corpus().join("qualified").join(format!("{stem}.json"));
        let expected = expected_for(&path, &value)?;
        let route = value["route"].as_str().unwrap();
        let case = value["case"].as_str().unwrap();
        if mutant {
            let error =
                golden::compare(&expected, &value).expect_err("qualified status mutant survived");
            if !error.contains("/observation/response/status") {
                return Err(error.into());
            }
            println!("MUTANT-REJECTED: {route} :: status");
        } else {
            golden::compare(&expected, &value)?;
            let companion = json!({"format":1,"go_source":SOURCE,"route":route,"case":format!("{case}-row-effects"),"effects":[{"table":"saml_projection","snapshot":value["observation"]["effects"],"identity":value["observation"].get("identity"),"mapping":value["observation"].get("mapping")} ]});
            let path = corpus().join("qualified").join(format!("{stem}-rows.json"));
            let expected = expected_for(&path, &companion)?;
            golden::compare(&expected, &companion)?;
            println!("GOLDEN-REPLAY: {route} :: {case}");
        }
    }
    Ok(())
}
pub(super) fn replay(actual: &Value, recording: bool) -> Result<(), Err> {
    if !recording {
        compare(actual, false)?;
    }
    Ok(())
}

/// The document a replay compares with: the frozen-Go capture, unless the family's
/// `divergences.json` pins that baseline (by sha256) to an authored expectation under
/// `feature/` for the owner-approved verified ACS (#546, decision 2026-11-08 on #534):
/// the ACS answers instead of 404, and login now advertises the working ACS URL.
/// `SAMLACS_WRITE_FEATURE=1` rewrites the expectations (and pinned hashes) from the
/// actual run, for review.
pub(super) fn expected_for(baseline: &std::path::Path, actual: &Value) -> Result<Value, Err> {
    use sha2::{Digest, Sha256};
    let family = corpus();
    let relative = baseline.strip_prefix(&family)?.to_str().unwrap().to_owned();
    let list = family.join("divergences.json");
    let mut entries: Vec<Value> = if list.exists() {
        serde_json::from_slice(&std::fs::read(&list)?)?
    } else {
        Vec::new()
    };
    let base: Value = serde_json::from_slice(&std::fs::read(baseline)?)?;
    let name = baseline.file_name().unwrap().to_str().unwrap().to_owned();
    let expectation = family.join("feature").join(&name);
    let hash = format!("{:x}", Sha256::digest(std::fs::read(baseline)?));
    // A status-mutant run (599) is never a candidate expectation.
    let mutant_run = actual["observation"]["response"]["status"] == 599;
    // `SAMLACS_WRITE_ONLY=<text>` limits regeneration to baselines whose path contains it: each
    // regenerating call now fails right after writing, so a multi-case test is regenerated one
    // case per run.
    let only = std::env::var("SAMLACS_WRITE_ONLY").unwrap_or_default();
    if std::env::var("SAMLACS_WRITE_FEATURE").as_deref() == Ok("1")
        && !mutant_run
        && relative.contains(&only)
        && (golden::compare(&base, actual).is_err()
            || entries.iter().any(|e| e["baseline"] == relative))
    {
        REGENERATED.store(true, std::sync::atomic::Ordering::SeqCst);
        std::fs::create_dir_all(expectation.parent().unwrap())?;
        std::fs::write(&expectation, serde_json::to_string_pretty(actual)? + "\n")?;
        let reason = if relative.contains("acs") {
            "owner-approved feature 2026-11-08 (#534): the verified SAML ACS replaces the frozen middleware path mismatch. Go answered every ACS POST with a text/plain 404 followed by a 401 problem and never reached verification; a message that fails verification is now a 401 problem (nothing is written but an audit row)."
        } else {
            "owner-approved feature 2026-11-08 (#534): login advertises the working ACS URL (/auth/saml/{idp}/acs) in the AuthnRequest and scopes the tracking cookie to it, where Go advertised the unmounted /saml/acs; the AuthnRequest no longer asks for a transient NameID, which cannot key a link; the tracking cookie is SameSite=None; Secure and its signed claims add purpose, registration and link flow."
        };
        match entries.iter_mut().find(|e| e["baseline"] == relative) {
            Some(e) => e["sha256"] = json!(hash),
            None => entries.push(json!({"baseline":relative,"sha256":hash,"expectation":format!("feature/{name}"),"reason":reason,"reviewer":"diff reviewed by the #546 implementer; owner decision 2026-11-08 (#534); Opus review before merge (#546)","reviewed":true})),
        }
        entries.sort_by(|a, b| a["baseline"].as_str().cmp(&b["baseline"].as_str()));
        std::fs::write(&list, serde_json::to_string_pretty(&entries)? + "\n")?;
        // A regenerating run never passes, and fails here, right after writing, so no caller can
        // go on to compare the freshly written expectation with itself and report success.
        return Err("expectations regenerated (SAMLACS_WRITE_FEATURE): review the diff and rerun without it".into());
    }
    let Some(entry) = entries.iter().find(|e| e["baseline"] == relative) else {
        return Ok(base);
    };
    assert_eq!(entry["reviewed"], true);
    let reason = entry["reason"].as_str().unwrap();
    assert!(reason.contains("owner-approved feature 2026-11-08 (#534)"));
    assert_eq!(entry["sha256"], hash, "{relative}: the Go capture changed");
    Ok(serde_json::from_slice(&std::fs::read(
        family.join(entry["expectation"].as_str().unwrap()),
    )?)?)
}

/// `SAMLACS_WRITE_FEATURE=1` rewrites expectations instead of asserting them, so a run that
/// did so must never pass: the environment's `close` fails it ("review and rerun").
pub(super) static REGENERATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) fn regeneration_guard() {
    if REGENERATED.load(std::sync::atomic::Ordering::SeqCst) && !std::thread::panicking() {
        panic!("expectations regenerated (SAMLACS_WRITE_FEATURE): review the diff and rerun without it");
    }
}
