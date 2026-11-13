//! Mechanical route qualification of immutable Go wire/effect observations.
use super::*;
use setjoin_conformance::golden;
pub(super) fn qualified(actual: &Value) -> Vec<Value> {
    let route = actual["route"].as_str().unwrap();
    let mut values = vec![actual.clone()];
    if let Some(command) = match route {
        "GET /auth/oidc/login" => Some("login"),
        "GET /auth/oidc/callback" => Some("callback"),
        "POST /auth/oidc/link" => Some("link"),
        _ => None,
    } {
        let mut alias = actual.clone();
        alias["route"] = json!(format!("* /auth/oidc/ {command}"));
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
        "GET /auth/oidc/login" => "login",
        "GET /auth/oidc/callback" => "callback",
        "POST /auth/oidc/link" => "link",
        "GET /auth/oidc/link" => "alias",
        "* /auth/oidc/ login" => "gateway-login",
        "* /auth/oidc/ callback" => "gateway-callback",
        "* /auth/oidc/ link" => "gateway-link",
        "* /auth/oidc/ mux" => "mux",
        _ => panic!("unknown RP qualification route"),
    };
    format!("{group}--{}", value["case"].as_str().unwrap())
}
pub(super) fn compare(actual: &Value, mutant: bool) -> Result<(), Err> {
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
            let companion = json!({"format":1,"go_source":SOURCE,"route":route,"case":format!("{case}-row-effects"),"effects":[{"table":"rp_projection","snapshot":value["observation"]["effects"],"identity":value["observation"].get("identity"),"mapping":value["observation"].get("mapping")} ]});
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

/// The reviewed document a replay compares with: the frozen-Go capture, unless the family's
/// `divergences.json` pins that baseline (by sha256) to an authored expectation under
/// `security/` for an owner-approved security fix (#530, #547). `SECFIX8_WRITE_SECURITY=1`
/// rewrites the expectations (and the pinned hashes) from the actual run, for review; a run that
/// did so never passes (`regeneration_guard`, called when the environment closes).
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
    let expectation = family.join("security").join(&name);
    let hash = format!("{:x}", Sha256::digest(std::fs::read(baseline)?));
    // `SECFIX8_WRITE_ONLY=<text>` limits regeneration to baselines whose path contains it, so a
    // multi-case test can be regenerated one case at a time (each such run fails by design).
    let only = std::env::var("SECFIX8_WRITE_ONLY").unwrap_or_default();
    let mut regenerated_now = false;
    if std::env::var("SECFIX8_WRITE_SECURITY").as_deref() == Ok("1")
        && relative.contains(&only)
        && (golden::compare(&base, actual).is_err() || entries.iter().any(|e| e["baseline"] == relative))
    {
        REGENERATED.store(true, std::sync::atomic::Ordering::SeqCst);
        regenerated_now = true;
        std::fs::create_dir_all(expectation.parent().unwrap())?;
        std::fs::write(&expectation, serde_json::to_string_pretty(actual)? + "\n")?;
        match entries.iter_mut().find(|e| e["baseline"] == relative) {
            Some(e) => e["sha256"] = json!(hash),
            None => entries.push(json!({"baseline":relative,"sha256":hash,"expectation":format!("security/{name}"),"reason":"owner-approved security fix 2026-11-06 (#530): UNREVIEWED","reviewer":"owner 2026-11-06","reviewed":true})),
        }
        entries.sort_by(|a, b| a["baseline"].as_str().cmp(&b["baseline"].as_str()));
        std::fs::write(&list, serde_json::to_string_pretty(&entries)? + "\n")?;
    }
    let Some(entry) = entries.iter().find(|e| e["baseline"] == relative) else {
        return Ok(base);
    };
    assert_eq!(entry["reviewed"], true);
    let reason = entry["reason"].as_str().unwrap();
    assert!(
        ["owner-approved security fix 2026-11-06 (#530)", "owner-approved security fix 2026-11-05 (#547)", "owner-approved functional fix 2026-11-09 (#548)"]
            .iter()
            .any(|accepted| reason.contains(accepted)),
        "{relative}: the reason must cite the owner decision and its ticket"
    );
    // An UNREVIEWED placeholder is tolerated only for an entry this very call regenerated (the run
    // fails at close); anywhere else it must fail, with or without the write flag.
    assert!(!reason.contains("UNREVIEWED") || regenerated_now, "{relative}: UNREVIEWED divergence entry");
    assert_eq!(entry["sha256"], hash, "{relative}: the Go capture changed");
    Ok(serde_json::from_slice(&std::fs::read(family.join(entry["expectation"].as_str().unwrap()))?)?)
}

/// The reviewed expectation for a baseline without ever writing (status-mutant runs compare with it).
pub(super) fn pinned_for(baseline: &std::path::Path) -> Result<Value, Err> {
    let family = corpus();
    let relative = baseline.strip_prefix(&family)?.to_str().unwrap().to_owned();
    let entries: Vec<Value> = serde_json::from_slice(&std::fs::read(family.join("divergences.json"))?)?;
    let file = match entries.iter().find(|e| e["baseline"] == relative) {
        Some(e) => family.join(e["expectation"].as_str().unwrap()),
        None => baseline.to_path_buf(),
    };
    Ok(serde_json::from_slice(&std::fs::read(file)?)?)
}

/// `SECFIX8_WRITE_SECURITY=1` rewrites expectations instead of asserting them, so a run that did
/// so must never pass: the environment's `close` fails it ("review and rerun").
pub(super) static REGENERATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(super) fn regeneration_guard() {
    if REGENERATED.load(std::sync::atomic::Ordering::SeqCst) && !std::thread::panicking() {
        panic!("expectations regenerated (SECFIX8_WRITE_SECURITY): review the diff and rerun without it");
    }
}
