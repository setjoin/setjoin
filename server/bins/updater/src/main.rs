mod adopt;
mod control;
mod dbtls;
mod files;
mod host;
mod install;
mod journal;
mod legacy;
mod migration;
mod office;
mod recovery;
mod run;
mod stage;
use anyhow::{anyhow, ensure, Result};
use setjoin_release_format::{Purpose, TrustStore, VerifyOptions, MIN_VERIFICATION_THRESHOLD};
use std::{collections::BTreeMap, fs};

fn flags(args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        ensure!(key.starts_with("--"), "unexpected argument {key}");
        let value = if matches!(
            key.as_str(),
            "--once" | "--allow-test-roots" | "--office-app-execution" | "--office-app-only"
        ) {
            "true".into()
        } else {
            args.next()
                .ok_or_else(|| anyhow!("missing value for {key}"))?
                .clone()
        };
        ensure!(
            result.insert(key.clone(), value).is_none(),
            "duplicate flag {key}"
        );
    }
    Ok(result)
}
/// #507: `--minimum-threshold` is raise-only. Release builds clamp it to the built-in
/// floor; only test builds (where fixtures have one signer) may go lower.
fn effective_threshold(requested: usize, may_lower: bool) -> usize {
    if may_lower || cfg!(feature = "oracle-mutants") {
        requested
    } else {
        requested.max(MIN_VERIFICATION_THRESHOLD)
    }
}
fn verify(mut f: BTreeMap<String, String>) -> Result<()> {
    let manifest = f
        .remove("--manifest")
        .ok_or_else(|| anyhow!("--manifest required"))?;
    let roots = f
        .remove("--trust-roots")
        .ok_or_else(|| anyhow!("--trust-roots required"))?;
    // #505: test trust roots and a caller-chosen clock exist only in non-release
    // builds; a release binary rejects both as unknown flags.
    #[cfg(debug_assertions)]
    let allow_test = f.remove("--allow-test-roots").is_some();
    #[cfg(not(debug_assertions))]
    let allow_test = false;
    let mut options = VerifyOptions {
        minimum_threshold: MIN_VERIFICATION_THRESHOLD,
        ..Default::default()
    };
    #[cfg(debug_assertions)]
    if let Some(now) = f.remove("--now") {
        options.now = chrono::DateTime::parse_from_rfc3339(&now)?.into();
    }
    if let Some(n) = f.remove("--minimum-threshold") {
        options.minimum_threshold = effective_threshold(n.parse()?, cfg!(debug_assertions));
    }
    options.channel = f.remove("--channel").unwrap_or_default();
    options.current_version = f.remove("--current-version").unwrap_or_default();
    options.platform = f.remove("--platform").unwrap_or_default();
    options.architecture = f.remove("--architecture").unwrap_or_default();
    options.last_metadata_version = f
        .remove("--last-metadata-version")
        .unwrap_or_else(|| "0".into())
        .parse()?;
    options.last_metadata_digest = f.remove("--last-metadata-digest").unwrap_or_default();
    ensure!(f.is_empty(), "unknown flags: {:?}", f.keys());
    let store = TrustStore::parse_roots(&fs::read(roots)?, Purpose::Release, allow_test)?;
    let verified = store.verify_manifest(&fs::read(manifest)?, &options)?;
    println!(
        "{}",
        serde_json::json!({"accepted":true, "sha256":verified.digest,
        "canonical":String::from_utf8(verified.canonical_bytes)?, "signer_key_ids":verified.signer_key_ids})
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = if args.first().is_some_and(|a| a == "recover") {
        recovery::execute(&args[1..]).await
    } else {
        match flags(if args.is_empty() { &[] } else { &args[1..] }) {
            Err(e) => Err(e),
            Ok(f) => match args.first().map(String::as_str) {
                Some("verify") => verify(f),
                Some("adopt-current-layout") => adopt::execute(f),
                Some("run") => run::execute(f).await,
                Some("install") => install::execute(f).await,
                Some("check-swap") => install::check(f).await,
                _ => Err(anyhow!("usage: setjoin-updater run|recover|verify [flags]")),
            },
        }
    };
    if let Err(error) = result {
        let usage = error.downcast_ref::<recovery::Usage>().is_some();
        if args.first().is_some_and(|a| a == "recover") && !usage {
            eprintln!("setjoin-recovery: {error:#}");
        } else {
            eprintln!("{error:#}");
        }
        std::process::exit(if usage { 2 } else { 1 });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn release_threshold_flag_cannot_lower_the_floor() {
        for n in [0, 1] {
            assert_eq!(super::effective_threshold(n, false), 2);
        }
        assert_eq!(super::effective_threshold(5, false), 5);
    }
}
