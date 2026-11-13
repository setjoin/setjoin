//! A complete, deterministic operator webmail build, shared by Go and Rust.
use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;

fn resource(line: &str) -> std::io::Result<()> {
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}
pub struct Website(pub PathBuf);
impl Drop for Website {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned website fixture");
        let _ = resource(&format!("Removed owned website {}", self.0.display()));
    }
}
pub fn website(name: &str) -> Result<Website, BoxError> {
    let parent = std::env::var_os("GOFREE_RECORD_GO_BINARY")
        .map(|p| PathBuf::from(p).parent().unwrap().to_owned())
        .unwrap_or_else(std::env::temp_dir);
    let root = parent.join(format!(
        "gofree-catchall-website-{}-{name}",
        std::process::id()
    ));
    resource(&format!(
        "Planned owned temporary website {}",
        root.display()
    ))?;
    std::fs::create_dir(&root)?;
    let result = Website(root);
    let files = [
        ("index.html", b"<html>catchall SPA</html>\n".repeat(40)),
        (
            "_app/version.json",
            b"{\"version\":\"catchall-v1\"}\n".to_vec(),
        ),
        (
            "_app/immutable/app.js",
            b"console.log(\"catchall\");\n".repeat(100),
        ),
        ("style.css", b"body {color: red}\n".to_vec()),
        ("manifest.webmanifest", b"{}\n".to_vec()),
        ("meet/mediapipe/model.tflite", vec![0, 1, 2, 3, 255]),
        ("plain.txt", b"plain fixture\n".to_vec()),
    ];
    let mut assets = vec![];
    let extra =
        (name == "spa_xml").then(|| ("feed.xml", b"<?xml version=\"1.0\"?><feed/>\n".to_vec()));
    for (path, bytes) in files.into_iter().chain(extra) {
        let file = result.0.join(path);
        std::fs::create_dir_all(file.parent().unwrap())?;
        std::fs::write(&file, &bytes)?;
        let mut representations = json!({});
        if path.ends_with("app.js") {
            let mut gzip = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
            gzip.write_all(&bytes)?;
            let gzip = gzip.finish()?;
            use base64::Engine;
            let brotli = base64::engine::general_purpose::STANDARD
                .decode("G8MJAARycT7B0ZJAMoqSvysLmeW2qjoxaf7i4JcFACy4Rgg=")?;
            for (coding, suffix, body) in [("gzip", "gz", gzip), ("br", "br", brotli)] {
                let sidecar = format!("{path}.{suffix}");
                std::fs::write(result.0.join(&sidecar), &body)?;
                representations[coding] = json!({"path":format!("/{sidecar}"),"bytes":body.len(),"sha256":format!("{:x}",Sha256::digest(&body))});
            }
        }
        assets.push(json!({"path":format!("/{path}"),"identityBytes":bytes.len(),"identitySha256":format!("{:x}",Sha256::digest(&bytes)),"representations":representations}));
    }
    std::fs::write(
        result.0.join("static-representations.v1.json"),
        serde_json::to_vec(&json!({"schemaVersion":1,"buildId":"catchall-v1","assets":assets}))?,
    )?;
    fn times(dir: &std::path::Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                times(&path)?;
            } else {
                std::fs::File::open(&path)?.set_times(std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                ))?;
            }
        }
        Ok(())
    }
    times(&result.0)?;
    Ok(result)
}
pub fn etag() -> String {
    format!(
        "\"sha256-{:x}\"",
        Sha256::digest(b"console.log(\"catchall\");\n".repeat(100))
    )
}
