use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn mask_text(mut raw: String, actor: i64) -> Result<String, BoxError> {
    for key in ["authorId", "exportedBy", "userId", "editedBy"] {
        for space in ["", " "] {
            for end in [",", "}", "]"] {
                raw = raw.replace(
                    &format!("\"{key}\":{space}{actor}{end}"),
                    &format!("\"{key}\":{space}\"<actor>\"{end}"),
                );
            }
        }
    }
    let bytes = raw.as_bytes();
    let (mut i, mut last) = (0, 0);
    let mut out = String::new();
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                i += 1;
                break;
            }
            i += 1;
        }
        let token = &raw[start..i];
        if let Ok(value) = serde_json::from_str::<String>(token) {
            let b = value.as_bytes();
            if b.len() >= 19
                && b.get(4) == Some(&b'-')
                && b.get(7) == Some(&b'-')
                && b.get(13) == Some(&b':')
            {
                out.push_str(&raw[last..start]);
                out.push_str("\"<timestamp>\"");
                last = i;
            }
        }
    }
    out.push_str(&raw[last..]);
    Ok(out)
}
pub async fn normalize(
    raw: &[u8],
    actor: i64,
    owner: &tokio_postgres::Client,
) -> Result<Value, BoxError> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/chat-compliance/zip_observation.py");
    let mut process = Command::new("python3")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    process
        .stdin
        .take()
        .ok_or("ZIP oracle stdin")?
        .write_all(raw)?;
    let output = process.wait_with_output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let mut doc: Value = serde_json::from_slice(&output.stdout)?;
    for file in doc["files"].as_array_mut().ok_or("ZIP files")? {
        let data = STANDARD.decode(file["base64"].as_str().ok_or("ZIP data")?)?;
        file.as_object_mut().unwrap().remove("base64");
        let name = file["name"].as_str().ok_or("ZIP filename")?.to_owned();
        if name == "manifest.json" {
            let mut manifest: Value = serde_json::from_slice(&data)?;
            for ch in manifest["channels"].as_array().ok_or("manifest channels")? {
                let id = ch["channelId"].as_i64().ok_or("manifest channel")?;
                let row=owner.query_one("SELECT id,after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 ORDER BY id DESC LIMIT 1",&[&id]).await?;
                if ch["chainHead"]["id"] != row.get::<_, i64>(0)
                    || ch["chainHead"]["checksum"] != row.get::<_, String>(1)
                {
                    return Err("manifest pin differs from committed audit head".into());
                }
            }
            manifest["messagesSha256"] = json!("<messages-sha256>");
            super::normalize(&mut manifest, actor, -1);
            for ch in manifest["channels"].as_array_mut().unwrap() {
                ch["chainHead"]["checksum"] = json!("<digest>");
            }
            file["json"] = manifest;
        } else if name == "messages.jsonl" {
            file["text"] = json!(mask_text(String::from_utf8(data)?, actor)?);
        } else {
            file["base64"] = json!(STANDARD.encode(data));
        }
    }
    Ok(doc)
}
