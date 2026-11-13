//! `GET /api/messages/{id}/attachments.zip` (#469): a streamed zip of a message's
//! non-inline attachments. Memory is bounded by the 2 KiB response framing, the
//! duplex pipe and one object chunk; nothing is buffered whole.
//!
//! Frozen Go commits to 200 before reading any blob, creates every entry before
//! fetching its bytes (a blob that cannot be read leaves an empty entry and the
//! zip carries on), keeps a truncated entry when a read breaks mid-stream, and
//! applied no size limit. Owner-approved security fix 2026-11-05 (#469/#512): entry names come
//! from `sanitize_filename` and the literal names `.` and `..` (which Go let through) become
//! `attachment`; a message with more than `MAX_ENTRIES` attachments is refused (413) and the
//! archive stops at `MAX_BYTES` of attachment content.
use super::messages::sanitize_filename;
use crate::{Body, RequestContext};
use async_zip::{base::write::ZipFileWriter, Compression, ZipEntryBuilder};
use futures_lite::io::AsyncWriteExt;
use hyper::Response;
use setjoin_jmap::messages::ZipSource;
use std::collections::HashMap;
use std::sync::Arc;

/// Most attachments one archive may carry; more is a 413 before anything streams.
pub const MAX_ENTRIES: usize = 200;
/// Most attachment content bytes one archive carries; the archive ends after the entry that
/// reaches it.
pub const MAX_BYTES: u64 = 1 << 30;

/// The archive entry name for an attachment filename: `sanitize_filename`, with the dot names
/// (`.`, `..`) replaced so no entry resolves to the extraction directory or its parent.
pub fn entry_name(filename: &str) -> String {
    let name = sanitize_filename(filename);
    if matches!(name.as_str(), "." | "..") && !setjoin_contracts::mutants::on("zip-dot-names") {
        return "attachment".into();
    }
    name
}

pub fn entries_allowed(count: usize) -> bool {
    count <= MAX_ENTRIES || setjoin_contracts::mutants::on("zip-unbounded")
}

/// The whole archive in memory, for tests (production streams through `response`).
pub async fn archive_bytes(source: ZipSource) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;
    let (write, mut read) = tokio::io::duplex(65536);
    let producer = tokio::spawn(async move { archive(write, source, None).await });
    let mut out = Vec::new();
    read.read_to_end(&mut out).await.map_err(|e| e.to_string())?;
    producer.await.map_err(|e| e.to_string())??;
    Ok(out)
}

/// Go's `path.Ext`: the suffix starting at the last dot of the final element.
fn ext(name: &str) -> &str {
    for (i, b) in name.bytes().enumerate().rev() {
        if b == b'/' {
            break;
        }
        if b == b'.' {
            return &name[i..];
        }
    }
    ""
}

/// `dedupeZipName`: a repeat of a name gets `-2`, `-3`, ... before its extension.
/// The suffixed name is not itself recorded, as in Go.
pub(super) fn dedupe(seen: &mut HashMap<String, usize>, name: String) -> String {
    let n = *seen.get(&name).unwrap_or(&0);
    seen.insert(name.clone(), n + 1);
    if n == 0 {
        return name;
    }
    let e = ext(&name);
    format!("{}-{}{}", &name[..name.len() - e.len()], n + 1, e)
}

pub(super) async fn response(
    head: bool,
    source: ZipSource,
    store: Option<Arc<crate::recovery_worker::S3Store>>,
    ctx: &RequestContext,
    id: String,
) -> Response<Body> {
    let subject = source.subject.clone().unwrap_or_default();
    let disposition = format!(
        "attachment; filename=\"{}-attachments.zip\"",
        sanitize_filename(&subject)
    );
    let mut response = crate::compliance_export::stream(
        head,
        "application/zip",
        disposition,
        ctx,
        id,
        move |mut out| async move {
            let (write, mut read) = tokio::io::duplex(65536);
            let producer = async move {
                let _ = archive(write, source, store).await;
                Ok::<_, String>(())
            };
            let consumer = async move {
                use tokio::io::AsyncReadExt;
                let mut buffer = [0; 16384];
                loop {
                    let n = read.read(&mut buffer).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    out.write(bytes::Bytes::copy_from_slice(&buffer[..n])).await?;
                }
                out.finish();
                Ok::<_, String>(())
            };
            let _ = tokio::try_join!(producer, consumer);
        },
    )
    .await;
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

async fn archive(
    write: tokio::io::DuplexStream,
    source: ZipSource,
    store: Option<Arc<crate::recovery_worker::S3Store>>,
) -> Result<(), String> {
    let mut zip = ZipFileWriter::with_tokio(tokio::io::BufWriter::with_capacity(4096, write));
    let mut seen = HashMap::new();
    let mut total: u64 = 0;
    for (sha, filename) in source.entries {
        if total >= MAX_BYTES && !setjoin_contracts::mutants::on("zip-unbounded") {
            break;
        }
        let name = dedupe(&mut seen, entry_name(&filename));
        let mut entry = zip
            .write_entry_stream(ZipEntryBuilder::new(name.into(), Compression::Deflate))
            .await
            .map_err(|e| e.to_string())?;
        if let Some(store) = &store {
            if let Ok(mut object) = store.blob_object(&sha).await {
                while let Ok(Some(chunk)) = object.chunk().await {
                    total += chunk.len() as u64;
                    entry.write_all(&chunk).await.map_err(|e| e.to_string())?;
                    if total >= MAX_BYTES && !setjoin_contracts::mutants::on("zip-unbounded") {
                        break;
                    }
                }
            }
        }
        entry.close().await.map_err(|e| e.to_string())?;
    }
    let mut writer = zip.close().await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}
