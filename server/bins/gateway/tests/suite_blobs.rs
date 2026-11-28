//! Consolidated integration test suite `suite_blobs` (preserves exact submodule test coverage).

#[allow(dead_code)]
pub mod common;

#[path = "attachment_transfer.rs"]
mod attachment_transfer;
#[path = "blob_download.rs"]
mod blob_download;
#[path = "blob_read_conditions.rs"]
mod blob_read_conditions;
#[path = "blob_upload.rs"]
mod blob_upload;
