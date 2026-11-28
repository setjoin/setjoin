//! Consolidated integration test suite `suite_drive` (preserves exact submodule test coverage).

#[allow(dead_code)]
#[path = "common/drive_commit.rs"]
pub mod commit_wire;
#[allow(dead_code)]
pub mod common;
#[allow(dead_code)]
#[path = "common/drive_s3.rs"]
pub mod drive_s3;
#[allow(dead_code)]
#[path = "common/drive_b_wire.rs"]
pub mod drive_wire;
#[allow(dead_code)]
#[path = "common/drive_wire.rs"]
pub mod drive_wire_2;
#[allow(dead_code)]
#[path = "common/office_fixture.rs"]
pub mod fixture;
#[allow(dead_code)]
#[path = "common/office_go.rs"]
pub mod office_go;
#[allow(dead_code)]
#[path = "common/office_provider.rs"]
pub mod office_provider;
#[allow(dead_code)]
#[path = "common/office_s3.rs"]
pub mod office_s3;
#[allow(dead_code)]
#[path = "common/drive_b_s3.rs"]
pub mod storage_wire;

#[path = "drive_b_recorded.rs"]
mod drive_b_recorded;
#[path = "drive_c_recorded.rs"]
mod drive_c_recorded;
#[path = "drive_core_recorded.rs"]
mod drive_core_recorded;
#[path = "drive_native_token.rs"]
mod drive_native_token;
#[path = "drive_recorded.rs"]
mod drive_recorded;
#[path = "office_admin.rs"]
mod office_admin;
#[path = "office_recorded.rs"]
mod office_recorded;
