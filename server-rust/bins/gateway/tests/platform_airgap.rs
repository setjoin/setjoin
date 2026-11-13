//! #455 signed offline-update HTTP parity.
mod common;
mod platform_oracle;
#[tokio::test]
async fn appcast_matches_frozen_go()->Result<(),common::BoxError>{
    for case in ["success","scoped","invalid"] {eprintln!("ORACLE-CASE airgap-feed {case}");platform_oracle::updates::run("airgap-feed",case,None).await?;}
    Ok(())
}
#[tokio::test]
async fn appcast_status_mutant_is_rejected()->Result<(),common::BoxError>{
    platform_oracle::updates::run("airgap-feed","success-status-mutant",None).await
}

#[tokio::test]
async fn appcast_head_keeps_frozen_go_length()->Result<(),common::BoxError>{
    platform_oracle::updates::run("airgap-feed","head",None).await
}
#[tokio::test]
async fn file_matches_frozen_go()->Result<(),common::BoxError>{
    for case in ["success","scoped","invalid","range","bad-range","not-modified","head","expired","tampered"] {
        eprintln!("ORACLE-CASE airgap-file {case}");
        platform_oracle::updates::run("airgap-file",case,None).await?;
    }Ok(())
}
#[tokio::test]
async fn file_status_mutant_is_rejected()->Result<(),common::BoxError>{
    platform_oracle::updates::run("airgap-file","success-status-mutant",None).await
}

#[tokio::test]
async fn upload_matches_frozen_go()->Result<(),common::BoxError>{
    for case in ["success","scoped","invalid","repeat","rollback","missing-slug","traversal","bad-metadata","bad-signature","hash-mismatch","no-roots","denied"] {
        eprintln!("ORACLE-CASE airgap-upload {case}");platform_oracle::updates::run("airgap-upload",case,None).await?;
    }Ok(())
}
#[tokio::test]
async fn upload_status_mutant_is_rejected()->Result<(),common::BoxError>{
    platform_oracle::updates::run("airgap-upload","success-status-mutant",None).await
}

// #542: the scoped upload replays against the reviewed security expectation
// (platform/divergences.json); mutant upgrade-scoped-grant-airgap-upload.
#[tokio::test]
async fn upload_scoped()->Result<(),common::BoxError>{
    platform_oracle::updates::run("airgap-upload","scoped",None).await
}
