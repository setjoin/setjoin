//! The case table: fixtures, seeds and the request each case sends.
use std::collections::BTreeMap;

use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::harness::BoxError;
use tokio_postgres::{types::Type, Client};

use super::scrub::Names;

pub struct Fx {
    pub a: Account,
    pub f: Option<Account>,
    pub names: Names,
    /// Seeded extra messages by name.
    pub extra: BTreeMap<&'static str, i64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Seed {
    Identities,
    Transfer,
    RecoveryS3,
    RecoveryRaw,
    SessionAdmin,
    SessionConfigured,
    SessionNative,
    DelegatedSendAs,
    DelegatedRead,
    DelegatedBlob,
    Blobs,
    None,
    Scheduled,
    Undo,
    UndoExpired,
    UndoSharedId,
    Recall,
    RecallAlias,
    RecallExpired,
    SubmissionExternal,
    SubmissionLocal,
    TwoScheduled,
    BrokenScheduled,
    Attachment,
    /// The inbox-only message is soft-deleted (destroyed twice through the reducer).
    Deleted,
    /// Both messages carry a list id.
    Newsletter,
    /// An Inbox message five days old, last in its thread, never answered.
    Stale,
    /// #469: both accounts' messages have a sender for the focus override.
    Focus,
    /// #469: the inbox-only message's raw reference is a stored blob.
    RawDownload,
    /// #469: the inbox-only message carries a mix of attachments to zip.
    Zip,
    /// #469: `Zip` plus two attachments larger than the 2 KiB response framing.
    ZipLarge,
    /// #469: the two-labels message's raw reference is a stored blob over 2 KiB.
    RawDownloadLarge,
    /// #469: the inbox-only messages carry a List-Unsubscribe header.
    Unsub(&'static str),
    /// As `Unsub`, with the routine audit tier switched on (restored on cleanup).
    UnsubFull(&'static str),
}

#[derive(Clone, Copy)]
pub struct Http {
    pub verb: &'static str,
    pub path: fn(&Fx) -> String,
    pub status: u16,
    pub headers: &'static [(&'static str, &'static str)],
}

pub struct Spec {
    pub http: Option<Http>,
    pub owner_pool: bool,
    pub route: &'static str,
    pub pattern: &'static str,
    pub path: fn(&Fx) -> String,
    pub status: u16,
    pub case: &'static str,
    /// The first method response the recording must contain.
    pub method: &'static str,
    pub seed: Seed,
    pub foreign: bool,
    pub repeat: bool,
    pub mutator: bool,
    pub nudges_on: bool,
    pub recall_on: bool,
    pub body: fn(&Fx) -> String,
}

impl Spec {
    const fn new(
        route: &'static str,
        case: &'static str,
        method: &'static str,
        body: fn(&Fx) -> String,
    ) -> Self {
        Spec {
            http: None,
            owner_pool: false,
            route,
            pattern: "/jmap",
            path: |_| "/jmap".into(),
            status: 200,
            case,
            method,
            seed: Seed::None,
            foreign: false,
            repeat: false,
            mutator: false,
            nudges_on: false,
            recall_on: false,
            body,
        }
    }
    const fn http(mut self, verb: &'static str, path: fn(&Fx) -> String, status: u16) -> Self {
        self.http = Some(Http {
            verb,
            path,
            status,
            headers: &[],
        });
        self
    }
    fn headers(mut self, headers: &'static [(&'static str, &'static str)]) -> Self {
        self.http.as_mut().unwrap().headers = headers;
        self
    }
    const fn owner(mut self) -> Self {
        self.owner_pool = true;
        self
    }
    const fn action(mut self, pattern: &'static str, path: fn(&Fx) -> String, status: u16) -> Self {
        self.pattern = pattern;
        self.path = path;
        self.status = status;
        self
    }
    const fn seed(mut self, seed: Seed) -> Self {
        self.seed = seed;
        self
    }
    const fn recall(mut self) -> Self {
        self.recall_on = true;
        self
    }
    const fn nudges(mut self) -> Self {
        self.nudges_on = true;
        self
    }
    const fn mutator(mut self) -> Self {
        self.mutator = true;
        self
    }
    const fn repeat(mut self) -> Self {
        self.repeat = true;
        self
    }
    const fn foreign(mut self) -> Self {
        self.foreign = true;
        self
    }
}

fn jmap(method: &str, args: &str) -> String {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["{method}",{args},"0"]]}}"#
    )
}

fn identity(method: &str, args: &str) -> String {
    jmap(method, args).replace(
        "urn:ietf:params:jmap:mail",
        "urn:ietf:params:jmap:submission",
    )
}
const SET: &str = "POST /jmap Email/set";
const RECOVER: &str = "POST /jmap Email/recover";
const PURGE: &str = "POST /jmap Email/purge";
const DELETED: &str = "POST /jmap Email/deletedQuery";
const BUNDLES: &str = "POST /jmap Email/bundles";
const NUDGES: &str = "POST /jmap Email/nudges";
const DISMISS: &str = "POST /jmap Email/nudgeDismiss";
const RECEIPT: &str = "POST /jmap Email/recoveryReceipt";
const GET: &str = "POST /jmap Email/get";
const QUERY: &str = "POST /jmap Email/query";

pub fn spec(case: &str) -> Spec {
    let mut spec = base_spec(case);
    if spec.route == "GET /.well-known/jmap" {
        spec.mutator = true;
    }
    spec
}
fn base_spec(case: &str) -> Spec {
    match case {
        "identity-set-database-fault"=>Spec::new("POST /jmap Identity/set","identity-set-database-fault","error",|f|identity("Identity/set",&format!(r#"{{"accountId":"{}","update":{{"a{}":{{"signature":"Must roll back"}}}},"destroy":["1"]}}"#,f.a.mailbox,f.extra["alias"]))).seed(Seed::Identities).mutator(),
        "identity-get"=>Spec::new("POST /jmap Identity/get","identity-get","Identity/get",|f|identity("Identity/get",&format!(r#"{{"accountId":"{}"}}"#,f.a.mailbox))).seed(Seed::Identities),
        "identity-get-cross-tenant"=>Spec::new("POST /jmap Identity/get","identity-get-cross-tenant","Identity/get",|f|identity("Identity/get",&format!(r#"{{"accountId":"{}","ids":["a{}"]}}"#,f.f.as_ref().unwrap().mailbox,f.extra["foreign-alias"]))).foreign().seed(Seed::Identities),
        "identity-get-invalid"=>Spec::new("POST /jmap Identity/get","identity-get-invalid","Identity/get",|_|identity("Identity/get",r#"{"ids":123}"#)).seed(Seed::Identities),
        "identity-changes"=>Spec::new("POST /jmap Identity/changes","identity-changes","Identity/changes",|f|identity("Identity/changes",&format!(r#"{{"accountId":"{}","sinceState":"0"}}"#,f.a.mailbox))).seed(Seed::Identities),
        "identity-changes-cross-tenant"=>Spec::new("POST /jmap Identity/changes","identity-changes-cross-tenant","Identity/changes",|f|identity("Identity/changes",&format!(r#"{{"accountId":"{}","sinceState":"0"}}"#,f.f.as_ref().unwrap().mailbox))).foreign().seed(Seed::Identities),
        "identity-changes-invalid"=>Spec::new("POST /jmap Identity/changes","identity-changes-invalid","Identity/changes",|_|identity("Identity/changes",r#"{"sinceState":123}"#)).seed(Seed::Identities),
        "identity-set"=>Spec::new("POST /jmap Identity/set","identity-set","Identity/set",|f|identity("Identity/set",&format!(r#"{{"accountId":"{}","create":{{"x":{{"name":"Denied"}}}},"update":{{"a{}":{{"name":"New Alias","signature":"New signature","replyTo":"new@oracle.example"}}}},"destroy":["1","bad"]}}"#,f.a.mailbox,f.extra["alias"]))).seed(Seed::Identities).mutator(),
        "identity-set-repeat"=>{let mut s=spec("identity-set");s.case="identity-set-repeat";s.repeat()},
        "identity-set-cross-tenant"=>Spec::new("POST /jmap Identity/set","identity-set-cross-tenant","Identity/set",|f|identity("Identity/set",&format!(r#"{{"accountId":"{}","update":{{"a{}":{{"signature":"Foreign update"}}}}}}"#,f.a.mailbox,f.extra["foreign-alias"]))).foreign().seed(Seed::Identities).mutator(),
        "identity-set-invalid"=>Spec::new("POST /jmap Identity/set","identity-set-invalid","Identity/set",|f|identity("Identity/set",&format!(r#"{{"accountId":"{}","update":{{"i{}":{{"name":"No"}},"abad":{{"name":"No"}}}}}}"#,f.a.mailbox,f.a.user))).seed(Seed::Identities).mutator(),
        "mailbox-set-database-fault"=>Spec::new("POST /jmap Mailbox/set","mailbox-set-database-fault","error",|f|jmap("Mailbox/set",&format!(r#"{{"accountId":"{}","create":{{"x":{{"name":"Fault"}}}}}}"#,f.a.mailbox))).mutator(),
        "mailbox-get-database-fault"=>Spec::new("POST /jmap Mailbox/get","mailbox-get-database-fault","error",|f|jmap("Mailbox/get",&format!(r#"{{"accountId":"{}"}}"#,f.a.mailbox))),
        "jmap-recovery-raw-s3"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw-s3","JMAP2 raw body", |_| String::new()).http("GET",|f|format!("/jmap/recovery-raw/{}/{}",f.a.mailbox,f.a.inbox_only),200).seed(Seed::RecoveryS3).mutator(),
        "jmap-recovery-raw-cross-tenant"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw-cross-tenant","recovery account access denied", |_| String::new()).http("GET",|f|format!("/jmap/recovery-raw/{}/{}",f.f.as_ref().unwrap().mailbox,f.f.as_ref().unwrap().inbox_only),403).foreign().seed(Seed::RecoveryRaw).mutator(),
        "jmap-recovery-raw-invalid"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw-invalid","recovery account access denied", |_| String::new()).http("GET",|_|"/jmap/recovery-raw/invalid/invalid".into(),403).seed(Seed::RecoveryRaw).mutator(),
        "jmap-recovery-raw-missing"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw-missing","recoverable message not found", |_| String::new()).http("GET",|f|format!("/jmap/recovery-raw/{}/{}",f.a.mailbox,f.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::RecoveryRaw).mutator(),
        "jmap-recovery-raw-hidden"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw-hidden","recovery raw endpoint is disabled", |_| String::new()).http("GET",|f|format!("/jmap/recovery-raw/{}/{}",f.a.mailbox,f.a.inbox_only),404).mutator(),
        "jmap-attachment-token-cross-tenant"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token-cross-tenant","404 page not found", |f|format!(r#"{{"accountId":"{}","sha256":"{FOREIGN_BLOB}"}}"#,f.f.as_ref().unwrap().mailbox)).http("POST", |_| "/api/mail/attachment-transfer-token".into(),404).foreign().seed(Seed::Transfer),
        "jmap-attachment-token-invalid"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token-invalid","invalid attachment transfer request", |f|format!(r#"{{"accountId":"{}","sha256":"invalid","userId":123}}"#,f.a.mailbox)).http("POST", |_| "/api/mail/attachment-transfer-token".into(),400).seed(Seed::Transfer),
        "jmap-attachment-token-policy-denied"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token-policy-denied","not allowed by current policy", |f|format!(r#"{{"accountId":"{}","sha256":"{OWN_BLOB}"}}"#,f.a.mailbox)).http("POST", |_| "/api/mail/attachment-transfer-token".into(),403).seed(Seed::Transfer),
        "jmap-attachment-token-browser"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token-browser","normal native access session required", |f|format!(r#"{{"accountId":"{}","sha256":"{OWN_BLOB}"}}"#,f.a.mailbox)).http("POST", |_| "/api/mail/attachment-transfer-token".into(),403).seed(Seed::Transfer),
        "jmap-attachment-token-hidden"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token-hidden","404 page not found", |_| "invalid".into()).http("POST", |_| "/api/mail/attachment-transfer-token".into(),404),
        "jmap-attachment-token"=>Spec::new("POST /mail/attachment-transfer-token","jmap-attachment-token","token", |f|format!(r#"{{"accountId":"{}","sha256":"{OWN_BLOB}"}}"#,f.a.mailbox)).http("POST", |_| "/api/mail/attachment-transfer-token".into(),200).seed(Seed::Transfer).repeat(),
        "jmap-download-range"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-range","attachment", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{OWN_BLOB}/proof.txt",f.a.mailbox),206).headers(&[("range","bytes=6-15")]).seed(Seed::Blobs),
        "jmap-download-invalid-range"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-invalid-range","invalid range", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{OWN_BLOB}/proof.txt",f.a.mailbox),416).headers(&[("range","bytes=999-")]).seed(Seed::Blobs),
        "jmap-download-not-modified"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-not-modified","", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{OWN_BLOB}/proof.txt",f.a.mailbox),304).headers(&[("if-none-match","\"abc31963fb81ff310085911d605a50ffc77fbc9c4deea365fad21cc30a7135dc\"")]).seed(Seed::Blobs),
        "jmap-download-cross-tenant"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-cross-tenant","access denied", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{FOREIGN_BLOB}/proof.txt",f.f.as_ref().unwrap().mailbox),403).foreign().seed(Seed::Blobs),
        "jmap-download-invalid"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-invalid","blob not found", |_| String::new()).http("GET",|_| "/jmap/download/invalid/missing/proof.txt".into(),404),
        "jmap-download-delegated"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-delegated","JMAP2 foreign attachment", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{FOREIGN_BLOB}/proof.txt",f.f.as_ref().unwrap().mailbox),200).foreign().seed(Seed::DelegatedBlob),
        "jmap-download-filename"=>Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download-filename","JMAP2 attachment body", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{OWN_BLOB}/%22p%5Cro%01of%22.txt?type=application%2Foctet-stream",f.a.mailbox),200).seed(Seed::Blobs),
        "jmap-recovery-raw"=>Spec::new("GET /jmap/recovery-raw/{accountId}/{messageId}","jmap-recovery-raw","JMAP2 raw body", |_| String::new()).http("GET",|f|format!("/jmap/recovery-raw/{}/{}",f.a.mailbox,f.a.inbox_only),200).seed(Seed::RecoveryRaw).mutator().repeat(),
        "jmap-session-admin"=>Spec::new("GET /.well-known/jmap","jmap-session-admin","permissions", |_| String::new()).http("GET", |_| "/.well-known/jmap".into(),200).seed(Seed::SessionAdmin),
        "jmap-upload-cross-tenant" => Spec::new("POST /jmap/upload/{accountId}","jmap-upload-cross-tenant","account not found", |_| "JMAP2 uploaded body\n".into()).http("POST",|f|format!("/jmap/upload/{}",f.f.as_ref().unwrap().mailbox),403).foreign().mutator(),
        "jmap-upload-invalid" => Spec::new("POST /jmap/upload/{accountId}","jmap-upload-invalid","invalid accountId", |_| "JMAP2 uploaded body\n".into()).http("POST",|_| "/jmap/upload/invalid".into(),400).mutator(),
        "jmap-upload-over-quota" => Spec::new("POST /jmap/upload/{accountId}","jmap-upload-over-quota","storage quota exceeded", |_| "JMAP2 uploaded body\n".into()).http("POST",|f|format!("/jmap/upload/{}",f.a.mailbox),413).mutator(),
        "jmap-upload-delegated" => Spec::new("POST /jmap/upload/{accountId}","jmap-upload-delegated","blobId", |_| "JMAP2 uploaded body\n".into()).http("POST",|f|format!("/jmap/upload/{}",f.f.as_ref().unwrap().mailbox),201).foreign().seed(Seed::DelegatedRead).mutator(),
        "focus-success"=>Spec::new("POST /messages/{id}/focus","focus-success","focused", |_| r#"{"focused":false}"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.a.inbox_only),200).seed(Seed::Focus).mutator(),
        "focus-focused"=>Spec::new("POST /messages/{id}/focus","focus-focused","focused", |_| r#"{"focused":true}"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.a.inbox_only),200).seed(Seed::Focus).mutator(),
        "focus-repeat"=>Spec::new("POST /messages/{id}/focus","focus-repeat","focused", |_| r#"{"focused":false}"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.a.inbox_only),200).seed(Seed::Focus).mutator().repeat(),
        "focus-body-quirks"=>Spec::new("POST /messages/{id}/focus","focus-body-quirks","focused", |_| r#"{"FOCUSED":true,"extra":[1e999],"focused":null} trailing garbage"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.a.inbox_only),200).seed(Seed::Focus).mutator(),
        "focus-cross-tenant"=>Spec::new("POST /messages/{id}/focus","focus-cross-tenant","message not found", |_| r#"{"focused":false}"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::Focus).mutator(),
        "focus-invalid-id"=>Spec::new("POST /messages/{id}/focus","focus-invalid-id","invalid message id", |_| r#"{"focused":false}"#.into()).http("POST",|_| "/api/messages/abc/focus".into(),400).seed(Seed::Focus).mutator(),
        "focus-invalid-body"=>Spec::new("POST /messages/{id}/focus","focus-invalid-body","invalid request body", |_| r#"{"focused":"yes"}"#.into()).http("POST",|f|format!("/api/messages/{}/focus",f.a.inbox_only),400).seed(Seed::Focus).mutator(),
        "download-success"=>Spec::new("GET /messages/{emailId}/download","download-success","JMAP2 attachment body", |_| String::new()).http("GET",|f|format!("/api/messages/{}/download",f.a.inbox_only),200).seed(Seed::RawDownload),
        "download-cross-tenant"=>Spec::new("GET /messages/{emailId}/download","download-cross-tenant","email not found", |_| String::new()).http("GET",|f|format!("/api/messages/{}/download",f.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::RawDownload),
        "download-invalid-id"=>Spec::new("GET /messages/{emailId}/download","download-invalid-id","invalid email ID", |_| String::new()).http("GET",|_| "/api/messages/abc/download".into(),400).seed(Seed::RawDownload),
        "download-large"=>Spec::new("GET /messages/{emailId}/download","download-large","", |_| String::new()).http("GET",|f|format!("/api/messages/{}/download",f.a.two_labels),200).seed(Seed::RawDownloadLarge),
        "download-no-blob"=>Spec::new("GET /messages/{emailId}/download","download-no-blob","email not found", |_| String::new()).http("GET",|f|format!("/api/messages/{}/download",f.a.two_labels),404).seed(Seed::RawDownload),
        "zip-success"=>Spec::new("GET /messages/{id}/attachments.zip","zip-success","", |_| String::new()).http("GET",|f|format!("/api/messages/{}/attachments.zip",f.a.inbox_only),200).seed(Seed::Zip),
        "zip-large"=>Spec::new("GET /messages/{id}/attachments.zip","zip-large","", |_| String::new()).http("GET",|f|format!("/api/messages/{}/attachments.zip",f.a.inbox_only),200).seed(Seed::ZipLarge),
        "zip-cross-tenant"=>Spec::new("GET /messages/{id}/attachments.zip","zip-cross-tenant","no attachments", |_| String::new()).http("GET",|f|format!("/api/messages/{}/attachments.zip",f.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::Zip),
        "zip-invalid-id"=>Spec::new("GET /messages/{id}/attachments.zip","zip-invalid-id","invalid message id", |_| String::new()).http("GET",|_| "/api/messages/0/attachments.zip".into(),400).seed(Seed::Zip),
        "zip-none"=>Spec::new("GET /messages/{id}/attachments.zip","zip-none","no attachments", |_| String::new()).http("GET",|f|format!("/api/messages/{}/attachments.zip",f.a.two_labels),404).seed(Seed::Zip),
        "unsubscribe-mailto"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-mailto","unsubscribed", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),200).seed(Seed::Unsub("<mailto:unsub@news.example>")).mutator(),
        "unsubscribe-audit-full"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-audit-full","unsubscribed", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),200).seed(Seed::UnsubFull("<https://unsubscribe.invalid/u>, <mailto:unsub@news.example>")).mutator(),
        "unsubscribe-post-failed"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-post-failed","unsubscribed", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),200).seed(Seed::Unsub("<https://unsubscribe.invalid/u?x=1>, <mailto:unsub@news.example>")).mutator().repeat(),
        "unsubscribe-private-url"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-private-url","unsubscribe URL is not allowed", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),400).seed(Seed::Unsub("<http://127.0.0.1/unsub>")).mutator(),
        "unsubscribe-bad-header"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-bad-header","invalid List-Unsubscribe header", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),400).seed(Seed::Unsub("not a bracketed header")).mutator(),
        "unsubscribe-no-header"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-no-header","no unsubscribe URL available", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.a.inbox_only),400).seed(Seed::Unsub("")).mutator(),
        "unsubscribe-cross-tenant"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-cross-tenant","message not found", |_| String::new()).http("POST",|f|format!("/api/messages/{}/unsubscribe",f.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::Unsub("<mailto:unsub@news.example>")).mutator(),
        "unsubscribe-invalid-id"=>Spec::new("POST /messages/{emailId}/unsubscribe","unsubscribe-invalid-id","message not found", |_| String::new()).http("POST",|_| "/api/messages/abc/unsubscribe".into(),404).seed(Seed::Unsub("<mailto:unsub@news.example>")).mutator(),
        "jmap-download" => Spec::new("GET /jmap/download/{accountId}/{blobId}/{name}","jmap-download","JMAP2 attachment body", |_| String::new()).http("GET",|f|format!("/jmap/download/{}/{OWN_BLOB}/proof.txt",f.a.mailbox),200).seed(Seed::Blobs),
        "jmap-session-native-owner" => Spec::new("GET /.well-known/jmap","jmap-session-native-owner","offline", |_| String::new()).http("GET", |_| "/.well-known/jmap".into(),200).seed(Seed::SessionNative).owner().mutator().repeat(),
        "jmap-upload" => Spec::new("POST /jmap/upload/{accountId}","jmap-upload","blobId", |_| "JMAP2 uploaded body\n".into()).http("POST",|f|format!("/jmap/upload/{}",f.a.mailbox),201).mutator().repeat(),
        "jmap-session-configured" => Spec::new("GET /.well-known/jmap", "jmap-session-configured", "helpEmail", |_| String::new()).http("GET", |_| "/.well-known/jmap".into(),200).seed(Seed::SessionConfigured),
        "jmap-session-native" => Spec::new("GET /.well-known/jmap", "jmap-session-native", "apiUrl", |_| String::new()).http("GET", |_| "/.well-known/jmap".into(),200).seed(Seed::SessionNative).mutator().repeat(),
        "jmap-session-cross-tenant" => Spec::new("GET /.well-known/jmap", "jmap-session-cross-tenant", "apiUrl", |_| String::new()).http("GET", |f| format!("/.well-known/jmap?accountId={}",f.f.as_ref().unwrap().mailbox),200).foreign(),
        "jmap-session-invalid" => Spec::new("GET /.well-known/jmap", "jmap-session-invalid", "apiUrl", |_| "not JSON".into()).http("GET", |_| "/.well-known/jmap?accountId=invalid".into(),200),
        "jmap-session-delegated-send-as" => Spec::new("GET /.well-known/jmap", "jmap-session-delegated-send-as", "apiUrl", |_| String::new())
            .http("GET", |_| "/.well-known/jmap".into(), 200).foreign().seed(Seed::DelegatedSendAs),
        "jmap-session-delegated-read" => Spec::new("GET /.well-known/jmap", "jmap-session-delegated-read", "apiUrl", |_| String::new())
            .http("GET", |_| "/.well-known/jmap".into(), 200).foreign().seed(Seed::DelegatedRead),
        "jmap-session" => Spec::new("GET /.well-known/jmap", "jmap-session", "apiUrl", |_| String::new())
            .http("GET", |_| "/.well-known/jmap".into(), 200),
        "blob-get-field-casing" => Spec::new("POST /jmap Blob/get", "blob-get-field-casing", "Blob/get", |fx| {
            jmap("Blob/get", &format!(r#"{{"ACCOUNTID":"{}","IDS":["{}"],"PROPERTIES":["size"]}}"#, fx.a.mailbox, OWN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).seed(Seed::Blobs),
        "mailbox-query-field-casing" => Spec::new("POST /jmap Mailbox/query", "mailbox-query-field-casing", "Mailbox/query", |fx| {
            jmap("Mailbox/query", &format!(r#"{{"accountId":"{}","LIMIT":1}}"#, fx.a.mailbox))
        }),
        "blob-get-cross-tenant" => Spec::new("POST /jmap Blob/get", "blob-get-cross-tenant", "Blob/get", |fx| {
            jmap("Blob/get", &format!(r#"{{"accountId":"{}","fromAccountId":"{}","toAccountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.f.as_ref().unwrap().mailbox, fx.a.mailbox, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "blob-get-invalid" => Spec::new("POST /jmap Blob/get", "blob-get-invalid", "error", |fx| {
            jmap("Blob/get", &format!(r#"{{"accountId":"{}","ids":17}}"#, fx.a.mailbox)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }),
        "blob-copy-cross-tenant" => Spec::new("POST /jmap Blob/copy", "blob-copy-cross-tenant", "Blob/copy", |fx| {
            jmap("Blob/copy", &format!(r#"{{"accountId":"{}","fromAccountId":"{}","toAccountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.f.as_ref().unwrap().mailbox, fx.a.mailbox, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "blob-copy-invalid" => Spec::new("POST /jmap Blob/copy", "blob-copy-invalid", "error", |fx| {
            jmap("Blob/copy", &format!(r#"{{"accountId":"{}","ids":17}}"#, fx.a.mailbox)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }),
        "blob-lookup-cross-tenant" => Spec::new("POST /jmap Blob/lookup", "blob-lookup-cross-tenant", "Blob/lookup", |fx| {
            jmap("Blob/lookup", &format!(r#"{{"accountId":"{}","fromAccountId":"{}","toAccountId":"{}","hashes":["{}"]}}"#, fx.a.mailbox, fx.f.as_ref().unwrap().mailbox, fx.a.mailbox, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "blob-lookup-invalid" => Spec::new("POST /jmap Blob/lookup", "blob-lookup-invalid", "error", |fx| {
            jmap("Blob/lookup", &format!(r#"{{"accountId":"{}","hashes":17}}"#, fx.a.mailbox)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }),
        "core-echo-cross-tenant" => Spec::new("POST /jmap Core/echo", "core-echo-cross-tenant", "Core/echo", |fx| {
            format!(r#"{{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{{"accountId":"{}"}},"0"]]}}"#, fx.f.as_ref().unwrap().mailbox)
        }).foreign(),
        "core-echo-invalid" => Spec::new("POST /jmap Core/echo", "core-echo-invalid", "Core/echo", |_| {
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",null,"0"]]}"#.into()
        }),
        "blob-get" => Spec::new("POST /jmap Blob/get", "blob-get", "Blob/get", |fx| {
            jmap("Blob/get", &format!(r#"{{"accountId":"{}","ids":["{}","{}","missing"],"properties":["size"]}}"#, fx.a.mailbox, OWN_BLOB, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "blob-copy" => Spec::new("POST /jmap Blob/copy", "blob-copy", "Blob/copy", |fx| {
            jmap("Blob/copy", &format!(r#"{{"fromAccountId":"{}","toAccountId":"{}","ids":["{}","{}","missing"]}}"#, fx.a.mailbox, fx.f.as_ref().unwrap().mailbox, OWN_BLOB, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "blob-lookup" => Spec::new("POST /jmap Blob/lookup", "blob-lookup", "Blob/lookup", |fx| {
            jmap("Blob/lookup", &format!(r#"{{"accountId":"{}","hashes":["{}","{}","missing"],"typeNames":["unsupported"]}}"#, fx.a.mailbox, OWN_BLOB, FOREIGN_BLOB)).replace("urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:blob")
        }).foreign().seed(Seed::Blobs),
        "core-echo" => Spec::new("POST /jmap Core/echo", "core-echo", "Core/echo", |_| {
            r#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"opaque":[1,"<hello>&",null],"z":true},"0"]]}"#.into()
        }),
        "thread-get-cross-tenant" => Spec::new("POST /jmap Thread/get", "thread-get-cross-tenant", "error", |fx| { jmap("Thread/get", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox)) }).foreign(),
        "thread-get-invalid" => Spec::new("POST /jmap Thread/get", "thread-get-invalid", "error", |fx| { jmap("Thread/get", &format!(r#"{{"accountId":"{}"}}"#, fx.a.mailbox)) }),
        "thread-changes-cross-tenant" => Spec::new("POST /jmap Thread/changes", "thread-changes-cross-tenant", "error", |fx| { jmap("Thread/changes", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox)) }).foreign(),
        "thread-changes-invalid" => Spec::new("POST /jmap Thread/changes", "thread-changes-invalid", "error", |fx| { jmap("Thread/changes", &format!(r#"{{"accountId":"{}","sinceState":"bad"}}"#, fx.a.mailbox)) }),
        "search-snippet-cross-tenant" => Spec::new("POST /jmap SearchSnippet/get", "search-snippet-cross-tenant", "error", |fx| { jmap("SearchSnippet/get", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox)) }).foreign(),
        "search-snippet-invalid" => Spec::new("POST /jmap SearchSnippet/get", "search-snippet-invalid", "error", |fx| { jmap("SearchSnippet/get", &format!(r#"{{"accountId":"{}","filter":{{}},"emailIds":[]}}"#, fx.a.mailbox)) }),
        "thread-get" => Spec::new("POST /jmap Thread/get", "thread-get", "Thread/get", |fx| {
            jmap("Thread/get", &format!(r#"{{"accountId":"{}","ids":["thr-two-labels","thr-inbox-only","thr-foreign-two-labels","missing"]}}"#, fx.a.mailbox))
        }).foreign(),
        "thread-changes" => Spec::new("POST /jmap Thread/changes", "thread-changes", "Thread/changes", |fx| {
            jmap("Thread/changes", &format!(r#"{{"accountId":"{}","sinceState":"0"}}"#, fx.a.mailbox))
        }),
        "search-snippet" => Spec::new("POST /jmap SearchSnippet/get", "search-snippet", "SearchSnippet/get", |fx| {
            jmap("SearchSnippet/get", &format!(r#"{{"accountId":"{}","filter":{{"text":"oracle"}},"emailIds":["{}","{}","bad"]}}"#, fx.a.mailbox, fx.a.two_labels, fx.f.as_ref().unwrap().two_labels))
        }).foreign(),
        "mailbox-get-cross-tenant" => Spec::new("POST /jmap Mailbox/get", "mailbox-get-cross-tenant", "error", |fx| {
            jmap("Mailbox/get", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox))
        }).foreign(),
        "mailbox-query-cross-tenant" => Spec::new("POST /jmap Mailbox/query", "mailbox-query-cross-tenant", "error", |fx| {
            jmap("Mailbox/query", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox))
        }).foreign(),
        "mailbox-changes-cross-tenant" => Spec::new("POST /jmap Mailbox/changes", "mailbox-changes-cross-tenant", "error", |fx| {
            jmap("Mailbox/changes", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox))
        }).foreign(),
        "mailbox-query-changes-cross-tenant" => Spec::new("POST /jmap Mailbox/queryChanges", "mailbox-query-changes-cross-tenant", "error", |fx| {
            jmap("Mailbox/queryChanges", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox))
        }).foreign(),
        "mailbox-set-cross-tenant" => Spec::new("POST /jmap Mailbox/set", "mailbox-set-cross-tenant", "error", |fx| {
            jmap("Mailbox/set", &format!(r#"{{"accountId":"{}"}}"#, fx.f.as_ref().unwrap().mailbox))
        }).foreign().mutator(),
        "mailbox-get-invalid" => Spec::new("POST /jmap Mailbox/get", "mailbox-get-invalid", "Mailbox/get", |fx| {
            jmap("Mailbox/get", &format!(r#"{{"accountId":"{}","ids":["bad","-1"]}}"#, fx.a.mailbox))
        }),
        "mailbox-query-invalid" => Spec::new("POST /jmap Mailbox/query", "mailbox-query-invalid", "Mailbox/query", |fx| {
            jmap("Mailbox/query", &format!(r#"{{"accountId":"{}","limit":-99}}"#, fx.a.mailbox))
        }),
        "mailbox-changes-invalid" => Spec::new("POST /jmap Mailbox/changes", "mailbox-changes-invalid", "error", |fx| {
            jmap("Mailbox/changes", &format!(r#"{{"accountId":"{}","sinceState":"bad"}}"#, fx.a.mailbox))
        }),
        "mailbox-query-changes-invalid" => Spec::new("POST /jmap Mailbox/queryChanges", "mailbox-query-changes-invalid", "error", |fx| {
            jmap("Mailbox/queryChanges", &format!(r#"{{"accountId":"{}","sinceQueryState":"bad"}}"#, fx.a.mailbox))
        }),
        "mailbox-set-invalid" => Spec::new("POST /jmap Mailbox/set", "mailbox-set-invalid", "Mailbox/set", |fx| {
            jmap("Mailbox/set", &format!(r#"{{"accountId":"{}","create":{{"x":{{"name":""}}}}}}"#, fx.a.mailbox))
        }).mutator(),
        "mailbox-set-repeat" => { let mut s = spec("mailbox-set"); s.case = "mailbox-set-repeat"; s.repeat() },
        "mailbox-set-rollback" => Spec::new("POST /jmap Mailbox/set", "mailbox-set-rollback", "error", |fx| {
            jmap("Mailbox/set", &format!(r#"{{"accountId":"{}","create":{{"x":{{"name":"MustRollback"}}}},"update":{{"bad":{{}}}}}}"#, fx.a.mailbox))
        }).mutator(),
        "mailbox-set" => Spec::new("POST /jmap Mailbox/set", "mailbox-set", "Mailbox/set", |fx| {
            jmap("Mailbox/set", &format!(r#"{{"accountId":"{}","create":{{"work":{{"name":"Work","color":"blue"}}}},"update":{{"{}":{{"name":"Projects","sortOrder":11}}}},"destroy":["{}","bad"]}}"#, fx.a.mailbox, fx.a.label, fx.extra["starred"]))
        }).mutator(),
        "mailbox-query" => Spec::new("POST /jmap Mailbox/query", "mailbox-query", "Mailbox/query", |fx| {
            jmap("Mailbox/query", &format!(r#"{{"accountId":"{}","filter":{{"name":"Inbox"}},"sort":[{{"property":"name","isAscending":false}}],"position":0,"limit":2}}"#, fx.a.mailbox))
        }),
        "mailbox-changes" => Spec::new("POST /jmap Mailbox/changes", "mailbox-changes", "Mailbox/changes", |fx| {
            jmap("Mailbox/changes", &format!(r#"{{"accountId":"{}","sinceState":"0","maxChanges":1}}"#, fx.a.mailbox))
        }),
        "mailbox-query-changes" => Spec::new("POST /jmap Mailbox/queryChanges", "mailbox-query-changes", "Mailbox/queryChanges", |fx| {
            jmap("Mailbox/queryChanges", &format!(r#"{{"accountId":"{}","filter":{{"role":"inbox"}},"sort":[]}}"#, fx.a.mailbox))
        }),
        "mailbox-get-ids" => Spec::new("POST /jmap Mailbox/get", "mailbox-get-ids", "Mailbox/get", |fx| {
            jmap("Mailbox/get", &format!(r#"{{"accountId":"{}","ids":["{}","{}","bad","999999999"],"properties":["name"]}}"#, fx.a.mailbox, fx.a.label, fx.f.as_ref().unwrap().label))
        }).foreign(),
        "mailbox-get" => Spec::new("POST /jmap Mailbox/get", "mailbox-get", "Mailbox/get", |fx| {
            jmap("Mailbox/get", &format!(r#"{{"accountId":"{}"}}"#, fx.a.mailbox))
        }),
        "submission-smime-unicode"=>Spec::new("POST /jmap EmailSubmission/set","submission-smime-unicode","EmailSubmission/set",|fx|{
            submission("EmailSubmission/set",&format!(r#"{{"accountId":"{}","create":{{"encrypted":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z","encryptſMIME":true}}}}}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).mutator(),
        "submission-get-case-folded"=>Spec::new("POST /jmap EmailSubmission/get","submission-get-case-folded","EmailSubmission/get",|fx|{
            submission("EmailSubmission/get",&format!(r#"{{"ACCOUNTID":"{}","AccountID":null,"IDS":["{}"]}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).seed(Seed::Scheduled),
        "submission-get-missing-account"=>Spec::new("POST /jmap EmailSubmission/get","submission-get-missing-account","error",|_|submission("EmailSubmission/get",r#"{"ids":[]}"#)),
        "submission-get-invalid-element"=>Spec::new("POST /jmap EmailSubmission/get","submission-get-invalid-element","error",|fx|{
            submission("EmailSubmission/get",&format!(r#"{{"accountId":"{}","ids":[true]}}"#,fx.a.mailbox))
        }),
        "submission-query-invalid-limit"=>Spec::new("POST /jmap EmailSubmission/query","submission-query-invalid-limit","error",|fx|{
            submission("EmailSubmission/query",&format!(r#"{{"accountId":"{}","limit":"few"}}"#,fx.a.mailbox))
        }),
        "submission-query-position-overflow"=>Spec::new("POST /jmap EmailSubmission/query","submission-query-position-overflow","error",|fx|{
            submission("EmailSubmission/query",&format!(r#"{{"accountId":"{}","position":2147483648}}"#,fx.a.mailbox))
        }),
        "submission-cancel-missing-id"=>Spec::new("POST /jmap EmailSubmission/cancel","submission-cancel-missing-id","error",|fx|{
            submission("EmailSubmission/cancel",&format!(r#"{{"accountId":"{}"}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-cancel-invalid-type"=>Spec::new("POST /jmap EmailSubmission/cancel","submission-cancel-invalid-type","error",|fx|{
            submission("EmailSubmission/cancel",&format!(r#"{{"accountId":"{}","emailId":7}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-set-invalid-account"=>Spec::new("POST /jmap EmailSubmission/set","submission-set-invalid-account","error",|_|{
            submission("EmailSubmission/set",r#"{"accountId":"abc","create":[]}"#)
        }).mutator(),
        "submission-set-invalid-argument-type"=>Spec::new("POST /jmap EmailSubmission/set","submission-set-invalid-argument-type","error",|_|{
            submission("EmailSubmission/set",r#"{"accountId":false}"#)
        }).mutator(),
        "submission-set-null-create"=>Spec::new("POST /jmap EmailSubmission/set","submission-set-null-create","EmailSubmission/set",|fx|{
            submission("EmailSubmission/set",&format!(r#"{{"accountId":"{}","create":null}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-set-db-error"=>Spec::new("POST /jmap EmailSubmission/set","submission-set-db-error","error",|fx|{
            create(fx,r#", "unused":"\u0000""#)
        }).mutator(),
        "submission-get-db-error"=>Spec::new("POST /jmap EmailSubmission/get","submission-get-db-error","error",|fx|{
            submission("EmailSubmission/get",&format!(r#"{{"accountId":"{}","ids":["{}"]}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).seed(Seed::BrokenScheduled),
        "submission-attachment-deferred"=>Spec::new("POST /jmap EmailSubmission/set","submission-attachment-deferred","EmailSubmission/set",|fx|{
            submission("EmailSubmission/set",&format!(r#"{{"accountId":"{}","create":{{"plain":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z"}},"attached":{{"EmailID":"{}","sendAt":"2099-01-02T03:04:05Z"}}}}}}"#,fx.a.mailbox,fx.a.two_labels,fx.a.inbox_only))
        }).seed(Seed::Attachment).mutator(),
        "submission-attachment-invalid-id"=>Spec::new("POST /jmap EmailSubmission/set","submission-attachment-invalid-id","EmailSubmission/set",|fx|{
            submission("EmailSubmission/set",&format!(r#"{{"accountId":"{}","create":{{"attached":{{"emailId":"abc"}}}}}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-smime-deferred"=>Spec::new("POST /jmap EmailSubmission/set","submission-smime-deferred","EmailSubmission/set",|fx|{
            submission("EmailSubmission/set",&format!(r#"{{"accountId":"{}","create":{{"plain":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z"}},"encrypted":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z","EncryptSMIME":true}}}}}}"#,fx.a.mailbox,fx.a.inbox_only,fx.a.inbox_only))
        }).mutator(),
        "submission-recall-cross-tenant" => Spec::new("POST /messages/{id}/recall","submission-recall-cross-tenant","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::Recall).recall().mutator(),
        "submission-recall-invalid" => Spec::new("POST /messages/{id}/recall","submission-recall-invalid","", |_|String::new())
            .action("/messages/{id}/recall", |_|"/api/messages/abc/recall".into(),400).foreign().seed(Seed::Recall).recall().mutator(),
        "submission-recall-repeat" => Spec::new("POST /messages/{id}/recall","submission-recall-repeat","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.a.inbox_only),200).foreign().seed(Seed::Recall).recall().mutator().repeat(),
        "submission-recall-disabled" => Spec::new("POST /messages/{id}/recall","submission-recall-disabled","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.a.inbox_only),404).foreign().seed(Seed::Recall).mutator(),
        "submission-recall-sender-denied" => Spec::new("POST /messages/{id}/recall","submission-recall-sender-denied","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.a.inbox_only),403).recall().mutator(),
        "submission-recall-alias" => Spec::new("POST /messages/{id}/recall","submission-recall-alias","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.a.inbox_only),200).foreign().seed(Seed::RecallAlias).recall().mutator(),
        "submission-recall-expired" => Spec::new("POST /messages/{id}/recall","submission-recall-expired","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.extra["expired"]),410).seed(Seed::RecallExpired).recall().mutator(),
        "submission-get-invalid-type" => Spec::new("POST /jmap EmailSubmission/get","submission-get-invalid-type","error",|fx|{
            submission("EmailSubmission/get",&format!(r#"{{"accountId":"{}","ids":17}}"#,fx.a.mailbox))
        }),
        "submission-undo-cross-tenant" => Spec::new("POST /messages/{id}/undo","submission-undo-cross-tenant","", |_|String::new())
            .action("/messages/{id}/undo", |fx|format!("/api/messages/{}/undo",fx.f.as_ref().unwrap().inbox_only),404).foreign().seed(Seed::Undo).mutator(),
        "submission-undo-invalid" => Spec::new("POST /messages/{id}/undo","submission-undo-invalid","", |_|String::new())
            .action("/messages/{id}/undo", |_|"/api/messages/abc/undo".into(),400).seed(Seed::Undo).mutator(),
        "submission-undo-repeat" => Spec::new("POST /messages/{id}/undo","submission-undo-repeat","", |_|String::new())
            .action("/messages/{id}/undo", |fx|format!("/api/messages/{}/undo",fx.a.inbox_only),410).seed(Seed::Undo).mutator().repeat(),
        "submission-undo-expired" => Spec::new("POST /messages/{id}/undo","submission-undo-expired","", |_|String::new())
            .action("/messages/{id}/undo", |fx|format!("/api/messages/{}/undo",fx.a.inbox_only),200).seed(Seed::UndoExpired).mutator(),
        "submission-undo-shared-id" => Spec::new("POST /messages/{id}/undo","submission-undo-shared-id","", |_|String::new())
            .action("/messages/{id}/undo", |fx|format!("/api/messages/{}/undo",fx.a.inbox_only),200).foreign().seed(Seed::UndoSharedId).mutator(),
        "submission-recall" => Spec::new("POST /messages/{id}/recall","submission-recall","", |_|String::new())
            .action("/messages/{id}/recall", |fx|format!("/api/messages/{}/recall",fx.a.inbox_only),200).foreign().seed(Seed::Recall).recall().mutator(),
        "submission-undo" => Spec::new("POST /messages/{id}/undo","submission-undo","", |_| String::new())
            .action("/messages/{id}/undo", |fx|format!("/api/messages/{}/undo",fx.a.inbox_only),200)
            .seed(Seed::Undo).mutator(),
        "submission-set-cross-tenant" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-cross-tenant", "error", |fx| {
            submission("EmailSubmission/set", &format!(r#"{{"accountId":"{}","create":{{"s":{{"emailId":"{}"}}}}}}"#,fx.f.as_ref().unwrap().mailbox,fx.a.inbox_only))
        }).foreign().mutator(),
        "submission-set-foreign-message" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-foreign-message", "EmailSubmission/set", |fx| {
            submission("EmailSubmission/set", &format!(r#"{{"accountId":"{}","create":{{"s":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z"}}}}}}"#,fx.a.mailbox,fx.f.as_ref().unwrap().inbox_only))
        }).foreign().mutator(),
        "submission-set-invalid" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-invalid", "EmailSubmission/set", |fx| {
            submission("EmailSubmission/set", &format!(r#"{{"accountId":"{}","create":{{"s":{{}}}}}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-set-invalid-create" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-invalid-create", "error", |fx| {
            submission("EmailSubmission/set", &format!(r#"{{"accountId":"{}","create":[]}}"#,fx.a.mailbox))
        }).mutator(),
        "submission-set-repeat" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-repeat", "EmailSubmission/set", |fx| {
            create(fx, r#", "sendAt":"2099-01-02T03:04:05Z""#)
        }).mutator().repeat(),
        "submission-set-external" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-external", "EmailSubmission/set", |fx| create(fx, "")).seed(Seed::SubmissionExternal).mutator(),
        "submission-set-local" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-local", "EmailSubmission/set", |fx| create(fx, "")).seed(Seed::SubmissionLocal).foreign().mutator(),
        "submission-set-patch" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-patch", "EmailSubmission/set", |fx| {
            create(fx,r##", "onSuccessUpdateEmail":{"#s":{"keywords":{"$seen":true}}}"##)
        }).seed(Seed::SubmissionExternal).mutator(),
        "submission-set-undo-window" => Spec::new("POST /jmap EmailSubmission/set", "submission-set-undo-window", "EmailSubmission/set", |fx| {
            create(fx,r#", "onSendUndoWindowSeconds":30"#)
        }).seed(Seed::SubmissionExternal).mutator(),
        "submission-query-total-page" => Spec::new("POST /jmap EmailSubmission/query", "submission-query-total-page", "EmailSubmission/query", |fx| {
            submission("EmailSubmission/query",&format!(r#"{{"accountId":"{}","limit":1}}"#,fx.a.mailbox))
        }).seed(Seed::TwoScheduled),
        "submission-get-missing-id" => Spec::new("POST /jmap EmailSubmission/get", "submission-get-missing-id", "EmailSubmission/get", |fx| {
            submission("EmailSubmission/get",&format!(r#"{{"accountId":"{}","ids":["999999999"]}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled),
        "submission-set" => Spec::new("POST /jmap EmailSubmission/set", "submission-set", "EmailSubmission/set", |fx| {
            submission("EmailSubmission/set", &format!(r#"{{"accountId":"{}","create":{{"s":{{"emailId":"{}","sendAt":"2099-01-02T03:04:05Z"}}}}}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).mutator(),
        "submission-cancel-repeat" => Spec::new("POST /jmap EmailSubmission/cancel", "submission-cancel-repeat", "EmailSubmission/cancel", |fx| {
            submission("EmailSubmission/cancel", &format!(r#"{{"accountId":"{}","emailId":"{}"}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).seed(Seed::Scheduled).mutator().repeat(),
        "submission-cancel-cross-tenant" => Spec::new("POST /jmap EmailSubmission/cancel", "submission-cancel-cross-tenant", "error", |fx| {
            let f=fx.f.as_ref().unwrap();
            submission("EmailSubmission/cancel", &format!(r#"{{"accountId":"{}","emailId":"{}"}}"#,f.mailbox,f.inbox_only))
        }).foreign().seed(Seed::Scheduled).mutator(),
        "submission-cancel-foreign-message" => Spec::new("POST /jmap EmailSubmission/cancel", "submission-cancel-foreign-message", "error", |fx| {
            submission("EmailSubmission/cancel", &format!(r#"{{"accountId":"{}","emailId":"{}"}}"#,fx.a.mailbox,fx.f.as_ref().unwrap().inbox_only))
        }).foreign().seed(Seed::Scheduled).mutator(),
        "submission-cancel-invalid" => Spec::new("POST /jmap EmailSubmission/cancel", "submission-cancel-invalid", "error", |fx| {
            submission("EmailSubmission/cancel", &format!(r#"{{"accountId":"{}","emailId":"abc"}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled).mutator(),
        "submission-cancel" => Spec::new("POST /jmap EmailSubmission/cancel", "submission-cancel", "EmailSubmission/cancel", |fx| {
            submission("EmailSubmission/cancel", &format!(r#"{{"accountId":"{}","emailId":"{}"}}"#,fx.a.mailbox,fx.a.inbox_only))
        }).seed(Seed::Scheduled).mutator(),
        "submission-get-cross-tenant" => Spec::new("POST /jmap EmailSubmission/get", "submission-get-cross-tenant", "error", |fx| {
            submission("EmailSubmission/get", &format!(r#"{{"accountId":"{}"}}"#,fx.f.as_ref().unwrap().mailbox))
        }).foreign().seed(Seed::Scheduled),
        "submission-query-cross-tenant" => Spec::new("POST /jmap EmailSubmission/query", "submission-query-cross-tenant", "error", |fx| {
            submission("EmailSubmission/query", &format!(r#"{{"accountId":"{}"}}"#,fx.f.as_ref().unwrap().mailbox))
        }).foreign().seed(Seed::Scheduled),
        "submission-get-malformed" => Spec::new("POST /jmap EmailSubmission/get", "submission-get-malformed", "EmailSubmission/get", |fx| {
            submission("EmailSubmission/get", &format!(r#"{{"accountId":"{}","ids":["abc","-1"]}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled),
        "submission-query-clamped" => Spec::new("POST /jmap EmailSubmission/query", "submission-query-clamped", "EmailSubmission/query", |fx| {
            submission("EmailSubmission/query", &format!(r#"{{"accountId":"{}","limit":-1,"position":-5}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled),
        "submission-query" => Spec::new("POST /jmap EmailSubmission/query", "submission-query", "EmailSubmission/query", |fx| {
            submission("EmailSubmission/query", &format!(r#"{{"accountId":"{}","filter":{{"before":"2000-01-01T00:00:00Z"}}}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled),
        "submission-get" => Spec::new("POST /jmap EmailSubmission/get", "submission-get", "EmailSubmission/get", |fx| {
            submission("EmailSubmission/get", &format!(r#"{{"accountId":"{}"}}"#,fx.a.mailbox))
        }).seed(Seed::Scheduled),
        "email-get" => Spec::new(GET, "email-get", "Email/get", |fx| {
            jmap(
                "Email/get",
                &format!(
                    r#"{{"accountId":"{}","ids":["{}","{}"]}}"#,
                    fx.a.mailbox, fx.a.two_labels, fx.a.inbox_only
                ),
            )
        }),
        "email-get-properties-not-found" => {
            Spec::new(GET, "email-get-properties-not-found", "Email/get", |fx| {
                jmap(
                    "Email/get",
                    &format!(
                        r#"{{"accountId":"{}","ids":["{}","abc","999999999"],"properties":["subject","keywords","mailboxIds"]}}"#,
                        fx.a.mailbox, fx.a.two_labels
                    ),
                )
            })
        }
        "email-get-cross-tenant" => Spec::new(GET, "email-get-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap(
                "Email/get",
                &format!(
                    r#"{{"accountId":"{}","ids":["{}"]}}"#,
                    f.mailbox, f.two_labels
                ),
            )
        })
        .foreign(),
        "email-get-foreign-message" => {
            Spec::new(GET, "email-get-foreign-message", "Email/get", |fx| {
                let f = fx.f.as_ref().expect("foreign");
                jmap(
                    "Email/get",
                    &format!(
                        r#"{{"accountId":"{}","ids":["{}"]}}"#,
                        fx.a.mailbox, f.two_labels
                    ),
                )
            })
            .foreign()
        }
        "email-get-malformed-ids" => Spec::new(GET, "email-get-malformed-ids", "Email/get", |fx| {
            jmap(
                "Email/get",
                &format!(r#"{{"accountId":"{}","ids":["abc","-1"]}}"#, fx.a.mailbox),
            )
        }),
        "email-query-text" => Spec::new(QUERY, "email-query-text", "Email/query", |fx| {
            jmap(
                "Email/query",
                &format!(
                    r#"{{"accountId":"{}","filter":{{"text":"oracle"}},"sort":[{{"property":"receivedAt","isAscending":true}}],"limit":10}}"#,
                    fx.a.mailbox
                ),
            )
        }),
        "email-query-combined-filter" => {
            Spec::new(QUERY, "email-query-combined-filter", "Email/query", |fx| {
                jmap(
                    "Email/query",
                    &format!(
                        r#"{{"accountId":"{}","filter":{{"inMailbox":"{}","from":"oracle@example.test","minSize":5,"hasKeyword":"$unseen"}},"position":0,"limit":5}}"#,
                        fx.a.mailbox, fx.a.label
                    ),
                )
            })
        }
        "email-query-cross-tenant" => Spec::new(QUERY, "email-query-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap(
                "Email/query",
                &format!(
                    r#"{{"accountId":"{}","filter":{{"text":"oracle"}}}}"#,
                    f.mailbox
                ),
            )
        })
        .foreign(),
        "email-query-foreign-tag" => {
            Spec::new(QUERY, "email-query-foreign-tag", "Email/query", |fx| {
                let f = fx.f.as_ref().expect("foreign");
                jmap(
                    "Email/query",
                    &format!(
                        r#"{{"accountId":"{}","filter":{{"inMailbox":"{}","text":"oracle"}}}}"#,
                        fx.a.mailbox, f.inbox
                    ),
                )
            })
            .foreign()
        }
        "email-query-clamped-paging" => {
            Spec::new(QUERY, "email-query-clamped-paging", "Email/query", |fx| {
                jmap(
                    "Email/query",
                    &format!(
                        r#"{{"accountId":"{}","filter":{{"text":"oracle"}},"position":1,"limit":-1}}"#,
                        fx.a.mailbox
                    ),
                )
            })
        }
        "email-query-bad-date" => Spec::new(QUERY, "email-query-bad-date", "error", |fx| {
            jmap(
                "Email/query",
                &format!(
                    r#"{{"accountId":"{}","filter":{{"before":"not-a-date"}}}}"#,
                    fx.a.mailbox
                ),
            )
        }),
        "email-set-update-flag" => Spec::new(SET, "email-set-update-flag", "Email/set", |fx| {
            jmap(
                "Email/set",
                &format!(
                    r#"{{"accountId":"{}","create":null,"update":{{"{}":{{"keywords":{{"$flagged":true,"$seen":true}}}}}},"destroy":null}}"#,
                    fx.a.mailbox, fx.a.two_labels
                ),
            )
        })
        .mutator(),
        "email-set-update-repeat" => Spec::new(SET, "email-set-update-repeat", "Email/set", |fx| {
            jmap(
                "Email/set",
                &format!(
                    r#"{{"accountId":"{}","update":{{"{}":{{"keywords":{{"$flagged":true}}}}}}}}"#,
                    fx.a.mailbox, fx.a.inbox_only
                ),
            )
        })
        .mutator()
        .repeat(),
        "email-set-move-label" => Spec::new(SET, "email-set-move-label", "Email/set", |fx| {
            jmap(
                "Email/set",
                &format!(
                    r#"{{"accountId":"{}","update":{{"{}":{{"mailboxIds":{{"{}":true}}}}}}}}"#,
                    fx.a.mailbox, fx.a.inbox_only, fx.extra["starred"]
                ),
            )
        })
        .mutator(),
        "email-set-destroy" => Spec::new(SET, "email-set-destroy", "Email/set", |fx| {
            jmap(
                "Email/set",
                &format!(r#"{{"accountId":"{}","create":null,"update":null,"destroy":["{}"]}}"#, fx.a.mailbox, fx.a.inbox_only),
            )
        })
        .mutator(),
        "email-set-cross-tenant" => Spec::new(SET, "email-set-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap(
                "Email/set",
                &format!(r#"{{"accountId":"{}","update":{{"{}":{{"keywords":{{"$seen":true}}}}}}}}"#, f.mailbox, f.two_labels),
            )
        })
        .mutator()
        .foreign(),
        "email-set-foreign-tag" => Spec::new(SET, "email-set-foreign-tag", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap(
                "Email/set",
                &format!(
                    r#"{{"accountId":"{}","update":{{"{}":{{"mailboxIds":{{"{}":true}}}}}}}}"#,
                    fx.a.mailbox, fx.a.two_labels, f.inbox
                ),
            )
        })
        .mutator()
        .foreign(),
        "email-set-invalid-keyword" => Spec::new(SET, "email-set-invalid-keyword", "Email/set", |fx| {
            jmap(
                "Email/set",
                &format!(r#"{{"accountId":"{}","update":{{"{}":{{"keywords":{{"$flagged":"maybe"}}}}}}}}"#, fx.a.mailbox, fx.a.two_labels),
            )
        })
        .mutator(),
        "email-set-destroy-malformed" => Spec::new(SET, "email-set-destroy-malformed", "Email/set", |fx| {
            jmap("Email/set", &format!(r#"{{"accountId":"{}","destroy":["abc","{}","-3"]}}"#, fx.a.mailbox, 999_999_999))
        })
        .mutator(),
        "email-recover" => Spec::new(RECOVER, "email-recover", "Email/recover", |fx| {
            jmap("Email/recover", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.a.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator(),
        "email-recover-repeat" => Spec::new(RECOVER, "email-recover-repeat", "Email/recover", |fx| {
            jmap("Email/recover", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.a.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator()
        .repeat(),
        "email-recover-cross-tenant" => Spec::new(RECOVER, "email-recover-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/recover", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, f.mailbox, f.inbox_only))
        })
        .mutator()
        .foreign(),
        "email-recover-foreign-message" => Spec::new(RECOVER, "email-recover-foreign-message", "Email/recover", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/recover", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, f.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator()
        .foreign(),
        "email-recover-malformed" => Spec::new(RECOVER, "email-recover-malformed", "Email/recover", |fx| {
            jmap("Email/recover", &format!(r#"{{"accountId":"{}","ids":["abc","999999999"]}}"#, fx.a.mailbox))
        })
        .mutator(),
        "email-purge" => Spec::new(PURGE, "email-purge", "Email/purge", |fx| {
            jmap("Email/purge", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.a.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator(),
        "email-purge-repeat" => Spec::new(PURGE, "email-purge-repeat", "Email/purge", |fx| {
            jmap("Email/purge", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.a.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator()
        .repeat(),
        "email-purge-cross-tenant" => Spec::new(PURGE, "email-purge-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/purge", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, f.mailbox, f.inbox_only))
        })
        .mutator()
        .foreign(),
        "email-purge-foreign-message" => Spec::new(PURGE, "email-purge-foreign-message", "Email/purge", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/purge", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, f.inbox_only))
        })
        .seed(Seed::Deleted)
        .mutator()
        .foreign(),
        "email-purge-malformed" => Spec::new(PURGE, "email-purge-malformed", "Email/purge", |fx| {
            jmap("Email/purge", &format!(r#"{{"accountId":"{}","ids":["abc","999999999"]}}"#, fx.a.mailbox))
        })
        .mutator(),
        "email-deleted-query" => Spec::new(DELETED, "email-deleted-query", "Email/deletedQuery", |fx| {
            jmap("Email/deletedQuery", &format!(r#"{{"accountId":"{}","limit":10,"position":0}}"#, fx.a.mailbox))
        })
        .seed(Seed::Deleted),
        "email-deleted-query-cross-tenant" => Spec::new(DELETED, "email-deleted-query-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/deletedQuery", &format!(r#"{{"accountId":"{}"}}"#, f.mailbox))
        })
        .foreign(),
        "email-deleted-query-clamped" => Spec::new(DELETED, "email-deleted-query-clamped", "Email/deletedQuery", |fx| {
            jmap("Email/deletedQuery", &format!(r#"{{"accountId":"{}","limit":-1,"position":1}}"#, fx.a.mailbox))
        })
        .seed(Seed::Deleted),
        "email-bundles" => Spec::new(BUNDLES, "email-bundles", "Email/bundles", |fx| {
            jmap("Email/bundles", &format!(r#"{{"accountId":"{}","limit":10}}"#, fx.a.mailbox))
        })
        .seed(Seed::Newsletter),
        "email-bundles-cross-tenant" => Spec::new(BUNDLES, "email-bundles-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/bundles", &format!(r#"{{"accountId":"{}"}}"#, f.mailbox))
        })
        .foreign(),
        "email-bundles-clamped" => Spec::new(BUNDLES, "email-bundles-clamped", "Email/bundles", |fx| {
            jmap("Email/bundles", &format!(r#"{{"accountId":"{}","limit":500,"position":2}}"#, fx.a.mailbox))
        })
        .seed(Seed::Newsletter),
        "email-nudges" => Spec::new(NUDGES, "email-nudges", "Email/nudges", |fx| {
            jmap("Email/nudges", &format!(r#"{{"accountId":"{}","limit":10}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale)
        .nudges(),
        "email-nudges-off" => Spec::new(NUDGES, "email-nudges-off", "Email/nudges", |fx| {
            jmap("Email/nudges", &format!(r#"{{"accountId":"{}","limit":10,"position":3}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale),
        "email-nudges-cross-tenant" => Spec::new(NUDGES, "email-nudges-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/nudges", &format!(r#"{{"accountId":"{}"}}"#, f.mailbox))
        })
        .nudges()
        .foreign(),
        "email-nudges-clamped" => Spec::new(NUDGES, "email-nudges-clamped", "Email/nudges", |fx| {
            jmap("Email/nudges", &format!(r#"{{"accountId":"{}","limit":500,"position":1}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale)
        .nudges(),
        "email-nudge-dismiss" => Spec::new(DISMISS, "email-nudge-dismiss", "Email/nudgeDismiss", |fx| {
            jmap("Email/nudgeDismiss", &format!(r#"{{"accountId":"{}","threadId":"thr-stale"}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale)
        .nudges()
        .mutator(),
        "email-nudge-dismiss-repeat" => Spec::new(DISMISS, "email-nudge-dismiss-repeat", "Email/nudgeDismiss", |fx| {
            jmap("Email/nudgeDismiss", &format!(r#"{{"accountId":"{}","threadId":"thr-stale"}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale)
        .nudges()
        .mutator()
        .repeat(),
        "email-nudge-dismiss-off" => Spec::new(DISMISS, "email-nudge-dismiss-off", "Email/nudgeDismiss", |fx| {
            jmap("Email/nudgeDismiss", &format!(r#"{{"accountId":"{}","threadId":"thr-stale"}}"#, fx.a.mailbox))
        })
        .seed(Seed::Stale)
        .mutator(),
        "email-nudge-dismiss-cross-tenant" => Spec::new(DISMISS, "email-nudge-dismiss-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/nudgeDismiss", &format!(r#"{{"accountId":"{}","threadId":"thr-stale"}}"#, f.mailbox))
        })
        .nudges()
        .mutator()
        .foreign(),
        "email-nudge-dismiss-empty-thread" => Spec::new(DISMISS, "email-nudge-dismiss-empty-thread", "Email/nudgeDismiss", |fx| {
            jmap("Email/nudgeDismiss", &format!(r#"{{"accountId":"{}","threadId":""}}"#, fx.a.mailbox))
        })
        .nudges()
        .mutator(),
        "email-recovery-receipt-disabled" => Spec::new(RECEIPT, "email-recovery-receipt-disabled", "error", |fx| {
            jmap("Email/recoveryReceipt", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, fx.a.mailbox, fx.a.two_labels))
        }),
        "email-recovery-receipt-cross-tenant" => Spec::new(RECEIPT, "email-recovery-receipt-cross-tenant", "error", |fx| {
            let f = fx.f.as_ref().expect("foreign");
            jmap("Email/recoveryReceipt", &format!(r#"{{"accountId":"{}","ids":["{}"]}}"#, f.mailbox, f.two_labels))
        })
        .foreign(),
        "email-recovery-receipt-invalid" => Spec::new(RECEIPT, "email-recovery-receipt-invalid", "error", |fx| {
            jmap("Email/recoveryReceipt", &format!(r#"{{"accountId":"{}","ids":[]}}"#, fx.a.mailbox))
        }),
        other => panic!("unknown email oracle case {other}"),
    }
}

async fn account(
    c: &Client,
    label: &str,
    prefix: &str,
    names: &mut Names,
) -> Result<Account, BoxError> {
    let a = fixture::account(c, label).await?;
    let p = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}-")
    };
    names.insert(a.mailbox, format!("<{p}mailbox>"));
    names.insert(a.user, format!("<{p}user>"));
    names.insert(a.domain, format!("<{p}domain>"));
    names.insert(a.two_labels, format!("<{p}two-labels>"));
    names.insert(a.inbox_only, format!("<{p}inbox-only>"));
    for row in c
        .query_typed(
            "SELECT id, name FROM tags WHERE mailbox_id = $1",
            &[(&a.mailbox, Type::INT8)],
        )
        .await?
    {
        names.insert(row.get(0), format!("<{p}tag:{}>", row.get::<_, String>(1)));
    }
    for (id, name) in [(a.two_labels, "two-labels"), (a.inbox_only, "inbox-only")] {
        c.query_typed(
            "UPDATE messages SET message_id = $2, thread_id = $3, raw_ref = $4 WHERE id = $1",
            &[
                (&id, Type::INT8),
                (&format!("<{p}{name}@oracle.test>"), Type::TEXT),
                (&format!("thr-{p}{name}"), Type::TEXT),
                (&format!("raw-{p}{name}"), Type::TEXT),
            ],
        )
        .await?;
    }
    Ok(a)
}

/// Purge queues a message's raw blob in a table no mailbox owns; the fixture's
/// fixed refs must not survive a case or the next purge would insert nothing.
async fn clear_orphans(c: &Client) -> Result<(), BoxError> {
    c.batch_execute(
        "DELETE FROM orphaned_message_blobs WHERE raw_ref IN \
         ('raw-two-labels', 'raw-inbox-only', 'raw-foreign-two-labels', 'raw-foreign-inbox-only')",
    )
    .await?;
    Ok(())
}

pub async fn fixture(c: &Client, spec: &Spec) -> Result<Fx, BoxError> {
    clear_orphans(c).await?;
    let mut names = Names::new();
    let a = account(c, "recorded-email", "", &mut names).await?;
    let f = if spec.foreign {
        match account(c, "recorded-foreign", "foreign", &mut names).await {
            Ok(f) => Some(f),
            Err(e) => {
                fixture::remove(c, &a).await?;
                return Err(e);
            }
        }
    } else {
        None
    };
    let mut extra = BTreeMap::new();
    for (key, name) in [("trash", "Trash"), ("starred", "Starred")] {
        let rows = c
            .query_typed(
                "SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2",
                &[(&a.mailbox, Type::INT8), (&name, Type::TEXT)],
            )
            .await?;
        extra.insert(key, rows[0].get::<_, i64>(0));
    }
    Ok(Fx { a, f, names, extra })
}

pub async fn seed(c: &Client, fx: &mut Fx, seed: Seed) -> Result<(), BoxError> {
    c.query_typed(
        "DELETE FROM blobs WHERE sha256=$1 AND ref_count=0",
        &[(&UPLOAD_BLOB, Type::TEXT)],
    )
    .await?;

    match seed {
        Seed::Identities => {
            for (a, email, key) in [
                (Some(&fx.a), "owner@oracle.example", "alias"),
                (fx.f.as_ref(), "foreign@oracle.example", "foreign-alias"),
            ] {
                if let Some(a) = a {
                    c.query_typed("UPDATE users SET email=$2,display_name='Identity Owner',first_name='Given',last_name='Family',updated_at='2026-01-01' WHERE id=$1",&[(&a.user,Type::INT8),(&email,Type::TEXT)]).await?;
                    let alias = format!("alias-{email}");
                    let rows=c.query_typed("INSERT INTO aliases(mailbox_id,domain_id,email,display_name,signature,reply_to) VALUES($1,$2,$3,'Alias Name','Old signature','reply@oracle.example') RETURNING id",&[(&a.mailbox,Type::INT8),(&a.domain,Type::INT8),(&alias,Type::TEXT)]).await?;
                    let id: i64 = rows[0].get(0);
                    fx.names.insert(id, format!("<{key}>"));
                    fx.extra.insert(key, id);
                }
            }
            Ok(())
        }
        Seed::RecoveryS3 => Ok(()),
        Seed::Transfer => {
            let id = register_native(c, fx).await?;
            seed_blobs(c, fx).await?;
            c.query_typed("UPDATE user_devices SET offline_opt_in=true,offline_approval='approved',automatic_network_pref='any',background_sync_enabled=true WHERE id=$1 AND user_id=$2",&[(&id,Type::INT8),(&fx.a.user,Type::INT8)]).await?;
            let rows=c.query_typed("INSERT INTO offline_policies(name,scope_type,scope_id,enabled,max_offline_days,require_approval,automatic_network_max,attachment_prefetch_max,connectivity_sync_mode,background_sync_allowed) VALUES('JMAP2 transfer policy','user',$1,true,30,true,'any','always','execute',true) RETURNING id",&[(&fx.a.user,Type::INT8)]).await?;
            fx.names.insert(rows[0].get(0), "<offline-policy>".into());
            Ok(())
        }
        Seed::RecoveryRaw => {
            c.query_typed(
                "UPDATE messages SET raw_ref=$3 WHERE mailbox_id=$1 AND id=$2",
                &[
                    (&fx.a.mailbox, Type::INT8),
                    (&fx.a.inbox_only, Type::INT8),
                    (
                        &"From: oracle@example.test\r\nSubject: Recovery\r\n\r\nJMAP2 raw body\r\n",
                        Type::TEXT,
                    ),
                ],
            )
            .await?;
            Ok(())
        }
        Seed::SessionAdmin => {
            c.query_typed("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,4,$1)",&[(&fx.a.user,Type::INT8)]).await?;
            Ok(())
        }
        Seed::SessionConfigured => {
            c.batch_execute("INSERT INTO system_config(key,value) VALUES ('brand_name','\"Go <Team>\"'),('brand_logo_url','\"https://example.test/logo?a=1&b=2\"'),('help_email','\"help@example.test\"'),('apps_caps_strict','\"TrUe\"') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value; INSERT INTO feature_toggles(key,enabled) VALUES ('feature.shared_task_lists',true),('dengbao.sod_mode',true) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled;").await?;
            c.query_typed(
                "UPDATE mailboxes SET deleted_purge_days=7,spam_purge_days=11 WHERE id=$1",
                &[(&fx.a.mailbox, Type::INT8)],
            )
            .await?;
            Ok(())
        }
        Seed::SessionNative => {
            register_native(c, fx).await?;
            Ok(())
        }

        Seed::Focus => {
            for id in [Some(fx.a.inbox_only), Some(fx.a.two_labels), fx.f.as_ref().map(|f| f.inbox_only)].into_iter().flatten() {
                c.query_typed("UPDATE messages SET from_addr='Sender@Oracle.Example' WHERE id=$1",&[(&id,Type::INT8)]).await?;
            }
            Ok(())
        }
        Seed::RawDownload => {
            seed_blobs(c, fx).await?;
            for (account, hash) in [(Some(&fx.a), OWN_BLOB), (fx.f.as_ref(), FOREIGN_BLOB)] {
                if let Some(a) = account {
                    c.query_typed("UPDATE messages SET raw_ref=$2,subject='Q3 report: draft/final' WHERE id=$1",&[(&a.inbox_only,Type::INT8),(&hash,Type::TEXT)]).await?;
                }
            }
            Ok(())
        }
        Seed::Zip | Seed::ZipLarge => {
            let missing = MISSING_BLOB.to_owned();
            for (account, hash, size) in [(Some(&fx.a), OWN_BLOB, 22i64), (Some(&fx.a), missing.as_str(), 5), (fx.f.as_ref(), FOREIGN_BLOB, 25)] {
                if let Some(a) = account {
                    c.query_typed("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,$3,'text/plain',0) ON CONFLICT DO NOTHING",&[(&hash,Type::TEXT),(&format!("mailblobs/{hash}"),Type::TEXT),(&size,Type::INT8)]).await?;
                    let _ = a;
                }
            }
            c.query_typed("UPDATE messages SET subject='Re: Q3 report / plan' WHERE id=$1",&[(&fx.a.inbox_only,Type::INT8)]).await?;
            for (message, hash, name, disposition) in [
                (fx.a.inbox_only, OWN_BLOB, Some("report.pdf"), "attachment"),
                (fx.a.inbox_only, OWN_BLOB, Some("report.pdf"), "attachment"),
                (fx.a.inbox_only, OWN_BLOB, Some("../evil name.txt"), "attachment"),
                (fx.a.inbox_only, missing.as_str(), Some("gone.bin"), "attachment"),
                (fx.a.inbox_only, OWN_BLOB, Some("logo.png"), "inline"),
                (fx.a.inbox_only, OWN_BLOB, None, "attachment"),
                (fx.a.inbox_only, OWN_BLOB, Some(".."), "attachment"),
            ] {
                c.query_typed("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes,disposition) SELECT id,received_at,$2,$3,'text/plain',22,$4 FROM messages WHERE id=$1",&[(&message,Type::INT8),(&hash,Type::TEXT),(&name,Type::TEXT),(&disposition,Type::TEXT)]).await?;
            }
            if seed == Seed::ZipLarge {
                c.query_typed("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,$3,'application/octet-stream',0) ON CONFLICT DO NOTHING",&[(&LARGE_BLOB,Type::TEXT),(&format!("mailblobs/{LARGE_BLOB}"),Type::TEXT),(&(LARGE_SIZE as i64),Type::INT8)]).await?;
                for name in ["big.bin", "big.bin"] {
                    c.query_typed("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes) SELECT id,received_at,$2,$3,'application/octet-stream',70000 FROM messages WHERE id=$1",&[(&fx.a.inbox_only,Type::INT8),(&LARGE_BLOB,Type::TEXT),(&name,Type::TEXT)]).await?;
                }
            }
            if let Some(f) = fx.f.as_ref() {
                c.query_typed("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes) SELECT id,received_at,$2,'secret.txt','text/plain',25 FROM messages WHERE id=$1",&[(&f.inbox_only,Type::INT8),(&FOREIGN_BLOB,Type::TEXT)]).await?;
            }
            Ok(())
        }
        Seed::RawDownloadLarge => {
            c.query_typed("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,$3,'application/octet-stream',0)",&[(&LARGE_BLOB,Type::TEXT),(&format!("mailblobs/{LARGE_BLOB}"),Type::TEXT),(&(LARGE_SIZE as i64),Type::INT8)]).await?;
            c.query_typed("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes) SELECT id,received_at,$2,'big.bin','application/octet-stream',70000 FROM messages WHERE id=$1",&[(&fx.a.two_labels,Type::INT8),(&LARGE_BLOB,Type::TEXT)]).await?;
            c.query_typed("UPDATE messages SET raw_ref=$2,subject=NULL WHERE id=$1",&[(&fx.a.two_labels,Type::INT8),(&LARGE_BLOB,Type::TEXT)]).await?;
            Ok(())
        }
        Seed::Unsub(header) | Seed::UnsubFull(header) => {
            if matches!(seed, Seed::UnsubFull(_)) {
                c.query_typed("UPDATE audit_policy SET level='full' WHERE id=1 AND level<>'full'",&[]).await?;
                fx.extra.insert("audit-raised", 1);
            }
            let header = if header.is_empty() { None } else { Some(header) };
            for id in [Some(fx.a.inbox_only), fx.f.as_ref().map(|f| f.inbox_only)].into_iter().flatten() {
                c.query_typed("UPDATE messages SET list_unsubscribe=$2,from_addr='news@news.example' WHERE id=$1",&[(&id,Type::INT8),(&header,Type::TEXT)]).await?;
            }
            Ok(())
        }
        Seed::None => Ok(()),
        Seed::DelegatedSendAs | Seed::DelegatedRead => {
            let f = fx.f.as_ref().unwrap();
            c.query_typed(
                "UPDATE domains SET name='gofree-jmap2-delegate.test' WHERE id=$1",
                &[(&f.domain, Type::INT8)],
            )
            .await?;
            c.query_typed("UPDATE users SET username='delegate@gofree-jmap2-delegate.test',email='delegate@gofree-jmap2-delegate.test' WHERE id=$1",&[(&f.user,Type::INT8)]).await?;
            c.query_typed("UPDATE mailboxes SET email='delegate@gofree-jmap2-delegate.test',display_name='Delegated Team' WHERE id=$1 AND user_id=$2",&[(&f.mailbox,Type::INT8),(&f.user,Type::INT8)]).await?;
            let permission = if seed == Seed::DelegatedSendAs {
                "send_as"
            } else {
                "read"
            };
            c.query_typed("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES($1,$2,$3,$4)",&[(&f.mailbox,Type::INT8),(&fx.a.user,Type::INT8),(&permission,Type::TEXT),(&f.user,Type::INT8)]).await?;
            c.query_typed("INSERT INTO aliases(mailbox_id,domain_id,email,display_name) VALUES($1,$2,'alias@gofree-jmap2-delegate.test','Alternate')",&[(&f.mailbox,Type::INT8),(&f.domain,Type::INT8)]).await?;
            Ok(())
        }

        Seed::Blobs | Seed::DelegatedBlob => {
            if seed == Seed::DelegatedBlob {
                let f = fx.f.as_ref().unwrap();
                c.query_typed("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES($1,$2,'read',$3)",&[(&f.mailbox,Type::INT8),(&fx.a.user,Type::INT8),(&f.user,Type::INT8)]).await?;
            }

            seed_blobs(c, fx).await?;
            Ok(())
        }

        Seed::Attachment => {
            c.query_typed(
                "UPDATE messages SET has_attachments=true WHERE mailbox_id=$1 AND id=$2",
                &[(&fx.a.mailbox, Type::INT8), (&fx.a.inbox_only, Type::INT8)],
            )
            .await?;
            Ok(())
        }

        Seed::BrokenScheduled => {
            c.query_typed("SELECT enqueue_scheduled_action('send','2099-01-02T03:04:05Z'::timestamptz,'{\"message_id\":\"abc\"}'::jsonb,$1)",&[(&fx.a.mailbox,Type::INT8)]).await?;
            Ok(())
        }
        Seed::RecallExpired => {
            let id=c.query_typed("INSERT INTO messages(mailbox_id,folder_id,message_id,subject,from_addr,raw_ref,received_at,size_bytes,thread_id) VALUES($1,get_tag_id('Inbox',$1),'<expired@oracle.test>','oracle','x@test','raw-expired',now()-interval '1 hour',10,'expired@oracle.test') RETURNING id",&[(&fx.a.mailbox,Type::INT8)]).await?[0].get::<_,i64>(0);
            fx.extra.insert("expired", id);
            fx.names.insert(id, "<expired>".into());
            Ok(())
        }
        Seed::Recall | Seed::RecallAlias => {
            c.query_typed("UPDATE messages SET from_addr='x@test',sent_at='2026-01-02T03:04:05Z' WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            let f = fx.f.as_ref().unwrap();
            c.query_typed("UPDATE messages SET message_id='<inbox-only@oracle.test>',from_addr='x@test' WHERE mailbox_id=$1 AND id=$2",&[(&f.mailbox,Type::INT8),(&f.inbox_only,Type::INT8)]).await?;
            if seed == Seed::RecallAlias {
                c.query_typed("INSERT INTO aliases(mailbox_id,email,domain_id) SELECT id,'jmap3-alias@oracle.test',domain_id FROM mailboxes WHERE id=$1",&[(&fx.a.mailbox,Type::INT8)]).await?;
                c.query_typed("UPDATE messages SET from_addr='jmap3-alias@oracle.test' WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            }
            Ok(())
        }
        Seed::Undo | Seed::UndoExpired | Seed::UndoSharedId => {
            c.query_typed("SELECT tag_message(id,received_at,'Sent',mailbox_id,'send',true) FROM messages WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            c.query_typed("SELECT enqueue_scheduled_action('send','2099-01-02T03:04:05Z'::timestamptz,jsonb_build_object('message_id',id,'received_at',received_at,'undo',true),mailbox_id) FROM messages WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            c.query_typed("INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status,next_attempt_at,mailbox_id) SELECT message_id,from_addr,ARRAY['recipient@external.test'],raw_ref,'deferred','2099-01-02T03:04:05Z',mailbox_id FROM messages WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            c.query_typed("INSERT INTO outbound_queue_hot(message_id,from_addr,rcpt_addrs,raw_ref,status,mailbox_id,message_pk) SELECT message_id,from_addr,ARRAY['recipient@external.test'],raw_ref,'pending',mailbox_id,id FROM messages WHERE mailbox_id=$1 AND id=$2",&[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8)]).await?;
            if seed == Seed::UndoExpired {
                c.query_typed("UPDATE outbound_queue SET next_attempt_at=now()-interval '1 hour' WHERE mailbox_id=$1",&[(&fx.a.mailbox,Type::INT8)]).await?;
                c.query_typed("UPDATE scheduled_actions SET fire_at=now()-interval '1 hour' WHERE mailbox_id=$1",&[(&fx.a.mailbox,Type::INT8)]).await?;
            }
            if seed == Seed::UndoSharedId {
                let f = fx.f.as_ref().unwrap();
                c.query_typed("INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status,next_attempt_at,mailbox_id) VALUES('<inbox-only@oracle.test>','foreign@oracle.test',ARRAY['foreign@external.test'],'raw-foreign-inbox-only','deferred','2099-01-02T03:04:05Z',$1)",&[(&f.mailbox,Type::INT8)]).await?;
            }
            Ok(())
        }
        Seed::SubmissionExternal | Seed::SubmissionLocal => {
            c.query_typed(
                "UPDATE mailboxes SET email='jmap3-sender@oracle.test' WHERE id=$1",
                &[(&fx.a.mailbox, Type::INT8)],
            )
            .await?;
            let recipient = if seed == Seed::SubmissionLocal {
                let f = fx.f.as_ref().unwrap();
                c.query_typed(
                    "UPDATE domains SET name='jmap3-recipient.test' WHERE id=$1",
                    &[(&f.domain, Type::INT8)],
                )
                .await?;
                c.query_typed(
                    "UPDATE mailboxes SET email='recipient@jmap3-recipient.test' WHERE id=$1",
                    &[(&f.mailbox, Type::INT8)],
                )
                .await?;
                "recipient@jmap3-recipient.test"
            } else {
                "recipient@external.test"
            };
            let to = format!(r#"[{{"email":"{recipient}"}}]"#);
            c.query_typed("UPDATE messages SET from_addr='jmap3-sender@oracle.test',to_addrs=$3::text::jsonb,body_text='submission body' WHERE mailbox_id=$1 AND id=$2",
                &[(&fx.a.mailbox,Type::INT8),(&fx.a.inbox_only,Type::INT8),(&to,Type::TEXT)]).await?;
            Ok(())
        }
        Seed::TwoScheduled => {
            for (id, date) in [
                (fx.a.inbox_only, "2099-01-02T03:04:05Z"),
                (fx.a.two_labels, "2099-01-03T03:04:05Z"),
            ] {
                c.query_typed(
                    "SELECT message_schedule($1,$2,$3::text::timestamptz)",
                    &[
                        (&fx.a.mailbox, Type::INT8),
                        (&id, Type::INT8),
                        (&date, Type::TEXT),
                    ],
                )
                .await?;
            }
            Ok(())
        }
        Seed::Scheduled => {
            c.query_typed(
                "SELECT message_schedule($1,$2,'2099-01-02T03:04:05Z'::timestamptz)",
                &[(&fx.a.mailbox, Type::INT8), (&fx.a.inbox_only, Type::INT8)],
            )
            .await?;
            Ok(())
        }
        Seed::Deleted => {
            for _ in 0..2 {
                c.query_typed(
                    "SELECT jmap_email_set_destroy($1, ARRAY[$2]::bigint[])",
                    &[(&fx.a.mailbox, Type::INT8), (&fx.a.inbox_only, Type::INT8)],
                )
                .await?;
            }
            Ok(())
        }
        Seed::Stale => {
            let id = c
                .query_typed(
                    "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, \
                     thread_id, raw_ref, received_at, is_read) \
                     VALUES ($1, $2, '<stale@oracle.test>', 'stale', 'sender@elsewhere.test', 10, \
                             'thr-stale', 'raw-stale', now() - interval '5 days', true) RETURNING id",
                    &[(&fx.a.mailbox, Type::INT8), (&fx.a.inbox, Type::INT8)],
                )
                .await?[0]
                .get::<_, i64>(0);
            c.query_typed(
                "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) \
                 SELECT id, received_at, $2, 'system', true FROM messages WHERE id = $1",
                &[(&id, Type::INT8), (&fx.a.inbox, Type::INT8)],
            )
            .await?;
            fx.names.insert(id, "<stale>".into());
            Ok(())
        }
        Seed::Newsletter => {
            for id in [fx.a.two_labels, fx.a.inbox_only] {
                c.query_typed(
                    "UPDATE messages SET list_id = '<news.oracle.test>' WHERE id = $1",
                    &[(&id, Type::INT8)],
                )
                .await?;
            }
            Ok(())
        }
    }
}

pub async fn remove(c: &Client, fx: &Fx) -> Result<(), BoxError> {
    clear_orphans(c).await?;
    if fx.extra.contains_key("audit-raised") {
        c.query_typed("UPDATE audit_policy SET level='lean' WHERE id=1",&[]).await?;
    }
    c.query_typed(
        "DELETE FROM offline_policies WHERE scope_type='user' AND scope_id=$1",
        &[(&fx.a.user, Type::INT8)],
    )
    .await?;
    c.query_typed(
        "DELETE FROM admin_role_assignments WHERE user_id=$1",
        &[(&fx.a.user, Type::INT8)],
    )
    .await?;
    for a in std::iter::once(&fx.a).chain(fx.f.iter()) {
        c.query_typed(
            "DELETE FROM message_recalls WHERE recalled_by=$1",
            &[(&a.user, Type::INT8)],
        )
        .await?;
        for table in ["outbound_queue_hot", "outbound_queue"] {
            c.query_typed(
                &format!("DELETE FROM {table} WHERE mailbox_id=$1"),
                &[(&a.mailbox, Type::INT8)],
            )
            .await?;
        }
    }
    fixture::remove(c, &fx.a).await?;
    if let Some(f) = &fx.f {
        fixture::remove(c, f).await?;
    }
    c.query_typed(
        "DELETE FROM blobs WHERE sha256=ANY($1::text[]) AND ref_count=0",
        &[(&vec![OWN_BLOB, FOREIGN_BLOB, UPLOAD_BLOB, LARGE_BLOB, MISSING_BLOB], Type::TEXT_ARRAY)],
    )
    .await?;
    let users = vec![fx.a.user, fx.f.as_ref().map(|a| a.user).unwrap_or(0)];
    c.query_typed(
        "DELETE FROM blob_user_usage WHERE user_id=ANY($1::bigint[])",
        &[(&users, Type::INT8_ARRAY)],
    )
    .await?;
    Ok(())
}

pub const UPLOAD_BLOB: &str = "569a2b7acf8d8a3e7d1c8dbccf2bafe414b6aa47bfefb9275f1b4a69ac405324";
pub const OWN_BLOB: &str = "abc31963fb81ff310085911d605a50ffc77fbc9c4deea365fad21cc30a7135dc";
pub const LARGE_BLOB: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
pub const MISSING_BLOB: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
pub const LARGE_SIZE: usize = 70000;
/// Deterministic bytes of the large blob.
pub fn large_bytes() -> Vec<u8> {
    (0..LARGE_SIZE).map(|i| if i % 61 == 60 { b'\n' } else { b'a' + (i * 7 % 26) as u8 }).collect()
}
pub const FOREIGN_BLOB: &str = "9440531d9ce2037edb8a0f680af235cff4a963e6d1a9d6c1e01fbdcfdfd9f9fc";

async fn register_native(c: &Client, fx: &mut Fx) -> Result<i64, BoxError> {
    let rows = c
        .query_typed(
            "SELECT offline_device_register($1,'gofree-jmap2-device','desktop')",
            &[(&fx.a.mailbox, Type::INT8)],
        )
        .await?;
    let id: i64 = rows[0].get(0);
    fx.names.insert(id, "<native-device>".into());
    fx.extra.insert("native-device", id);
    Ok(id)
}
async fn seed_blobs(c: &Client, fx: &Fx) -> Result<(), BoxError> {
    for (account, hash, bytes) in [
        (Some(&fx.a), OWN_BLOB, b"JMAP2 attachment body\n".as_slice()),
        (
            fx.f.as_ref(),
            FOREIGN_BLOB,
            b"JMAP2 foreign attachment\n".as_slice(),
        ),
    ] {
        if let Some(a) = account {
            c.query_typed("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,$3,'text/plain',0)", &[(&hash, Type::TEXT), (&format!("mailblobs/{hash}"), Type::TEXT), (&(bytes.len() as i64), Type::INT8)]).await?;
            c.query_typed("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,size_bytes) SELECT id,received_at,$3,'proof.txt','text/plain',$4 FROM messages WHERE id=$1 AND mailbox_id=$2", &[(&a.two_labels,Type::INT8), (&a.mailbox,Type::INT8), (&hash,Type::TEXT), (&(bytes.len() as i64),Type::INT8)]).await?;
        }
    }
    Ok(())
}

fn submission(method: &str, args: &str) -> String {
    format!(
        r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:submission"],"methodCalls":[["{method}",{args},"0"]]}}"#
    )
}

fn create(fx: &Fx, extra: &str) -> String {
    submission(
        "EmailSubmission/set",
        &format!(
            r#"{{"accountId":"{}","create":{{"s":{{"emailId":"{}"{extra}}}}}}}"#,
            fx.a.mailbox, fx.a.inbox_only
        ),
    )
}
