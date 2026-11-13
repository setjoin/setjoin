//! Independent offline-update signing and on-disk observation for #455.
use crate::common::BoxError;
use base64::{engine::general_purpose::STANDARD_NO_PAD,Engine};
use ring::signature::{Ed25519KeyPair,KeyPair};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{io::Write,path::PathBuf};
pub const UPLOADED:&[u8]=b"Setjoin offline update replacement\n";
pub const PAYLOAD:&[u8]=b"Setjoin offline update fixture\n";
pub struct Fixture {pub root:PathBuf,pub metadata:String,pub expiry:String,pub upload_metadata:String}
impl Fixture {
    pub fn new(user:i64,mode:&str)->Result<Self,BoxError> {
        let ledger=std::env::var("GOFREE_RESOURCE_LEDGER").ok();
        let base=std::env::var_os("GOFREE_AIRGAP_FIXTURE_ROOT").map(PathBuf::from).unwrap_or_else(||ledger.as_ref().and_then(|path|std::path::Path::new(path).parent()).map(std::path::Path::to_owned).unwrap_or_else(std::env::temp_dir));
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let root=base.join(format!("gofree-plat2b-airgap-{user}-{nonce}"));
        if let Some(ledger)=ledger {writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Owned airgap fixture {} (removed by Drop)",root.display())?;}
        std::fs::create_dir(&root)?;
        let mut fixture=Self{root,metadata:String::new(),upload_metadata:String::new(),expiry:(chrono::Utc::now()+chrono::Duration::hours(if mode=="expired" {-1}else{24})).to_rfc3339_opts(chrono::SecondsFormat::Secs,true)};
        std::fs::create_dir(fixture.root.join("store"))?;
        let key=Ed25519KeyPair::from_seed_unchecked(&[45;32]).map_err(|_|"oracle Ed25519 key")?;
        let public=STANDARD_NO_PAD.encode(key.public_key().as_ref());
        std::fs::write(fixture.root.join("trust.json"),json!({"schema_version":1,"purpose":"offline-update","keys":[{"id":"offline-oracle","algorithm":"ed25519","public_key":public,"test_only":false}]}).to_string())?;
        let hash=format!("{:x}",Sha256::digest(PAYLOAD));
        // Frozen Go targetMetadata struct field order, independent of the port.
        let unsigned=format!("{{\"schema_version\":1,\"metadata_version\":1,\"expires_at\":\"{}\",\"slug\":\"linux-amd64\",\"version\":\"1.2.3\",\"platform\":\"desktop\",\"filename\":\"bundle.bin\",\"size_bytes\":{},\"sha256\":\"{hash}\",\"key_id\":\"offline-oracle\",\"signature\":\"\"}}",fixture.expiry,PAYLOAD.len());
        let mut signature=STANDARD_NO_PAD.encode(key.sign(unsigned.as_bytes()).as_ref());
        if mode=="tampered" {signature.replace_range(0..1,if signature.starts_with('A'){"B"}else{"A"});}
        fixture.metadata=unsigned.replace("\"signature\":\"\"",&format!("\"signature\":\"{signature}\""));
        let upload_hash=format!("{:x}",Sha256::digest(UPLOADED));
        let version=if matches!(mode,"rollback") {1}else{2};
        let unsigned_upload=unsigned.replace("\"metadata_version\":1",&format!("\"metadata_version\":{version}"))
            .replace("\"version\":\"1.2.3\"","\"version\":\"1.2.4\"")
            .replace("\"filename\":\"bundle.bin\"","\"filename\":\"bundle-v2.bin\"")
            .replace(&hash,&upload_hash).replace(&format!("\"size_bytes\":{}",PAYLOAD.len()),&format!("\"size_bytes\":{}",UPLOADED.len()));
        let mut signature=STANDARD_NO_PAD.encode(key.sign(unsigned_upload.as_bytes()).as_ref());
        if mode=="bad-signature" {signature.replace_range(0..1,if signature.starts_with('A'){"B"}else{"A"});}
        fixture.upload_metadata=unsigned_upload.replace("\"signature\":\"\"",&format!("\"signature\":\"{signature}\""));
        let bundle=json!({"version":"1.2.3","platform":"desktop","slug":"linux-amd64","filename":"bundle.bin","sha256":hash,"size_bytes":PAYLOAD.len(),"uploaded_at":"2026-10-01T00:00:00Z","metadata_version":1,"expires_at":fixture.expiry,"key_id":"offline-oracle","target_metadata":fixture.metadata});
        std::fs::write(fixture.root.join("store/linux-amd64.json"),bundle.to_string())?;
        std::fs::write(fixture.root.join("store/linux-amd64_bundle.bin"),PAYLOAD)?;
        let modified=std::time::UNIX_EPOCH+std::time::Duration::from_secs(chrono::DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")?.timestamp() as u64);
        std::fs::File::options().write(true).open(fixture.root.join("store/linux-amd64_bundle.bin"))?.set_times(std::fs::FileTimes::new().set_modified(modified))?;
        if mode=="no-roots" {std::fs::remove_file(fixture.root.join("trust.json"))?;}
        Ok(fixture)
    }
    pub fn environment(&self)->Vec<(&'static str,String)> {vec![
        ("--volume",format!("{}:/oracle-airgap",self.root.display())),
        ("--volume",format!("{}:/var/lib/setjoin/updates",self.root.join("store").display())),
        ("OFFLINE_UPDATE_TRUST_ROOTS","/oracle-airgap/trust.json".into()),
    ]}
    pub fn response(&self,status:u16,raw:&str)->Result<String,BoxError> {
        if status!=200{return Ok(raw.into());}
        let bundle:Value=serde_json::from_str(raw)?;
        let target:Value=serde_json::from_str(&self.upload_metadata)?;
        if bundle["target_metadata"]!=json!(self.upload_metadata) {return Err("upload response changed signed target".into());}
        for key in ["slug","version","platform","filename","sha256","size_bytes","metadata_version","key_id"] {if bundle[key]!=target[key]{return Err(format!("upload response does not match signed {key}").into());}}
        Ok(raw.replace(&serde_json::to_string(&self.upload_metadata)?,"\"<verified-signed-target>\""))
    }
    pub fn snapshot(&self)->Result<Value,BoxError> {
        let mut files=vec![];
        for file in std::fs::read_dir(self.root.join("store"))? {
            let file=file?;let name=file.file_name().to_string_lossy().into_owned();let raw=std::fs::read(file.path())?;
            if name.ends_with(".json") {
                let mut value:Value=serde_json::from_slice(&raw)?;
                if (value["target_metadata"]!=json!(self.metadata) && value["target_metadata"]!=json!(self.upload_metadata)) || value["expires_at"]!=json!(self.expiry){return Err("persisted signed target differs from admitted fixture".into());}
                if value["metadata_version"].as_u64().is_some_and(|n|n>1) {
                    use std::os::unix::fs::PermissionsExt;
                    if file.metadata()?.permissions().mode()&0o777!=0o640{return Err("published metadata is not0640".into());}
                    let uploaded=chrono::DateTime::parse_from_rfc3339(value["uploaded_at"].as_str().ok_or("missing upload time")?)?;
                    if (uploaded.with_timezone(&chrono::Utc)-chrono::Utc::now()).num_seconds().abs()>120{return Err("upload time is not current".into());}
                    value["uploaded_at"]=json!("<timestamp>");
                }
                value["target_metadata"]=json!("<verified-signed-target>");value["expires_at"]=json!("<expiry>");
                files.push(json!({"name":name,"json":value}));
            }else{
                if name.ends_with("bundle-v2.bin") {use std::os::unix::fs::PermissionsExt;if file.metadata()?.permissions().mode()&0o777!=0o600{return Err("published update is not0600".into());}}
                files.push(json!({"name":name,"size":raw.len(),"sha256":format!("{:x}",Sha256::digest(raw))}));}
        }
        files.sort_by_key(|v|v["name"].as_str().unwrap_or("").to_owned());Ok(json!(files))
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.root);}}
