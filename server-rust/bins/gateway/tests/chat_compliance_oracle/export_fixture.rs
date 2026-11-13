use super::*;
use sha2::{Digest, Sha256};
pub const A: &[u8] = b"Evidence chunk A\n";
pub const B: &[u8] = b"\x00binary B<>\xff";
pub async fn attachments(owner: &tokio_postgres::Client, actor: i64) -> Result<(), BoxError> {
    let mut body = A.to_vec();
    body.extend_from_slice(B);
    let sha = format!("{:x}", Sha256::digest(&body));
    let ca = format!("{:x}", Sha256::digest(A));
    let cb = format!("{:x}", Sha256::digest(B));
    owner.execute("INSERT INTO drive_spaces(id,name,owner_user_id) OVERRIDING SYSTEM VALUE VALUES(963001,'compl3-attachments',$1)",&[&actor]).await?;
    owner.execute("INSERT INTO drive_nodes(id,space_id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES(963101,963001,'file','Evidence.bin',$1)",&[&actor]).await?;
    owner
        .batch_execute("INSERT INTO drive_files(node_id,space_id) VALUES(963101,963001)")
        .await?;
    owner.execute("INSERT INTO drive_file_versions(id,file_node_id,space_id,content_sha256,size_bytes,author_user_id) OVERRIDING SYSTEM VALUE VALUES (963201,963101,963001,$1,29,$2),(963202,963101,963001,$1,29,$2)",&[&sha,&actor]).await?;
    owner.execute("INSERT INTO drive_chunks(scope_key,sha256,size_bytes,storage_ref) VALUES ('g',$1,17,'compl3-chunk-A'),('g',$2,12,'compl3-chunk-B')",&[&ca,&cb]).await?;
    owner.execute("INSERT INTO drive_version_chunks(version_id,ordinal,scope_key,chunk_sha256) VALUES(963201,0,'g',$1),(963201,1,'g',$2),(963202,0,'g',$1),(963202,1,'g',$2)",&[&ca,&cb]).await?;
    owner.batch_execute("INSERT INTO chat_message_attachments(id,channel_id,message_id,file_node_id,version_id,filename,size_bytes,ordinal) OVERRIDING SYSTEM VALUE VALUES (963301,961001,966001,963101,963201,'One.bin',29,0),(963302,961001,966001,963101,963202,'Two.bin',29,1)").await?;
    Ok(())
}
pub async fn cleanup(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner.batch_execute("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM chat_message_attachments WHERE id BETWEEN 963300 AND 963399;DELETE FROM drive_version_chunks WHERE version_id BETWEEN 963200 AND 963299;DELETE FROM drive_file_versions WHERE id BETWEEN 963200 AND 963299;DELETE FROM drive_files WHERE node_id=963101;DELETE FROM drive_nodes WHERE id=963101;DELETE FROM drive_spaces WHERE id=963001;DELETE FROM drive_chunks WHERE storage_ref IN ('compl3-chunk-A','compl3-chunk-B');COMMIT").await?;
    Ok(())
}
