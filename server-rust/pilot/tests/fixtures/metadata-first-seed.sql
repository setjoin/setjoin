-- ISSUE 204, SOURCE CANDIDATE ONLY. Not an executable standalone script.
-- Commit 4399a2f5eacbfa50206bcbc84883f7b40a53bf6b; tree
-- 4bbaa6153513646a2bf9e7f3fb4aa7ef4e3aa0e0. Fixture JSON SHA256
-- a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934;
-- fixture contract ca21c4123b119b7ff82a8a14f8a23bdbf1f52d42e99974f90245b647f70950b6;
-- accepted mapping 73434dafa967a815add90f1af13a495eff60db2bc2fb18cadf7cb5817a104acf;
-- inventory 557b1a3090e8a79bd595a4a3657295108bed2044cdd2891d954aabec4b790eda;
-- FTS contract bd6159b6534d5bbd56fdfe63af2b47f384eee427d179c7916e146394da4d5055;
-- FTS inputs 5cd6d832548d1d26ab12eda2336cd109ecb21263d3917266eecf3135c2bf57fb.
--
-- Execution HOLD: role/connection/target/transaction ownership, exact schema,
-- installed functions, trigger state and partitions, independent whole-row and
-- bystander oracle, and independently generated/verified FTS goldens must be
-- admitted first. This source is not a loader or authorization. Caller owns a
-- single transaction and its isolation/conflict strategy, bindings, rollback,
-- unknown-commit recovery and commit verification. No success receipt before a
-- verified commit. No ON CONFLICT adoption, retries, sequence adjustment, trigger
-- disabling, schema/role/grant changes, object-byte I/O or automatic cleanup.
-- Required source branch: migrations through pinned final schema including V029,
-- V075, V078, V085, V156, V164, V182, V197, V199, V201, V249, V272 and
-- the pinned imap_membership_uid_allocate reducer and BEFORE INSERT trigger,
-- all required parent/partition triggers enabled. Require the disposable target,
-- role, partition routing and exact definitions before any write. Reject any
-- mismatch. Every named SELECT/RETURNING below must yield exactly the stated
-- number of rows, otherwise abort and reconcile. Generated identifiers are
-- distinct bindings in distinct namespaces, not literals or claims of authority.
-- No result row is itself the independent expected-state oracle.
--
-- Frozen proposed constants, not fixture-provided physical IDs:
-- D='t03-metadata.fixture.test'; owner user='t03-owner', email
-- 't03-owner@t03-metadata.fixture.test', display='T03 Owner'; other user=
-- 't03-other', email='t03-other@t03-metadata.fixture.test', display='T03 Other'.
-- Blob label B=64 ASCII '0' characters (metadata identifier, NOT byte hash),
-- reference 'metadata-only/t03/fixture-blob', size=51, type='text/plain',
-- ref_count=0. Raw refs 'metadata-only/t03/root' and 'metadata-only/t03/reply'
-- are synthetic references and do not establish object existence.
-- Physical ID, raw-ref, blob label, size, quota and principal proposal require
-- separate admission. Reject any conflicting/preexisting row; do not adopt it.
--
-- [01] Transaction-local FTS setting; caller verifies effective setting is
-- exactly false on this same transaction and connection before message writes.
SET LOCAL app.skip_fts = 'false';

-- [02] Collision preflight: parameters $1=D, $2=owner email, $3=other email,
-- $4=owner username, $5=other username, $6=B. One row of ten zero counts
-- required. Independent isolation/locking must cover races, all reachable
-- conflicts and address claims, including aliases and identity admission.
-- The separate setup authority must prove effective visibility of V249 FORCE-RLS
-- quarantine rows; a filtered zero is not proof of absence. No runtime role
-- grant or RLS change is authorized here.
SELECT
 (SELECT count(*) FROM public.domains WHERE lower(name)=lower($1::text)) AS domain_matches,
 (SELECT count(*) FROM public.users WHERE lower(email) IN (lower($2::text),lower($3::text)) OR lower(ad_upn) IN (lower($2::text),lower($3::text)) OR username IN ($4::text,$5::text)) AS user_matches,
 (SELECT count(*) FROM public.mailboxes WHERE lower(email) IN (lower($2::text),lower($3::text))) AS mailbox_matches,
 (SELECT count(*) FROM public.aliases WHERE lower(email) IN (lower($2::text),lower($3::text))) AS alias_matches,
 (SELECT count(*) FROM public.mailbox_address_claims WHERE normalized_address IN (lower($2::text),lower($3::text))) AS claim_matches,
 (SELECT count(*) FROM public.identity_address_quarantine WHERE address IN (lower($2::text),lower($3::text))) AS quarantine_matches,
 (SELECT count(*) FROM public.blobs WHERE sha256=$6::text) AS blob_matches,
 (SELECT count(*) FROM public.messages WHERE message_id IN ('<t03-root@fixture.test>','<t03-reply@fixture.test>') OR raw_ref IN ('metadata-only/t03/root','metadata-only/t03/reply')) AS message_matches,
 (SELECT count(*) FROM public.blobs WHERE minio_ref='metadata-only/t03/fixture-blob') AS blob_ref_matches,
 (SELECT count(*) FROM public.message_attachments WHERE blob_sha256=$6::text) AS attachment_matches;

-- [03] Insert domain. $1=D. Capture returned id as domain_id (one row).
INSERT INTO public.domains(name) VALUES ($1::text) RETURNING id;

-- [04] Insert owner then other as separate ordered invocations. For each:
-- $1=username, $2=domain_id, $3=email, $4=display name. Capture returned id
-- independently as owner_user_id / other_user_id (one row each). V201 seeds
-- sender_control_state; V155/V249 admission checks remain active.
INSERT INTO public.users(username,domain_id,email,display_name)
VALUES ($1::text,$2::bigint,$3::text,$4::text) RETURNING id;

-- [05] Insert owner then other mailbox, same order. For each: $1=corresponding
-- user ID, $2=domain_id, $3=email, $4=display name. Capture returned ID as
-- owner_mailbox_id / other_mailbox_id (one row each). Hooks create folders,
-- tags, lifecycle, primary claim and local authority, and quota hook updates
-- mailbox. No caller password, credential, or pre-existing account is used.
INSERT INTO public.mailboxes(user_id,domain_id,email,display_name,type,is_primary,enabled,receive_enabled,quota_bytes,sending_quota_day)
VALUES ($1::bigint,$2::bigint,$3::text,$4::text,'personal',true,true,true,1048576,100)
RETURNING id;

-- [06] For each mailbox separately, $1=mailbox ID. Exactly one row each;
-- capture folder_id as owner_inbox_folder_id / other_inbox_folder_id and
-- tag_id as owner_inbox_tag_id / other_inbox_tag_id. These are distinct
-- namespaces; no numeric equality is assumed or arranged.
SELECT f.id AS folder_id, t.id AS tag_id
FROM public.folders f JOIN public.tags t ON t.mailbox_id=f.mailbox_id
WHERE f.mailbox_id=$1::bigint AND f.name='Inbox' AND f.role='inbox'
  AND t.name='Inbox' AND t.tag_type='system';

-- [07] Insert one metadata-only blob row. $1=B, $2=synthetic minio_ref.
-- Capture returned sha256 as blob_label. This is metadata, not an object.
INSERT INTO public.blobs(sha256,minio_ref,size_bytes,content_type,ref_count)
VALUES ($1::text,$2::text,51,'text/plain',0) RETURNING sha256;

-- [08] Two ordered messages. Each has $1=owner_mailbox_id,
-- $2=owner_inbox_tag_id (legacy folder_id tag mirror), $3=Internet message ID,
-- $4=subject, $5=from_name, $6=body_text, $7=size_bytes, $8=has_attachments,
-- $9=raw_ref, $10=received_at timestamptz, $11=in_reply_to, $12=references_hdr.
-- Root: $3='<t03-root@fixture.test>'; $4='T03 t03_metadata_20261027';
-- $5='T03 Root Sender'; $6='T03 t03_metadata_20261027 root body'; $7=0;
-- $8=false; $9='metadata-only/t03/root'; $10='2026-06-14T10:00:00Z';
-- $11=NULL; $12=NULL. Capture (id,received_at) as root_id,root_received_at.
-- Reply: $3='<t03-reply@fixture.test>'; $4='Re: T03 t03_metadata_20261027';
-- $5='T03 Reply Sender'; $6='T03 t03_metadata_20261027 reply body'; $7=51;
-- $8=true; $9='metadata-only/t03/reply'; $10='2026-06-14T11:00:00Z';
-- $11=$12='<t03-root@fixture.test>'. Capture reply_id,reply_received_at.
-- All are fixed fixture values except explicitly labelled mapping proposals.
INSERT INTO public.messages(mailbox_id,folder_id,message_id,subject,from_addr,from_name,body_text,body_html,size_bytes,has_attachments,is_read,thread_id,raw_ref,received_at,in_reply_to,references_hdr,crypto_type)
VALUES ($1::bigint,$2::bigint,$3::text,$4::text,'fixture-sender@fixture.test',$5::text,$6::text,NULL,$7::bigint,$8::boolean,false,'t03-thread-001',$9::text,$10::timestamptz,$11::text,$12::text,NULL)
RETURNING id,received_at;

-- [09] Two ordered membership inserts: root then reply. $1=corresponding message
-- id, $2=its returned received_at, $3=owner_inbox_tag_id. Capture returned
-- message_id,received_at,tag_id,imap_uid; do not infer IDs or fabricate UIDs.
-- Pinned allocator branch expects UID 1 then 2 for fresh tag/empty ledger;
-- V182 counters and primary sync remain active. Later oracle compares effects.
INSERT INTO public.message_tags(message_id,received_at,tag_id,added_by,is_primary)
VALUES ($1::bigint,$2::timestamptz,$3::bigint,'fixture',true)
RETURNING message_id,received_at,tag_id,imap_uid;

-- [10] One reply attachment. $1=reply_id, $2=reply_received_at, $3=blob_label.
-- Capture returned id as attachment_id. V075 increments blob ref_count to 1.
INSERT INTO public.message_attachments(message_id,received_at,blob_sha256,filename,content_id,content_type,disposition,size_bytes)
VALUES ($1::bigint,$2::timestamptz,$3::text,'e2e-attachment.txt',NULL,'text/plain','attachment',51)
RETURNING id;
-- End of source. Caller retains transaction and outcome responsibility.
