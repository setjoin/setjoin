# Issue 204 metadata-first physical mapping — source candidate

Status: source-only candidate, **not complete loader admission**. Schema sources are Git objects at commit `4399a2f5eacbfa50206bcbc84883f7b40a53bf6b`, tree `4bbaa6153513646a2bf9e7f3fb4aa7ef4e3aa0e0`; source hashes appear in the companion inventory. Fixture JSON (1630 bytes, SHA-256 `a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934`) and contract (5791 bytes, SHA-256 `ca21c4123b119b7ff82a8a14f8a23bdbf1f52d42e99974f90245b647f70950b6`) were strictly decoded and independently verified from the parent’s in-thread handoff. Both prior supported Library materializations failed transport. Parent attests archive SHA `fc70847b8133572d36dac8765403ce519f7f533b5db3883ef7b51c3ff5e3d6e5`; this consumer did not receive or independently verify that archive. A previous graph textual contract was withheld after a length/hash mismatch; it was not used.

## Logical selectors to physical relationships

These selectors are not IDs, credentials or authority. A separately reviewed loader must supply physical identifiers and bind each row, and verify migrations and triggers actually present. `tenant` is the common tenant relation, with `domains.id` a schema-backed candidate because users and mailboxes have `domain_id`; fixture text alone does not choose a domain name or prove a tenant-to-domain convention. `owner` and `other` map to distinct `users.id`; `owner-inbox` and `bystander-inbox` map to distinct `mailboxes.id`, associated respectively through `mailboxes.user_id` and the common domain binding. No address or username for either actor is specified.

| Selector | Physical row / fixed fields and relations |
|---|---|
| `t03-thread-001` | Both `messages.thread_id` use this literal stored key; it is not a physical message ID. |
| `root` | `messages` composite `(id,received_at)` with mailbox = owner-inbox; Internet `message_id` `<t03-root@fixture.test>`; received `2026-06-14T10:00:00Z`; subject `T03 t03_metadata_20261027`; from_addr `fixture-sender@fixture.test`; from_name `T03 Root Sender`; body_text `T03 t03_metadata_20261027 root body`; body_html NULL; is_read false. |
| `reply` | Different `messages` composite key, same owner mailbox; Internet `message_id` `<t03-reply@fixture.test>`; received `2026-06-14T11:00:00Z`; subject `Re: T03 t03_metadata_20261027`; same from_addr; from_name `T03 Reply Sender`; body_text `T03 t03_metadata_20261027 reply body`; body_html NULL; is_read false; `in_reply_to` and `references_hdr` each `<t03-root@fixture.test>`. |
| `owner-inbox/Inbox` | Two `message_tags` rows use each message's composite key and the owner's mailbox-scoped Inbox `tags.id`; not folder ID. Initial expected unread is 2. `messages.folder_id` is a required legacy tag-ID mirror, not the independently generated folder ID; see the successor closure below. |
| `reply-attachment` | One `message_attachments` row references reply's composite key and a `blobs.sha256` metadata row; filename `e2e-attachment.txt`, content_type `text/plain`, disposition `attachment`, content_id NULL, size_bytes 51. Root has no attachment. |
| `fixture-blob` | Symbolic selector for the database blob metadata row. It is not a SHA-256 value, storage key, URL or byte proof. The required `blobs.sha256`, `minio_ref`, `size_bytes` and initial `ref_count` must be supplied by an independently reviewed metadata-only setup contract. |

The baseline requires `messages.raw_ref`, mailbox and legacy tag-mirror IDs and other physical fields beyond fixture values. The fixture does not specify raw_ref, message sizes or `has_attachments`, physical IDs, account names, or how to allocate them. `messages` and `message_tags` are partitioned by received_at: bind the actual composite keys and available partitions. `has_attachments` and message size must be set and checked consistently with the later accepted mapping rather than inferred from the attachment size. Body preview literal is the entire root body under the stated `left(body_text,256)` projection. The independently specified seen sequence is `(false,false,2)`, `(false,true,1)`, `(true,true,0)`; it is an oracle proposal, not an observation.

## Conditional setup inventory and bystanders

The following are expected only for an admitted route that inserts fresh rows, with pinned migrations installed and triggers enabled. Existing-row reuse, conflict handling, updates, trigger state, quota configuration, generated IDs and timestamps change the result; no execution is implied.

* One domain candidate, two user rows, two mailbox rows, two message rows, two Inbox memberships, one reply attachment and one associated blob metadata row are the intended fresh-row shape, subject to the unresolved mapping above. V001 FK requires the blob metadata row; no content load or object operation follows. Its `ref_count` defaults to 1, and V075 `attachment_blob_refcount_inc` adds 1; a different initial value must be explicit. Baseline zero-ref cleanup executes only when resulting ref_count is zero. V235 usage changes only if a separate `blob_user_charges` row is inserted; no such insert is entailed by this fixture. Do not assume charge or cleanup queue entries, object bytes, upload, readback, download or SYS-01.
* V201 `sender_control_user_seed` inserts one `sender_control_state` per new user with generation default 1, unless conflict, and timestamp is generated. V249 address admission checks cross-person claims and may reject; V155 checks complete federation pairs. V143 mailbox guest guard rejects a user with guest-account state. These are checks, not permission to modify identities.
* For each newly inserted enabled, receive-enabled, user-bound primary personal mailbox, V199 creates lifecycle state active/accepting/bound with user and was_primary true, plus lower(email) active primary address claim, subject to conflicts and defaults. V164 `identity_primary_mailbox_authority_init` inserts `user_lifecycle_authorities(user_id, authority_kind='local')` on conflict do nothing for each new primary personal mailbox. Two fresh qualifying users/mailboxes therefore imply two each of sender control, lifecycle, claims and local authority rows, conditional on actual prior state. Inspect V199 and V164 for all other fields and constraints before comparing whole rows.
* V001 mailbox insert hooks create seven nonjournal folders per mailbox: Inbox, Sent, Drafts, Trash, Spam, Archive, Templates. V078 supplies eleven system tags per mailbox: Inbox, Sent, Drafts, Trash, Spam, Starred, Snoozed, Scheduled, Important, Muted, Other. Two fresh nonjournal mailboxes therefore imply 14 folders and 22 tags when hooks succeed; IDs, timestamps and UID validity are generated. Quota defaults depend on `system_config` and may update mailbox state. V085 alters primary enforcement. The mandatory quota update and its column-specific trigger closure are detailed below; additional updates require their own closure.
* V029 `trg_messages_tsv`, invoked by baseline `messages_tsv_update`, uses subject/from inputs and, unless `app.skip_fts=true`, sets body_tsv NULL for `smime-encrypted`, otherwise derives it from body text. Bind crypto_type, app.skip_fts and deployed function before comparing vectors. With two unread inserts into an initially empty owner Inbox, V182 counters imply total=2, unread=2, size=sum of the two message sizes, and jmap_state advances twice from its actual initial value. V001 exclusivity can remove same-group membership; primary sync can update folder_id; Spam training is conditional on Spam, not Inbox.

A future whole-row comparison must independently define column coverage, stable normalization for generated IDs/timestamps and exact expected deltas, and capture before/after rows for the other mailbox, its folders/tags/counters and associated identity and lifecycle state. Snapshot every unrelated preexisting row that the admitted route can reach; verify unchanged except explicitly enumerated setup effects. The fixture alone supplies no exact preexisting bystander row values or whole-row oracle. Do not substitute an assumed empty database. Compare absence of unexpected memberships/attachments within the scoped fixture and retain the distinction between generated setup rows and later runtime effects.

## Remaining source/admission decisions

The setup operation order, physical values, full expected row projection and bystander baseline, partition/trigger/migration state, quota settings, and complete trigger/replacement closure require review. The inventory is focused, not an exhaustive proof that no other installed trigger can run. Integration result/event schema and transaction witness are separate. No SQL, database, fixture loading, tests, services, authentication or object access ran for this source contract. Retained upload work and its 401 are separate from this metadata-only P0 slice.

## Successor: proposed exact setup policy (source design only)

The following are proposals for review, not facts supplied by the fixture and not observed setup. Use a fresh synthetic-only domain `t03-metadata.fixture.test`; user names `t03-owner` and `t03-other`, emails `t03-owner@t03-metadata.fixture.test` and `t03-other@t03-metadata.fixture.test`, display names `T03 Owner` and `T03 Other`. Two fresh enabled local users, with both federation pairs NULL and no guest-account rows, each receive a fresh enabled, receive-enabled, primary personal mailbox with the corresponding email and display name. Both map to the one domain. Ensure all identifiers/addresses are absent beforehand; conflicts HOLD rather than adopt or delete. No password or auth/session operation is required for this source proposal.

Proposed allocation is database-generated identities captured from the actual inserts, separately named domain, users, mailboxes, folder rows, tag rows, message `(id, received_at)` and attachment ID; never infer equality across sequences. Generate folders/tags through existing mailbox triggers and capture Inbox folder and Inbox tag independently by mailbox/name. Proposed explicit mailbox quotas are 1048576 bytes and 100 sends/day; because they differ from the column defaults, quota hook preserves them while still performing its UPDATE. Verify exact values and system configuration as part of later runtime admission; no config is changed by this document.

Insert two messages using exact fixture literals and root/reply `has_attachments=false/true`, `is_read=false`, `crypto_type=NULL`, `body_html=NULL`, root reply headers NULL and reply headers root Internet ID. Proposed size_bytes 0 and 51 respectively are synthetic metadata only, not byte measurements. Proposed `raw_ref` values `metadata-only/t03/root` and `metadata-only/t03/reply` are inert references, not claims that objects exist. Insert memberships with `is_primary=true`, `added_by='fixture'`, and NULL snooze/schedule fields. This is a proposed policy for the sole location tag; the JMAP reducer `mailserver/sql/reducers/jmap_email.sql:530-552` marks the first selected tag primary. The trigger writes `messages.folder_id=owner Inbox tags.id`, NOT the generated Inbox folder ID. V077 explicitly calls this a tag-ID denormalized mirror; the previous v2 description of a folder FK was incorrect. Bind and compare the two namespaces independently even if numeric values happen to coincide. Do not manipulate sequences to make them equal.

For `fixture-blob`, propose a unique, explicitly synthetic metadata identifier of 64 zero hex digits and `minio_ref='metadata-only/t03/fixture-blob'`, size_bytes=51, content_type='text/plain', initial ref_count=0; after the one attachment insert expected ref_count=1. These values are labels and sizes only, not a hash of bytes, usable object key or claim that any object exists. Require identifier absence and no preexisting referencing rows before insertion. No blob charges or object writes are part of this proposal. Collisions or a semantic requirement that the field prove bytes require a revised reviewed contract, not fabricated byte evidence. Insert order: domain; users; mailboxes and their triggered rows; capture folder/tag bindings; blob metadata; messages; memberships; attachment. No bypass of checks/triggers. Verify the actual schema and constraints before any future execution.

## Expected row and comparison specification

The fixture literals in the mapping above are exact. For new qualifying rows, sender_control_state has corresponding user_id, generation 1 and statement-generated updated_at. Each mailbox_lifecycle is keyed by its mailbox ID, `active/accepting/bound`, corresponding bound_user_id, was_primary=true, generation=policy_generation=1; retained_at, retention_until, redirect_address, reason, last_operation_id and updated_by NULL; updated_at generated. Each address claim is lower(mailbox email), corresponding mailbox ID, kind primary, state active, generation 1, released_at NULL, claimed_at generated. Each user_lifecycle_authorities row has the corresponding user_id, authority_kind local, link_id and established_by NULL, generation 1, generated established_at and updated_at. V156 deferred `user_lifecycle_authorities_link_guard` returns immediately for local authority; do not silently skip its deferred constraint.

For messages, V001 defaults include empty to/cc/bcc JSON arrays and categories, false flagged/answered/draft/deleted/held/receipt requests/external/name_spoof, priority 0, first_time true. Unspecified optional V001 columns default NULL; explicit fixture/proposal fields override defaults. V029 computes all three vectors from subject, from_addr/from_name and body_text when `app.skip_fts` is not true; if it is true it returns NEW unchanged. Compare actual vectors through a separately defined exact typed representation, not hand-guessed tokenization. Freeze or record this setting and require nonencrypted NULL crypto_type. The final columns and migration overlays for the proposed rows are listed below.

Each generated nonjournal mailbox has V001 folders `(name,role,path,sort_order)`: Inbox/inbox/INBOX/0; Sent/sent/INBOX/Sent/10; Drafts/drafts/INBOX/Drafts/20; Trash/trash/INBOX/Trash/30; Spam/spam/INBOX/Spam/40; Archive/archive/INBOX/Archive/50; Templates/templates/INBOX/Templates/60. V078 lists all eleven system tag attribute tuples, including icon, color, exclusive group, default, sort, IMAP exposure/name: bind these against V078 lines 58–94, not just names. Capture all generated IDs and UID validity separately. From fresh tag counters 0/0/0/jmap_state 0, two memberships produce owner Inbox total 2, unread 2, size 51, jmap_state 2 under this proposal; all ten other owner tags and all eleven bystander tags retain initial counters. Other tag attributes remain exact unchanged from trigger-created rows. No assumption that a generated timestamp equals a hardcoded clock: capture transaction timestamp for `now()` defaults and statement timestamp for statement_timestamp defaults, compare exact relations rather than erase time columns; preserve the fixture received_at literals and record epoch-derived UID validity. Explicit ID maps must be one-to-one within each namespace and references checked, not normalized away.

Capture pre-setup bystander rows and complete scoped table inventories, then compare keyed whole rows before/after, permitting only the enumerated inserts and explicit quota update. Bystander mailbox and its generated rows are expected setup effects; after setup their rows must remain unchanged through later owner-only operations except where an independently reviewed result contract explicitly says otherwise. Existing unrelated domains/users/mailboxes/messages/tags/attachments/blobs, lifecycle/authority/claims/sender state, charges/usage/cleanup queue and relevant config must be compared unchanged; report unexpected rows and fields, not merely counts. Snapshot source/target actual schema and all relevant columns, partition routing and trigger states. Sequence advancement is an expected setup effect, not bystander equality. This requires a separately designed comparator and transaction witness.

## Trigger closure matrix for the proposed inserts

| Reachable operation | Source and precise predicate/effect | Remaining verification |
|---|---|---|
| users INSERT | V155 pair completeness; V249 identity admission; V201 one sender state. | Existing address/alias uniqueness, exact deployed definitions and row-default list. |
| mailboxes INSERT | V143 guest guard; V001 folder/tag creation and primary check; V078 tag replacement; V164 local authority; V199 lifecycle/claim; V001 quota hook. | Verify actual migration/trigger status; no assumption about physical order beyond database semantics. |
| mailbox quota hook UPDATE | V001 always executes `UPDATE mailboxes SET quota_bytes=..., sending_quota_day=... WHERE id=NEW.id`, even if unchanged. V085 `mailbox_primary_enforce` AFTER INSERT OR UPDATE invokes baseline primary check. | Verify no additional applicable UPDATE triggers or replacements outside inspected migration sources; inspect full deployed schema. |
| quota-only UPDATE predicates | V143 and V249 are UPDATE OF user_id; V172 UPDATE OF user_id,is_primary; V199 UPDATE OF email,user_id,enabled,receive_enabled. None is named in quota UPDATE's SET list. V186 and V222 concern UPDATE of users, not this mailbox update. | These are not fired by this quota-only statement absent other triggers changing targeted columns; separately inventory any later indirect updates. No blanket assertion about all future setup. |
| V164 authority INSERT | V156 deferred link guard runs at constraint time; local branch returns NEW. | Ensure transaction commits and constraint is enabled in future runtime. |
| messages INSERT | V029 FTS via V001 trigger; read/write partition route. | Exact active schema, trigger and vector representation. |
| membership INSERT | V001 exclusivity, primary sync and Spam hook; V182 counters. For sole Inbox tag, primary sync sets folder_id to tag ID; no Spam predicate. | Check additional repository SQL trigger definitions and IMAP columns/UID allocation before full row oracle. |
| attachment INSERT | V075 refcount +1; V001 zero cleanup triggers only if resulting zero. | Verify blob metadata uniqueness and no unlisted side effects. V235 charge trigger requires separate charge INSERT, which is not proposed. |

## Explicit omissions

The final column inventory and fixture-specific trigger exclusions below supersede the open-ended v3 gaps. Complete runtime schema identity and fixture-specific conflict/bystander evidence remain later admission checks. Actual deployment, identity allocation, row persistence and transaction success remain unobserved. A body provider, result/event schema and real transaction witness remain separate contracts. No machine checks, SQL or runtime actions were performed.

### Membership UID source closure

V197 adds `message_tags.imap_uid` nullable and `imap_modseq` default 1, and creates the UID ledger. Separately loaded `reducers/trg_imap_membership_uid_allocate.sql` installs a BEFORE INSERT trigger with no feature-toggle check: NULL/nonpositive UID invokes `imap_membership_uid_allocate`, which locks the tag, selects max(next, ledger max+1), increments tag `imap_uid_next` and `imap_modseq`, and inserts an active ledger row. The chosen source contract requires these pinned reducers/triggers installed and enabled. The proposed ordered root then reply insert on a fresh Inbox with next=1, modseq=1 and empty ledger yields membership UIDs 1,2, each membership modseq=1, active ledger rows 1,2 with the two composite message keys, tag next=3 and modseq=3; ledger allocated_at and tag updated_at use transaction time. V197 alone does not install this reducer trigger. The future loader must verify the chosen exact trigger and function identities and enabled state and HOLD on mismatch; it must not select an alternate outcome or change a feature flag to force this branch. The separately installed retire trigger is AFTER DELETE; no membership delete is proposed. Preserve all unrelated ledger and backfill rows unchanged.

## Final schema delta and exact branch

Apply the baseline column inventory below with these exact overlays, in migration order: V008 adds users.address_policy_enabled boolean NOT NULL default true; V013 adds nullable messages.smime_status, smime_signer_email, smime_signer_cn and smime_issuer_cn (all NULL in this proposal); V023 removes users.admin_role; V031 removes messages.smime_encrypt; V077 removes folders.total_count, unread_count and size_bytes; V197 adds nullable message_tags.imap_uid and imap_modseq NOT NULL default 1; V201 adds mailboxes.jmap_mailwork_state bigint NOT NULL default 0; V272 adds users.factor_generation, possession_password_failed_attempts, possession_webauthn_failed_attempts NOT NULL default 0 and nullable possession_password_locked_until and possession_webauthn_locked_until. Do not compare a removed column. The proposed rows have no credentials, factors or sign-in operations: password_hash, factor secrets, lock timestamps and optional identity fields are NULL and the corresponding flags/counters retain defaults.

Choose the canonical branch with V197 plus the pinned `imap_membership_uid_allocate` function and `message_tags_imap_uid_allocate` trigger installed and enabled. Root and reply receive UIDs 1 and 2 in insertion order, active ledger rows, tag uid_next 3 and modseq 3. Ledger and tag timestamps follow `now()`; `message_tags.imap_modseq=1`. Before any future setup, require exact source/deployed function identity, enabled trigger, fresh tag and ledger state; HOLD if mismatched. Feature toggle is not a gate inside that trigger. No branch selection from a live outcome is allowed.

## Source column inventory for exact proposed rows

The following column declarations are taken from the baseline CREATE TABLE bodies; the above overlays supersede them. Lines without DEFAULT and without an explicit proposed value are NULL where nullable. `id` for domains/users/mailboxes/folders/tags/messages/attachments has a baseline sequence default via V001 lines 6424–6753; capture IDs independently. `now()` is the transaction timestamp, statement_timestamp() the statement timestamp; capture rather than discard these values. Exact constraints, partition schema and enabled triggers still require runtime binding.

### domains

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
name text NOT NULL
is_primary boolean DEFAULT false NOT NULL
is_local boolean DEFAULT true NOT NULL
catch_all_mailbox_id bigint
dkim_selector text
dkim_private_key_enc text
dkim_key_expires_at timestamp with time zone
spf_record text
dmarc_policy text DEFAULT 'none'::text NOT NULL
dmarc_rua text
dmarc_ruf text
dmarc_pct integer DEFAULT 100 NOT NULL
mta_sts_policy text DEFAULT 'none'::text NOT NULL
max_message_bytes bigint DEFAULT 52428800 NOT NULL
quota_bytes bigint
created_at timestamp with time zone DEFAULT now() NOT NULL
updated_at timestamp with time zone DEFAULT now() NOT NULL
sandbox_enabled boolean DEFAULT false NOT NULL
sandbox_action text DEFAULT 'quarantine'::text NOT NULL
sandbox_file_types text DEFAULT '*'::text NOT NULL
```

### users

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
username text NOT NULL
domain_id bigint NOT NULL
email text NOT NULL
display_name text NOT NULL
first_name text
last_name text
job_title text
phone text
manager_id bigint
department_id bigint
avatar_sha256 text
password_hash text
must_change_password boolean DEFAULT false NOT NULL
is_local_admin boolean DEFAULT false NOT NULL
ad_object_guid uuid
ad_usn_changed bigint
ad_sam_account text
ad_upn text
sync_source text DEFAULT 'local'::text NOT NULL
local_overrides jsonb DEFAULT '{}'::jsonb NOT NULL
last_synced_at timestamp with time zone
krb5_principal text
saml_name_id text
saml_session_index text
saml_idp_entity_id text
oidc_subject text
oidc_issuer text
oidc_provider text
webauthn_credentials jsonb DEFAULT '[]'::jsonb NOT NULL
webauthn_user_handle bytea
totp_secret_enc text
totp_enabled boolean DEFAULT false NOT NULL
totp_enabled_at timestamp with time zone
last_totp_used_at timestamp with time zone
totp_failed_attempts integer DEFAULT 0 NOT NULL
totp_locked_until timestamp with time zone
mfa_exempt boolean DEFAULT false NOT NULL
enabled boolean DEFAULT true NOT NULL
is_admin boolean DEFAULT false NOT NULL
last_login_at timestamp with time zone
last_login_ip inet
created_at timestamp with time zone DEFAULT now() NOT NULL
updated_at timestamp with time zone DEFAULT now() NOT NULL
push_mfa_enabled boolean DEFAULT false NOT NULL
totp_backup_codes_enc text[]
last_login_country text
scim_external_id text
view_prefs jsonb
external_sender_warning boolean DEFAULT true NOT NULL
address_policy_enabled boolean NOT NULL DEFAULT true
factor_generation bigint NOT NULL DEFAULT 0
possession_password_failed_attempts integer NOT NULL DEFAULT 0
possession_password_locked_until timestamp with time zone
possession_webauthn_failed_attempts integer NOT NULL DEFAULT 0
possession_webauthn_locked_until timestamp with time zone
```

### mailboxes

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
user_id bigint
domain_id bigint NOT NULL
email text NOT NULL
type text DEFAULT 'personal'::text NOT NULL
display_name text NOT NULL
is_primary boolean DEFAULT false NOT NULL
quota_bytes bigint DEFAULT '53687091200'::bigint NOT NULL
used_bytes bigint DEFAULT 0 NOT NULL
sending_quota_day integer DEFAULT 500 NOT NULL
sending_sent_today integer DEFAULT 0 NOT NULL
sending_quota_reset_at date DEFAULT CURRENT_DATE NOT NULL
enabled boolean DEFAULT true NOT NULL
receive_enabled boolean DEFAULT true NOT NULL
hidden_from_gal boolean DEFAULT false NOT NULL
litigation_hold boolean DEFAULT false NOT NULL
hold_since timestamp with time zone
hold_reason text
hold_set_by bigint
deleted_purge_days integer
spam_purge_days integer
spam_folder_enabled boolean DEFAULT true NOT NULL
spam_sensitivity text DEFAULT 'medium'::text NOT NULL
resource_type text
resource_capacity integer
auto_accept_meetings boolean DEFAULT false NOT NULL
max_meeting_hours integer
booking_window_days integer DEFAULT 365 NOT NULL
jmap_email_state bigint DEFAULT 0 NOT NULL
jmap_mailbox_state bigint DEFAULT 0 NOT NULL
jmap_thread_state bigint DEFAULT 0 NOT NULL
created_at timestamp with time zone DEFAULT now() NOT NULL
updated_at timestamp with time zone DEFAULT now() NOT NULL
jmap_tag_state bigint DEFAULT 0 NOT NULL
quarantine_self_service boolean DEFAULT true NOT NULL
jmap_reminder_state bigint DEFAULT 0 NOT NULL
jmap_mailwork_state bigint NOT NULL DEFAULT 0
```

### folders

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
mailbox_id bigint NOT NULL
parent_id bigint
name text NOT NULL
role text
path text NOT NULL
sort_order integer DEFAULT 0 NOT NULL
imap_uid_validity bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint NOT NULL
imap_uid_next bigint DEFAULT 1 NOT NULL
imap_modseq bigint DEFAULT 1 NOT NULL
subscribed boolean DEFAULT true NOT NULL
created_at timestamp with time zone DEFAULT now() NOT NULL
updated_at timestamp with time zone DEFAULT now() NOT NULL
```

### tags

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
mailbox_id bigint NOT NULL
parent_id bigint
name text NOT NULL
color text
icon text
sort_order integer DEFAULT 0 NOT NULL
tag_type text DEFAULT 'user'::text NOT NULL
exclusive_group text
is_default boolean DEFAULT false NOT NULL
total_count integer DEFAULT 0 NOT NULL
unread_count integer DEFAULT 0 NOT NULL
size_bytes bigint DEFAULT 0 NOT NULL
imap_expose boolean DEFAULT true NOT NULL
imap_name text
imap_uid_validity bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint NOT NULL
imap_uid_next bigint DEFAULT 1 NOT NULL
imap_modseq bigint DEFAULT 1 NOT NULL
jmap_state bigint DEFAULT 0 NOT NULL
created_at timestamp with time zone DEFAULT now() NOT NULL
updated_at timestamp with time zone DEFAULT now() NOT NULL
```

### messages

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
mailbox_id bigint NOT NULL
folder_id bigint NOT NULL
message_id text NOT NULL
subject text
from_addr text NOT NULL
from_name text
to_addrs jsonb DEFAULT '[]'::jsonb NOT NULL
cc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL
bcc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL
reply_to text
in_reply_to text
references_hdr text
body_text text
body_html text
body_tsv tsvector
subject_tsv tsvector
from_tsv tsvector
size_bytes bigint DEFAULT 0 NOT NULL
has_attachments boolean DEFAULT false NOT NULL
is_read boolean DEFAULT false NOT NULL
is_flagged boolean DEFAULT false NOT NULL
is_answered boolean DEFAULT false NOT NULL
is_draft boolean DEFAULT false NOT NULL
is_deleted boolean DEFAULT false NOT NULL
categories text[] DEFAULT '{}'::text[] NOT NULL
thread_id text NOT NULL
imap_uid bigint
imap_modseq bigint
spam_score real
spam_headers jsonb
spf_result text
dkim_result text
dmarc_result text
raw_ref text NOT NULL
held boolean DEFAULT false NOT NULL
sent_at timestamp with time zone
received_at timestamp with time zone DEFAULT now() NOT NULL
dkim_selector text
dkim_domain text
crypto_type text
priority integer DEFAULT 0 NOT NULL
sensitivity text
read_receipt_requested boolean DEFAULT false NOT NULL
delivery_receipt_requested boolean DEFAULT false NOT NULL
vote_options jsonb
scheduled_at timestamp with time zone
deleted_at timestamp with time zone
pinned_at timestamp with time zone
vote_response text
is_external boolean DEFAULT false NOT NULL
sender_display_name text
is_name_spoof boolean DEFAULT false NOT NULL
is_first_time boolean DEFAULT true NOT NULL
list_unsubscribe text
list_id text
flag_due_at timestamp with time zone
flag_reminder_at timestamp with time zone
smime_status text
smime_signer_email text
smime_signer_cn text
smime_issuer_cn text
```

### message_tags

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
message_id bigint NOT NULL
received_at timestamp with time zone NOT NULL
tag_id bigint NOT NULL
added_at timestamp with time zone DEFAULT now() NOT NULL
added_by text
snooze_until timestamp with time zone
scheduled_at timestamp with time zone
is_primary boolean DEFAULT false NOT NULL
imap_uid bigint
imap_modseq bigint NOT NULL DEFAULT 1
```

### message_attachments

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
id bigint NOT NULL
message_id bigint NOT NULL
received_at timestamp with time zone NOT NULL
blob_sha256 text NOT NULL
filename text
content_id text
content_type text NOT NULL
disposition text DEFAULT 'attachment'::text NOT NULL
size_bytes bigint NOT NULL
```

### blobs

Source: `mailserver/sql/dbschema/V001__baseline.sql`; final overlays above.

```text
sha256 text NOT NULL
minio_ref text NOT NULL
size_bytes bigint NOT NULL
content_type text
ref_count integer DEFAULT 1 NOT NULL
created_at timestamp with time zone DEFAULT now() NOT NULL
```

### sender_control_state

Source: `mailserver/sql/dbschema/V201__webmail_competitive_productivity.sql`; final overlays above.

```text
user_id bigint PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE
generation bigint NOT NULL DEFAULT 1 CHECK(generation>0)
updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
```

### mailbox_lifecycle

Source: `mailserver/sql/dbschema/V199__mailbox_lifecycle_retention.sql`; final overlays above.

```text
mailbox_id bigint PRIMARY KEY REFERENCES public.mailboxes(id) ON DELETE RESTRICT
access_state text NOT NULL DEFAULT 'active' CHECK(access_state IN ('active','suspended','detached'))
delivery_state text NOT NULL DEFAULT 'accepting' CHECK(delivery_state IN ('accepting','redirecting','rejecting'))
binding_state text NOT NULL DEFAULT 'bound' CHECK(binding_state IN ('bound','retained','shared'))
bound_user_id bigint REFERENCES public.users(id) ON DELETE RESTRICT
was_primary boolean NOT NULL DEFAULT false
generation bigint NOT NULL DEFAULT 1 CHECK(generation>0)
policy_generation bigint NOT NULL DEFAULT 1 CHECK(policy_generation>0)
retained_at timestamptz
retention_until timestamptz
redirect_address text
reason text CHECK(reason IS NULL OR octet_length(reason) BETWEEN 1 AND 1024)
last_operation_id uuid
updated_by bigint REFERENCES public.users(id) ON DELETE SET NULL
updated_at timestamptz NOT NULL DEFAULT now()
```

### mailbox_address_claims

Source: `mailserver/sql/dbschema/V199__mailbox_lifecycle_retention.sql`; final overlays above.

```text
normalized_address text PRIMARY KEY CHECK(normalized_address=lower(normalized_address))
mailbox_id bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT
address_kind text NOT NULL CHECK(address_kind IN ('primary','alias'))
claim_state text NOT NULL DEFAULT 'active' CHECK(claim_state IN ('active','retained','released'))
generation bigint NOT NULL DEFAULT 1 CHECK(generation>0)
claimed_at timestamptz NOT NULL DEFAULT now()
released_at timestamptz
```

### user_lifecycle_authorities

Source: `mailserver/sql/dbschema/V156__identity_source_link_substrate.sql`; final overlays above.

```text
user_id             BIGINT PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE (V164 replaces V156 RESTRICT)
authority_kind      TEXT NOT NULL
link_id             BIGINT UNIQUE REFERENCES public.user_identity_links(id) ON DELETE RESTRICT
generation          BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0)
established_by      BIGINT REFERENCES public.users(id) ON DELETE SET NULL
established_at      TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
```

### imap_membership_uid_ledger

Source: `mailserver/sql/dbschema/V197__imap_membership_uid.sql`; final overlays above.

```text
tag_id bigint NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE
imap_uid bigint NOT NULL CHECK (imap_uid > 0)
message_id bigint NOT NULL
received_at timestamptz NOT NULL
active boolean NOT NULL DEFAULT true
allocated_at timestamptz NOT NULL DEFAULT now()
retired_at timestamptz
```

## Fixture-specific excluded operations

No user UPDATE or DELETE: V035 enabled-user guard, V172 user authority fence, V186 user-change invalidation and V222 user reachability fence/deferred revalidation do not match. No mailbox DELETE or UPDATE OF user_id/is_primary/email/enabled/receive_enabled: V085 delete constraint, V143/V249 ownership guards, V172 authority fence and V199 lifecycle-update predicate do not match the quota-only SET. The general V085 primary check DOES run on that UPDATE. No aliases, identity links, admin assignments, system_config, charges, user-group, feature-toggle, deletion or retention writes are proposed. No attachment deletion: the V001 attachment deletion decrement does not apply. No membership deletion: the reducer-installed UID retirement trigger does not apply. No message DELETE: V182 delete and V001 hold checks do not apply. Inbox is not Spam; fresh membership has no prior location membership to delete. V156 local-authority deferred check still executes. V075 increments blob refcount 0→1, so V001 zero-ref cleanup does not enqueue. Exact trigger/function hashes and schema/partition/permissions are later runtime preconditions, never assumed observed.

Remaining separate contracts: a body provider that can return the inline text without object access; result/event schema and ordering; a transaction witness and full row/bystander comparator. The source list fixes the reviewed schema branch but does not establish deployment, persistence, authorization or runtime acceptance.
