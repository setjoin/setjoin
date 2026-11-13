# P0 metadata first-mail fixture contract

Fixture: `metadata-first-mail.json`; SHA-256 `a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934`. This is a frozen synthetic data contract for independent source review. It is not a fixture loader, runtime receipt, authenticated identity, persisted-state observation, or product acceptance.

## Exact input and relationships

The top-level object has exactly `schema`, `run_id`, `tenant`, `actors`, `mailboxes`, `thread`, `messages`, `attachment`, and `membership`. Every nested object has exactly the keys shown in the fixture; reject absent, extra, or duplicate decoded keys at every level. `schema` is the exact string `setjoin.p0.metadata-first-mail.fixture/v1`. `run_id` is exactly `t03_metadata_20261027` and must satisfy `[a-z0-9_]{1,32}`. All keys, identities, names, addresses, timestamps and markers are strings; `seen` is a boolean, `size_bytes` is the integer 51, `body_html` and attachment `content_id` are JSON null, and the list fields and `attachment_keys` are arrays with exactly the indicated members and order. A boolean does not satisfy the integer type. Reject placeholders, unresolved substitution tokens, malformed JSON, and duplicate logical or Internet message identities.

The `tenant` key is `tenant`; actors are `owner`, then `other`; mailboxes are `owner-inbox` for `owner` and `bystander-inbox` for `other`, both associated with `tenant`. The ordered message keys are `root`, `reply`, both belonging to `owner-inbox`; both belong to the stored thread key `t03-thread-001`. The root Internet message ID is `<t03-root@fixture.test>`, and the reply Internet message ID is `<t03-reply@fixture.test>`. When a separately admitted loader maps this contract to its actual schema, the reply's `in_reply_to` and `references_hdr` are each the root Internet message ID. These relationships are fixed here; they are not extra JSON fields and are not physical row IDs.

The root and reply timestamps are respectively `2026-06-14T10:00:00Z` and `2026-06-14T11:00:00Z`. Both use address `fixture-sender@fixture.test`; their distinct displayed sender names are `T03 Root Sender` and `T03 Reply Sender`. The root subject is `T03 t03_metadata_20261027` and the reply subject is `Re: T03 t03_metadata_20261027`. Root body is `T03 t03_metadata_20261027 root body`; reply body is `T03 t03_metadata_20261027 reply body`. Both body HTML values are null, both seen values are false, and both messages are members of the owner mailbox's `Inbox` tag in the listed root/reply order. The intended initial Inbox unread count is 2.

Only `reply` references attachment key `reply-attachment`; the attachment references `reply` and has filename `e2e-attachment.txt`, content type `text/plain`, disposition `attachment`, null content ID, size 51, and blob metadata logical selector `fixture-blob`. The selector is not a content hash, URL, object key, or evidence of bytes. No content upload, object readback, download, malware or SYS-01 behavior is covered.

All symbolic keys are fixture-local selectors, never physical user, mailbox, message, tag, attachment, blob, or tenant IDs and never authentication or authority. A future separately reviewed loader must supply its own physical identifiers and other required database fields, and inventory its actual setup dependencies and effects. In particular, V201 user insertion seeds `sender_control_state`, V199 mailbox insertion creates lifecycle and address-claim state, and V075 attachment insertion increments the synthetic blob row's refcount. These setup details are outside this artifact; their presence here does not establish that they ran or authorize access or cleanup.

## Independent literal validation vectors

The following are review vectors for a future independent consumer; they are not results of an executed test or database operation. Compare literal values and exact object keys, types, order and references, not values computed from a candidate implementation.

| Vector | Required result |
|---|---|
| The complete fixture exactly as pinned above | Accept the input contract. Root/reply are distinct, unread and in owner Inbox; reply alone has the declared attachment. |
| Root summary preview | Exactly `T03 t03_metadata_20261027 root body`: the ASCII body is shorter than 256 characters, so the baseline `left(body_text, 256)` projects the full root body. |
| Intended seen sequence | `(root=false, reply=false, unread=2)`, then `(false,true,1)`, then `(true,true,0)`. These are independent expected values, not proof of persistence or client convergence. |
| `run_id` changed to `T03 metadata!` | Reject invalid grammar and mismatch with pinned literal. |
| Root body changed to `T03 t03_metadata_20261027 altered body` | Reject changed pinned marker. |
| Reply attachment key changed to `missing-attachment` | Reject dangling reference. |
| Reply Internet message ID changed to `<t03-root@fixture.test>` | Reject duplicate Internet message identity. |
| Either initial `seen` changed to true | Reject changed initial state. |
| Root `attachment_keys` changed to `["reply-attachment"]` or attachment `message` changed to `root` | Reject wrong attachment ownership. |
| Add an object field or remove a required field | Reject the non-exact shape. |
| Repeat a decoded object key, including escaped-equivalent spellings | Reject duplicate keys even if the values are equal. |
| Substitute an unresolved template token for any pinned literal | Reject the placeholder and changed literal. |

A complete runtime oracle, result/event schemas, ordered mixed-outcome rules, real transaction witness and comparator compatibility remain outside this two-file contract and require their own review and admission. No automatic success or retry follows from this document.
