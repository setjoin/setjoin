# F17 slice `contacts` oracle (#297)

Frozen Go: the covered production source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`
(Go unchanged since). Same harness as calendar-booking: the Go binary runs per case
behind the Rust front door on the disposable database, replay removes Go
(`setjoin_gateway_proxied_to_go_by_family_total{family="F17"} 0`). Record with
`GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`; goldens are exclusive-create (delete
both files of a case to re-record). Run serially (`-- --test-threads=1`).

The two inventory routes use method `*`, so goldens record `request.method` `*` and
the real method under `concrete_method`; the path is the subtree pattern with the
real one under `external_path`. Fixture: two accounts, books 971001/971002, seed
contacts 972001-972003 (ids masked); the snapshot holds contacts, books' state and
the change journal. The REV of exported cards (the row's `updated_at`) is masked.

| Command | Cases |
| --- | --- |
| csv-preview | success, other account (no DB), non-multipart, no file, blank file, bad header, bad later row (`sample` null), header only, bad query escape, GET 404 |
| csv-import | success, repeat (duplicate-key row errors), foreign book 403, non-multipart, no file, bad/missing/unknown book id, bad dialect, bad mapping, mapping override (unset fields default to column 0), skip, overwrite (upsert + etag), setjoin dialect unescape, parse error text, empty file, blank email, no email column (name identity), query beats body, NUL cell (server error text) |
| vcf-import | success, repeat, foreign book, non-multipart, missing UID, rename, overwrite, skip, dates, out-of-range date |
| csv-export | success (formula neutralization), foreign book, bad id, empty book, bad jsonb (500), POST 404 |
| vcf-export | book, one contact, foreign book, bad id, foreign/missing contact (403), bad contact id, bad jsonb (500), folded long line |

Go quirks mirrored (ARCH-029): the dispatch tests path suffixes; `FormValue` takes the
URL query before the body and a malformed query makes the upload a 400; an absent
mapping field means column 0 (only email defaults to -1); vCard prefix tests are
case-insensitive but `TrimPrefix` is not (`uid:x` keeps the whole line); exported
EMAIL/TEL values are empty when the jsonb key is not `value` (imported rows store
`address`/`number`) and duplicate ROLE/NOTE lines are written; imports run each row on
the request pool without a tenant GUC, so the change journal write is skipped under RLS.
