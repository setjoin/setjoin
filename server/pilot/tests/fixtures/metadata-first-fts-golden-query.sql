-- ISSUE 204: fixed, read-only, metadata-only FTS golden source; NOT EXECUTED.
-- Inputs are the independently frozen fixture and FTS recipes, never candidate
-- rows or application data. Accepted FTS inputs SHA256
-- 5cd6d832548d1d26ab12eda2336cd109ecb21263d3917266eecf3135c2bf57fb;
-- FTS contract bd6159b6534d5bbd56fdfe63af2b47f384eee427d179c7916e146394da4d5055;
-- fixture a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934;
-- exact source base 4399a2f5eacbfa50206bcbc84883f7b40a53bf6b.
-- Those are caller-verified external bindings, not self-authenticating claims.
-- Independently bind this file's bytes/hash, client invocation/tool/build hashes,
-- approved task-owned fresh instance identity, database identity and process
-- custody before execution. SQL version() is not a binary checksum or proof
-- of instance identity. Selected source syntax below is PostgreSQL 17-specific;
-- exact binary/build, version and catalog branch must be verified before use.
--
-- Caller must establish one owned connection and read-only transaction with a
-- coherent snapshot and retain all result sets from this file on that same
-- connection/transaction. Compare witness rows and built-in implementations to
-- independently verified selected build/catalog definitions; reject missing,
-- altered, external or mismatched objects/options. Require UTF8 database AND
-- client encoding; capture locale/collation provider/version and effective
-- session settings. File/config/parser/dictionary external resources and build
-- bytes need independent custody and checksum evidence where applicable; catalog
-- names and prosrc alone do not prove built-in machine code. No app schema,
-- fixture tables, app credentials/roles, extensions or pgcrypto are required.
-- Caller records external input/output SHA256 over explicitly framed bytes and
-- the selector/order mapping. Exactly six unique ordered rows, non-NULL input
-- and output, matching hex byte lengths and exact frozen literals are required.
-- Empty non-NULL text is zero bytes / empty hex, distinct from SQL NULL or a
-- missing row. Capture the protocol's NULL state and do not trim, sort, fold,
-- re-tokenize, strip positions/weights or compare only search matches. Reject
-- extra, incomplete or duplicated records. No generated golden is claimed here.
-- Caller must acknowledge ROLLBACK and exact process/connection cleanup; any
-- uncertain terminal outcome is HOLD, never an automatic retry. Read-only
-- computation does not establish application V029, trigger or persisted rows;
-- later verification separately binds them and cannot rewrite goldens.
--
-- [1] Session and database witness, same transaction as all following queries.
-- Caller additionally verifies actual target/build using external custody.
SELECT pg_catalog.version() AS server_version_build,
       pg_catalog.current_database() AS database_name,
       pg_catalog.pg_backend_pid() AS backend_pid,
       pg_catalog.transaction_timestamp() AS transaction_time,
       pg_catalog.inet_server_addr() AS server_address,
       pg_catalog.inet_server_port() AS server_port,
       pg_catalog.current_setting('server_version_num') AS server_version_num,
       pg_catalog.current_setting('server_encoding') AS server_encoding,
       pg_catalog.current_setting('client_encoding') AS client_encoding,
       pg_catalog.current_setting('default_text_search_config') AS default_text_search_config,
       pg_catalog.current_setting('TimeZone') AS timezone,
       pg_catalog.current_setting('standard_conforming_strings') AS standard_conforming_strings,
       d.oid AS database_oid, d.datlocprovider, d.datcollate, d.datctype,
       d.datlocale, d.daticurules, d.datcollversion
FROM pg_catalog.pg_database AS d
WHERE d.datname = pg_catalog.current_database();

-- [2] Configuration, parser, complete ordered token->dictionary mapping,
-- options, template and implementation function OIDs (including optional 0).
-- Names/OIDs are identification; definitions and external build custody are
-- separately required. Caller checks exact completeness and pg_catalog ownership.
SELECT c.oid AS config_oid, cn.nspname AS config_schema, c.cfgname, c.cfgowner,
       p.oid AS parser_oid, pn.nspname AS parser_schema, p.prsname,
       p.prsstart::oid AS parser_start, p.prstoken::oid AS parser_token,
       p.prsend::oid AS parser_end, p.prsheadline::oid AS parser_headline,
       p.prslextype::oid AS parser_lextype,
       m.maptokentype, m.mapseqno,
       d.oid AS dictionary_oid, dn.nspname AS dictionary_schema, d.dictname,
       d.dictowner, d.dictinitoption,
       t.oid AS template_oid, tn.nspname AS template_schema, t.tmplname,
       t.tmplinit::oid AS template_init, t.tmpllexize::oid AS template_lexize
FROM pg_catalog.pg_ts_config AS c
JOIN pg_catalog.pg_namespace AS cn ON cn.oid=c.cfgnamespace
JOIN pg_catalog.pg_ts_parser AS p ON p.oid=c.cfgparser
JOIN pg_catalog.pg_namespace AS pn ON pn.oid=p.prsnamespace
JOIN pg_catalog.pg_ts_config_map AS m ON m.mapcfg=c.oid
JOIN pg_catalog.pg_ts_dict AS d ON d.oid=m.mapdict
JOIN pg_catalog.pg_namespace AS dn ON dn.oid=d.dictnamespace
JOIN pg_catalog.pg_ts_template AS t ON t.oid=d.dicttemplate
JOIN pg_catalog.pg_namespace AS tn ON tn.oid=t.tmplnamespace
WHERE c.oid='pg_catalog.simple'::pg_catalog.regconfig
ORDER BY m.maptokentype,m.mapseqno;

-- [3] Definitions/identity of every referenced parser/template implementation.
-- prosrc/probin and signature/language/config are catalog evidence, not a
-- replacement for verified PostgreSQL build and external resource hashes.
WITH cfg AS (
 SELECT c.oid,c.cfgparser FROM pg_catalog.pg_ts_config c
 WHERE c.oid='pg_catalog.simple'::pg_catalog.regconfig
), refs AS (
 SELECT p.prsstart::oid AS id FROM pg_catalog.pg_ts_parser p JOIN cfg ON p.oid=cfg.cfgparser
 UNION SELECT p.prstoken::oid FROM pg_catalog.pg_ts_parser p JOIN cfg ON p.oid=cfg.cfgparser
 UNION SELECT p.prsend::oid FROM pg_catalog.pg_ts_parser p JOIN cfg ON p.oid=cfg.cfgparser
 UNION SELECT p.prsheadline::oid FROM pg_catalog.pg_ts_parser p JOIN cfg ON p.oid=cfg.cfgparser
 UNION SELECT p.prslextype::oid FROM pg_catalog.pg_ts_parser p JOIN cfg ON p.oid=cfg.cfgparser
 UNION SELECT t.tmplinit::oid FROM pg_catalog.pg_ts_template t JOIN pg_catalog.pg_ts_dict d ON d.dicttemplate=t.oid JOIN pg_catalog.pg_ts_config_map m ON m.mapdict=d.oid JOIN cfg ON cfg.oid=m.mapcfg
 UNION SELECT t.tmpllexize::oid FROM pg_catalog.pg_ts_template t JOIN pg_catalog.pg_ts_dict d ON d.dicttemplate=t.oid JOIN pg_catalog.pg_ts_config_map m ON m.mapdict=d.oid JOIN cfg ON cfg.oid=m.mapcfg
)
SELECT p.oid,n.nspname,p.proname,p.proowner,p.prolang,p.prorettype,
       p.proargtypes,p.prosrc,p.probin,p.proconfig
FROM refs JOIN pg_catalog.pg_proc p ON p.oid=refs.id
JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
WHERE refs.id <> 0 ORDER BY p.oid;

-- [4] Frozen literals only. One U+0020 separates sender address and name.
-- Hex frames are unambiguous, even for empty strings. Caller validates count,
-- selector order, no NULLs, hex decoding/byte lengths, literals and external
-- cryptographic hashes, and stores exact output bytes without transformations.
WITH inputs(ord,selector,input_text) AS (VALUES
 (1,'root.body_tsv','T03 t03_metadata_20261027 root body'),
 (2,'root.subject_tsv','T03 t03_metadata_20261027'),
 (3,'root.from_tsv','fixture-sender@fixture.test T03 Root Sender'),
 (4,'reply.body_tsv','T03 t03_metadata_20261027 reply body'),
 (5,'reply.subject_tsv','Re: T03 t03_metadata_20261027'),
 (6,'reply.from_tsv','fixture-sender@fixture.test T03 Reply Sender')
), vectors AS (
 SELECT ord,selector,input_text,
        pg_catalog.to_tsvector('pg_catalog.simple'::pg_catalog.regconfig,input_text)::text AS output_text
 FROM inputs
), bytes AS (
 SELECT ord,selector,pg_catalog.convert_to(input_text,'UTF8') AS input_bytes,
        pg_catalog.convert_to(output_text,'UTF8') AS output_bytes
 FROM vectors
)
SELECT ord,selector,input_bytes IS NULL AS input_is_null,
       pg_catalog.octet_length(input_bytes) AS input_length,
       pg_catalog.encode(input_bytes,'hex') AS input_hex,
       output_bytes IS NULL AS output_is_null,
       pg_catalog.octet_length(output_bytes) AS output_length,
       pg_catalog.encode(output_bytes,'hex') AS output_hex
FROM bytes ORDER BY ord;
