# Frozen golden-query metadata expectations

Status: SOURCE-ONLY, PROPOSED FOR REVIEW. This is not a runtime receipt, a catalog qualification, or a provider. The frozen SQL member is SHA-256 `778f2ca1a12d71259a0f40950ec8050f4201e4553d8561f5538db662eabb1596`, in Library `libfile_9abd08306b48819191c0fbbe34e36fcc` v1 archive `74a642ede244466fad76da92903b62b7cae8e61f861a8f6d168a2d11e23c4661`. PostgreSQL 17.11 archive `dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979` and the 38 independently byte-compared source members are identified in SOURCE-PINS.json.

## Interpretation and acceptance boundaries

The table assumes the intended built-in PostgreSQL types, operators, functions and catalogs resolve correctly. The query uses unqualified `::oid` and `::text`; effective search path, including temporary type precedence, must be qualified independently. All fields require protocol text format **0**; that is a client/protocol requirement, not an intrinsic SQL property. Compare actual RowDescription name, type OID and format at every ordinal, then preserve each value's NULL state and exact bytes. N means the validator requires non-NULL for successful intended execution; Y means NULL is permitted only where the independently reviewed witness baseline permits it. N is not a blanket claim that SQL declares the expression NOT NULL.

Zero optional function OIDs are values, not SQL NULL. Do not admit zero merely because the catalog permits it: the independently bound exact baseline governs. Missing rows, unexpected rows, duplicates, malformed fields, mismatched metadata or incomplete results fail closed. No wildcard accepts missing owner/build/resource expectations.

## Result 1: session/database witness

Require exactly one row and independently verify current database identity. The unique catalog name implies at most one, not guaranteed existence. No ORDER BY.

| Ordinal | Name | OID | NULL |
|---:|---|---:|:---:|
| 1 | server_version_build | 25 | N |
| 2 | database_name | 19 | N |
| 3 | backend_pid | 23 | N |
| 4 | transaction_time | 1184 | N |
| 5 | server_address | 869 | Y |
| 6 | server_port | 23 | Y |
| 7 | server_version_num | 25 | N |
| 8 | server_encoding | 25 | N |
| 9 | client_encoding | 25 | N |
| 10 | default_text_search_config | 25 | N |
| 11 | timezone | 25 | N |
| 12 | standard_conforming_strings | 25 | N |
| 13 | database_oid | 26 | N |
| 14 | datlocprovider | 18 | N |
| 15 | datcollate | 25 | N |
| 16 | datctype | 25 | N |
| 17 | datlocale | 25 | Y |
| 18 | daticurules | 25 | Y |
| 19 | datcollversion | 25 | Y |

Address and port can be NULL for Unix sockets, absent MyProcPort, non-IP address families, or name-resolution failure. Locale fields depend on provider and version; the actual baseline governs.

## Result 2: configuration and mapping witness

24 fields. Ordered by `maptokentype, mapseqno`; require independent exact mapping contents and count. Inner joins can hide broken references.

| Ordinal | Name | OID | NULL |
|---:|---|---:|:---:|
| 1 | config_oid | 26 | N |
| 2 | config_schema | 19 | N |
| 3 | cfgname | 19 | N |
| 4 | cfgowner | 26 | N |
| 5 | parser_oid | 26 | N |
| 6 | parser_schema | 19 | N |
| 7 | prsname | 19 | N |
| 8 | parser_start | 26 | N |
| 9 | parser_token | 26 | N |
| 10 | parser_end | 26 | N |
| 11 | parser_headline | 26 | N; schema permits zero |
| 12 | parser_lextype | 26 | N |
| 13 | maptokentype | 23 | N |
| 14 | mapseqno | 23 | N |
| 15 | dictionary_oid | 26 | N |
| 16 | dictionary_schema | 19 | N |
| 17 | dictname | 19 | N |
| 18 | dictowner | 26 | N |
| 19 | dictinitoption | 25 | Y |
| 20 | template_oid | 26 | N |
| 21 | template_schema | 19 | N |
| 22 | tmplname | 19 | N |
| 23 | template_init | 26 | N; schema permits zero |
| 24 | template_lexize | 26 | N |

## Result 3: referenced implementation functions

10 fields. UNION deduplicates references; zero is excluded and rows are ordered by `p.oid`. Require independent exact nonzero function set and definitions; inner joins can hide missing definitions.

| Ordinal | Name | OID | NULL |
|---:|---|---:|:---:|
| 1 | oid | 26 | N |
| 2 | nspname | 19 | N |
| 3 | proname | 19 | N |
| 4 | proowner | 26 | N |
| 5 | prolang | 26 | N |
| 6 | prorettype | 26 | N |
| 7 | proargtypes | 30 | N |
| 8 | prosrc | 25 | N |
| 9 | probin | 25 | Y |
| 10 | proconfig | 1009 | Y |

## Result 4: frozen vectors

8 fields, exactly six unique rows ordered by `ord` 1 through 6. Require the frozen selector/literal order, false NULL flags, valid even-length hex, exact decoded byte lengths and exact input literals. Keep output bytes unmodified; no observed output or accepted golden is claimed.

| Ordinal | Name | OID | NULL |
|---:|---|---:|:---:|
| 1 | ord | 23 | N |
| 2 | selector | 25 | N |
| 3 | input_is_null | 16 | N; false |
| 4 | input_length | 23 | N |
| 5 | input_hex | 25 | N |
| 6 | output_is_null | 16 | N; false |
| 7 | output_length | 23 | N |
| 8 | output_hex | 25 | N |

Empty non-NULL bytes, SQL NULL and missing rows are distinct. Do not trim, sort, normalize or discard vector positions or weights.

## Seed facts and holds

Retained stock source seed implies 19 result-2 mappings (token types 1–11 and 15–22, sequence 1, dictionary 3765, template 3727) and seven result-3 function OIDs 3717, 3718, 3719, 3720, 3721, 3725 and 3726. Selected seed references include parser_headline 3720 and template_init 3725. These are source-derived expectations, not observed runtime facts or an accepted independent baseline.

HOLD until independently bound: expected catalog and function contents and owners, database identity and locale/provider, actual PostgreSQL build and implementation bytes, dictionaries and other external resources, transaction/search-path integrity, observed outputs, connection and target custody, and rollback/cleanup acknowledgements. Keep witness observations and rollback evidence distinct from vector results. The accepted pure framer is referenced, not redefined: Library `libfile_5c161f6e1fe081918145baead1a64747` v2 archive `a266c7bf0acd4f485c3b1846e5add10f7d8b358872dc3bd0e642489be6f27f8e`. Complete receipt-envelope integration remains a separate reviewed unit.
