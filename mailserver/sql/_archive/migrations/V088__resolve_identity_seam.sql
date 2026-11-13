-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V088 — ADR-004 §3: the address-aware identity resolution seam (reducer layer).
--
-- Loads `resolve_identity(p_address) → (user_id, primary_mailbox, domain_id)`:
-- the reducer-layer twin of authserver's connector.ResolveIdentitySQL. It resolves
-- a PERSON by ANY of their addresses — users.email ∪ aliases.email ∪ users.ad_upn
-- (case-insensitive, enabled users only). The calendar reducers
-- (calendar_sharing / jmap_calendar / calendar_itip — all loaded by V001/V084 via
-- `\i`, which re-resolve their bodies under CREATE OR REPLACE late-binding) call it
-- so an owner / delegate / attendee / share-grantee addressed by an alias or UPN
-- resolves correctly — closing the same bug class as ADR-004 Half A (which matched
-- users.email only). Pure additive function load; no schema change. Idempotent
-- (CREATE OR REPLACE FUNCTION).
--
-- R4 by p_mailbox_id propagation in the callers (no native RLS) — resolve_identity
-- is a STABLE read-only resolver and introduces no new user-data write path.

\i ../reducers/resolve_identity.sql
