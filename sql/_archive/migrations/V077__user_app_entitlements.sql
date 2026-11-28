-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V077__user_app_entitlements.sql
-- B8 — Effective capabilities (S7 + S11)
--
-- Creates the user_app_entitlements table that underpins per-user app access
-- control.  Subsequent steps in B8 (tasks B8.2–B8.5) add the resolver reducer,
-- session surface, enforcement middleware, and admin CRUD — all via additional
-- \i statements appended to this file.

\i ../schema/051_user_app_entitlements.sql
\i ../reducers/effective_capabilities.sql
\i ../reducers/check_app_entitlement.sql
\i ../reducers/set_app_entitlement.sql
