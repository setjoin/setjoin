-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V002: Phase 9 additions — calendar resources, free/busy, iTIP/iMIP.
-- Run with: psql -f V002__calendar_phase9.sql  (from sql/migrations/ directory)

\i ../schema/025_calendar_resources.sql
\i ../reducers/calendar_freebusy.sql
\i ../reducers/calendar_itip.sql
