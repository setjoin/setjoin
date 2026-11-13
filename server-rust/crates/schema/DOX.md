# Embedded schema catalog (#354)

Foundation crate containing the canonical `mailserver/sql/dbschema/V*.sql`
catalog in ascending numeric version order. `build.rs` embeds the original SQL
verbatim; no migrated copy or runtime source checkout is required. No database
connection, domain dependency or side effect belongs here. Callers choose the
operator credential and execute each migration transaction through setjoin-pg.
The mailctl direct-database process oracle verifies current, behind, missing
baseline, apply and owner-credential selection against frozen Go.
