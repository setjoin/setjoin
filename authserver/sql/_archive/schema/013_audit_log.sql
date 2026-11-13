-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 013: Append-only audit log — trigger-enforced immutable.
-- NOTIFY trigger fires on INSERT for admin dashboard streaming.
-- Monthly partitioning for retention and performance.
CREATE TABLE audit_log (
    id              BIGSERIAL,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id         BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    source_ip       INET,
    geo_country     TEXT,
    protocol        TEXT,
    event_type      TEXT        NOT NULL,
    device_id       TEXT,
    session_id      TEXT,
    metadata        JSONB,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX audit_log_event_type_idx ON audit_log (event_type, occurred_at DESC);
CREATE INDEX audit_log_user_idx ON audit_log (user_id, occurred_at DESC);
CREATE INDEX audit_log_ip_idx ON audit_log (source_ip, occurred_at DESC);

-- Seed first monthly partition
CREATE TABLE audit_log_2026_05 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- Enforce append-only (no UPDATE/DELETE)
-- TRIAGE FENCE (D-AUTHSERVER-SQL--ARCHIVE-004, 2026-09): this row-level fence
-- is INCOMPLETE and the archived shape must not be resurrected as-is —
-- TRUNCATE and partition DETACH bypass row-level BEFORE UPDATE/DELETE
-- triggers entirely, so audit rows remain truncatable/detachable by any
-- role holding those table-level privileges (well above the pooled app
-- roles, but the gap is real; inherited from the live baseline, not archival
-- drift). Audit-tamper-evidence ownership is deferred to the G0-G4 program;
-- any live successor must pair this trigger with TRUNCATE/DETACH revocation
-- (or event triggers) before claiming an append-only guarantee.
CREATE OR REPLACE FUNCTION trg_audit_log_immutable() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: cannot UPDATE or DELETE';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_log_immutable();

-- NOTIFY trigger for admin dashboard streaming
CREATE OR REPLACE FUNCTION trg_audit_log_notify() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('audit:' || COALESCE(NEW.user_id::TEXT, 'anon'), json_build_object(
        'event_type', NEW.event_type,
        'source_ip', NEW.source_ip,
        'occurred_at', NEW.occurred_at,
        'metadata', NEW.metadata
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_notify
    AFTER INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_log_notify();
