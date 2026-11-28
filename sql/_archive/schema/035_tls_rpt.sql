-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 035_tls_rpt.sql: TLS-RPT session aggregation (RFC 8460)
-- Records per-policy-domain TLS session results for daily report generation.

CREATE TABLE IF NOT EXISTS tls_rpt_sessions (
    id              BIGSERIAL PRIMARY KEY,
    policy_domain   TEXT        NOT NULL,       -- the email domain being delivered to (e.g., example.com)
    policy_type     TEXT        NOT NULL DEFAULT 'sts',  -- 'sts' or 'no-policy-found'
    mx_host         TEXT        NOT NULL,       -- the MX hostname connected to
    mx_ip           TEXT,                        -- resolved IP address
    result          TEXT        NOT NULL,       -- 'success', 'starttls-not-supported', 'certificate-expired',
                                                -- 'certificate-host-mismatch', 'validation-failure', 'tlsa-invalid'
    failure_reason  TEXT,                        -- human-readable failure detail
    session_count   INT         NOT NULL DEFAULT 1,
    report_uri      TEXT,                        -- rua URI from _smtp._tls TXT record
    report_date     DATE        NOT NULL,        -- aggregation date
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tls_rpt_sessions_date_idx ON tls_rpt_sessions(report_date);
CREATE INDEX IF NOT EXISTS tls_rpt_sessions_domain_idx ON tls_rpt_sessions(policy_domain, report_date);
CREATE UNIQUE INDEX IF NOT EXISTS tls_rpt_sessions_uniq_idx 
    ON tls_rpt_sessions(policy_domain, mx_host, mx_ip, result, report_date);
