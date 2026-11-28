-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- 034_dmarc_reports.sql: DMARC aggregate reporting (RFC 7489 §7)
-- Stores per-domain aggregate report data for daily batch submission.

CREATE TABLE IF NOT EXISTS dmarc_reports (
    id              BIGSERIAL PRIMARY KEY,
    domain          TEXT        NOT NULL,       -- the FROM domain being reported
    report_uri      TEXT        NOT NULL,       -- rua mailto: URI target
    begin_time      TIMESTAMPTZ NOT NULL,       -- report period start (UTC)
    end_time        TIMESTAMPTZ NOT NULL,       -- report period end (UTC)
    total_count     INT         NOT NULL DEFAULT 0,  -- successful authentications
    count_none      INT         NOT NULL DEFAULT 0,  -- DMARC result "none"
    count_pass      INT         NOT NULL DEFAULT 0,  -- DMARC result "pass"
    count_fail      INT         NOT NULL DEFAULT 0,  -- DMARC result "fail"
    count_temperror INT         NOT NULL DEFAULT 0,
    count_permperror INT        NOT NULL DEFAULT 0,
    policy_domain   TEXT,                         -- organizational domain
    policy_pct      INT         NOT NULL DEFAULT 100,
    spf_pass_count  INT         NOT NULL DEFAULT 0,
    dkim_pass_count INT         NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dmarc_reports_domain_idx ON dmarc_reports(domain);
CREATE INDEX IF NOT EXISTS dmarc_reports_period_idx ON dmarc_reports(begin_time);
CREATE UNIQUE INDEX IF NOT EXISTS dmarc_reports_domain_period_idx 
    ON dmarc_reports(domain, begin_time, end_time);

-- Clean up reports older than 30 days
-- [pg_cron→Go cron worker] SELECT cron.schedule('prune-dmarc-reports', '0 3 * * *',
--     $$ DELETE FROM dmarc_reports WHERE created_at < now() - interval '30 days'; $$);

-- Forensic (ruf) reports stored per-message
CREATE TABLE IF NOT EXISTS dmarc_forensic_reports (
    id              BIGSERIAL PRIMARY KEY,
    message_id      BIGINT,     -- soft reference to messages(id); no FK due to partitioned PK
    from_domain     TEXT        NOT NULL,
    report_uri      TEXT        NOT NULL,
    subject         TEXT,
    from_addr       TEXT,
    spf_result      TEXT,
    dkim_result     TEXT,
    dmarc_result    TEXT,
    raw_body        TEXT,                         -- raw message body for forensic report
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dmarc_forensic_domain_idx ON dmarc_forensic_reports(from_domain);
