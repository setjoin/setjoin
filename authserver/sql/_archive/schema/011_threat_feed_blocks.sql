-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 011: Threat feed CIDR blocks — Spamhaus DROP list entries.
-- Hot-swapped atomically via the threat feed refresh goroutine.
-- GiST index enables fast containment queries: cidr >>= ip.
CREATE TABLE threat_feed_blocks (
    cidr        INET        PRIMARY KEY,
    source      TEXT        NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX threat_feed_cidr_idx ON threat_feed_blocks USING gist (cidr inet_ops);
