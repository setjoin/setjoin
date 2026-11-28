-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V091__dsn_via_scheduled_action.sql
-- WAVE 9 — move the one genuine logic-misplacement in the trigger layer: the RFC
-- 5322 Delivery Status Notification (bounce) that was synthesized and deliver()-ed
-- SYNCHRONOUSLY from inside the AFTER UPDATE trigger on outbound_queue
-- (schema/013_queues.sql). Plan: docs/superpowers/plans/archive/2026-06-18-trigger-families-dsn-misplacement.md.
--
-- The misplacement (four axes): a full inbound-delivery pipeline call (deliver(),
-- the heaviest reducer) ran as a side-effect of a status UPDATE, INSIDE the Go
-- egress worker's bounce-setter txn, with NO retry and NO idempotency, and ZERO
-- pgTAP coverage. A deliver() RAISE rolled back the bounce-status UPDATE → the dead
-- message requeued forever.
--
-- The move (B0 — a new `dsn` action_kind; action_kind has NO CHECK so NO column
-- migration): the trigger shrinks to a single enqueue_scheduled_action('dsn', …);
-- the new scheduled_action_dsn(p_action) handler does the sender resolution (via the
-- ADR-004 resolve_identity seam — address-aware, so an alias/UPN sender still gets
-- their bounce) + the byte-for-byte-preserved MIME build + the deliver() call, now
-- async + retried + crash-reclaimable + idempotent (dedup_key='dsn:'||queue_id) +
-- tested. The bounce STATUS write stays synchronous (the Go worker commits it); only
-- the bounce EMAIL defers (≤1 min via the @every-1m dispatcher).
--
-- This migration converges an EXISTING DB onto the same end-state the fresh-load path
-- (load-test-schema.sh → V001 + reducers ×2) reaches: it loads the new handler reducer,
-- CREATE-OR-REPLACEs the enqueue + dispatch reducers to gate the `dsn` kind, and
-- CREATE-OR-REPLACEs the trigger function to its enqueue-only body. The frozen V001
-- replay of schema/013 installs the (now shrunk) trigger; this migration is the
-- idempotent existing-DB twin. CREATE OR REPLACE FUNCTION is replay-safe.

-- 1. The new handler. -- deps: deliver, resolve_identity (both already loaded by V001
--    + the reducer pass; resolve_identity shipped in V088).
\i ../reducers/scheduled_action_dsn.sql

-- 2. Gate the `dsn` kind in the single writer + the kind→handler router.
\i ../reducers/scheduled_action_enqueue.sql
\i ../reducers/scheduled_actions_dispatch.sql

-- 3. Shrink the trigger function to enqueue-only (the trigger BINDING is unchanged;
--    function bodies are replaceable even though schema/013 is frozen).
CREATE OR REPLACE FUNCTION trg_outbound_queue_dsn() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'bounced' AND (OLD.status IS NULL OR OLD.status != 'bounced') THEN
        PERFORM enqueue_scheduled_action(
            'dsn',
            now(),
            jsonb_build_object('queue_id', NEW.id),
            NEW.mailbox_id,            -- owner (may be NULL; handler defer-resolves the sender)
            'dsn:' || NEW.id::TEXT     -- idempotency: a reclaim re-enqueue is a no-op
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
