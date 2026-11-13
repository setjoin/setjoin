-- chat_unfurl.sql: link-unfurl cache + message-payload merge (Pillar A3 QoL
-- Task 13 — full unfurl with images, SSRF-hardened at the Go fetch layer,
-- internal/chat/unfurl.go).
--
-- chat_link_previews (V122 §E) is a global url_hash-keyed cache with FORCE
-- RLS and ZERO policies — deny-all even to a function's own owner unless
-- that owner is a BYPASSRLS role (the V114/chat_space_ensure precedent:
-- SECURITY DEFINER alone is not enough — the FUNCTION OWNER is what native
-- RLS actually checks, so every reducer here that touches chat_link_previews
-- is SECURITY DEFINER + apply_worker_ownership). This is a worker/background
-- cache, never an interactive p_user_id-authorized user action — there is no
-- membership or ownership concept for a URL.
--
-- Claim/fetch/apply is a three-step protocol so two concurrent posts of the
-- SAME url only ever fetch it once (URL possession is the capability, per
-- the plan's grill-decided shared-cache posture — the cache itself carries
-- no per-user scope):
--   1. chat_link_preview_claim — the Go worker calls this FIRST for a fresh
--      url_hash; only the caller whose INSERT actually lands (ON CONFLICT DO
--      NOTHING) goes on to fetch. Everyone else calls chat_link_preview_lookup
--      instead — if status='ok', they apply the already-cached result to
--      their OWN message without fetching anything.
--   2. chat_link_preview_cache_write — the claim-winner calls this EXACTLY
--      ONCE after fetching (Go has already PUT the image bytes + inserted the
--      blobs row at ref_count=0 by this point, mirroring blob/handler.go's
--      Put), to record the final ok/error state and increment the image
--      blob's ref_count — the ONLY increment path (V122's §E comment: there
--      is no INSERT trigger to mirror, unlike message_attachments' V075).
--   3. chat_message_unfurl_apply — merges the cached preview into ONE
--      message's payload + fans out a message_edited-style notify. Called by
--      both the claim-winner (after cache_write) and every subsequent poster
--      of an already-cached URL (skipping steps 1+2 entirely).
--
-- ponytail: a caller that finds the cache row status='pending' (someone
-- else's fetch is still in flight, or a prior fetch crashed before writing a
-- result) does nothing — no retry, no queueing. The TTL eviction worker leg
-- (internal/chat, ~14d) reaps a stuck pending row same as any other, so a
-- later post of the same URL gets to re-claim and retry. Good enough for a
-- best-effort v1 enrichment; a retry queue is not built.
--
-- No new BZ code: the plan's Global Constraints allocate BZ176-179 to Tasks
-- 3/6/9/2 only. Every failure mode here (fetch denied, oversized, wrong
-- content-type, stuck pending, message soft-deleted/gone) degrades silently
-- — unfurl is best-effort enrichment, never a blocking part of send, so
-- nothing here ever RAISEs.
--
-- ── Metadata bound (occ_980dba9c476e43f3e6d8ef7e —
-- unfurl-unbounded-title-description) ────────────────────────────────────────
-- og:title / og:description are parsed from attacker-controlled page bytes
-- (up to maxHTMLBytes = 2 MiB of HTML) and V122 types both columns as
-- unbounded text, so without a bound the fetch path could persist megabytes
-- of third-party junk per URL and duplicate it into chat_messages.payload
-- via chat_message_unfurl_apply. The bound is a state invariant on the write
-- path this file owns (chat_link_previews is FORCE RLS deny-all; every write
-- is chat_link_preview_cache_write), expressed as truncation-with-marker —
-- NOT a CHECK, because a CHECK would fail the whole cache write (RAISE) and
-- this file's settled posture is silent degradation, never a blocked fetch.
-- chat_unfurl_bound_text truncates to the character cap and marks the
-- truncation with a trailing ellipsis occupying the cap's final character, so
-- the stored value is always ≤ the cap and visibly marked. Both writers bound:
-- cache_write at ingress (caps 512 title / 1024 description characters) and
-- chat_message_unfurl_apply at the payload merge (same caps — idempotent on
-- already-bounded values, so pre-bound legacy cache rows are bounded at
-- duplication too). The Go fetch path mirrors the same caps in
-- internal/chat/unfurl.go (boundUnfurlText) before it ever calls cache_write.

CREATE OR REPLACE FUNCTION chat_unfurl_bound_text(p_text text, p_max_chars integer) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    IF char_length(p_text) <= p_max_chars THEN
        RETURN p_text; -- at-cap and under-cap values pass through unmarked
    END IF;
    -- The ellipsis occupies the cap's final character: the result is always
    -- exactly p_max_chars characters (never exceeds the bound) and visibly
    -- marked as truncated.
    RETURN left(p_text, p_max_chars - 1) || '…';
END;
$$;

CREATE OR REPLACE FUNCTION chat_link_preview_claim(p_url_hash text, p_url text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    INSERT INTO chat_link_previews (url_hash, url, status)
      VALUES (p_url_hash, p_url, 'pending')
      ON CONFLICT (url_hash) DO NOTHING;
    RETURN FOUND;
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_claim(text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_link_preview_lookup(p_url_hash text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
DECLARE
    v_row chat_link_previews;
BEGIN
    SELECT * INTO v_row FROM chat_link_previews WHERE url_hash = p_url_hash;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
      'status', v_row.status, 'url', v_row.url, 'title', v_row.title,
      'description', v_row.description, 'imageBlobSha256', v_row.image_blob_sha256);
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_lookup(text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_link_preview_cache_write(
    p_url_hash text, p_title text, p_description text,
    p_image_blob_sha256 text, p_status text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    -- Metadata bound (occ_980dba9c476e43f3e6d8ef7e): the fetched page is
    -- attacker-controlled, so title/description are truncated-with-marker to
    -- this file's caps at the only write path before they can reach
    -- chat_link_previews (and from there chat_messages.payload). See the file
    -- header's "Metadata bound" section.
    UPDATE chat_link_previews
       SET title = chat_unfurl_bound_text(p_title, 512),
           description = chat_unfurl_bound_text(p_description, 1024),
           image_blob_sha256 = p_image_blob_sha256, status = p_status,
           fetched_at = now()
     WHERE url_hash = p_url_hash;
    -- the ONLY increment path for an unfurl image's ref_count (V122 §E) —
    -- the claim-winner calls this exactly once per url_hash, so there is no
    -- double-increment race to guard against here.
    IF p_image_blob_sha256 IS NOT NULL THEN
        UPDATE blobs SET ref_count = ref_count + 1 WHERE sha256 = p_image_blob_sha256;
    END IF;
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_cache_write(text,text,text,text,text)'::regprocedure);

CREATE OR REPLACE FUNCTION chat_message_unfurl_apply(p_message_id bigint, p_url_hash text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_channel_id bigint;
    v_preview    chat_link_previews;
BEGIN
    SELECT * INTO v_preview FROM chat_link_previews WHERE url_hash = p_url_hash AND status = 'ok';
    IF NOT FOUND THEN
        RETURN; -- no cached success yet (pending/error/never-fetched) — no-op
    END IF;

    -- Trusted-preview provenance (med-chat-unfurl-href-001): reduce-time
    -- scheme allowlist — the anchor href this merge produces may only ever be
    -- http(s); javascript:, data:, scheme-less/relative and malformed URLs
    -- never reach the trusted enrichment chrome. Primary gates live at the Go
    -- fetch layer and at chat_message_send (sender-supplied previews are
    -- stripped outright); this is the belt-and-braces check on the cache row
    -- itself, failing closed as a silent no-op like every other guard in this
    -- file — never a RAISE.
    --
    -- Provenance epoch marker (r2): every preview this function merges carries
    -- 'appliedBy' => 'chat_message_unfurl_apply' — the ONLY field combination
    -- the renderer trusts. Pre-fix stored rows (a forged HTTPS card smuggled
    -- in before chat_message_send stripped payload.preview, and genuine
    -- reducer-written rows alike) carry no marker and provenance is not
    -- retroactively client-verifiable, so they fail closed at render: no
    -- card. Going forward send-time stripping keeps the attacker out of
    -- payload.preview entirely, so the marker cannot be forged through any
    -- reducer path (chat_message_edit writes body only).
    IF v_preview.url IS NULL OR v_preview.url !~* '^https?://\S+$' THEN
        RETURN;
    END IF;

    SELECT channel_id INTO v_channel_id FROM chat_messages
     WHERE id = p_message_id AND deleted_at IS NULL;
    IF v_channel_id IS NULL THEN
        RETURN; -- message gone/soft-deleted by the time the fetch completed
    END IF;

    -- Chat A4a Task 8 / spec-delta 5: payload is EXEMPT from the WORM trigger
    -- (pin/poll counters need it to stay writable), and unfurl COPIES
    -- third-party title/description text into it — so without this skip, a
    -- content-bearing column would be freely mutable in an "immutable"
    -- channel and the product's own claim ("messages cannot be edited or
    -- deleted") would be false. Not fetching on behalf of a records channel
    -- is also the right compliance posture, so this is a silent no-op, not
    -- a raised error — same best-effort-enrichment posture as every other
    -- guard in this file.
    IF (SELECT classification FROM chat_channels WHERE id = v_channel_id) = 'gxp' THEN
        RETURN;
    END IF;

    -- Second bound half (occ_980dba9c476e43f3e6d8ef7e): the payload merge
    -- re-applies the same caps as cache_write, so rows cached before the bound
    -- landed (or any future unbounded writer) are still bounded at the moment
    -- their metadata duplicates into chat_messages.payload. Idempotent on
    -- already-bounded values.
    UPDATE chat_messages
       SET payload = COALESCE(payload, '{}'::jsonb) || jsonb_build_object('preview',
             jsonb_build_object('url', v_preview.url, 'title', chat_unfurl_bound_text(v_preview.title, 512),
               'description', chat_unfurl_bound_text(v_preview.description, 1024), 'imageSha256', v_preview.image_blob_sha256,
               'appliedBy', 'chat_message_unfurl_apply'))
     WHERE id = p_message_id;

    -- ponytail: no change_seq bump (same write-amplification ceiling as poll
    -- votes, chat_poll.sql) — this is async metadata enrichment arriving
    -- after the message already replayed once, not a user-visible edit; a
    -- client that missed the live push heals on its next normal fetch/
    -- re-open of the channel, not via since(seq) replay.
    PERFORM notify_chat_state(v_channel_id, 'message_edited', p_message_id, NULL);
END;
$$;
SELECT apply_worker_ownership('chat_message_unfurl_apply(bigint,text)'::regprocedure);

-- chat_link_preview_image_owner: the authorization boundary for the image-
-- serving route (GET /chat/unfurl/image/{sha256}, internal/chat/unfurl.go).
-- blobs is a GLOBAL content-addressed table shared with mail attachments/
-- Drive/HR receipts — without this check, the route would be an oracle for
-- ANY blob's bytes+content-type given its bare sha256, not just unfurl
-- images. Only a sha256 actually cached as a successful unfurl image is
-- servable.
CREATE OR REPLACE FUNCTION chat_link_preview_image_owner(p_sha256 text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog, public AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM chat_link_previews
                    WHERE image_blob_sha256 = p_sha256 AND status = 'ok');
END;
$$;
SELECT apply_worker_ownership('chat_link_preview_image_owner(text)'::regprocedure);
