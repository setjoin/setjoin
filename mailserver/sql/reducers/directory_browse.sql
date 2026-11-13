-- Directory Browser: department tree + member listing + search for the GAL /
-- HAB-style browsing. Leverages the departments hierarchy (parent_id + path).
--
-- ORG-WIDE (ADR-004, docs/adr/ARCH-004-directory-org-scope.md): a setjoin
-- deployment is exactly ONE organization. Email domains / AD forests are
-- mail-routing + AD-sync boundaries WITHIN that org, not tenant boundaries. The
-- directory therefore spans every domain/forest of the deployment. There is no
-- `u.domain_id = <home domain>` scoping anywhere in the directory — that filter
-- (removed here) fragmented one org across its own AD domains and hid colleagues
-- on sister domains. `departments` has no `domain_id` and stays org-wide.
--
-- ONE VISIBILITY SEAM (ADR-004 §4): the "who can this caller see" rule lives in
-- a SINGLE place — `directory_visible_users(p_mailbox_id)`. `directory_members`,
-- `directory_search`, `directory_tree`'s people lookups, and `gal_search`
-- (jmap_contact.sql) all read the seam; none re-derives scope, so they cannot
-- drift apart again (the inconsistency ADR-004 fixes).
--
-- ADDRESS-AWARE (ADR-004 §3): a directory entry is a PERSON with a full address
-- set — `users.email` (primary) ∪ `aliases.email` (every alias on the person's
-- mailboxes) ∪ `users.ad_upn` (UPN). The seam exposes that set as `addresses`
-- (JSONB array of {email, type, isPrimary}) for the result card, and a flat
-- `address_blob` for case-insensitive matching. Search and the returned card
-- both honor the full set (Exchange GAL parity), not just `users.email`.
--

-- directory_address_set: the full address set for ONE person (user), as a JSONB
-- array of {email, type, isPrimary}. primary = users.email; aliases pulled from
-- every mailbox the user owns; UPN appended when present and not already covered.
-- Deduplicated case-insensitively, primary first. The single owner of "a person's
-- addresses" — gal_search/directory_search render it verbatim.
CREATE OR REPLACE FUNCTION directory_address_set(
  p_user_id    BIGINT,
  p_email      TEXT,
  p_ad_upn     TEXT
) RETURNS JSONB AS $$
  WITH addrs AS (
    -- primary
    SELECT lower(p_email) AS email, 'primary'::TEXT AS type, TRUE AS is_primary, 0 AS ord
    WHERE p_email IS NOT NULL
    UNION ALL
    -- aliases on any mailbox the person owns
    SELECT lower(a.email), 'alias', a.is_primary, 1
    FROM aliases a
    JOIN mailboxes m ON m.id = a.mailbox_id
    WHERE m.user_id = p_user_id
    UNION ALL
    -- AD userPrincipalName
    SELECT lower(p_ad_upn), 'upn', FALSE, 2
    WHERE p_ad_upn IS NOT NULL AND p_ad_upn <> ''
  ),
  dedup AS (
    SELECT DISTINCT ON (email) email, type, is_primary, ord
    FROM addrs
    ORDER BY email, ord  -- primary type wins over alias/upn for the same address
  )
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object('email', email, 'type', type, 'isPrimary', is_primary)
      ORDER BY ord, email
    ),
    '[]'::JSONB
  )
  FROM dedup;
$$ LANGUAGE sql STABLE;

-- directory_visible_users: THE org-wide visibility seam (ADR-004 §4). Returns the
-- set of people the caller (p_mailbox_id) may see in the directory, address-aware.
-- Today the rule is: every enabled user whose primary mailbox is not hidden from
-- the GAL — ORG-WIDE (no domain filter). p_mailbox_id is accepted so the rule can
-- evolve to a per-caller policy without changing any consumer; it is currently
-- validated only as a known mailbox (zero rows for an unknown caller, fail-safe).
-- `address_blob` is the space-joined lower-cased address set for ILIKE matching;
-- `addresses` is the structured set for the result card.
CREATE OR REPLACE FUNCTION directory_visible_users(
  p_mailbox_id BIGINT
) RETURNS TABLE(
  id            BIGINT,
  email         TEXT,
  display_name  TEXT,
  first_name    TEXT,
  last_name     TEXT,
  phone         TEXT,
  job_title     TEXT,
  department_id BIGINT,
  dept_name     TEXT,
  avatar_sha256 TEXT,
  is_manager    BOOLEAN,
  addresses     JSONB,
  address_blob  TEXT
) AS $$
  SELECT
    u.id, u.email, u.display_name, u.first_name, u.last_name,
    u.phone, u.job_title, u.department_id, d.name AS dept_name, u.avatar_sha256,
    EXISTS(SELECT 1 FROM users mu WHERE mu.manager_id = u.id AND mu.enabled = TRUE) AS is_manager,
    directory_address_set(u.id, u.email, u.ad_upn) AS addresses,
    (
      -- flat, lower-cased address set for case-insensitive substring matching
      SELECT string_agg(elem->>'email', ' ')
      FROM jsonb_array_elements(directory_address_set(u.id, u.email, u.ad_upn)) elem
    ) AS address_blob
  FROM users u
  LEFT JOIN departments d ON d.id = u.department_id
  WHERE u.enabled = TRUE
    -- Guest P7: guests are external collaborators, never org-directory
    -- principals. Exclude on discriminator presence, not lifecycle status, so
    -- invited/active/disabled/expired guests all remain invisible. This shared
    -- seam also feeds GAL search + CardDAV and keeps every end-user directory
    -- surface aligned. Use the RLS-safe SECURITY DEFINER helper: a raw
    -- guest_accounts NOT EXISTS would see zero rows under setjoin_app's
    -- self-read-only FORCE-RLS policy and fail open.
    AND NOT is_guest_account(u.id)
    -- hidden_from_gal (bug fix): a person's primary mailbox can opt out of the
    -- GAL/directory entirely — the column has existed since V001 but this seam
    -- never checked it (dead flag; retired-docs:superpowers/plans/archive/2026-07-08-gal-carddav-collection.md
    -- T1). Every seam consumer (directory_members/search/tree, gal_search, and
    -- the LDAP People search/base/Compare adapter) inherits the same rule.
    AND NOT EXISTS (SELECT 1 FROM mailboxes pm
                    WHERE pm.user_id = u.id AND pm.is_primary AND pm.hidden_from_gal)
    -- org-wide: NO domain filter (ADR-004). Caller-existence keeps an unknown
    -- mailbox from listing the org (fail-safe), without re-introducing scope.
    AND EXISTS (SELECT 1 FROM mailboxes cm WHERE cm.id = p_mailbox_id);
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION directory_tree(
  p_mailbox_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  -- People counts/flags below read the org-wide visibility seam (one rule), so
  -- the tree's member math matches directory_members / directory_search exactly.
  FOR v_row IN
    WITH RECURSIVE visible AS (
      SELECT v.id, v.department_id, v.is_manager FROM directory_visible_users(p_mailbox_id) v
    ),
    dept_tree AS (
      SELECT d.id, d.name, d.parent_id, d.path, 0 AS depth,
             (SELECT COUNT(*) FROM visible vu WHERE vu.department_id = d.id) AS member_count,
             EXISTS(SELECT 1 FROM visible vu WHERE vu.department_id = d.id AND vu.is_manager) AS has_managers
      FROM departments d
      WHERE d.parent_id IS NULL
      UNION ALL
      SELECT d.id, d.name, d.parent_id, d.path, dt.depth + 1,
             (SELECT COUNT(*) FROM visible vu WHERE vu.department_id = d.id),
             EXISTS(SELECT 1 FROM visible vu WHERE vu.department_id = d.id AND vu.is_manager)
      FROM departments d
      JOIN dept_tree dt ON d.parent_id = dt.id
    )
    SELECT * FROM dept_tree ORDER BY depth, name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'name', v_row.name,
      'parentId', CASE WHEN v_row.parent_id IS NOT NULL THEN v_row.parent_id::TEXT END,
      'path', v_row.path,
      'depth', v_row.depth,
      'memberCount', v_row.member_count,
      'hasManagers', v_row.has_managers
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', '-1',
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql;

-- directory_members: returns users in a department, sorted manager-first.
-- ORG-WIDE + address-aware via the directory_visible_users seam (ADR-004).
CREATE OR REPLACE FUNCTION directory_members(
  p_mailbox_id   BIGINT,
  p_department_id BIGINT,
  p_offset       INT DEFAULT 0,
  p_limit        INT DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_result  JSONB := '[]'::JSONB;
  v_row     RECORD;
  v_total   INT;
BEGIN
  SELECT COUNT(*) INTO v_total
  FROM directory_visible_users(p_mailbox_id) v
  WHERE v.department_id = p_department_id;

  FOR v_row IN
    SELECT v.*
    FROM directory_visible_users(p_mailbox_id) v
    WHERE v.department_id = p_department_id
    ORDER BY v.is_manager DESC, v.display_name
    OFFSET p_offset LIMIT p_limit
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'email', v_row.email,
      'addresses', v_row.addresses,
      'displayName', v_row.display_name,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'phone', v_row.phone,
      'jobTitle', v_row.job_title,
      'department', v_row.dept_name,
      'isManager', v_row.is_manager,
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'departmentId', p_department_id::TEXT,
    'list', v_result,
    'total', v_total,
    'offset', p_offset
  );
END;
$$ LANGUAGE plpgsql;

-- directory_search: search for users matching query across the full address set.
-- ORG-WIDE + address-aware via the directory_visible_users seam (ADR-004): the
-- query matches display name, the WHOLE address set (primary ∪ aliases ∪ UPN),
-- names, department, and job title; the card returns every address.
CREATE OR REPLACE FUNCTION directory_search(
  p_mailbox_id BIGINT,
  p_query      TEXT,
  p_limit      INT DEFAULT 50
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  FOR v_row IN
    SELECT v.*
    FROM directory_visible_users(p_mailbox_id) v
    WHERE (p_query = '' OR v.display_name ILIKE '%' || p_query || '%'
                       OR v.address_blob ILIKE '%' || p_query || '%'
                       OR v.first_name ILIKE '%' || p_query || '%'
                       OR v.last_name ILIKE '%' || p_query || '%'
                       OR v.dept_name ILIKE '%' || p_query || '%'
                       OR v.job_title ILIKE '%' || p_query || '%')
    ORDER BY v.display_name
    LIMIT p_limit
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'email', v_row.email,
      'addresses', v_row.addresses,
      'displayName', v_row.display_name,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'phone', v_row.phone,
      'jobTitle', v_row.job_title,
      'department', v_row.dept_name,
      'isManager', v_row.is_manager,
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END
    );
  END LOOP;

  RETURN jsonb_build_object(
    'accountId', p_mailbox_id::TEXT,
    'list', v_result
  );
END;
$$ LANGUAGE plpgsql;
