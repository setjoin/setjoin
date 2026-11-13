-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Departments: drives the LDAP OU tree structure.
-- Admin defines the hierarchy here; the LDAP server reads it.
CREATE TABLE departments (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT    NOT NULL,
  parent_id   BIGINT  REFERENCES departments(id) ON DELETE SET NULL,
  path        TEXT    NOT NULL UNIQUE, -- materialized path e.g. 'Engineering/Backend'
  ldap_ou     TEXT    NOT NULL,        -- OU name exposed in LDAP tree
  sort_order  INT     NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX departments_parent_idx ON departments(parent_id);
CREATE INDEX departments_path_idx   ON departments(path);
