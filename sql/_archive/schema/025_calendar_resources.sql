-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Calendar resource types and booking policies for rooms and equipment.
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS resource_type TEXT
  CHECK (resource_type IN ('personal','room','equipment')) DEFAULT 'personal';
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS booking_policy TEXT
  CHECK (booking_policy IN ('auto-accept','manual','decline-conflict')) DEFAULT 'auto-accept';
ALTER TABLE calendars ADD COLUMN IF NOT EXISTS capacity INT;

CREATE INDEX IF NOT EXISTS calendars_resource_type_idx ON calendars(resource_type) WHERE resource_type != 'personal';
