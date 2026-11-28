-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Calendar: RFC 5545 iCalendar model. JMAP primary; CalDAV bridge reads same tables.
CREATE TABLE calendars (
  id              BIGSERIAL   PRIMARY KEY,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name            TEXT        NOT NULL,
  color           TEXT,                   -- hex color e.g. '#4A90D9'
  description     TEXT,
  timezone        TEXT        NOT NULL DEFAULT 'UTC',
  is_default      BOOL        NOT NULL DEFAULT FALSE,
  is_shared       BOOL        NOT NULL DEFAULT FALSE,
  ical_feed_url   TEXT,                   -- external iCal subscription URL
  jmap_state      BIGINT      NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX calendars_mailbox_idx ON calendars(mailbox_id);
CREATE UNIQUE INDEX calendars_default_idx ON calendars(mailbox_id) WHERE is_default;

CREATE TABLE calendar_acls (
  calendar_id     BIGINT  NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  user_id         BIGINT  NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
  permission      TEXT    NOT NULL CHECK (permission IN ('read','write','admin')),
  PRIMARY KEY (calendar_id, user_id)
);

CREATE TABLE calendar_events (
  id              BIGSERIAL   PRIMARY KEY,
  calendar_id     BIGINT      NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  uid             TEXT        NOT NULL,   -- iCalendar UID (stable across updates)
  component_type  TEXT        NOT NULL DEFAULT 'VEVENT'
                    CHECK (component_type IN ('VEVENT','VTODO','VJOURNAL')),

  -- VEVENT fields
  title           TEXT        NOT NULL,
  description     TEXT,
  location        TEXT,
  url             TEXT,
  start_at        TIMESTAMPTZ,            -- NULL for VTODO without DTSTART
  end_at          TIMESTAMPTZ,            -- NULL for VTODO without DUE
  all_day         BOOL        NOT NULL DEFAULT FALSE,
  timezone        TEXT,

  -- VTODO fields
  priority        INT         CHECK (priority BETWEEN 0 AND 9),
  percent_complete INT        CHECK (percent_complete BETWEEN 0 AND 100),
  completed_at    TIMESTAMPTZ,
  due_at          TIMESTAMPTZ,            -- VTODO DUE date

  -- Recurrence (RFC 5545)
  rrule           TEXT,                   -- RRULE: string verbatim
  rdate           TIMESTAMPTZ[],          -- RDATE values
  exdate          TIMESTAMPTZ[],          -- EXDATE exceptions

  -- Exception to a recurring event
  recurrence_id   TIMESTAMPTZ,            -- identifies which occurrence this overrides

  -- Status (VEVENT: confirmed/tentative/cancelled; VTODO: needs-action/in-progress/completed/cancelled)
  status          TEXT        NOT NULL DEFAULT 'confirmed'
                    CHECK (status IN ('confirmed','tentative','cancelled','needs-action','in-progress','completed')),

	  -- Transparency (RFC 5545 §3.8.2.7): OPAQUE blocks time; TRANSPARENT is free.
	  transp          TEXT        NOT NULL DEFAULT 'OPAQUE'
	                    CHECK (transp IN ('OPAQUE', 'TRANSPARENT')),

  -- Meeting
  is_meeting      BOOL        NOT NULL DEFAULT FALSE,
  meeting_url     TEXT,
  organizer_email TEXT,
  organizer_name  TEXT,
  sequence        INT         NOT NULL DEFAULT 0, -- iTIP sequence number for updates

  -- VALARM data (parsed but not triggered)
  valarm          JSONB,                  -- array of {trigger, action, description}

  -- JMAP / CalDAV sync
  jmap_state      BIGINT      NOT NULL DEFAULT 0,
  etag            TEXT,                   -- CalDAV ETag (computed on write)

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The recurrence-aware unique index on (calendar_id, uid, recurrence_override) is
-- defined in schema/046_calendar_recurrence.sql, because it must include the
-- recurrence_override column that 046 adds (an exception event shares the master's
-- uid, distinguished by its RECURRENCE-ID override). It cannot live here —
-- recurrence_override does not exist yet at this point in the load.

CREATE INDEX events_calendar_idx ON calendar_events(calendar_id);
CREATE INDEX events_range_idx    ON calendar_events(start_at, end_at);
CREATE INDEX events_uid_idx      ON calendar_events(uid);

CREATE TABLE event_attendees (
  id          BIGSERIAL   PRIMARY KEY,
  event_id    BIGINT      NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
  email       TEXT        NOT NULL,
  name        TEXT,
  role        TEXT        NOT NULL DEFAULT 'required'
                CHECK (role IN ('organizer','required','optional','resource')),
  status      TEXT        NOT NULL DEFAULT 'needs-action'
                CHECK (status IN ('needs-action','accepted','declined','tentative')),
  rsvp        BOOL        NOT NULL DEFAULT TRUE
);

CREATE INDEX attendees_event_idx ON event_attendees(event_id);
CREATE INDEX attendees_email_idx ON event_attendees(email);
CREATE INDEX calendar_acls_user_idx ON calendar_acls(user_id);

-- VTIMEZONE definitions (RFC 5545 §3.6.5).
-- Stores timezone STANDARD and DAYLIGHT sub-component data per calendar.
CREATE TABLE vt_timezone (
  id              BIGSERIAL   PRIMARY KEY,
  calendar_id     BIGINT      NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  tzid            TEXT        NOT NULL,   -- e.g. "America/New_York" or custom TZID
  standard        JSONB,                  -- {offset_from, offset_to, dtstart, rrule, tzname}
  daylight        JSONB,                  -- same shape as standard
  UNIQUE (calendar_id, tzid)
);
