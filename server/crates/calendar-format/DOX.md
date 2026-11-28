# Shared calendar format (#526)
Pure Go-compatible iCalendar parsing and migration JSON, extracted from the gateway
without behavior changes. Gateway `ics` re-exports its original API. SMTP uses
`parse_itip`: duplicate METHOD fails, exact VEVENT markers and the first event.
No database, authentication or calendar authority lives here. Qualification:
SMTP enabled_imip_* socket/DB Go replays and existing gateway calendar worker/import replays.
