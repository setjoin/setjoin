//! Static typed SQL contract catalog for `setjoin-calendar` (F17).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

macro_rules! contact_columns {
    () => {
        "c.vcard_uid, c.display_name, c.first_name, c.last_name, c.company, \
         c.job_title, c.department, c.emails::text, c.phones::text, c.addresses::text, c.urls::text, \
         c.instant_msgs::text, c.notes, to_char(c.birthday,'YYYYMMDD'), to_char(c.anniversary,'YYYYMMDD'), \
         c.avatar_sha256, to_jsonb(c.categories)::text, \
         to_char(c.updated_at AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')"
    };
}

const CONTACT_ROW_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("vcard_uid", Type::TEXT),
    ColumnSpec::named("display_name", Type::TEXT),
    ColumnSpec::named("first_name", Type::TEXT),
    ColumnSpec::named("last_name", Type::TEXT),
    ColumnSpec::named("company", Type::TEXT),
    ColumnSpec::named("job_title", Type::TEXT),
    ColumnSpec::named("department", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("notes", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("avatar_sha256", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
];

const CARDDAV_CONTACT_COLUMNS: &[ColumnSpec] = &[
    ColumnSpec::named("vcard_uid", Type::TEXT),
    ColumnSpec::named("display_name", Type::TEXT),
    ColumnSpec::named("first_name", Type::TEXT),
    ColumnSpec::named("last_name", Type::TEXT),
    ColumnSpec::named("company", Type::TEXT),
    ColumnSpec::named("job_title", Type::TEXT),
    ColumnSpec::named("department", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("notes", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("avatar_sha256", Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::unnamed(Type::TEXT),
    ColumnSpec::named("id", Type::INT8),
    ColumnSpec::named("etag", Type::TEXT),
    ColumnSpec::named("addressbook_id", Type::INT8),
];

pub const FLAG: SqlContract = SqlContract {
    id: "calendar.flag",
    domain: "calendar",
    sql: "SELECT enabled FROM feature_toggles WHERE key = $1",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ENTITLED_APP: SqlContract = SqlContract {
    id: "calendar.entitled_app",
    domain: "calendar",
    sql: "SELECT check_user_app_entitlement($1,$2)",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PAGE_LIST: SqlContract = SqlContract {
    id: "calendar.page_list",
    domain: "calendar",
    sql: "SELECT booking_page_list($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PAGE_UPSERT: SqlContract = SqlContract {
    id: "calendar.page_upsert",
    domain: "calendar",
    sql: "SELECT booking_page_upsert($1, $2::text::jsonb)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PAGE_DELETE: SqlContract = SqlContract {
    id: "calendar.page_delete",
    domain: "calendar",
    sql: "SELECT booking_page_delete($1, $2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_PUBLIC_GET: SqlContract = SqlContract {
    id: "calendar.booking_public_get",
    domain: "calendar",
    sql: "SELECT COALESCE(booking_page_public_get($1), 'null'::jsonb)::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_SLOTS: SqlContract = SqlContract {
    id: "calendar.booking_slots",
    domain: "calendar",
    sql: "SELECT booking_slots($1, $2::text::date, $3::text::date)::text",
    params: &[Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_CREATE: SqlContract = SqlContract {
    id: "calendar.booking_create",
    domain: "calendar",
    sql: "SELECT booking_create($1, $2::text::timestamptz, $3, $4, $5::text::jsonb, $6, $7::text::inet)::text",
    params: &[
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_CONFIRM: SqlContract = SqlContract {
    id: "calendar.booking_confirm",
    domain: "calendar",
    sql: "SELECT booking_confirm($1, $2)::text",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_CANCEL: SqlContract = SqlContract {
    id: "calendar.booking_cancel",
    domain: "calendar",
    sql: "SELECT booking_cancel($1)::text",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const BOOKING_EXPIRE_DUE: SqlContract = SqlContract {
    id: "calendar.booking_expire_due",
    domain: "calendar",
    sql: "SELECT booking_expire_due()",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::INT4)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FREE_BUSY_MULTI: SqlContract = SqlContract {
    id: "calendar.free_busy_multi",
    domain: "calendar",
    sql: "SELECT calendar_free_busy_multi($1, $2, $3::text::timestamptz, $4::text::timestamptz)::text",
    params: &[Type::INT8, Type::INT8_ARRAY, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBSCRIPTIONS_LIST: SqlContract = SqlContract {
    id: "calendar.subscriptions_list",
    domain: "calendar",
    sql: "SELECT s.id, s.calendar_id::text, c.name, s.url, \
                 to_char(s.last_fetch_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                 s.last_status, s.last_error, s.refresh_interval_minutes \
            FROM calendar_subscriptions s \
            JOIN calendars c ON c.id = s.calendar_id \
           WHERE s.user_id = $1 \
           ORDER BY s.created_at",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("url", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("last_status", Type::TEXT),
        ColumnSpec::named("last_error", Type::TEXT),
        ColumnSpec::named("refresh_interval_minutes", Type::INT4),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const SUBSCRIPTION_COUNT: SqlContract = SqlContract {
    id: "calendar.subscription_count",
    domain: "calendar",
    sql: "SELECT count(*) FROM calendar_subscriptions WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareExplainAndRlsDenyProbe,
    audit: SqlAuditPosture::Standard,
};

pub const SUBSCRIPTION_COUNT_UNSCOPED_MUTANT: SqlContract = SqlContract {
    id: "calendar.subscription_count_unscoped_mutant",
    domain: "calendar",
    sql: "SELECT count(*) FROM calendar_subscriptions WHERE user_id = $1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SUBSCRIBE: SqlContract = SqlContract {
    id: "calendar.subscribe",
    domain: "calendar",
    sql: "SELECT sub_id, calendar_id FROM rust_calendar_subscribe($1, $2, $3, $4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[
        ColumnSpec::named("sub_id", Type::INT8),
        ColumnSpec::named("calendar_id", Type::INT8),
    ],
    scope: SqlScope::MailboxReadWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UNSUBSCRIBE: SqlContract = SqlContract {
    id: "calendar.unsubscribe",
    domain: "calendar",
    sql: "SELECT rust_calendar_unsubscribe(0::bigint, $1, $2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OWNED_MAILBOX_FOR_BOOK: SqlContract = SqlContract {
    id: "calendar.contacts.owned_mailbox_for_book",
    domain: "calendar",
    sql: "SELECT mb.id FROM addressbooks ab \
            JOIN mailboxes mb ON mb.id = ab.mailbox_id \
           WHERE ab.id = $1 AND mb.user_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OWNS_CONTACT: SqlContract = SqlContract {
    id: "calendar.contacts.owns_contact",
    domain: "calendar",
    sql: "SELECT true FROM contacts c \
            JOIN addressbooks ab ON ab.id = c.addressbook_id \
            JOIN mailboxes mb ON mb.id = ab.mailbox_id \
           WHERE c.id = $1 AND mb.user_id = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTACT_EXISTS: SqlContract = SqlContract {
    id: "calendar.contacts.exists",
    domain: "calendar",
    sql: "SELECT EXISTS(\
            SELECT 1 FROM contacts c \
              JOIN addressbooks ab ON ab.id = c.addressbook_id \
             WHERE c.addressbook_id = $1 AND c.vcard_uid = $2 AND ab.mailbox_id = $3)",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WRITE_CONTACT: SqlContract = SqlContract {
    id: "calendar.contacts.write_contact",
    domain: "calendar",
    sql: "SELECT rust_contacts_import_write($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REMOVE_CONTACT: SqlContract = SqlContract {
    id: "calendar.contacts.remove_contact",
    domain: "calendar",
    sql: "SELECT rust_contacts_import_remove($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NOTIFY_IMPORT: SqlContract = SqlContract {
    id: "calendar.contacts.notify_import",
    domain: "calendar",
    sql: "SELECT notify_contact_state($1, 'contact_created', NULL)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_CSV_ROWS: SqlContract = SqlContract {
    id: "calendar.contacts.export_csv_rows",
    domain: "calendar",
    sql: "SELECT COALESCE(first_name,''), COALESCE(last_name,''), COALESCE(display_name,''), \
                 COALESCE(company,''), COALESCE(job_title,''), \
                 COALESCE(emails,'[]'::jsonb)::text, COALESCE(phones,'[]'::jsonb)::text, \
                 COALESCE(notes,'') \
            FROM contacts \
           WHERE addressbook_id = $1 \
             AND EXISTS (SELECT 1 FROM addressbooks ab JOIN mailboxes mb ON mb.id = ab.mailbox_id \
                          WHERE ab.id = $1 AND mb.user_id = $2) \
           ORDER BY display_name",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_VCARD_ROWS: SqlContract = SqlContract {
    id: "calendar.contacts.export_vcard_rows",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        " FROM contacts c \
           JOIN addressbooks ab ON ab.id = c.addressbook_id \
           JOIN mailboxes mb ON mb.id = ab.mailbox_id \
          WHERE c.addressbook_id = $1 AND mb.user_id = $2 \
          ORDER BY c.display_name"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: CONTACT_ROW_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_VCARD_ROW: SqlContract = SqlContract {
    id: "calendar.contacts.export_vcard_row",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        " FROM contacts c \
           JOIN addressbooks ab ON ab.id = c.addressbook_id \
           JOIN mailboxes mb ON mb.id = ab.mailbox_id \
          WHERE c.id = $1 AND mb.user_id = $2"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: CONTACT_ROW_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_CALENDARS: SqlContract = SqlContract {
    id: "calendar.dav.calendars",
    domain: "calendar",
    sql: "SELECT c.id,c.mailbox_id,c.name,c.timezone FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE mb.user_id=$1 ORDER BY c.name",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("timezone", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_CALENDAR: SqlContract = SqlContract {
    id: "calendar.dav.calendar",
    domain: "calendar",
    sql: "SELECT c.id,c.mailbox_id,c.name,c.timezone FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$1 AND mb.user_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("timezone", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_EVENT: SqlContract = SqlContract {
    id: "calendar.dav.event",
    domain: "calendar",
    sql: "SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND ce.uid=$2 AND mb.user_id=$3 AND ce.recurrence_override IS NULL",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_TIMEZONE_CATALOG: SqlContract = SqlContract {
    id: "calendar.dav.timezone_catalog",
    domain: "calendar",
    sql: "SELECT calendar_id,tzid,standard::text FROM vt_timezone",
    params: &[],
    columns: &[
        ColumnSpec::named("calendar_id", Type::INT8),
        ColumnSpec::named("tzid", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_OWNED_TIMEZONE: SqlContract = SqlContract {
    id: "calendar.dav.owned_timezone",
    domain: "calendar",
    sql: "SELECT v.standard::text FROM vt_timezone v JOIN calendars c ON c.id=v.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE v.calendar_id=$1 AND v.tzid=$2 AND mb.user_id=$3",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_OVERRIDES: SqlContract = SqlContract {
    id: "calendar.dav.overrides",
    domain: "calendar",
    sql: "SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND ce.uid=$2 AND mb.user_id=$3 AND ce.recurrence_override IS NOT NULL ORDER BY ce.recurrence_override",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_EVENTS: SqlContract = SqlContract {
    id: "calendar.dav.events",
    domain: "calendar",
    sql: "SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND mb.user_id=$2 AND ce.recurrence_override IS NULL AND (NULLIF($3,'') IS NULL OR ce.end_at>NULLIF($3,'')::timestamptz) AND (NULLIF($4,'') IS NULL OR ce.start_at<NULLIF($4,'')::timestamptz) ORDER BY ce.start_at LIMIT $5",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_SYNC: SqlContract = SqlContract {
    id: "calendar.dav.sync",
    domain: "calendar",
    sql: "SELECT caldav_changes($1,'CalendarEvent',$2,$3)::text WHERE EXISTS(SELECT 1 FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND c.mailbox_id=$1 AND mb.user_id=$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_FREE_BUSY: SqlContract = SqlContract {
    id: "calendar.dav.free_busy",
    domain: "calendar",
    sql: "SELECT calendar_free_busy($1,ARRAY[c.mailbox_id],$4::text::timestamptz,$5::text::timestamptz)::text FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND mb.user_id=$3",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_CREATE: SqlContract = SqlContract {
    id: "calendar.dav.create",
    domain: "calendar",
    sql: "SELECT jmap_calendar_event_set_create(c.mailbox_id,$1,$3,$4::text::jsonb)::text FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND mb.user_id=$1",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_EVENT_ETAG: SqlContract = SqlContract {
    id: "calendar.dav.event_etag",
    domain: "calendar",
    sql: "SELECT ce.etag FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.id=$1 AND mb.user_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("etag", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_UPDATE: SqlContract = SqlContract {
    id: "calendar.dav.update",
    domain: "calendar",
    sql: "SELECT jmap_calendar_event_set_update(c.mailbox_id,$4::text::jsonb)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_OCCURRENCE: SqlContract = SqlContract {
    id: "calendar.dav.occurrence",
    domain: "calendar",
    sql: "SELECT jmap_calendar_event_set_occurrence(c.mailbox_id,ce.id,$4::text::timestamptz,'this',$5::text::jsonb)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_DESTROY: SqlContract = SqlContract {
    id: "calendar.dav.destroy",
    domain: "calendar",
    sql: "SELECT jmap_calendar_event_set_destroy(c.mailbox_id,ARRAY[ce.id])::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DAV_BLOCKED_AUDIT: SqlContract = SqlContract {
    id: "calendar.dav.blocked_audit",
    domain: "calendar",
    sql: "SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,'calendar','routine')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_BLOCKED_AUDIT: SqlContract = SqlContract {
    id: "calendar.carddav.blocked_audit",
    domain: "calendar",
    sql: "SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,'contacts','routine')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_BOOKS: SqlContract = SqlContract {
    id: "calendar.carddav.books",
    domain: "calendar",
    sql: "SELECT ab.id,ab.mailbox_id,ab.name,coalesce(ab.description,'') FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE mb.user_id=$1 ORDER BY ab.name",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_GET_CONTACT: SqlContract = SqlContract {
    id: "calendar.carddav.get_contact",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        ",c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.addressbook_id=$1 AND c.vcard_uid=$2 AND mb.user_id=$3"
    ),
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: CARDDAV_CONTACT_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_BOOK: SqlContract = SqlContract {
    id: "calendar.carddav.book",
    domain: "calendar",
    sql: "SELECT ab.id,ab.mailbox_id,ab.name,coalesce(ab.description,'') FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$1 AND mb.user_id=$2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("id", Type::INT8),
        ColumnSpec::named("mailbox_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_LIST_CONTACTS: SqlContract = SqlContract {
    id: "calendar.carddav.list_contacts",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        ",c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.addressbook_id=$1 AND mb.user_id=$2 ORDER BY c.display_name"
    ),
    params: &[Type::INT8, Type::INT8],
    columns: CARDDAV_CONTACT_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_SEARCH_CONTACTS: SqlContract = SqlContract {
    id: "calendar.carddav.search_contacts",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        ",c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE mb.user_id=$1 AND ($2<=0 OR c.addressbook_id=$2) AND ($3='' OR c.display_name ILIKE $4 OR c.emails::text ILIKE $4) ORDER BY c.display_name LIMIT 1000"
    ),
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: CARDDAV_CONTACT_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_CONTACTS_BY_UIDS: SqlContract = SqlContract {
    id: "calendar.carddav.contacts_by_uids",
    domain: "calendar",
    sql: concat!(
        "SELECT ",
        contact_columns!(),
        ",c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.vcard_uid=ANY($1) AND mb.user_id=$2"
    ),
    params: &[Type::TEXT_ARRAY, Type::INT8],
    columns: CARDDAV_CONTACT_COLUMNS,
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_SYNC: SqlContract = SqlContract {
    id: "calendar.carddav.sync",
    domain: "calendar",
    sql: "SELECT caldav_changes($1,'ContactCard',$2,$3)::text WHERE EXISTS(SELECT 1 FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND ab.mailbox_id=$1 AND mb.user_id=$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::MailboxReadOnly,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_CREATE: SqlContract = SqlContract {
    id: "calendar.carddav.create",
    domain: "calendar",
    sql: "SELECT jmap_contact_set_create(ab.mailbox_id,$3::text::jsonb)::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_UPDATE: SqlContract = SqlContract {
    id: "calendar.carddav.update",
    domain: "calendar",
    sql: "SELECT jmap_contact_set_update(ab.mailbox_id,$4::text::jsonb)::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1 AND $3::bigint>0",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_DELETE: SqlContract = SqlContract {
    id: "calendar.carddav.delete",
    domain: "calendar",
    sql: "SELECT jmap_contact_set_destroy(ab.mailbox_id,ARRAY[$3::bigint])::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1 AND $3::bigint>0",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_GAL_USERS: SqlContract = SqlContract {
    id: "calendar.carddav.gal_users",
    domain: "calendar",
    sql: "SELECT (to_jsonb(v)||jsonb_build_object('manager_name',mgr.display_name,'updated_micros',(extract(epoch FROM u.updated_at)*1000000)::bigint,'rev',to_char(u.updated_at AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')))::text FROM mailboxes caller CROSS JOIN LATERAL directory_visible_users(caller.id) v JOIN users u ON u.id=v.id LEFT JOIN users mgr ON mgr.id=u.manager_id AND mgr.enabled AND EXISTS (SELECT 1 FROM directory_visible_users(caller.id) mv WHERE mv.id=mgr.id) WHERE caller.user_id=$1 AND caller.is_primary AND ($2::bigint IS NULL OR v.id=$2) AND ($3='' OR v.display_name ILIKE $4 OR v.address_blob ILIKE $4) ORDER BY v.display_name LIMIT $5",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_GAL_USERS_MUTANT: SqlContract = SqlContract {
    id: "calendar.carddav.gal_users_mutant",
    domain: "calendar",
    sql: "SELECT (to_jsonb(v)||jsonb_build_object('manager_name',mgr.display_name,'updated_micros',(extract(epoch FROM u.updated_at)*1000000)::bigint,'rev',to_char(u.updated_at AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')))::text FROM mailboxes caller CROSS JOIN LATERAL directory_visible_users(caller.id) v JOIN users u ON u.id=v.id LEFT JOIN users mgr ON mgr.id=u.manager_id AND mgr.enabled WHERE caller.user_id=$1 AND caller.is_primary AND ($2::bigint IS NULL OR v.id=$2) AND ($3='' OR v.display_name ILIKE $4 OR v.address_blob ILIKE $4) ORDER BY v.display_name LIMIT $5",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_GAL_RECORD: SqlContract = SqlContract {
    id: "calendar.carddav.gal_record",
    domain: "calendar",
    sql: "SELECT gal_visibility_record(mb.id,$2) FROM mailboxes mb WHERE mb.user_id=$1 AND mb.is_primary",
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::JSONB)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_GAL_SYNC: SqlContract = SqlContract {
    id: "calendar.carddav.gal_sync",
    domain: "calendar",
    sql: "SELECT gal_changes(mb.id,$2,$3)::text FROM mailboxes mb WHERE mb.user_id=$1 AND mb.is_primary",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CARDDAV_PRIMARY_MAILBOX: SqlContract = SqlContract {
    id: "calendar.carddav.primary_mailbox",
    domain: "calendar",
    sql: "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    FLAG,
    ENTITLED_APP,
    PAGE_LIST,
    PAGE_UPSERT,
    PAGE_DELETE,
    BOOKING_PUBLIC_GET,
    BOOKING_SLOTS,
    BOOKING_CREATE,
    BOOKING_CONFIRM,
    BOOKING_CANCEL,
    BOOKING_EXPIRE_DUE,
    FREE_BUSY_MULTI,
    SUBSCRIPTIONS_LIST,
    SUBSCRIPTION_COUNT,
    SUBSCRIPTION_COUNT_UNSCOPED_MUTANT,
    SUBSCRIBE,
    UNSUBSCRIBE,
    OWNED_MAILBOX_FOR_BOOK,
    OWNS_CONTACT,
    CONTACT_EXISTS,
    WRITE_CONTACT,
    REMOVE_CONTACT,
    NOTIFY_IMPORT,
    EXPORT_CSV_ROWS,
    EXPORT_VCARD_ROWS,
    EXPORT_VCARD_ROW,
    DAV_CALENDARS,
    DAV_CALENDAR,
    DAV_EVENT,
    DAV_TIMEZONE_CATALOG,
    DAV_OWNED_TIMEZONE,
    DAV_OVERRIDES,
    DAV_EVENTS,
    DAV_SYNC,
    DAV_FREE_BUSY,
    DAV_CREATE,
    DAV_EVENT_ETAG,
    DAV_UPDATE,
    DAV_OCCURRENCE,
    DAV_DESTROY,
    DAV_BLOCKED_AUDIT,
    CARDDAV_BLOCKED_AUDIT,
    CARDDAV_BOOKS,
    CARDDAV_GET_CONTACT,
    CARDDAV_BOOK,
    CARDDAV_LIST_CONTACTS,
    CARDDAV_SEARCH_CONTACTS,
    CARDDAV_CONTACTS_BY_UIDS,
    CARDDAV_SYNC,
    CARDDAV_CREATE,
    CARDDAV_UPDATE,
    CARDDAV_DELETE,
    CARDDAV_GAL_USERS,
    CARDDAV_GAL_USERS_MUTANT,
    CARDDAV_GAL_RECORD,
    CARDDAV_GAL_SYNC,
    CARDDAV_PRIMARY_MAILBOX,
];
