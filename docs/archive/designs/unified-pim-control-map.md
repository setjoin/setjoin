# Unified PIM control map — UF10–UF12

Status: DRAFT source-bound U0 continuation, 2026-09-07. This is a reference map,
not implementation authorization, a visual review, or complete PIM coverage.
The UI owner plan
and family inventory
remain authoritative for U0/U1 scope. Webmail and the respective Calendar,
Contacts/directory and Tasks owners must qualify the proposed cases below.

## Read boundary and counting

This pass fully read the three five-line route wrappers, all three main components
(5,938 lines), six directly mounted editor/dialog components (1,410 lines), and
four component test files (1,128 lines). Main scripts and markup were read in
bounded chunks without gaps; CSS was read as source, not rendered or visually
audited. The register below gives exact source bytes and read limits. Other
transitive components, stores, APIs, reducers and test files are not covered.

The denominator is **71 local control groups: CA01–CA32 (32), CO01–CO20 (20),
TA01–TA19 (19)**. A group is a named set of related markup controls/state branches,
not a DOM-element count or a new route. Repeated event/task/card instances and
reused week/work-week/day controls count once with variants explicitly named.
These groups refine UF10–UF12; they do not change the 313-source-candidate or
22-family denominators and do not close nested/runtime residuals.

## Shared disposition rules

- **Keep** means preserve the current owning route, field meaning and audience
  during redesign; it does not bless observed shortcomings. No route retirement,
  new shared editor, account synchronization or additional permission is approved.
- **Local** means an observed in-memory edit/view selection, except the explicit
  localStorage writes named below. **Submit** means the UI awaits a function or
  fetch; that alone proves neither a durable commit nor authorization. Do not label
  a fulfilled callback, empty list, toast or closed dialog as independent evidence.
- Every mutation needs an owning-domain positive/denied/revoked/response-lost
  fixture; client predicates are presentation only. Preserve account/address-book,
  calendar, personal/shared-list and assigned-only boundaries. Never turn GAL
  visibility, free/busy availability, a room pick or an app capability into a grant.
- Each group inherits proposed checks for initial/loading/empty/error/populated,
  unavailable and hidden/disabled states where meaningful. Name impossible states;
  do not imply an absent branch is implemented. For writes, distinguish rejection,
  confirmed mutation with refresh failure and unknown outcome before offering retry.
- Close/Cancel currently follows the named handlers; no general PIM autosave,
  durable draft restore or cancellation protocol was established. **FG-DES-01**
  remains a pending departure-policy proposal. Storyboard unsaved event/contact/
  task/comment and settings-like sharing edits separately; do not silently submit
  invitations, grants or other policy changes to preserve a form. Retention requires
  current access. A lost permission cannot be overridden by preservation.
- **FG-DES-02** (System only for an absent saved theme) and representative visuals
  remain pending. Existing DESIGN.md stays binding. No palette, spacing, contrast,
  responsive behavior or accessibility pass is asserted by reading CSS. Future
  receipts use the UI plan's 360/768/1024/1440 widths, 200% zoom, coarse pointer,
  keyboard/focus return, Chinese/English/German and light/dark fixtures.
- Tables use register IDs plus exact one-based line ranges. `Pxx` are proposed
  acceptance cases, not existing tests. `E1`–`E4` are read test sources; selectors
  listed later are real test expressions, not new executable test IDs.

## Calendar — UF10

All rows keep `/calendar` and its split-view component ownership. Event forms are
local until Submit; returned calendars/events provide UI context, not permission
proof. `C` is CalendarApp; `R`, `RF`, `SC` are its direct children.

| Group | Source | Current controls and state | Disposition / specific remaining check |
|---|---|---|---|
| CA01 | C 294–314,1175–1200 | Previous/Today/Next; Month/Week/Work Week/Day/Agenda; New event, Find a time, shared/import/subscribe/print entries. | Keep navigation and five variants; store persistence not traced. Date/title localization and month-boundary movement need P01/P12. |
| CA02 | C 1203–1239 | Calendar visibility checkboxes and color dots; shared/read-only badge, otherwise Share action; subscribed branch takes precedence. | Keep display selection separate from sharing. Hidden Share is not server authorization; P02. |
| CA03 | C 239–258,1005–1013,1216–1228 | Subscription globe, last-fetch text, error/partial dot with tooltip; Unsubscribe after native confirmation. Initial status load failure is swallowed. | Preserve pending/partial/error distinction; failure is not “no subscriptions.” No stop-sync/deletion guarantee inferred; P09. |
| CA04 | C 109–130,1241–1249 | Working start/end time; immediate writes to `sj-cal-work-start/end`, default 09:00/17:00, parsed whole-hour shading; inverted range disables shading. | Keep device-local display/scheduling prefill, not availability policy. Minute precision, invalid storage and storage-write failure need P01. |
| CA05 | C 132–159,1251–1258 | Second-timezone select, None plus runtime IANA list; validates stored value; writes `sj-cal-tz2`. | Keep display-only local preference. P01 must exercise unavailable/throwing supported-values enumeration, invalid stored zones and DST boundaries; existing validation/formatting is not executed evidence. |
| CA06 | C 339–370,1265–1311 | Loading spinner; six-week month cells clickable by pointer/Enter/Space; up to three event/task pills; noninteractive `+N more` text. | Keep event detail versus task navigation separate. Overflow discovery and nested keyboard activation need P12; E1 samples cells/pills. |
| CA07 | C 608–724,1312–1437 | Week/work-week/day hour slots create; timed/all-day details; writable timed-event drag/resize, 15-minute snap, optimistic preview; recurring scope path. | Keep edit alternative to pointer gesture. Read-only/all-day exclusions, cancelled drag, rollback, DST/cross-day and late view response need P01/P02/P04. |
| CA08 | C 413–426,1154–1163,1438–1477 | Agenda event/task rows and empty message; month/agenda task pills call `goto('/tasks')`; completed/cancelled tasks excluded. | Current link has no task ID or return context. Keep honest destination; targeted task/return is proposed, not existing; P10. |
| CA09 | C 504–586,1490–1496 | Required Title; Calendar select uses **all** loaded calendars; new form picks first calendar. | Do not describe selector as writable-only (import differs). No-calendar, stale/read-only destination and invalid title need P02. |
| CA10 | C 726–749,1497–1519 | Start/end dates; time fields hidden for All day; save builds ISO dates; edit seeds ISO date slices plus local times. | Preserve exact temporal meaning; no automatic timezone correction claimed. Positive/negative offsets, DST, end-before-start and all-day round trips: P01. |
| CA11 | C 1520–1525 | Location and multiline Description. | Keep event-local fields; long text, clearing and dirty departure need P03/P12. |
| CA12 | C 449–462,744,1526–1542 | Color picker; conditional inherit-calendar action; empty sends null. Grid calls `safeColor`. | Keep per-event override distinct from theme. E1 checks inline style only; no visual/contrast pass. |
| CA13 | C 96–98,579–580,1543–1560 | Show as free/busy/tentative (new default busy); binary Private checkbox (new default public). | Busy status is not RSVP. Preserve unrepresented privacy values on unrelated edits; redaction and write authority need P02. |
| CA14 | C 36–63,747–749,1550–1553 | Remind me: none/start/5/15/30/60/1440 minutes; absolute DISPLAY trigger recomputed on save; unknown offset maps to none. | Keep actual presets; nonpreset/multiple alarms and recurrence reminder preservation need P01/P03. No firing guarantee from UI. |
| CA15 | R 16–53,61–88 | Repeat none/daily/weekly/monthly/yearly; interval minimum 1; child seeds local state once. | Keep local RRULE editor; dialog reopen/event-switch and unsupported rule preservation require P03/P04. Parser not read. |
| CA16 | R 56–73,91–120 | Weekly day toggles; end never/count (default 10)/until date; changing away from weekly clears BYDAY. | Keep conditional fields and aria-pressed; validate empty end, count/interval bounds and original rule round trip, P04. |
| CA17 | C 751–760,1569–1593 | Required/optional email text, Add room, Add Scheduling Assistant; removable resource chips; room picks deduplicated by email. | Buckets are separate, not proven globally deduplicated. Clearing every attendee, duplicates, room/optional round trip and nested return: P02/P03/P04. |
| CA18 | C 761–763,1594–1600 | Send on behalf of: Myself plus loaded identities; field is sent as delegatedFrom when nonempty. | Keep separate from delegate RSVP. An identity option is not delegation authorization; P02. |
| CA19 | C 767–805,1564–1568,1634–1641 | Meet capability gates Add Meet and existing meeting URL join. Event submit precedes separate createMeeting or clear-only event patch. | Preserve toggle-edge behavior; do not promise atomic event+meeting creation. Partial success/lost response, recurrence scope path and revoked Meet: P05. |
| CA20 | C 595–598,767–834,1604–1619 | Create/Save changes, edit Delete, Cancel and dialog close; saving/deleting guards; errors in outer banner, failed dispatch keeps form. | Keep failed draft recoverable; no current dirty-close guard. Close/reopen while submitting and action conflicts need P03/P05. |
| CA21 | C 1623–1690,1718–1723 | Detail time/location/notes/organizer/attendees/roles/recurrence; organizer RSVP counts; Edit/Delete shown without a read-only predicate here. | Keep metadata only when authorized. Do not infer safe edit/delete from drag restrictions; P02. `rsvp-roster` is source testid, not executed evidence. |
| CA22 | C 836–845,1021–1083,1692–1717 | Invitee Accept/Tentative/Decline/Propose; matched delegate responds accepted on behalf; organized meeting Send update; individual busy states. | Keep three authority paths distinct. Rejection, response loss, revoked delegation, duplicate send and stale target: P02/P05. |
| CA23 | C 848–878,1806–1833 | Proposed start/end datetime-local, Send proposal/Cancel/close; busy and inline error; initially ISO-sliced times. | Proposal does not directly reschedule event. Preserve origin, temporal meaning, failed form and close/reopen outcome; P01/P03. |
| CA24 | C 880–910,1091–1121,1727–1776 | Scheduling attendee emails, from/to, duration 15/30/45/60/90, working hours, Find slots/Cancel; searching, missing-attendee/no-slot/error. | Keep query-only semantics, required-attendee-only editor prefill; no grant/room reservation. Denied availability and stale query need P02/P04. |
| CA25 | C 1123–1152,1777–1803 | Slot score/free-block/conflict badge; selecting slot resets fields and opens **create**, even when entered from an editor. | Do not call this “apply slot to current edit.” Preserve/reconcile prior draft explicitly in proposal; P03/P04. E1 badge is only mocked rendering. |
| CA26 | C 913–929,1841–1855 | Owner email/Open/Close; no-result/error inline; success closes, clears email and refreshes; no local busy flag. | Keep current-user viewer identity; rapid submits/revoked share/switch target need P02/P05. |
| CA27 | C 950–979,1857–1890 | `.ics` file, writable target calendar, skip/rename/overwrite; Import/Close, busy, errors, imported/skipped result. | Keep one-shot import distinct from subscription; empty target and partial outcome/refresh/lost response need P09. No safe overwrite/rollback guarantee. |
| CA28 | C 981–1002,1892–1913 | Calendar URL and optional Name; Subscribe/Close, blank URL error, busy; closes after subscribe then calendar reload. | A subscription acknowledgement is not first successful sync. External URL security belongs to backend owner, P09; no URL fetch in this pass. |
| CA29 | C 719–724,808–821,1915–1942 | Edit/delete scope title and This/Following/Series actions; close dispatches cancelScope; apply closes prompt before awaiting. | Keep destructive scope explicit and drag rollback ownership; repeat-click/error/reopen plus each scope need P04. Store implementation not read. |
| CA30 | RF 23–88 | Capacity minimum 0; loading/empty/resource rows; Pick adds resource attendee and closes; Close. `load` has finally but no catch/error rendering. | Room pick is not booking. Add failure/unavailable projection and permission/concurrent-capacity case, P02/P04. |
| CA31 | SC 56–66,147–181,225–262 | Existing grant list/loading/empty; email + freebusy/read/write/admin + Add; Revoke/Close; busy guard. Load error stored but not rendered; add/revoke have no local catch. | Keep per-calendar grants distinct from defaults. Require visible denied/unknown and reconciled grant state; P02/P05. |
| CA32 | SC 38–145,186–223 | Conditional user default visibility; everyone/department, existing group audience only; level child; Save, inherited baseline, error. Failed overview hides section; failed save restores prior row if one exists. | This is user-scope sharing default, not calendar-specific grant or org policy. No new group source/reset. First-save failure, revocation and cross-tab conflict: P02/P03; LevelSegment residual. |

## Contacts — UF11

Keep `/contacts`. Directory/GAL is not a personal address book; personal groups are
not organization distribution lists. The following client calls do not establish
backend identity resolution or mutation authorization.

| Group | Source | Current controls and state | Disposition / specific remaining check |
|---|---|---|---|
| CO01 | O 36–61,532–547,557–570,623–624,658–659 | Directory/Contacts mode (localStorage `directoryMode`, default directory), department-name filter retaining ancestors, mounted tree/member pane, directory error. | Keep display preference local and department context explicit; nested tree/member actions remain R01. |
| CO02 | O 225–241,573–583 | Address-book selection and GAL toggle clear group/duplicate view; load/search dispatch. | Preserve distinct source/audience; late responses and loss of book/GAL access: P06. |
| CO03 | O 136–180,584–613 | Groups empty/list/count/select; New/Edit/Delete. Expansion makes synthetic `grp-*` contact cards. Delete has no confirmation in this handler. | Keep group deletion distinct from contact deletion; synthetic recipient cards must not imply owned contact identity. P06/P07. |
| CO04 | O 193–223,626–636,712–747 | Search contacts (255), list/grid, loading/empty/card view; prior refresh aborted, 300ms search timer. | Keep scope-labelled search; this is not proof of out-of-order publication safety. P06/P12. |
| CO05 | O 637–653 | Non-GAL New contact/Import CSV/Export CSV/Export vCard/Find duplicates. Exports navigate to selected-book URL. | Keep export scope explicit, including when a group is displayed. No in-page download receipt or safe-export guarantee; P06/P09. |
| CO06 | O 476–530,660–710 | Duplicate clusters/shared email, keep-radio (fuller default), Merge/Back, loading/empty/busy; one nonkeeper per merge. | Keep explicit keeper and pairwise effect, not whole-cluster atomic merge. P07; E2 checks one mocked pair only. |
| CO07 | O 454–472,719–744,856–921 | Click/Enter/Space card detail; photo/name/company/title/department/notes; GAL primary+alias/UPN mailto links, personal email/phone text. | Keep full address-kind meaning; mailto is not proven in-app compose. Synthetic-member detail and redacted/stale identity need P06. |
| CO08 | O 305–355,771–792 | First/last name, required Display Name; company/job title/department; field length and validation errors. | Keep contact-local form and current validators; no claim normalized validation values are persisted. Clearing/long multilingual names: P03/P12. |
| CO09 | O 793–795,836–838 | Address Book select and Notes (5000). | Explicit book destination; no automatic cross-book move semantics inferred. Revoked destination/dirty notes: P03/P06. |
| CO10 | O 292–302,327–339,796–835 | Add/remove emails (home/work/other) and phones (home/work/mobile/other); remove only with >1 row; invalid email/long phone error. | Keep multi-value meaning and last blank row; edit seeds existing arrays without cloning here. Cancel-versus-store isolation and clearing: P03/P06. |
| CO11 | O 385–399,761–770 | Photo file input, uploading/disabled, blob preview; upload occurs before contact Save. No remove-photo action here. | Do not invent photo reset or equate upload with saved contact. Late upload/cancel/orphan ownership needs P03/P05. |
| CO12 | O 287–290,305–382,841–854,925–933 | Create/Save/Delete/Cancel/close; busy flags; await mutation then close and refresh; errors in outer banner. | No current dirty guard or Delete confirmation established. Capture target/draft, preserve failed write and distinguish refresh failure; P03/P05/P07. |
| CO13 | O 428–452,934–938 | GAL Add to Contacts; selected or contact address-book ID; copies named fields, `emails` and phones; busy/error/close. | Copy, not GAL edit. Full `addresses` rendering does not prove aliases/UPN copied into `emails`; qualify field-preservation and destination, P06. |
| CO14 | O 405–425,927–929 | Forward as business card: export selected contact, upload `.vcf`, close, `composeStore.open` with subject/attachment. | Keep Mail handoff separate from send. Draft collision, blob failure and response loss require P05/P10; no transport/cleanup guarantee inferred. |
| CO15 | G 36–49,117–132,157–162 | Group name create/rename, reseeded on open/target change; required, max255; local error. | Keep mailbox group identity; reseed while dirty and changed target require P03/P07. |
| CO16 | G 51–115,164–211 | Existing member remove; loaded-contact picker + Add; free-email + Add, validation and case-insensitive free-email dedup; empty list. | Local member edits until Save; contactId versus email discriminators retained. No global duplicate/recursive-group guarantee; P07. |
| CO17 | G 117–146,214–219 | Save/Cancel/close; create or rename first, then separate member delta; busy and role-alert error. | Not atomic name+membership. Partial create/member failure needs stable identity/reconciliation before retry, P05/P07. |
| CO18 | I 48–104,135–148 | Import `.csv`/`.vcf`; choose step, busy/error; CSV preview request, vCard skips mapping; wizard resets each open. | Keep file/format choice explicit. Close/reopen during preview and stale file results: P03/P09. |
| CO19 | I 20–30,63–71,149–203 | Eight mappings: firstName/lastName/fullName/email/company/jobTitle/phone/notes, -1 omitted; sample table; skip/overwrite strategy; vCard hint instead of mapping. | No extra fields/merge strategy implied. Preview is not import; invalid mapping/partial rows/untrusted sample text: P09. |
| CO20 | I 111–132,204–226; O 188–191,952–956 | Import submits file/book/strategy (+ CSV mapping), renders imported/skipped/errors and calls onDone; ContactsApp immediately closes onDone. Close remains available. | Do not claim result remains visible in mounted journey. Qualify acknowledgement, response loss, partial result and same operation/re-entry before retry; P05/P09. |

## Tasks — UF12

Keep `/tasks`. Personal and shared-list boards reuse controls; assigned-to-me is
status-only. The main component captures mutation targets through its coordinator,
but this pass does not re-audit that coordinator, adapters or domain authorization.

| Group | Source | Current controls and state | Disposition / specific remaining check |
|---|---|---|---|
| TA01 | T 121–150,314–335,774–832 | My Tasks, capability-gated Assigned/shared-list navigation, open-count badges, new-list entry; owner-only management menu. Capability read once at mount. | Keep scope/provenance; dynamic revocation, stale list and count/error/empty distinctions need P08. |
| TA02 | T 293–312,758–760,833–842 | Personal-only Search (255) and All statuses/needs-action/in-progress/completed/cancelled filter. | Do not imply search/filter applies to assigned/shared-list board. Keep existing status strings, P08. |
| TA03 | T 761–771,884–890 | Non-assigned Kanban/List/New task; loading only when empty board, otherwise empty prompt or rows. | Keep view controls distinct from authorization; list-specific loading/error owner not traced. P08/P12. |
| TA04 | T 846–883 | Assigned list title/owner/list-or-personal provenance/due/status select; no create/edit/drag; failure banner+toast. | Preserve status-only contract, no inherited board authority. Rapid status changes, revoke and rollback/unknown need P08. |
| TA05 | T 890–953 | Four kanban columns/counts; clickable/keyboard cards, priority/due/checklist/assignee/description; Start/Done disabled per task busy. | Keep direct status actions as keyboard alternative, not proof of full keyboard reorder. P08/P12. |
| TA06 | T 954–1047 | List rows with top-level/child roll-up, done checkbox, status/priority/due/assignee; Edit/Delete; busy guards. | Keep parent hierarchy distinct from checklist and row click; orphan/filter-hidden parent and propagation need P08/P12. |
| TA07 | T 593–653,898–914,969–983 | Native drag reorder before row/card; empty-column drop appends and changes status; dragged ID cleared on end/drop. | Preserve captured target and busy coordination; cross-view drag, concurrent reorder and nonpointer alternative need P08. |
| TA08 | T 487–517,1063–1083 | Title required255; status four values; priority **0/1/5/9** options, not all numeric values. | Keep existing values; preserve unsupported stored priority on unrelated edit. No new priority semantics; P03/P08. |
| TA09 | T 425–446,505–507,1084–1092 | Start/Due/Reminder datetime-local; edit slices stored strings; empty fields sent undefined. | Clearing is not proven durable clearing. Timezone round trip, due/reminder removal and recurrence timing: P01/P08. |
| TA10 | T 233–257,319,1093–1130 | Personal GAL/free-email single assignee, debounced results; shared-list roster select + Unassigned. Save sends assigneeEmail, never user ID. | Keep target-specific identity resolution; current list supplies options while modal target is separately captured. Switch-list/unavailable roster/revocation: P08. |
| TA11 | T 259–291,702–732,1132–1143 | Recurrence none/daily/weekly/monthly/yearly + unrecognized Custom; parent select top-level/self-excluded, empty when has children. | Untouched rule retained; selecting preset rewrites rule. Parent candidates are loaded board only, not authority proof. P04/P08. |
| TA12 | T 502,508,655–665,1144–1160 | Description5000; category text100/add/remove; empty description/categories sent undefined. | Keep local edits; distinguish “empty payload omitted” from cleared server value. No reset-all or unconditional clear guarantee; P03/P08. |
| TA13 | T 667–692,1161–1184 | Checklist done/text500/remove; new text + button/Enter; local temporary IDs; saves whole array; progress badge. | Keep separate from subtasks; unadded text and close/reopen, concurrent whole-array edits need P03/P08. |
| TA14 | T 400–474,487–547,1053–1062,1187–1194 | Save/Cancel/close; modal epoch+captured-target guards; failed save stays with focused role-alert and draft. | Preserve proven-at-source scoped completion, not blanket protection for every async handler. Dirty-close still pending; E4 samples failure/stale target, P03/P05. |
| TA15 | T 549–577,1198–1254,1315–1323 | Detail status/priority/due/assignee/recurrence/description/categories; Edit/Delete; detail Delete closes immediately while removal runs. Toast offers Restore copy. | Preserve **new-copy**, not Undo/full recovery. E4 checks limited copy fields; failure after close, revoked target and copy identity need P07/P08. |
| TA16 | T 158–230,1256–1311 | Expand/collapse Activity; loading/empty/comment/system rows; plain comment5000, @ GAL suggestions, submit disabled blank/busy; success clears body then reloads. | Separate comment authority from status/full edit. Activity/mention/comment late target, lost response and dirty comment need P03/P05/P08. |
| TA17 | T 476–485,1233–1239 | Open email closes dialog and navigates `/inbox?t=<linkedMessageId>`. | Loaded-inbox selection/authorized fallback is not proven here; preserve link provenance without new Mail access, P10. E4 only checks goto. |
| TA18 | T 337–398,1325–1350 | Owner Rename/Members/Delete menu; New/Rename name200, Save/Cancel/close; native confirmation before list delete. | Keep destructive list delete distinct from task Restore copy. Awaited store calls are not a re-personalization/ACL receipt; P05/P07/P08. |
| TA19 | M 19–61,64–124; T 817–828,1352–1355 | Live-store roster or prop fallback; owner Add email; nonowner row removable by owner/self, no owner self-remove; pending/error/Close. | Dialog supports self-leave, but this parent exposes Members only via owner menu. Do not claim member journey reachable. Revoked/stale fallback and entry-point qualification: P08. |

## Existing test identities — source read, not run

All four files use mocks. These anchors identify exact selectors and the limited
oracle read; they are not retained passing evidence or an exhaustive test catalog.
No current selector is claimed for a group not represented below.

| Source | Read selectors / exact case anchor | What it checks; what remains open |
|---|---|---|
| E1 148–222 | `.month-cell`, `.task-pill`, label `Title`, text `Create`, label `Add setjoin Meet` | Cell keyboard attributes/Space opens form; pill rendering; create/Meet mocked calls. No live save, room or task-handoff authority. |
| E1 224–308 | `Find slots`, `Attendees (emails)`, `.slot-conflict`, `Repeat`, `Every`, button `Mo`, `Owner's email`, `Add room`, `Add Scheduling Assistant` | Scheduling dispatch/conflict display, recurrence mount, shared-owner argument, room load, assistant prefill. No slot-to-existing-draft preservation or denied free/busy. |
| E1 318–422 | `.event-pill`, labels `Color`, `Show as`, `Private`, button `Edit` | Mocked color filtering/payload and selected busy/privacy values; not privacy enforcement or rendered contrast. |
| E1 426–512 | `Calendar URL`, `Name`, `Subscribe`, `.cal-sub-icon`, `.cal-sub-dot--error`, `Unsubscribe` | Blank URL, subscription arguments, status text and confirm true/false. No network trust/sync correctness. |
| E1 514–573 | `.week-grid .day-column`, `.day-grid`, `Create event at 14:00`, `.agenda-item`, dialog `Planning`/`Edit event` | Week7/work-week5/day, one time-prefill, agenda fixtures and detail metadata. Despite case wording, agenda test does not subsequently assert an empty agenda. |
| E2 68–103,111–155 | `[data-pim-shell]`, `.pim-topbar__title`, `.dir-search-bar input`, `Import CSV`, `Export CSV`, `Export vCard`, label `New group` | Shell/tree filter/group/import entry and stubbed export navigation only. |
| E2 164–234 | `Find duplicates`, `Merge`, `.contact-card .email`, `.addr-more`, `.addr-line a`, `.addr-kind` | Mocked keeper/drop pair, primary/alias/UPN labels and mailto URLs; not merge data safety or GAL-copy completeness. |
| E3 57–68 | `[data-pim-shell]`, `.pim-topbar__title` | Two shell/title smoke cases only. |
| E4 73–155 | `Title`, `Description`, `Category`, `Add an item`, `Mark task done`, `Edit task`, `Delete task`, dialog `[role="alert"]` | Validation/payload, limited Restore copy fields, captured list refresh and focused failed-save draft. Historical case title says “undo”; assertion explicitly requires `Restore copy`. |
| E4 157–251 | `Comment`, option `/Bob/`, `Open email`, `Assigned to me: Review policy`, `Start`, `Done`, `Manage Team Plan`, menuitem `Rename`/`Delete` | Mock comment+mention, goto, status-only, board moves, list create/rename/delete, initialization/status error. No real ACL/notification/reorder evidence. |

## Proposed critical cases and independent oracles

Use existing Webmail/component and owning-domain front doors when later authorized;
do not invent a new executable lane. For each P case retain group IDs, role/source
fixtures, exact selector, action, expected UI **and** independent domain result,
plus cleanup ownership. Mocks can prove presentation; they cannot close reducer,
worker, live browser, native-host or visual gates. Cases are proposed, not run.

| Case | Critical setup/action | Required oracle / ownership |
|---|---|---|
| P01 | CA01/04/05/07/10/14/23/24 and TA09: positive/negative UTC offsets, DST gap/fold, midnight, all-day, start/end changes and saved reminder offsets. | Calendar/Tasks owners freeze date-vs-instant representation and original-value comparison. Verify displayed/submitted/stored values separately; local view prefs must not change account availability. |
| P02 | CA02/09/13/17/18/21/22/24/26/30–32: owner/shared read-only/freebusy/private, denied calendar, revoked identity/delegation, room conflict and defaults OFF/load failure. | Domain-approved fixture must prove no unauthorized detail or mutation, including manually invoked paths. Keep private redaction, calendar grants, user defaults, delegation and resource booking independent. |
| P03 | All editors: nonempty/only-attendee/only-photo/only-checklist/comment edits; Cancel/Escape/close/navigation; open another entity while async work remains. | Characterize current outcome before migrating; proposal requires explicit preserved/unsaved/discarded state within access. No automatic grant/invitation submission. Pending FG-DES-01 is not evidence of current persistence. |
| P04 | CA07/15/16/17/24/25/29/30, TA11: each recurrence scope, cancel recurring drag, unsupported rule, room nested return, assistant slot picked from dirty edit. | Calendar owner compares original recurrence identity and intended event mutation. Existing picker resets to create; storyboard safe prior-draft disposition, never falsely call it in-place apply. RRULE/backend/parser qualifications remain open. |
| P05 | CA19/20/22/26/31, CO11/12/14/17/20, TA14/16/18: delay/reject/drop each write or follow-up refresh; double action, close/reopen/change target. | Distinguish submitted identity, confirmed first effect, second-step failure and unknown receipt. Reconcile before retry; no duplicate event/meeting/group/import/comment. Do not generalize Tasks coordinator guards to other handlers. |
| P06 | CO01–05/07–10/13: directory/GAL/book/group switching; synthetic group recipient; alias/UPN copy; revoked book; late search/expansion. | Contacts/directory owners prove actual identity/destination and safe denied state. Synthetic `grp-*` rows are not owned Contact IDs. Verify array edits do not mutate displayed contacts before Save or survive Cancel unintentionally. |
| P07 | CO03/06/12/15–17, TA15/18: keeper selection, cluster >2, partial group rename/create+members, contact/group deletion, task copy and list deletion. | Domain owners enumerate actual destructive effect/receipt. Do not conflate group removal, contact merge, limited new task copy and list-wide access removal; no forced rollback after irreversible effects. |
| P08 | TA01–19: personal/list A/list B/assigned; owner/member/self; capability revoked, roster removed while dialog open; hidden parent, omitted clears, recurrence/completion, concurrent reorder/whole-array edits. | Tasks owner proves target and permission at mutation; UI cannot reuse stale roster fallback as grant. Separate task coordinator, assigned-status, comment, list and membership protocols; qualify member self-leave entry before claiming reachability. |
| P09 | CA03/27/28, CO05/18–20: missing file/target, invalid mappings, skip/overwrite/rename as supported, partial errors, close/reopen/lost response, subscription pending/failed/partial. | Calendar/import owners bind exact imported/skipped/errors and operation identity where supported; no blind retry or “finished” from closing. CSV result is currently hidden by parent onDone; specify mounted acknowledgement. Source URL trust and cleanup need backend evidence. |
| P10 | CA08/19, CO07/14, TA17: Calendar→Tasks, event→Meet, contact→Mail, task→Mail with absent/revoked destination and existing dirty composer. | Receiving owner proves authorized selection/fallback and preserved originating work. Current generic `/tasks`, mailto and goto calls do not establish deep-link/return behavior or a reusable grant. |
| P11 | CA03/24/26/30–32, CO01/03/04/20, TA03/16/19: initial rejection, stale completion, empty versus unavailable, post-success reload failure. | Named state and recovery copy must remain truthful; fill missing error/receipt rendering only with an approved owner contract. No response means unknown, not empty/success. |
| P12 | All groups at U1 fixture widths/locales/themes, keyboard/touch/zoom; crowded month, nested dialogs, long roster/aliases/categories, status/error announcements. | Visual/accessibility owner captures representative screenshots and keyboard/focus oracles separately. Styling read does not approve palette, mobile layout, contrast, touch drag or dialog stack behavior. |

## Explicit residuals and resumable next boundary

| Residual | Exact next boundary / owner |
|---|---|
| R01 Directory internals | `DirectorySidebar.svelte` and `DirectoryMemberList.svelte`, mounted by O 565/659, not read. Department expansion, member detail/actions, pagination, directory load/permission states and their nested dialogs remain open to Contacts/directory owner. |
| R02 Shared primitives | `PimShell.svelte`, UI Dialog/Menu/Input/Select/Checkbox/Avatar, Icon and SC's `LevelSegment.svelte` not read. Shell sidebar collapse, focus stack, nested close, portal semantics and option internals remain Webmail/U2 work, not transitively counted. |
| R03 Calendar authorities | C import seams 18–34 and child imports: calendar/event/action/subscription/task stores, RRULE/format/print helpers, Meet API and backend not read. Source UI already exposes subscribe, while Webmail DOX 358 still says webcal deferred; root/domain owner should reconcile that stale sentence, not remove current controls. |
| R04 Contacts authorities | O imports 6–34: contact/group/directory/compose stores, client/export/import/upload handlers and normalization helpers not read. Full multi-step outcomes, blob cleanup, merge and address authority remain open. |
| R05 Tasks authorities | T imports 7–36: task/taskLists stores, coordinator, comment/activity/GAL client and reducers not read. DOX 398 says in-process; current markup uses in-progress. Do not allocate or change canonical status values from this map. |
| R06 Remaining evidence | Direct-child tests, recurrence/drag/print/subscription store tests and other component/behavior tests beyond E1–E4 not read. No assertion that absent-from-this-map tests do not exist. Runtime, CI, generated/native wrappers, screenshots and whole-product coverage remain unperformed. |

Next bounded unit starts at R01/R02 or one named domain trace, not a whole-PIM scan.
Every independent review must preserve the distinction between a source-observed
gap and a proposed correction; this map is not a product bugfix authorization.

## Frozen input register

SHA-256 values bind whole-file bytes, even where the stated read scope is partial.
Paths below are relative to the repository through their links. A matching hash
does not imply a full-file read outside the declared limits.

| ID / linked input | Read lines | SHA-256 |
|---|---|---|
| [D — docs DOX](../AGENTS.md:1) | 1–252 full | `2767f16c6b87ca244d5a28a29a9b4a572ec2424be2dbc8788126afb463c64919` |
| [W — Webmail DOX](../../mailserver/webmail/AGENTS.md:350) | 1–74 and 350–415; not full file | `e070a1fa17c594c851fa110d7c94af52de0fd5659a69a784b731d835870c114c` |
| U — UI plan | 118–194,205–315 current relevant sections | `af3c2e91debd7736420e75117c8da0c77e4730e17010067c64e28226c85f0390` |
| F — family inventory | 1–164 full | `012f685fc5f6a3c9623b27437c0f4e5aa11a2ef2557b41a9a644ecb59e2f6cce` |
| [RC — calendar route](../../mailserver/webmail/src/routes/calendar/+page.svelte:1) | 1–5 full | `bafbdd08bece4d9d50f92d41640d4c8b54288c9b2588ce58780cfb55ddcf92fe` |
| [RO — contacts route](../../mailserver/webmail/src/routes/contacts/+page.svelte:1) | 1–5 full | `aeab4f135668d015045507cba574f5004ee9a3b14b949ece811eb988cfb4eca6` |
| [RT — tasks route](../../mailserver/webmail/src/routes/tasks/+page.svelte:1) | 1–5 full | `9f1baffc9090c9f41e817e54bc88208f2e3290d4092e2d7b31735d6e364938c6` |
| [C — CalendarApp](../../mailserver/webmail/src/lib/components/CalendarApp.svelte:1) | 1–2535 full; CSS1944–2535 source only | `2a21a7f2d206623dea71bd3e5d57a1c0b5b210a1ab35524fce65d8b41375e624` |
| [O — ContactsApp](../../mailserver/webmail/src/lib/components/ContactsApp.svelte:1) | 1–1341 full; CSS959–1341 source only | `404840ce1cf5d368ff2799226b4116685b83e728e1dcd5c377e8ad1e6672d9d2` |
| [T — TasksApp](../../mailserver/webmail/src/lib/components/TasksApp.svelte:1) | 1–2062 full; CSS1357–2062 source only | `81b2893f301c8412e19f52884601cd8ca6b7bb477c32b22c5cba32ea661f6753` |
| [R — RecurrenceEditor](../../mailserver/webmail/src/lib/components/calendar/RecurrenceEditor.svelte:1) | 1–167 full | `29e4d56ed35d9120fc8e25913aae0331b169ef8a768282c0523020f6d2dd31d3` |
| [RF — RoomFinder](../../mailserver/webmail/src/lib/components/calendar/RoomFinder.svelte:1) | 1–131 full | `2e4995a1b76d48a793c5dcba0a01286a2f8ea3d31a95e99ca18bbf57129b7902` |
| [SC — ShareCalendarDialog](../../mailserver/webmail/src/lib/components/calendar/ShareCalendarDialog.svelte:1) | 1–352 full | `d4b5092f5b9a1c93b354d004c3f4f64b01f98ccce16b3a3ad5ac290cf8e01511` |
| [G — ContactGroupModal](../../mailserver/webmail/src/lib/components/ContactGroupModal.svelte:1) | 1–278 full | `74b89a4f6680d032c5cbd55098ec22f7c68cac5b4a210c9c1b33a8ca07e22a07` |
| [I — CsvImportModal](../../mailserver/webmail/src/lib/components/CsvImportModal.svelte:1) | 1–287 full | `7a107757cc8e25f968ce10000b34619687ec9f88f4f0ad3d4c9ac8b080d0ba89` |
| [M — TaskListMembersDialog](../../mailserver/webmail/src/lib/components/TaskListMembersDialog.svelte:1) | 1–195 full | `29a6309dedb656a3c863371c99462b5c7dfdff3f0bb12e64fc82a9609a0093f0` |
| [E1 — CalendarApp tests](../../mailserver/webmail/src/lib/components/CalendarApp.test.ts:1) | 1–573 full | `4bd51a4e18945876253a5905706f4c7ee4c59bdd9de7ec8b9f6b7f5e59e49238` |
| [E2 — ContactsApp tests](../../mailserver/webmail/src/lib/components/ContactsApp.test.ts:1) | 1–234 full | `26e3df3144126d4e497d27ae72a5962beb4cd11452b57ee09d7f5eb7363c216f` |
| [E3 — TasksApp tests](../../mailserver/webmail/src/lib/components/TasksApp.test.ts:1) | 1–69 full | `a6f7adc44aac90ceb4559a7c5251fa8129d771840e39abd943d36c4dff1f5f5b` |
| [E4 — TasksApp behavior tests](../../mailserver/webmail/src/lib/components/TasksApp.behavior.test.ts:1) | 1–252 full | `b9ca189495bcbf42503718da40a983d1d9c599f8f718f6538a538336688f110f` |

## Authoring receipt

The existing Graphify graph was queried before repository discovery; its broad
results are navigation only. Documentation-generation's reference quadrant shaped
the source/claim separation; no generated tutorial or executable workflow is implied.
Only this document is owned/written by this unit. No tests, browser, network,
services, credentials, Git operations or temporary resources were used. Root owns
independent review, index/DOX links, final Graphify update and hook-check under
`sj-plan-rest-20260907` and the existing planning-continuation resource ledger.
