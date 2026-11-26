# Unified settings: canonical group and field disposition

Date: 2026-09-07. Status: source-bound **proposal**, author-only; not U0/U1
completion, implementation approval, visual approval or a review score.
Owner: Webmail design with the existing account, Mail/PIM, security and native
offline owners. This document assigns presentation destinations, not business
authority, new permissions, routes, endpoints or reset actions.

Authority: UI plan U0
and its pre-U1 proposal.
Source vocabulary and existing test mappings come from the fully read
settings option inventory.
That inventory remains the detailed option/value reference; every group is mapped
below without treating duplicates as fewer inventoried controls.

## Evidence and denominator

The inventory contains 17 page candidates: `/settings` plus 16 children. Its five
detail tables contain exactly 52 groups, not 52 individual widgets or exhaustive
state combinations. Navigation, information, actions and dialogs count where the
inventory counts them. The 17 route hashes still match the frozen
surface inventory.

| Inventory section | Inventory lines | Mapping IDs | Groups |
|---|---|---|---|
| Root control inventory | 52–63 | USM01–USM12 | 12 |
| Preference and content-editor options | 69–82 | USM13–USM26 | 14 |
| Sharing, booking, rules and storage options | 88–100 | USM27–USM39 | 13 |
| Security controls, tabs and overlays | 108–115 | USM40–USM47 | 8 |
| Migration option and lifecycle detail | 123–127 | USM48–USM52 | 5 |
| Total | Five tables; duplicate Language labels remain separate rows | USM01–USM52 | 52 |

This author fully read the 146-line option inventory and the UI plan's U0 and
amendment/pre-U1 sections. Existing control facts and test-selector mappings are
inherited from that inventory, not a new end-to-end read of all 7,393 page lines.
Additional focused source reads checked root preference initialization/handlers,
appearance initialization/handlers, language script and descriptive copy,
notification form/load/save/cancel, storage script, automatic-reply state/save,
booking defaults and privacy receipt/trust controls; `offline/window.ts` was fully
read. The source register binds all 17 pages, two inventoried mounted components
and the window helper. Hash comparison does not establish their runtime behavior.
API/store/reducer/native-helper internals, generic UI primitives and test bodies
were not newly audited. A source-derived comment is not independent backend proof.

## Reading the mapping

- `R01`–`R17`, `C01`–`C02` and `H01` resolve to exact files and hashes in the
  source register. A suffix such as `R01:451` is the source line, not a new route.
  The `I` column identifies the exact group row in the option inventory.
- **Keep** preserves the current route/editor. **Consolidate** proposes one editor
  behind both entries; retain the old functional entry until the successor is
  reviewed and tested. A destination section name is conceptual, not an allocated
  fragment, redirect or endpoint. Preserve authorized deep links and return targets.
- **L** means local browser/origin preference, including webviews where applicable;
  account isolation, cross-tab synchronization and native persistence are not
  inferred from a localStorage key. **A** means the current account/user or owned
  domain object targeted by the page, not proof of reducer authorization. **D**
  means native-device capability/cache state. **O-read** is inherited organization,
  group or OU policy displayed here without an organization-policy editor.
- **None** in Reset/default means no dedicated reset-to-default action was
  inventoried in that group, not proof that none exists anywhere. A named UI seed
  is initial/fallback form state, not a server default or permission to overwrite
  an existing value. **Unestablished** preserves an explicit source/contract gap.
- Existing acknowledgement describes what the page observes: local application,
  an HTTP/helper result, refreshed data or a progress projection. A toast alone is
  not a durable receipt, cross-device synchronization or completed external effect.
  Failed/unchecked responses must not become a proposed “Saved” or “Cancelled”.
- Every `USMnn-P` is a **proposed fixture obligation**, not an existing selector,
  registered test, executed case or passing result. Existing selector text below
  comes from the inventory's test/source mappings. Its exact file links remain in
  the 17-route test register.

### Shared preservation requirements

These requirements apply to every row and do not claim present implementation:

1. **Local conflict (CL):** exercise two entries/tabs, account switching and failed
   local persistence. Do not silently turn local preferences into synced account
   settings or promise cross-tab arbitration the helper has not demonstrated.
2. **Account conflict (CA):** keep the owning domain's current authorization and
   conflict rules. Refresh/reconcile after stale writes, permission loss or lost
   responses; disclose no protected cached values after access ends. An expected
   revision/receipt interface must be source-bound before use, not invented here.
   If no safe conflict interface is available, retain the existing editor and
   record the blocked consolidation rather than advertise conflict-safe saving.
3. **Device conflict (CD):** device availability, server approval, account preference
   and effective native result are separate facts. Recheck caps/current access;
   unknown, denied and revoked stay distinct. Do not replace server policy with a
   local switch or treat an account-stored window as a per-device grant.
4. **Dirty form (DF):** FG-DES-01 is still a final-gate proposal. For edit/save
   settings, propose Stay editing, explicit Save with confirmed result, or Discard
   unsaved form changes. Do not silently autosave policy changes on navigation.
   Retention of secrets/revoked data remains bounded by its existing owner. This
   differs from the proposal for preserving unsent message drafts.
5. **Default (DT):** FG-DES-02 proposes System only when no theme is saved. Preserve
   explicit saved values and pre-paint initialization. The root's current `light`
   and appearance page's current `system` fallbacks remain recorded; this document
   does not approve replacing either. No bulk “Reset all settings” is introduced.
6. **Operation (OP):** page departure is not cancellation. Re-entry uses the same
   authorized domain operation and its actual pending/unknown/terminal result.
   Domain cancellation support is not inferred from a button named Cancel. No
   global job store or new re-entry API is allocated by this map.

## Root groups

| ID / I / group and existing source-scope | Proposed canonical destination | Current commit and honest acknowledgement | Reset/default disposition | Conflict/permission preservation | Existing selector; proposed fixture gap |
|---|---|---|---|---|---|
| USM01 / I52 / Profile: display name, read-only email; R01:451, A | Keep `/settings` Profile; no replacement profile editor invented | Explicit Save; busy; non-OK/network inline alert; success toast after response/auth refresh, not a new receipt | None; display name loads from user, with email-local-part fallback, not a reset target | CA + DF; email stays noneditable; refresh failure and concurrent profile edit need distinction | `Save changes`, `role=alert` in root settings tests; USM01-P stale edit, failed refresh and departure |
| USM02 / I53 / Theme `light/dark/system`; R01:468, L | Consolidate into `/settings/appearance`; root link/shared editor only after parity | Immediate shared-helper application and toast; no dedicated busy/error state; no account-sync claim | None; root absent-value `light`; DT pending | CL; preserve saved choice across both entries and pre-paint | `Dark/Light/System` mapped on appearance, not root select parity; USM02-P absent/stored/cross-tab/failing write |
| USM03 / I54 / Language `en/zh/de`; R01:478, L | Consolidate into `/settings/language` | Immediate async locale switch, root `sj-lang` write and toast; page-local rejection UI absent | None; root absent-value `en`; locale fallback internals unestablished | CL; preserve locale while returning to the originating authorized app | Language buttons/`aria-pressed` exist on child; USM03-P root-child parity and rejected locale load |
| USM04 / I55 / Density compact switch; R01:488, L | Consolidate into `/settings/appearance` Density | Immediate helper call, no Save/dirty state | None; false maps to `comfortable`, true to `compact` | CL; no organization density policy inferred | Child `Compact/Comfortable`; USM04-P root-child and two-tab parity |
| USM05 / I56 / Mail timing: undo 5/10/30 seconds, morning 7/8/9; R01:502, L | Keep `/settings` local Mail preferences; no new account Mail-settings route | Immediate change writes all five local Mail preferences and toasts; downstream send/snooze effect unverified | None; local fallbacks 10 seconds and 8:00 | CL; protect sibling preference values from stale form writes; no server-send guarantee | Existing option text in source, no group-specific case established; USM05-P every enum, sibling preservation and account switch |
| USM06 / I57 / Mail switches: newsletters, shortcuts, desktop notifications; R01:522, L | Keep `/settings` local Mail preferences; cross-link Notifications with scope explanation | Immediate shared five-key local write; not browser subscription or server notification consent | None; local fallbacks true/true/false respectively | CL; retain three controls, never merge desktop switch with USM19/20 | Source switches; USM06-P each toggle, denied browser permission and stale sibling value |
| USM07 / I58 / Passkeys: credential list and Add; R01:580, A plus authenticator | Keep root Passkeys until a separately tested security-editor successor exists; link from security if needed | Explicit enrollment action; begin/create/finish/list refresh; cancellation/error alert; no enrollment-specific busy flag | No reset/delete control inventoried; empty list is data, not default credentials | CA; authenticator cancellation, expired authority and duplicate click; never copy credentials into another settings store | Root settings test file mapped; no exact passkey case established by inventory; USM07-P enrollment/error/refresh/duplicate submission |
| USM08 / I59 / Root TOTP setup/secret/code/enable/disable; R01:599, A | Consolidate into `/settings/security` TOTP editor; retain USM44 re-enrolment | Explicit setup/verify/disable, loading/code-length gates and inline error | None; disabled status is server-derived; Disable is a security mutation, not reset | CA; retain owning factor/step-up rules; no extra secret retention under DF | Root/source actions and security TOTP workflow tests; USM08-P cross-entry status and safe departure during setup |
| USM09 / I60 / Offline approval/availability/download/request; R01:637, D + server policy | Consolidate into `/settings/storage` availability/approval, preserving native and browser branches | Explicit Request approval: busy/toast/live announcement; request accepted is not approval granted; download is navigation | No policy reset; unknown/pending/denied/revoked not defaults | CD; do not hide policy decisions behind a cache-size error or turn download into offline availability | `cache mail on this device` and native approval cases in root offline tests; USM09-P all cap branches and repeated request |
| USM10 / I61 / Offline opt-in and numeric window; R01:652, D + server-stored preference request | Consolidate qualified cache controls into `/settings/storage`; preserve actual enum mapping, not arbitrary days | Opt-in optimistic with rollback/alert; window changes local state and sends request without status check, so no confirmed-save claim | None; root begins at 7 days then cap-derived value; helper/storage seed 30d is separate, not a chosen replacement | CD; freeze preference scope and root/storage mismatch; never equate window, opt-in and approval | Root offline tests + storage slider; USM10-P non-bucket input, 4xx/transport error, cap change and two-entry reconciliation |
| USM11 / I62 / Recovery copies: opt-in, coverage, incident offers/cancel/status; R01:687, D + authorized recovery incident | Keep root recovery controls in place until their own native recovery owner qualifies a destination; Storage may link, not substitute B2 selected restore | Explicit opt-in/Offer/Cancel; helper progress and per-artifact status; busy/error visible; list refresh failure clears rows, not proof no incidents exist | None; initial false/zero/empty are UI seeds, not server policy or erasure | CD + OP; preserve native db/recoveryBlob predicate and exact incident/artifact authority; no general backup grant | Source dynamic artifact controls; USM11-P stable row selectors, lost response, revocation, upload cancellation and restart |
| USM12 / I63 / Navigation/disclosure: ten Mail links, password/Advanced links, download, details; R01:526/776, no setting scope | Keep overview links; appearance/language/security/cache entries resolve their canonical editor; preserve existing routes | Navigation/disclosure only; no “Saved”; external new-tab behavior remains explicit | Not applicable; opening/closing details resets no preferences | Current misleading security/password/app-password/webhook copy needs proven destination or honest unavailable text; no fabricated editor | Existing child buttons/details; USM12-P every deep link, keyboard return, external-tab and unsupported destination |

## Preference and content-editor groups

| ID / I / group and existing source-scope | Proposed canonical destination | Current commit and honest acknowledgement | Reset/default disposition | Conflict/permission preservation | Existing selector; proposed fixture gap |
|---|---|---|---|---|---|
| USM13 / I69 / Appearance theme/density and replay tour; R03:29/54/130, L | Keep `/settings/appearance`, canonical for USM02/04; tour remains a distinct action | Immediate local helper/toast; tour navigates Inbox then requests replay, not saved preference | None; child absent theme System, density comfortable; DT pending; replay is not reset | CL; preserve tour lifecycle and authorize return destination independently | `Dark/Light/System`, `Compact/Comfortable`; replay navigation test; USM13-P absent theme and shared-entry parity |
| USM14 / I70 / Language buttons and regional examples; R07:15/34/54, L + display-only examples | Keep `/settings/language`, canonical for USM03 | Async locale switch/toast; fixed Date/Time/Number examples are read-only, not editable formats | None; initial en; helper effective default unestablished | CL; do not introduce timezone/date/number preference fields from examples | Three language buttons and `aria-pressed`; USM14-P rejected switch, long locale labels and correct examples |
| USM15 / I71 / About health/version/server/account links; R02:24/48/101, A information + system health projection | Keep `/settings/about` | Read-only loading/health/error; non-OK may leave null health without error; no current Retry | Not applicable; unavailable health is not a default healthy state | CA for disclosure; preserve current information scope, not admin-edit rights | Version/status cards, `getByAltText('SetJoin')`; USM15-P non-OK/null, unavailable details and links |
| USM16 / I72 / Automatic replies enable/schedule/start/end; R05:72/124, A mailbox | Keep `/settings/automatic-replies`, same form as USM17 | Explicit Save; spinner/saving/error; schedule off sends null dates; not an immediate switch effect | None; UI seeds disabled/unscheduled/blank dates, not overwrite defaults after failed GET | CA + DF; retain inverted-range refusal; distinguish indefinite schedule from missing load | `ar-save`, start/end date labels; USM16-P empty/one-sided/inverted dates, failure, stale edit and departure |
| USM17 / I73 / Automatic replies subject/internal/external text, audience all/contacts/none; R05:151, A mailbox | Keep same automatic-replies form; no separate competing saver | Explicit Save with USM16; HTTP failure inline; sends empty HTML; unknown loaded audience coerces all today | None; empty text/all are UI seeds; do not reset unrecognized server values silently in successor | CA + DF; retain hidden-external-body and plain-text limits; no invented recipient picker or rich editor | Subject/internal-body labels and three audience cases; USM17-P each audience, failed GET, hidden body preservation and concurrent edit |
| USM18 / I74 / Approval delegation enable/delegate/search/dates; R04:61/142, A approval authority | Keep `/settings/approval-delegation`; never merge into mailbox Sharing | Explicit Save; saving/error; search 2+ characters/eight results; disabled save clears delegate/dates under existing contract | Change clears selected delegate locally; disabling-and-saving is not reset; initial policy unestablished | CA + DF; approval delegation is not mailbox send/read authority; reject invalid range and stale directory result | `ad-save`; no direct page test found by inventory; USM18-P direct editor fixture, search race, range, permission loss and dirty departure |
| USM19 / I75 / Browser push subscription; R09:43/81/165, browser/device permission | Keep `/settings/notifications` Browser permission, separately labelled from USM06/20 | Explicit Enable triggers helper; busy; granted/error toast; no prompt from mount; no delivery-success claim | No in-app permission reset/revoke action inventoried; denied needs platform guidance, not toggling account preference | CD; unsupported/denied/granted distinct; changing account preference cannot grant browser permission | Browser unsupported/not-asked/granted/denied cases; USM19-P explicit-only prompt, helper failure and account/device separation |
| USM20 / I76 / Global delivery push/desktop-online/sound/mail/calendar/task; R09:179, A global preference, not O policy | Keep Notifications account delivery form with USM21; not a per-device chooser | Explicit Save and Cancel; response OK updates local prefs/toast, not actual notification delivery | Cancel restores last loaded/saved prefs, not factory reset; UI seed push true, sound default, stop false, mail all, reminders true | CA + DF; no browser-permission gating of account editor; preserve fields shared with privacy, no stale whole-form overwrite claim | `Notification sound`, `Notify me about`, Save/Cancel; USM20-P every enum, failed/absent load, stale privacy interaction |
| USM21 / I77 / DND start/end, Mon–Sun bitmask, Save/Cancel; R09:28/106/211, A global preference | Keep same Notifications form/one saver | Explicit Save; blank times become null; errors displayed; no dedicated saving/dirty flag | Cancel restores prefs only if present; blank times/127-day-mask are UI seed, not approved all-day policy | CA + DF; cross-midnight/zero-day/all-day meaning remains owner gap; no inferred timezone policy | `Start time`, `End time`, Save/Cancel; USM21-P day masks, midnight/empty fields, double submit and cross-tab conflict |
| USM22 / I78 / External sender label switch; R10:102/189, A user choice plus O-read effective gate | Keep `/settings/privacy` Labels, not organization policy editor | Immediate optimistic save + session refresh; disabled before load/while saving; rollback/inline error | None; effective org ∧ user behavior is a source comment, not independently verified enforcement/default | CA; separate user preference from immutable-to-this-page organization policy; recheck session refresh | External-label switch and save/rollback tests; USM22-P org-off/user-on, refresh failure and revoked write |
| USM23 / I79 / Receipt ask/always/never and trusted-image-sender Remove; R10:56/127/220, A preferences/trust | Keep `/settings/privacy`; receipt policy and sender-removal remain separate actions | Immediate policy save preserves loaded notification fields; failure reverts; Remove per row with alert/busy; no general Save | None; no Add trust/reset-all action; initial receipt default not established here | CA; preserve global notification fields across stale snapshots; trust removal must affect authorized current sender only | `sj-read-receipt-policy`; mapped tests cover labels only; USM23-P all policies, trust rows, notification conflict and removal failure |
| USM24 / I80 / Signatures alias/text/new-reply defaults/New/Edit/Delete; R15:74/114/136, A Mail | Keep `/settings/signatures` | Editor Save/Cancel; row default and Delete immediate requests; HTTP failure toast, transport handling incomplete; no mutation-busy/confirm | Editor Cancel abandons clone; default roles new/reply/both/none are assignments, not reset; new-form defaults unestablished | CA + DF; preserve existing HTML; `both` to single-role behavior is unresolved, not independent checkbox parity | `sig-new-btn`, `Alias`, `Signature`, `sig-save-btn`, row default/delete IDs; USM24-P all role transitions, transport failure and dirty departure |
| USM25 / I81 / Templates name/subject/bodyHtml and CRUD; R17:41/103, A Mail | Keep `/settings/templates`, distinct from Compose insertion | Explicit Save/Cancel; name required; saving gate; errors retain form; list/delete toast | Cancel is form departure, not delete/reset; no reset action, defaults unestablished | CA + DF; no sanitizer/security claim from textarea; preserve content through failed save | `tpl-new-btn`, `tpl-delete-{id}`, `tpl-save-btn`; no direct page test identified; USM25-P editor CRUD/failure/dirty states, not Compose sanitizer substitution |
| USM26 / I82 / Quick steps name/icon/action rows/CRUD; R11:13/46/156, A Mail | Keep `/settings/quick-steps`; preserve complete inventoried icon/action vocabulary | Explicit Save/Cancel; delete action; name + action required; busy/error; type change resets params | Cancel discards deep-cloned actions; no reset-all or reorder control; initial defaults unestablished | CA + DF; distinguish action-type intentional parameter clearing from lost fields; source `position` does not create reorder UX | `qs-new-btn`, `qs-add-action`, `qs-save-btn`, Name; USM26-P each action/icon, parameter reset, Cancel isolation and stale edit |

## Sharing, booking, rules and storage groups

| ID / I / group and existing source-scope | Proposed canonical destination | Current commit and honest acknowledgement | Reset/default disposition | Conflict/permission preservation | Existing selector; proposed fixture gap |
|---|---|---|---|---|---|
| USM27 / I88 / Sharing overview/calendar defaults/grants/delegates; R14:47/104, A own objects + O-read inherited default | Keep `/settings/sharing`; inherited policy informational | Explicit revoke action; serialized busy/live announcement; skeleton/error/Retry; no role picker | Removing own default/grant is revocation, not reset-all; inherited group/OU/org defaults cannot be edited here | CA; preserve own-versus-inherited provenance and exact grant type; no approval-delegation merge | `sharing-skeleton`, row Revoke, Retry; USM27-P own/group/OU/org precedence, lost access and row identity |
| USM28 / I89 / Mailbox delegate email/access/Grant/Remove; C01:35/66/136, A own mailbox | Keep Sharing Delegate access dialog; separate approval editor USM18 | Explicit Grant/Remove, busy; separate load/action errors; Close does not revoke | Close abandons form only; Remove is explicit grant mutation; no access reset | CA; retain read/send_as/send_on_behalf/full_access/manage_calendar as distinct grants; UI scope is not reducer proof | `Person (email)`, `Access level`, `Grant access`; USM28-P each grant, stale list, permission loss and dialog focus |
| USM29 / I90 / Booking title/slug/description/enabled/CRUD/Copy; R06:97/188/285, A owner booking page with public link | Keep `/settings/booking`; public `/book/{slug}` is an output, not an admin editor | Explicit Save/Cancel and Delete; Copy separate; feature-off distinguished; failed Save keeps form, clipboard failure swallowed | Randomize generates slug in draft, not reset; new form blank identity/enabled true; no delete-confirm | CA + DF; public visibility changes belong to owner; no success inferred from copying URL; no guessed slug-conflict protocol | `Page title`, `Link name`, create/feature-off tests; USM29-P slug conflict, copy failure, enabled change and dirty departure |
| USM30 / I91 / Booking duration/buffer/max-day/notice/advance; R06:52/195, A page configuration | Keep Booking form with USM29/31 | Explicit Save; numeric coercion visible, not server-range validation | None; new-form seeds 30/0/8/120/60; input fallbacks 30/0/1/0/1 differ; timezone seeded browser/UTC, no chooser | CA + DF; preserve exact values and units; do not invent supported min/max or silently normalize imported values | Existing booking form tests do not cover all numeric fields; USM30-P zero/blank/invalid/limits and persisted round-trip |
| USM31 / I92 / Booking weekday windows/questions/required; R06:24/230, A page configuration | Keep same Booking form; no new shared Calendar preference | Explicit Save/Cancel; one visible time pair per enabled day, question add/remove local | New weekdays 09:00–17:00; no reset; Cancel isolation unverified due shallow question copy | CA + DF; multiple loaded windows currently collapse; preserve unsupported data before permitting successor editing | Booking page tests partial; USM31-P multi-window round-trip, question Cancel isolation, day/time labels and conflicts |
| USM32 / I93 / Rules name/priority/runOn/enabled/stop/CRUD; R12:21/215/353, A Mail rule | Keep `/settings/rules`; one rule editor contract | Form Save/Cancel; row enabled immediate; Delete browser-confirmed; busy/error | No reset; priority integer-or-0 is coercion, not policy default; Cancel is not rule disable | CA + DF; server/client/both options do not prove native execution capability; keep current owner gate | Rules E2E `New rule`, Name, `Save rule`; USM32-P runOn capability, toggling while editing, failed delete and stale rule |
| USM33 / I94 / Rules condition fields/operators/value/add/remove; R12:21/313, A Mail rule | Keep same rule editor; retain full inventoried vocabulary without new operators | Local rows until Save; flat AND editing only; value absent for is_true | No reset; removing a condition edits draft, not retroactive message state | CA + DF; grouped/non-field round-trip and field/operator compatibility unresolved; do not approve destructive flattening | E2E `Value` covers one path; USM33-P each field/operator family, grouped input preservation and stable row selectors |
| USM34 / I95 / Rules action vocabulary/parameters/add/remove; R12:27/333, A Mail rule/effect authority | Keep same rule editor; no extra action permissions | Local rows until Save; no action-specific picker/reset handler inventoried | No reset; no implicit parameter reset claimed when changing action | CA + DF; preserve folder/category/address/header/footer fields; forwarding/deletion/header effects keep domain authorization | E2E `Folder or tag name` partial; USM34-P each action/parameter, stale type change and disallowed effect |
| USM35 / I96 / Message-to-rule query prefill; R12:73, A context + local draft | Keep `/settings/rules` prefill entry and authorized return; URL cleanup not a new redirect contract | Prefill creates draft; no mutation until Save; sender precedes domain; subject may append | No reset; new query must not silently overwrite an unrelated dirty rule | CA + DF; URL context is not authority; preserve one editor session across cleanup | No exact prefill test identified in inventory; USM35-P sender/domain precedence, dirty draft collision and query removal |
| USM36 / I97 / Rules retro apply window/Run/panel Cancel/status; R12:227/394, A rule/job | Keep `/settings/rules` same-job re-entry per UI plan | Explicit Run; 90d/1y/all; bounded page polling; Cancel closes panel only when idle, not job cancellation | No reset/undo implied; changing window is new intent only before authorized Run | CA + OP; reconcile existing job after timeout/refresh; no second Run to regain status; no invented cancel endpoint | Source Run/Cancel/radios; USM36-P stable rule/job selectors, lost response, refresh, exhausted polling and real terminal outcome |
| USM37 / I98 / Storage quota/native estimate/cache/free/gate; R16:32/66/172, A mailbox quota + D readouts + server caps | Keep `/settings/storage`; display scopes separately | Read-only loading/error/Retry; browser cloud card only; unknown/disallowed native caps inert | Not applicable; zero free-space currently means unknown for overflow display, not spare capacity | CD + CA; no inherited policy editor; distinguish bridge absence, denied caps and quota-fetch error | Storage loading/error/Retry/browser/inert cases; USM37-P account/device scope labels and unknown-space display |
| USM38 / I99 / Storage window/Fit/Sync/Clear entry; R16:107/210 + H01:5, D cache + server preference | Keep `/settings/storage`, canonical window UI for USM10 after persistence qualification | Slider/Fit immediate selection then helper Save; error but no rollback; Sync explicit helper/readback/toast, not generic all-mail completion | No reset; helper default and page seed 30d; six windows 7d/30d/90d/180d/365d/all; Fit is calculated choice | CD; resolve preference scope and effective caps; preserve cache approval and syncing/inert guards; no silent deadline or window expansion | `role=slider`, active/inert/first-run/overflow cases; USM38-P same failed write across root/storage, Fit bounds and Sync receipt gap |
| USM39 / I100 / Storage dangerous Clear dialog; R16:129/278, D cache | Keep same Storage dialog and blast-radius copy | Explicit confirmed Clear; busy footer; failure keeps dialog/error; helper result then size refresh/close | Clear cache is destructive scoped action, not preference reset or server-mail deletion | CD + OP; preserve exact device/account ownership and accepted-work retention requirements; generic dismissal behavior unverified | Cache-clear dialog cases; USM39-P exact affected bytes, failed clear/readback, dismissal while busy and focus return |

## Security groups

| ID / I / group and existing source-scope | Proposed canonical destination | Current commit and honest acknowledgement | Reset/default disposition | Conflict/permission preservation | Existing selector; proposed fixture gap |
|---|---|---|---|---|---|
| USM40 / I108 / Device tab/list/logout dialog; R13:111/643/1102, A device-session authority, not local preference | Keep `/settings/security` Devices | Explicit confirmed Logout for noncurrent active device; dialog closes before request; success removes row, error toast; no separate commit busy | No reset; initial devices tab is presentation, logout is revocation | CA; keep current-device exclusion; a device row disappearing is not proof all physical-device effects stopped | Devices/history/totp tab IDs and security workflow tests; USM40-P late list, duplicate confirm, revoked scope and device identity |
| USM41 / I109 / Sign-in history/filter/pagination/Not me; R13:288/680, A audit projection | Keep Security History; Not me enters USM43, not a history-edit form | Filter/load/Retry read-only, 200-row offset pages; Not me opens action dialog | Filter changes no records; no clear-history/reset action | CA; retain filtered-empty versus failed load; no cross-account/cached audit disclosure after revocation | `failed-only-toggle`, `signins-*`, `signin-row-{id}`, `signins-load-more`; USM41-P offset race, filter reset, denied history and stable rows |
| USM42 / I110 / Individual/all session sign-out + dialogs; R13:759/932, A security | Keep Security Sessions; do not merge with device/logout or secure-account actions | Explicit Confirm; current/all terminal handlers navigate login; errors toast; dialogs close before request | No reset; sign-out is revocation, Cancel only declines request | CA + OP; preserve current-session warning; response loss is not confirmed logout; no browser-local-only interpretation | `session-revoke-{id}`, `revoke-current-warning`, `revoke-all-trigger/confirm`; USM42-P current/other/all, repeated confirm and unknown response |
| USM43 / I111 / Secure account/Not me/list/typed SECURE; R13:377/962, A security | Keep Security Secure account dialog with distinct consequence | Explicit typed confirmation; list busy/error gates; OK or 401 treated terminal by handler; `secureCommitting` not in disabled expression | No reset/undo; Cancel closes form, not reversal of accepted action | CA + OP; preserve owner terminal/security semantics; do not infer 401 universally proves success; duplicate submission remains gap | `secure-account-trigger/type/confirm`, `secure-list-error`; USM43-P double-click, dismissal, stale list, authorization failure versus terminal response |
| USM44 / I112 / TOTP tab/setup/code/re-enrol/disable; R13:530/794, A security | Keep canonical Security TOTP editor for USM08; retain Re-enroll | Explicit setup/verify/re-enrol/disable; loading/length gates and inline errors; no ordinary settings Save | No reset; server factor state is authoritative; re-enrolment is separate security intent | CA; preserve current owner proof/permission; textual secret and QR-oriented copy need reconciliation, not invented QR support | TOTP tab and workflow tests; USM44-P root-child parity, re-enrol authorization, failed verification and secret-safe departure |
| USM45 / I113 / Client mTLS status/subject/expiry/Retry; R13:822 + C02:65, A authenticated certificate projection | Keep Security Client certificate information; not S/MIME editor | Read-only status valid/expiring/expired/none; independent loading/error/Retry | No reset/upload/enrollment action; enrollment remains out-of-band | CA disclosure; missing status none is projection behavior, not certificate revocation; no key upload inferred | CertStatusCard status cases; USM45-P status/error distinctions, scope and inaccessible subject |
| USM46 / I114 / Own S/MIME identity list/default/upload/delete; R13:441/830/1116, A signing/encryption identity | Keep Security S/MIME identities; separate from mTLS and contacts | Explicit upload/default/delete; upload busy/validation; default/delete failures currently log; no truthful successful mutation from silence | Set default is identity selection, not reset; Delete confirmed; no restore-default/new-key action | CA; preserve key custody and distinct delete authority; no secret autosave via DF; certificate accept filters are not validation proof | Security certificate workflow cases; source upload/default/delete actions; USM46-P key/file errors, default/delete failure, duplicate submit and secret cleanup |
| USM47 / I115 / Contacts' certificate import/list/source/expiry/delete; R13:217/1007/1128, A contact trust | Keep Security Contacts' certificates, not own-key or organization trust editor | Explicit import/delete; import busy/error, deletion failure logs; harvested/imported and signing-only are display facts | No reset; optional label, no private-key input in inventoried import; delete is scoped trust mutation | CA; preserve harvested encryption eligibility and source provenance; no new CA-management privilege | Security workflow cases partial; USM47-P row-scoped IDs, expired/expiring/signing-only, failed delete and permission loss |

## Migration groups

| ID / I / group and existing source-scope | Proposed canonical destination | Current commit and honest acknowledgement | Reset/default disposition | Conflict/permission preservation | Existing selector; proposed fixture gap |
|---|---|---|---|---|---|
| USM48 / I123 / Source selection IMAP/EWS/M365 and defaults status; R08:18/269/296, local draft + A migration context + read-only global defaults | Keep `/settings/migration`; M365 remains informational until its owner admits a workflow | Immediate local selection clears connection result; optional defaults load; no settings Save/start for M365 | Source change resets connection result intentionally; no global-default reset/editor | CA + DF; defaults are not credentials/authority; failed defaults lookup cannot be reported configured | Migration workflow/source selection tests; USM48-P selection race, defaults failure and M365 no-start branch |
| USM49 / I124 / IMAP host/port/security/user/password/test/Next; R08:88/326, sensitive local draft + A migration target | Keep Migration IMAP step | Local edits; explicit Test connection; Next gated on successful result string, not durable migration acceptance | No reset; port choices 993/143/other and tls/starttls/none remain inventory, not recommended defaults | CA + DF; fresh test after relevant edit, port validation, secret retention and cleartext policy remain owning gaps | IMAP labels/port/Next tests; USM49-P edited-after-test invalidation, bounds, denied egress and secret-safe departure |
| USM50 / I125 / EWS URL/user/password/Next; R08:306, sensitive local draft + A migration target | Keep Migration EWS step | Local edit; Next on three nonempty fields; no EWS connection-test action currently mounted | No reset; defaults unestablished, do not copy IMAP test success | CA + DF; preserve URL/credential owner and qualification; no implied validated connection from Next | EWS workflow mapping; USM50-P malformed/denied endpoint, stale source switch and secret-safe Back/navigation |
| USM51 / I126 / ICS/VCF uploads, skip/overwrite/rename, Start/Back; R08:112/374, A new migration job + local files | Keep Migration upload/start step | Explicit Start creates job then optional upload; unchecked upload response cannot confirm imported data; Back is navigation | No reset; conflict mode is an explicit choice, not permission to overwrite arbitrary data | CA + DF + OP; preserve exact target/scope; separate job acceptance, upload verification and import outcome; no replay-on-refresh | Optional upload/start workflow cases; USM51-P wrong file/size, upload failure after job creation, overwrite preview and lost Start response |
| USM52 / I127 / Running/paused/terminal/logs/Pause/Resume/Cancel/Inbox; R08:172/401, A existing migration job | Keep Migration same-job re-entry per pre-U1 plan; not a new global operation dashboard | Explicit controls, but page ignores response status; polling projects outcome; fixed 50/100 width is not measured progress | Cancel is requested domain action, not reset or automatic deletion of imported work; Inbox navigation changes no job | CA + OP; confirmed control outcomes, timer teardown, restart/re-entry and unknown state remain gaps; never show cancelled on transport success alone | Running/EWS/M365 workflow controls; USM52-P stable job identity, control 4xx/lost response, unmount, paused resume and terminal rediscovery |

## Source register and current route disposition

Hashes below are current bytes, not implementation or visual receipts. Route
source IDs are used in every mapping row. Each route remains available until its
proposed successor/alias behavior is explicitly reviewed; this file removes none.

| ID | Existing file / route | Canonical route disposition | SHA-256 |
|---|---|---|---|
| R01 | [root page](../../mailserver/webmail/src/routes/settings/+page.svelte), `/settings` | Keep profile/local Mail/passkeys/recovery pending qualified successor; consolidate only mapped duplicates | `ece13eeb7049bf11ad8ceaeaabb52832e3c4b4d561a235d72967aa00b8545b3f` |
| R02 | [about page](../../mailserver/webmail/src/routes/settings/about/+page.svelte), `/settings/about` | Keep information | `a938d8d869e83b93c38dc1f688494c175323e3e50c49aedd77db26077bd9e66e` |
| R03 | [appearance page](../../mailserver/webmail/src/routes/settings/appearance/+page.svelte), `/settings/appearance` | Canonical theme/density and existing tour | `7c96c31d1211a7207540f1ad8f6cf9573a5da194ead6bf95d0a5b2c56c216e6b` |
| R04 | [approval page](../../mailserver/webmail/src/routes/settings/approval-delegation/+page.svelte), `/settings/approval-delegation` | Keep approval authority editor | `12529c2d15a01474b6e4d96b6414d017791448bfae06c3c8271182a7a9709a5f` |
| R05 | [automatic replies page](../../mailserver/webmail/src/routes/settings/automatic-replies/+page.svelte), `/settings/automatic-replies` | Keep one two-group form | `46b108179d89ee7dbc28b7b7a3eba785e9e7921c79f0d662fb7ed3a072bdbcf2` |
| R06 | [booking page](../../mailserver/webmail/src/routes/settings/booking/+page.svelte), `/settings/booking` | Keep owner editor | `e78416b938fae95e86d23d6ef81461b07b71be0e075674658c7cd0f84d23c922` |
| R07 | [language page](../../mailserver/webmail/src/routes/settings/language/+page.svelte), `/settings/language` | Canonical locale; regional examples read-only | `cf44534bf25d0ef3af87f2a4c605e1c1ae1afd76a26408c1f30419eb0a8a0ab0` |
| R08 | [migration page](../../mailserver/webmail/src/routes/settings/migration/+page.svelte), `/settings/migration` | Keep source-owned wizard/status | `7dcf5e3bf216e38e7614ca221025fe4119d781bf6b666ff3d1f05c8001157a2f` |
| R09 | [notifications page](../../mailserver/webmail/src/routes/settings/notifications/+page.svelte), `/settings/notifications` | Keep distinct browser and account controls | `52bcaa5775322a0fec69da86d2ceda766c8c8aca7f82758745185465b989c9c5` |
| R10 | [privacy page](../../mailserver/webmail/src/routes/settings/privacy/+page.svelte), `/settings/privacy` | Keep user preference/trust editor | `182163559e8bf74bf11f464e34c44944c6395dbfd75724e38d26b39edd7193b2` |
| R11 | [quick steps page](../../mailserver/webmail/src/routes/settings/quick-steps/+page.svelte), `/settings/quick-steps` | Keep action editor | `4bb23a8b260416c7f2796e8c2bb433f8344d5140cf9cc756928c28f9bb6a529a` |
| R12 | [rules page](../../mailserver/webmail/src/routes/settings/rules/+page.svelte), `/settings/rules` | Keep editor/prefill and same-job re-entry | `8189fc897cc1ebf481b40bbb7171366feea4f1bdc259b51aa0df50e45771e850` |
| R13 | [security page](../../mailserver/webmail/src/routes/settings/security/+page.svelte), `/settings/security` | Keep distinct security editors/dialogs; canonical TOTP | `f7cde52ad52cfaf80ca434d91e1db585201261eaf1a26ab0ad7af45af0cfd572` |
| R14 | [sharing page](../../mailserver/webmail/src/routes/settings/sharing/+page.svelte), `/settings/sharing` | Keep scoped overview/delegate editor | `1e6459712106ff4d2afff14c74ccda06bab5456960b16286fc375bc31ff2c803` |
| R15 | [signatures page](../../mailserver/webmail/src/routes/settings/signatures/+page.svelte), `/settings/signatures` | Keep signatures and default assignments | `fecfec9238fa4cf915d6bde8c4039df76c81beec9cc2fdc718861ffc8cb42dbd` |
| R16 | [storage page](../../mailserver/webmail/src/routes/settings/storage/+page.svelte), `/settings/storage` | Canonical qualified native cache controls, account quota separately labelled | `7408ced845fcb376960c94bc88992de0d9c7bd8c23c6ca0b193a1876fb17efc0` |
| R17 | [templates page](../../mailserver/webmail/src/routes/settings/templates/+page.svelte), `/settings/templates` | Keep editor, not Compose insertion surface | `47a03cc4a744d3c950aeb9cbd9d662f47cc56f4abe2ae53bf17cea900135a85f` |
| C01 | [ShareMailboxDialog](../../mailserver/webmail/src/lib/components/ShareMailboxDialog.svelte) | Preserve own-mailbox grant types | `154c2446969de84eca1a0d23e5accb350d82c15848bddb4c5ddde475371ccf2b` |
| C02 | [CertStatusCard](../../mailserver/webmail/src/lib/components/CertStatusCard.svelte) | Preserve read-only mTLS status | `7952c47ab0c442b014e7d2886810901dfb65b4a29e6a8ef1c3b2ffde0e87d480` |
| H01 | [offline window](../../mailserver/webmail/src/lib/offline/window.ts) | Preserve native window vocabulary, not a new grant | `304310cc5bd2985500a80576363f36d1571c76d594a496f275db2d2625647839` |

Documentary input bindings:

| Input | SHA-256 |
|---|---|
| Settings option matrix | `4e63d6f791a96e3ff5a819b42234802c3c96e462ef15d5efef64eef363cd8662` |
| Frozen surface inventory | `6bef489c7cf23dfad39efd0e13b91d967a679cdf7e141e4184b5f6b3786c4423` |
| UI plan | `619c562e370d5753e9708731163c9444f46bc0d46fc42eb7f6674142bc5aa469` |

The UI plan initially hashed
`bdc278c6d2808bb59f2f525bc203d60d0deacd6b2c47c3c05a9cb7f57a3bfd13`.
During authoring, root changed only its review footer to link the completed
Engineering correction receipt, retaining the prior scoped score and open visual
gates. The current footer was read and the binding above refreshed; root confirms
the U0/pre-U1 behavior sections are unchanged. This editorial receipt drift is not
new settings approval. Later index-link additions require their own hash chronology.

## Acceptance and integration boundary

Before retiring an entry, bind its USM row to the actual shared editor/caller,
current domain authority and persistence owner, existing or proposed executable
selector, fixture and old/new route parity check. Every USMnn-P includes a positive
case plus load/save failure or denied/unavailable case appropriate to that row.
For mutating forms add stale/cross-tab, lost response and DF departure; for actions
add duplicate/late completion; for read-only groups test absence of mutation.
These obligations do not assert every combination is meaningful: exclusions need
an explicit reason and cannot hide a named enum or conditional field.

Keep the inventory's existing test limits: approval delegation and templates lack
an identified direct page test; rules E2E samples one vocabulary path; privacy
tests do not prove receipt/trust removal. Preserve all six security confirmation
dialogs. Propose stable row-scoped selectors where only dynamic/text/positional
targets exist; do not fabricate current test IDs for them.

No user choice is closed here. FG-DES-01/02, current screenshots, full state frames,
360/768/1024/1440 comparisons, keyboard/focus/announcements, three languages,
200% zoom, native-host behavior and final visual approval remain with U0/U1 and
their existing owners. A complete group mapping is not a complete runtime audit.

Root integration: add a link immediately after the settings inventory paragraph
in UI plan U0 and from the pre-U1 table's field-by-field mapping paragraph. This
document need not become a second navigation catalog. Root owns those edits,
independent review, the continuation ledger and Graphify/index maintenance.

Author validation reconciled all 52 IDs to their exact inventory lines, all 17
route candidates and 20 source-register hashes. All 28 relative links and cited
line bounds resolve; whitespace and final newline are clean. This is documentary
validation, not an application test. This unit creates only this Markdown file under local
Mac task `sj-plan-score-20260907`; no services, temporary resources, application
tests, network activity, credentials, Git actions, outside review or subagents.
