# Outlook Classic vs setjoin — Feature Map

Date: 2026-06-16
Source: outlook-classic-feature-map workflow (6 area agents + synthesis); 242 features graded
Status legend: have | partial | missing | not-needed | ask

# Outlook Classic (Windows) vs setjoin — Feature Parity & Gap Analysis

Scope: every Outlook-Classic-for-Windows feature mapped against the current setjoin implementation, grouped by product area. Status is verbatim: **have** / **partial** / **missing** / **not-needed** / **ask**. Evidence cites the files/reducers/endpoints that back the assessment. Priority is the migration priority for closing the gap.

Totals across all areas: **have 90 · partial 67 · missing 67 · not-needed 17 · ask 1** (242 features). *(A1 compose-parity, 2026-06-17: +7 → have — recall UI, signatures card + new/reply default, S/MIME sign+encrypt toggles, attachment reminder, inline image, font/size/color toolbar, plain-text-only send.)*

---

## Ratified Non-Goals

The 17 **not-needed** features below are **ratified non-goals** (owner-confirmed 2026-06-16): they will not be built. This section exists so the decision is *findable* — a future contributor proposing one of these can grep `ratified_non_goal` and see it was a deliberate call, not an oversight. Each carries the machine-readable marker `ratified_non_goal: true` and a one-line rationale. (To reverse one, change its marker and move it out of this section with a dated note.)

```yaml
- feature: IRM / Sensitivity labels / Do-Not-Forward / Purview      # Area 1
  ratified_non_goal: true
  rationale: Full Azure-RMS/Purview is cloud-coupled; advisory sensitivity header + DLP cover the on-prem need.
- feature: Stationery & themes (compose backgrounds/fonts)          # Area 1
  ratified_non_goal: true
  rationale: Clutter + a11y/deliverability hazard; clean token styling is the deliberate house style.
- feature: Save sent item to a chosen folder                        # Area 1
  ratified_non_goal: true
  rationale: Gmail-style Sent location tag + rules already redirect/organize the saved copy.
- feature: AutoArchive (scheduled move of old items to .pst)        # Area 2
  ratified_non_goal: true
  rationale: Server-side tiered storage + retention replace client-side .pst movement entirely.
- feature: Weather bar (3-day forecast)                             # Area 3
  ratified_non_goal: true
  rationale: Would phone home to a forecast service — breaks the air-gap-capable on-prem guarantee.
- feature: Business Card view / EBC (designed card image)           # Area 4
  ratified_non_goal: true
  rationale: Legacy Outlook artifact; vCard interchange covers the real contact-exchange need.
- feature: Map It (open mailing address on a map)                   # Area 4
  ratified_non_goal: true
  rationale: Requires an external maps service; conflicts with the on-prem/air-gap goal.
- feature: Notes module (sticky notes)                              # Area 5
  ratified_non_goal: true
  rationale: MS itself steers users to OneNote; out of scope as a mail-suite primitive. (Owner may revisit as a future SMB app.)
- feature: Journal (activity log / time tracking)                   # Area 5
  ratified_non_goal: true
  rationale: Deprecated by MS since 2013; setjoin's journal.sql is compliance archiving, not a personal Journal.
- feature: Microsoft To Do / My Day integration                     # Area 5
  ratified_non_goal: true
  rationale: Proprietary MS cloud; setjoin Tasks is the native on-prem store, with no cloud counterpart to sync to.
- feature: Read Aloud / narration of a task                         # Area 5
  ratified_non_goal: true
  rationale: OS/browser screen readers already narrate; TasksApp carries ARIA roles + keyboard nav.
- feature: Mail profiles (multiple Outlook profiles)                # Area 6
  ratified_non_goal: true
  rationale: MAPI/Win32 artifact; a web session per identity (re-login / alias switch) replaces it.
- feature: Public folders                                           # Area 6
  ratified_non_goal: true
  rationale: Legacy Exchange; shared mailboxes + DLs + shared calendars cover the modern case.
- feature: Online Archive (In-Place Archive secondary mailbox)      # Area 6
  ratified_non_goal: true
  rationale: S3 tiering replaces a user-visible second mailbox node (design choice vs an All-Mail tag).
- feature: COM add-ins (legacy VSTO/native)                         # Area 6
  ratified_non_goal: true
  rationale: No COM analog in a web SPA; MS itself is deprecating COM for web add-ins. (Web-add-in extensibility is the separate open `ask` row, not this non-goal.)
- feature: Ribbon & Quick Access Toolbar customization              # Area 6
  ratified_non_goal: true
  rationale: The SPA shell is intentionally fixed; no per-user chrome-customization model.
- feature: Office/Purview Message Encryption (OME)                  # Area 6
  ratified_non_goal: true
  rationale: OME is Azure-RMS-bound; setjoin uses S/MIME (open standard) + at-rest encryption by design.
```

---

## Area 1 — Mail: compose & send

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Compose new message (full-screen/window) | New Email opens a full compose window with To/Cc/Bcc, Subject, body, ribbon tabs. | have | ComposeScreen.svelte full-screen dialog, From/To/Cc/Bcc/Subject/body + options sidebar; M4 migrated all legacy features. | high |
| To / Cc / Bcc recipients | Address fields with name resolution; Cc/Bcc toggled via Options. | have | ComposeScreen.svelte L38-41,839-872; Cc/Bcc hidden by default, revealed on demand. | high |
| GAL / Contacts name autocomplete | Type-ahead against GAL+Contacts; Check Names (Ctrl+K). | have | galSearch() L638-682; LDAP GAL. Combobox with keyboard nav; no separate Check Names / picker dialog but inline resolution covers daily case. | high |
| Contact-frequency ranking in autocomplete | Ranks Auto-Complete by most-recent/frequent. | have | recordSend()/contactRanking util L15,528-530. | med |
| From / send-as identity selector | Send as another account/alias/shared mailbox with rights. | have | from-select L811-820; send.sql verifies send_as/send_on_behalf/full_access L41-80 (enforced server-side). | high |
| Rich text (HTML) body editor | HTML compose with fonts/colors/lists/links/images/tables. | have | RichTextEditor.svelte (TipTap StarterKit) + toolbar (bold/italic/underline/strike/lists/blockquote/link/**image/font/size/color** — A1). Table still TODO. | high |
| Message format HTML / RTF / Plain Text | Switch outgoing format among HTML, Outlook RTF, Plain Text. | have | A1: **Plain text only** Switch in compose More panel drops the HTML body part in buildMsg(). TNEF/Outlook-RTF intentionally not produced (not-needed). | med |
| Font family / size / text color / highlight | Format Text ribbon font/size/color/highlight. | have | A1: RichTextEditorToolbar Font/Size selects + text-color input (TipTap TextStyle/Color/FontFamily/FontSize). Highlight still TODO. | med |
| Insert hyperlink | Insert > Link with text+URL, edit/remove. | have | toolbar openLinkDialog/insertLink/removeLink L76-110. | med |
| Insert inline image / picture | Insert > Pictures embeds inline. | have | A1: TipTap Image extension (URL-only, allowBase64:false) + toolbar Insert-image dialog; RichTextEditor.insertImage(). | med |
| Insert table | Insert > Table builds HTML table. | missing | No @tiptap/extension-table in extensions. | low |
| Attach file (local) | Attach File / drag-drop. | have | handleFiles/uploadBlob L708-722, drop-zone L907-919; SHA-256 dedup S3 blobs. | high |
| Cloud / OneDrive attachment (share-link + permissions) | Attach cloud file as sharing link with view/edit perms. | missing | No cloud-attach/share-link code anywhere; no cloud-storage integration. | low |
| Large-file / over-quota attachment handling | Warns on size; offers upload-to-cloud-as-link. | missing | No size-limit warning or upload-as-link in handleFiles; uploads just fail. | low |
| Forgotten / attachment reminder | Warns when body mentions an attachment but none attached. | have | A1: mentionsAttachment() (EN/ZH/DE keyword scan, URLs stripped) warns once on Send when attachments=0; second Send proceeds. | med |
| Draft autosave | Auto-saves drafts periodically and on close. | have | saveDraft() + 5s debounce L632-636; editingDraftId tracking. | high |
| Save / re-open draft | Drafts reopen with all fields. | have | loadDraft() L393-414 restores from/to/cc/bcc/subject/priority/sensitivity/readReceipt/scheduledAt/voteOptions. | high |
| Importance (High/Normal/Low) | Priority flag shown to recipient. | have | priority state+select L75,1020-1023; V007 messages.priority; mapped to JMAP 1/0/-1. | med |
| Sensitivity (Normal/Personal/Private/Confidential) | Sets sensitivity header. | have | sensitivity select L76,1024-1027; V007 CHECK column. Advisory only (as in Outlook). | low |
| Request read receipt | MDN sent when recipient opens. | have | readReceipt switch L85,975; V007 read_receipts; HandleReadReceipt sends MDN via send_read_receipt() (handler.go L2294). Full loop. | med |
| Request delivery receipt | MTA confirms delivery. | partial | V007 delivery_receipt_requested column exists; buildMsg hardcodes undefined L455 — no UI toggle, no DSN wiring. | low |
| Voting buttons + response tracking | Approve/Reject etc., responses tallied. | partial | Compose voting UI L86-88,1028-1048; V007 vote_options + vote_responses table, but no inbound vote capture / tally UI. | low |
| Delay delivery / schedule send | "Do not deliver before" date/time; waits in Outbox. | have | schedule modes + DateTimePicker L182-187,966-974; jmap_email_submission.sql sendAt L62-80 → message_schedule(); cron enqueues. Quick presets. Server-side (no client running needed). | high |
| Undo send | Brief cancel window after Send. | have | undo countdown + emailSubmissionCancel L49-51,553-589; configurable 5-300s. Better than classic. | high |
| Recall this message (retract + replace) | Delete/replace unread copies, same-org, with report. | have | A1: Recall action (Undo2) in the Sent reading-pane toolbar → recallEmail() → POST /messages/{id}/recall (recall_message() reducer, 5-min window, internal-only, feature.recall). Recall-and-*replace* deferred per the Track-A index. | high |
| Resend this message | Reopens editable copy to resend (e.g. after NDR). | missing | No resend handler/UI. Can approximate via forward. | med |
| Reply / Reply All / Forward | New compose with quoted original + prefilled recipients. | have | loadReplyContext() quotes original L370-391; reading-pane actions in M3. | high |
| Reply-To (Have replies sent to) | Direct Replies To a different address. | have | replyTo field L41,460; per-alias reply_to in send.sql. | low |
| Signatures (multiple, per-account/alias, new vs reply default) | Named signatures, per-account, auto-insert, Insert > Signature. | have | A1: signatures-management card at /settings/signatures (list/create/edit/delete); new-vs-reply default via user_signatures.default_for (V082) + set_signature_default reducer; mid-compose Insert→Signature menu. Backed by /settings/signatures CRUD; send.sql still appends per-identity. | high |
| Roaming / cloud signatures | Signatures roam across devices. | have | Stored server-side in signatures table → roam by default. | low |
| S/MIME digital signing | Options > Sign with user cert. | have | smime/smime.go (CMS SignedData); outbound.go signSMIME() auto-signs when a cert exists. A1 adds a per-message **Sign (S/MIME)** compose toggle (`smimeSign` in buildMsg(), mirrors Encrypt). | med |
| S/MIME encryption | Encrypt contents+attachments to recipient certs. | have | smimeEncrypt toggle L91,1049 → outbound.go encryptSMIME() L222; smime.go EnvelopedData. Per-message toggle wired end-to-end. | med |
| IRM / Sensitivity labels / Do-Not-Forward / Purview | Rights-management labels enforce no-forward/print/expiry. | not-needed | Advisory sensitivity header implemented; full Azure-RMS/Purview is cloud-coupled, out of scope on-prem. DLP + advisory cover the need. | low |
| @mentions | Type @ to pick a person; auto-added to To. | missing | No @-mention extension/handler. Popular collaboration affordance. | med |
| Quick Parts / Building Blocks / AutoText | Save/insert reusable snippets in body. | missing | templateVariableExtension is merge-tokens, not snippets; no snippet gallery. | low |
| Email templates (.oft equivalent) | Save/start from reusable message templates. | partial | email_templates table (V007) + merge-token chips, but no surfaced template picker/manager UI. .oft file format itself not-needed. | med |
| Stationery & themes (compose backgrounds/fonts) | Default theme/background for new HTML mail. | not-needed | Deliberate non-goal (clutter, a11y/deliverability); clean token styling. | low |
| Spell check (before send / as-you-type) + Editor | Spelling/grammar, check-before-send, squiggles, Editor. | partial | TipTap relies on browser native spellcheck only; no check-before-send gate, no grammar/Editor, no custom dictionary. | med |
| AutoCorrect | Fix typos + smart quotes as you type. | missing | Only markdown-paste auto-conversion exists. | low |
| Dictation (speech-to-text) | Dictate transcribes speech to body. | missing | Not present. | low |
| Read Aloud | Read Aloud / Immersive Reader narrates. | missing | Not present; browser TTS could cover later. | low |
| Categories / color categories | Assign color categories to a message. | have | categories state + UI L77,1050-1059; tag-on-send L1003-1011 (tags = durable Gmail-style equivalent). | low |
| AI writing assist (draft/polish/translate/shorten) | Copilot drafts/coaches email. | have | runAssist() L747-777 gated by effectiveCaps.assist (B4). setjoin-native Copilot equivalent. | low |
| Insert meeting / schedule from compose | Calendar via separate meeting item. | have | includeMeeting + AvailabilityGrid + room finder L977-1001 — beyond classic compose. | low |
| MailTips (external/large-audience/OOO/no-send-as) | Inline warnings above compose. | have | fetchMailTips() + badges L684-706,874-886; /auth/me/mailtips. Parity for common cases. | med |
| Expires after (message expiry) | Greys message in recipient mailbox past a date. | missing | No expiry field in compose or V007 schema. Rarely used. | low |
| Save sent item to a chosen folder | Redirect saved copy to a non-default folder. | not-needed | Gmail-style Sent location tag + rules cover the case. | low |
| Auto-Bcc / always Bcc an address | Achieved via add-ins/rules (journaling/compliance). | have | send.sql per-identity bcc_send auto-BCC (~L108-114) + journaling. | low |
| Minimize / pop-out compose | Compose is a window you minimize/return to. | have | minimize → compose-pill L796,1092-1102; composeStore minimize/maximize. | low |

---

## Area 2 — Mail: read & triage

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Reading Pane (preview pane) | Right/bottom pane; position Right/Bottom/Off. | have | ReadingPane.svelte + inbox layout. Pane position fixed (right); no bottom/off toggle. | high |
| Reading-pane mark-read timing | Mark read when viewed / wait N sec / on selection change. | partial | Open-on-select sets $seen; no configurable timer, no mark-on-selection-change. | med |
| Mark Read / Mark Unread | Toggle read/unread on one/many (Ctrl+Q/U). | partial | $seen keyword + markRead 'i' shortcut + emailSet path, but no explicit mark-read/unread toolbar/menu action wired in pane/row; toggling unread on a read message has no control. | high |
| Preview text lines in list | Configurable 0-3 preview lines. | partial | MailRow renders single ellipsised preview line; not configurable, no density toggle. | low |
| Conversation / threaded view | Group into conversations, expand/collapse, per-folder. | have | buildThreads(); Flat/Threaded tabs; MessageList expand/collapse. Some views force flat. | high |
| Conversation settings (other folders, indented, etc.) | Show-from-other-folders, senders-above-subject, classic indented. | missing | Threads by threadId only; no cross-folder rollup or indentation options. | low |
| Ignore Conversation (→ Deleted + future replies) | Ignore deletes thread + auto-deletes future replies ~30 days. | partial | muteEmail()/muteThread() apply 'Muted' tag (closest analog) but does NOT delete or auto-trash future replies. | med |
| Clean Up (delete redundant quoted messages) | Removes messages fully contained in later replies. | missing | No clean-up action anywhere. Niche; threaded view collapses clutter. | low |
| Flag for Follow Up (basic flag/star) | Flag for follow-up; To-Do bar/Tasks; flag column. | partial | $flagged via starEmail(); Star button in MailRow/ReadingPane; rule action 'flag'. Plain boolean — no due date, no To-Do bar, no Tasks roll-up. | high |
| Flag with due date + presets (Today/Tomorrow/Week/Custom) | Follow Up dropdown sets start/due dates. | missing | jmap.ts has dueAt?/reminderAt? L274-275 but no UI to set flag date; no presets. | med |
| Follow-up reminder (pop-up for flagged mail) | Pops a reminder at the set time. | missing | No reminder engine for flagged mail; reminder fields unused for mail. | med |
| Set Quick Click (default one-click flag) | Configurable default flag in one click. | partial | One-click star in MailRow/pane, but flag is fixed boolean; no configurable default. | low |
| Mark Complete / Clear Flag (strikethrough) | Mark complete (check+strikethrough) or clear. | partial | Clearing flag = un-star; no separate 'complete' state with strikethrough. | low |
| Categories / Color Categories | Assign colored categories; manage master list. | have | Gmail-style tags: MailSidebar tag tree, ReadingPane tag picker (create/add/remove/color), messages.categories + rule 'categorize'. Conceptually richer; term differs. | high |
| Quick Steps (one-click multi-action macros) | Custom buttons chaining actions; built-in Move To/To Manager. | missing | None (grep = nothing). Power-user staple; setjoin has individual buttons + rules but no user-defined macro. | high |
| Rules — client + server (Rules Wizard) | Conditions/actions/exceptions; client vs server; run now. | have | rule_engine.sql/rule_engine_or.sql (eval_condition+apply_action, run_on server/both/client, OR-grouping); settings/rules + admin/rules; docs/specs/RULES.md. | high |
| Run Rules Now / retroactive apply | Apply selected rules to existing folder. | partial | Competitive-analysis cites retroactive bulk apply; verify an explicit 'run now / apply to existing' control is surfaced in settings/rules UI. | med |
| Conditional Formatting (font/color rules in views) | View Settings colors/bolds rows by condition. | missing | No per-view conditional row styling. Tags give color but not condition-driven. | low |
| Focused / Other Inbox | Splits inbox into Focused/Other tabs; learns. | missing | Fixed 7 sidebar views; no ML split. Newsletter Bundles is the nearest noise-reduction analog. | med |
| Junk filtering + Block / Never Block Sender | Junk level, Safe/Blocked Senders, Block TLD; Block/Not-Junk. | have | Per-user safe/blocked lists (/settings/senders); spam classifier + Not-Spam action in ReadingPane. A one-click 'Block Sender' from a row is not clearly surfaced. | high |
| Search Folders (virtual saved-search folders) | Virtual folders matching criteria across real folders. | missing | Search is query-driven (tag:/from:) but not saveable as persistent virtual folders. | med |
| Search query operators (from:, subject:, has:attachment) | Instant Search refiners + keywords. | have | parseSearch() tag:/from:; pg_search BM25 full-text. Fewer refiners than Outlook (no has:attachment / received: surfaced). | high |
| Archive (one-click → Archive / Backspace) | Archive button moves to Archive folder. | have | archiveEmail()/archiveThread() strip location tags; Archive button + 'e' shortcut; undo toast. | high |
| AutoArchive (scheduled move of old items to .pst) | Periodically moves old items to archive file. | not-needed | Deliberate non-goal; server-side tiered storage + retention replace client-side .pst. | low |
| Online Archive (server-side secondary mailbox) | Separate cloud archive mailbox with own retention. | partial | Retention/MRM + tiered storage exist server-side; no user-visible 'Online Archive' node in sidebar. | med |
| Snooze (hide until later) | Native Snooze in new Outlook; classic uses flags. | have | message_snooze.sql + Snoozed tag; SnoozePicker; Snoozed view; cron wakes via process_message_timers(). Better than classic. | med |
| Sweep (bulk-delete/move by sender, recurring) | Moves/deletes all current+future from a sender (OWA). | partial | Mute + sender rules ('move_to') cover most intent; no one-click 'sweep keep latest / older than N'. (Not in classic anyway.) | low |
| Pin message to top of list | Keeps message at top of list. | have | pinnedAt field; MessageList separates pinned/unpinned with divider L61-62 + test. (Confirm pin toggle wiring in row/pane.) | low |
| Attachment indicator + open/save/download | Paperclip in list; chips in pane; Open/Save As/Save All. | have | Paperclip in MailRow; download chips in ReadingPane (/blobs/{sha256}). No 'Save All' bulk, no per-file Open/Save-As menu. | high |
| Attachment Preview (Office/PDF/images in pane) | Click to preview inside reading pane. | missing | Chips download only; no inline previewer. Files must be downloaded. | med |
| Inline/embedded images (CID, block external) | Inline images; blocks remote with prompt. | partial | CID → /blobs/{sha256} rewrite in sanitizedHTML; sandboxed srcdoc iframe. No 'remote images blocked by default + Download Pictures' toggle. | med |
| HTML vs Plain Text body toggle | View as HTML/plain; read-all-as-plain-text security. | have | htmlMode toggle in ReadingPane. No global 'read all as plain text' security setting. | low |
| MailTips (vacation/external/large-audience) | Inline tips when composing. | have | /auth/me/mailtips → HandleMailTips; debounced poll, banners. (Compose feature; listed for completeness.) | med |
| External sender / first-contact / spoof banner | Org [External] banner + safety tips. | have | EmailAnnotations → ExternalSenderBanner (isExternal/isNameSpoof/isFirstTime); display-name spoof detection. Stronger than classic. | high |
| Read receipts (request + send MDN) | Request on send; prompt to send when opening. | partial | Outbound MDN send (RFC 3798) + compose toggle exist. Inbound MDN auto-processing (sender-visible rollup) DEFERRED. | med |
| Voting buttons (respond to a poll) | Reader clicks; tallied vote response. | partial | Read-side vote buttons render + open a reply; no sender-side tally and likely no compose UI to set options. | low |
| Reply / Reply All / Forward (incl. inline quick reply) | From ribbon/pane; inline reply. | partial | Reply, Forward, inline quick-reply (5s cancel) present; NO distinct Reply All button in pane toolbar. | high |
| Recall This Message | Recall unread sent message from internal mailboxes. | have | recall.sql (trash unread internal copies, insert stub); POST /messages/{id}/recall 5-min window, toggle-gated. | med |
| Undo Send | Brief cancel window after Send. | have | undo_send reducer; UndoToast + 5s window. Exceeds classic. | med |
| Copilot — Summarize email/thread (read-side) | Summarize button condenses thread. | missing | Assist provider exists (shared/assist) but wired only into compose; no summarize in ReadingPane/inbox. Plumbing reusable. | med |
| Translate message (read-side) | Translate body / detect / always-translate-from. | partial | Translate exists only in compose runAssist('translate'); no inbound-message translate in pane. | low |
| Read Aloud (TTS of message) | Narrates with word highlighting. | missing | No TTS narration. | low |
| Immersive Reader (focus mode) | Distraction-free reading + a11y aids. | missing | Not implemented (app has reduced-motion fallbacks only). | low |
| Delay Delivery / scheduled send | Per-message held until a chosen time. | have | message_schedule; Scheduled view + EmailSubmission sendAt + cancel. (Compose; listed for parity.) | med |
| Keyboard-driven triage | Extensive shortcuts (Ctrl+R, Del, Ctrl+1..). | have | EMAIL_SHORTCUTS (j/k, r, e, delete, c). Gmail-style map ≠ Outlook (re-learn cost). | med |
| S/MIME signed/encrypted indicators | Lock/seal icons + security panel. | have | S/MIME badge (cryptoType/smimeVerifiedBy) in ReadingPane sender block. | low |
| Newsletter bundling + one-click Unsubscribe | No native bundling in classic; List-Unsubscribe not surfaced. | have | NewsletterBundle.svelte + newsletter_bundles.sql; POST /messages/{id}/unsubscribe. setjoin-only, beyond parity. | low |
| Move to Folder / drag-to-folder + picker | Move button/picker, drag, Always-Move-From-Sender. | partial | Tag-based: toggleTag/archive/trash + rule 'move_to'. No drag-to-folder, no 'always move from this sender' one-click from a message. | med |
| Group By / Arrange By / sort columns | Date/From/Size/Subject/Importance grouping + column sort. | missing | Sort fixed to receivedAt desc; no user-chosen grouping/sort. | low |

---

## Area 3 — Calendar

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Appointment vs Meeting distinction | New Appointment (no attendees) vs New Meeting (invites). | partial | is_meeting BOOL + attendee model; UI flips to meeting when any attendee added — no explicit choice / 'Invite Attendees' affordance. | high |
| Create / edit / delete event | Double-click/New to create; Delete (+cancellation if meeting). | have | saveEvent()/handleDelete(); jmap_calendar_event_set_create/_update/_destroy. | high |
| Day / Week / Work-Week / Month views | Day, Work Week, Week, Month, Schedule views. | partial | Month/Week/Day + Agenda. Missing dedicated Work-Week (Mon-Fri) and Schedule (timeline) views. | high |
| Schedule View (horizontal multi-calendar timeline) | Lane-per-calendar timeline. | missing | Only Month/Week/Day/Agenda; AvailabilityGrid is scheduling-dialog only, not a main view. | low |
| Today / navigate / go-to-date | Today, arrows, Date Navigator mini-month. | partial | prevPeriod/nextPeriod/goToday exist; no mini-month navigator, no go-to-date picker. | med |
| All-day events | All-day banner row. | have | form.allDay + allday render; all_day column. | high |
| Recurring events (patterns + custom) | Recurrence dialog: interval, BYDAY, end conditions; occurrence vs series. | partial | Full RFC-5545 RRULE storage + exception model + BYSETPOS; but webmail form only fixed dropdown (none/daily/weekly/monthly/yearly) — no interval/BYDAY/end/occurrence editor. | high |
| Edit this occurrence vs entire series | Prompts occurrence vs series. | partial | Data model supports per-occurrence exceptions (schema/046); CalendarApp has no occurrence-vs-series prompt — can't edit a single instance from web. | high |
| Reminders / event alarms (dismiss/snooze/sound) | Reminder dropdown + Reminders window. | partial | VALARM parsed/stored but explicitly NOT fired — no scheduler dispatches; event form has no reminder field. Daily-reliance gap. | high |
| Scheduling Assistant (free/busy grid) | Attendee free/busy bars; pick common slot; AutoPick. | partial | AvailabilityGrid + calendar_freebusy_multi + 'Find a time' → findFreeSlots. Wired flow is a simpler email-list dialog; full grid (room row/working-hours overlay) not in main composer; no AutoPick button. | high |
| AutoPick next available time | << / >> jumps to next all-free slot. | partial | Ranked mutual free slots exist (findFreeSlots), but no incremental <</>> stepper. | med |
| Meeting requests — send invites (iMIP) | Emails .ics METHOD:REQUEST. | have | calendar_itip.sql calendar_send_invite(); caldav/imip.go REQUEST email. | high |
| RSVP (Accept/Tentative/Decline) | Response email to organizer; status tracked. | have | jmap_calendar_event_rsvp() + calendar_process_itip_reply(); handleRsvp() buttons. | high |
| Response tracking (organizer view) | Tracking tab shows each attendee's status + summary. | have | event_attendees.status; jmap returns participationStatus; detail dialog renders per-attendee rsvp. No dedicated tracking summary tab/percentages. | high |
| Propose New Time (counter-proposal) | Recipient counter-proposes; organizer accepts COUNTER. | missing | caldav/itip.go parses MethodCounter but ProcessITIP logs 'not yet supported'; no UI. | med |
| Receive meeting request → tentative on calendar | Inbound REQUEST shows tentatively before response. | have | caldav/itip.go processRequest() creates tentative event (dedup + rate limit). | high |
| Meeting cancellation (organizer cancels) | Attendees get CANCEL; item removed/cancelled. | have | calendar_process_itip_cancel(); processCancel() verifies organizer. | high |
| Update meeting + send updates (sequence bump) | Editing prompts Send Update; attendees get revised time. | partial | sequence tracked + set_update works, but no explicit 'send update to attendees' (re-issue REQUEST + SEQUENCE) flow from editor. | high |
| Rooms & resources booking (room mailboxes) | Add room; auto-accept/decline by policy. | partial | resource_type + booking_policy + capacity; rooms in free/busy. NO reducer enforcing booking policy, no UI to add a room as resource attendee. | high |
| Room Finder (filter by building/capacity/floor/features) | Room Finder pane suggests rooms by availability. | missing | No RoomFinder.svelte (AGENTS.md references it = doc drift); no building/floor/feature metadata, no room-list grouping. | med |
| Calendar sharing & permission levels | Share with Reviewer/Author/Editor levels. | partial | calendar_acls (read/write/admin) + is_shared; jmap returns myRights. No webmail UI to grant/revoke, no granular Outlook levels (free/busy-only vs full). | high |
| Open another user's / shared calendar | Open Calendar > From Address Book. | missing | loadCalendars() only loads signed-in account (filters mailbox_id=p_account_id); no 'open other user calendar'. (Even though ACL grants exist.) | high |
| Delegate access (manage meetings on behalf) | Delegates receive/respond/create on manager's behalf. | partial | mailbox_delegates + delegated create enforced + 'Send on behalf of' Select. Missing: delegate responding to invites on behalf, delegate-management UI in calendar. | high |
| Overlay multiple calendars | Check multiple to overlay merged/color-coded. | partial | Sidebar checkboxes + visibleCalendarIds; owned calendars render merged/color-coded. Missing side-by-side and overlaying OTHER users' calendars. | med |
| Calendar Groups (saved sets, e.g. 'My Team') | Named groups of people's calendars. | missing | No calendar-group concept in schema/UI. | low |
| Color categories on events (+ filter) | Color categories on appointments; filter/color by category. | missing | calendar_events has NO categories column (mail/contacts/tasks do); event color only from parent calendar. | med |
| Private / confidential items | Mark Private; sharers see 'Private Appointment'. | missing | No CLASS field (only status + transp). Privacy gap once sharing lands. | med |
| Show As / Free-Busy status | Free/Tentative/Busy/OOF/Working Elsewhere. | partial | transp (free/busy) + status tentative; no OOF or Working-Elsewhere states, no 'Show As' selector on form. | med |
| Out-of-office / OOF calendar event | OOF event blocks time + optionally triggers auto-replies. | missing | No OOF-event type linking calendar to vacation/auto-reply; free/busy has no OOF status. | low |
| Working hours / work week config | Set work day start/end + work days; shade non-work. | partial | Working hours exist only as transient 'Find a time' inputs; not persisted, don't shade Day/Week views. | med |
| Dual / additional time zones | Second/third TZ column with labels + swap. | missing | TZ stored (VTIMEZONE round-trips for CalDAV); UI shows single local gutter only. | low |
| Per-event time zones (start vs end) | Distinct start/end TZ. | missing | Single timezone column; no separate start/end TZ. | low |
| Teams / Skype / online-meeting add | One-click join link + dial-in. | partial | meeting_url plumbed through invites; no UI toggle, no integrated conferencing provider. Needs future meetings product. | med |
| Email a calendar / send as iCal | Share a date range as .ics summary. | partial | Invite emails carry .ics + ICS import; no 'email my calendar for a date range' export-to-mail. | low |
| Publish calendar / ICS subscription | Publish to URL or subscribe to internet calendar. | partial | calendars.ical_feed_url column exists; no fetch/refresh job or subscribe/publish UI. | low |
| CalDAV access (external clients) | Standards equivalent for 3rd-party clients. | have | internal/caldav/ (PROPFIND/REPORT/PUT/GET/DELETE/MKCALENDAR, free-busy, VTIMEZONE); feature.caldav. | med |
| Holidays (country/region sets) | Add Holidays imports holiday events. | missing | No holiday import/seed/UI. Could be a subscribable ICS feed later. | low |
| Weather bar (3-day forecast) | Forecast strip atop calendar. | not-needed | Deliberate non-goal for air-gap-capable on-prem (would phone home). | low |
| Bookings (public scheduling pages) | Public self-service booking pages. | missing | Separate M365 product; not present. | low |
| FindTime / poll-style time voting | Propose slots; attendees vote. | missing | No poll/voting for meeting times. Add-in territory; scheduling assistant instead. | low |
| Attendee roles: Required / Optional / Resource | Mark roles; affects tracking/scheduling. | partial | event_attendees.role CHECK + stored; CalendarApp form is flat comma-separated list (all default), no role picker. | med |
| Attach files / link items to an event | Insert > Attach File on meeting. | missing | events have description/url but no attachment linkage in model/UI. | low |
| Forward a meeting / add attendees after | Forward sends invite to more people. | missing | No forward-meeting action; attendees only at create/edit. | low |
| Reading/preview of meeting details | When/where/organizer/attendees/notes/recurrence. | have | detail Dialog renders When/Where/Notes/Organizer/Attendees/Repeats. | med |
| Search calendar events (text / date range) | Instant Search over items. | have | jmap_calendar_event_query supports text/before/after/inCalendar; UI uses range queries but no free-text search box surfaced. | med |
| Drag-to-move / resize; click-to-create | Drag to reschedule/resize; click slot to create. | partial | Click-empty-slot-to-create works; NO drag-to-move/resize — rescheduling needs the editor. | med |
| Real-time calendar push (state + notify) | Exchange pushes changes; invites appear without refresh. | have | jmap_*_state + pg_notify('calendar:...'); CalendarApp websocket refreshes. | med |
| Multiple personal calendars (create/color/rename/delete) | Several calendars with distinct colors. | partial | set_update updates name/color/tz; sidebar lists+colors. NO create-new / rename / delete controls in webmail. | med |

---

## Area 4 — Contacts / People / Address Book

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Create / edit / delete personal contact | Full New Contact form; Save & Close. | have | ContactsApp.svelte CRUD modal; jmap_contact_set_create/update/destroy. UI form omits addresses/URLs/IMs though DB+JMAP support them. | high |
| Multiple personal address books / contact folders | Several Contacts folders. | have | addressbooks table + jmap_addressbook_get/set_*; sidebar lists $addressBooks. Sidebar exposes no create/rename UI. | med |
| Address Book order / name-resolution order | Choose default + search order of multiple books. | missing | No ordering/priority field; GAL vs personal is a manual toggle, not a configurable order. Niche. | low |
| Global Address List (GAL) — browse/search directory | All org users searchable in Address Book + picker. | have | gal_search() reducer; LDAP GAL; 'Company Directory (GAL)' toggle; compose galSearch() picker. Read-only org directory. | high |
| GAL detailed property card (manager, reports, org) | General/Organization/Phone/Member Of tabs + reports tree. | partial | Org tree exists (directory_browse.sql, OrgChart.svelte) but per-person GAL modal shows basic fields only — no manager/direct-reports 'Member Of' card. | med |
| Add GAL entry to personal Contacts | Right-click > Add to Contacts. | have | importFromGAL() → createContact() with 'Add to Contacts' in GAL detail modal. | med |
| Personal contact group / distribution list (user-created) | Named list of members addressed as one recipient. | missing | No personal contact-group model. distribution_groups are admin/SCIM org DLs, not user-created. No group/membership table in contacts schema. Daily-driver gap. | high |
| Org / admin distribution groups | Admin-managed DLs in GAL; expandable. | have | distribution_groups via scim_upsert_group.sql; deliver_group_vacation.sql; admin console. (Distinct from personal groups.) | med |
| Contact photo | Add Picture; shown on card + messages. | have | handlePhotoUpload → uploadBlob; avatar_sha256; vcard.go PHOTO. | med |
| Contact card detail view | Read-only card with all fields + actions. | have | detail Dialog renders name/company/title/dept/emails/phones/notes. Omits addresses/URLs/IMs/birthday/anniversary/categories though stored. | med |
| Business Card view / EBC (card image) | Designed card layout, customizable, insert in signatures. | not-needed | Legacy Outlook artifact; vCard interchange covers the real need. | low |
| Per-contact certificates (S/MIME public keys) | Certificates tab stores recipient encryption cert. | missing | contacts has no cert/KEY column; vcard.go parses no KEY. Gated on per-recipient S/MIME-from-contact scope. | low |
| Auto-Complete / nickname cache (typed-address suggestions) | Recently-used addresses while typing; X to remove one. | partial | onGalInput() suggests from GAL only; contactRanking.ts records frequency in localStorage but not wired as typed-address autocomplete; no per-entry remove. Missing past-recipient cache + personal-contacts source. | high |
| Contact frequency ranking for suggestions | Weights by how often/recently you mail. | partial | contactRanking.ts recordSend/getSendCount/rankContacts exists but not applied to live compose GAL suggestions. | med |
| Search contacts | Instant search by name/company. | have | search box; jmap_contact_query text filter + trigram index. | high |
| Sort / view contacts (name/company/recent; list vs card) | People/Business Card/Card/Phone/List views; multiple sorts. | partial | list/grid toggle; backend always ORDER BY display_name. No selectable sort key, no Phone/List column views. | low |
| Import contacts from CSV | Import/Export wizard with field mapping. | missing | No CSV import (ContactsApp importVCard() only POSTs vCard to /carddav). No CSV parser in internal/. CSV is the dominant Outlook migration format. | high |
| Export contacts to CSV | Export all contacts to .csv. | missing | No CSV export; only vCard export via CardDAV. | med |
| Import / export vCard (.vcf) | Import a .vcf; save/forward a contact as vCard. | have | carddav/vcard.go parseVCard/contactToVCard (FN/N/EMAIL/TEL/BDAY/ADR/PHOTO/CATEGORIES); importVCard() → /carddav/{ab}/import. | med |
| CardDAV sync (3rd-party apps) | Interop equivalent (no native Outlook EAS). | have | carddav/ reads/writes same contacts tables. Bonus over Outlook (Apple/Thunderbird). | low |
| Linked contacts (merge entries for one person) | People view links GAL+personal+social; manual Link/Unlink. | missing | No link/merge model; independent rows keyed by vcard_uid. | low |
| Find / merge duplicate contacts | Detects dupes on import; manual merge. | missing | Create always inserts a new row; no detection/merge. Matters during CSV/vCard import. | med |
| People pane in reading pane (sender card + shared items) | Sender photo/details/recent mail/attachments. | missing | No people/contact-card surface in reading pane. Could be a future 'sender card on hover'. | low |
| Favorite / pin contacts | Add to Favorites pins to a group/nav bar. | missing | No is_favorite flag; no favorites grouping. | low |
| Categorize / color-category a contact | Color categories for grouping/filtering. | partial | contacts.categories TEXT[] + GIN index + JMAP carry; ContactsApp form/detail has no categories UI. | low |
| Follow-up flag / reminder on a contact | Flag a contact with a reminder. | missing | No flag/reminder field on contacts. | low |
| Forward a contact (as Outlook contact / vCard) | Attach contact as .vcf to an email. | missing | No 'forward/share contact' action; compose has no attach-contact-as-vCard helper. (Server can emit vCard — cheap to wire.) | low |
| Map It (open mailing address on a map) | Opens address in a maps service. | not-needed | Requires external maps service; conflicts with on-prem/air-gap goal. | low |
| Call / IM / start meeting from a contact (presence) | Card quick actions: email/call/IM/schedule. | missing | No presence integration or quick-action bar (only Edit/Delete/Add-to-Contacts). Depends on chat/meeting module. | low |
| Shared / delegated contacts folder | Open another user's / shared mailbox's contacts. | partial | addressbooks.is_shared + jmap exposes isShared/myRights; mailbox_delegates exists. No UI to open another user's address book. | med |
| Birthday / anniversary (auto-add to calendar) | Fields auto-create recurring calendar events. | partial | contacts.birthday/anniversary columns + JMAP + vCard BDAY/ANNIVERSARY. No UI field, no auto-calendar-event creation. | low |
| Directory / org-chart browse by department | GAL Organization view approximation. | have | directory_browse.sql; DirectorySidebar/DirectoryMemberList/OrgChart; directory mode toggle. Exceeds Outlook. | low |
| MailTips (recipient warnings in compose) | Inline tips when adding recipients. | have | ComposeScreen fetchMailTips() → /auth/me/mailtips. (Coverage of tip types not audited here.) | med |

---

## Area 5 — Tasks / To-Do / Notes / Journal

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Create a basic task (subject, notes) | New Task; appears in Tasks/To-Do Bar/Daily Task List. | have | TasksApp.svelte New-task dialog; jmap_task_set_create; 012_tasks.sql. Full CRUD via Task/set. | high |
| Task start date & due date | Start + Due fields; overdue in red. | partial | Only single due_at — no separate start date. Overdue highlighting present. | high |
| Task status (5 values) | Not Started/In Progress/Completed/Waiting/Deferred. | partial | 4 statuses (needs-action/in-progress/completed/cancelled); no Waiting/Deferred. Close enough. | med |
| % Complete field | Spinner; 100%→Completed, 1-99%→In Progress. | missing | No percent_complete column. Status discrete only. | low |
| Task priority (Low/Normal/High) | Priority dropdown; High = red. | have | priority 0-9; priorityLabel/Color (None/Low/Medium/High) + dot. 4 levels vs 3. | med |
| Mark task complete (checkbox / button) | Click checkbox or Mark Complete; strikethrough. | have | kanban 'Done' + moveStatus; auto-sets completed_at. No inline list checkbox (use kanban/dropdown) — minor UX gap. | high |
| Recurring task (+ regenerate after completion) | Recurrence dialog; regenerate N days after complete. | partial | rrule column + stored via set_create/update — STORED ONLY; no UI to set recurrence, no engine regenerates next occurrence. Inert. | med |
| Skip occurrence (recurring task) | Advances to next due without completing. | missing | No recurrence engine; rrule never expanded. | low |
| Subtasks / task hierarchy | Classic has none (To Do has steps). | have | parent_id self-FK; jmap 'hasParent'; subtasks (Phase 11). Exceeds classic. | low |
| Task reminder (pop-up at set time) | Reminder checkbox + date/time; Reminders window. | partial | reminder_at stored + in form, but NO cron scans it (cron/tasks.go has no reminder processor) — never fires. Real gap. | high |
| Reminders window (Dismiss/Dismiss All/Snooze, tasks+appts) | Single window aggregating due reminders. | missing | No reminders-window component; no reminder-firing cron. Daily-driver feature. | high |
| Assign task to another person | Assign Task emails request; accept/decline; ownership transfers. | partial | assignee_user_id FK + assigneeEmail/Name read-only in detail. NO assign UI, NO task-request email, NO accept/decline, NO ownership transfer. | med |
| Send status report / keep updated copy | Status-report + keep-updated checkboxes; %sync; completion email. | missing | No status-report/task-update messaging. Depends on email-based delegation (absent). | low |
| Flag an email for follow-up (Today/Tomorrow/Week/Custom) | Flag with due-date presets; flagged mail → task. | partial | Only boolean $flagged star — no due date, no presets, no reminder, flagged email is NOT a task. Core GTD workflow missing. | high |
| Add reminder to a flagged email | Right-click flag > Add Reminder; pops at time. | missing | No flag-with-reminder; flag is boolean. Requires due-dates + reminder engine (both absent). | med |
| Mark Complete / Remove from List on flagged email | Clear flag removes from list; Mark Complete leaves check. | missing | Flagged mail isn't a task; only un-star. N/A until flagged-mail-as-task exists. | low |
| Convert / drag an email to Tasks | Drag email to Tasks (or Quick Step); carries body. | missing | linked_message_id column + linkedMessageId exist but NO UI wires email→task. Plumbing without UI. | med |
| To-Do Bar (right pane: tasks + flagged + events) | Persistent aggregated pane. | missing | No To-Do-Bar; Tasks live only in /tasks PimShell. | med |
| Daily Task List in Calendar | Strip under day/week showing tasks due that day. | missing | No task strip; CalendarApp not integrated with tasks. | low |
| Task views (Simple/Detailed/Active/Next 7 Days/Overdue/Completed/By Category) | View presets + grouping. | partial | kanban + list + status filter + text search + overdue styling, but not the named Outlook presets / By-Category grouping. | low |
| Search / filter tasks | Instant Search + view filters. | have | searchText → jmap_task_query text ILIKE + statusFilter. | med |
| Categorize tasks (color categories) | Color categories; group/filter. | partial | tasks.categories TEXT[] + chips UI, but NO color, no shared master category list across apps. | low |
| Link task to a calendar event | Not first-class in Outlook (surface in calendar). | have | tasks.linked_event_id FK + linkedEventId in get/set. Mild superset. | low |
| Notes module (sticky notes, searchable, categorized) | Notes folder of color sticky notes. | not-needed | No Notes module; Microsoft itself steers to OneNote. Deliberate non-goal. (ask if product wants parity.) | low |
| Journal (activity log / time tracking) | Journal timeline; manual entries + timer; auto deprecated 2013. | not-needed | Deprecated by MS since 2013; setjoin's journal.sql is compliance archiving, not personal Journal. Deliberate non-goal. | low |
| Microsoft To Do / My Day integration | Tasks sync with To Do app; My Day planner. | not-needed | Proprietary MS cloud; no equivalent on-prem. setjoin Tasks is the native store. | low |
| Real-time sync / push of task changes | Tasks sync across devices instantly. | partial | jmap_task_changes is a STUB (always empty); jmap_state bumps but no pg_notify for tasks. Reload-based only. | med |
| Print a task / task list | File > Print (Table/Memo). | missing | No print affordance; browser print only, no task layout. | low |
| Read Aloud / narration of a task | Read Aloud narrates the item. | not-needed | OS/browser screen readers cover narration; TasksApp has ARIA roles/keyboard. | low |

---

## Area 6 — Accounts / platform / AI / compliance

| Feature | Outlook Classic behavior | setjoin status | Evidence / notes | Priority |
|---|---|---|---|---|
| Multiple accounts in one profile (Exchange/IMAP/POP/M365) | One profile holds many mailboxes in a single tree. | partial | jmap_identity.sql (primary + aliases); From-select. Single-tenant-per-login; identities can't be created via JMAP (set_create no-op); no external-account aggregation in one SPA session. | med |
| Mail profiles (multiple Outlook profiles, prompt-for-profile) | Control-Panel Mail applet manages named profiles. | not-needed | MAPI/Win32 artifact; web session per identity replaces it (re-login / alias switch). | low |
| Automatic Replies / Out of Office (server-side, internal vs external, date-bounded) | Server-side auto-reply, date range, inside vs outside org. | partial | Backend solid: deliver_group_vacation.sql (start/end, only_contacts, per-sender dedup). NO webmail settings page (no vacation/OOO route), no separate internal/external bodies. High-priority self-service gap. | high |
| Mailbox delegation — Send As / Send on Behalf | Delegates send-as or on-behalf-of; From offers the address. | have | V007 get_mailbox_delegates() (send_as/send_on_behalf/full_access); From-select iterates delegates. Verify outbound stamps Sender vs From per tier. | high |
| Shared mailboxes (full-access, auto-mapping, send-as) | Shared mailboxes appear in folder list for Full Access. | have | Phase 6 shared mailboxes; mailbox_effective_type.sql derives 'shared' (V076). Confirm sidebar surfaces it (auto-mapping). | high |
| Public folders | Org-wide shared Public Folder hierarchy. | not-needed | Legacy Exchange; MS itself steers off it. Shared mailboxes + DLs + shared calendars cover the modern case. | low |
| Online Archive (In-Place Archive) + auto-archive movement | Second archive mailbox node; MRM moves aged items. | not-needed | S3 tiering replaces a user-visible second mailbox (features.md). Explicit design choice (vs All-Mail tag). | low |
| Retention policies / MRM (tags, default delete/archive) | Retention tags shown per folder/item; users apply personal tags. | partial | retention.sql tag_retention()/enforce_retention(); admin retention UI. Missing: user-applied personal retention tags + per-item tag/expiry display in the client. | med |
| Litigation / Legal Hold | Admin preserves all items invisibly; blocks purge. | have | mailboxes.litigation_hold + trg_messages_hold_check (BZ015) + per-message admin_ediscovery.go HoldSelected(); retention respects holds. | med |
| eDiscovery / Content Search (KQL, cases, export) | Cross-mailbox search, cases, holds, export. | have | admin_ediscovery.go (KQL StartSearch/Hold/Export MBOX) + cases CRUD; /admin/ediscovery + /admin/content-search. PST export returns 501 (partial only for PST format). | med |
| Instant Search (in-folder / all-mailbox keyword) | Indexed keyword search + recent-search recall. | have | pg_search BM25 (CJK ICU); parseSearch text/from:/tag: operators. CJK tokenization is a real edge. | high |
| Advanced Find / Query Builder (multi-field, AND/OR, save as Search Folder) | Field-by-field criteria + Query Builder + save as Search Folder. | partial | Token operators only; no visual multi-field builder, no saved Search Folders. KQL exists but is an admin tool. Power-user gap. | med |
| Cached / Offline Exchange Mode (OST, OAB, work offline) | Local replica + OAB; works fully offline. | partial | mail-core (JMAP+SQLite cache) DEPRECATED per web-first unification; webmail offline/PWA deferred. No committed offline story today. Laptop-on-flaky-network gap. | med |
| Autodiscover / account auto-setup | Finds server settings from email; email + password only. | have | auto-discovery login flow designed/documented. For 3rd-party clients verify Autodiscover/autoconfig XML endpoints are served. | med |
| COM add-ins (legacy VSTO/native) | Win32 COM/VSTO add-ins extend ribbon + items. | not-needed | No COM analog in a web SPA; MS deprecating COM in favor of web add-ins. | low |
| Web add-ins (Office.js task panes) + marketplace | Office.js task-pane/command add-ins; add-in store. | missing | No Office.js host, manifest loader, or marketplace. (See ask row: is 3rd-party extensibility in scope at all?) | low |
| Ribbon & Quick Access Toolbar customization | Add/remove/reorder ribbon tabs + pin commands. | not-needed | SPA shell is intentionally fixed; no per-user chrome-customization model. | low |
| Copilot — summarize thread | Summarize button condenses thread with citations. | partial | POST /assist/complete over shared/assist, gated feature.assist; admin config + AssistDrawer. No dedicated 'summarize this thread' action in reading pane — prompt scaffolding is the missing piece, not transport. | med |
| Copilot — draft email from prompt | Draft with Copilot generates body; tone/length controls. | partial | Compose assist panel (M4) calls /assist/complete; outbound assist HTML sanitized. Tone/length presets + polished 'Draft with Copilot' UX not confirmed. | med |
| Copilot — Coaching (tone/clarity/sentiment) | Reviews draft; suggests tone/clarity improvements. | missing | No coaching-specific prompt; only generic complete. Achievable as a prompt template; not shipped. | low |
| Copilot — Meeting recap / prep brief | Pre-meeting brief + post-meeting recap from mail/cal/files. | missing | No meeting-recap/prep; no transcription pipeline. Depends on a meetings product setjoin lacks. | low |
| Copilot — Chat / Q&A over mailbox | NL questions across mail/calendar. | missing | /assist/complete takes context but no retrieval/RAG over the mailbox; no grounded Q&A. Plumbing exists, grounding does not. | low |
| Accessibility Checker (compose-time a11y lint) | Flags missing alt text/contrast/reading order in the email. | missing | No a11y-checker in compose (only UI-level a11y). Niche authoring aid. | low |
| Screen reader / Narrator support (ARIA) | Full Narrator/JAWS/NVDA across the client. | partial | focus-rings, ARIA roles (GAL combobox), reduced-motion fallbacks. No published VPAT / external audit. 'partial' until conformance verified end-to-end. | med |
| Read Aloud (TTS of a message) | Speaks selected message with word highlighting. | missing | No TTS in reading pane. Browser SpeechSynthesis could provide cheaply. | low |
| S/MIME (sign/encrypt, cert management, Trust Center) | Per-message/default Sign/Encrypt with X.509; read signed/encrypted. | have | Server-side fully implemented (smime.go CMS sign/encrypt/verify/decrypt; outbound.go; recipient certs from DB/LDAP); admin + self-service cert upload. A1: per-message **Sign** + **Encrypt** toggles both wired in compose More panel. | med |
| Office/Purview Message Encryption (OME, Do-Not-Forward to anyone) | Encrypt-Only/DNF/RMS templates without recipient certs. | not-needed | OME is Azure-RMS-bound; setjoin uses S/MIME (open standard) + at-rest encryption by design. (ask-adjacent if a customer demands recipient-agnostic encrypt+DNF.) | low |
| Delay Delivery / scheduled send | Per-message future send; waits in Outbox. | have | scheduledAt/scheduleMode/scheduleOptions (B2); send.sql. Server-side — strictly better than client-dependent classic delay. | high |
| Recall This Message | Delete already-sent message from recipients' mailboxes. | have | recall.sql recall_message() (find unread internal by Message-ID, trash, stub); POST /messages/{id}/recall; + 5-min Undo Send. Strong parity. | high |
| Voting buttons (Yes/No/Maybe poll, tracked) | Poll buttons; aggregated responses in Tracking. | missing | No voting/poll in compose or backend. Proprietary; rarely a migration blocker. | low |
| Read & Delivery Receipts (MDN request + tracking) | Request receipt; recipient MDN; sender Tracking tab. | partial | RECEIVING side wired: HandleReadReceipt + send_read_receipt sends MDN (RFC 3798) on open (handler.go L2294). Missing: compose request-a-receipt checkbox + sender Tracking view. (CLAUDE.md 'B7 MDN deferred' note is stale — flag to owner.) | med |
| Rules & Alerts wizard (client+server) | Condition/action builder; server rules run without client. | have | rule_engine_or.sql (eval/apply, OR grouping, run_on); settings/rules + admin templates. Confirm action coverage matches Outlook (move/forward/flag/category). | high |
| Mobile / ActiveSync (EAS) parity | EAS syncs mail/cal/contacts/policy + remote wipe to phones. | partial | ActiveSync explicitly dropped (replaced by JMAP). Native iOS/Android over JMAP + MAM (remote wipe/lock) cover the intent — not the EAS wire protocol. Gap only if customers must use stock OS mail clients via EAS. | med |
| Add-in / extensibility ecosystem (product decision) | Add-in ecosystem (CRM/ticketing/e-sign panes) is core value for many orgs. | ask | No extensibility host today. Decide whether 3rd-party extensibility (Office.js-style panes or webhook/app model) is in scope, or whether assist + rules + transport pipeline is the ceiling. | low |
