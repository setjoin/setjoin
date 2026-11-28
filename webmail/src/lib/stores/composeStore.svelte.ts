// ComposeStore — the compose surface's draft-content state owner (Svelte 5 $state
// rune class, instantiated per mount — NOT a singleton).
//
// Slices 1 + 4 of the A6 ComposeScreen extraction:
//   - Slice 1: the draft-content group (addressing/subject/body/attachments/
//     signature/schedule/priority/S-MIME fields + `mailboxes`) + the pure-ish
//     helpers that read only those fields (`parseAddrList`, `getDraftsId`/
//     `getSentId`, `getBodyHTML`/`getBodyText`, `buildMsg`).
//   - Slice 4: GAL / recipient-autocomplete + mailtips (the `gal*` combobox
//     state + `mailtipsWarnings`, and `onGalInput`/`pickContact`/`pickGroup`/
//     `fetchMailTips`/… — the recipient-writing methods live here because they
//     mutate the store-owned to/cc/bcc/replyTo). Debounce timers are private +
//     cleared by `teardown()` (the component's onDestroy calls it).
//   - Slice 3: attachment upload — `uploading`/`uploadErrors` + `handleFiles`
//     (returns the over-cap-SKIPPED names so the VIEW toasts them; the store
//     imports no toast/i18n) + `removeAttachment` + the `MAX_ATTACH_BYTES` const.
//     WAVE-5 #2 extends this to inline body images: `stageInlineImage` reuses
//     the same #uploadOne machinery (an inline row is just a `ComposeAttachment`
//     with `inline: true`), so uploading/failedUploads/attachmentBytes and the
//     Send gate cover it for free; `buildMsg` rewrites its `blob:` preview URL to
//     `cid:` and adds the `{cid, disposition:'inline'}` attachment entry.
//     `pruneOrphanedInlineImages` drops the row if its <img> is deleted from
//     the body directly (RichTextEditor never owns store state — see the
//     editor-seam note below).
//   - Slice 2a: draft autosave — `draftSaving`/`draftSaved`/`draftSaveError` +
//     `editingDraftId` (the draft lifecycle id, shared with the still-in-component
//     send path) + `saveDraft(editor, userEmail)`.
//   - Slice 2b: `buildSubmission` — the pure core of handleSend (the
//     EmailSubmission envelope + scheduled-send + tag-on-send + S/MIME intents),
//     now unit-testable. The rest of `handleSend` (i18n/toast/undo-timer/meeting/
//     view-actions) stays in the component pending a deliberate view/logic split.
// The component instantiates one `new ComposeStore()`, binds the template to
// `compose.*`, and keeps the rest (send/draft/attachment-upload/signature-load/
// UI-toggle logic + the $effects) — later slices continue the extraction.
//
// Editor seam (arch-A3 echo-loop hazard): the RichTextEditor's `content` prop is
// read ONCE at mount; body writes/reads go IMPERATIVELY through the editor handle.
// This store does NOT own the `bind:this` ref — the body-reading methods take the
// editor handle as a PARAMETER (`getBodyHTML(editor)` / `getBodyText(editor)` /
// `buildMsg(editor, …)`), so the seam stays explicit at every call site and the
// store carries no editor lifecycle.

import { get } from 'svelte/store';
import { sanitizeOutboundHTML } from '$lib/sanitize';
import { galSearch, sha256Hex, putBlob, loadSession, emailGet } from '$lib/jmap/client';
import { emailSet, emailSubmissionSet } from '$lib/jmap/offline-client';
import { mailDraftOpen, mailDraftReplace, type MailDraftSession } from '$lib/mail/mailDraft';
import { suggestRecipients, removeRecipient, recordSend } from '$lib/utils/contactRanking';
import type { RecipientSuggestion } from '$lib/utils/contactRanking';
import { contactGroups, expandGroup } from '$lib/stores/contactGroups';
import type { Mailbox, EmailAddress, ContactCard, ContactGroup } from '$lib/types/jmap';

/** Client-side attachment cap — mirrors the send reducer's 25 MiB server cap. */
export const MAX_ATTACH_BYTES = 26214400;

/** WAVE-5 #2: mime whitelist for an inline body image (paste/drag/toolbar-upload).
 *  SVG is deliberately excluded — it is script-bearing and the compose preview
 *  is NOT sandboxed, so a pasted/dropped SVG falls through to the ordinary
 *  file-attachment path instead of being inlined into the body. */
export const INLINE_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

type ComposePriority = 'high' | 'normal' | 'low';

function priorityValue(priority: ComposePriority): number {
	if (priority === 'high') return 1;
	if (priority === 'low') return -1;
	return 0;
}

/** Minimal shape of the RichTextEditor handle the store reads body content through. */
export interface EditorHandle {
	getHTML(): string;
	getText(): string;
}

/** A user signature row as returned by `/settings/signatures`. */
export interface ComposeSignature {
	id: number;
	alias_email: string;
	signature_html: string;
	signature_text: string;
	is_default: boolean;
	default_for: 'new' | 'reply' | 'both' | 'none';
}

export interface ComposeHydrationTicket {
	generation: number;
	fingerprint: string;
}

/** Per-chip upload lifecycle (WAVE-5 #3). Absent status (prefilled/restored
 *  attachments, forward hand-offs) means 'done'. */
export type UploadStatus = 'preparing' | 'uploading' | 'done' | 'failed';

/** A staged attachment reference (uploaded, or upload in flight). */
export interface ComposeAttachment {
	name: string;
	size: number;
	/** SHA-256 blob id — '' until the pre-upload hash completes. */
	blobId: string;
	type: string;
	status?: UploadStatus;
	/** 0–100 while uploading; 100 when done. */
	progress?: number;
	/** Chip identity for the in-flight abort/retry bookkeeping. */
	uploadId?: string;
	/** WAVE-5 #2: true for an inline body image (paste/drag/toolbar-upload) — it
	 *  shares the upload/budget/gate machinery with file attachments below but is
	 *  excluded from the file-attachment chip list (it renders inline in the body
	 *  instead) and carries a stable Content-ID + the live preview URL used to
	 *  find/rewrite its <img> tag at submit time. */
	inline?: boolean;
	/** Content-ID (bare token, no angle brackets — the assembler adds those). */
	cid?: string;
	/** The `blob:` object URL inserted as the <img src>; used to rewrite the tag
	 *  to `cid:` at submit time and to prune the row if the image is deleted
	 *  from the body directly (backspace). */
	previewUrl?: string;
}

/**
 * Thrown by createAndSubmit when EmailSubmission/set reports a notCreated marker
 * (S/MIME sign/encrypt failures etc.). The store never localizes — the view maps
 * `.code` to a message (and NAMES `.addresses` for the encrypt-no-cert case),
 * never rendering the raw server description.
 */
export class SubmissionMarkerError extends Error {
	constructor(
		public code: string | undefined,
		public addresses?: string[]
	) {
		super(code ?? 'send_failed');
		this.name = 'SubmissionMarkerError';
	}
}

export class ComposeStore {
	#hydrationGeneration = 0;
	// ── Draft-content $state (the addressing/subject/body group formerly in
	//    ComposeScreen.svelte) ──
	fromEmail = $state('');
	to = $state('');
	cc = $state('');
	bcc = $state('');
	replyTo = $state('');
	subject = $state('');
	bodyHtml = $state('');
	bodyText = $state('');
	categories = $state<string[]>([]);
	newCategory = $state('');
	attachments = $state<ComposeAttachment[]>([]);
	signature = $state('');
	useSignature = $state(true);
	signatures = $state<ComposeSignature[]>([]);
	selectedSignatureId = $state<number | null>(null);
	scheduledAt = $state('');
	readReceipt = $state(false);
	voteOptions = $state<string[]>(['']);
	voteResponse = $state('');
	useVoting = $state(false);
	priority = $state<ComposePriority>('normal');
	sensitivity = $state<'normal' | 'personal' | 'private' | 'confidential'>('normal');
	sendTags = $state<string[]>([]);
	plainTextOnly = $state(false);
	smimeEncrypt = $state(false);
	smimeSign = $state(false);
	mailboxes = $state<Mailbox[]>([]);
	/** #13 shared-mailbox use-surface: the delegated mailbox's accountId when
	 *  composing FROM a shared-mailbox workspace (compose.ts opts.accountId).
	 *  Null = personal (the module-singleton accountId in jmap/client.ts). */
	sharedAccountId = $state<string | null>(null);
	sharedDraftsEnabled = $state(false);

	// ── GAL / recipient autocomplete + mailtips (slice 4) ──
	galError = $state(false);
	galQuery = $state('');
	galResults = $state<ContactCard[]>([]);
	galTarget = $state<'to' | 'cc' | 'bcc' | 'replyTo'>('to');
	galShow = $state(false);
	galActive = $state(-1);
	cacheSuggestions = $state<RecipientSuggestion[]>([]);
	groupSuggestions = $state<ContactGroup[]>([]);
	mailtipsWarnings = $state<any[]>([]);
	// ── DLP policy tip (compose dry-run of send-time DLP, mirrors mailtips) ──
	dlpTip = $state<{ violated: boolean; policyId?: number; policyName?: string; action?: string; reasonKind?: string }>({ violated: false });
	// Debounce handles — plain (non-reactive) fields; cleared in teardown().
	#galTimer: ReturnType<typeof setTimeout> | null = null;
	#mailtipsTimer: ReturnType<typeof setTimeout> | null = null;
	#dlpTimer: ReturnType<typeof setTimeout> | null = null;
	#dlpSeq = 0;

	// ── Attachment upload state (slice 3, reworked WAVE-5 #3) ──
	// Per-chip lifecycle lives ON the attachment rows; these are the derived
	// aggregates the view gates on. The current-batch counters drive the
	// "Uploading N of M…" send-gate copy and reset when the batch drains.
	batchDone = $state(0);
	batchTotal = $state(0);
	/** True while any chip is hashing or uploading — gates Send. */
	uploading = $derived(
		this.attachments.some((a) => a.status === 'preparing' || a.status === 'uploading')
	);
	/** Names of chips whose upload failed (retry per chip; Send blocked). */
	failedUploads = $derived(
		this.attachments.filter((a) => a.status === 'failed').map((a) => a.name)
	);
	// Non-reactive in-flight bookkeeping, keyed by uploadId. #files also backs
	// per-chip retry (a failed chip re-uploads the original File).
	#files = new Map<string, File>();
	#aborts = new Map<string, AbortController>();
	#nextUploadId = 0;

	// ── Draft autosave (slice 2a) ──
	draftSaving = $state(false);
	draftSaved = $state(false);
	draftSaveError = $state(false);
	// The id of the draft being edited. Personal drafts retain the legacy
	// destroy/recreate flow; shared drafts are retargeted atomically by the
	// reducer while this stable collaboration session remains constant.
	// Shared with the send path (handleSend, still in the component until its own
	// slice) — it belongs here with the draft lifecycle it drives.
	editingDraftId = $state<string | null>(null);
	sharedDraftSession = $state<MailDraftSession | null>(null);
	sharedDraftReadOnly = $state(false);
	sharedDraftConflict = $state(false);
	#draftSaveErrorTimer: ReturnType<typeof setTimeout> | null = null;

	// ── $derived ──
	/** Total size in bytes of the staged attachments. */
	attachmentBytes = $derived(this.attachments.reduce((n, a) => n + a.size, 0));

	// ── Pure helper: address-list parsing ──
	parseAddrList(s: string): EmailAddress[] {
		return s
			.split(',')
			.map((e) => e.trim())
			.filter(Boolean)
			.map((e) => {
				const match = e.match(/^(.*?)\s*<(.+?)>$/);
				if (match) return { name: match[1].trim(), email: match[2].trim() };
				return { email: e };
			});
	}

	// ── Mailbox lookups (read `mailboxes`) ──
	#systemMailboxId(role: string): string | null {
		const candidates = this.mailboxes.filter((m) => m.role === role);
		// Mailbox/get intentionally includes delegated mailbox tags beside the
		// personal account's tags. A delegated folder can sort first, which makes
		// a personal draft target a foreign tag and fail as `mailboxIds empty`.
		// The reducer marks send-capable delegated rows with maySubmit=true.
		const preferred = this.sharedAccountId
			? candidates.find((m) => m.myRights?.maySubmit === true)
			: candidates.find((m) => m.myRights?.maySubmit !== true);
		return preferred?.id ?? candidates[0]?.id ?? null;
	}

	getDraftsId(): string | null {
		return this.#systemMailboxId('drafts');
	}

	getSentId(): string | null {
		return this.#systemMailboxId('sent');
	}

	// ── Body reads through the editor seam (handle passed in — see header note) ──
	getBodyHTML(editor: EditorHandle | null): string {
		return this.bodyHtml || editor?.getHTML() || '';
	}

	getBodyText(editor: EditorHandle | null): string {
		return this.bodyText || editor?.getText()?.trim() || '';
	}

	// ── Build the JMAP Email/set create object from the draft fields ──
	// `userEmail` is the caller's session email (a component $derived off the auth
	// store); it is only the `from`-address fallback when `fromEmail` is empty, so
	// it stays a parameter rather than coupling the store to the auth store.
	buildMsg(editor: EditorHandle | null, userEmail = ''): Record<string, unknown> {
		const bodyTextVal = this.getBodyText(editor);
		let bodyHTMLVal = this.getBodyHTML(editor);
		const draftsId = this.getDraftsId();

		// WAVE-5 #2: rewrite inline-image `blob:` object URLs to `cid:` references.
		// MUST run before sanitizeHTML below — DOMPurify's default URI allowlist has
		// no `blob:` scheme (it would strip the src entirely) but does allow `cid:`.
		// Only a DONE image still referenced in the CURRENT body qualifies: an
		// in-flight upload has no blobId yet (excluded, like a non-inline in-flight
		// attachment below), and one whose previewUrl no longer appears in the body
		// (the user deleted the <img> directly) is a stale row — skip it rather
		// than attach an orphan (pruneOrphanedInlineImages normally clears these
		// reactively, but buildMsg re-checks independently rather than trust that).
		const inlineDone = this.attachments.filter(
			(a) => a.inline && a.previewUrl && (a.status ?? 'done') === 'done' && bodyHTMLVal.includes(a.previewUrl)
		);
		for (const a of inlineDone) {
			bodyHTMLVal = bodyHTMLVal.replaceAll(a.previewUrl as string, `cid:${a.cid}`);
		}

		const msg: Record<string, unknown> = {
			from: [{ email: this.fromEmail || userEmail || 'unknown@unknown' }],
			to: this.parseAddrList(this.to),
			subject: this.subject,
			bodyValues: { text: { value: bodyTextVal, partId: 'text' } },
			textBody: [{ partId: 'text', type: 'text/plain' }],
			mailboxIds: draftsId ? { [draftsId]: true } : {},
			priority: priorityValue(this.priority),
			sensitivity: this.sensitivity !== 'normal' ? this.sensitivity : undefined,
			readReceiptRequested: this.readReceipt || undefined
		};

		if (this.cc) msg.cc = this.parseAddrList(this.cc);
		if (this.bcc) msg.bcc = this.parseAddrList(this.bcc);
		if (this.replyTo) msg.replyTo = [{ email: this.replyTo }];
		if (bodyHTMLVal && !this.plainTextOnly) {
			// Defense-in-depth: sanitize the outbound HTML independently of the
			// editor's runtime schema before it is persisted/sent to recipients.
			// Plain-text-only drops the HTML part entirely (recipients get text only).
			// C2: sanitizeOutboundHTML (allowRemoteImages=true), NOT the bare inbound
			// sanitizeHTML default — the user's own inserted remote images must survive.
			msg.bodyValues = {
				...(msg.bodyValues as object),
				html: { value: sanitizeOutboundHTML(bodyHTMLVal), partId: 'html' },
			};
		}
		if (this.scheduledAt) msg.scheduledAt = new Date(this.scheduledAt).toISOString();
		if (this.useVoting && this.voteOptions.some((v) => v.trim())) {
			msg.voteOptions = this.voteOptions.filter((v) => v.trim());
		}
		if (this.voteResponse) (msg as Record<string, unknown>).voteResponse = this.voteResponse;
		if (this.smimeEncrypt) msg.smimeEncrypt = true;
		// Staged (already-uploaded) attachments → the Email/set create object the
		// reducer reads at jmap_email_set_create (v_obj->'attachments' → message_attachments).
		// Omitting this silently drops every outbound attachment (regression the e2e
		// attachment round-trip caught). Shape = {blobId,name,type,size}; cid/disposition
		// default server-side.
		// Only fully-uploaded chips go on the message (absent status = prefilled/
		// restored = done). In-flight chips gate Send; failed chips block it in
		// handleSend — neither may silently ride along with an empty blobId.
		// Inline images use `inlineDone` (computed above) instead of a fresh status
		// check, so a since-deleted placeholder never rides along as a stray
		// regular attachment.
		const nonInlineDone = this.attachments.filter((a) => !a.inline && (a.status ?? 'done') === 'done');
		const allDone = [...nonInlineDone, ...inlineDone];
		if (allDone.length > 0) {
			msg.attachments = allDone.map((a) => ({
				blobId: a.blobId,
				name: a.name,
				type: a.type,
				size: a.size,
				...(a.inline ? { cid: a.cid, disposition: 'inline' } : {})
			}));
		}

		return msg;
	}

	// Build the EmailSubmission/set create object for a sent email — the envelope +
	// scheduled-send (sendAt), tag-on-send (onSuccessUpdateEmail keyword patch), and
	// S/MIME sign/encrypt intents, from the draft fields. Pure logic (the most
	// test-worthy part of the send path); the caller (handleSend, still in the
	// component) owns the JMAP call + the undo-timer/toast/close view concerns.
	buildSubmission(
		emailId: string,
		userEmail: string,
		scheduleMode: string,
		undoWindowSeconds: number
	): Record<string, unknown> {
		const sub: Record<string, unknown> = {
			emailId,
			envelope: {
				mailFrom: { email: this.fromEmail || userEmail || 'unknown@unknown' },
				rcptTo: this.parseAddrList(this.to)
			},
			onSendUndoWindowSeconds: undoWindowSeconds
		};
		// B2: scheduled send
		if (this.scheduledAt && scheduleMode !== 'now') {
			sub.sendAt = new Date(this.scheduledAt).toISOString();
		}
		// B3: tag-on-send
		if (this.sendTags.length > 0) {
			const keywordPatch: Record<string, boolean> = {};
			for (const tagId of this.sendTags) {
				keywordPatch[`keywords/$` + tagId] = true;
			}
			sub.onSuccessUpdateEmail = { [`#${emailId}`]: keywordPatch };
		}
		// C3 / P4-5: carry the sign/encrypt intents so the submission handler runs
		// S/MIME signing / the fail-closed encrypt cert-availability check.
		if (this.smimeSign) sub.signSMIME = true;
		if (this.smimeEncrypt) sub.encryptSMIME = true;
		if (this.sharedDraftSession) {
			sub.draftSessionId = this.sharedDraftSession.id;
			sub.draftLeaseEpoch = this.sharedDraftSession.leaseEpoch;
			sub.draftRevision = this.sharedDraftSession.contentRevision;
		}
		return sub;
	}

	// createAndSubmit: the JMAP orchestration of a send — create the email (destroying
	// the edited draft), then submit it (buildSubmission does the envelope/schedule/
	// tags/S-MIME). Returns { emailId, held } — held=true when the send was parked for
	// external-send approval (the view shows a "held" toast and skips the undo timer).
	// Throws a SubmissionMarkerError on a submission notCreated marker (the view localizes
	// .code) or a plain Error on a flow failure (drafts-missing / offline / create-failed).
	// On success records the recipients for autocomplete + clears editingDraftId. The view
	// keeps validation and the undo-timer/toast/close orchestration around this call.
	async createAndSubmit(
		editor: EditorHandle | null,
		userEmail: string,
		scheduleMode: string,
		undoWindowSeconds: number
	): Promise<{ emailId: string; held: boolean }> {
		await loadSession();
		const draftsId = this.getDraftsId();
		if (!draftsId) throw new Error('Drafts folder not found');

		const msg = this.buildMsg(editor, userEmail);
		// The edited draft is destroyed only AFTER the submission succeeds.
		// Bundling the destroy into the create meant a failed submission (e.g.
		// over the daily quota) had already destroyed the user's draft, left the
		// staged message orphaned, and — with editingDraftId still pointing at
		// the destroyed row — every retry staged another orphan.
		let emailId: string;
		let stagedForCleanup = false;
		if (this.sharedAccountId && this.sharedDraftSession) {
			this.sharedDraftSession = await mailDraftReplace({
				accountId: this.sharedAccountId,
				session: this.sharedDraftSession,
				draft: msg
			});
			emailId = this.sharedDraftSession.messageId;
			this.editingDraftId = emailId;
		} else {
			const emailResult = await emailSet({ 'email-1': msg }, null, null, this.sharedAccountId);
			if ('offline' in emailResult) throw new Error('Cannot send while offline');
			const createdId = emailResult.created?.['email-1']?.id;
			if (!createdId) {
				const notCreated = emailResult.notCreated?.['email-1'];
				throw new Error(notCreated?.description || 'Failed to create email');
			}
			emailId = createdId;
			stagedForCleanup = true;
		}

		const subCreate = { 'sub-1': this.buildSubmission(emailId, userEmail, scheduleMode, undoWindowSeconds) };
		let held = false;
		try {
			const subResult = await emailSubmissionSet(subCreate, this.sharedAccountId);
			if (!('offline' in subResult)) {
				const subNotCreated = (subResult as { notCreated?: Record<string, { type?: string; description?: string; addresses?: string[] }> }).notCreated;
				if (subNotCreated?.['sub-1']) {
					const entry = subNotCreated['sub-1'];
					throw new SubmissionMarkerError(entry.type, entry.addresses);
				}
				// Held for external-send approval: the message is parked as an approval_request
				// (no queued/undo send exists), so the view must NOT arm the undo-send timer.
				held = (subResult as { created?: Record<string, { heldForApproval?: boolean }> })
					.created?.['sub-1']?.heldForApproval === true;
			}
		} catch (e) {
			// The submission failed — clean up the staged message so a retry
			// doesn't accumulate orphaned rows. Email/set destroy is trash-first
			// (Gmail-style; jmap_email_set_destroy), and a failed send's staging
			// row is garbage, not user content — destroy twice to purge it past
			// Trash. Best-effort: the compose stays open with content either way.
			if (stagedForCleanup) {
				try {
					await emailSet(null, null, [emailId], this.sharedAccountId);
					await emailSet(null, null, [emailId], this.sharedAccountId);
				} catch {
					/* staging cleanup is best-effort */
				}
			}
			throw e;
		}

		if (this.editingDraftId && !this.sharedDraftSession) {
			try {
				await emailSet(null, null, [this.editingDraftId], this.sharedAccountId);
			} catch {
				/* draft cleanup is best-effort — the next explicit save overwrites it */
			}
		}
		this.editingDraftId = null;
		this.sharedDraftSession = null;
		this.sharedDraftReadOnly = false;
		this.sharedDraftConflict = false;
		for (const addr of msg.to as EmailAddress[]) recordSend(addr.email, addr.name);
		if (msg.cc) for (const addr of msg.cc as EmailAddress[]) recordSend(addr.email, addr.name);
		if (msg.bcc) for (const addr of msg.bcc as EmailAddress[]) recordSend(addr.email, addr.name);
		return { emailId, held };
	}

	// ── GAL / recipient autocomplete + mailtips (slice 4) ─────────────────────
	// The recipient-writing methods target this.to/cc/bcc/replyTo (already owned
	// by the store), so this logic naturally lives beside the fields it mutates.

	onGalInput(target: 'to' | 'cc' | 'bcc' | 'replyTo', val: string) {
		this.galTarget = target;
		this.galQuery = val;
		this.galActive = -1;
		if (this.#galTimer) clearTimeout(this.#galTimer);
		const q = val.trim();
		// Cache + group suggestions resolve instantly (localStorage / in-memory),
		// so surface them immediately ahead of the debounced GAL fetch.
		this.refreshLocalSuggestions(q);
		if (!q || q.length < 2) {
			this.galResults = [];
			this.galShow = this.cacheSuggestions.length > 0 || this.groupSuggestions.length > 0;
			this.galError = false;
			return;
		}
		this.galShow = true;
		this.#galTimer = setTimeout(async () => {
			try {
				this.galResults = await galSearch(q, 10);
				this.galError = false;
				this.galActive = -1;
			} catch {
				this.galError = true;
			}
			this.galShow = this.galResults.length > 0 || this.cacheSuggestions.length > 0 || this.groupSuggestions.length > 0;
		}, 200);
	}

	// Recompute the instant (non-GAL) suggestion lists for the current query.
	refreshLocalSuggestions(q: string) {
		const lower = q.toLowerCase();
		this.groupSuggestions = q
			? get(contactGroups).filter((g) => g.name.toLowerCase().includes(lower))
			: [];
		this.cacheSuggestions = suggestRecipients(q, 5);
	}

	// Total count of dropdown options (groups → cache → GAL) for keyboard nav.
	suggestionCount(): number {
		return this.groupSuggestions.length + this.cacheSuggestions.length + this.galResults.length;
	}

	// Activate the option at flat index `i` across the merged dropdown.
	async pickAt(i: number) {
		if (i < 0) return;
		if (i < this.groupSuggestions.length) {
			await this.pickGroup(this.groupSuggestions[i]);
			return;
		}
		const ci = i - this.groupSuggestions.length;
		if (ci < this.cacheSuggestions.length) {
			this.pickCacheSuggestion(this.cacheSuggestions[ci]);
			return;
		}
		const gi = ci - this.cacheSuggestions.length;
		if (gi < this.galResults.length) this.pickContact(this.galResults[gi]);
	}

	appendRecipient(display: string) {
		if (this.galTarget === 'to') this.to = this.to ? this.to + ', ' + display : display;
		else if (this.galTarget === 'cc') this.cc = this.cc ? this.cc + ', ' + display : display;
		else if (this.galTarget === 'bcc') this.bcc = this.bcc ? this.bcc + ', ' + display : display;
		else if (this.galTarget === 'replyTo') this.replyTo = display;
	}

	// A person picked from an @-mention in the body always goes to To. Force
	// galTarget FIRST — appendRecipient writes to whatever galTarget currently is,
	// so a stray Cc/Bcc/Reply-To focus would otherwise leak the mention into the
	// wrong field. No-op on a person with no address (the chip is still inserted).
	mentionRecipient(label: string, email: string) {
		this.galTarget = 'to';
		if (!email) return;
		this.appendRecipient(label ? `${label} <${email}>` : email);
	}

	pickCacheSuggestion(s: RecipientSuggestion) {
		const display = s.name ? `${s.name} <${s.email}>` : s.email;
		if (this.galTarget === 'replyTo') this.replyTo = s.email;
		else this.appendRecipient(display);
		this.galShow = false;
		this.galQuery = '';
		this.galActive = -1;
	}

	// "Send to group" (Outlook behavior): expand the group and append every member.
	async pickGroup(g: ContactGroup) {
		this.galShow = false;
		this.galQuery = '';
		this.galActive = -1;
		try {
			const recipients = await expandGroup(g.id);
			for (const r of recipients) {
				this.appendRecipient(r.name ? `${r.name} <${r.email}>` : r.email);
			}
		} catch {
			// Expansion failed — leave the field untouched rather than inserting a bad token.
		}
	}

	// Forget a cached recipient (the per-row X) and refresh the dropdown in place.
	forgetSuggestion(email: string, e: Event) {
		e.stopPropagation();
		removeRecipient(email);
		this.refreshLocalSuggestions(this.galQuery.trim());
		this.galShow = this.suggestionCount() > 0;
		this.galActive = -1;
	}

	// Keyboard navigation for the GAL combobox (ArrowDown/Up/Enter/Escape).
	onGalKeydown(target: 'to' | 'cc' | 'bcc' | 'replyTo', e: KeyboardEvent) {
		const total = this.suggestionCount();
		if (this.galTarget !== target || !this.galShow || total === 0) {
			if (e.key === 'Escape' && this.galShow) this.galShow = false;
			return;
		}
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			this.galActive = (this.galActive + 1) % total;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			this.galActive = (this.galActive - 1 + total) % total;
		} else if (e.key === 'Enter' && this.galActive >= 0) {
			e.preventDefault();
			this.pickAt(this.galActive);
		} else if (e.key === 'Escape') {
			e.preventDefault();
			this.galShow = false;
		}
	}

	pickContact(c: ContactCard) {
		const addr = c.email || c.emails?.[0]?.address || '';
		if (!addr) return;
		const display = c.displayName ? `${c.displayName} <${addr}>` : addr;
		if (this.galTarget === 'to') this.to = this.to ? this.to + ', ' + display : display;
		if (this.galTarget === 'cc') this.cc = this.cc ? this.cc + ', ' + display : display;
		if (this.galTarget === 'bcc') this.bcc = this.bcc ? this.bcc + ', ' + display : display;
		if (this.galTarget === 'replyTo') this.replyTo = addr;
		this.galShow = false;
		this.galQuery = '';
		this.galActive = -1;
	}

	async fetchMailTips() {
		const allRecipients = [this.to, this.cc, this.bcc].filter(Boolean).join(',');
		if (!allRecipients && !this.fromEmail) return;
		const params = new URLSearchParams();
		params.set('recipients', allRecipients);
		if (this.fromEmail) params.set('from', this.fromEmail);
		try {
			const res = await fetch(`/auth/me/mailtips?${params.toString()}`);
			if (res.ok) {
				const data = await res.json();
				this.mailtipsWarnings = data.warnings ?? [];
			}
		} catch {
			this.mailtipsWarnings = [];
		}
	}

	debounceMailTips() {
		if (this.#mailtipsTimer) clearTimeout(this.#mailtipsTimer);
		this.#mailtipsTimer = setTimeout(() => this.fetchMailTips(), 500);
	}

	// Compose-time DLP dry-run (Purview-style policy tip): dry-runs the SAME
	// dlp_evaluate_draft seam send() enforces via dlp_check, so the tip can
	// never disagree with enforcement. #dlpSeq drops a stale in-flight response
	// (fast typing can reorder two in-flight checks — a stale "clean" must
	// never overwrite a fresher "block").
	async fetchDlpCheck() {
		const seq = ++this.#dlpSeq;
		if (!this.subject && !this.bodyText) return;
		const recipients = [this.to, this.cc, this.bcc]
			.filter(Boolean)
			.join(',')
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		try {
			const res = await fetch('/auth/me/dlp-check', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					recipients,
					subject: this.subject,
					bodyText: this.bodyText,
					bodyHtml: this.bodyHtml
				})
			});
			if (res.ok && seq === this.#dlpSeq) this.dlpTip = await res.json();
		} catch {
			/* advisory: keep the last known tip */
		}
	}

	// Body payload (vs mailtips' recipient-only GET) → a longer 1s debounce.
	debounceDlpCheck() {
		if (this.#dlpTimer) clearTimeout(this.#dlpTimer);
		this.#dlpTimer = setTimeout(() => this.fetchDlpCheck(), 1000);
	}

	// ── Attachment upload (slice 3, reworked WAVE-5 #3) ──────────────────────
	// Stage the given files as chips immediately (status 'preparing'), then
	// upload each sequentially over XHR with real progress. Returns the names of
	// files SKIPPED for exceeding the 25 MiB cap so the caller (the view) can
	// toast them — the store stays UI-agnostic (no toast/i18n import). Per-chip
	// failures set status 'failed' (retryUpload re-runs them).
	async handleFiles(files: FileList | File[] | null): Promise<string[]> {
		if (!files) return [];
		const skipped: string[] = [];
		const accepted: string[] = [];
		let total = this.attachmentBytes;
		for (const file of Array.from(files)) {
			// Refuse anything that would push the total over the server cap — skip
			// rather than upload a blob the send reducer will reject.
			if (total + file.size > MAX_ATTACH_BYTES) {
				skipped.push(file.name);
				continue;
			}
			total += file.size;
			const id = `up-${this.#nextUploadId++}`;
			this.#files.set(id, file);
			this.attachments = [
				...this.attachments,
				{
					name: file.name,
					size: file.size,
					blobId: '',
					type: file.type,
					status: 'preparing',
					progress: 0,
					uploadId: id
				}
			];
			accepted.push(id);
		}
		this.batchTotal += accepted.length;
		// Sequential like the old loop — one PUT at a time keeps the progress and
		// the "N of M" copy honest.
		for (const id of accepted) await this.#uploadOne(id);
		return skipped;
	}

	// ── Inline body images (WAVE-5 #2) ───────────────────────────────────────
	// Stage a pasted/dropped/toolbar-picked image as an INLINE attachment.
	// Synchronous: creates the local preview URL + attachment row and kicks off
	// the upload in the BACKGROUND (reusing #uploadOne — the same hash/dedupe/
	// XHR-progress path as file attachments, so it naturally shares the
	// uploading/failedUploads/attachmentBytes derived state), so the caller
	// (RichTextEditor) can insert the placeholder <img> immediately without
	// awaiting the upload. Returns null — caller falls back to the ordinary
	// file-attachment path — when the mime type isn't whitelisted or the shared
	// 25 MiB budget is exceeded; that path independently re-checks both and
	// shows the SAME toast copy, so there is no separate error path to build here.
	stageInlineImage(file: File): { previewUrl: string; uploadId: string; cid: string } | null {
		if (!INLINE_IMAGE_TYPES.includes(file.type)) return null;
		if (this.attachmentBytes + file.size > MAX_ATTACH_BYTES) return null;
		const id = `up-${this.#nextUploadId++}`;
		const cid = `${id}@setjoin.inline`;
		const previewUrl = URL.createObjectURL(file);
		this.#files.set(id, file);
		this.attachments = [
			...this.attachments,
			{
				name: file.name,
				size: file.size,
				blobId: '',
				type: file.type,
				status: 'preparing',
				progress: 0,
				uploadId: id,
				inline: true,
				previewUrl,
				cid
			}
		];
		this.batchTotal += 1;
		void this.#uploadOne(id);
		return { previewUrl, uploadId: id, cid };
	}

	/** Drop an inline image's attachment row when the user deletes its <img> node
	 *  directly from the body (backspace) — otherwise the row survives invisibly
	 *  (no body placeholder, not shown in the file-chip list) yet still eats the
	 *  shared budget and, if still uploading, keeps Send gated forever. Call on
	 *  every editor update with the CURRENT body html (cheap: a substring search
	 *  per staged inline image, typically 0–2 rows). */
	pruneOrphanedInlineImages(html: string) {
		for (const a of [...this.attachments]) {
			if (a.inline && a.previewUrl && !html.includes(a.previewUrl)) {
				this.removeAttachment(this.attachments.indexOf(a));
			}
		}
	}

	/** Index of the chip with this uploadId, or -1 (removed by cancel). */
	#chipIndex(id: string): number {
		return this.attachments.findIndex((a) => a.uploadId === id);
	}

	#patchChip(id: string, patch: Partial<ComposeAttachment>) {
		const i = this.#chipIndex(id);
		if (i >= 0) this.attachments[i] = { ...this.attachments[i], ...patch };
	}

	// One chip's upload: hash ('preparing', indeterminate — the whole-file digest
	// blocks before progress can move) → dedupe fast-path → XHR PUT ('uploading',
	// real onprogress) → 'done' at 100 / 'failed'. A cancelled chip was already
	// removed by cancelUpload; every exit bumps the batch counter.
	async #uploadOne(id: string): Promise<void> {
		const file = this.#files.get(id);
		if (!file || this.#chipIndex(id) < 0) return;
		try {
			const blobId = await sha256Hex(file);
			if (this.#chipIndex(id) < 0) return; // cancelled during the hash
			// Dedupe fast-path: the same bytes are already staged → the blob exists
			// server-side, no second PUT. Jump straight to 100 (no fake curve).
			const dupe = this.attachments.some(
				(a) => a.uploadId !== id && a.blobId === blobId && (a.status ?? 'done') === 'done'
			);
			if (dupe) {
				this.#patchChip(id, { blobId, status: 'done', progress: 100 });
				return;
			}
			const ctrl = new AbortController();
			this.#aborts.set(id, ctrl);
			this.#patchChip(id, { blobId, status: 'uploading' });
			await putBlob(blobId, file, {
				signal: ctrl.signal,
				onProgress: (frac) => this.#patchChip(id, { progress: Math.round(frac * 100) })
			});
			this.#patchChip(id, { status: 'done', progress: 100 });
		} catch (e) {
			if (this.#chipIndex(id) < 0) return; // aborted → chip already removed
			console.error('Upload failed', file.name, e);
			this.#patchChip(id, { status: 'failed' });
		} finally {
			this.#aborts.delete(id);
			this.batchDone += 1;
			if (!this.uploading) {
				// Batch drained (all done/failed/cancelled) — reset the N-of-M copy.
				this.batchDone = 0;
				this.batchTotal = 0;
			}
		}
	}

	/** Cancel an in-flight chip: abort the XHR AND remove the chip (un-gates Send). */
	cancelUpload(id: string) {
		this.#revokeInlinePreview(this.attachments.find((a) => a.uploadId === id));
		this.#aborts.get(id)?.abort();
		this.#aborts.delete(id);
		this.#files.delete(id);
		this.attachments = this.attachments.filter((a) => a.uploadId !== id);
		this.batchTotal = Math.max(0, this.batchTotal - 1);
		if (!this.uploading) {
			this.batchDone = 0;
			this.batchTotal = 0;
		}
	}

	/** Re-run a failed chip's upload from the retained File. */
	async retryUpload(id: string): Promise<void> {
		const i = this.#chipIndex(id);
		if (i < 0 || this.attachments[i].status !== 'failed' || !this.#files.has(id)) return;
		this.#patchChip(id, { status: 'preparing', progress: 0 });
		this.batchTotal += 1;
		await this.#uploadOne(id);
	}

	removeAttachment(idx: number) {
		const a = this.attachments[idx];
		if (a?.uploadId && (a.status === 'preparing' || a.status === 'uploading')) {
			this.cancelUpload(a.uploadId);
			return;
		}
		this.#revokeInlinePreview(a);
		if (a?.uploadId) this.#files.delete(a.uploadId);
		this.attachments = this.attachments.filter((_, i) => i !== idx);
	}

	/** Reset only draft state owned by this store after a successful send, held
	 * acceptance, or explicit discard. The view remains responsible for editor
	 * DOM, focus, toast/undo timers, menus, window close and responsive layout. */
	resetOwnedState() {
		this.#hydrationGeneration += 1;
		for (const attachment of [...this.attachments]) {
			if (attachment.uploadId) this.cancelUpload(attachment.uploadId);
			else this.#revokeInlinePreview(attachment);
		}
		this.to = '';
		this.cc = '';
		this.bcc = '';
		this.replyTo = '';
		this.subject = '';
		this.bodyHtml = '';
		this.bodyText = '';
		this.categories = [];
		this.newCategory = '';
		this.attachments = [];
		this.priority = 'normal';
		this.sensitivity = 'normal';
		this.scheduledAt = '';
		this.readReceipt = false;
		this.useVoting = false;
		this.voteOptions = [''];
		this.voteResponse = '';
		this.sendTags = [];
		this.plainTextOnly = false;
		this.smimeEncrypt = false;
		this.smimeSign = false;
		this.editingDraftId = null;
		this.sharedDraftSession = null;
		this.sharedDraftReadOnly = false;
		this.sharedDraftConflict = false;
		this.sharedAccountId = null;
		this.draftSaveError = false;
		this.galError = false;
		this.batchDone = 0;
		this.batchTotal = 0;
	}

	/** Starts one guarded async draft hydration. The fingerprint covers edits
	 * whose background loaders never legitimately change them. From is excluded
	 * because mailbox/account discovery may initialize it; the view explicitly
	 * invalidates hydration for a user-driven From selection instead. */
	beginHydration(): ComposeHydrationTicket {
		this.#hydrationGeneration += 1;
		return {
			generation: this.#hydrationGeneration,
			fingerprint: this.#hydrationFingerprint()
		};
	}

	/** Explicit user intent that cannot be inferred from the field fingerprint.
	 * From is initialized/corrected by background mailbox/account discovery, so
	 * only the view's user-driven From selector may invalidate hydration. */
	invalidateHydration(): void {
		this.#hydrationGeneration += 1;
	}

	canApplyHydration(ticket: ComposeHydrationTicket): boolean {
		return ticket.generation === this.#hydrationGeneration && ticket.fingerprint === this.#hydrationFingerprint();
	}

	/** Atomically validates and applies the synchronous store portion of a draft
	 * hydration, then returns a new ticket for any delayed view-side work (for
	 * example the editor write after tick()). */
	applyHydration(ticket: ComposeHydrationTicket, apply: () => void): ComposeHydrationTicket | null {
		if (!this.canApplyHydration(ticket)) return null;
		apply();
		return {
			generation: this.#hydrationGeneration,
			fingerprint: this.#hydrationFingerprint()
		};
	}

	#hydrationFingerprint(): string {
		return JSON.stringify([
			this.to,
			this.cc,
			this.bcc,
			this.replyTo,
			this.subject,
			this.bodyHtml,
			this.bodyText,
			this.priority,
			this.sensitivity,
			this.scheduledAt,
			this.readReceipt,
			this.useVoting,
			this.voteOptions,
			this.voteResponse
		]);
	}

	// ponytail: revokes eagerly on remove/cancel rather than only at teardown() —
	// a long single-page compose session (paste+remove many images) would
	// otherwise leak object URLs for its whole lifetime. Ceiling: if the SAME
	// node were ever duplicated within the body (copy-paste of an in-flight
	// image, sharing one previewUrl across two <img> tags — not a flow this UI
	// offers today), the surviving copy would break; revisit if that lands.
	#revokeInlinePreview(a: ComposeAttachment | undefined) {
		if (a?.inline && a.previewUrl) {
			try {
				URL.revokeObjectURL(a.previewUrl);
			} catch {
				/* already revoked / unsupported */
			}
		}
	}

	// ── Draft autosave (slice 2a) ─────────────────────────────────────────────
	// Debounced by the component (handleUpdate schedules this). Takes the editor
	// handle (to read the current body) + userEmail (the from-fallback, a component
	// $derived off the auth store) as params, so the store stays decoupled from the
	// editor ref and the auth store. Banners are just state the view reads.
	async saveDraft(editor: EditorHandle | null, userEmail = '') {
		const bodyTextVal = this.getBodyText(editor);
		if (!this.subject && !bodyTextVal && !this.to) return;
		if (this.draftSaving || this.sharedDraftReadOnly) return;
		this.draftSaving = true;
		try {
			await loadSession();
			const draftsId = this.getDraftsId();
			if (!draftsId) return;
			const msg = this.buildMsg(editor, userEmail);
			if (this.sharedAccountId && this.sharedDraftsEnabled && this.sharedDraftSession) {
				const session = await mailDraftReplace({
					accountId: this.sharedAccountId,
					session: this.sharedDraftSession,
					draft: msg
				});
				this.sharedDraftSession = session;
				this.editingDraftId = session.messageId;
			} else {
				const destroyIds = this.editingDraftId ? [this.editingDraftId] : null;
				const result = await emailSet({ 'draft-1': msg }, null, destroyIds, this.sharedAccountId);
				if (!('offline' in result) && result.created?.['draft-1']?.id) {
					const id = result.created['draft-1'].id;
					this.editingDraftId = id;
					if (this.sharedAccountId && this.sharedDraftsEnabled) {
						const [created] = await emailGet([id], ['id', 'receivedAt'], undefined, this.sharedAccountId);
						if (!created?.receivedAt) throw new Error('Shared draft identity unavailable');
						this.sharedDraftSession = await mailDraftOpen({
							accountId: this.sharedAccountId,
							messageId: id,
							receivedAt: created.receivedAt,
							finalSenderAddress: this.fromEmail || userEmail,
						});
					}
				}
			}
			this.sharedDraftConflict = false;
			this.draftSaved = true;
			setTimeout(() => (this.draftSaved = false), 2000);
		} catch (e) {
			console.error('Draft save failed', e);
			if (this.sharedAccountId && this.sharedDraftsEnabled && this.sharedDraftSession) {
				this.sharedDraftReadOnly = true;
				this.sharedDraftConflict = true;
			}
			this.draftSaveError = true;
			if (this.#draftSaveErrorTimer) clearTimeout(this.#draftSaveErrorTimer);
			this.#draftSaveErrorTimer = setTimeout(() => {
				this.draftSaveError = false;
			}, 3000);
		} finally {
			this.draftSaving = false;
		}
	}

	// Clear the autocomplete/mailtips debounce timers — the component's onDestroy
	// calls this so they never fire after unmount.
	teardown() {
		for (const a of this.attachments) this.#revokeInlinePreview(a);
		if (this.#galTimer) {
			clearTimeout(this.#galTimer);
			this.#galTimer = null;
		}
		if (this.#mailtipsTimer) {
			clearTimeout(this.#mailtipsTimer);
			this.#mailtipsTimer = null;
		}
		if (this.#dlpTimer) {
			clearTimeout(this.#dlpTimer);
			this.#dlpTimer = null;
		}
		if (this.#draftSaveErrorTimer) {
			clearTimeout(this.#draftSaveErrorTimer);
			this.#draftSaveErrorTimer = null;
		}
	}
}
