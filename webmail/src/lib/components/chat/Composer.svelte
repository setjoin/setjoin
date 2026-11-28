<svelte:options runes={true} />

<script lang="ts">
	// Composer — Task 15. A raw <textarea> (not the M1 Textarea primitive,
	// which has no onkeydown/ref passthrough — needed here for Enter-to-send
	// and cursor-position mention/emoji insertion; MessageList's own scroll
	// container took the same raw-element route in Task 14 for the same
	// reason). Reuses chatStore.send() directly (it always targets
	// chatStore.activeChannelId, which this composer is always rendered for —
	// both the main composer and ThreadPane's own) rather than inventing an
	// onSend callback prop.
	//
	// ponytail: the plan's "buffer preserved" note is already the STORE's job
	// (a failed send's body lives on the optimistic row itself — Design F4,
	// Task 12/15's MessageRow Retry/Discard) — this composer clears its local
	// text immediately on submit and does not keep a separate per-channel
	// draft cache. Add one if switching channels mid-draft turns out to lose
	// work users care about.
	import { tick, onMount } from 'svelte';
	import { chatStore, pendingKey, chatErrorMessage } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import { COMMON_EMOJI } from './MessageRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { Progress, Dialog, Badge, showToast } from '$lib/components/ui';
	import { formatBytes } from '$lib/utils/display';
	import { t } from '$lib/i18n';

	const TYPING_THROTTLE_MS = 3000;
	const MAX_ATTACHMENTS = 8;
	const CAP_NOTICE_MS = 3000;
	// A3 QoL Task 15 — voice recording cap, matches BZ178's server-side
	// durationMs ceiling in chat_message_send exactly (no point letting the
	// client record past what the reducer will reject).
	const VOICE_CAP_MS = 300_000;

	// Task 2/17 review fix: the BZ codes scheduled_action_chat_send.sql catches
	// at fire time and writes onto payload->>'failureCode' (membership/archive/
	// permission — see docs/reducer-error-codes.md BZ163 section). Each has a
	// chat.schedule.reason.<code> i18n key. An unrecognized code (shouldn't
	// happen given the reducer's catch list, but the queue must never assume)
	// falls back to the raw SQLSTATE — NEVER lastError, which is the English
	// PL/pgSQL RAISE text and would defeat i18n for zh/de users.
	const SCHEDULE_FAILURE_REASON_CODES = ['BZ163', 'BZ164', 'BZ166', 'BZ168', 'BZ171'];
	function scheduleFailureReason(code: string | null): string {
		if (code && SCHEDULE_FAILURE_REASON_CODES.includes(code)) return t(`chat.schedule.reason.${code}`);
		return code ?? '';
	}

	let {
		channelId,
		parentId = null,
		canBroadcast = false,
		disabled = false,
		disabledMessage,
		noAttachments = false,
	}: {
		channelId: number;
		parentId?: number | null;
		canBroadcast?: boolean;
		disabled?: boolean;
		/** Pillar C2 Task 7 — overrides the generic "only admins can post
		 *  here" copy when `disabled` is true for a DIFFERENT reason (a
		 *  kicked/scope-revoked federated room mirror, archive-read-only).
		 *  Undefined keeps the original admins-only copy — every pre-C2
		 *  caller/test is unaffected. */
		disabledMessage?: string;
		/** Pillar C2 Task 7 (Q11) — a room-bound channel cannot propagate
		 *  attachments to the other member orgs (BZ212 remains the send-time
		 *  enforcement); this disables the Paperclip picker with a tooltip
		 *  rather than the global `chatStore.attachmentsEnabled` alone, which
		 *  would let a user compose an attachment only to hit the BZ212 toast
		 *  at send time. */
		noAttachments?: boolean;
	} = $props();

	interface MentionCandidate {
		key: string;
		label: string;
		insertText: string;
		hint?: string;
		userId?: number;
		external?: boolean;
		removed?: boolean;
		isBroadcast?: 'channel' | 'all';
	}

	let value = $state('');
	let mentions = $state<{ userId: number; displayName: string }[]>([]);
	let broadcast = $state<'channel' | 'all' | null>(null);
	let emojiOpen = $state(false);
	let taEl = $state<HTMLTextAreaElement | undefined>();

	// ── attachments (Chat A2 Task 8) ────────────────────────────────────────
	let fileInputEl = $state<HTMLInputElement | undefined>();
	let dragCounter = $state(0);
	let capNotice = $state(false);
	let capNoticeTimer: ReturnType<typeof setTimeout> | null = null;

	// This composer's own slice of the store — keyed identically to how
	// send()/addAttachments/removeAttachment/retryAttachment index it
	// internally (Design H8: survives a channel switch and back; ThreadPane's
	// composer is the SAME store, a different parentId).
	let pendingKeyStr = $derived(pendingKey(channelId, parentId));
	let pending = $derived(chatStore.pendingAttachments[pendingKeyStr] ?? []);
	let uploading = $derived(pending.some((p) => p.status === 'hashing' || p.status === 'uploading'));
	let hasReadyAttachment = $derived(pending.some((p) => p.status === 'ready'));
	let uploadAnnouncement = $derived.by(() => {
		if (!uploading) return '';
		const total = pending.length;
		const done = pending.filter((p) => p.status === 'ready').length;
		return t('chat.attach.uploading', { done: String(done), total: String(total) });
	});

	function pickFiles(): void {
		fileInputEl?.click();
	}

	function handleFileInputChange(e: Event & { currentTarget: HTMLInputElement }): void {
		const files = Array.from(e.currentTarget.files ?? []);
		addFiles(files);
		// M16: reset so picking the SAME file again re-fires change (mobile camera
		// re-capture, or re-attaching after a Remove); `accept` is left unset so a
		// mobile file picker still offers the camera, not just an image gallery.
		e.currentTarget.value = '';
	}

	// Pillar C2 Task 7 review (M2): the ONE choke every intake path (file
	// picker, paste, drag-drop on the composer, ChatApp's pane-level drop via
	// acceptDroppedFiles below) routes through — the Paperclip button's own
	// disabled state was the only place this was previously enforced, so
	// paste/drop still silently dead-ended in the BZ212 toast at send time.
	function addFiles(files: File[]): void {
		if (files.length === 0 || !chatStore.attachmentsEnabled) return;
		if (noAttachments) {
			showToast(t('chat.federation.attachDisabled'));
			return;
		}
		const room = MAX_ATTACHMENTS - pending.length;
		if (room <= 0) {
			flashCapNotice();
			return;
		}
		const accepted = files.slice(0, room);
		chatStore.addAttachments(channelId, parentId, accepted);
		if (files.length > room) flashCapNotice();
	}

	function flashCapNotice(): void {
		capNotice = true;
		if (capNoticeTimer) clearTimeout(capNoticeTimer);
		capNoticeTimer = setTimeout(() => {
			capNotice = false;
		}, CAP_NOTICE_MS);
	}

	// Design H4 (paste-from-clipboard): only intercepted when the clipboard
	// actually carries files (a screenshot/image paste) — a normal text paste
	// falls through untouched. Pasted files never carry a meaningful name, so
	// every one is renamed, matching the plan's literal "synthesize
	// image-<ISO>.png" (M17 edge case: an empty File.type falls back to png).
	function handlePaste(e: ClipboardEvent): void {
		if (!chatStore.attachmentsEnabled) return;
		const files = Array.from(e.clipboardData?.files ?? []);
		if (files.length === 0) return;
		e.preventDefault();
		const stamp = new Date().toISOString().replace(/[:.]/g, '-');
		const renamed = files.map(
			(f, i) => new File([f], `image-${stamp}${i > 0 ? '-' + i : ''}.png`, { type: f.type || 'image/png' }),
		);
		addFiles(renamed);
	}

	function hasFileDrag(e: DragEvent): boolean {
		return !!e.dataTransfer?.types.includes('Files');
	}

	// M9 (whole-pane drag-drop): ChatApp's main pane wraps this composer with
	// its own dragover/drop pair so a drop over MessageList doesn't navigate
	// the browser away. A drop landing directly on the composer strip is
	// still handled here first — stopPropagation keeps the pane's listener
	// from seeing the (already-handled) bubbled event and double-adding the
	// same files via composerRef.acceptDroppedFiles.
	function handleDragEnter(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		e.preventDefault();
		e.stopPropagation();
		dragCounter++;
	}
	function handleDragOver(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		e.preventDefault(); // required for drop to fire
		e.stopPropagation();
	}
	function handleDragLeave(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		e.stopPropagation();
		dragCounter = Math.max(0, dragCounter - 1);
	}
	function handleDrop(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled) return;
		e.preventDefault();
		e.stopPropagation();
		dragCounter = 0;
		addFiles(Array.from(e.dataTransfer?.files ?? []));
	}

	/** The composer intake, exposed for ChatApp's pane-level drop handler
	 *  (M9: whole-pane drag-drop) — a drop anywhere over the message pane
	 *  (not just this composer strip) routes here via `bind:this`, reusing
	 *  the SAME cap/accept logic as a direct drop or the Paperclip picker
	 *  rather than duplicating it at the pane level. */
	export function acceptDroppedFiles(files: File[]): void {
		addFiles(files);
	}

	// ── voice recording (A3 QoL Task 15) — the recorded clip rides the SAME
	// composer attachment/pending-list machinery above (one audio/* file
	// through addAttachments), so the chunk-upload rail, cap, and chip UI
	// are all reused verbatim; only the eventual send differs (sendVoice,
	// not send) — voiceClientId/voiceDurationMs is how submit() tells them
	// apart. ────────────────────────────────────────────────────────────
	let recording = $state(false);
	let recordingElapsedMs = $state(0);
	let voiceDurationMs = $state<number | null>(null);
	let voiceClientId = $state<string | null>(null);
	let mediaRecorder: MediaRecorder | null = null;
	let mediaStream: MediaStream | null = null;
	let recordedChunks: BlobPart[] = [];
	let recordedMimeType = '';
	let recordingTimer: ReturnType<typeof setInterval> | null = null;
	let recordingStartedAt = 0;

	function pickMimeType(): string {
		if (typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported?.('audio/webm;codecs=opus')) return 'audio/webm;codecs=opus';
		return 'audio/mp4'; // Safari
	}

	async function toggleRecording(): Promise<void> {
		if (recording) {
			stopRecording();
			return;
		}
		let stream: MediaStream;
		try {
			stream = await navigator.mediaDevices.getUserMedia({ audio: true });
		} catch {
			showToast(t('chat.voice.micDenied'), { variant: 'danger' });
			return;
		}
		mediaStream = stream;
		recordedMimeType = pickMimeType();
		recordedChunks = [];
		mediaRecorder = new MediaRecorder(stream, { mimeType: recordedMimeType });
		mediaRecorder.ondataavailable = (e: BlobEvent) => {
			if (e.data.size > 0) recordedChunks.push(e.data);
		};
		mediaRecorder.start();
		recording = true;
		recordingStartedAt = Date.now();
		recordingElapsedMs = 0;
		recordingTimer = setInterval(() => {
			recordingElapsedMs = Date.now() - recordingStartedAt;
			if (recordingElapsedMs >= VOICE_CAP_MS) stopRecording();
		}, 250);
	}

	function stopMediaTracks(): void {
		mediaStream?.getTracks().forEach((tr) => tr.stop());
		mediaStream = null;
	}

	/** Stop-and-keep — the mic toggle button's second click, or the cap timer. */
	function stopRecording(): void {
		if (!recording || !mediaRecorder) return;
		if (recordingTimer) {
			clearInterval(recordingTimer);
			recordingTimer = null;
		}
		recording = false;
		const durationMs = recordingElapsedMs;
		mediaRecorder.onstop = () => {
			stopMediaTracks();
			finalizeRecording(durationMs);
		};
		mediaRecorder.stop();
		mediaRecorder = null;
	}

	/** Cancel affordance — discards the in-progress recording, never attaches it. */
	function cancelRecording(): void {
		if (!recording || !mediaRecorder) return;
		if (recordingTimer) {
			clearInterval(recordingTimer);
			recordingTimer = null;
		}
		recording = false;
		mediaRecorder.onstop = () => {
			stopMediaTracks();
			recordedChunks = [];
		};
		mediaRecorder.stop();
		mediaRecorder = null;
	}

	function finalizeRecording(durationMs: number): void {
		const blob = new Blob(recordedChunks, { type: recordedMimeType });
		const ext = recordedMimeType.includes('webm') ? 'webm' : 'm4a';
		const file = new File([blob], `voice-${new Date().toISOString().replace(/[:.]/g, '-')}.${ext}`, { type: recordedMimeType });
		chatStore.addAttachments(channelId, parentId, [file]);
		// addAttachments pushes its new chip synchronously (before any await),
		// so the just-added entry is reliably the last row for this key.
		const rows = chatStore.pendingAttachments[pendingKeyStr] ?? [];
		const added = rows[rows.length - 1];
		voiceClientId = added?.clientId ?? null;
		voiceDurationMs = durationMs;
	}

	function formatElapsed(ms: number): string {
		const totalSec = Math.floor(ms / 1000);
		const m = Math.floor(totalSec / 60);
		const s = totalSec % 60;
		return `${m}:${String(s).padStart(2, '0')}`;
	}

	// ── poll creation ("+" menu) — A3 QoL Task 15 ───────────────────────
	let plusOpen = $state(false);
	let pollDialogOpen = $state(false);
	let pollQuestion = $state('');
	let pollOptions = $state<string[]>(['', '']);
	let pollMulti = $state(false);
	let canSubmitPoll = $derived(pollQuestion.trim().length > 0 && pollOptions.filter((o) => o.trim().length > 0).length >= 2);

	/** Exported (Meet B3 Task 8) so MeetChatPanel can bind:this this
	 *  Composer and open the SAME poll dialog from the meet ControlsBar's
	 *  Poll button — never a duplicated dialog. */
	export function openPollDialog(): void {
		plusOpen = false;
		pollQuestion = '';
		pollOptions = ['', ''];
		pollMulti = false;
		pollDialogOpen = true;
	}

	async function submitPoll(): Promise<void> {
		if (!canSubmitPoll) return;
		const opts = pollOptions.map((o) => o.trim()).filter((o) => o.length > 0);
		try {
			await chatApi.createPoll(channelId, pollQuestion.trim(), opts, pollMulti);
			pollDialogOpen = false;
			// The poll message arrives via the normal WS push (chat_poll_create
			// posts through chat_message_send, Task 6's seam) — this is a
			// snappy own-echo for the acting user, not a substitute for that push.
			await chatStore.backfillSince(channelId);
		} catch (err) {
			// [UX #8, pipeline review] had no catch at all — a rejection left the
			// dialog open with zero signal and the question/options untouched
			// (which is fine — this leaves the dialog open, unlike doSchedule's
			// value-clearing bug — but the failure was otherwise silent).
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}

	// ── send-later (ScheduledAction rail) + the scheduled-queue chip ────
	// A3 QoL Task 15. The composer never inserts an optimistic timeline row
	// for a scheduled send (chatStore.scheduleSend's own contract) — the
	// queue below is the only pre-fire surface.
	let scheduleMenuOpen = $state(false);
	let customScheduleOpen = $state(false);
	let customFireAt = $state('');
	let queueOpen = $state(false);
	let scheduledForChannel = $derived(chatStore.scheduled.filter((s) => s.channelId === channelId));

	onMount(() => {
		void chatStore.loadScheduled();
	});

	async function doSchedule(fireAtIso: string): Promise<void> {
		const body = value.trim();
		if (!body) return;
		const mentionIds = mentions.map((m) => m.userId);
		const bc = broadcast;
		try {
			// [UX #8, pipeline review] used to clear value/mentions/broadcast
			// BEFORE awaiting scheduleSend — a rejection lost the typed message
			// with no way to recover it. Clear only after the call succeeds.
			await chatStore.scheduleSend(channelId, body, fireAtIso, parentId ?? null, mentionIds, bc);
			value = '';
			mentions = [];
			broadcast = null;
		} catch (err) {
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}

	async function scheduleIn1h(): Promise<void> {
		scheduleMenuOpen = false;
		await doSchedule(new Date(Date.now() + 3_600_000).toISOString());
	}

	async function scheduleTomorrowMorning(): Promise<void> {
		scheduleMenuOpen = false;
		const d = new Date();
		d.setDate(d.getDate() + 1);
		d.setHours(9, 0, 0, 0);
		await doSchedule(d.toISOString());
	}

	function openCustomSchedule(): void {
		scheduleMenuOpen = false;
		customFireAt = '';
		customScheduleOpen = true;
	}

	async function confirmCustomSchedule(): Promise<void> {
		if (!customFireAt) return;
		const iso = new Date(customFireAt).toISOString();
		customScheduleOpen = false;
		await doSchedule(iso);
	}

	let mentionOpen = $state(false);
	let mentionStart = $state(0);
	let mentionIndex = $state(0);
	let mentionCandidates = $state<MentionCandidate[]>([]);
	let mentionRequestId = 0;

	// Plain instance fields (not $state) — one-shot bookkeeping, not UI state,
	// mirroring MessageList's frozenForChannelId latch (Task 14).
	let lastTypingAt = 0;
	let lastChannelId: number | null = null;

	$effect(() => {
		const cid = channelId;
		if (lastChannelId === cid) return;
		lastChannelId = cid;
		value = '';
		mentions = [];
		broadcast = null;
		mentionOpen = false;
		void tick().then(() => taEl?.focus());
	});

	function currentMentionToken(text: string, cursor: number): { start: number; query: string } | null {
		const upto = text.slice(0, cursor);
		const at = upto.lastIndexOf('@');
		if (at === -1) return null;
		const between = upto.slice(at + 1);
		if (/\s/.test(between)) return null; // whitespace breaks the token
		return { start: at, query: between };
	}

	async function searchMentions(query: string): Promise<void> {
		const requestId = ++mentionRequestId;
		const candidates: MentionCandidate[] = [];
		if (canBroadcast) {
			const q = query.toLowerCase();
			if ('channel'.startsWith(q)) {
				candidates.push({
					key: 'bc-channel',
					label: t('chat.composer.mentionChannel'),
					insertText: 'channel',
					hint: t('chat.composer.mentionChannelHint'),
					isBroadcast: 'channel',
				});
			}
			if ('all'.startsWith(q)) {
				candidates.push({
					key: 'bc-all',
					label: t('chat.composer.mentionAll'),
					insertText: 'all',
					hint: t('chat.composer.mentionAllHint'),
					isBroadcast: 'all',
				});
			}
		}
		let members: Awaited<ReturnType<typeof chatApi.searchMembers>> = [];
		try {
			members = await chatApi.searchMembers(channelId, query);
		} catch {
			members = [];
		}
		if (requestId !== mentionRequestId) return; // a fresher keystroke already superseded this query
		for (const m of members) {
			candidates.push({
				key: `m-${m.userId}`,
				label: m.displayName,
				insertText: m.displayName,
				userId: m.userId,
				external: m.external,
				removed: m.removed,
			});
		}
		mentionCandidates = candidates;
		mentionIndex = 0;
		mentionOpen = candidates.length > 0;
	}

	function throttledTyping(): void {
		const now = Date.now();
		if (now - lastTypingAt < TYPING_THROTTLE_MS) return;
		lastTypingAt = now;
		void chatApi.sendTyping(channelId);
	}

	function handleInput(e: Event & { currentTarget: HTMLTextAreaElement }): void {
		value = e.currentTarget.value;
		throttledTyping();
		const cursor = e.currentTarget.selectionStart ?? value.length;
		const token = currentMentionToken(value, cursor);
		if (token) {
			mentionStart = token.start;
			void searchMentions(token.query);
		} else {
			mentionOpen = false;
		}
	}

	function selectMention(cand: MentionCandidate | undefined): void {
		if (!cand) return;
		const cursor = taEl?.selectionStart ?? value.length;
		const before = value.slice(0, mentionStart);
		const after = value.slice(cursor);
		const inserted = `@${cand.insertText} `;
		value = before + inserted + after;
		const newPos = (before + inserted).length;
		mentionOpen = false;
		if (cand.isBroadcast) broadcast = cand.isBroadcast;
		else if (cand.userId != null && !mentions.some((m) => m.userId === cand.userId)) {
			mentions = [...mentions, { userId: cand.userId, displayName: cand.insertText }];
		}
		void tick().then(() => {
			taEl?.focus();
			taEl?.setSelectionRange(newPos, newPos);
		});
	}

	function insertEmoji(emoji: string): void {
		const start = taEl?.selectionStart ?? value.length;
		const end = taEl?.selectionEnd ?? value.length;
		value = value.slice(0, start) + emoji + value.slice(end);
		emojiOpen = false;
		const newPos = start + emoji.length;
		void tick().then(() => {
			taEl?.focus();
			taEl?.setSelectionRange(newPos, newPos);
		});
	}

	async function submit(): Promise<void> {
		if (uploading || recording) return; // send-while-uploading/recording is disabled at the button too
		// A3 QoL Task 15: a recorded voice clip takes over the send entirely —
		// voice messages are attachment-only (empty body, msgType='voice'),
		// same shape as an attachment-only text send but routed through
		// sendVoice so the store stamps msgType/payload correctly.
		if (voiceDurationMs != null) {
			const durationMs = voiceDurationMs;
			voiceDurationMs = null;
			voiceClientId = null;
			await chatStore.sendVoice(durationMs, parentId ?? null);
			void tick().then(() => taEl?.focus());
			return;
		}
		const body = value.trim();
		// Design C2 (Grill decision 9): attachment-only messages are legal — an
		// empty body sends fine as long as at least one attachment is ready.
		if (!body && !hasReadyAttachment) return;
		const mentionIds = mentions.map((m) => m.userId);
		const bc = broadcast;
		value = '';
		mentions = [];
		broadcast = null;
		await chatStore.send(body, parentId ?? null, mentionIds, bc);
		void tick().then(() => taEl?.focus());
	}

	function handleKeydown(e: KeyboardEvent): void {
		// Focus trap (Design contract): suggestion navigation never leaves the
		// textarea — arrow/Enter/Escape are intercepted here, not on the list.
		if (mentionOpen && mentionCandidates.length > 0) {
			if (e.key === 'ArrowDown') {
				e.preventDefault();
				mentionIndex = (mentionIndex + 1) % mentionCandidates.length;
				return;
			}
			if (e.key === 'ArrowUp') {
				e.preventDefault();
				mentionIndex = (mentionIndex - 1 + mentionCandidates.length) % mentionCandidates.length;
				return;
			}
			if (e.key === 'Enter' || e.key === 'Tab') {
				e.preventDefault();
				selectMention(mentionCandidates[mentionIndex]);
				return;
			}
			if (e.key === 'Escape') {
				e.preventDefault();
				mentionOpen = false;
				return;
			}
		}
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			void submit();
		}
	}
</script>

{#if disabled}
	<div class="composer composer--disabled" role="note">
		<Icon name="ShieldAlert" size={14} />
		<span>{disabledMessage ?? t('chat.composer.announcementDisabled')}</span>
	</div>
{:else}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<!-- Whole-pane drag-drop convenience only (M9) — the real keyboard/screen-reader
	     accessible attach path is the Paperclip button + hidden file input below. -->
	<div
		class="composer"
		class:composer--dragover={dragCounter > 0}
		ondragenter={handleDragEnter}
		ondragover={handleDragOver}
		ondragleave={handleDragLeave}
		ondrop={handleDrop}
	>
		{#if broadcast}
			<div class="composer__broadcast">
				<span>{t('chat.composer.broadcastLabel', { target: broadcast })}</span>
				<button type="button" class="composer__broadcast-clear" aria-label={t('chat.composer.broadcastClear')} onclick={() => (broadcast = null)}>
					<Icon name="X" size={12} />
				</button>
			</div>
		{/if}
		{#if mentionOpen}
			<ul class="composer__mentions" role="listbox" aria-label="@mentions">
				{#each mentionCandidates as cand, i (cand.key)}
					<li>
						<button
							type="button"
							class="composer__mention-item"
							class:active={i === mentionIndex}
							role="option"
							aria-selected={i === mentionIndex}
							onclick={() => selectMention(cand)}
						>
							<span class="composer__mention-name">@{cand.label}</span>
							{#if cand.external}
								<Badge label={t('chat.externalBadge')} />
							{/if}
							{#if cand.removed}
								<Badge label={t('chat.removedBadge')} variant="warning" />
							{/if}
							{#if !cand.external && !cand.removed && cand.hint}
								<span class="composer__mention-hint">{cand.hint}</span>
							{/if}
						</button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if chatStore.attachmentsEnabled && pending.length > 0}
			<ul class="composer__attachments" role="list" aria-label={t('chat.attach.list')}>
				{#each pending as p (p.clientId)}
					<li class="composer__attachment" class:composer__attachment--failed={p.status === 'failed'}>
						<Icon name="FileText" size={16} />
						<span class="composer__attachment-name">{p.name}</span>
						<span class="composer__attachment-size">{formatBytes(p.size)}</span>
						{#if p.status === 'failed'}
							<span class="composer__attachment-error">{p.error}</span>
							<button
								type="button"
								class="composer__attachment-btn"
								aria-label={t('chat.attach.retry', { name: p.name })}
								onclick={() => chatStore.retryAttachment(channelId, parentId, p.clientId)}
							>
								<Icon name="RotateCcw" size={14} />
							</button>
						{:else if p.status !== 'ready'}
							<Progress value={p.progress} max={p.size} label={t('chat.attach.uploading', { done: String(p.progress), total: String(p.size) })} />
						{/if}
						<button
							type="button"
							class="composer__attachment-btn"
							aria-label={t('chat.attach.remove', { name: p.name })}
							onclick={() => {
								// A3 QoL Task 15: removing the voice chip specifically must
								// also drop the pending voice-send intent, or Send would
								// route into sendVoice() for an attachment that no longer exists.
								if (p.clientId === voiceClientId) {
									voiceClientId = null;
									voiceDurationMs = null;
								}
								chatStore.removeAttachment(channelId, parentId, p.clientId);
							}}
						>
							<Icon name="X" size={14} />
						</button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if capNotice}
			<span class="composer__cap-notice" role="status">{t('chat.attach.capReached')}</span>
		{/if}
		{#if scheduledForChannel.length > 0}
			<button type="button" class="composer__scheduled-chip" onclick={() => (queueOpen = true)}>
				{scheduledForChannel.length === 1 ? t('chat.schedule.chipOne') : t('chat.schedule.chip', { n: String(scheduledForChannel.length) })}
			</button>
		{/if}
		{#if recording}
			<div class="composer__recording" role="status">
				<span class="composer__recording-dot" aria-hidden="true"></span>
				<span>{formatElapsed(recordingElapsedMs)}</span>
				{#if VOICE_CAP_MS - recordingElapsedMs <= 30_000}
					<span class="composer__recording-cap">
						{t('chat.voice.capCountdown', { s: String(Math.max(0, Math.ceil((VOICE_CAP_MS - recordingElapsedMs) / 1000))) })}
					</span>
				{/if}
				<button type="button" class="composer__attachment-btn" aria-label={t('chat.voice.cancel')} onclick={cancelRecording}>
					<Icon name="X" size={14} />
				</button>
			</div>
		{/if}
		<div class="composer__row">
			<textarea
				bind:this={taEl}
				data-testid="composer-input"
				class="composer__textarea"
				rows="1"
				placeholder={parentId != null ? t('chat.composer.placeholderThread') : t('chat.composer.placeholder')}
				{value}
				oninput={handleInput}
				onkeydown={handleKeydown}
				onpaste={handlePaste}
			></textarea>
			{#if chatStore.attachmentsEnabled}
				<input
					type="file"
					multiple
					hidden
					bind:this={fileInputEl}
					onchange={handleFileInputChange}
					data-testid="composer-file-input"
				/>
				<button
					type="button"
					class="composer__icon-btn"
					aria-label={t('chat.attach.button')}
					title={noAttachments ? t('chat.federation.attachDisabled') : undefined}
					disabled={pending.length >= MAX_ATTACHMENTS || noAttachments}
					onclick={pickFiles}
				>
					<Icon name="Paperclip" size={16} />
				</button>
				<button
					type="button"
					class="composer__icon-btn"
					aria-label={recording ? t('chat.voice.stop') : t('chat.voice.record')}
					aria-pressed={recording}
					title={noAttachments ? t('chat.federation.attachDisabled') : undefined}
					disabled={noAttachments}
					onclick={() => void toggleRecording()}
				>
					<Icon name={recording ? 'Square' : 'Mic'} size={16} />
				</button>
			{/if}
			<div class="composer__plus-wrap">
				<button
					type="button"
					class="composer__icon-btn"
					aria-label={t('chat.composer.addMenu')}
					aria-haspopup="menu"
					aria-expanded={plusOpen}
					onclick={() => (plusOpen = !plusOpen)}
				>
					<Icon name="Plus" size={16} />
				</button>
				{#if plusOpen}
					<div class="composer__plus-menu" role="menu">
						<button
							type="button"
							class="composer__menu-item"
							role="menuitem"
							disabled={noAttachments}
							title={noAttachments ? t('chat.federation.attachDisabled') : undefined}
							onclick={openPollDialog}
						>
							{t('chat.poll.create')}
						</button>
					</div>
				{/if}
			</div>
			<div class="composer__emoji-wrap">
				<button type="button" class="composer__icon-btn" aria-label={t('chat.composer.emoji')} onclick={() => (emojiOpen = !emojiOpen)}>
					<Icon name="Smile" size={16} />
				</button>
				{#if emojiOpen}
					<div class="composer__emoji-popover" role="menu">
						{#each COMMON_EMOJI as emoji (emoji)}
							<button type="button" class="composer__emoji-btn" role="menuitem" onclick={() => insertEmoji(emoji)}>{emoji}</button>
						{/each}
					</div>
				{/if}
			</div>
			<div class="composer__send-wrap">
				<button
					type="button"
					class="composer__send"
					aria-label={uploading ? uploadAnnouncement : t('chat.composer.send')}
					disabled={uploading || recording}
					aria-disabled={uploading || recording}
					onclick={() => void submit()}
				>
					<Icon name="Send" size={16} />
				</button>
				<button
					type="button"
					class="composer__send-caret"
					aria-label={t('chat.schedule.sendLater')}
					aria-haspopup="menu"
					aria-expanded={scheduleMenuOpen}
					disabled={uploading || recording}
					onclick={() => (scheduleMenuOpen = !scheduleMenuOpen)}
				>
					<Icon name="ChevronDown" size={12} />
				</button>
				{#if scheduleMenuOpen}
					<div class="composer__schedule-menu" role="menu">
						<button type="button" class="composer__menu-item" role="menuitem" onclick={() => void scheduleIn1h()}>{t('chat.schedule.in1h')}</button>
						<button type="button" class="composer__menu-item" role="menuitem" onclick={() => void scheduleTomorrowMorning()}>{t('chat.schedule.tomorrow')}</button>
						<button type="button" class="composer__menu-item" role="menuitem" onclick={openCustomSchedule}>{t('chat.schedule.custom')}</button>
					</div>
				{/if}
			</div>
		</div>
		<div aria-live="polite" class="sr-only">{uploadAnnouncement}</div>
		<div aria-live="polite" class="sr-only">{recording ? t('chat.voice.recordingAnnounce') : ''}</div>
	</div>
{/if}

{#if pollDialogOpen}
	<Dialog open title={t('chat.poll.createTitle')} onClose={() => (pollDialogOpen = false)}>
		{#snippet children()}
			<div class="composer__poll-form">
				<label class="composer__poll-field">
					<span>{t('chat.poll.question')}</span>
					<input class="composer__poll-input" bind:value={pollQuestion} />
				</label>
				{#each pollOptions as _, i}
					<label class="composer__poll-field">
						<span>{t('chat.poll.option', { n: String(i + 1) })}</span>
						<input class="composer__poll-input" bind:value={pollOptions[i]} />
					</label>
				{/each}
				<button type="button" class="composer__btn" onclick={() => (pollOptions = [...pollOptions, ''])}>
					{t('chat.poll.addOption')}
				</button>
				<label class="composer__poll-multi">
					<input type="checkbox" bind:checked={pollMulti} />
					{t('chat.poll.allowMulti')}
				</label>
			</div>
		{/snippet}
		{#snippet footer()}
			<button type="button" class="composer__btn" onclick={() => (pollDialogOpen = false)}>{t('common.cancel')}</button>
			<button type="button" class="composer__send" disabled={!canSubmitPoll} onclick={() => void submitPoll()}>
				{t('chat.poll.create')}
			</button>
		{/snippet}
	</Dialog>
{/if}

{#if customScheduleOpen}
	<Dialog open title={t('chat.schedule.customTitle')} onClose={() => (customScheduleOpen = false)}>
		{#snippet children()}
			<label class="composer__poll-field">
				<span>{t('chat.schedule.pickTime')}</span>
				<input type="datetime-local" class="composer__poll-input" bind:value={customFireAt} />
			</label>
			<p class="composer__schedule-tz">{t('chat.schedule.timezone', { tz: Intl.DateTimeFormat().resolvedOptions().timeZone })}</p>
		{/snippet}
		{#snippet footer()}
			<button type="button" class="composer__btn" onclick={() => (customScheduleOpen = false)}>{t('common.cancel')}</button>
			<button type="button" class="composer__send" disabled={!customFireAt} onclick={() => void confirmCustomSchedule()}>
				{t('chat.schedule.confirm')}
			</button>
		{/snippet}
	</Dialog>
{/if}

{#if queueOpen}
	<Dialog open title={t('chat.schedule.queueTitle')} onClose={() => (queueOpen = false)}>
		{#snippet children()}
			{#if scheduledForChannel.length === 0}
				<p>{t('chat.schedule.empty')}</p>
			{:else}
				<ul class="composer__queue-list">
					{#each scheduledForChannel as s (s.actionId)}
						<li class="composer__queue-item" class:composer__queue-item--failed={s.status === 'failed'}>
							{#if s.status === 'failed'}
								<span class="composer__queue-badge">{t('chat.schedule.failed')}</span>
								<span class="composer__queue-reason">{scheduleFailureReason(s.failureCode)}</span>
							{/if}
							<p class="composer__queue-body">{s.body}</p>
							<span class="composer__queue-time">{new Date(s.fireAt).toLocaleString()}</span>
							<button
								type="button"
								class="composer__attachment-btn"
								aria-label={t('common.cancel')}
								onclick={() => void chatStore.cancelScheduled(s.actionId)}
							>
								<Icon name="X" size={14} />
							</button>
						</li>
					{/each}
				</ul>
			{/if}
		{/snippet}
	</Dialog>
{/if}

<style>
	.composer {
		position: relative;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-2) var(--space-3);
		border-top: 1px solid var(--border-default);
		background: var(--surface-card);
	}
	.composer--disabled {
		flex-direction: row;
		align-items: center;
		gap: var(--space-2);
		color: var(--text-caption);
		font-size: var(--text-sm);
		min-height: 44px;
	}
	.composer__row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.composer__textarea {
		flex: 1;
		min-height: 44px;
		max-height: 200px;
		resize: vertical;
		padding: var(--space-2) var(--space-3);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		line-height: var(--leading-normal);
		color: var(--text-primary);
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}
	.composer__textarea:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.composer__emoji-wrap {
		position: relative;
		display: inline-flex;
	}
	.composer__icon-btn,
	.composer__send {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.composer__send {
		background: var(--accent);
		color: var(--text-inverse);
	}
	.composer__icon-btn:hover {
		background: var(--surface-hover);
	}
	.composer__send:hover {
		filter: brightness(1.05);
	}
	.composer__emoji-popover {
		position: absolute;
		bottom: calc(100% + 4px);
		right: 0;
		z-index: 20;
		display: flex;
		gap: 2px;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.composer__emoji-btn {
		min-height: 44px;
		min-width: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-lg);
		cursor: pointer;
	}
	.composer__emoji-btn:hover {
		background: var(--surface-hover);
	}
	.composer__broadcast {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}
	.composer__broadcast-clear {
		display: inline-flex;
		min-height: 44px;
		min-width: 44px;
		align-items: center;
		justify-content: center;
		border: none;
		background: transparent;
		color: inherit;
		cursor: pointer;
	}
	.composer__mentions {
		position: absolute;
		bottom: 100%;
		left: var(--space-3);
		right: var(--space-3);
		z-index: 20;
		list-style: none;
		margin: 0 0 4px;
		padding: 4px;
		max-height: 240px;
		overflow-y: auto;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.composer__mention-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		width: 100%;
		min-height: 44px;
		padding: 0 var(--space-2);
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
		cursor: pointer;
		text-align: left;
	}
	.composer__mention-item.active,
	.composer__mention-item:hover {
		background: var(--surface-hover);
	}
	.composer__mention-hint {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	/* ── attachments (Chat A2 Task 8) ──────────────────────────────────── */
	/* Svelte scopes styles per-component, so the aria-live announcer's sr-only
	   class must be defined here (not inherited) or the status text renders
	   visibly. Mirrors MessageList's own scoped copy. */
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}
	.composer--dragover {
		outline: 2px dashed var(--accent);
		outline-offset: -4px;
		background: var(--surface-selected);
	}
	.composer__attachments {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.composer__attachment {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-height: 44px;
		padding: var(--space-1) var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		font-size: var(--text-sm);
	}
	.composer__attachment--failed {
		border-color: var(--danger-solid);
		background: var(--danger-bg);
	}
	.composer__attachment-name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--text-primary);
	}
	.composer__attachment-size {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		white-space: nowrap;
	}
	.composer__attachment-error {
		font-size: var(--text-2xs);
		color: var(--danger-fg);
	}
	.composer__attachment-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.composer__attachment-btn:hover {
		background: var(--surface-hover);
	}
	.composer__cap-notice {
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}

	/* ── shared bordered button (poll/schedule dialog footers) — A3 QoL Task 15 ── */
	.composer__btn {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 36px;
		border: 1px solid var(--border-default);
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-xs);
		padding: 0 var(--space-2);
	}
	.composer__btn:hover {
		background: var(--surface-hover);
	}

	/* ── voice recording — A3 QoL Task 15 ─────────────────────────────────── */
	.composer__recording {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.composer__recording-dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: var(--danger-solid);
	}
	.composer__recording-cap {
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}

	/* ── "+" menu / send-later menu — A3 QoL Task 15 ─────────────────────── */
	.composer__plus-wrap,
	.composer__send-wrap {
		position: relative;
		display: inline-flex;
	}
	.composer__plus-menu,
	.composer__schedule-menu {
		position: absolute;
		bottom: calc(100% + 4px);
		right: 0;
		z-index: 20;
		display: flex;
		flex-direction: column;
		min-width: 180px;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.composer__menu-item {
		display: flex;
		align-items: center;
		min-height: 36px;
		padding: 0 var(--space-2);
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
		cursor: pointer;
		text-align: left;
	}

	@media (pointer: coarse) {
		.composer__menu-item {
			min-height: 44px;
		}
	}
	.composer__menu-item:hover {
		background: var(--surface-hover);
	}
	.composer__send-caret {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 20px;
		min-height: 44px;
		border: none;
		background: var(--accent);
		color: var(--text-inverse);
		cursor: pointer;
		border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
	}
	.composer__send-caret:hover {
		filter: brightness(1.05);
	}

	/* ── poll create form / schedule dialogs — A3 QoL Task 15 ────────────── */
	.composer__poll-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.composer__poll-field {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.composer__poll-input {
		min-height: 36px;
		padding: 0 var(--space-2);
		font-size: var(--text-sm);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.composer__poll-multi {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.composer__schedule-tz {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}

	/* ── scheduled-queue chip + dialog — A3 QoL Task 15 ──────────────────── */
	.composer__scheduled-chip {
		align-self: flex-start;
		display: inline-flex;
		align-items: center;
		min-height: 28px;
		border: 1px solid var(--border-default);
		background: var(--surface-sunken);
		border-radius: var(--radius-full);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.composer__scheduled-chip:hover {
		background: var(--surface-hover);
	}
	.composer__queue-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.composer__queue-item {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.composer__queue-item--failed {
		border-color: var(--danger-solid);
		background: var(--danger-bg);
	}
	.composer__queue-badge {
		display: inline-flex;
		align-items: center;
		padding: 0 6px;
		border-radius: var(--radius-sm);
		background: var(--danger-solid);
		color: var(--text-inverse);
		font-size: var(--text-2xs);
		font-weight: 600;
	}
	.composer__queue-reason {
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}
	.composer__queue-body {
		flex-basis: 100%;
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.composer__queue-time {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
</style>
