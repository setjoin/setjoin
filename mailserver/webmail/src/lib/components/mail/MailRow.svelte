<svelte:options runes={true} />
<script lang="ts">
	import { Tag, IconButton } from '$lib/components/ui';
	import type { TagColor } from '$lib/components/ui/tag';
	import Icon from '$lib/components/Icon.svelte';
	import PersonCard from '$lib/components/PersonCard.svelte';
	import SnoozePicker from '$lib/components/SnoozePicker.svelte';
	import { t, localeCode } from '$lib/i18n';
	import { sanitizeSnippet } from '$lib/mail/searchSnippet';
	import { getOpenSwipeRowId, setOpenSwipeRowId } from './mailRowSwipe.svelte';
	import type { Email, Mailbox } from '$lib/types/jmap';
	import type { MailWorkStatus } from '$lib/mail/mailWork';

	interface Props {
		email: Email;
		/** Resolved tag mailboxes — up to the first 2 are rendered as chips. */
		tags: Mailbox[];
		selected: boolean;
		onOpen: () => void;
		onArchive: () => void;
		onStar: () => void;
		onTrash: () => void;
		/** Mark read/unread toggle — receives the desired read state (rendered only when provided). */
		onToggleRead?: (read: boolean) => void;
		/** Scheduled send timestamp (ISO). When set, displayed instead of receivedAt. */
		sendAt?: string;
		/** Cancel-scheduled callback. When set, a Cancel IconButton is shown. */
		onCancel?: () => void;
		/** Whether this row is currently in the Other pile (Focused/Other split, V078). */
		isOther?: boolean;
		/** Move to Focused/Other (V078). Receives the desired `focused` state. When set, a
		 *  move IconButton is shown whose label flips on {@link isOther}. */
		onMoveFocus?: (focused: boolean) => void;
		/** When set, rendered as data-tour on the row root (onboarding anchor). */
		tour?: string;
		/** Swipe/long-press action tray "Snooze" button (QoL #2). Receives the
		 *  chosen date from the inline SnoozePicker. Omitted → no Snooze in the tray. */
		onSnooze?: (date: Date) => void;
		/** Reducer-authored shared-mailbox work state for this thread. */
		workStatus?: MailWorkStatus;
	}

	let { email, tags, selected, onOpen, onArchive, onStar, onTrash, onToggleRead, sendAt, onCancel, isOther = false, onMoveFocus, tour, onSnooze, workStatus }: Props = $props();

	const unread = $derived(!email.keywords?.['$seen']);

	const senderName = $derived(
		email.from && email.from.length > 0
			? (email.from[0].name || email.from[0].email || 'Unknown')
			: 'Unknown',
	);

	const senderEmail = $derived(email.from?.[0]?.email ?? '');

	const subject = $derived(email.subject || '(no subject)');
	// SP1 P5 (D-F1): an encrypted message never shows a plaintext snippet — the
	// body is encrypted-at-rest, so the list shows a Lock placeholder instead of a
	// blank row (and the preview, NULL server-side, is never leaked).
	const isEncrypted = $derived(email.cryptoType === 'smime-encrypted');
	const snippet = $derived(isEncrypted ? '' : (email.preview ?? ''));

	/** Format ISO timestamp to a short display string (mono). */
	function formatTime(iso: string | undefined): string {
		if (!iso) return '';
		const d = new Date(iso);
		if (isNaN(d.getTime())) return '';
		const now = new Date();
		const isToday =
			d.getFullYear() === now.getFullYear() &&
			d.getMonth() === now.getMonth() &&
			d.getDate() === now.getDate();
		if (isToday) {
			return d.toLocaleTimeString(localeCode(), { hour: '2-digit', minute: '2-digit', hour12: false });
		}
		return d.toLocaleDateString(localeCode(), { month: 'short', day: 'numeric' });
	}

	const timestamp = $derived(formatTime(sendAt ?? email.receivedAt));

	// Only render the first 2 tags
	const visibleTags = $derived(tags.slice(0, 2));

	function handleRowClick(e: MouseEvent) {
		// Don't open when clicking the hover cluster buttons
		const target = e.target as HTMLElement;
		if (target.closest('.sj-mailrow__cluster')) return;
		// Tapping an already-revealed row (swipe tray open) snaps it back instead
		// of opening the message — matches iOS reveal-buttons behavior.
		if (revealed) {
			closeTray();
			return;
		}
		onOpen();
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			onOpen();
		}
	}

	function handleArchive(e: MouseEvent) {
		e.stopPropagation();
		onArchive();
	}

	function handleStar(e: MouseEvent) {
		e.stopPropagation();
		onStar();
	}

	function handleTrash(e: MouseEvent) {
		e.stopPropagation();
		onTrash();
	}

	function handleCancel(e: MouseEvent) {
		e.stopPropagation();
		onCancel?.();
	}

	function handleMoveFocus(e: MouseEvent) {
		e.stopPropagation();
		// Row in Other → move to Focused (focused=true); row in Focused → move to Other.
		onMoveFocus?.(isOther);
	}

	function handleToggleRead(e: MouseEvent) {
		e.stopPropagation();
		// `unread` is the current state; clicking sets read = unread (read it now)
		// or unread = !unread (mark a read one back to unread).
		onToggleRead?.(unread);
	}

	// ── Swipe-to-reveal action tray (QoL #2, touch only) ──
	// ponytail: fixed tray width rather than measuring the tray DOM node — the
	// tray is always exactly 3 buttons at a fixed size; revisit with
	// bind:clientWidth if the tray ever gets a variable button count.
	const TRAY_WIDTH = 168;
	const LONG_PRESS_MS = 600;
	const DRAG_THRESHOLD = 4;

	let revealed = $state(false);
	let dragging = $state(false);
	let dragX = $state(0); // live pointer-move offset while dragging
	let showSnoozePicker = $state(false);
	let startX = 0;
	let startY = 0;
	let pointerId: number | null = null;
	let longPressTimer: ReturnType<typeof setTimeout> | undefined;

	// Another row revealing itself (or a scroll, which resets the shared id to
	// null) snaps this row back. Only watches `revealed` (a row that has
	// actually committed open, via openTray() setting the shared id to its own
	// email.id) — an in-progress drag hasn't touched the shared id yet, so it
	// must NOT be closed here just because the id doesn't (yet) match.
	$effect(() => {
		if (revealed && getOpenSwipeRowId() !== email.id) {
			revealed = false;
			showSnoozePicker = false;
		}
	});

	function clampDrag(dx: number): number {
		const base = revealed ? -TRAY_WIDTH : 0;
		return Math.max(-TRAY_WIDTH, Math.min(0, base + dx));
	}

	function clearLongPress() {
		if (longPressTimer !== undefined) {
			clearTimeout(longPressTimer);
			longPressTimer = undefined;
		}
	}

	function openTray() {
		revealed = true;
		dragging = false;
		dragX = 0;
		setOpenSwipeRowId(email.id);
	}

	function closeTray() {
		revealed = false;
		dragging = false;
		dragX = 0;
		showSnoozePicker = false;
		if (getOpenSwipeRowId() === email.id) setOpenSwipeRowId(null);
	}

	function handlePointerDown(e: PointerEvent) {
		if (e.pointerType !== 'touch') return;
		pointerId = e.pointerId;
		startX = e.clientX;
		startY = e.clientY;
		dragging = false;
		clearLongPress();
		longPressTimer = setTimeout(() => {
			longPressTimer = undefined;
			openTray();
		}, LONG_PRESS_MS);
	}

	function handlePointerMove(e: PointerEvent) {
		if (e.pointerId !== pointerId) return;
		const dx = e.clientX - startX;
		const dy = e.clientY - startY;
		if (!dragging) {
			if (Math.abs(dx) < DRAG_THRESHOLD && Math.abs(dy) < DRAG_THRESHOLD) return;
			// A real drag (in either axis) is not a long-press — cancel the timer.
			clearLongPress();
			if (Math.abs(dy) > Math.abs(dx)) return; // vertical scroll — let the browser handle it
			dragging = true;
			(e.currentTarget as Element).setPointerCapture?.(e.pointerId);
		}
		dragX = clampDrag(dx);
	}

	function handlePointerUp(e: PointerEvent) {
		if (e.pointerId !== pointerId) return;
		clearLongPress();
		pointerId = null;
		if (!dragging) return;
		dragging = false;
		// Reveal+tap only: crossing half the tray width snaps fully open, otherwise
		// snaps fully back — a full-width drag never auto-commits an action.
		if (dragX <= -TRAY_WIDTH / 2) {
			openTray();
		} else {
			closeTray();
		}
	}

	function handlePointerCancel(e: PointerEvent) {
		if (e.pointerId !== pointerId) return;
		clearLongPress();
		pointerId = null;
		dragging = false;
		dragX = 0;
		if (!revealed) closeTray();
	}

	const trayOpen = $derived(revealed || dragging);
	const translateX = $derived(dragging ? dragX : revealed ? -TRAY_WIDTH : 0);

	function commitArchive() {
		onArchive();
		closeTray();
	}

	function commitTrash() {
		onTrash();
		closeTray();
	}

	function handleSnoozeSelect(date: Date) {
		onSnooze?.(date);
		closeTray();
	}
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
	class="sj-mailrow"
	class:sj-mailrow--selected={selected}
	role="button"
	tabindex="0"
	aria-label={`${unread ? 'Unread, ' : ''}message from ${senderName}: ${subject}${timestamp ? `, ${timestamp}` : ''}`}
	onclick={handleRowClick}
	onkeydown={handleKeyDown}
	onpointerdown={handlePointerDown}
	onpointermove={handlePointerMove}
	onpointerup={handlePointerUp}
	onpointercancel={handlePointerCancel}
	data-tour={tour}
>
	<!-- Swipe action tray (QoL #2, touch only): sits behind the inner content,
	     revealed by translating the inner wrapper left. Only mounted while
	     revealed/dragging so it never enters the tab order when hidden. -->
	{#if trayOpen}
		<div class="sj-mailrow__swipe-tray" aria-hidden={!revealed}>
			{#if onSnooze}
				<span class="sj-mailrow__snooze-anchor">
					<IconButton
						label="Snooze"
						size="sm"
						tabindex={revealed ? 0 : -1}
						onclick={(e) => { e.stopPropagation(); showSnoozePicker = !showSnoozePicker; }}
					>
						<Icon name="Clock" size={16} strokeWidth={1.75} />
					</IconButton>
					{#if showSnoozePicker}
						<div class="sj-mailrow__snooze-popover" role="dialog" aria-label="Snooze options">
							<SnoozePicker onSelect={handleSnoozeSelect} onClose={() => (showSnoozePicker = false)} />
						</div>
					{/if}
				</span>
			{/if}
			<IconButton
				label="Archive"
				size="sm"
				tabindex={revealed ? 0 : -1}
				onclick={(e) => { e.stopPropagation(); commitArchive(); }}
			>
				<Icon name="Archive" size={16} strokeWidth={1.75} />
			</IconButton>
			<IconButton
				label="Trash"
				size="sm"
				tabindex={revealed ? 0 : -1}
				onclick={(e) => { e.stopPropagation(); commitTrash(); }}
			>
				<Icon name="Trash2" size={16} strokeWidth={1.75} />
			</IconButton>
		</div>
	{/if}

	<div
		class="sj-mailrow__inner"
		class:sj-mailrow__inner--dragging={dragging}
		style={`transform: translateX(${translateX}px)`}
	>
	<!-- Line 1: dot + sender + paperclip + timestamp -->
	<div class="sj-mailrow__line1">
		<span
			class="sj-mailrow__dot"
			data-unread={unread ? 'true' : 'false'}
			aria-hidden="true"
		></span>
		<span class="sj-mailrow__sender" data-unread={unread ? 'true' : 'false'}>
			{#if senderEmail}
				<PersonCard email={senderEmail} name={senderName} />
			{:else}
				{senderName}
			{/if}
		</span>
		<div class="sj-mailrow__time-row">
			{#if email.smimeStatus === 'valid'}
				<span class="sj-mailrow__verified" aria-label={t('inbox.smime_verified')} title={t('inbox.smime_verified')}>
					<Icon name="ShieldCheck" size={12} strokeWidth={1.75} />
				</span>
			{/if}
			{#if email.hasAttachment}
				<span class="sj-mailrow__paperclip" aria-label="Has attachment">
					<Icon name="Paperclip" size={12} strokeWidth={1.75} />
				</span>
			{/if}
			<span class="sj-mailrow__time" data-unread={unread ? 'true' : 'false'}>
				{timestamp}
			</span>
		</div>
	</div>

	<!-- Line 2: subject (search-highlighted when a snippet is present) -->
	<div class="sj-mailrow__subject" data-unread={unread ? 'true' : 'false'}>
		{#if email.searchSubject}
			<!-- @html is safe: sanitizeSnippet escapes everything, re-allows only <mark> -->
			<!-- eslint-disable-next-line svelte/no-at-html-tags -->
			{@html sanitizeSnippet(email.searchSubject)}
		{:else}
			{subject}
		{/if}
	</div>

	<!-- Line 3: snippet + tag chips + hover cluster -->
	<div class="sj-mailrow__line3">
		{#if isEncrypted}
			<span class="sj-mailrow__encrypted">
				<Icon name="Lock" size={12} strokeWidth={1.75} class="sj-mailrow__lock" />
				<span class="sj-mailrow__encrypted-text">{t('inbox.encrypted_placeholder')}</span>
			</span>
		{:else if email.searchPreview}
			<!-- @html is safe: sanitizeSnippet escapes everything, re-allows only <mark> -->
			<!-- eslint-disable-next-line svelte/no-at-html-tags -->
			<span class="sj-mailrow__snippet">{@html sanitizeSnippet(email.searchPreview)}</span>
		{:else}
			<span class="sj-mailrow__snippet">{snippet}</span>
		{/if}
		{#if visibleTags.length > 0}
			<span class="sj-mailrow__chips">
				{#each visibleTags as tag (tag.id)}
					<Tag label={tag.name} color={(tag.color as TagColor) ?? 'gray'} size="sm" dot={false} />
				{/each}
			</span>
		{/if}
		{#if workStatus}
			<span class="sj-mailrow__work" data-status={workStatus} aria-label={`${t('inbox.work.status')}: ${t(`inbox.work.${workStatus}`)}`}>
				<span aria-hidden="true"></span>{t(`inbox.work.${workStatus}`)}
			</span>
		{/if}
	</div>

	<!-- Hover action cluster: floating bottom-right -->
	<div class="sj-mailrow__cluster">
		<IconButton label="Archive" size="sm" onclick={handleArchive}>
			<Icon name="Archive" size={14} strokeWidth={1.75} />
		</IconButton>
		<IconButton
			label={email.keywords?.['$flagged'] ? 'Unstar' : 'Star'}
			size="sm"
			active={!!email.keywords?.['$flagged']}
			onclick={handleStar}
		>
			<Icon name="Star" size={14} strokeWidth={1.75} />
		</IconButton>
		<IconButton label="Trash" size="sm" onclick={handleTrash}>
			<Icon name="Trash2" size={14} strokeWidth={1.75} />
		</IconButton>
		{#if onMoveFocus}
			<IconButton
				label={isOther ? 'Move to Focused' : 'Move to Other'}
				size="sm"
				onclick={handleMoveFocus}
			>
				<Icon name="ArrowLeftRight" size={14} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if onToggleRead}
			<IconButton
				label={unread ? t('triage.mark_read') : t('triage.mark_unread')}
				size="sm"
				onclick={handleToggleRead}
			>
				<Icon name={unread ? 'MailOpen' : 'Mail'} size={14} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if onCancel}
			<IconButton label="Cancel send" size="sm" onclick={handleCancel}>
				<Icon name="X" size={14} strokeWidth={1.75} />
			</IconButton>
		{/if}
	</div>
	</div>
</div>

<style>
	.sj-mailrow {
		display: flex;
		flex-direction: column;
		gap: 3px;
		padding: 9px 12px;
		cursor: pointer;
		border-bottom: 1px solid var(--border-subtle);
		position: relative;
		background: transparent;
		user-select: none;
		overflow: hidden;
		/* Swipe reveal (QoL #2) is a horizontal gesture — leave vertical panning
		   (list scroll) to the browser; JS owns the horizontal axis. */
		touch-action: pan-y;
	}

	.sj-mailrow:hover {
		background: var(--surface-hover);
	}

	.sj-mailrow--selected {
		background: var(--surface-selected);
	}

	.sj-mailrow--selected:hover {
		background: var(--surface-selected);
	}

	.sj-mailrow:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* Inner content wrapper — slides left via translateX to reveal the swipe
	   tray sitting behind it. Same background as the row so it fully occludes
	   the tray when not revealed. */
	.sj-mailrow__inner {
		display: flex;
		flex-direction: column;
		gap: 3px;
		background: var(--surface-card);
		transition: transform var(--duration-fast, 150ms) var(--ease-out, ease-out);
	}

	.sj-mailrow__inner--dragging {
		transition: none;
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-mailrow__inner {
			transition: none;
		}
	}

	/* Swipe action tray — fixed-width, right-anchored, sits behind __inner. */
	.sj-mailrow__swipe-tray {
		position: absolute;
		top: 0;
		right: 0;
		bottom: 0;
		width: 168px;
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 6px;
		padding: 0 10px;
		background: var(--surface-sunken);
	}

	.sj-mailrow__snooze-anchor {
		position: relative;
		display: inline-flex;
	}

	.sj-mailrow__snooze-popover {
		position: absolute;
		bottom: 100%;
		right: 0;
		z-index: 50;
		margin-bottom: 4px;
	}

	/* Line 1 */
	.sj-mailrow__line1 {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.sj-mailrow__dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		flex: none;
		background: transparent;
	}

	.sj-mailrow__dot[data-unread='true'] {
		background: var(--accent);
	}

	.sj-mailrow__sender {
		flex: 1;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium); /* 500 for read */
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-mailrow__sender[data-unread='true'] {
		font-weight: 600;
	}

	.sj-mailrow__time-row {
		display: flex;
		align-items: center;
		gap: 4px;
		flex: none;
	}

	.sj-mailrow__verified {
		color: var(--success-fg);
		display: inline-flex;
		align-items: center;
	}

	.sj-mailrow__paperclip {
		color: var(--text-tertiary);
		display: inline-flex;
		align-items: center;
	}

	.sj-mailrow__time {
		font-size: var(--text-2xs);
		font-family: var(--font-mono);
		color: var(--text-caption);
		white-space: nowrap;
	}

	.sj-mailrow__time[data-unread='true'] {
		color: var(--text-accent);
	}

	/* Line 2 */
	.sj-mailrow__subject {
		padding-left: 15px; /* aligns past 7px dot + 8px gap */
		font-size: var(--text-sm);
		font-weight: 400;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-mailrow__subject[data-unread='true'] {
		font-weight: 600;
	}

	/* Line 3 */
	.sj-mailrow__line3 {
		padding-left: 15px;
		display: flex;
		align-items: center;
		gap: 6px;
	}

	.sj-mailrow__snippet {
		flex: 1;
		font-size: var(--text-xs);
		color: var(--text-caption);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-mailrow__work {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		flex: none;
		font-size: var(--text-2xs);
		color: var(--text-caption);
		white-space: nowrap;
	}

	.sj-mailrow__work > span {
		width: 7px;
		height: 7px;
		border-radius: var(--radius-full);
		background: var(--gray-500);
	}

	.sj-mailrow__work[data-status='owned'] > span { background: var(--info-fg); }
	.sj-mailrow__work[data-status='waiting'] > span { background: var(--warning-fg); }
	.sj-mailrow__work[data-status='done'] > span { background: var(--success-fg); }

	/* Search-highlight <mark> is {@html}-injected (SearchSnippet/get), so it sits
	   outside Svelte's class-scoping — target it via :global under the row. */
	.sj-mailrow__subject :global(mark),
	.sj-mailrow__snippet :global(mark) {
		background: var(--accent-subtle);
		color: var(--accent-fg-on-subtle);
		border-radius: var(--radius-xs);
		padding: 0 1px;
	}

	/* SP1 P5 (D-F1): encrypted-message Lock placeholder — calm, neutral, never a
	   blank row. Uses the same caption tone as the snippet (no new colours). */
	.sj-mailrow__encrypted {
		flex: 1;
		display: inline-flex;
		align-items: center;
		gap: 4px;
		overflow: hidden;
		color: var(--text-caption);
	}

	.sj-mailrow__encrypted-text {
		font-size: var(--text-xs);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-mailrow__encrypted :global(.sj-mailrow__lock) {
		flex: none;
		color: var(--text-caption);
	}

	.sj-mailrow__chips {
		display: flex;
		gap: 4px;
		align-items: center;
		flex: none;
	}

	/* Hover action cluster */
	.sj-mailrow__cluster {
		position: absolute;
		right: 8px;
		bottom: 6px;
		display: none;
		gap: 2px;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		box-shadow: var(--shadow-sm);
		padding: 2px;
	}

	.sj-mailrow:hover .sj-mailrow__cluster,
	.sj-mailrow:focus-within .sj-mailrow__cluster {
		display: flex;
	}

	/* No-hover (touch) devices: the hover cluster stays hidden — swipe-reveal
	   (.sj-mailrow__swipe-tray) is the touch equivalent (QoL #2, M2 review fix). */
</style>
