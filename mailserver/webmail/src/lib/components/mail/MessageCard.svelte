<svelte:options runes={true} />
<script lang="ts">
	import { get } from 'svelte/store';
	import { IconButton, Avatar, Badge, Menu, Dialog, showToast } from '$lib/components/ui';
	import type { MenuItem } from '$lib/components/ui/Menu.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import EmailAnnotations from '$lib/components/EmailAnnotations.svelte';
	import DeliveryPanel from './delivery/DeliveryPanel.svelte';
	import SenderCard from './SenderCard.svelte';
	import { formatBytes } from '$lib/utils/display';
	import { renderEmailBodyHTML, hasRemoteImages } from '$lib/sanitize';
	import { splitQuotedHTML, splitQuotedText } from '$lib/mail/quoteSplit';
	import { imageTrust } from '$lib/stores/imageTrust.svelte';
	import { isMonoBody } from '$lib/stores/inboxModel';
	import { addressBooks, loadAddressBooks } from '$lib/stores/contacts';
	import { t } from '$lib/i18n';
	import type { Email, Attachment } from '$lib/types/jmap';
	import { effectiveCaps } from '$lib/stores/session';
	import { e5ui } from '$lib/offline/e5ui.svelte';
	import { e5TransferDisplay } from '$lib/offline/e5.uiProjection';

	/**
	 * One message of a conversation, rendered as a collapsible card (Gmail/Outlook
	 * style). Collapsed → a one-line header (avatar, sender, date, preview); expanded
	 * → the full sender block, body, and attachments — identical markup to the old
	 * single-message reading pane, so existing selectors/styles are preserved.
	 *
	 * The card owns its OWN body rendering: per-message HTML sanitization + the
	 * remote-image (tracking-pixel) block state, computed only when expanded. Reply/
	 * forward act on the thread's latest message (per-message reply is out of scope),
	 * so the sender-block actions relay the pane-level handlers; delivery inspection
	 * IS per-message and opens this card's own DeliveryPanel.
	 */
	interface Props {
		email: Email;
		expanded: boolean;
		onToggle: () => void;
		/** JMAP account id — builds attachment download URLs. */
		accountId?: string;
		onReply: () => void;
		onReplyAll?: () => void;
		onForward: () => void;
		/** Resend after NDR/bounce — surfaced by this card's DeliveryPanel only when bounced>0. */
		onResend?: () => void;
		onVoteResponse?: (option: string) => void;
		/** #13 shared-mailbox use-surface DANGER STATE: read-only shared-mailbox
		 *  grant — Reply/Reply-all/Forward render DISABLED with a tooltip
		 *  (never hidden). See ReadingPane's matching inline-reply gating. */
		composeDisabled?: boolean;
		composeDisabledReason?: string;
	}

	let {
		email,
		expanded,
		onToggle,
		accountId = '',
		onReply,
		onReplyAll,
		onForward,
		onResend,
		onVoteResponse,
		composeDisabled = false,
		composeDisabledReason = '',
	}: Props = $props();

	// Per-card body state — each message tracks its own remote-image opt-in + HTML mode.
	let showRemoteImages = $state(false);
	// Item A escape hatch: the rare false-positive tracker gets loaded anyway, on
	// top of the "load remote images" gate above (still requires images to be
	// loading in the first place — see `allowRemote`).
	let loadEverything = $state(false);
	let htmlMode = $state(false);
	let showDelivery = $state(false);
	// The attachment currently open in the inline preview dialog (image/PDF only).
	let previewAtt = $state<Attachment | null>(null);
	// Quoted-tail visibility (WAVE-5 #6). Per-card; the pill toggles it.
	let showQuoted = $state(false);
	// #11 inline "Add to Contacts": which attachment (by blobId) is mid-import,
	// so the icon-button can show a busy state without a per-card global flag.
	let addingContactBlobId = $state<string | null>(null);

	// Image + PDF preview inline; everything else stays a plain download. v1 is
	// browser-native (no PDF.js) — the gateway serves these Content-Disposition:
	// inline with their real content-type when the ?type override is omitted.
	function isPreviewable(type: string | undefined): boolean {
		const ty = (type || '').toLowerCase();
		return ty.startsWith('image/') || ty === 'application/pdf';
	}

	// #11: a vCard attachment gets an inline "Add to Contacts" alongside download.
	function isVCard(att: Attachment): boolean {
		return att.type === 'text/vcard' || /\.vcf$/i.test(att.name ?? '');
	}

	// POSTs the attachment straight to the existing bulk-import endpoint (handles a
	// single vCard fine) against the caller's first address book, then toasts the
	// {imported,skipped,errors} result. Reuses the same import surface CsvImportModal
	// drives, so jmap_state/push already fire on a successful import.
	async function addToContacts(att: Attachment) {
		if (addingContactBlobId) return;
		addingContactBlobId = att.blobId;
		try {
			if (get(addressBooks).length === 0) await loadAddressBooks();
			const books = get(addressBooks);
			if (books.length === 0) {
				showToast(t('inbox.add_to_contacts_failed'), { variant: 'danger' });
				return;
			}
			const blobRes = await fetch(inlineUrl(att));
			if (!blobRes.ok) throw new Error(`download failed (${blobRes.status})`);
			const blob = await blobRes.blob();
			const form = new FormData();
			form.set('file', blob, att.name ?? 'contact.vcf');
			form.set('addressBookId', String(books[0].id));
			const res = await fetch('/api/contacts/import/vcf', { method: 'POST', body: form });
			const result = await res.json();
			if (!res.ok || result.imported === 0) {
				showToast(t('inbox.add_to_contacts_failed'), { variant: 'danger' });
				return;
			}
			showToast(t('inbox.add_to_contacts_success'), { variant: 'success' });
		} catch {
			showToast(t('inbox.add_to_contacts_failed'), { variant: 'danger' });
		} finally {
			addingContactBlobId = null;
		}
	}

	// Same URL, two intents: inline (no ?type — gateway serves the real content_type
	// as Content-Disposition: inline) for preview; ?type=octet-stream forces download.
	function inlineUrl(att: Attachment): string {
		return `/jmap/download/${accountId}/${att.blobId}/${encodeURIComponent(att.name ?? 'attachment')}`;
	}
	function downloadUrl(att: Attachment): string {
		return `${inlineUrl(att)}?type=application/octet-stream`;
	}

	// ── E5 durable transfer rows (Phase 2 pass 3; R4 terminals) ────────────────
	// Routed ONLY while the connectivity-aware-sync program is active AND the
	// shell proved the durable-transfer capability. Browser anchors stay
	// unchanged otherwise. Row identity is the opaque transfer key (account +
	// blob), never the filename; row STATE arrives from the E3/E4 controller
	// through e5ui — this card can never invent a completion.
	const e5TransfersActive = $derived(e5ui.active && e5ui.durableTransferAvailable);
	function transferKey(blobId: string): string {
		return `${accountId}:${blobId}`;
	}
	function e5RowFor(blobId: string) {
		if (!e5TransfersActive) return null;
		const row = e5ui.transferRow(transferKey(blobId));
		return row === null ? null : e5TransferDisplay({ ...row });
	}
	function startSaveAll(): void {
		if (!e5TransfersActive) return;
		const ids = visibleAttachments.map((att) => transferKey(att.blobId));
		if (ids.length === 0 || e5ui.saveAllGroup(email.id) !== null) return;
		e5ui.createSaveAllGroup(email.id, ids);
		for (const id of ids) e5ui.setTransferRow(id, { state: 'queued' });
	}
	function transferAction(key: string, action: 'resume' | 'cancel' | 'retry'): void {
		e5ui.transferAction(key, action);
	}
	function saveAllCancel(): void {
		const plan = e5ui.cancelSaveAll(email.id);
		if (plan === null) return;
		for (const id of plan.toCancel) {
			// Cancel stops unfinished children WITHOUT deleting completed downloads.
			e5ui.applySaveAllChild(email.id, id, { state: 'cancelled' });
			e5ui.setTransferRow(id, { state: 'cancelled' });
		}
		// ONE group announcement replaces the per-child burst.
		e5ui.announceSaveAllGroup(email.id);
	}
	function saveAllRetry(): void {
		const ids = e5ui.retrySaveAll(email.id);
		for (const id of ids) {
			// Re-queued under CURRENT authorization by the coordinator seam.
			e5ui.applySaveAllChild(email.id, id, { state: 'queued' });
			e5ui.setTransferRow(id, { state: 'queued' });
		}
		e5ui.announceSaveAllGroup(email.id);
	}

	const mono = $derived(isMonoBody(email));
	const senderName = $derived(email.from?.[0]?.name || email.from?.[0]?.email || 'Unknown');
	const senderEmail = $derived(email.from?.[0]?.email ?? '');
	const showExternalLabel = $derived(
		$effectiveCaps.externalLabels && email.isExternal === true,
	);

	// Per-sender remote-image trust (WAVE-5 #5, V091). A trusted sender's remote
	// images auto-load; the trust list only ungates the FETCH — sanitize always
	// still runs (renderEmailBodyHTML → sanitizeHTML below).
	const senderTrusted = $derived(imageTrust.has(senderEmail));
	const allowRemote = $derived(showRemoteImages || senderTrusted);
	$effect(() => {
		if (expanded) void imageTrust.ensureLoaded();
	});

	async function alwaysLoadFromSender() {
		showRemoteImages = true; // load now, regardless of the persist outcome
		try {
			await imageTrust.add(senderEmail);
			// Act-then-undo; the durable undo surface is /settings/privacy.
			showToast(t('inbox.images_always_toast', { sender: senderEmail }), {
				actionLabel: t('common.undo'),
				onAction: () => void imageTrust.remove(senderEmail).catch(() => {})
			});
		} catch {
			showToast(t('inbox.images_always_failed'));
		}
	}

	// SP1 P5 (D-F1): an encrypted message whose decrypt-on-read did NOT succeed shows
	// a calm can't-decrypt panel instead of the body — never a blank pane, never red.
	const cantDecrypt = $derived(
		email.cryptoType === 'smime-encrypted' && email.decryptState !== 'decrypted',
	);

	// Visible (non-inline) attachments for the chip row.
	const visibleAttachments = $derived(
		(email.attachments ?? []).filter((a) => a.disposition !== 'inline'),
	);

	// Per-card sanitized HTML — only computed when the card is expanded (collapsed
	// cards skip the DOMPurify pass). cid-rewrite + sanitize is shared with the print
	// helper via renderEmailBodyHTML (single source of truth). Tracker-image count
	// (Item A) rides along via the out-param, in the SAME sanitize pass.
	const sanitized = $derived.by(() => {
		if (!expanded) return { html: '', trackersBlocked: 0 };
		const out = { trackersBlocked: 0 };
		const html = renderEmailBodyHTML(email, { allowRemoteImages: allowRemote, loadEverything }, out);
		return { html, trackersBlocked: out.trackersBlocked };
	});
	const sanitizedHTML = $derived(sanitized.html);
	const trackersBlocked = $derived(sanitized.trackersBlocked);

	const remoteImagesBlocked = $derived(
		!allowRemote && !!email.bodyHTML && hasRemoteImages(email.bodyHTML),
	);

	// ── Quoted-text collapse (WAVE-5 #6) ──
	// The split runs on the SANITIZED html AFTER the cid rewrite (sanitizedHTML
	// above) — both halves stay sanitized. Plain-text bodies use the trivial
	// `> `-prefix-run splitter. Whole-body quote / no boundary → no pill.
	// GATED on email.bodyHTML (mirrors the existing toggle-button/iframe gate):
	// reading `sanitizedHTML` forces its renderEmailBodyHTML computation even
	// when the card ends up rendering plain text, so every access below only
	// touches it once we already know there IS an html body to render.
	const htmlSplit = $derived.by(() =>
		email.bodyHTML && sanitizedHTML ? splitQuotedHTML(sanitizedHTML) : { main: '', quoted: null },
	);
	const textSplit = $derived.by(() => splitQuotedText(email.bodyText ?? ''));
	// The active mode's quoted tail (null = render no pill).
	const hasQuoted = $derived(
		htmlMode && sanitizedHTML ? htmlSplit.quoted !== null : textSplit.quoted !== null,
	);
	const displayHTML = $derived(
		email.bodyHTML ? (htmlSplit.quoted !== null && !showQuoted ? htmlSplit.main : sanitizedHTML) : '',
	);
	const displayText = $derived(
		textSplit.quoted !== null && !showQuoted ? textSplit.main : (email.bodyText || email.preview || ''),
	);

	// ── Iframe auto-height ──
	// sandbox="" (opaque origin, test-pinned — NEVER allow-same-origin) makes the
	// frame's contentDocument unreadable, so the height comes from a hidden
	// measurer div rendering the SAME sanitized html in the parent DOM.
	// Containment: DOMPurify already sanitized the markup ({@html} does not
	// execute scripts and no event attrs survive the allowlist); height:0 +
	// overflow:hidden + visibility:hidden + contain:paint keep even hypothetical
	// CSS escapes invisible and clipped while scrollHeight still reports the
	// laid-out content height. Re-measures on every content change (expand,
	// quote toggle, image opt-in) + on inline-image loads.
	let measureEl = $state<HTMLDivElement | null>(null);
	let frameHeight = $state(0);
	$effect(() => {
		void displayHTML; // re-run when the rendered content changes
		const el = measureEl;
		if (!el) return;
		const measure = () => {
			// +32 ≈ the srcdoc body's default 8px margins + line-metric slack.
			frameHeight = el.scrollHeight > 0 ? el.scrollHeight + 32 : 0;
		};
		measure();
		// Inline cid images load async and change the height.
		el.addEventListener('load', measure, true);
		return () => el.removeEventListener('load', measure, true);
	});

	// Type icon by content-type (Gmail-style); default the generic file glyph.
	function attachIcon(type: string | undefined): 'Image' | 'Archive' | 'FileText' {
		const ty = (type || '').toLowerCase();
		if (ty.startsWith('image/')) return 'Image';
		if (ty.includes('zip') || ty.includes('tar') || ty.includes('compressed')) return 'Archive';
		return 'FileText';
	}

	function formatDateFull(iso: string | undefined): string {
		if (!iso) return '';
		return new Date(iso).toLocaleString();
	}

	const shortDate = $derived(email.receivedAt ? new Date(email.receivedAt).toLocaleDateString() : '');

	const moreMenuItems: MenuItem[] = [{ id: 'inspect-delivery', label: 'Inspect delivery' }];
	function handleMoreMenuSelect(id: string) {
		if (id === 'inspect-delivery') showDelivery = true;
	}
</script>

<div class="sj-msg-card" class:sj-msg-card--expanded={expanded}>
	{#if expanded}
		<!-- Sender block. The avatar is its OWN trigger (SenderCard people-pane); the
		     name/date area is the collapse toggle — siblings, never nested (a button
		     can't contain a button). -->
		<div class="sj-reading-body__sender">
			<SenderCard name={senderName} email={senderEmail} />
			<button
				class="sj-msg-card__sender-toggle"
				onclick={onToggle}
				aria-expanded="true"
				aria-label="Collapse message"
			>
				<div class="sj-reading-body__sender-info">
					<div class="sj-reading-body__sender-line1">
						<span class="sj-reading-body__sender-name">{senderName}</span>
						{#if showExternalLabel}
							<Badge variant="warning" label={t('mail.external_label')} />
						{/if}
						{#if senderEmail}
							<span class="sj-reading-body__sender-email">&lt;{senderEmail}&gt;</span>
						{/if}
					</div>
					<div class="sj-reading-body__sender-line2">
						<span class="sj-reading-body__sender-to">to me</span>
						<span class="sj-reading-body__sender-dot">·</span>
						<span class="sj-reading-body__sender-date">{formatDateFull(email.receivedAt)}</span>
						{#if email.smimeStatus === 'valid'}
							<span class="sj-reading-body__smime-badge sj-reading-body__smime-badge--verified"
								title={t('inbox.smime_verified_qualifier')}>
								<Icon name="ShieldCheck" size={12} strokeWidth={1.75} />
								<span class="sj-reading-body__smime-signer">{t('inbox.smime_verified')}{#if email.smimeSignerCn || email.smimeSignerEmail} · {email.smimeSignerCn || email.smimeSignerEmail}{/if}</span>
							</span>
						{:else if email.smimeStatus === 'invalid' || email.smimeStatus === 'untrusted'}
							<span class="sj-reading-body__smime-badge">
								<Icon name="Shield" size={12} strokeWidth={1.75} />
								{t('inbox.smime_signed_unverified')}
							</span>
						{/if}
						<!-- SP1 P5 (D-F4): the Lock idiom is DISTINCT from the verified
						     ShieldCheck — a decrypted encrypted message shows the Lock
						     "Encrypted" chip ALONGSIDE (not instead of) a verified badge. -->
						{#if email.cryptoType === 'smime-encrypted' && email.decryptState === 'decrypted'}
							<span class="sj-reading-body__smime-badge sj-reading-body__smime-badge--encrypted"
								title={t('inbox.encrypted_indicator')}>
								<Icon name="Lock" size={12} strokeWidth={1.75} />
								{t('inbox.encrypted_indicator')}
							</span>
						{/if}
					</div>
				</div>
			</button>
			<div class="sj-reading-body__sender-actions">
				<IconButton
					label={composeDisabled ? composeDisabledReason : 'Reply'}
					size="sm"
					disabled={composeDisabled}
					onclick={onReply}
				>
					<Icon name="Reply" size={15} strokeWidth={1.75} />
				</IconButton>
				{#if onReplyAll}
					<IconButton
						label={composeDisabled ? composeDisabledReason : t('triage.reply_all')}
						size="sm"
						disabled={composeDisabled}
						onclick={onReplyAll}
					>
						<Icon name="ReplyAll" size={15} strokeWidth={1.75} />
					</IconButton>
				{/if}
				<IconButton
					label={composeDisabled ? composeDisabledReason : 'Forward'}
					size="sm"
					disabled={composeDisabled}
					onclick={onForward}
				>
					<Icon name="Forward" size={15} strokeWidth={1.75} />
				</IconButton>
				<Menu items={moreMenuItems} onSelect={handleMoreMenuSelect} label="More actions" align="end">
					{#snippet children()}
						<Icon name="MoreHorizontal" size={16} strokeWidth={1.75} />
					{/snippet}
				</Menu>
			</div>
		</div>

		<EmailAnnotations email={email} />

		<!-- Vote buttons -->
		{#if email.voteOptions && email.voteOptions.length > 0}
			<div class="sj-reading-body__votes">
				<span class="sj-reading-body__votes-label">Vote:</span>
				{#each email.voteOptions as option}
					<button class="sj-reading-body__vote-btn" onclick={() => onVoteResponse?.(option)}>
						{option}
					</button>
				{/each}
			</div>
		{/if}

		<!-- Body -->
		<div class="sj-reading-body__content">
			{#if cantDecrypt}
				<!-- SP1 P5 (D-F1): calm can't-decrypt panel — neutral, never red. The
				     two variants explain WHY without alarm; no body / preview shown. -->
				<div class="sj-reading-body__decrypt-state">
					<Icon name="Lock" size={16} strokeWidth={1.75} />
					{#if email.decryptState === 'no_key'}
						<p class="sj-reading-body__decrypt-msg">{t('inbox.decrypt_no_key')}</p>
						<a class="sj-reading-body__decrypt-link" href="/settings/security">{t('inbox.decrypt_no_key_link')}</a>
					{:else if email.decryptState === 'wrong_key'}
						<p class="sj-reading-body__decrypt-msg">{t('inbox.decrypt_wrong_key')}</p>
					{:else}
						<p class="sj-reading-body__decrypt-msg">{t('inbox.decrypt_error')}</p>
					{/if}
				</div>
			{:else}
				{#if email.bodyHTML && sanitizedHTML}
					<button
						class="sj-reading-body__html-toggle"
						aria-pressed={htmlMode}
						onclick={() => (htmlMode = !htmlMode)}
					>
						{htmlMode ? 'Show Plain Text' : 'Show HTML'}
					</button>
				{/if}
				{#if htmlMode && (remoteImagesBlocked || trackersBlocked > 0)}
					<div class="sj-reading-body__remote-banner">
						{#if remoteImagesBlocked}
							<span>Remote images were blocked to protect your privacy.</span>
							<button type="button" onclick={() => (showRemoteImages = true)}>Load images</button>
							{#if senderEmail}
								<button type="button" onclick={alwaysLoadFromSender}>{t('inbox.images_always')}</button>
							{/if}
						{/if}
						{#if trackersBlocked > 0}
							<span>{t('inbox.trackers_blocked', { count: String(trackersBlocked) })}</span>
							{#if !loadEverything}
								<button type="button" onclick={() => (loadEverything = true)}>
									{t('inbox.load_all_images')}
								</button>
							{/if}
						{/if}
					</div>
				{/if}
				{#if htmlMode && sanitizedHTML}
					<!-- Hidden measurer: same sanitized html, parent DOM, contained —
					     drives the sandboxed iframe's auto-height (see the script note). -->
					<div class="sj-msg-card__measurer" aria-hidden="true" bind:this={measureEl}>
						<!-- displayHTML is derived only from renderEmailBodyHTML's sanitized output. -->
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html displayHTML}
					</div>
					<iframe
						class="sj-reading-body__html-frame"
						title="Email HTML content"
						sandbox=""
						srcdoc={displayHTML}
						style:height={frameHeight > 0 ? `${frameHeight}px` : undefined}
					></iframe>
				{:else}
					<div class="sj-reading-body__text" class:sj-reading-body__text--mono={mono}>
						{displayText}
					</div>
				{/if}
				<!-- Quoted-text pill (WAVE-5 #6): a REAL button in the parent DOM below
				     the iframe — sandbox="" kills injected in-body buttons, and
				     allow-scripts would breach the XSS barrier. Focus stays on the
				     button across toggles (the element never unmounts). -->
				{#if hasQuoted}
					<button
						type="button"
						class="sj-msg-card__quote-toggle"
						aria-expanded={showQuoted}
						onclick={() => (showQuoted = !showQuoted)}
					>
						<Icon name={showQuoted ? 'ChevronUp' : 'ChevronDown'} size={13} strokeWidth={1.75} />
						{showQuoted ? t('inbox.hide_quoted') : t('inbox.show_quoted')}
					</button>
				{/if}
			{/if}
		</div>

		<!-- Attachments — previewable types (image/PDF) open an inline dialog; the rest
		     stay native download anchors (keyboard-operable; the gateway forces
		     Content-Disposition: attachment via the ?type override). E5: while the
		     connectivity-aware program is active with a proven durable-transfer
		     capability, attachments with a durable transfer row show that row's
		     state/bytes/actions instead of a bare anchor. -->
		{#if visibleAttachments.length > 0}
			<div class="sj-reading-body__attachments" aria-label="Attachments">
				{#each visibleAttachments as att (att.blobId)}
					{@const e5row = e5RowFor(att.blobId)}
					{#if e5row !== null}
						<div class="sj-e5-transfer-row" data-testid="e5-transfer-row">
							<span class="sj-e5-transfer-row__state" data-testid="e5-transfer-state">{t(e5row.key)}</span>
							{#if e5row.pauseReasonKey}
								<span class="sj-e5-transfer-row__reason">{t(e5row.pauseReasonKey)}</span>
							{/if}
							{#if e5row.progress}
								<span class="sj-e5-transfer-row__bytes">
									{formatBytes(e5row.progress.done)}{e5row.progress.total !== undefined ? ` / ${formatBytes(e5row.progress.total)}` : ''}
								</span>
							{/if}
							{#if e5row.actions.resume}
								<button type="button" class="sj-e5-transfer-row__btn" onclick={() => transferAction(transferKey(att.blobId), 'resume')}>{t('offline.e5.transfer.resume')}</button>
							{/if}
							{#if e5row.actions.cancel}
								<button type="button" class="sj-e5-transfer-row__btn" onclick={() => transferAction(transferKey(att.blobId), 'cancel')}>{t('offline.e5.transfer.cancel')}</button>
							{/if}
							{#if e5row.actions.retry}
								<button type="button" class="sj-e5-transfer-row__btn" onclick={() => transferAction(transferKey(att.blobId), 'retry')}>{t('offline.e5.transfer.retry')}</button>
							{/if}
							{#if e5row.actions.open}
								<a class="sj-e5-transfer-row__btn" href={downloadUrl(att)} download={att.name ?? 'attachment'}>{t('offline.e5.transfer.open')}</a>
							{/if}
							{#if e5row.alert}
								<span class="sr-only" role="alert">{t(e5row.key)}</span>
							{/if}
						</div>
					{:else}
						{#if isPreviewable(att.type)}
							<button
								type="button"
								class="sj-reading-body__attachment-chip"
								onclick={() => (previewAtt = att)}
								aria-label={t('inbox.preview_attachment', { name: att.name ?? 'attachment' })}
							>
								<Icon name={attachIcon(att.type)} size={16} strokeWidth={1.75} />
								<span class="sj-reading-body__attachment-name">{att.name ?? 'attachment'}</span>
								{#if att.size}<span class="sj-reading-body__attachment-size">{formatBytes(att.size)}</span>{/if}
								<Icon name="Maximize2" size={14} strokeWidth={1.75} />
							</button>
						{:else}
							<a
								class="sj-reading-body__attachment-chip"
								href={downloadUrl(att)}
								download={att.name ?? 'attachment'}
								aria-label={`Download ${att.name ?? 'attachment'}`}
							>
								<Icon name={attachIcon(att.type)} size={16} strokeWidth={1.75} />
								<span class="sj-reading-body__attachment-name">{att.name ?? 'attachment'}</span>
								{#if att.size}<span class="sj-reading-body__attachment-size">{formatBytes(att.size)}</span>{/if}
								<Icon name="Download" size={14} strokeWidth={1.75} />
							</a>
						{/if}
					{/if}
					{#if isVCard(att)}
						<IconButton
							label={t('inbox.add_to_contacts')}
							variant="ghost"
							size="sm"
							disabled={addingContactBlobId === att.blobId}
							onclick={() => addToContacts(att)}
						>
							<Icon name="UserPlus" size={16} strokeWidth={1.75} />
						</IconButton>
					{/if}
				{/each}
				{#if visibleAttachments.length > 1 && e5TransfersActive}
					{@const group = e5ui.saveAllGroup(email.id)}
					{#if group === null}
						<!-- E5: Save all is a grouped job with resumable children (R4),
						     never the unresumable ZIP stream, while transfers are durable. -->
						<button
							type="button"
							class="sj-reading-body__attachment-saveall"
							data-testid="e5-saveall-start"
							onclick={startSaveAll}
						>
							<Icon name="Download" size={14} strokeWidth={1.75} />
							{t('inbox.save_all_attachments', { count: String(visibleAttachments.length) })}
						</button>
					{:else}
						<div class="sj-e5-saveall" data-testid="e5-saveall-group">
							<span data-testid="e5-saveall-summary">
								{t('offline.e5.saveall.summary', {
									completed: String(group.summary.completed),
									total: String(group.summary.total),
								})}
								{#if group.summary.indeterminate}
									· {t('offline.e5.saveall.indeterminate')}
								{/if}
							</span>
							{#if group.summary.failed > 0 || group.summary.expired > 0}
								<button type="button" class="sj-e5-transfer-row__btn" data-testid="e5-saveall-retry" onclick={saveAllRetry}>
									{t('offline.e5.saveall.retry')}
								</button>
							{/if}
							{#if !group.summary.allComplete && group.summary.cancelled === 0}
								<button type="button" class="sj-e5-transfer-row__btn" data-testid="e5-saveall-cancel" onclick={saveAllCancel}>
									{t('offline.e5.saveall.cancel')}
								</button>
							{/if}
							{#if group.summary.unavailable > 0}
								<span class="sj-e5-transfer-row__reason" data-testid="e5-saveall-unavailable">
									{t('offline.e5.saveall.unavailable', { n: String(group.summary.unavailable) })}
								</span>
							{/if}
						</div>
					{/if}
				{:else if visibleAttachments.length > 1}
					<a
						class="sj-reading-body__attachment-saveall"
						href={`/api/messages/${email.id}/attachments.zip`}
						download
					>
						<Icon name="Download" size={14} strokeWidth={1.75} />
						{t('inbox.save_all_attachments', { count: String(visibleAttachments.length) })}
					</a>
				{/if}
			</div>
		{/if}
	{:else}
		<!-- Collapsed: one-line summary header. -->
		<button class="sj-msg-card__summary" onclick={onToggle} aria-expanded="false">
			<Avatar name={senderName} size="sm" />
			<span class="sj-msg-card__summary-name">{senderName}</span>
			{#if showExternalLabel}
				<Badge variant="warning" label={t('mail.external_label')} />
			{/if}
			<span class="sj-msg-card__summary-preview">{email.preview ?? ''}</span>
			<span class="sj-msg-card__summary-date">{shortDate}</span>
		</button>
	{/if}
</div>

{#if showDelivery}
	<DeliveryPanel
		emailId={email.id}
		rawUrl={`/api/messages/${email.id}/download`}
		open
		{onResend}
		onClose={() => (showDelivery = false)}
	/>
{/if}

<!-- Attachment preview (image/PDF). Image via <img> (img-src 'self'); PDF via a
     same-origin <iframe> (frame-src 'self') kept sandbox="" as defence-in-depth —
     object-src is 'none', so never <embed>/<object>. Download stays reachable in
     the footer so the preview never removes the download path. -->
{#if previewAtt}
	{@const att = previewAtt}
	<Dialog
		open
		wide
		title={att.name ?? 'attachment'}
		titleHtmlAttr={att.name}
		onClose={() => (previewAtt = null)}
	>
		{#if (att.type ?? '').toLowerCase().startsWith('image/')}
			<img class="sj-attachment-preview__img" src={inlineUrl(att)} alt={att.name ?? 'attachment'} />
		{:else}
			<iframe
				class="sj-attachment-preview__frame"
				src={inlineUrl(att)}
				sandbox=""
				title={t('inbox.preview_attachment', { name: att.name ?? 'attachment' })}
			></iframe>
		{/if}
		{#snippet footer()}
			<a
				class="sj-attachment-preview__download"
				href={downloadUrl(att)}
				download={att.name ?? 'attachment'}
			>
				<Icon name="Download" size={14} strokeWidth={1.75} />
				{t('inbox.download')}
			</a>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-msg-card {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		margin-bottom: 12px;
	}

	.sj-msg-card--expanded {
		padding: 14px 16px;
		box-shadow: var(--shadow-xs);
	}

	/* Collapsed one-line header. */
	.sj-msg-card__summary {
		display: flex;
		align-items: center;
		gap: 10px;
		width: 100%;
		padding: 8px 12px;
		border: none;
		background: none;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		border-radius: var(--radius-md);
	}

	.sj-msg-card__summary:hover {
		background: var(--surface-hover);
	}

	.sj-msg-card__summary:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-msg-card__summary-name {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		flex: none;
		max-width: 30%;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-msg-card__summary-preview {
		flex: 1;
		min-width: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-msg-card__summary-date {
		flex: none;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}

	/* — Sender block — */
	.sj-reading-body__sender {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 16px;
	}

	/* Avatar + identity is the collapse toggle; the sender actions sit outside it. */
	.sj-msg-card__sender-toggle {
		display: flex;
		align-items: center;
		gap: 10px;
		flex: 1;
		min-width: 0;
		border: none;
		background: none;
		cursor: pointer;
		text-align: left;
		padding: 0;
		font-family: var(--font-sans);
	}

	.sj-msg-card__sender-toggle:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-sm);
	}

	.sj-reading-body__sender-info {
		flex: 1;
		min-width: 0;
	}

	.sj-reading-body__sender-line1 {
		display: flex;
		align-items: baseline;
		gap: 6px;
		flex-wrap: wrap;
	}

	.sj-reading-body__sender-name {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}

	.sj-reading-body__sender-email {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-mono);
	}

	.sj-reading-body__sender-line2 {
		font-size: var(--text-xs);
		color: var(--text-caption);
		display: flex;
		align-items: center;
		gap: 4px;
		flex-wrap: wrap;
		margin-top: 2px;
	}

	.sj-reading-body__sender-dot {
		margin: 0 2px;
	}

	.sj-reading-body__smime-badge {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-2xs);
		padding: 2px 8px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		color: var(--text-secondary);
	}

	.sj-reading-body__smime-badge--verified {
		background: var(--success-bg);
		color: var(--success-fg);
	}

	.sj-reading-body__smime-badge--verified :global(svg) {
		color: var(--success-fg);
	}

	/* SP1 P5 (D-F4): the Lock "Encrypted" chip — distinct from the verified
	   ShieldCheck, neutral tone (never the success-green of verified). */
	.sj-reading-body__smime-badge--encrypted {
		background: var(--surface-sunken);
		color: var(--text-secondary);
	}

	/* SP1 P5 (D-F1): calm can't-decrypt panel — neutral surface, never red. */
	.sj-reading-body__decrypt-state {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 8px;
		padding: 16px;
		border-radius: var(--radius-md);
		background: var(--surface-sunken);
		color: var(--text-secondary);
	}

	.sj-reading-body__decrypt-state :global(svg) {
		color: var(--text-caption);
	}

	.sj-reading-body__decrypt-msg {
		margin: 0;
		font-size: var(--text-sm);
		line-height: 1.5;
		max-width: 60ch;
	}

	.sj-reading-body__decrypt-link {
		font-size: var(--text-sm);
		color: var(--accent);
		text-decoration: none;
	}

	.sj-reading-body__decrypt-link:hover {
		text-decoration: underline;
	}

	.sj-reading-body__smime-signer {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 22ch;
	}

	.sj-reading-body__sender-actions {
		display: flex;
		gap: 2px;
		flex: none;
	}

	/* — Vote buttons — */
	.sj-reading-body__votes {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 12px;
		flex-wrap: wrap;
	}

	.sj-reading-body__votes-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.sj-reading-body__vote-btn {
		padding: 4px 12px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		cursor: pointer;
		color: var(--text-primary);
	}

	.sj-reading-body__vote-btn:hover {
		border-color: var(--accent);
		background: var(--surface-hover);
	}

	.sj-reading-body__vote-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* — Body content — */
	.sj-reading-body__content {
		margin-bottom: 4px;
	}

	.sj-reading-body__html-toggle {
		padding: 4px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		cursor: pointer;
		color: var(--text-secondary);
		margin-bottom: 8px;
	}

	.sj-reading-body__html-toggle:hover {
		border-color: var(--accent);
	}

	.sj-reading-body__html-toggle:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-reading-body__remote-banner {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 8px 12px;
		margin-bottom: 8px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-hover);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.sj-reading-body__remote-banner button {
		padding: 4px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		cursor: pointer;
		color: var(--text-primary);
	}

	.sj-reading-body__remote-banner button:hover {
		border-color: var(--accent);
	}

	.sj-reading-body__remote-banner button:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-reading-body__text {
		white-space: pre-wrap;
		color: var(--text-primary);
		max-width: 640px;
		font-size: var(--text-lg);
		font-family: var(--font-sans);
		line-height: var(--leading-relaxed);
	}

	.sj-reading-body__text--mono {
		font-size: var(--text-sm);
		font-family: var(--font-mono);
		line-height: 1.6;
	}

	.sj-reading-body__html-frame {
		width: 100%;
		min-height: 80px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
	}

	/* Hidden auto-height measurer: zero footprint, invisible, paint-contained
	   (contain:paint also makes it the containing block for any fixed/absolute
	   descendant, so nothing can overlay the app). scrollHeight still reports
	   the laid-out content height. */
	.sj-msg-card__measurer {
		height: 0;
		overflow: hidden;
		visibility: hidden;
		pointer-events: none;
		contain: paint;
	}

	/* Ghost pill toggling the quoted tail. */
	.sj-msg-card__quote-toggle {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		margin-top: 8px;
		padding: 3px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		background: none;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}

	.sj-msg-card__quote-toggle:hover {
		border-color: var(--accent);
		color: var(--text-primary);
	}

	.sj-msg-card__quote-toggle:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* — Attachments — */
	.sj-reading-body__attachments {
		margin-top: 20px;
	}

	.sj-reading-body__attachment-chip {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-sunken);
		font-size: var(--text-sm);
		font-family: var(--font-sans);
		text-align: left;
		text-decoration: none;
		color: var(--text-primary);
		cursor: pointer;
	}

	.sj-reading-body__attachment-chip:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* — Attachment preview dialog — */
	.sj-attachment-preview__img {
		display: block;
		max-width: 100%;
		max-height: 70vh;
		margin: 0 auto;
	}

	.sj-attachment-preview__frame {
		width: 100%;
		height: 70vh;
		border: none;
		background: var(--surface-card);
	}

	.sj-attachment-preview__download {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: var(--text-sm);
		color: var(--accent);
		text-decoration: none;
	}

	.sj-attachment-preview__download :global(svg) {
		color: var(--accent);
	}

	.sj-attachment-preview__download:hover {
		text-decoration: underline;
	}

	.sj-reading-body__attachment-chip :global(svg) {
		color: var(--text-tertiary);
	}

	.sj-reading-body__attachment-chip:hover :global([aria-label="Download"]),
	.sj-reading-body__attachment-chip:hover {
		color: var(--accent);
	}

	.sj-reading-body__attachment-size {
		color: var(--text-caption);
		font-size: var(--text-xs);
		margin-left: auto;
	}

	.sj-reading-body__attachment-name {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
	}

	.sj-reading-body__attachment-saveall {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 8px 12px;
		border-radius: var(--radius-md);
		font-size: var(--text-sm);
		color: var(--accent);
		text-decoration: none;
		cursor: pointer;
	}

	.sj-reading-body__attachment-saveall :global(svg) {
		color: var(--accent);
	}

	.sj-reading-body__attachment-saveall:hover {
		text-decoration: underline;
	}

	/* — E5 durable transfer rows / save-all group (token-only, both themes) — */
	.sj-e5-transfer-row {
		display: inline-flex;
		align-items: center;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-sunken);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sj-e5-transfer-row__state { font-weight: var(--font-weight-semibold); }
	.sj-e5-transfer-row__reason { color: var(--text-tertiary); font-size: var(--text-xs); }
	.sj-e5-transfer-row__bytes { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.sj-e5-transfer-row__btn {
		display: inline-flex;
		align-items: center;
		min-height: 44px;
		padding: 0 var(--space-2);
		border: none;
		background: none;
		font: inherit;
		font-size: var(--text-sm);
		color: var(--accent);
		text-decoration: none;
		cursor: pointer;
	}
	.sj-e5-transfer-row__btn:hover { text-decoration: underline; }
	.sj-e5-transfer-row__btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-e5-saveall {
		display: inline-flex;
		align-items: center;
		flex-wrap: wrap;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-e5-transfer-row,
		.sj-e5-saveall { transition: none; }
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
</style>
