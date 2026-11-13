<svelte:options runes={true} />

<script module lang="ts">
	// Chat A2 Task 8 — a module-scope (shared across EVERY MessageAttachments
	// instance in the app, one JS module) concurrency gate on attachment
	// resolution (node-meta GET + content blob fetch): caps how many of these
	// pipelines run at once so scrolling into a history-heavy channel doesn't
	// fire a network thundering-herd. ponytail: a fixed cap + FIFO queue, not
	// a generic semaphore utility — the ONLY caller is the effect below.
	const MAX_CONCURRENT_ATTACHMENT_FETCHES = 4;
	let activeAttachmentFetches = 0;
	const attachmentFetchQueue: (() => void)[] = [];
	async function withFetchSlot<T>(fn: () => Promise<T>): Promise<T> {
		if (activeAttachmentFetches >= MAX_CONCURRENT_ATTACHMENT_FETCHES) {
			await new Promise<void>((resolve) => attachmentFetchQueue.push(resolve));
		}
		activeAttachmentFetches++;
		try {
			return await fn();
		} finally {
			activeAttachmentFetches--;
			const next = attachmentFetchQueue.shift();
			if (next) next();
		}
	}
</script>

<script lang="ts">
	// MessageAttachments — the attachment-carrying genres of a chat message
	// (Chat A2 Task 8's image/file surface, A3 QoL Task 15's voice player),
	// split out of MessageRow.svelte (whole-pipeline review arch #9). Voice
	// is bundled in here rather than its own file: a voice clip is a single
	// attachment resolved through the EXACT SAME node-meta -> content-blob
	// pipeline as an image/file attachment (resolved/imageBlobUrls, the
	// withFetchSlot concurrency gate, resolveAttachment/loadThumb) — splitting
	// it out would either duplicate that pipeline or force an awkward prop
	// handoff of live resolution state; "attachments" is the coherent genre,
	// voice/image/file are its three renderers.
	//
	// `chat_message_to_json` projects only {id, fileNodeId, filename,
	// contentType, sizeBytes} per attachment (no versionId — see
	// chat_message.sql) so the real content is reached in two hops, same as
	// the sync engine's own nodesMeta pattern: GET /api/drive/nodes?ids=
	// <fileNodeId> (already-shipped batch node-meta read, membership-gated
	// via the Task 4 two-arm UNION so a derived chat member passes) resolves
	// headVersionId, then the existing fetchVersionContent(versionId)/
	// contentUrl(versionId) do the real fetch — no new Go/SQL route needed
	// (chat-bound spaces are always 'regular' classification, so content.go's
	// X-Setjoin-Render gate never applies here).
	import { onDestroy } from 'svelte';
	import type { StoreMessage } from '$lib/chat/store.svelte';
	import type { ChatAttachment } from '$lib/chat/api';
	import { Dialog } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { typedFetch } from '$lib/http';
	import { contentUrl, fetchVersionContent } from '$lib/drive/api';
	import { effectiveCaps, isGuestSession } from '$lib/stores/session';
	import { user } from '$lib/stores/auth';
	import type { VersionMeta } from '$lib/drive/opener.svelte';
	import { formatBytes } from '$lib/utils/display';
	import SecureViewer from '$lib/components/drive/SecureViewer.svelte';

	const OFFICE_TYPES = new Set([
		'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
		'application/vnd.openxmlformats-officedocument.presentationml.presentation',
		'application/msword',
		'application/vnd.ms-excel',
		'application/vnd.ms-powerpoint',
		'application/vnd.oasis.opendocument.text',
		'application/vnd.oasis.opendocument.spreadsheet',
		'application/vnd.oasis.opendocument.presentation',
	]);

	let { message }: { message: StoreMessage } = $props();

	// ── voice (A3 QoL Task 6's msg_type/payload seam, Task 15's playback) ──
	let isVoice = $derived(message.msgType === 'voice');
	let voiceDurationMs = $derived((message.payload as { durationMs?: number } | null | undefined)?.durationMs ?? 0);
	function formatDuration(ms: number): string {
		const totalSec = Math.round(ms / 1000);
		const m = Math.floor(totalSec / 60);
		const s = totalSec % 60;
		return `${m}:${String(s).padStart(2, '0')}`;
	}

	interface AttachmentResolution {
		status: 'pending' | 'ready' | 'unavailable';
		headVersionId?: number;
	}
	interface NodeMetaLite {
		nodeId: number;
		headVersionId: number | null;
		deletedAt: string | null;
	}

	let resolved = $state<Record<number, AttachmentResolution>>({});
	let imageBlobUrls = $state<Record<number, string>>({});
	let lightboxAttachmentId = $state<number | null>(null);
	let previewAttachmentId = $state<number | null>(null);
	// The auth identity is available independently of the JMAP capability load,
	// so a failed/unresolved session document must not expose member download
	// affordances to a known guest. Server BZ215 remains authoritative.
	let guestViewOnly = $derived(
		($user?.accountType === 'guest' || $isGuestSession) && !$effectiveCaps.allowDownload,
	);

	// fileNodeId 0 is the store's own optimistic placeholder (store.svelte.ts's
	// send()) for a still-sending message — never a real drive_nodes id, so it's
	// excluded here rather than firing a doomed lookup or a premature tombstone;
	// the placeholder array is overwritten in place once the send reconciles.
	// Voice messages resolve their SINGLE attachment through the same
	// pipeline below but render it as a native <audio> player (voiceAttachment),
	// not the generic image/file chip UI — nonVoiceAttachments excludes it so
	// the two rendering paths never both fire for the same attachment.
	let liveAttachments = $derived((message.attachments ?? []).filter((a) => a.fileNodeId > 0));
	let voiceAttachment = $derived(isVoice ? liveAttachments[0] : undefined);
	let nonVoiceAttachments = $derived(isVoice ? [] : liveAttachments);
	let imageAttachments = $derived(nonVoiceAttachments.filter((a) => (a.contentType ?? '').startsWith('image/')));
	let fileAttachments = $derived(nonVoiceAttachments.filter((a) => !(a.contentType ?? '').startsWith('image/')));
	let lightboxAttachment = $derived(liveAttachments.find((a) => a.id === lightboxAttachmentId));
	let previewAttachment = $derived(liveAttachments.find((a) => a.id === previewAttachmentId));
	let previewVersion = $derived.by((): VersionMeta | null => {
		if (!previewAttachment) return null;
		const versionId = resolved[previewAttachment.id]?.headVersionId;
		if (!versionId) return null;
		return {
			versionId,
			name: previewAttachment.filename,
			contentType: previewAttachment.contentType ?? null,
			size: previewAttachment.sizeBytes,
			classification: 'regular',
			previewStatus: 'none',
		};
	});

	$effect(() => {
		for (const a of liveAttachments) {
			if (a.id in resolved) continue;
			resolved[a.id] = { status: 'pending' };
			void withFetchSlot(() => resolveAttachment(a));
		}
	});

	async function resolveAttachment(a: ChatAttachment): Promise<void> {
		try {
			const rows = await typedFetch<NodeMetaLite[]>(`/api/drive/nodes?ids=${a.fileNodeId}`);
			const meta = rows[0];
			// Invisible/unknown/deleted node — nodes_meta.go silently omits it
			// rather than 403/404ing (its own doc comment), indistinguishable
			// from "no longer available", which IS the tombstone case here.
			if (!meta || meta.headVersionId == null || meta.deletedAt) {
				resolved[a.id] = { status: 'unavailable' };
				return;
			}
			resolved[a.id] = { status: 'ready', headVersionId: meta.headVersionId };
			if (!guestViewOnly && (a.contentType ?? '').startsWith('image/')) await loadThumb(a.id, meta.headVersionId);
		} catch {
			resolved[a.id] = { status: 'unavailable' };
		}
	}

	// Design H6: fetch via the authed client -> RAM blob -> object URL (never a
	// bare <img src="/api/..."> — the browser would issue an unauthenticated,
	// header-less request). Revoked in onDestroy below.
	async function loadThumb(attachmentId: number, versionId: number): Promise<void> {
		try {
			const res = await fetchVersionContent(versionId);
			const blob = await res.blob();
			imageBlobUrls[attachmentId] = URL.createObjectURL(blob);
		} catch {
			markUnavailable(attachmentId);
		}
	}

	function markUnavailable(attachmentId: number): void {
		resolved[attachmentId] = { ...resolved[attachmentId], status: 'unavailable' };
	}

	function openLightbox(attachmentId: number): void {
		if (resolved[attachmentId]?.status === 'ready' && imageBlobUrls[attachmentId]) lightboxAttachmentId = attachmentId;
	}
	function closeLightbox(): void {
		lightboxAttachmentId = null;
	}
	function openPreview(attachmentId: number): void {
		if (resolved[attachmentId]?.status === 'ready') previewAttachmentId = attachmentId;
	}

	onDestroy(() => {
		for (const url of Object.values(imageBlobUrls)) URL.revokeObjectURL(url);
	});
</script>

{#if isVoice}
	<div class="mrow__voice">
		{#if voiceAttachment && resolved[voiceAttachment.id]?.status === 'ready' && guestViewOnly}
			<span class="mrow__voice-tombstone">{t('chat.attach.viewOnly')}</span>
		{:else if voiceAttachment && resolved[voiceAttachment.id]?.status === 'ready'}
			<!-- svelte-ignore a11y_media_has_caption -->
			<audio controls data-testid="voice-player" src={contentUrl(resolved[voiceAttachment.id].headVersionId!)}></audio>
		{:else if voiceAttachment && resolved[voiceAttachment.id]?.status === 'unavailable'}
			<span class="mrow__voice-tombstone">{t('chat.attach.unavailable')}</span>
		{:else}
			<span class="mrow__voice-loading" aria-hidden="true">…</span>
		{/if}
		<span class="mrow__voice-duration">{formatDuration(voiceDurationMs)}</span>
	</div>
{/if}

{#if nonVoiceAttachments.length > 0}
	<div class="mrow__attachments">
		{#if imageAttachments.length > 0}
			<ul class="mrow__images" role="list" aria-label={t('chat.attach.list')}>
				{#each imageAttachments as a (a.id)}
					<li>
						<button
							type="button"
							class="mrow__thumb-btn"
							onclick={() => openLightbox(a.id)}
							disabled={guestViewOnly || resolved[a.id]?.status !== 'ready' || !imageBlobUrls[a.id]}
						>
							<div class="mrow__thumb" style="width: 160px; height: 120px; aspect-ratio: 4 / 3;">
								{#if resolved[a.id]?.status === 'unavailable'}
									<Icon name="FileText" size={20} />
									<span class="mrow__thumb-tombstone">{t('chat.attach.unavailable')}</span>
								{:else if guestViewOnly && resolved[a.id]?.status === 'ready'}
									<Icon name="Image" size={20} />
									<span class="mrow__thumb-tombstone">{t('chat.attach.viewOnly')}</span>
								{:else if imageBlobUrls[a.id]}
									<img src={imageBlobUrls[a.id]} alt={a.filename} class="mrow__thumb-img" onerror={() => markUnavailable(a.id)} />
								{:else}
									<Icon name="Image" size={20} />
								{/if}
							</div>
						</button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if fileAttachments.length > 0}
			<ul class="mrow__files" role="list" aria-label={t('chat.attach.list')}>
				{#each fileAttachments as a (a.id)}
					<li class="mrow__file-chip">
						<Icon name="FileText" size={16} />
						<span class="mrow__file-name">{a.filename}</span>
						{#if resolved[a.id]?.status === 'unavailable'}
							<span class="mrow__file-tombstone">{t('chat.attach.unavailable')}</span>
						{:else}
							<span class="mrow__file-size">{formatBytes(a.sizeBytes)}</span>
							{#if resolved[a.id]?.status === 'ready' && guestViewOnly && OFFICE_TYPES.has(a.contentType ?? '')}
								<button
									type="button"
									class="mrow__file-action"
									onclick={() => openPreview(a.id)}
									aria-label={t('chat.attach.preview')}
								>
									<Icon name="Eye" size={14} />
								</button>
							{:else if resolved[a.id]?.status === 'ready' && guestViewOnly}
								<span class="mrow__file-tombstone">{t('chat.attach.viewOnly')}</span>
							{:else if resolved[a.id]?.status === 'ready'}
								<a
									class="mrow__file-action"
									href={contentUrl(resolved[a.id].headVersionId!)}
									download={a.filename}
									aria-label={t('chat.attach.download')}
								>
									<Icon name="Download" size={14} />
								</a>
								<a
									class="mrow__file-action"
									href={contentUrl(resolved[a.id].headVersionId!)}
									target="_blank"
									rel="noopener"
									aria-label={t('chat.attach.openInDrive')}
								>
									<Icon name="HardDrive" size={14} />
								</a>
							{/if}
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</div>
{/if}

{#if previewVersion}
	<SecureViewer version={previewVersion} source={{ kind: 'online' }} onclose={() => (previewAttachmentId = null)} />
{/if}

{#if lightboxAttachment}
	<Dialog open title={lightboxAttachment.filename} onClose={closeLightbox}>
		{#snippet children()}
			<div class="mrow__lightbox-body">
				<img src={imageBlobUrls[lightboxAttachment.id]} alt={lightboxAttachment.filename} class="mrow__lightbox-img" />
			</div>
		{/snippet}
		{#snippet footer()}
			<a
				class="mrow__btn"
				href={contentUrl(resolved[lightboxAttachment.id]?.headVersionId ?? 0)}
				download={lightboxAttachment.filename}
			>
				<Icon name="Download" size={14} />
				{t('chat.attach.download')}
			</a>
		{/snippet}
	</Dialog>
{/if}

<style>
	/* ── voice — A3 QoL Task 15 ──────────────────────────────────────────── */
	.mrow__voice {
		flex-basis: 100%;
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.mrow__voice-duration {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.mrow__voice-tombstone {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		font-style: italic;
	}

	/* ── attachments (Chat A2 Task 8) ──────────────────────────────────── */
	.mrow__attachments {
		flex-basis: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.mrow__images {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
	.mrow__thumb-btn {
		display: block;
		padding: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: none;
		cursor: pointer;
		overflow: hidden;
	}
	.mrow__thumb-btn:disabled {
		cursor: default;
	}
	/* Design C1 (CRITICAL): fixed dimensions, never derived from the image's
	   intrinsic size or load state — a late image load must not change this
	   box's footprint, or A1's scrollHeight-based stick-to-bottom + prepend
	   anchor breaks. width/height/aspect-ratio are set as an inline style on
	   the element (see markup above), not here: jsdom's getComputedStyle
	   doesn't reliably reflect scoped-component stylesheet rules, which made
	   the row-height-unchanged pin test vacuous (it passed even with the
	   dimensions deleted). An inline style is read back by getComputedStyle
	   in both jsdom and real browsers, so the pin test is load-bearing. */
	.mrow__thumb {
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-sunken);
		color: var(--text-caption);
	}
	.mrow__thumb-img {
		width: 100%;
		height: 100%;
		object-fit: contain;
	}
	.mrow__thumb-tombstone {
		font-size: var(--text-2xs);
		text-align: center;
		padding: 0 var(--space-2);
	}
	.mrow__files {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.mrow__file-chip {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-height: 32px;
		padding: var(--space-1) var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		font-size: var(--text-sm);
		max-width: 320px;
	}
	.mrow__file-name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--text-primary);
	}
	.mrow__file-size {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		white-space: nowrap;
	}
	.mrow__file-tombstone {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		font-style: italic;
	}
	.mrow__file-action {
		border: 0;
		background: transparent;
		padding: 0;
		font: inherit;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 28px;
		min-height: 28px;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
	}
	.mrow__file-action:hover {
		background: var(--surface-hover);
	}

	@media (pointer: coarse) {
		.mrow__file-action {
			min-width: 44px;
			min-height: 44px;
		}
	}
	.mrow__lightbox-body {
		display: flex;
		align-items: center;
		justify-content: center;
		max-height: 70vh;
	}
	.mrow__lightbox-img {
		max-width: 100%;
		max-height: 70vh;
		object-fit: contain;
	}
	.mrow__btn {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 44px;
		justify-content: center;
		border: 1px solid var(--border-default);
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-xs);
		padding: 0 var(--space-2);
	}
	.mrow__btn:hover {
		background: var(--surface-hover);
	}
</style>
