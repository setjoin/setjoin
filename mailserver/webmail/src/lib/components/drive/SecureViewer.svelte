<svelte:options runes={true} />

<script lang="ts">
	// SecureViewer — the in-app render for a Drive version (spec §8.3 dispatch
	// matrix). The XSS barrier is the sandbox="" iframe (html/eml/svg, reusing
	// MessageCard.svelte's precedent) + never rendering SVG via <img> (SVG can
	// carry script/foreignObject). No plaintext ever touches disk for vault
	// content: the "small" path assembles a RAM Blob (revoked on close) and the
	// "large/AV" path streams from the ticketed 127.0.0.1 loopback server —
	// neither writes a decrypted temp file.
	import { Dialog, Button, EmptyState } from '$lib/components/ui';
	import { sanitizeHTML } from '$lib/sanitize';
	import { fetchVersionContent, fetchVersionPreview } from '$lib/drive/api';
	import {
		openViewAttempt,
		acquireAndCommit,
		blobUrlAdapter,
		nativeTicketAdapter,
		valueResource,
		type ViewAttempt,
	} from '$lib/drive/viewAttempt.svelte';
	import { t } from '$lib/i18n';
	import { user } from '$lib/stores/auth';
	import { effectiveCaps, isGuestSession } from '$lib/stores/session';
	import type { VersionMeta, ContentSource } from '$lib/drive/opener.svelte';
	import WatermarkOverlay from '$lib/components/WatermarkOverlay.svelte';
	import ExportRequestButton from './ExportRequestButton.svelte';

	// Office content-types the P1/P3 rendition pipeline covers (mirrors
	// drive_preview_request.sql's CHECK constraint — duplicated here since no
	// type crosses the Go/SQL/TS boundary).
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

	type Kind = 'image' | 'svg' | 'pdf' | 'av' | 'html' | 'text' | 'office' | 'unknown';

	function classify(ct: string | null): Kind {
		if (!ct) return 'unknown';
		if (ct === 'image/svg+xml') return 'svg'; // NEVER via <img> for secure content
		if (ct.startsWith('image/')) return 'image';
		if (ct === 'application/pdf') return 'pdf';
		if (ct.startsWith('video/') || ct.startsWith('audio/')) return 'av';
		if (ct === 'text/html' || ct === 'message/rfc822') return 'html';
		if (OFFICE_TYPES.has(ct)) return 'office';
		if (ct.startsWith('text/') || ct === 'application/json') return 'text';
		return 'unknown';
	}

	let { version, source, onclose }: { version: VersionMeta; source: ContentSource; onclose: () => void } = $props();

	/** §8.2 — above this (or any AV in vault mode): loopback streaming, never a RAM assembly. */
	const RAM_CAP = 512 * 1024 * 1024;

	const kind = $derived(classify(version.contentType));
	const isAudio = $derived(version.contentType?.startsWith('audio/') ?? false);
	// /auth/me carries the independently authenticated account type. Keep the
	// view-only posture even when JMAP capability loading is unresolved/failed;
	// otherwise a guest briefly receives member affordances until the server
	// rejects them. A positive allowDownload remains required to leave the tier.
	const guestViewOnly = $derived(
		($user?.accountType === 'guest' || $isGuestSession) && !$effectiveCaps.allowDownload,
	);

	let objectUrl = $state<string | null>(null);
	let loopbackSrc = $state<string | null>(null);
	let textContent = $state<string | null>(null);
	let sanitizedHtml = $state<string | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let notReady = $state(false); // office rendition pending/unsupported, or preview 404
	let viewOnlyUnsupported = $state(false);
	let governedExportOnly = $state(false);
	/** Live status parsed from getPreview's 404 detail — overrides the
	 *  possibly-stale version.previewStatus prop once the server has answered. */
	let previewStatusLive = $state<string | null>(null);

	// AR-02 viewAttempt: the attempt owns every acquisition lifetime (blob URLs
	// and native serve tickets). Teardown, retry and prop-change supersession
	// release exactly once; an acquisition completing after release self-releases
	// and never reaches live state — revoke() folded into attempt.releaseAll().
	// Every state write goes through acquireAndCommit, which rechecks attempt
	// currency immediately before the write: cleanup landing between acquire()'s
	// resolution and this component's continuation must not write stale state.
	let attempt: ViewAttempt | null = null;

	function releaseAttempt(): void {
		attempt?.releaseAll();
		attempt = null;
	}

	/** Opens a fresh attempt after releasing the previous one — retry and
	 *  prop-change re-runs supersede in-flight completions via the stale check. */
	function freshAttempt(): ViewAttempt {
		releaseAttempt();
		attempt = openViewAttempt();
		return attempt;
	}

	async function loadVault(current: ViewAttempt, manifest: NonNullable<Extract<ContentSource, { kind: 'vault' }>['manifest']>): Promise<void> {
		const native = window.setjoinNative;
		if (!native?.drive) throw new Error(t('drive.viewer.loadFailed'));
		if (kind === 'av' || version.size > RAM_CAP) {
			// Native loopback streaming — Range seek, no RAM assembly, no size cap (R1).
			const drive = native.drive;
			const { port } = await drive.serveStart();
			// Ticket acquisition is the attempt's business: a grant resolving after
			// teardown/supersession is revoked immediately and never reaches live
			// state, even when cleanup lands between the acquire() resolution and
			// this component's continuation (acquireAndCommit rechecks currency).
			await acquireAndCommit(current, 'native-ticket', () => nativeTicketAdapter(drive, manifest), (value) => {
				loopbackSrc = `http://127.0.0.1:${port}${value}`;
			});
			return;
		}
		if (kind === 'office') {
			// The vault mirrors the ORIGINAL file, never the server-side PDF
			// rendition — fall through to the metadata-card fallback.
			return;
		}
		if (!native.db) throw new Error(t('drive.viewer.loadFailed'));
		// Small/medium: per-chunk base64 via db.query is a RENDER-path
		// convenience (§8.2), not the banned sync path — assemble a RAM Blob.
		const parts: BlobPart[] = [];
		for (const c of manifest.chunks) {
			const rows = await native.db.query<{ bytes: string }>('drive', 'SELECT bytes FROM dc_chunks WHERE sha256 = ?', [
				c.sha256,
			]);
			if (current.closed) return; // superseded mid-assembly: stop reading chunks
			if (!rows[0]) throw new Error(t('drive.viewer.chunkMissing'));
			parts.push(Uint8Array.from(atob(rows[0].bytes), (ch) => ch.charCodeAt(0)));
		}
		const blob = new Blob(parts, { type: version.contentType ?? undefined });
		await registerDecoded(current, blob);
	}

	/** Routes the decoded RAM blob through the attempt — sanitized HTML and
	 *  text ride valueResource (no-op release) for a uniform stale check.
	 *  Each write rides acquireAndCommit so attempt currency is rechecked
	 *  immediately before the state write. */
	async function registerDecoded(current: ViewAttempt, blob: Blob): Promise<void> {
		if (kind === 'html' || kind === 'svg') {
			await acquireAndCommit(current, 'sanitized-html', async () => valueResource(sanitizeHTML(await blob.text())), (value) => {
				sanitizedHtml = value;
			});
		} else if (kind === 'text') {
			await acquireAndCommit(current, 'text', async () => valueResource(await blob.text()), (value) => {
				textContent = value;
			});
		} else {
			await acquireAndCommit(
				current,
				'blob-url',
				() => blobUrlAdapter(blob),
				(value) => {
					objectUrl = value;
				},
			);
		}
	}

	async function loadOnline(current: ViewAttempt): Promise<void> {
		// Guest G4: never even request original bytes for a view-only guest.
		// Office files have the separate rendition authority below; every other
		// format stays metadata-only, matching the honest no-DRM posture.
		if (guestViewOnly && kind !== 'office') {
			viewOnlyUnsupported = true;
			return;
		}
		// Secure/GxP originals are never a browser render source: a request
		// header is client-controlled and cannot distinguish viewing from
		// exfiltration. Only server-generated office renditions may render;
		// every other protected format uses the governed export workflow.
		if (version.classification !== 'regular' && kind !== 'office') {
			governedExportOnly = true;
			return;
		}
		if (kind === 'office') {
			// Always ask the server -- getPreview (preview.go) is the single
			// source of truth (it also owns the lazy 'none'->'pending' flip on
			// first hit), never the client's snapshotted version.previewStatus.
			// A 404 problem body's `detail` names the current status
			// ("... status=pending)") so a re-render after Retry (or a real
			// rendition landing) reflects the LIVE state instead of the stale
			// prop from when the viewer opened.
			const res = await fetchVersionPreview(version.versionId, { allowStatuses: [404] });
			if (res.status === 404) {
				const body = (await res.json().catch(() => null)) as { detail?: string } | null;
				if (current.closed) return; // superseded: no live-state write
				previewStatusLive = body?.detail?.match(/status=(\w+)/)?.[1] ?? version.previewStatus;
				notReady = true;
				return;
			}
			// Acquisition + state write ride the attempt (see acquireAndCommit):
			// cleanup landing between the acquire() resolution and the objectUrl
			// write never reaches live state.
			await acquireAndCommit(
				current,
				'blob-url',
				async () => blobUrlAdapter(await res.blob()),
				(value) => {
					objectUrl = value;
				},
			);
			return;
		}
		const res = await fetchVersionContent(version.versionId);
		await registerDecoded(current, await res.blob());
	}

	async function load(): Promise<void> {
		const current = freshAttempt();
		loading = true;
		error = null;
		notReady = false;
		viewOnlyUnsupported = false;
		governedExportOnly = false;
		previewStatusLive = null;
		objectUrl = null;
		loopbackSrc = null;
		sanitizedHtml = null;
		textContent = null;
		try {
			if (source.kind === 'vault') await loadVault(current, source.manifest);
			else await loadOnline(current);
		} catch (e) {
			if (!current.closed) error = e instanceof Error ? e.message : String(e);
		} finally {
			if (!current.closed) loading = false;
		}
	}

	$effect(() => {
		void load();
		return () => releaseAttempt();
	});
</script>

<Dialog open={true} title={version.name} wide onClose={onclose}>
	<div class="sv">
		{#if loading}
			<div class="sv__loading">{t('common.loading')}</div>
		{:else if error}
			<EmptyState title={error} />
		{:else if viewOnlyUnsupported}
			<EmptyState title={t('drive.viewer.viewOnlyUnsupported')} />
		{:else if governedExportOnly}
			<EmptyState title={t('drive.viewer.governedExportOnly')} />
		{:else if notReady}
			<EmptyState
				title={(previewStatusLive ?? version.previewStatus) === 'unsupported'
					? t('drive.viewer.previewUnsupported')
					: t('drive.viewer.previewPending')}
			>
				{#snippet action()}
					{#if (previewStatusLive ?? version.previewStatus) !== 'unsupported'}
						<Button variant="secondary" size="sm" onclick={() => void load()}>{t('common.retry')}</Button>
					{/if}
				{/snippet}
			</EmptyState>
		{:else if kind === 'image' && objectUrl}
			<img class="sv__image" src={objectUrl} alt={version.name} />
		{:else if (kind === 'pdf' || kind === 'office') && objectUrl}
			<embed class="sv__pdf" src={objectUrl} type="application/pdf" title={version.name} />
		{:else if (kind === 'html' || kind === 'svg') && sanitizedHtml != null}
			<iframe class="sv__frame" title={version.name} sandbox="" srcdoc={sanitizedHtml}></iframe>
		{:else if kind === 'text' && textContent != null}
			<pre class="sv__text">{textContent}</pre>
		{:else if kind === 'av' && (objectUrl || loopbackSrc)}
			{#if isAudio}
				<audio class="sv__av" controls src={objectUrl ?? loopbackSrc}></audio>
			{:else}
				<!-- svelte-ignore a11y_media_has_caption -- arbitrary user-uploaded
				     video has no caption track to attach; keyboard-reachable
				     `controls` is the a11y floor for this content type. -->
				<video class="sv__av" controls src={objectUrl ?? loopbackSrc}></video>
			{/if}
		{:else}
			<EmptyState title={t('drive.viewer.requestExport')} />
		{/if}
		<WatermarkOverlay enabled={guestViewOnly} userEmail={$user?.email ?? ''} />
	</div>
	{#if source.kind === 'online' && !guestViewOnly}
		<div class="sv__export">
			<ExportRequestButton versionId={version.versionId} action="download" classification={version.classification} />
			<ExportRequestButton versionId={version.versionId} action="print" classification={version.classification} />
		</div>
	{/if}
</Dialog>

<style>
	.sv {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 240px;
		max-height: 70vh;
		overflow: hidden;
	}
	.sv__loading {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.sv__image {
		max-width: 100%;
		max-height: 70vh;
		object-fit: contain;
	}
	.sv__pdf {
		width: 100%;
		height: 70vh;
		border: none;
	}
	.sv__frame {
		width: 100%;
		height: 70vh;
		border: none;
	}
	.sv__text {
		width: 100%;
		max-height: 70vh;
		overflow: auto;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
	}
	.sv__av {
		max-width: 100%;
		max-height: 70vh;
	}
	.sv__export {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding-top: var(--space-2);
		margin-top: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		width: 100%;
	}
</style>
