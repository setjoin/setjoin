<svelte:options runes={true} />

<script lang="ts">
	import type { DriveVersion } from '$lib/drive/api';
	import { fetchVersionContent, fetchVersionPreview } from '$lib/drive/api';
	import { formatBytes } from '$lib/utils/display';
	import { formatDateTime } from '$lib/i18n';
	import { t } from '$lib/i18n';
	import { comparePaneMode } from './comparePane';
	import { openViewAttempt, blobUrlAdapter, valueResource, type ViewAttempt } from '$lib/drive/viewAttempt.svelte';

	let {
		left,
		right,
		fileName,
	}: {
		left: DriveVersion;
		right: DriveVersion;
		fileName: string;
	} = $props();

	let mode = $derived(comparePaneMode(left, right, fileName));
	let identical = $derived(left.sha256 === right.sha256);

	// Side-by-side content — fetched only when the pane is actually renderable
	// (mode !== 'metadataOnly'). The attempt owns every acquisition: teardown,
	// a mid-flight mode flip, or a superseding run releases exactly once, and
	// completions landing after release self-release (AR-02 viewAttempt).
	let leftUrl = $state('');
	let rightUrl = $state('');
	let leftText = $state('');
	let rightText = $state('');
	// A rejected side (e.g. a stale 'ready' prop meeting a preview 404)
	// degrades the comparison to the metadata-only note instead of leaking the
	// succeeded side's resource or surfacing an unhandled rejection.
	let degraded = $state(false);

	interface SidePayload {
		url: string;
		text: string;
	}

	async function loadSide(attempt: ViewAttempt, currentMode: string, version: DriveVersion): Promise<SidePayload> {
		const res =
			currentMode === 'officeRendition' ? await fetchVersionPreview(version.id) : await fetchVersionContent(version.id);
		const blob = await (res as unknown as { blob(): Promise<Blob> }).blob();
		if (currentMode === 'text') {
			const text = await blob.text();
			const acquired = await attempt.acquire('compare-text', () => valueResource(text));
			return acquired ? { url: '', text: acquired.value } : { url: '', text: '' };
		}
		const acquired = await attempt.acquire('compare-blob-url', () => blobUrlAdapter(blob));
		return acquired ? { url: acquired.value, text: '' } : { url: '', text: '' };
	}

	$effect(() => {
		const currentMode = mode;
		if (currentMode === 'metadataOnly') return;
		const attempt = openViewAttempt();
		degraded = false;
		leftUrl = '';
		rightUrl = '';
		leftText = '';
		rightText = '';
		// All-settled: a one-side failure releases the succeeded side through
		// the attempt and degrades the panes — no orphan acquisition, no
		// unhandled rejection.
		void Promise.allSettled([loadSide(attempt, currentMode, left), loadSide(attempt, currentMode, right)]).then(
			([l, r]) => {
				if (attempt.closed) return;
				if (l.status === 'rejected' || r.status === 'rejected') {
					attempt.releaseAll();
					degraded = true;
					return;
				}
				leftUrl = l.value.url;
				rightUrl = r.value.url;
				leftText = l.value.text;
				rightText = r.value.text;
			},
		);
		return () => attempt.releaseAll();
	});
</script>

<div class="cv">
	<table class="cv__meta">
		<tbody>
			<tr>
				<th>{t('drive.compare.content')}</th>
				<td colspan="2">{identical ? t('drive.compare.identical') : t('drive.compare.differs')}</td>
			</tr>
			<tr>
				<th>{t('drive.compare.size')}</th>
				<td>{formatBytes(left.size)}</td>
				<td>{formatBytes(right.size)}</td>
			</tr>
			<tr>
				<th>{t('drive.compare.author')}</th>
				<td>#{left.author}</td>
				<td>#{right.author}</td>
			</tr>
			<tr>
				<th>{t('drive.compare.note')}</th>
				<td>{left.note ?? '—'}</td>
				<td>{right.note ?? '—'}</td>
			</tr>
			<tr>
				<th>{t('drive.compare.date')}</th>
				<td>{formatDateTime(left.createdAt)}</td>
				<td>{formatDateTime(right.createdAt)}</td>
			</tr>
			<tr>
				<th>{t('drive.compare.labels')}</th>
				<td>{left.labels.join(', ') || '—'}</td>
				<td>{right.labels.join(', ') || '—'}</td>
			</tr>
		</tbody>
	</table>

	{#if mode === 'metadataOnly' || degraded}
		<p class="cv__no-preview">{t('drive.compare.noPreview')}</p>
	{:else}
		<div class="cv__panes">
			<div class="cv__pane">
				<h3 class="cv__pane-title">{t('drive.compare.left')}</h3>
				{#if mode === 'image'}
					<img src={leftUrl} alt={fileName} class="cv__image" />
				{:else if mode === 'text'}
					<pre class="cv__text">{leftText}</pre>
				{:else if mode === 'officeRendition'}
					<embed class="cv__pdf" src={leftUrl} type="application/pdf" title={fileName} />
				{/if}
			</div>
			<div class="cv__pane">
				<h3 class="cv__pane-title">{t('drive.compare.right')}</h3>
				{#if mode === 'image'}
					<img src={rightUrl} alt={fileName} class="cv__image" />
				{:else if mode === 'text'}
					<pre class="cv__text">{rightText}</pre>
				{:else if mode === 'officeRendition'}
					<embed class="cv__pdf" src={rightUrl} type="application/pdf" title={fileName} />
				{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.cv {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		max-height: 70vh;
		overflow-y: auto;
	}
	.cv__meta {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.cv__meta th {
		text-align: left;
		color: var(--text-caption);
		font-weight: 500;
		padding: var(--space-1) var(--space-2);
		white-space: nowrap;
	}
	.cv__meta td {
		padding: var(--space-1) var(--space-2);
		border-top: 1px solid var(--border-subtle);
	}
	.cv__no-preview {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.cv__panes {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: var(--space-3);
	}
	.cv__pane {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
		min-width: 0;
	}
	.cv__pane-title {
		margin: 0 0 var(--space-2);
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-caption);
	}
	.cv__image {
		max-width: 100%;
		display: block;
	}
	.cv__text {
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		max-height: 320px;
		overflow-y: auto;
	}
	.cv__pdf {
		width: 100%;
		height: 320px;
	}
</style>
