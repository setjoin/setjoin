<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { sanitizeHTML } from '$lib/sanitize';
	import { Card, Badge, Button, Select, Input, Dialog, EmptyState, Spinner } from '$lib/components/ui';

	// Resource layer (3): block every fetch the sandboxed preview could fire
	// (tracking beacons, remote CSS, fonts). Prepended AFTER sanitize because
	// DOMPurify strips <meta>/<head>. data: images are intentionally blocked too
	// (decoder surface + visual lure), not a beacon concern. frame-ancestors is
	// omitted — a <meta> CSP ignores it and the parent already sets it.
	const PREVIEW_CSP =
		'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">';

	let items: any[] = $state([]);
	let stats = $state({ active: 0, released: 0, rejected: 0 });
	let status = $state('active');
	let query = $state('');
	let previewItem: any = $state(null);
	let previewHTML = $state('');
	let previewRaw = $state('');
	let showSource = $state(false);
	let loading = $state(false);
	let showPreview = $state(false);

	onMount(() => { loadStats(); loadItems(); });

	async function loadStats() {
		const res = await adminFetch('/admin/quarantine/stats');
		if (res.ok) stats = await res.json();
	}

	async function loadItems() {
		loading = true;
		const params = new URLSearchParams({ status, limit: '50' });
		if (query) params.set('q', query);
		const res = await adminFetch('/admin/quarantine?' + params.toString());
		if (res.ok) items = (await res.json()).items || [];
		loading = false;
	}

	async function preview(id: number) {
		const res = await adminFetch(`/admin/quarantine/${id}/preview`);
		if (res.ok) {
			const data = await res.json();
			previewItem = data;
			// Markup layer (1): sanitize client-side regardless of server output.
			// The server now stores + returns raw bytes; the client is the sole
			// sanitize boundary for the render. previewRaw keeps the unsanitized
			// bytes for the inert escaped-text "view source" (banked byte path).
			previewRaw = data.html || '';
			previewHTML = PREVIEW_CSP + sanitizeHTML(previewRaw);
			showSource = false;
			showPreview = true;
		}
	}

	async function release(id: number) {
		const res = await adminFetch(`/admin/quarantine/${id}/release`, { method: 'POST' });
		if (res.ok) { await loadStats(); await loadItems(); showPreview = false; previewItem = null; }
	}

	async function reject(id: number) {
		const res = await adminFetch(`/admin/quarantine/${id}/reject`, { method: 'POST' });
		if (res.ok) { await loadStats(); await loadItems(); showPreview = false; previewItem = null; }
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Quarantine</h1>
			<p>Held messages flagged as spam or malicious.</p>
		</div>
	</header>

	<div class="sj-stats-row">
		<span class="sj-stat-badge sj-stat--active"><Badge variant="warning" dot={true} label={'Active: ' + stats.active} /></span>
		<span class="sj-stat-badge"><Badge variant="success" dot={true} label={'Released: ' + stats.released} /></span>
		<span class="sj-stat-badge"><Badge variant="danger" dot={true} label={'Rejected: ' + stats.rejected} /></span>
	</div>

	<div class="sj-toolbar">
		<select class="sj-select" bind:value={status} onchange={loadItems}>
			<option value="active">Active</option>
			<option value="released">Released</option>
			<option value="rejected">Rejected</option>
		</select>
		<input class="sj-input" type="search" placeholder="Search by from or subject…" bind:value={query} oninput={loadItems} />
	</div>

	<Card flush={true}>
		{#if loading}
			<EmptyState title="Loading…" />
		{:else if items.length === 0}
			<EmptyState title="No quarantined messages found." />
		{:else}
			<table class="sj-table">
				<thead><tr><th>Date</th><th>From</th><th>Subject</th><th>Recipient</th><th>Reason</th><th>Status</th><th></th></tr></thead>
				<tbody>
					{#each items as item}
						<tr>
							<td>{new Date(item.quarantinedAt).toLocaleDateString()}</td>
							<td>{item.fromAddr}</td>
							<td>{item.subject}</td>
							<td>{item.recipient}</td>
							<td>{item.virusName || item.reason}</td>
							<td>
								{#if item.releasedAt}<Badge variant="success" label="Released" />
								{:else if item.rejectedAt}<Badge variant="danger" label="Rejected" />
								{:else}<Badge variant="warning" dot={true} label="Active" />
								{/if}
							</td>
							<td class="sj-actions">
								<Button variant="ghost" size="sm" onclick={() => preview(item.id)} disabled={!!item.releasedAt || !!item.rejectedAt}>Preview</Button>
								<Button variant="secondary" size="sm" onclick={() => release(item.id)} disabled={!!item.releasedAt || !!item.rejectedAt || !hasPermission($adminPermissions, 'security.write')}>Release</Button>
								<Button variant="ghost" size="sm" onclick={() => reject(item.id)} disabled={!!item.releasedAt || !!item.rejectedAt || !hasPermission($adminPermissions, 'security.write')}>Reject</Button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</Card>

	{#if showPreview && previewItem}
	<Dialog open={showPreview} title="Message preview" wide={true} onClose={() => { showPreview = false; previewItem = null; }}>
		{#snippet children()}
			<p><strong>From:</strong> {previewItem.fromAddr}</p>
			<p><strong>Subject:</strong> {previewItem.subject}</p>
			<p><strong>Quarantined:</strong> {new Date(previewItem.quarantinedAt).toLocaleString()}</p>
			<div class="sj-preview-toggle">
				<Button variant="ghost" size="sm" onclick={() => (showSource = !showSource)}>
					{showSource ? 'Show rendered' : 'View source'}
				</Button>
			</div>
			{#if showSource}
				<!-- Inert byte path: raw bytes as HTML-escaped text (Svelte text
				     interpolation escapes; NEVER srcdoc/{@html}). -->
				<pre class="sj-preview-source">{previewRaw}</pre>
			{:else}
				<div class="sj-preview-frame"><iframe sandbox="" srcdoc={previewHTML} title="Message preview"></iframe></div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => { showPreview = false; previewItem = null; }}>Close</Button>
		{/snippet}
	</Dialog>
	{/if}
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-stats-row { display: flex; gap: 8px; margin-bottom: 12px; }
	.sj-toolbar { display: flex; gap: 8px; margin-bottom: 12px; }
	.sj-select { height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); }
	.sj-select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-input { flex: 1; height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); max-width: 320px; }
	.sj-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); white-space: nowrap; }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); }
	.sj-actions { display: flex; gap: 4px; white-space: nowrap; }
	.sj-preview-toggle { display: flex; justify-content: flex-end; margin: 8px 0 0; }
	.sj-preview-frame { border: 1px solid var(--border-default); border-radius: var(--radius-sm); margin: 8px 0; }
	.sj-preview-frame iframe { width: 100%; height: 400px; border: none; }
	.sj-preview-source { width: 100%; height: 400px; margin: 8px 0; padding: 8px; overflow: auto; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font-family: var(--font-mono, monospace); font-size: var(--text-xs); white-space: pre-wrap; word-break: break-all; }
</style>
