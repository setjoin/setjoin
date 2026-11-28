<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { sanitizeHTML } from '$lib/sanitize';
	import { typedFetch } from '$lib/http';
	import { createSettingsResource } from '$lib/composables/settings-resource.svelte';
	import { authedBootstrap } from '$lib/composables/authed-bootstrap.svelte';
	import {
		Card,
		Table,
		Button,
		Badge,
		Dialog,
		EmptyState,
		Spinner,
		showToast,
		type TableColumn
	} from '$lib/components/ui';

	interface QuarantineItem {
		id: number;
		quarantinedAt: string;
		fromAddr: string;
		subject: string;
		reason: string;
		virusName?: string;
		releasedAt?: string;
		rejectedAt?: string;
		html?: string;
	}

	const RELEASE_WINDOW_MS = 6000;

	// Resource layer: block every fetch the sandboxed preview could fire
	// (tracking beacons, remote CSS/fonts). Prepended AFTER sanitize because
	// DOMPurify strips <meta>/<head>. data: images are intentionally blocked too
	// (decoder surface + visual lure). frame-ancestors is omitted — a <meta> CSP
	// ignores it and the parent already sets it.
	const PREVIEW_CSP =
		'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">';

	let items = $state<QuarantineItem[]>([]);
	let previewItem = $state<QuarantineItem | null>(null);
	let previewHTML = $state('');
	let loading = $state(false);
	let acting = $state<Set<number>>(new Set());
	let rejectTarget = $state<QuarantineItem | null>(null);

	// Every call runs through the shared settings-resource composable or the
	// $lib/http seam (timeout/abort/typed errors AND the 401 outcome — its
	// login redirect): the page no longer hand-rolls any fetch + res.ok chain.
	// The list load and the post-action reloads ride the list resource; the
	// one-shot preview read uses the typed seam directly.
	const listRes = createSettingsResource<{ items?: QuarantineItem[] }>({
		load: { url: '/api/quarantine?limit=50', method: 'GET' },
	});

	// Pending optimistic releases keyed by item id (act-then-undo window).
	const pendingReleases = new Map<number, ReturnType<typeof setTimeout>>();

	const columns: TableColumn[] = [
		{ key: 'quarantinedAt', label: 'Date' },
		{ key: 'fromAddr', label: 'From' },
		{ key: 'subject', label: 'Subject' },
		{ key: 'reason', label: 'Reason' },
		{ key: 'status', label: 'Status' },
		{ key: 'actions', label: 'Actions' }
	];

	const rows = $derived(items as unknown as Array<Record<string, unknown>>);

	// WP5: authenticated mount bootstrap. authedBootstrap probes the session
	// and runs the protected list load ONLY after proven authentication; an
	// unproven page settles to its silent-empty surface (redirects belong to
	// the auth seams) and an unmount aborts in-flight work.
	authedBootstrap(
		(signal) => void loadItems(signal),
		{ onUnproven: () => { loading = false; } }
	);
	onMount(() => () => listRes.cleanup());

	async function loadItems(signal?: AbortSignal) {
		loading = true;
		const data = await listRes.load({ signal });
		if (data) items = data.items ?? [];
		// A 401 is the seam's outcome: httpRequest has already fired its login
		// redirect; the page keeps its silent-empty UX for other failures.
		loading = false;
	}

	function startActing(id: number) {
		acting = new Set([...acting, id]);
	}

	function stopActing(id: number) {
		const next = new Set(acting);
		next.delete(id);
		acting = next;
	}

	async function preview(id: number) {
		if (acting.has(id)) return;
		startActing(id);
		try {
			const data = await typedFetch<QuarantineItem>(`/api/quarantine/${id}/preview`);
			previewItem = data;
			previewHTML = PREVIEW_CSP + sanitizeHTML(data.html || '');
		} catch {
			// Preserve the silent-failure UX: a failed preview leaves the dialog
			// closed (the seam's 401 redirect — if any — already happened).
		} finally {
			stopActing(id);
		}
	}

	// Release is reversible within an undo window: mark the row released
	// optimistically and defer the network call so Undo can cancel it.
	function release(item: QuarantineItem) {
		const id = item.id;
		if (acting.has(id) || pendingReleases.has(id)) return;
		items = items.map((it) =>
			it.id === id ? { ...it, releasedAt: new Date().toISOString() } : it
		);

		const timer = setTimeout(() => commitRelease(id), RELEASE_WINDOW_MS);
		pendingReleases.set(id, timer);

		showToast('Message released to your inbox.', {
			actionLabel: 'Undo',
			durationMs: RELEASE_WINDOW_MS,
			onAction: () => undoRelease(id)
		});
	}

	function undoRelease(id: number) {
		const timer = pendingReleases.get(id);
		if (timer) clearTimeout(timer);
		pendingReleases.delete(id);
		items = items.map((it) =>
			it.id === id ? { ...it, releasedAt: undefined } : it
		);
	}

	async function commitRelease(id: number) {
		pendingReleases.delete(id);
		startActing(id);
		try {
			const result = await listRes.save({
				url: `/api/quarantine/${id}/release`, method: 'POST',
			});
			if (result.ok) {
				await loadItems();
				if (previewItem?.id === id) previewItem = null;
			}
		} finally {
			stopActing(id);
		}
	}

	function askReject(item: QuarantineItem) {
		rejectTarget = item;
	}

	async function confirmReject() {
		const item = rejectTarget;
		rejectTarget = null;
		if (!item || acting.has(item.id)) return;
		startActing(item.id);
		try {
			const result = await listRes.save({
				url: `/api/quarantine/${item.id}/reject`, method: 'POST',
			});
			if (result.ok) {
				await loadItems();
				if (previewItem?.id === item.id) previewItem = null;
			}
		} finally {
			stopActing(item.id);
		}
	}

	function isInactive(item: QuarantineItem): boolean {
		return !!item.releasedAt || !!item.rejectedAt;
	}
</script>

<div class="quarantine-page">
	<h2>Quarantined messages</h2>
	<p class="subtitle">Messages held for your safety. Release only messages you recognize and trust.</p>

	{#if loading}
		<div class="loading"><Spinner size={20} /></div>
	{:else if items.length === 0}
		<Card flush={true}>
			<EmptyState title="Your quarantine is empty. No suspicious messages have been detected." />
		</Card>
	{:else}
		<Card flush={true}>
			<Table {columns} {rows}>
				{#snippet cell(row, col)}
					{@const item = row as unknown as QuarantineItem}
					{#if col.key === 'quarantinedAt'}
						{new Date(item.quarantinedAt).toLocaleDateString()}
					{:else if col.key === 'fromAddr'}
						{item.fromAddr}
					{:else if col.key === 'subject'}
						{item.subject}
					{:else if col.key === 'reason'}
						{item.virusName || item.reason}
					{:else if col.key === 'status'}
						{#if item.releasedAt}
							<Badge variant="success" label="Released" />
						{:else if item.rejectedAt}
							<Badge variant="danger" label="Rejected" />
						{:else}
							<Badge variant="warning" dot={true} label="Active" />
						{/if}
					{:else if col.key === 'actions'}
						<span class="actions">
							<Button
								variant="ghost"
								size="sm"
								onclick={() => preview(item.id)}
								disabled={isInactive(item) || acting.has(item.id)}
							>
								Preview
							</Button>
							<Button
								variant="secondary"
								size="sm"
								onclick={() => release(item)}
								disabled={isInactive(item) || acting.has(item.id)}
							>
								Release
							</Button>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => askReject(item)}
								disabled={isInactive(item) || acting.has(item.id)}
							>
								Reject
							</Button>
						</span>
					{/if}
				{/snippet}
			</Table>
		</Card>
	{/if}

	{#if previewItem}
		{@const pv = previewItem}
		<Dialog
			open={true}
			title="Message preview"
			wide={true}
			onClose={() => (previewItem = null)}
		>
			{#snippet children()}
				<p><strong>From:</strong> {pv.fromAddr}</p>
				<p><strong>Subject:</strong> {pv.subject}</p>
				<p><strong>Quarantined:</strong> {new Date(pv.quarantinedAt).toLocaleString()}</p>
				<div class="preview-frame">
					<iframe sandbox="" srcdoc={previewHTML} title="Message preview"></iframe>
				</div>
			{/snippet}
			{#snippet footer()}
				<Button variant="ghost" onclick={() => (previewItem = null)}>Close</Button>
			{/snippet}
		</Dialog>
	{/if}

	{#if rejectTarget}
		{@const rt = rejectTarget}
		<Dialog
			open={true}
			title="Reject message"
			onClose={() => (rejectTarget = null)}
		>
			{#snippet children()}
				<p>
					Permanently delete the message from {rt.fromAddr}? This cannot be undone.
				</p>
			{/snippet}
			{#snippet footer()}
				<Button variant="ghost" onclick={() => (rejectTarget = null)}>Cancel</Button>
				<Button variant="danger" onclick={confirmReject}>Reject message</Button>
			{/snippet}
		</Dialog>
	{/if}
</div>

<style>
	.quarantine-page {
		padding: var(--space-6);
		max-width: 900px;
		margin: 0 auto;
		font-family: var(--font-sans);
		color: var(--text-primary);
	}
	h2 {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		margin: 0 0 var(--space-1);
	}
	.subtitle {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-6);
	}
	.loading {
		display: flex;
		justify-content: center;
		padding: var(--space-12) 0;
	}
	.actions {
		display: inline-flex;
		gap: var(--space-1);
	}
	.preview-frame {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		margin: var(--space-4) 0;
	}
	.preview-frame iframe {
		width: 100%;
		height: 400px;
		border: none;
	}
</style>
