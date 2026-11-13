<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { user } from '$lib/stores/auth';
	import { loadSession, emailDeletedQuery, emailRecover, emailPurge } from '$lib/jmap/client';
	import { parseError } from '$lib/errors';
	import Icon from '$lib/components/Icon.svelte';
	import {
		Card,
		Table,
		Button,
		Checkbox,
		Badge,
		Dialog,
		EmptyState,
		Spinner,
		type TableColumn
	} from '$lib/components/ui';
	import type { Email } from '$lib/types/jmap';

	let emails = $state<Email[]>([]);
	let loading = $state(false);
	let error = $state('');
	let selectedIds = $state<Set<string>>(new Set());
	let processing = $state<Set<string>>(new Set());
	let purgeDays = $state(30);
	let purgeDialog = $state<{ ids: string[] } | null>(null);

	const columns: TableColumn[] = [
		{ key: 'select', label: '' },
		{ key: 'subject', label: 'Subject' },
		{ key: 'from', label: 'From' },
		{ key: 'deleted', label: 'Deleted' },
		{ key: 'autopurge', label: 'Auto-purge' },
		{ key: 'actions', label: 'Actions' }
	];

	const rows = $derived(emails as unknown as Array<Record<string, unknown>>);
	const allSelected = $derived(emails.length > 0 && selectedIds.size === emails.length);
	const someSelected = $derived(selectedIds.size > 0 && selectedIds.size < emails.length);

	onMount(async () => {
		if (!$user?.hasMailbox) {
			goto('/apps');
			return;
		}
		try {
			const sessionResp = await fetch('/jmap/session');
			if (sessionResp.ok) {
				const session = await sessionResp.json();
				purgeDays = session.purgeConfig?.deletedPurgeDays ?? 30;
			}
		} catch {
			// keep default purgeDays on failure
		}
		// Load the JMAP session once on mount (the account id is cached for all
		// subsequent recover/purge calls), then the deleted list. Guard the
		// session load: a transient /.well-known/jmap failure must surface as an
		// error, not reject the async onMount with an unhandled rejection (every
		// other page that calls loadSession() in onMount guards it the same way).
		try {
			await loadSession();
		} catch (e) {
			error = parseError(e).message;
			return;
		}
		await loadDeleted();
	});

	async function loadDeleted() {
		loading = true;
		error = '';
		try {
			const res = await emailDeletedQuery(100, 0);
			emails = (res.list as Email[]) ?? [];
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function daysUntilPurge(deletedAt?: string): number {
		if (!deletedAt) return purgeDays;
		const deleted = new Date(deletedAt);
		const purge = new Date(deleted.getTime() + purgeDays * 24 * 60 * 60 * 1000);
		const now = new Date();
		const diff = Math.ceil((purge.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
		return Math.max(0, diff);
	}

	async function recoverOne(id: string) {
		processing = new Set(processing).add(id);
		try {
			await emailRecover([id]);
			emails = emails.filter((e) => e.id !== id);
			const next = new Set(selectedIds);
			next.delete(id);
			selectedIds = next;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			const next = new Set(processing);
			next.delete(id);
			processing = next;
		}
	}

	async function recoverSelected() {
		if (selectedIds.size === 0) return;
		const ids = Array.from(selectedIds);
		processing = new Set(ids);
		try {
			await emailRecover(ids);
			emails = emails.filter((e) => !selectedIds.has(e.id));
			selectedIds = new Set();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			processing = new Set();
		}
	}

	function askPurge(ids: string[]) {
		if (ids.length === 0) return;
		purgeDialog = { ids };
	}

	async function confirmPurge() {
		const ids = purgeDialog?.ids ?? [];
		purgeDialog = null;
		if (ids.length === 0) return;
		processing = new Set(ids);
		try {
			await emailPurge(ids);
			const removed = new Set(ids);
			emails = emails.filter((e) => !removed.has(e.id));
			const nextSel = new Set(selectedIds);
			for (const id of ids) nextSel.delete(id);
			selectedIds = nextSel;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			processing = new Set();
		}
	}

	function toggleSelect(id: string) {
		const next = new Set(selectedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		selectedIds = next;
	}

	function selectAll() {
		if (selectedIds.size === emails.length) {
			selectedIds = new Set();
		} else {
			selectedIds = new Set(emails.map((e) => e.id));
		}
	}
</script>

<div class="recover-page">
	<header>
		<h1>Recover deleted items</h1>
		<p class="subtitle">
			Deleted items are automatically purged after {purgeDays} days. Emails here do not count against
			your quota.
		</p>
	</header>

	{#if error}
		<div class="alert">{error}</div>
	{/if}

	<div class="toolbar">
		<Button variant="secondary" onclick={loadDeleted} disabled={loading}>
			{loading ? 'Loading…' : 'Refresh'}
		</Button>
		{#if emails.length > 0}
			<Checkbox
				checked={allSelected}
				indeterminate={someSelected}
				label="Select all"
				onchange={selectAll}
			/>
		{/if}
		{#if selectedIds.size > 0}
			<Button variant="ghost" onclick={recoverSelected}>
				Recover selected ({selectedIds.size})
			</Button>
			<Button variant="danger" onclick={() => askPurge(Array.from(selectedIds))}>
				Purge selected ({selectedIds.size})
			</Button>
		{/if}
	</div>

	{#if loading && emails.length === 0}
		<div class="loading"><Spinner size={20} /></div>
	{:else if emails.length === 0}
		<Card flush={true}>
			<EmptyState title="No deleted items to recover." />
		</Card>
	{:else}
		<Card flush={true}>
			<Table {columns} {rows}>
				{#snippet cell(row, col)}
					{@const email = row as unknown as Email}
					{#if col.key === 'select'}
						<Checkbox
							checked={selectedIds.has(email.id)}
							label={`Select ${email.subject || '(no subject)'}`}
							onchange={() => toggleSelect(email.id)}
						/>
					{:else if col.key === 'subject'}
						{email.subject || '(no subject)'}
					{:else if col.key === 'from'}
						{email.from?.[0]?.email || 'Unknown'}
					{:else if col.key === 'deleted'}
						{new Date(email.deletedAt || '').toLocaleString()}
					{:else if col.key === 'autopurge'}
						{#if email.held}
							<span class="held-badge" title="Protected by litigation hold">
								<Icon name="Lock" size={12} />
								<Badge variant="warning" label="Hold" />
							</span>
						{:else}
							{daysUntilPurge(email.deletedAt)} days
						{/if}
					{:else if col.key === 'actions'}
						<span class="row-actions">
							<Button
								variant="ghost"
								size="sm"
								onclick={() => recoverOne(email.id)}
								disabled={processing.has(email.id)}
							>
								{processing.has(email.id) ? '…' : 'Recover'}
							</Button>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => askPurge([email.id])}
								disabled={processing.has(email.id)}
							>
								{processing.has(email.id) ? '…' : 'Purge'}
							</Button>
						</span>
					{/if}
				{/snippet}
			</Table>
		</Card>
	{/if}
</div>

{#if purgeDialog}
	{@const count = purgeDialog.ids.length}
	<Dialog open={true} title="Purge deleted items" onClose={() => (purgeDialog = null)}>
		{#snippet children()}
			<p>
				Permanently delete {count}
				{count === 1 ? 'email' : 'emails'}? This cannot be undone.
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (purgeDialog = null)}>Cancel</Button>
			<Button variant="danger" onclick={confirmPurge}>Purge</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.recover-page {
		padding: var(--space-6);
		font-family: var(--font-sans);
		max-width: 1200px;
		margin: 0 auto;
		color: var(--text-primary);
	}

	header {
		margin-bottom: var(--space-5);
	}

	h1 {
		font-size: var(--text-2xl);
		font-weight: var(--weight-bold);
		letter-spacing: var(--tracking-display);
		margin: 0 0 var(--space-1);
		color: var(--text-primary);
	}

	.subtitle {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
		margin: 0;
	}

	.toolbar {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
		align-items: center;
		flex-wrap: wrap;
	}

	.alert {
		padding: var(--space-3) var(--space-4);
		border-radius: var(--radius-md);
		margin-bottom: var(--space-4);
		font-size: var(--text-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
	}

	.loading {
		display: flex;
		justify-content: center;
		padding: var(--space-12) 0;
	}

	.held-badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		color: var(--warning-fg);
	}

	.row-actions {
		display: inline-flex;
		gap: var(--space-1);
	}
</style>
