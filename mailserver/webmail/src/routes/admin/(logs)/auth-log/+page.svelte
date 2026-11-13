<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import {
		Card, Table, Button, Input,
		EmptyState, Spinner, type TableColumn,
	} from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';

	interface AuthLogEntry {
		id: number;
		userId?: number | null;
		email: string;
		event: string;
		provider: string;
		ipAddress: string;
		occurredAt: string;
	}

	const COLUMNS: TableColumn[] = [
		{ key: 'time', label: 'Time', sortable: false, mono: true },
		{ key: 'email', label: 'Email', sortable: false, mono: true },
		{ key: 'event', label: 'Event', sortable: false },
		{ key: 'provider', label: 'Provider', sortable: false, mono: true },
		{ key: 'ip', label: 'IP address', sortable: false, mono: true },
	];

	let entries = $state<AuthLogEntry[]>([]);
	let loading = $state(true);
	let error = $state('');
	let emailFilter = $state('');
	let eventFilter = $state('');
	let providerFilter = $state('');

	async function load() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			if (emailFilter) params.set('email', emailFilter);
			if (eventFilter) params.set('event', eventFilter);
			if (providerFilter) params.set('provider', providerFilter);
			params.set('limit', '200');
			const res = await adminFetch('/admin/auth-log?' + params.toString());
			entries = await res.json();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(() => load());

	function formatTime(iso: string): string {
		return new Date(iso).toLocaleString();
	}

	function eventLabel(event: string): string {
		const labels: Record<string, string> = {
			login_success: 'Login success',
			login_failure: 'Login failure',
			logout: 'Logout',
			mfa_success: 'MFA success',
			mfa_failure: 'MFA failure',
			password_change: 'Password change',
			password_reset: 'Password reset',
			account_locked: 'Account locked',
			account_unlocked: 'Account unlocked',
			session_expired: 'Session expired',
		};
		return labels[event] ?? event;
	}

	let rows = $derived(
		entries.map((e) => ({
			time: formatTime(e.occurredAt),
			email: e.email,
			event: eventLabel(e.event),
			provider: e.provider,
			ip: e.ipAddress,
		})) as Record<string, unknown>[],
	);
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>{t('admin.sidebar.auth_log')}</h1>
		<p class="page-desc">Sign-in, MFA and session events across every auth provider.</p>
	</div>
</header>

<div class="filter-bar">
	<div class="filter-input-wrap">
		<Input type="text" placeholder="Filter by email" mono={true} bind:value={emailFilter} />
	</div>
	<div class="filter-input-wrap">
		<Input type="text" placeholder="Filter by event" mono={true} bind:value={eventFilter} />
	</div>
	<div class="filter-input-wrap">
		<Input type="text" placeholder="Filter by provider" mono={true} bind:value={providerFilter} />
	</div>
	<Button variant="secondary" size="md" onclick={load} disabled={loading}>
		<Icon name="Search" size={14} strokeWidth={1.75} />
		{t('admin.common.search')}
	</Button>
</div>

{#if loading}
	<div class="auth-log-empty">
		<Spinner size={28} />
		<div>{t('admin.dashboard.loading_health')}</div>
	</div>
{:else if error}
	<div class="auth-log-error">
		<Icon name="Key" size={24} strokeWidth={1.75} />
		<div>{error}</div>
		<Button variant="secondary" size="sm" onclick={load}>Retry</Button>
	</div>
{:else if entries.length === 0}
	<EmptyState title="No auth log entries found." watermark={true} />
{:else}
	<Card flush={true}>
		{#snippet children()}
			<Table columns={COLUMNS} rows={rows} />
		{/snippet}
	</Card>
{/if}

<style>
	.page-header {
		margin-bottom: 16px;
	}

	.page-header h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.page-desc {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: var(--leading-normal);
	}

	.filter-bar {
		display: flex;
		gap: 8px;
		margin-bottom: 12px;
		align-items: center;
		flex-wrap: wrap;
	}

	.filter-input-wrap {
		flex: 1 1 160px;
		max-width: 200px;
		min-width: 140px;
	}

	.auth-log-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 64px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.auth-log-error {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 12px;
		padding: 48px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		text-align: center;
	}
</style>
