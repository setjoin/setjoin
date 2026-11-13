<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		Card, Badge, Button,
		EmptyState, Spinner, showToast,
	} from '$lib/components/ui';
	import { adminAlertList, adminAlertAck, adminAlertUnsuppress, type AlertStatus } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { alertSeverity, formatAuditTime } from '$lib/admin/audit';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';

	let alerts = $state<AlertStatus[]>([]);
	let loading = $state(true);
	let error = $state('');

	onMount(() => load());

	async function load() {
		loading = true;
		error = '';
		try {
			alerts = await adminAlertList();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function deriveText(a: AlertStatus): string {
		const parts = [a.checkName];
		if (a.lastError) parts.push(a.lastError);
		if (a.consecutive > 1) parts.push(`${a.consecutive} consecutive failures`);
		return parts.join(' — ');
	}

	function deriveSeverityLabel(a: AlertStatus): string {
		if (a.suppressed) return 'Suppressed';
		if (a.consecutive >= 3) return 'Firing';
		if (a.consecutive >= 1) return 'Warning';
		return 'OK';
	}

	async function acknowledge(a: AlertStatus) {
		try {
			await adminAlertAck(a.checkName);
			showToast('Alert acknowledged', {
				actionLabel: 'Undo',
				onAction: async () => {
					await adminAlertUnsuppress(a.checkName);
					await load();
				},
			});
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function isFiring(a: AlertStatus): boolean {
		return !a.suppressed;
	}
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>{t('admin.sidebar.alerts')}</h1>
		<p class="page-desc">
			Raised by monitoring and the threat interceptor.
		</p>
	</div>
</header>

{#if loading}
	<div class="alerts-empty">
		<Spinner size={28} />
		<div>Loading alerts...</div>
	</div>
{:else if error}
	<div class="alerts-error">
		<Icon name="BellRing" size={24} strokeWidth={1.75} />
		<div>{error}</div>
		<Button variant="secondary" size="sm" onclick={load}>Retry</Button>
	</div>
{:else if alerts.length === 0}
	<EmptyState title="No active alerts. Health checks are passing." watermark={true} />
{:else}
	<Card flush={true}>
		{#each alerts as a (a.checkName)}
			{@const variant = alertSeverity(a.consecutive, a.suppressed)}
			<div class="alert-row" class:alert-row--firing={isFiring(a)}>
				<Badge variant={variant} dot={true} label={deriveSeverityLabel(a)} />
				<span class="alert-text">{deriveText(a)}</span>
				<span class="alert-time">{formatAuditTime(a.lastChecked ?? '')}</span>
				{#if isFiring(a)}
					<Button
						variant="ghost"
						size="sm"
						disabled={!hasPermission($adminPermissions, 'security.write')}
						onclick={() => acknowledge(a)}
					>
						Acknowledge
					</Button>
				{:else}
					<span class="alert-suppressed-label">Suppressed</span>
				{/if}
			</div>
		{/each}
	</Card>
{/if}

<style>
	.page-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 16px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}

	.page-header-left {
		flex: 1;
		min-width: 0;
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

	.alert-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 16px;
		border-bottom: 1px solid var(--border-subtle);
		flex-wrap: wrap;
	}

	.alert-row:last-child {
		border-bottom: none;
	}

	.alert-text {
		flex: 1;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		line-height: var(--leading-normal);
		min-width: 160px;
	}

	.alert-time {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		white-space: nowrap;
	}

	.alert-suppressed-label {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.alerts-empty {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 64px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.alerts-error {
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
