<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Badge, Button, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';

	let d = $state<any>({});

	async function loadStats() {
		const res = await adminFetch('/admin/spam');
		if (res.ok) d = await res.json();
	}

	onMount(loadStats);

	async function resetModel(userId: number, email: string) {
		if (!confirm(`Reset spam model for ${email}? All training data will be lost.`)) return;
		const res = await adminFetch(`/admin/spam/models/${userId}`, { method: 'DELETE' });
		if (!res.ok) { showToast('Failed to reset model'); return; }
		await loadStats();
	}

	async function toggleModel(userId: number, email: string, disabled: boolean) {
		const label = disabled ? 're-enable FTRL scoring' : 'disable FTRL scoring';
		if (!confirm(`${label} for ${email}?`)) return;
		const action = disabled ? 'enable' : 'disable';
		const res = await adminFetch(`/admin/spam/models/${userId}/${action}`, { method: 'POST' });
		if (!res.ok) { showToast('Failed to update model'); return; }
		await loadStats();
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>Spam</h1>
		</div>
	</header>

	<Card>
		{#snippet children()}
			<div class="sj-stat-grid">
				<Card>
					{#snippet children()}
						<div class="sj-stat">
							<span class="sj-stat-label">Status</span>
							<span class="sj-stat-value" class:sj-stat-value--enabled={d.enabled} class:sj-stat-value--disabled={!d.enabled}>
								{d.enabled ? 'Enabled' : 'Disabled'}
							</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-stat">
							<span class="sj-stat-label">Trained Users</span>
							<span class="sj-stat-value">{d.total_models ?? 0}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-stat">
							<span class="sj-stat-label">Total Training Samples</span>
							<span class="sj-stat-value">{d.total_samples ?? 0}</span>
						</div>
					{/snippet}
				</Card>
				<Card>
					{#snippet children()}
						<div class="sj-stat">
							<span class="sj-stat-label">Active This Week</span>
							<span class="sj-stat-value">{d.active_week ?? 0}</span>
						</div>
					{/snippet}
				</Card>
			</div>

			{#if (d.total_classified ?? 0) > 0}
				<div class="sj-stat-grid" style="margin-top: 12px;">
					<Card>
						{#snippet children()}
							<div class="sj-stat">
								<span class="sj-stat-label">False Positive Rate ({d.total_fp} rescues / {d.total_classified})</span>
								<span class="sj-stat-value">{(d.fp_rate * 100).toFixed(2)}%</span>
							</div>
						{/snippet}
					</Card>
				</div>
			{/if}

			<div class="sj-section" style="margin-top: 16px;">
				<h2 class="sj-section-head">Top Users</h2>
				<Card flush={true}>
					{#snippet children()}
						<table class="sj-table">
							<thead><tr><th>User</th><th>Samples</th><th>Model Size</th><th>Last Trained</th><th></th></tr></thead>
							<tbody>
								{#each d.top_users ?? [] as u}
									<tr>
										<td>{u.email} {u.disabled ? '(disabled)' : ''}</td>
										<td>{u.sample_count}</td>
										<td>{u.model_size_kb} KB</td>
										<td>{u.trained_at}</td>
										<td>
											<div class="sj-actions">
												<Button variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'security.write')} onclick={() => toggleModel(u.user_id, u.email, u.disabled)}>
													{u.disabled ? 'Enable' : 'Disable'}
												</Button>
												<Button variant="danger" size="sm" disabled={!hasPermission($adminPermissions, 'security.write')} onclick={() => resetModel(u.user_id, u.email)}>
													Reset
												</Button>
											</div>
										</td>
									</tr>
								{:else}
									<tr><td colspan="5" class="sj-empty-cell">No trained models yet</td></tr>
								{/each}
							</tbody>
						</table>
					{/snippet}
				</Card>
			</div>

			<p class="sj-meta">
				Feature space: {(d.feature_size ?? 0).toLocaleString()} buckets &middot;
				Min samples before scoring: {d.min_samples ?? 0}
			</p>
		{/snippet}
	</Card>
</div>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
	}
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-section-head {
		margin: 0 0 8px;
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-stat-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 12px;
	}
	.sj-stat {
		padding: 4px 0;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.sj-stat-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sj-stat-value {
		font-size: var(--text-xl);
		font-weight: 600;
		color: var(--text-primary);
		font-family: var(--font-mono);
	}
	.sj-stat-value--enabled { color: var(--success-fg); }
	.sj-stat-value--disabled { color: var(--text-disabled); }
	.sj-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.sj-table th {
		text-align: left;
		padding: 8px 12px;
		font-size: var(--text-2xs);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		font-weight: 600;
		border-bottom: 1px solid var(--border-default);
	}
	.sj-table td {
		padding: 8px 12px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-actions { display: flex; gap: 4px; }
	.sj-empty-cell {
		color: var(--text-tertiary);
		font-style: italic;
	}
	.sj-meta {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin-top: 12px;
	}
</style>
