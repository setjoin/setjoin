<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Button, Input, Card, Badge, Spinner, EmptyState } from '$lib/components/ui';

	interface NodeConfig {
		host: string;
		role: string;
		ssh_user: string;
		ssh_key: string;
	}

	interface DeploymentStep {
		name: string;
		status: string;
		output?: string;
		error?: string;
	}

	interface DeployState {
		profile: number;
		nodes: NodeConfig[];
		steps: DeploymentStep[];
		status: string;
		log: string[];
		started_at?: string;
	}

	let deployState = $state<DeployState | null>(null);
	let polling = $state(false);
	let pollTimer = $state<ReturnType<typeof setInterval> | null>(null);

	let nodes = $state<NodeConfig[]>([
		{ host: '', role: 'primary', ssh_user: 'root', ssh_key: '/root/.ssh/id_rsa' },
		{ host: '', role: 'standby', ssh_user: 'root', ssh_key: '/root/.ssh/id_rsa' },
		{ host: '', role: 'standby', ssh_user: 'root', ssh_key: '/root/.ssh/id_rsa' },
	]);
	let deploying = $state(false);
	let error = $state('');

	onMount(() => {
		loadStatus();
		return () => { if (pollTimer) clearInterval(pollTimer); };
	});

	async function loadStatus() {
		try {
			const resp = await adminFetch('/admin/deploy/status');
			deployState = await resp.json();
		} catch { /* ignore */ }
	}

	function startPolling() {
		polling = true;
		pollTimer = setInterval(async () => {
			await loadStatus();
			if (deployState && (deployState.status === 'done' || deployState.status === 'failed')) {
				stopPolling();
			}
		}, 2000);
	}

	function stopPolling() {
		polling = false;
		if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
	}

	async function startDeploy() {
		error = '';
		const filled = nodes.filter(n => n.host.trim() !== '');
		if (filled.length !== 3) {
			error = 'All 3 node hosts are required.';
			return;
		}
		deploying = true;
		try {
			await adminFetch('/admin/deploy/start', {
				method: 'POST',
				body: JSON.stringify({ nodes }),
			});
			startPolling();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			deploying = false;
		}
	}

	async function cancelDeploy() {
		try {
			await adminFetch('/admin/deploy/cancel', { method: 'POST' });
		} catch { /* ignore */ }
		stopPolling();
		await loadStatus();
	}

	function stepBadgeVariant(status: string): 'success' | 'danger' | 'warning' | 'neutral' {
		switch (status) {
			case 'ok': return 'success';
			case 'running': return 'warning';
			case 'failed': return 'danger';
			default: return 'neutral';
		}
	}

	function stepLabel(status: string): string {
		switch (status) {
			case 'ok': return 'Done';
			case 'running': return 'Running';
			case 'failed': return 'Failed';
			default: return 'Pending';
		}
	}

	function statusVariant(status: string): 'success' | 'danger' | 'warning' | 'neutral' {
		switch (status) {
			case 'done': return 'success';
			case 'deploying': return 'warning';
			case 'verifying': return 'warning';
			case 'failed': return 'danger';
			default: return 'neutral';
		}
	}

	function statusLabel(status: string): string {
		switch (status) {
			case 'done': return 'Complete';
			case 'deploying': return 'Deploying';
			case 'verifying': return 'Verifying';
			case 'failed': return 'Failed';
			default: return 'Ready';
		}
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>HA Deployment Wizard</h1>
			<p class="sj-page-desc">Deploy a 3-node high-availability mail server cluster via SSH.</p>
		</div>
	</header>

	{#if error}
		<div class="sj-alert-danger" role="alert">{error}</div>
	{/if}

	{#if deployState && (deployState.status === 'deploying' || deployState.status === 'verifying')}
		{@const ds = deployState}
		<Card>
			{#snippet children()}
				<div class="sj-deploy-header">
					<Badge variant={statusVariant(ds.status)} label={statusLabel(ds.status)} dot={true} />
				</div>
				{#if ds.steps.length > 0}
					<div class="sj-steps">
						{#each ds.steps as step}
							<div class="sj-step-row">
								<Badge variant={stepBadgeVariant(step.status)} label={stepLabel(step.status)} dot={true} />
								<span class="sj-step-name">{step.name}</span>
								{#if step.error}
									<span class="sj-step-error">{step.error}</span>
								{/if}
							</div>
						{/each}
					</div>
				{/if}
				<div class="sj-deploy-actions">
					<Button variant="danger" size="sm" onclick={cancelDeploy} disabled={!hasPermission($adminPermissions, 'system.upgrade')}>Cancel Deployment</Button>
				</div>
			{/snippet}
		</Card>
	{:else if deployState && deployState.status === 'done'}
		<Card>
			{#snippet children()}
				<div class="sj-deploy-header">
					<Badge variant="success" label="Complete" dot={true} />
				</div>
				<p class="sj-deploy-msg">The HA cluster is ready. Update your gateway DSN to point to Pgpool-II.</p>
			{/snippet}
		</Card>
	{:else if deployState && deployState.status === 'failed'}
		<Card>
			{#snippet children()}
				<div class="sj-deploy-header">
					<Badge variant="danger" label="Failed" dot={true} />
				</div>
				<p class="sj-deploy-msg">Check the step details below. Fix any issues and try again.</p>
			{/snippet}
		</Card>
	{/if}

	{#if !deployState || deployState.status === 'config' || deployState.status === 'done' || deployState.status === 'failed'}
		<Card>
			{#snippet children()}
				<h2 class="sj-section-head">Node Configuration</h2>
				<p class="sj-hint">Enter the hostnames/IPs and SSH credentials for 3 clean Ubuntu 24.04 servers.</p>

				{#each nodes as node, i}
					<fieldset class="sj-node-group">
						<legend>Node {i + 1} &mdash; {node.role === 'primary' ? 'Primary (read/write)' : 'Standby (read-only)'}</legend>
						<div class="sj-node-fields">
							<Input
								label="Host"
								type="text"
								value={node.host}
								placeholder="10.0.0.{i + 1}"
								oninput={(e) => node.host = (e.target as HTMLInputElement).value}
							/>
							<Input
								label="SSH User"
								type="text"
								value={node.ssh_user}
								placeholder="root"
								oninput={(e) => node.ssh_user = (e.target as HTMLInputElement).value}
							/>
						</div>
						<Input
							label="SSH Key Path"
							type="text"
							value={node.ssh_key}
							placeholder="/root/.ssh/id_rsa"
							oninput={(e) => node.ssh_key = (e.target as HTMLInputElement).value}
						/>
					</fieldset>
				{/each}

				<Button variant="primary" onclick={startDeploy} disabled={deploying || !hasPermission($adminPermissions, 'system.upgrade')}>
					{deploying ? 'Starting...' : 'Start Deployment'}
				</Button>
			{/snippet}
		</Card>
	{/if}

	{#if deployState && deployState.log && deployState.log.length > 0}
		{@const dl = deployState}
		<Card>
			{#snippet children()}
				<h2 class="sj-section-head">Deployment Log</h2>
				<pre class="sj-deploy-log">{dl.log.join('\n')}</pre>
			{/snippet}
		</Card>
	{/if}
</div>

<style>
	.sj-page { max-width: 900px; }
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-desc {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-alert-danger {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.sj-section-head {
		margin: 0 0 8px;
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0 0 12px;
	}
	.sj-deploy-header { margin-bottom: 12px; }
	.sj-deploy-actions { margin-top: 12px; }
	.sj-deploy-msg { font-size: var(--text-sm); color: var(--text-secondary); margin: 8px 0 0; }
	.sj-steps { margin: 12px 0; }
	.sj-step-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px 0;
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-step-row:last-child { border-bottom: none; }
	.sj-step-name { flex: 1; font-size: var(--text-sm); color: var(--text-primary); }
	.sj-step-error { font-size: var(--text-xs); color: var(--danger-fg); }
	.sj-node-group {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 16px;
		margin-bottom: 16px;
	}
	.sj-node-group legend {
		font-size: var(--text-sm);
		font-weight: 600;
		padding: 0 8px;
		color: var(--text-primary);
	}
	.sj-node-fields {
		display: flex;
		gap: 12px;
		margin-bottom: 12px;
	}
	.sj-node-fields > :global(*) {
		flex: 1;
	}
	.sj-deploy-log {
		background: var(--surface-sunken);
		padding: 16px;
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-family: var(--font-mono);
		max-height: 400px;
		overflow-y: auto;
		white-space: pre-wrap;
		color: var(--text-secondary);
		line-height: var(--leading-normal);
	}
</style>
