<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { user } from '$lib/stores/auth';
	import { Card } from '$lib/components/ui';

	interface HealthStatus {
		status: string;
		version?: string;
		uptime?: string;
		go_version?: string;
		db_status?: string;
		s3_status?: string;
	}

	let health: HealthStatus | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		try {
			const res = await fetch('/health', { credentials: 'include' });
			if (res.ok) {
				health = await res.json();
			}
		} catch (e) {
			error = parseError(e).message;
			logger.error('settings/about: failed to load health', e);
		}
		loading = false;
	});

	let brandName = $derived('SetJoin');
	let userEmail = $derived($user?.email ?? '');
</script>

<div class="sj-about-page">
	<h1 class="sj-page-title">About</h1>

	<div class="sj-about-hero">
		<img class="sj-about-logo sj-ink" src="/brand/logo-mark.svg" alt="SetJoin" width="64" height="64" />
		<h2>{brandName}</h2>
		<p class="sj-about-tagline">集合 &middot; Self-hosted workspace</p>
		{#if health?.version}
			<code class="sj-version-code">Version {health.version}</code>
		{/if}
	</div>

	{#if loading}
		<p class="sj-loading">{t('common.loading')}</p>
	{:else if health}
		<Card title="System Status">
			<div class="sj-status-grid">
				<div class="sj-status-item">
					<span class="sj-status-label">Server</span>
					<span class="sj-status-val sj-ok">{health.status || 'healthy'}</span>
				</div>
				<div class="sj-status-item">
					<span class="sj-status-label">Database</span>
					<span class="sj-status-val" class:sj-ok={health.db_status === 'ok'} class:sj-err={health.db_status !== 'ok'}>
						{health.db_status || 'connected'}
					</span>
				</div>
				<div class="sj-status-item">
					<span class="sj-status-label">Blob Storage</span>
					<span class="sj-status-val" class:sj-ok={health.s3_status === 'ok'} class:sj-err={health.s3_status !== 'ok'}>
						{health.s3_status || 'connected'}
					</span>
				</div>
				{#if health.uptime}
					<div class="sj-status-item">
						<span class="sj-status-label">Uptime</span>
						<span class="sj-status-val">{health.uptime}</span>
					</div>
				{/if}
				{#if health.go_version}
					<div class="sj-status-item">
						<span class="sj-status-label">Go Version</span>
						<span class="sj-status-val">{health.go_version}</span>
					</div>
				{/if}
			</div>
		</Card>
	{:else if error}
		<p class="sj-error">Unable to load system status: {error}</p>
	{/if}

	<Card title="Account">
		{#if userEmail}
			<code class="sj-mono-block">{userEmail}</code>
		{/if}
		<p class="sj-card-desc">SetJoin Mail is part of the SetJoin platform — a self-hosted alternative to Microsoft 365 for organizations of 300 to 10,000 users.</p>
	</Card>

	<Card title="Open Source">
		<p class="sj-card-desc">SetJoin is built on open standards and open source software. See the documentation for a full list of dependencies and licenses.</p>
		<div class="sj-link-list">
			<a href="https://github.com/setjoin/setjoin" target="_blank" rel="noopener" class="sj-link-item">
				GitHub Repository
				<span class="sj-link-arrow">&rarr;</span>
			</a>
			<a href="/docs" class="sj-link-item">
				Documentation
				<span class="sj-link-arrow">&rarr;</span>
			</a>
		</div>
	</Card>
</div>

<style>
	.sj-about-page {
		max-width: 640px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}

	.sj-about-hero {
		display: flex;
		flex-direction: column;
		align-items: center;
		padding: 32px 24px;
		border-radius: var(--radius-lg);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		text-align: center;
	}

	.sj-about-logo {
		display: block;
		width: 64px;
		height: 64px;
		margin-bottom: 12px;
	}

	.sj-about-hero h2 {
		font-size: var(--text-xl);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 8px;
	}

	.sj-about-tagline {
		font-size: var(--text-md);
		color: var(--text-secondary);
		margin: 0 0 8px;
	}

	.sj-version-code {
		font-size: var(--text-sm);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
		background: var(--surface-sunken);
		padding: 4px 12px;
		border-radius: var(--radius-sm);
	}

	.sj-status-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.sj-status-item {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.sj-status-label {
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.sj-status-val {
		font-size: var(--text-md);
		color: var(--text-primary);
	}

	.sj-ok { color: var(--success-fg); }
	.sj-err { color: var(--danger-fg); }

	.sj-mono-block {
		font-family: var(--font-mono);
		font-size: var(--text-md);
		color: var(--text-primary);
		margin-bottom: 8px;
	}

	.sj-card-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	.sj-link-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 12px;
	}

	.sj-link-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 12px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		color: var(--text-accent);
		text-decoration: none;
		font-size: var(--text-md);
		font-weight: 500;
		transition: background 0.15s ease;
	}

	.sj-link-item:hover { background: var(--surface-hover); }
	.sj-link-arrow { font-size: 18px; }

	.sj-loading { color: var(--text-tertiary); text-align: center; }
	.sj-error { color: var(--danger-fg); }
</style>
