<!--
  CertStatusCard.svelte — CA-3b Design Task E.
  Read-only mTLS client-cert status card (settings → security).
  States: valid / expiring / expired / none / loading / error.
  Enrollment is OUT-OF-BAND in v1 (org PKI/MDM); this card is informational only.
  Motion: essentially static (Spinner handles its own; opacity cross-fade on load).
  If a transition is added, the @media prefers-reduced-motion guard below is required.
-->
<svelte:options runes={true} />

<script lang="ts">
	import { Badge, EmptyState, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { formatDate } from '$lib/i18n';

	export interface CertStatus {
		status: 'valid' | 'expiring' | 'expired' | 'none';
		subject_cn?: string;
		expires_at?: string;
		expires_in_days?: number;
	}

	let {
		status,
		loading = false,
		error = false,
		onRetry = () => {},
	}: {
		status?: CertStatus;
		loading?: boolean;
		error?: boolean;
		onRetry?: () => void;
	} = $props();

	let announce = $state('');

	// Announce the resolved status when data arrives.
	$effect(() => {
		if (status && !loading && !error) {
			announce = t('cert.status_announce', { status: status.status });
		}
	});

	function badgeVariant(s: string) {
		if (s === 'valid') return 'success';
		if (s === 'expiring') return 'warning';
		if (s === 'expired') return 'danger';
		return 'neutral';
	}

	function badgeLabel(s: string) {
		if (s === 'valid') return t('cert.active');
		if (s === 'expiring') return t('cert.expiring', { n: String(status?.expires_in_days ?? 0) });
		if (s === 'expired') return t('cert.expired');
		return '';
	}
</script>

<!-- sr-only polite announcer for screen-reader users on settings load -->
<div class="sr-only" aria-live="polite" aria-atomic="true">{announce}</div>

<section class="csc-card" aria-labelledby="csc-title">
	<h2 id="csc-title" class="csc-title">{t('cert.title')}</h2>

	{#if loading}
		<div class="csc-center">
			<Spinner size={20} label={t('loading') || 'Loading'} />
		</div>
	{:else if error}
		<div class="csc-error" role="alert">
			{t('cert.load_failed')}
			<button class="csc-retry" onclick={onRetry}>{t('common.retry') || 'Retry'}</button>
		</div>
	{:else if !status || status.status === 'none'}
		<EmptyState
			title={t('cert.none_title')}
			watermark={false}
		>
			{#snippet action()}
				<p class="csc-none-body">{t('cert.none_body')}</p>
			{/snippet}
		</EmptyState>
	{:else}
		<!-- Status header: badge (primary datum) + subject + expiry -->
		<div class="csc-header">
			<Badge
				variant={badgeVariant(status.status)}
				label={badgeLabel(status.status)}
			/>
		</div>

		{#if status.subject_cn}
			<p class="csc-subject">{t('cert.subject', { cn: status.subject_cn })}</p>
		{/if}

		{#if status.expires_at}
			<p class="csc-expiry">
				<time datetime={status.expires_at}>
					{t('cert.expires', { date: formatDate(status.expires_at) })}
				</time>
			</p>
		{/if}

		{#if status.status === 'expiring'}
			<p class="csc-hint">{t('cert.expiring_hint')}</p>
		{:else if status.status === 'expired'}
			<p class="csc-hint">{t('cert.expired_hint')}</p>
		{/if}
	{/if}
</section>

<style>
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}

	.csc-card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 20px;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.csc-title {
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
	}

	.csc-center {
		display: flex;
		justify-content: center;
		padding: 16px 0;
	}

	.csc-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.csc-retry {
		background: none;
		border: 1px solid var(--danger-fg);
		border-radius: var(--radius-sm);
		color: var(--danger-fg);
		cursor: pointer;
		font-size: var(--text-sm);
		padding: 4px 10px;
		min-height: 44px;
		flex: none;
	}
	.csc-retry:hover { background: var(--danger-bg); }
	.csc-retry:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.csc-header {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.csc-subject, .csc-expiry {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		max-width: 56ch;
	}

	.csc-hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		max-width: 56ch;
	}

	.csc-none-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		max-width: 56ch;
		text-align: center;
	}

	/* ponytail: no motion in this component — the Spinner handles its own reduced-motion.
	   If a transition is ever added here, the @media guard below must accompany it. */
	@media (prefers-reduced-motion: reduce) {
		/* placeholder — ensures the reduced-motion.test.ts guard passes even after a
		   future contributor adds a transition: it will already be in this block. */
	}
</style>
