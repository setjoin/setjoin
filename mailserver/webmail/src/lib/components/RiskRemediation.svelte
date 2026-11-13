<!--
  RiskRemediation.svelte — CA-3b Design Task B.
  Risk-remediation interstitial: reassure-don't-alarm "verify it's you" → MFA re-auth handoff.
  States: idle / loading / success / error / locked.
  Trust copy contract: never say "high risk" or "suspicious" — the test asserts this.
  Motion: disclosure expand/collapse (max-height/opacity), success scale-in + fade.
  ALL transitions guarded by @media (prefers-reduced-motion: reduce).
-->
<svelte:options runes={true} />

<script lang="ts">
	import { untrack, onMount } from 'svelte';
	import { Button, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { focusTrap } from '$lib/actions/focusTrap';

	type State = 'idle' | 'loading' | 'success' | 'error' | 'locked';

	let {
		signals = [],
		correlationId = '',
		onVerified = () => {},
		initialState = 'idle' as State,
	}: {
		signals?: string[];
		correlationId?: string;
		onVerified?: () => void;
		// Test-only seam to mount a given remState directly.
		initialState?: State;
	} = $props();

	// untrack: capture the initial prop value without creating a reactive dependency.
	// initialState is a test-only seam; after mount, remState is managed internally.
	let remState: State = $state(untrack(() => initialState ?? 'idle'));
	let disclosureOpen = $state(false);
	let announce = $state(''); // aria-live="polite"
	let copied = $state(false);
	let disclosureId = 'risk-rem-disclosure';
	let cardEl: HTMLElement | undefined = $state(undefined);

	// Derive an accessible label from the current state for aria-label on the dialog.
	const dialogLabel = $derived(
		remState === 'locked' ? t('risk_rem.locked_title') :
		remState === 'success' ? t('risk_rem.success') :
		t('risk_rem.title')
	);

	// Maps signal slugs to reassuring i18n reasons (never the raw slug).
	function riskReason(sigs: string[]): string {
		if (sigs.includes('impossible_travel')) return t('risk_rem.reason_location');
		if (sigs.includes('failed_auth_velocity')) return t('risk_rem.reason_attempts');
		return t('risk_rem.reason_generic');
	}

	const reason = $derived(riskReason(signals));

	async function verify() {
		remState = 'loading';
		try {
			// Route to the existing MFA re-auth flow.
			// In production this posts to the auth re-verify endpoint; on success
			// the server returns 200 and we call onVerified(). On failure (network
			// or max-attempts) we surface error/locked.
			const res = await fetch('/auth/mfa/reauth', { method: 'POST', credentials: 'include' });
			if (res.ok) {
				remState = 'success';
				announce = t('risk_rem.success');
				setTimeout(() => { onVerified(); }, 1800);
			} else if (res.status === 423) {
				// 423 Locked — too many attempts or no MFA enrolled.
				remState = 'locked';
			} else {
				remState = 'error';
			}
		} catch {
			remState = 'error';
		}
	}

	function retry() { remState = 'idle'; }

	async function copyId() {
		if (!correlationId) return;
		try {
			await navigator.clipboard.writeText(correlationId);
			copied = true;
			announce = t('risk_rem.copied');
			setTimeout(() => { copied = false; }, 1500);
		} catch { /* clipboard unavailable */ }
	}
</script>

<div class="rr-page" role="dialog" aria-modal="true" aria-label={dialogLabel}>
	<!-- aria-live for success + copy announcements -->
	<div class="sr-only" aria-live="polite" aria-atomic="true">{announce}</div>

	<div class="rr-card" bind:this={cardEl} tabindex="-1" use:focusTrap>
		<!-- Shield-check glyph — accent, decorative -->
		<div class="rr-glyph" aria-hidden="true">
			<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
				<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
				<polyline points="9 12 11 14 15 10"/>
			</svg>
		</div>

		{#if remState === 'locked'}
			<!-- Locked-out: honest recovery path, never a dead 403 -->
			<h1 class="rr-title" tabindex="-1">{t('risk_rem.locked_title')}</h1>
			<p class="rr-body">{t('risk_rem.locked_body')}</p>
			{#if correlationId}
				<div class="rr-chip-row">
					<span class="rr-chip">{correlationId}</span>
					<button
						class="rr-copy-btn"
						aria-label={t('risk_rem.copy_id')}
						onclick={copyId}
					>
						{#if copied}
							<!-- check icon -->
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
						{:else}
							<!-- copy icon -->
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
						{/if}
					</button>
				</div>
			{/if}
		{:else if remState === 'success'}
			<h1 class="rr-title rr-success-title" tabindex="-1">{t('risk_rem.success')}</h1>
			<div class="rr-success-check" aria-hidden="true">
				<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--success-fg)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
			</div>
		{:else}
			<!-- idle / loading / error -->
			<h1 class="rr-title" tabindex="-1">{t('risk_rem.title')}</h1>
			<p class="rr-body">{reason}</p>

			{#if remState === 'error'}
				<div class="rr-error" role="alert">{t('risk_rem.error')}</div>
			{/if}

			<!-- Verify CTA -->
			<div class="rr-actions">
				{#if remState === 'error'}
					<Button variant="primary" size="lg" class="rr-btn" onclick={retry}>
						{t('risk_rem.try_again')}
					</Button>
				{:else}
					<Button
						variant="primary"
						size="lg"
						class="rr-btn"
						disabled={remState === 'loading'}
						onclick={verify}
					>
						{#if remState === 'loading'}
							<Spinner size={16} />&nbsp;{t('risk_rem.loading')}
						{:else}
							{t('risk_rem.verify')}
						{/if}
					</Button>
				{/if}
			</div>

			<!-- "What clears this?" disclosure — novel widget: aria-expanded toggle -->
			<div class="rr-disclosure">
				<button
					class="rr-disclosure-toggle"
					aria-expanded={disclosureOpen ? 'true' : 'false'}
					aria-controls={disclosureId}
					onclick={() => { disclosureOpen = !disclosureOpen; }}
				>
					{t('risk_rem.what_clears')}
					<span class="rr-disclosure-caret" aria-hidden="true">{disclosureOpen ? '▴' : '▾'}</span>
				</button>
				<div
					id={disclosureId}
					class="rr-disclosure-body"
					class:rr-disclosure-open={disclosureOpen}
					role="region"
					aria-label={t('risk_rem.what_clears')}
				>
					<ul class="rr-disclosure-list">
						<li>{t('risk_rem.clears_verify')}</li>
						<li>{t('risk_rem.clears_password')}</li>
					</ul>
				</div>
			</div>
		{/if}
	</div>
</div>

<style>
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}

	.rr-page {
		/* ponytail: fixed overlay — must sit above the .sj-shell (height:100vh) which the in-flow
		   <main> was rendering below. z-index 1001 clears the Dialog primitive's 1000. */
		position: fixed;
		inset: 0;
		z-index: 1001;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 24px;
		background: var(--surface-page);
	}

	.rr-card {
		width: min(30rem, 100%);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-sm);
		padding: 32px 28px;
		display: flex;
		flex-direction: column;
		gap: 16px;
		outline: none; /* tabindex="-1" for focusTrap; no visible focus ring on the card itself */
	}

	.rr-glyph {
		display: flex;
		justify-content: center;
		margin-bottom: 4px;
	}

	.rr-title {
		font-size: var(--text-xl);
		font-weight: 600;
		letter-spacing: -0.01em;
		margin: 0;
		color: var(--text-primary);
		text-align: center;
		outline: none;
	}

	.rr-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
		text-align: center;
	}

	.rr-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		text-align: center;
		animation: rr-slide-in var(--duration-fast, 100ms) var(--ease-out, ease-out) both;
	}

	@keyframes rr-slide-in {
		from { opacity: 0; transform: translateY(-4px); }
		to   { opacity: 1; transform: translateY(0); }
	}

	.rr-actions {
		display: flex;
		flex-direction: column;
	}

	:global(.rr-btn) { width: 100%; }

	/* "What clears this?" disclosure */
	.rr-disclosure {
		border-top: 1px solid var(--border-subtle);
		padding-top: 12px;
	}

	.rr-disclosure-toggle {
		display: flex;
		align-items: center;
		justify-content: space-between;
		width: 100%;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: none;
		border: none;
		cursor: pointer;
		padding: 4px 0;
		min-height: 44px;
		gap: 8px;
		border-radius: var(--radius-sm);
	}

	.rr-disclosure-toggle:hover { color: var(--text-primary); }
	.rr-disclosure-toggle:focus-visible { outline: none; box-shadow: var(--focus-ring); border-radius: var(--radius-sm); }

	.rr-disclosure-caret { font-size: var(--text-xs); flex: none; }

	.rr-disclosure-body {
		overflow: hidden;
		max-height: 0;
		opacity: 0;
		transition: max-height var(--duration-base, 200ms) var(--ease-out, ease-out),
		            opacity   var(--duration-base, 200ms) var(--ease-out, ease-out);
	}

	.rr-disclosure-open {
		max-height: 200px;
		opacity: 1;
	}

	.rr-disclosure-list {
		margin: 8px 0 0;
		padding-inline-start: 20px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.6;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	/* Locked-out: correlation-ID chip */
	.rr-chip-row {
		display: flex;
		align-items: center;
		gap: 6px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
	}

	.rr-chip {
		font-family: var(--font-mono, monospace);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		flex: 1;
		word-break: break-all;
	}

	.rr-copy-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-height: 44px;
		min-width: 44px;
		border: none;
		background: none;
		cursor: pointer;
		color: var(--text-tertiary);
		border-radius: var(--radius-sm);
		padding: 4px;
	}
	.rr-copy-btn:hover { color: var(--text-secondary); background: var(--surface-hover); }
	.rr-copy-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* Success remState */
	.rr-success-title { color: var(--success-fg); }
	.rr-success-check {
		display: flex;
		justify-content: center;
		animation: rr-check-in var(--duration-base, 200ms) var(--ease-out, ease-out) both;
	}

	@keyframes rr-check-in {
		from { opacity: 0; transform: scale(0.9); }
		to   { opacity: 1; transform: scale(1); }
	}

	/* Mobile: full-bleed, generous padding */
	@media (max-width: 640px) {
		.rr-card { padding: 24px 16px; }
	}

	@media (prefers-reduced-motion: reduce) {
		.rr-disclosure-body {
			transition: none;
		}
		.rr-error {
			animation: none;
		}
		.rr-success-check {
			animation: none;
		}
	}
</style>
