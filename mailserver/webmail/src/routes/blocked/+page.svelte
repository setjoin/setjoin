<!--
	/blocked — end-user blocked screen (CA-2 device lockout + CA-3b policy block).

	CA-2 device lockout (existing): navigated to with ?ref=<correlation-id> when BZ095
	blocks access; explains enrollment + how to get approved. No `block` prop.

	CA-3b policy block (Design Task A): receives a `block` prop with the runtime 403
	payload: { decision, mode, reason, correlation_id, remediation }. Three modes:
	  - hard: "Access blocked by policy" + Contact IT + reason callout.
	  - step_up: "Additional verification needed" + Verify now (routes to MFA/risk flow).
	  - report_only: dismissible info banner (user can continue) — pilot mode.
	Unknown mode falls back to hard (safest).

	Motion: entrance animation (fade + slide) already guarded by reduced-motion block below.
-->
<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { Button, Spinner } from '$lib/components/ui';
	import { isNative } from '$lib/native';
	import { attachDeviceProofHeaders } from '$lib/native/deviceProof';
	import { blockedCopy } from '$lib/blocked';
	import { jmapSession } from '$lib/stores/session';
	import Icon from '$lib/components/Icon.svelte';

	// CA-3b: optional policy-block payload. When present, the CA-3b view is shown.
	// In production this comes from a store set by the runtime middleware 403 handler;
	// in tests it is passed as a prop directly (per Design Task A test spec).
	interface PolicyBlock {
		decision: string;
		mode: string;
		reason: string;
		correlation_id: string;
		remediation: string;
		policy_name?: string;
	}

	let { block = null as PolicyBlock | null } = $props();

	// Read correlation ref from ?ref= query param (set by jmapCall from X-CA-Correlation-Id).
	const ref = $derived(page.url.searchParams.get('ref') ?? undefined);
	const native = $derived(isNative());
	const copy = $derived(blockedCopy(native));

	// Admin contact email: from org system_config (help_email) via JMAP session.
	// Falls back to admin@{org-domain} derived from the session username — always
	// uses the org's mail domain, never window.location.hostname.
	const contactEmail = $derived.by(() => {
		const s = $jmapSession;
		if (s?.helpEmail) return s.helpEmail;
		const u = s?.username ?? '';
		const at = u.indexOf('@');
		return at >= 0 ? 'admin@' + u.slice(at + 1) : '';
	});

	// CA-3b: policy block state machine.
	// Normalise mode: unknown mode → 'hard' (safest fallback).
	const KNOWN_MODES = ['hard', 'step_up', 'report_only'] as const;
	type PolicyMode = typeof KNOWN_MODES[number];
	const policyMode = $derived<PolicyMode>(
		block && KNOWN_MODES.includes(block.mode as PolicyMode) ? (block.mode as PolicyMode) : 'hard'
	);

	let policyLiveMsg = $state('');
	let idCopied = $state(false);

	async function copyCorrelationId() {
		if (!block?.correlation_id) return;
		try {
			await navigator.clipboard.writeText(block.correlation_id);
			idCopied = true;
			policyLiveMsg = t('blocked.copied');
			setTimeout(() => { idCopied = false; }, 1500);
		} catch { /* clipboard unavailable */ }
	}

	// Device lockdown state (CA-2, unrelated to block prop)
	type BlockPhase = 'idle' | 'requested' | 'error';
	let phase = $state<BlockPhase>('idle');
	// ponytail: separate isLoading from phase so TypeScript doesn't flag impossible
	// comparisons inside phase-narrowed blocks, and so 'requested' UI stays visible
	// during handleCheckAgain (we only need spinner on the check button, not a phase swap).
	let isLoading = $state(false);
	let errorMsg = $state('');
	// aria-live region text — updated on phase change so screen readers announce.
	let liveMsg = $state('');

	let h1El: HTMLHeadingElement | undefined = $state(undefined);

	onMount(() => {
		// Move focus to h1 so screen readers announce the lockout state (not a silent swap).
		h1El?.focus();
	});

	// ponytail: POST /device/self-enroll — user-facing enrollment. Endpoint to be
	// wired in a follow-up task; the error state handles a missing endpoint cleanly.
	async function handleRequestApproval() {
		if (isLoading) return;
		isLoading = true;
		errorMsg = '';
		liveMsg = '';
		try {
			const headers = new Headers({ 'Content-Type': 'application/json' });
			await attachDeviceProofHeaders(headers);
			const res = await fetch('/api/device/self-enroll', {
				method: 'POST',
				headers,
				credentials: 'include',
			});
			if (res.ok) {
				phase = 'requested';
				liveMsg = t('device_lockdown.blocked.requested');
			} else {
				errorMsg = t('device_lockdown.blocked.request_error');
				phase = 'error';
				liveMsg = errorMsg;
			}
		} catch {
			errorMsg = t('device_lockdown.blocked.request_error');
			phase = 'error';
			liveMsg = errorMsg;
		} finally {
			isLoading = false;
		}
	}

	async function handleCheckAgain() {
		if (isLoading) return;
		isLoading = true;
		liveMsg = '';
		try {
			const res = await fetch('/.well-known/jmap', { credentials: 'include' });
			if (res.ok) {
				// Device approved — return to inbox.
				goto('/inbox', { replaceState: true });
			} else {
				// Still blocked — stay on requested state.
				liveMsg = t('device_lockdown.blocked.requested');
			}
		} catch {
			// Network error — stay in requested state
		} finally {
			isLoading = false;
		}
	}

	async function copyRef() {
		if (!ref) return;
		try {
			await navigator.clipboard.writeText(ref);
		} catch { /* clipboard not available in this context */ }
	}
</script>

{#if block}
	<!-- ── CA-3b policy-block view (Design Task A) ── -->
	<main class="bl-page">
		<!-- aria-live for copy + state announcements -->
		<div class="sr-only" aria-live="polite" aria-atomic="true">{policyLiveMsg}</div>

		<div class="bl-col">
			<img class="bl-wordmark" src="/brand/logo-wordmark.svg" width="120" height="28" alt="setjoin" />

			{#if policyMode === 'report_only'}
				<!-- Report-only: info banner, NOT a wall — user can continue -->
				<div class="bl-report-banner" role="status" aria-live="polite">
					<p class="bl-report-text">{t('blocked.report_only', { reason: block.reason })}</p>
					<Button variant="primary" size="lg" onclick={() => history.back()}>
						{t('blocked.continue')}
					</Button>
				</div>
			{:else}
				<div class="bl-card">
					<!-- Shield/lock glyph — --text-tertiary (not red; block ≠ user fault) -->
					<div class="bl-icon" aria-hidden="true">
						<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
							<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
						</svg>
					</div>

					<h1 class="bl-title" tabindex="-1" bind:this={h1El}>
						{policyMode === 'step_up' ? t('blocked.title_stepup') : t('blocked.title_hard')}
					</h1>

					{#if policyMode === 'hard'}
						<p class="bl-body">{t('blocked.signin_ok')}</p>
					{/if}

					<!-- Reason callout — never JSON.stringify(block) -->
					{#if block.reason}
						<div class="bl-reason">{block.reason}</div>
					{/if}

					<!-- CTA -->
					<div class="bl-actions">
						{#if policyMode === 'step_up'}
							<Button variant="primary" size="lg" class="bl-btn-full" onclick={() => goto('/inbox')}>
								{t('blocked.verify')}
							</Button>
						{:else}
							<a
								class="bl-contact-link"
								href={contactEmail ? 'mailto:' + contactEmail : undefined}
							>
								{t('blocked.contact_it')}
							</a>
						{/if}
					</div>

					<!-- Copyable correlation-ID chip (only when id is non-empty) -->
					{#if block.correlation_id}
						<div class="bl-id-row">
							<span class="bl-id-chip">{block.correlation_id}</span>
							<button
								class="bl-copy-btn"
								aria-label={t('blocked.copy_id')}
								onclick={copyCorrelationId}
							>
								{#if idCopied}
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
								{:else}
									<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
								{/if}
							</button>
						</div>
						<p class="bl-quote-hint">{t('blocked.quote_to_it')}</p>
					{/if}

					<!-- Tertiary recovery: switch user -->
					<a class="bl-switch-link" href="/login">{t('blocked.switch_user')}</a>
				</div>
			{/if}
		</div>
	</main>
{:else}
	<!-- ── CA-2 device lockdown view (existing) ── -->
<div class="bl-page" data-testid="blocked-page">
	<div class="bl-col">
		<!-- Brand mark (login-screen visual family) -->
		<img
			class="bl-wordmark"
			src="/brand/logo-wordmark.svg"
			width="120"
			height="28"
			alt="setjoin"
		/>

		<div class="bl-card">
			<!-- ShieldAlert in --warning-fg: recoverable, not an alarm -->
			<div class="bl-icon" aria-hidden="true">
				<Icon name="ShieldAlert" size={40} strokeWidth={1.5} color="var(--warning-fg)" />
			</div>

			<main>
				<h1
					bind:this={h1El}
					tabindex="-1"
					class="bl-title"
					data-testid="blocked-title"
				>
					{t(copy.titleKey)}
				</h1>

				<p class="bl-body" data-testid="blocked-body">{t(copy.bodyKey)}</p>

				<!-- Requested sub-state: success body addition -->
				{#if phase === 'requested' && native}
					<p class="bl-body bl-ack" data-testid="blocked-ack">
						{t('device_lockdown.blocked.requested_ack')}
					</p>
				{/if}
			</main>

			<!-- aria-live region: announces requested / error state changes to screen readers -->
			<div aria-live="polite" aria-atomic="true" class="bl-live-region">
				{liveMsg}
			</div>

			<!-- Recovery actions -->
			<div class="bl-actions" data-testid="blocked-actions">
				{#each copy.actions as action (action.id)}
					{#if action.id === 'request_approval'}
						{#if phase === 'requested'}
							<!-- Waiting state: show the requested badge + Check again -->
							<div class="bl-requested-badge" data-testid="blocked-requested-badge">
								<Icon name="Clock" size={16} strokeWidth={1.75} color="var(--text-secondary)" aria-hidden="true" />
								<span>{t('device_lockdown.blocked.requested')}</span>
							</div>
							<Button
								variant="secondary"
								size="lg"
								class="bl-btn-full"
								disabled={isLoading}
								onclick={handleCheckAgain}
								data-testid="blocked-check-again"
							>
								{#if isLoading}
									<Spinner size={16} />&nbsp;{t('device_lockdown.blocked.requesting')}
								{:else}
									{t('device_lockdown.blocked.check_again')}
								{/if}
							</Button>
						{:else}
							<!-- First-time / error: primary request-approval CTA -->
							<Button
								variant={action.primary ? 'primary' : 'secondary'}
								size="lg"
								class="bl-btn-full"
								disabled={isLoading}
								onclick={handleRequestApproval}
								data-testid="blocked-request-btn"
							>
								{#if isLoading}
									<Spinner size={16} />&nbsp;{t('device_lockdown.blocked.requesting')}
								{:else}
									{t(action.labelKey)}
								{/if}
							</Button>
						{/if}
					{:else if action.id === 'install_app'}
						<Button
							variant={action.primary ? 'primary' : 'secondary'}
							size="lg"
							class="bl-btn-full"
							onclick={() => { window.open('/downloads', '_blank'); }}
							data-testid="blocked-install-btn"
						>
							{t(action.labelKey)}
						</Button>
					{:else if action.id === 'contact_admin'}
						<a
							class="bl-contact-link"
							href={contactEmail ? 'mailto:' + contactEmail : undefined}
							data-testid="blocked-contact-link"
						>
							{t(action.labelKey)}
						</a>
					{/if}
				{/each}

				{#if phase === 'error'}
					<div class="bl-error" role="alert" data-testid="blocked-error">
						{errorMsg}
					</div>
				{/if}
			</div>

			<!-- Tertiary: de-emphasised copyable reference id (admin aid, not shouted at user) -->
			{#if ref}
				<div class="bl-ref-row" data-testid="blocked-ref-row">
					<span class="bl-ref-text">{t('device_lockdown.blocked.reference', { ref })}</span>
					<button
						class="bl-copy-btn"
						aria-label={t('device_lockdown.blocked.copy_ref_aria', { ref })}
						onclick={copyRef}
						data-testid="blocked-copy-ref"
					>
						<Icon name="Copy" size={14} strokeWidth={1.75} aria-hidden="true" />
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
{/if}

<style>
	/* ── Page ── */
	.bl-page {
		min-height: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 24px;
		background: var(--surface-page);
	}

	.bl-col {
		width: min(400px, 100%);
		display: flex;
		flex-direction: column;
		gap: 20px;
		/* Entrance animation: fade + 8px slide-up (login-card family) */
		animation: bl-enter var(--duration-base, 200ms) var(--ease-out, ease-out) both;
	}

	@keyframes bl-enter {
		from {
			opacity: 0;
			transform: translateY(8px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.bl-col {
			animation: none;
		}
	}

	/* ── Wordmark ── */
	.bl-wordmark {
		display: block;
		margin: 0 auto;
	}

	:global([data-theme='dark']) .bl-wordmark {
		content: url('/brand/logo-wordmark-dark.svg');
	}

	/* ── Card ── */
	.bl-card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-sm);
		padding: 28px 24px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	/* ── Icon ── */
	.bl-icon {
		display: flex;
		justify-content: center;
		margin-bottom: 4px;
	}

	/* ── Typography ── */
	.bl-title {
		font-size: var(--text-xl);
		font-weight: 600;
		letter-spacing: -0.01em;
		margin: 0;
		color: var(--text-primary);
		text-align: center;
		/* allow focus for programmatic focus-on-mount; visually invisible */
		outline: none;
	}

	.bl-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
		text-align: center;
	}

	.bl-ack {
		color: var(--text-secondary);
	}

	/* ── aria-live ── */
	.bl-live-region {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}

	/* ── Requested badge ── */
	.bl-requested-badge {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding: 8px 0;
	}

	/* ── Actions ── */
	.bl-actions {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	/* Full-width buttons for touch / mobile */
	:global(.bl-btn-full) {
		width: 100%;
	}

	/* ── Error ── */
	.bl-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg, color-mix(in srgb, var(--danger-fg) 10%, transparent));
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		text-align: center;
	}

	/* ── Contact link ── */
	.bl-contact-link {
		text-align: center;
		font-size: var(--text-sm);
		color: var(--text-accent);
		text-decoration: none;
		padding: 4px 0;
		min-height: 44px;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.bl-contact-link:hover {
		text-decoration: underline;
	}

	/* ── Reference row ── */
	.bl-ref-row {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		margin-top: 8px;
	}

	.bl-ref-text {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-family: var(--font-mono, monospace);
	}

	.bl-copy-btn {
		display: inline-flex;
		align-items: center;
		border: none;
		background: none;
		padding: 4px;
		cursor: pointer;
		color: var(--text-tertiary);
		border-radius: var(--radius-sm);
		min-height: 44px;
		min-width: 44px;
		justify-content: center;
	}

	.bl-copy-btn:hover {
		color: var(--text-secondary);
		background: var(--surface-hover);
	}

	.bl-copy-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* ── CA-3b policy block additions ── */
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}

	/* report-only: info banner, not a wall */
	.bl-report-banner {
		width: min(400px, 100%);
		background: var(--info-bg);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 20px;
		display: flex;
		flex-direction: column;
		gap: 12px;
		animation: bl-enter var(--duration-base, 200ms) var(--ease-out, ease-out) both;
	}

	.bl-report-text {
		font-size: var(--text-sm);
		color: var(--info-fg);
		margin: 0;
		line-height: 1.5;
	}

	/* reason callout — wraps, never truncates */
	.bl-reason {
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.5;
		max-width: 100%;
		overflow-wrap: break-word;
	}

	/* correlation-ID chip row */
	.bl-id-row {
		display: flex;
		align-items: center;
		gap: 6px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
	}

	.bl-id-chip {
		font-family: var(--font-mono, monospace);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		flex: 1;
		word-break: break-all;
	}

	.bl-quote-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
		text-align: center;
	}

	.bl-switch-link {
		text-align: center;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		text-decoration: none;
		padding: 4px 0;
		min-height: 44px;
		display: flex;
		align-items: center;
		justify-content: center;
	}
	.bl-switch-link:hover { text-decoration: underline; }
	.bl-switch-link:focus-visible { outline: none; box-shadow: var(--focus-ring); border-radius: var(--radius-sm); }

	@media (prefers-reduced-motion: reduce) {
		.bl-report-banner {
			animation: none;
		}
	}
</style>
