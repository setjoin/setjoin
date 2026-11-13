<!--
	/security-event — honest-recovery screen for server-pushed security events.
	Currently: remote-wipe (?reason=remote-wipe). Brief §DESIGN: the user MUST
	NOT land on a plain login form after a wipe — they need context and a clear
	next step. Visual family: login-card (--surface-card, --border-default, brand mark).
	Tone: "your data was protected" (calm, recoverable) — not "ACCESS DENIED".
-->
<svelte:options runes={true} />
<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { Button } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	const reason = $derived(page.url.searchParams.get('reason') ?? 'unknown');
</script>

<div class="se-page" data-testid="security-event-page">
	<div class="se-col">
		<img
			class="se-wordmark"
			src="/brand/logo-wordmark.svg"
			width="120"
			height="28"
			alt="setjoin"
		/>

		<div class="se-card">
			<!-- ShieldCheck: security action succeeded, calm rather than alarming -->
			<div class="se-icon" aria-hidden="true">
				<Icon name="ShieldCheck" size={40} strokeWidth={1.5} color="var(--text-accent)" />
			</div>

			<main>
				<h1
					class="se-title"
					data-testid="security-event-title"
				>
					{#if reason === 'remote-wipe'}
						{t('security_event.remote_wipe.title')}
					{:else}
						{t('security_event.generic.title')}
					{/if}
				</h1>

				<!-- role=status + aria-live=polite: polite live region so a SR user who
				     arrives mid-route hears the reassurance without an assertive interrupt.
				     ponytail: 'polite' is deliberate — calm/handled tone, not alarm. -->
			<p class="se-body" data-testid="security-event-body" role="status" aria-live="polite">
					{#if reason === 'remote-wipe'}
						{t('security_event.remote_wipe.body')}
					{:else}
						{t('security_event.generic.body')}
					{/if}
				</p>
			</main>

			<div class="se-actions">
				<Button
					variant="primary"
					size="lg"
					class="se-btn-full"
					autofocus
					onclick={() => goto('/', { replaceState: true })}
					data-testid="security-event-sign-in"
				>
					{t('security_event.sign_in')}
				</Button>
			</div>
		</div>
	</div>
</div>

<style>
	.se-page {
		min-height: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 24px;
		background: var(--surface-page);
	}

	.se-col {
		width: min(400px, 100%);
		display: flex;
		flex-direction: column;
		gap: 20px;
		animation: se-enter var(--duration-base, 200ms) var(--ease-out, ease-out) both;
	}

	@keyframes se-enter {
		from { opacity: 0; transform: translateY(8px); }
		to   { opacity: 1; transform: translateY(0); }
	}

	@media (prefers-reduced-motion: reduce) {
		.se-col { animation: none; }
	}

	.se-wordmark {
		display: block;
		margin: 0 auto;
	}

	:global([data-theme='dark']) .se-wordmark {
		content: url('/brand/logo-wordmark-dark.svg');
	}

	.se-card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-sm);
		padding: 28px 24px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.se-icon {
		display: flex;
		justify-content: center;
		margin-bottom: 4px;
	}

	.se-title {
		font-size: var(--text-xl);
		font-weight: 600;
		letter-spacing: -0.01em;
		margin: 0;
		color: var(--text-primary);
		text-align: center;
	}

	.se-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
		text-align: center;
	}

	.se-actions {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	:global(.se-btn-full) {
		width: 100%;
	}
</style>
