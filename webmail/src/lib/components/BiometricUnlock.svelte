<svelte:options runes={true} />
<script lang="ts">
	import { Lock, Fingerprint, ScanFace } from 'lucide-svelte';
	import Spinner from '$lib/components/ui/Spinner.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Input from '$lib/components/ui/Input.svelte';
	import Card from '$lib/components/ui/Card.svelte';
	import { focusTrap } from '$lib/actions/focusTrap';
	import { offline } from '$lib/offline/state.svelte';
	import { t } from '$lib/i18n';
	import {
		isBiometricEnrolled,
		unlockMail,
		unlockWithPassphrase,
	} from '$lib/offline/biometric';

	// ── state ────────────────────────────────────────────────────────────────

	let biometricAvailable = $state(false); // set after async check below
	let showPassphrase = $state(false);
	let passphrase = $state('');
	let passphraseWrong = $state(false);

	// ponytail: check biometric enrollment once on mount — async guard so the
	// no-biometric-device path falls immediately to passphrase form.
	$effect(() => {
		isBiometricEnrolled().then((v) => {
			biometricAvailable = v;
			// No biometric → surface the passphrase form as primary path right away.
			if (!v && offline.enrolled) showPassphrase = true;
		});
	});

	const headlineId = `bio-headline-${Math.random().toString(36).slice(2)}`;

	// Whether an idle-relock triggered the current locked state.
	const wasRelocked = $derived(offline.liveMessage === 'offline.live.relocked');

	// Primary button label — platform-adapted.
	// ponytail: detect Face ID via platform UA string; fallback to generic cta.
	// Ceiling: native shell can inject a hint on the bridge for exact hardware name.
	function unlockBtnKey(): string {
		if (!biometricAvailable) return 'offline.unlock.cta';
		if (typeof navigator !== 'undefined' && /iPhone|iPad/.test(navigator.userAgent)) {
			return 'offline.unlock.face';
		}
		return 'offline.unlock.touch';
	}

	// ── handlers ─────────────────────────────────────────────────────────────

	async function handleUnlock() {
		offline.setLockState('unlocking');
		const result = await unlockMail();
		if (result === 'ok') {
			// state already set to unlocked inside biometric.ts
		} else if (result === 'failed') {
			offline.setLockState('failed');
		} else {
			// cancelled — OS sheet dismissed
			offline.setLockState('cancelled');
		}
	}

	async function handlePassphraseSubmit() {
		passphraseWrong = false;
		const result = await unlockWithPassphrase(passphrase);
		if (result === 'wrong') {
			passphraseWrong = true;
		}
		// 'ok' → biometric.ts already set lockState to 'unlocked' + announced
	}

	function handleEnrollEnable() {
		offline.enrolled = true;
		offline.setSyncPhase('provisioning');
	}

	function handleEnrollNotNow() {
		// Dismiss without enabling — offline mail stays disabled.
		offline.featureEnabled = false;
	}

	// Esc → move focus to passphrase fallback (per spec: can't escape a lock).
	function handleEscape() {
		showPassphrase = true;
		// The focusTrap will pick up the newly-visible input on the next Tab cycle.
	}
</script>

{#if offline.needsUnlock || !offline.enrolled}
	<!-- Enrollment card (first-time — no enrolled state yet) -->
	{#if !offline.enrolled}
		<div class="bio-backdrop" data-testid="bio-enroll-card">
			<div class="bio-center">
				<Card title={t('offline.enroll.title')}>
					{#snippet children()}
						<p class="bio-enroll-body">
							{t('offline.enroll.body', {
								biometric: biometricAvailable
									? (typeof navigator !== 'undefined' && /iPhone|iPad/.test(navigator.userAgent)
										? t('offline.enroll.biometric_face')
										: t('offline.enroll.biometric_touch'))
									: t('offline.enroll.biometric_device')
							})}
						</p>
						<div class="bio-enroll-actions">
							<Button
								variant="primary"
								data-testid="bio-enroll-enable"
								onclick={handleEnrollEnable}
							>
								{t('offline.enroll.enable')}
							</Button>
							<Button
								variant="ghost"
								data-testid="bio-enroll-not-now"
								onclick={handleEnrollNotNow}
							>
								{t('offline.enroll.not_now')}
							</Button>
						</div>
					{/snippet}
				</Card>
			</div>
		</div>
	<!-- Locked-inbox overlay (return unlock) -->
	{:else}
		<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
		<div
			class="bio-overlay"
			role="dialog"
			aria-modal="true"
			aria-labelledby={headlineId}
			use:focusTrap={{ onEscape: handleEscape }}
			data-testid="bio-dialog"
		>
			<!-- Assertive live region — user-blocking outcomes heard immediately by AT. -->
			<!-- The failed/cancelled inline messages are role=alert and double as this. -->
			<span
				class="sr-only"
				aria-live="assertive"
				data-testid="bio-assertive-live"
			>
				{offline.liveMessage === 'offline.live.unlock_failed' ? t('offline.live.unlock_failed') : ''}
			</span>

			<!-- Idle-relock note (calm reassurance, not an alarm). -->
			{#if wasRelocked}
				<p class="bio-relocked" data-testid="bio-relocked-note">
					{t('offline.unlock.relocked')}
				</p>
			{/if}

			<!-- Large watermark glyph (aria-hidden — button carries visible label). -->
			<span
				class="bio-glyph"
				class:bio-glyph--pulse={offline.lockState === 'locked' || offline.lockState === 'unlocking'}
				aria-hidden="true"
			>
				{#if biometricAvailable && typeof navigator !== 'undefined' && /iPhone|iPad/.test(navigator.userAgent)}
					<ScanFace size={64} />
				{:else if biometricAvailable}
					<Fingerprint size={64} />
				{:else}
					<Lock size={64} />
				{/if}
			</span>

			<h2 id={headlineId} class="bio-headline" data-testid="bio-headline">
				{t('offline.unlock.locked_inbox')}
			</h2>
			<p class="bio-hint" data-testid="bio-hint">
				{t('offline.unlock.locked_hint')}
			</p>

			<!-- State-specific feedback -->
			{#if offline.lockState === 'failed'}
				<div role="alert" class="bio-alert bio-alert--danger" data-testid="bio-failed-msg">
					{t('offline.unlock.failed')}
				</div>
			{:else if offline.lockState === 'cancelled'}
				<div class="bio-alert bio-alert--info" data-testid="bio-cancelled-msg">
					{t('offline.unlock.cancelled')}
				</div>
			{/if}

			<!-- Primary action — biometric unlock button (or Spinner when unlocking). -->
			{#if !showPassphrase}
				<div class="bio-actions">
					{#if offline.lockState === 'unlocking'}
						<!-- ponytail: bio-touch extends Button's size=lg to 44px min-height (touch target; --control-height-lg is 40px) -->
						<Button
							variant="primary"
							size="lg"
							class="bio-touch"
							disabled
							data-testid="bio-unlock-btn"
							aria-label={t('offline.unlock.unlocking')}
						>
							<span class="bio-spinner" data-testid="bio-spinner">
								<Spinner size={16} label={t('offline.unlock.unlocking')} />
							</span>
							{t('offline.unlock.unlocking')}
						</Button>
					{:else if offline.lockState === 'failed'}
						<Button
							variant="primary"
							size="lg"
							class="bio-touch"
							onclick={handleUnlock}
							data-testid="bio-retry-btn"
						>
							{t('offline.unlock.retry')}
						</Button>
					{:else}
						<Button
							variant="primary"
							size="lg"
							class="bio-touch"
							onclick={handleUnlock}
							data-testid="bio-unlock-btn"
						>
							{t(unlockBtnKey())}
						</Button>
					{/if}

					<button
						type="button"
						class="bio-link"
						onclick={() => { showPassphrase = true; passphraseWrong = false; }}
						data-testid="bio-passphrase-toggle"
					>
						{t('offline.unlock.use_passphrase')}
					</button>
				</div>
			{:else}
				<!-- Passphrase fallback form -->
				<form
					class="bio-passphrase-form"
					onsubmit={(e) => { e.preventDefault(); handlePassphraseSubmit(); }}
				>
					<!-- ponytail: no error prop here — the role=alert below is the sole renderer;
					     Input's built-in error span + the alert div would duplicate text + AT announcement. -->
					<Input
						type="password"
						label={t('offline.unlock.passphrase_label')}
						bind:value={passphrase}
						data-testid="bio-passphrase-input"
					/>
					{#if passphraseWrong}
						<div role="alert" class="bio-alert bio-alert--danger" data-testid="bio-passphrase-wrong">
							{t('offline.unlock.passphrase_wrong')}
						</div>
					{/if}
					<Button variant="primary" type="submit" data-testid="bio-passphrase-submit">
						{t('offline.unlock.passphrase_cta')}
					</Button>
					{#if biometricAvailable}
						<button
							type="button"
							class="bio-link"
							onclick={() => { showPassphrase = false; passphraseWrong = false; }}
							data-testid="bio-unlock-btn"
						>
							{t(unlockBtnKey())}
						</button>
					{/if}
				</form>
			{/if}
		</div>
	{/if}
{/if}

<style>
	.bio-backdrop {
		position: fixed;
		inset: 0;
		background: var(--overlay-scrim);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: var(--z-modal, 1000);
	}
	.bio-center {
		max-width: 400px;
		width: 100%;
		padding: var(--space-4);
	}
	.bio-enroll-body {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin-bottom: var(--space-4);
		line-height: var(--leading-relaxed);
	}
	.bio-enroll-actions {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	/* Locked-inbox overlay — fills the mail pane, not the whole viewport */
	.bio-overlay {
		position: absolute;
		inset: 0;
		background: var(--surface-app);
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-6);
		z-index: var(--z-overlay, 100);
		/* slide-up + fade on entry, inheriting Dialog's duration token */
		animation: bio-enter var(--duration-base, 200ms) var(--ease-out) both;
	}

	@keyframes bio-enter {
		from { opacity: 0; transform: translateY(8px); }
		to   { opacity: 1; transform: translateY(0); }
	}
	.bio-relocked {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		text-align: center;
		max-width: 320px;
	}
	.bio-glyph {
		color: var(--text-tertiary);
		display: flex;
		align-items: center;
		justify-content: center;
	}
	/* Pulse on locked/unlocking — "ready / working" signal */
	.bio-glyph--pulse {
		animation: bio-pulse var(--duration-slow, 260ms) ease-in-out infinite alternate;
	}

	@keyframes bio-pulse {
		from { opacity: 1; }
		to   { opacity: 0.35; }
	}
	.bio-headline {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		text-align: center;
		margin: 0;
	}
	.bio-hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		text-align: center;
		max-width: 320px;
		margin: 0;
	}
	.bio-alert {
		font-size: var(--text-sm);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		max-width: 320px;
		text-align: center;
	}
	.bio-alert--danger { color: var(--danger-fg); background: var(--danger-bg); }
	.bio-alert--info   { color: var(--text-secondary); background: var(--surface-sunken); }
	.bio-actions {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		max-width: 280px;
	}
	/* Touch-target extension — M1 Button size=lg is 40px; WCAG 2.5.5 requires 44px. */
	/* ponytail: two properties only; everything else comes from Button variant=primary size=lg */
	:global(.bio-touch) {
		width: 100%;
		min-height: 44px;
	}
	.bio-link {
		background: transparent;
		border: none;
		color: var(--accent-fg-on-subtle, var(--accent));
		font-size: var(--text-sm);
		font-family: var(--font-sans);
		cursor: pointer;
		padding: var(--space-1);
		text-decoration: underline;
		min-height: 44px;
	}
	.bio-link:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.bio-passphrase-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		width: 100%;
		max-width: 280px;
	}
	.bio-spinner {
		display: inline-flex;
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	/* ── Reduced-motion ─────────────────────────────────────────────────────── */
	/* ponytail: both the overlay enter animation and the glyph pulse are removed
	   under reduced-motion; the shake on failed→locked is omitted entirely
	   (it's a loop-free single translate with motion, so no reduced fallback needed
	   as there's no repeat). Ceiling: add shake if UX specifies it. */
	@media (prefers-reduced-motion: reduce) {
		.bio-overlay    { animation: none; }
		.bio-glyph--pulse { animation: none; }
	}
	/* Mobile: full-screen overlay */
	@media (max-width: 640px) {
		.bio-overlay { padding: var(--space-4); }
	}
</style>
