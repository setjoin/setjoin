<!--
  MfaReauthHandoff.svelte — possession scheme v7 §3.1 method-aware reauth
  handoff, shared by /settings/security and /settings.

  When a gated arm answers 403 reauth_required, this form mints the proof that
  retries it. The offered methods are the account's ENROLLED proof methods:
  C1 accounts prove with WebAuthn-UV or a current TOTP code (spec §3
  possession endpoints); the password challenge appears only for the C2/C3
  password step-up cohorts. The server remains the cohort authority — a
  mis-offered proof is refused by the 403 contract and surfaced inline.

  Auth-generation fencing (spec §3.1): an account identity change retires
  every in-flight proof — a ceremony resolving after a switch/account-drop
  never delivers its token.
-->
<svelte:options runes={true} />

<script lang="ts">
	import { untrack } from 'svelte';
	import { t } from '$lib/i18n';
	import { user, authIdentity, beginMFAReauth, possessionTOTPProof, provePossessionWebAuthn, type MFAReauthOperation } from '$lib/stores/auth';
	import { Button, Input } from '$lib/components/ui';

	/** The enrolled proof methods offered to the account, preference order. */
	export type ReauthProofMethod = 'webauthn_uv' | 'totp' | 'password';

	let {
		operation,
		methods,
		onproof,
		oncancel = () => {},
	}: {
		/** The §1.3 operation the minted grant will authorize. */
		operation: MFAReauthOperation;
		/** Enrolled methods (non-empty); possession methods first, password last. */
		methods: ReauthProofMethod[];
		onproof: (proof: { method: ReauthProofMethod; token: string }) => void;
		oncancel?: () => void;
	} = $props();

	// untrack: the choice is captured once when the handoff mounts; the pages
	// close (and re-open) the handoff on any identity change, so a reactive
	// re-seed is never wanted here.
	let selected = $state<ReauthProofMethod>(untrack(() => methods[0]));

	// If the offered methods change while the handoff is open (e.g. the
	// account's credential list landing mid-handoff), a now-unoffered
	// selection falls back to the preferred method — never a stale arm.
	$effect(() => {
		if (!methods.includes(selected)) selected = methods[0];
	});
	let password = $state('');
	let code = $state('');
	let error = $state('');
	let proving = $state(false);

	// ── Auth-generation fencing ──
	// Any account identity change (checkAuth observing a different user, or
	// logout) retires in-flight proofs: the captured generation no longer
	// matches, so a late ceremony result is discarded before it can reach the
	// page's held-proof state (spec §3.1 — UX fence; the server's tuple
	// binding is the enforcement).
	const identity = $derived($user ? authIdentity($user) : null);
	let generation = 0;
	$effect(() => {
		void identity;
		generation += 1;
		password = '';
		code = '';
		error = '';
		proving = false;
		return () => {
			generation += 1;
		};
	});

	function methodLabel(method: ReauthProofMethod): string {
		if (method === 'webauthn_uv') return t('security.reauth.method_webauthn');
		if (method === 'totp') return t('security.reauth.method_totp');
		return t('security.reauth.method_password');
	}

	function pick(method: ReauthProofMethod) {
		if (proving) return;
		selected = method;
		error = '';
	}

	function fail(message: string) {
		error = message;
		proving = false;
	}

	async function submit() {
		if (proving) return;
		const gen = generation;
		proving = true;
		error = '';
		try {
			if (selected === 'webauthn_uv') {
				const proof = await provePossessionWebAuthn(operation);
				if (gen !== generation) return; // identity changed mid-ceremony — discard
				if (proof.scope !== 'session') {
					fail(t('security.reauth.webauthn_error'));
					return;
				}
				onproof({ method: 'webauthn_uv', token: proof.reauthToken });
			} else if (selected === 'totp') {
				const proof = await possessionTOTPProof(operation, code.trim());
				if (gen !== generation) return;
				onproof({ method: 'totp', token: proof.reauthToken });
			} else {
				const proof = await beginMFAReauth(password, operation);
				if (gen !== generation) return;
				onproof({ method: 'password', token: proof.reauthToken });
			}
		} catch (e) {
			if (gen !== generation) return;
			fail(e instanceof Error && e.message ? e.message : t('security.reauth.error'));
			return;
		}
		proving = false;
	}
</script>

<div class="sj-reauth-form" data-testid="mfa-reauth-form">
	<p class="sj-reauth-desc">
		{methods.length === 1 && methods[0] === 'password'
			? t('security.reauth.body')
			: t('security.reauth.method_body')}
	</p>

	{#if methods.length > 1}
		<div class="sj-reauth-methods" role="group" aria-label={t('security.reauth.method_prompt')}>
			{#each methods as method (method)}
				<Button
					variant={selected === method ? 'primary' : 'secondary'}
					size="sm"
					data-testid={`mfa-reauth-method-${method}`}
					aria-pressed={selected === method}
					onclick={() => pick(method)}
					disabled={proving}
				>
					{methodLabel(method)}
				</Button>
			{/each}
		</div>
	{/if}

	{#if selected === 'webauthn_uv'}
		<Button
			variant="primary"
			size="sm"
			data-testid="mfa-reauth-passkey"
			onclick={submit}
			disabled={proving}
		>
			{proving ? t('security.reauth.passkey_waiting') : t('security.reauth.method_webauthn')}
		</Button>
	{:else if selected === 'totp'}
		<Input
			size="md"
			label={t('security.reauth.totp_label')}
			bind:value={code}
			mono
			inputmode="numeric"
			maxlength={6}
			data-testid="mfa-reauth-code"
		/>
		<div class="sj-reauth-row">
			<Button variant="secondary" size="sm" onclick={oncancel} disabled={proving}>
				{t('common.cancel')}
			</Button>
			<Button
				variant="primary"
				size="sm"
				data-testid="mfa-reauth-confirm"
				onclick={submit}
				disabled={proving || code.trim().length === 0}
			>
				{proving ? t('security.reauth.verifying') : t('security.reauth.confirm')}
			</Button>
		</div>
	{:else}
		<Input
			size="md"
			label={t('security.reauth.password_label')}
			type="password"
			bind:value={password}
			autocomplete="current-password"
			data-testid="mfa-reauth-password"
		/>
		<div class="sj-reauth-row">
			<Button variant="secondary" size="sm" onclick={oncancel} disabled={proving}>
				{t('common.cancel')}
			</Button>
			<Button
				variant="primary"
				size="sm"
				data-testid="mfa-reauth-confirm"
				onclick={submit}
				disabled={proving || password.length === 0}
			>
				{proving ? t('security.reauth.verifying') : t('security.reauth.confirm')}
			</Button>
		</div>
	{/if}

	{#if error}<p class="sj-reauth-error" role="alert">{error}</p>{/if}
</div>

<style>
	.sj-reauth-form {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 12px;
		padding-top: 12px;
		border-top: 1px solid var(--border);
	}

	.sj-reauth-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	.sj-reauth-methods {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
	}

	.sj-reauth-row {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 10px;
	}

	.sj-reauth-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
		margin: 0;
	}
</style>
