<svelte:options runes={true} />

<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { Button, Checkbox, Input, Spinner } from '$lib/components/ui';
	import { problemDetail } from '$lib/errors';
	import { httpRequest } from '$lib/http';
	import { formatDateTime, t } from '$lib/i18n';

	interface GuestInviteDisclosure {
		org_name: string;
		invited_email: string;
		channels: string[];
		disclosure_text: string;
		disclosure_version: string;
		expires_at: string;
	}

	interface PasswordPolicy {
		minLength: number;
		maxBytes: number;
		requireUppercase: boolean;
		requireLowercase: boolean;
		requireDigit: boolean;
		requireSpecial: boolean;
	}

	type State = 'loading' | 'ready' | 'submitting' | 'success' | 'error';

	let viewState = $state<State>('loading');
	let disclosure: GuestInviteDisclosure | null = $state(null);
	let passwordPolicy = $state<PasswordPolicy | null>(null);
	let token = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let accepted = $state(false);
	let error = $state('');
	let errorRetryable = $state(false);

	const terminalInviteError = 'guest-invite-terminal';

	let passwordsMatch = $derived(password === confirmPassword);
	let passwordError = $derived(
		password && passwordPolicy ? passwordPolicyViolation(password, passwordPolicy) : ''
	);
	let passwordHint = $derived(
		passwordPolicy
			? t('guest_accept.password_policy_hint', { min: String(passwordPolicy?.minLength ?? 8) })
			: t('guest_accept.password_hint')
	);
	let canActivate = $derived(
		viewState === 'ready' &&
		accepted &&
		password.length > 0 &&
		passwordError === '' &&
		confirmPassword.length > 0 &&
		passwordsMatch
	);

	function parsePasswordPolicy(raw: unknown): PasswordPolicy {
		if (!raw || typeof raw !== 'object') throw new Error('invalid password policy');
		const value = raw as Partial<PasswordPolicy>;
		if (
			!Number.isInteger(value.minLength) ||
			(value.minLength ?? 0) < 1 ||
			!Number.isInteger(value.maxBytes) ||
			(value.maxBytes ?? 0) < 1 ||
			typeof value.requireUppercase !== 'boolean' ||
			typeof value.requireLowercase !== 'boolean' ||
			typeof value.requireDigit !== 'boolean' ||
			typeof value.requireSpecial !== 'boolean'
		) {
			throw new Error('invalid password policy');
		}
		return value as PasswordPolicy;
	}

	function passwordPolicyViolation(value: string, policy: PasswordPolicy): string {
		if (new TextEncoder().encode(value).length > policy.maxBytes) {
			return t('guest_accept.password_too_long', { max: String(policy.maxBytes) });
		}
		if ([...value].length < policy.minLength) {
			return t('guest_accept.password_too_short', { min: String(policy.minLength) });
		}
		if (policy.requireUppercase && !/\p{Lu}/u.test(value)) {
			return t('guest_accept.password_needs_uppercase');
		}
		if (policy.requireLowercase && !/\p{Ll}/u.test(value)) {
			return t('guest_accept.password_needs_lowercase');
		}
		if (policy.requireDigit && !/\p{Nd}/u.test(value)) {
			return t('guest_accept.password_needs_digit');
		}
		if (policy.requireSpecial && !/[\p{P}\p{S}]/u.test(value)) {
			return t('guest_accept.password_needs_special');
		}
		return '';
	}

	async function responseError(res: Response, fallback: string): Promise<string> {
		const body = (await res.json().catch(() => null)) as
			| { error?: unknown; detail?: unknown; title?: unknown }
			| null;
		if (body && typeof body.error === 'string') return body.error;
		return problemDetail(
			new Response(JSON.stringify(body ?? {}), {
				status: res.status,
				headers: { 'Content-Type': 'application/json' }
			}),
			fallback
		);
	}

	onMount(() => {
		token = page.url.searchParams.get('token') ?? '';
		// Keep the credential in memory for the POST, but remove it from the
		// address bar/history before any user interaction or screenshot.
		if (token) {
			history.replaceState(history.state, '', page.url.pathname);
		}
		if (!token) {
			viewState = 'error';
			error = t('guest_accept.invalid');
			errorRetryable = false;
			return;
		}
		void loadInvite();
	});

	async function loadInvite() {
		viewState = 'loading';
		error = '';
		errorRetryable = false;
		try {
			const res = await httpRequest(
				`/auth/guest-invite/accept?token=${encodeURIComponent(token)}`,
				{
					loginRedirect: null,
					unauthorizedMessage: terminalInviteError,
					onError: (response) => responseError(response, t('guest_accept.load_failed'))
				}
			);
			disclosure = (await res.json()) as GuestInviteDisclosure;
			const policyResponse = await httpRequest('/auth/password-policy', {
				loginRedirect: null,
				onError: () => t('guest_accept.load_failed')
			});
			passwordPolicy = parsePasswordPolicy(await policyResponse.json());
			viewState = 'ready';
		} catch (caught) {
			viewState = 'error';
			if (caught instanceof Error && caught.message === terminalInviteError) {
				error = t('guest_accept.invalid');
				errorRetryable = false;
			} else {
				error = t('guest_accept.load_failed');
				errorRetryable = true;
			}
		}
	}

	async function activate(event: SubmitEvent) {
		event.preventDefault();
		if (!canActivate) return;
		if (!passwordsMatch) {
			error = t('guest_accept.password_mismatch');
			return;
		}

		viewState = 'submitting';
		error = '';
		try {
			await httpRequest('/auth/guest-invite/accept', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					token,
					disclosure_accepted: true,
					new_password: password
				}),
				loginRedirect: null,
				unauthorizedMessage: terminalInviteError,
				onError: (response) => responseError(response, t('guest_accept.activate_failed'))
			});
			token = '';
			password = '';
			confirmPassword = '';
			viewState = 'success';
		} catch (caught) {
			if (caught instanceof Error && caught.message === terminalInviteError) {
				token = '';
				viewState = 'error';
				error = t('guest_accept.invalid');
				errorRetryable = false;
				return;
			}
			viewState = 'ready';
			error = caught instanceof Error ? caught.message : t('guest_accept.activate_failed');
		}
	}
</script>

<svelte:head>
	<title>{t('guest_accept.page_title')}</title>
	<meta name="referrer" content="no-referrer" />
</svelte:head>

<div class="guest-accept-page">
	<div class="guest-accept-column">
		<img class="wordmark" src="/brand/logo-wordmark.svg" width="146" height="34" alt="setjoin" />

		<section class="guest-accept-card" aria-labelledby="guest-accept-title">
			{#if viewState === 'loading'}
				<div class="loading" role="status" aria-live="polite">
					<Spinner size={28} label={t('guest_accept.loading')} />
					<p>{t('guest_accept.loading')}</p>
				</div>
			{:else if viewState === 'error'}
				<div class="terminal-state">
					<div class="status-dot status-dot--danger" aria-hidden="true"></div>
					<h1 id="guest-accept-title">
						{t(errorRetryable ? 'guest_accept.load_error_title' : 'guest_accept.invalid_title')}
					</h1>
					<p>{error}</p>
					{#if errorRetryable}
						<Button size="lg" onclick={loadInvite}>
							{t('guest_accept.retry')}
						</Button>
					{/if}
					<Button variant="secondary" size="lg" onclick={() => goto('/')}>
						{t('guest_accept.back_to_sign_in')}
					</Button>
				</div>
			{:else if viewState === 'success'}
				<div class="terminal-state">
					<div class="status-dot status-dot--success" aria-hidden="true"></div>
					<h1 id="guest-accept-title">{t('guest_accept.success_title')}</h1>
					<p>{t('guest_accept.success_body')}</p>
					<Button size="lg" onclick={() => goto('/')}>
						{t('guest_accept.sign_in')}
					</Button>
				</div>
			{:else if disclosure}
				<header class="invite-header">
					<div class="external-badge">
						<span class="status-dot status-dot--warning" aria-hidden="true"></span>
						{t('guest_accept.external_badge')}
					</div>
					<h1 id="guest-accept-title">{t('guest_accept.title', { org: disclosure.org_name })}</h1>
					<p>{t('guest_accept.invited_as', { email: disclosure.invited_email })}</p>
				</header>

				<div class="invite-facts" aria-label={t('guest_accept.invitation_details')}>
					<div>
						<span>{t('guest_accept.organization')}</span>
						<strong>{disclosure.org_name}</strong>
					</div>
					<div>
						<span>{t('guest_accept.expires')}</span>
						<strong>{formatDateTime(disclosure.expires_at)}</strong>
					</div>
					{#if disclosure.channels.length > 0}
						<div>
							<span>{t('guest_accept.channels')}</span>
							<strong>{disclosure.channels.join(', ')}</strong>
						</div>
					{/if}
				</div>

				<div class="disclosure" aria-labelledby="guest-disclosure-title">
					<h2 id="guest-disclosure-title">{t('guest_accept.disclosure_title')}</h2>
					<p>{disclosure.disclosure_text}</p>
				</div>

				<form onsubmit={activate}>
					<Input
						id="guest-password"
						label={t('guest_accept.password')}
						hint={passwordHint}
						error={passwordError || undefined}
						type="password"
						autocomplete="new-password"
						required
						minlength={passwordPolicy?.minLength ?? 8}
						maxlength={128}
						size="lg"
						bind:value={password}
						disabled={viewState === 'submitting'}
					/>
					<Input
						id="guest-password-confirm"
						label={t('guest_accept.confirm_password')}
						error={confirmPassword && !passwordsMatch ? t('guest_accept.password_mismatch') : undefined}
						type="password"
						autocomplete="new-password"
						required
						minlength={passwordPolicy?.minLength ?? 8}
						maxlength={128}
						size="lg"
						bind:value={confirmPassword}
						disabled={viewState === 'submitting'}
					/>
					<Checkbox
						id="guest-disclosure-accept"
						bind:checked={accepted}
						label={t('guest_accept.accept_disclosure')}
						disabled={viewState === 'submitting'}
					/>

					{#if error}
						<div class="form-error" role="alert">{error}</div>
					{/if}

					<Button type="submit" size="lg" disabled={!canActivate || viewState === 'submitting'}>
						{viewState === 'submitting' ? t('guest_accept.activating') : t('guest_accept.activate')}
					</Button>
				</form>
			{/if}
		</section>

		<p class="privacy-note">{t('guest_accept.private_installation')}</p>
	</div>
</div>

<style>
	.guest-accept-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6);
		background: var(--surface-page);
	}

	.guest-accept-column {
		width: 100%;
		max-width: 560px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-5);
	}

	.wordmark {
		display: block;
	}

	:global([data-theme='dark']) .wordmark {
		content: url('/brand/logo-wordmark-dark.svg');
	}

	.guest-accept-card {
		width: 100%;
		padding: var(--space-8);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-xs);
	}

	.invite-header {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin-bottom: var(--space-5);
	}

	.invite-header h1,
	.terminal-state h1 {
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
		margin: 0;
	}

	.invite-header p,
	.terminal-state p,
	.loading p,
	.privacy-note {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}

	.external-badge {
		display: inline-flex;
		align-items: center;
		align-self: flex-start;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		color: var(--warning-fg);
		background: var(--warning-bg);
		border-radius: var(--radius-full);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
	}

	.status-dot {
		width: var(--space-2);
		height: var(--space-2);
		border-radius: var(--radius-full);
		flex: none;
	}

	.status-dot--warning {
		background: var(--warning-solid);
	}

	.status-dot--danger {
		background: var(--danger-solid);
	}

	.status-dot--success {
		background: var(--success-solid);
	}

	.invite-facts {
		display: grid;
		gap: var(--space-3);
		padding: var(--space-4);
		margin-bottom: var(--space-4);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
	}

	.invite-facts div {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
		gap: var(--space-3);
	}

	.invite-facts span {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}

	.invite-facts strong {
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		overflow-wrap: anywhere;
	}

	.disclosure {
		padding: var(--space-4);
		margin-bottom: var(--space-5);
		border-left: var(--space-1) solid var(--info-solid);
		background: var(--info-bg);
	}

	.disclosure h2 {
		margin: 0 0 var(--space-2);
		color: var(--info-fg);
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
	}

	.disclosure p {
		color: var(--info-fg);
		font-size: var(--text-sm);
		line-height: var(--leading-relaxed);
	}

	form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.form-error {
		padding: var(--space-3);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border: 1px solid var(--danger-solid);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}

	.loading,
	.terminal-state {
		min-height: 280px;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-4);
		text-align: center;
	}

	.privacy-note {
		text-align: center;
	}

	@media (max-width: 640px) {
		.guest-accept-page {
			padding: var(--space-3);
			align-items: flex-start;
		}

		.guest-accept-card {
			padding: var(--space-5);
		}

		.invite-facts div {
			grid-template-columns: 1fr;
			gap: var(--space-1);
		}
	}
</style>
