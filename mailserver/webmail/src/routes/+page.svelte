<svelte:options runes={true} />

<script lang="ts">
	import { login, loginWithCaptcha, changePassword, startWebAuthnLogin, ForcePasswordChangeError, MFARequiredError, MFAEnrollmentRequiredError, ThreatBlockedError, verifyTOTP, setupTOTPEnrollment, confirmTOTPEnrollment, provePossessionWebAuthn, ReauthRequiredError } from '$lib/stores/auth';
	import { Button, Input, Checkbox } from '$lib/components/ui';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { logger } from '$lib/logger';
	import { onMount, onDestroy } from 'svelte';
	import { t } from '$lib/i18n';
	import { parseOIDCOPContinuation } from '$lib/auth/oidcContinue';

	// D-I.3: show a flash when redirected here after secure-account
	const securedFlash = $derived(page.url.searchParams.get('secured') === '1' ? t('security.secured_relogin') : '');
	const oidcOPContinuation = $derived(
		parseOIDCOPContinuation(page.url.searchParams.get('continue'))
	);

	let email = $state('');
	let password = $state('');
	let error = $state('');
	let loading = $state(false);
	let rememberDevice = $state(true);

	let hostname = $derived(typeof window !== 'undefined' ? window.location.hostname : '');

	// Auto-discovery
	let serverURL = $state('');
	let discoveredServer = $state('');
	let loginField = $state<'email' | 'upn'>('email');
	let loginDomainHint = $state('');
	let loginName = $state('');
	let showManual = $state(false);
	let discoverTimeout: ReturnType<typeof setTimeout> | null = null;

	async function discoverServer(mail: string) {
		const domain = mail.split('@')[1];
		if (!domain) return;
		try {
			const resp = await fetch(`/api/discover?domain=${encodeURIComponent(domain)}`);
			if (resp.ok) {
				const data = await resp.json();
				discoveredServer = data.url;
				serverURL = data.url;
				loginField = data.login_field || 'email';
				loginDomainHint = data.login_domain_hint || '';
			}
		} catch { /* discovery failed — user can enter server manually */ }
	}

	function onEmailInput(value: string) {
		email = value;
		discoveredServer = '';
		if (discoverTimeout) clearTimeout(discoverTimeout);
		if (value.includes('@')) {
			discoverTimeout = setTimeout(() => discoverServer(value), 500);
		}
	}

	let brandName = $state('SetJoin');
	let brandLogoUrl = $state('');

	// CA-3b: cert-hint for failed-cert login banner (non-blocking, fail-open).
	let certStatus = $state<'' | 'expired' | 'untrusted' | 'no_match'>('');

	onMount(async () => {
		// Branding fetch only — wordmark theme sync is CSS-driven
		try {
			const resp = await fetch('/jmap/session');
			if (resp.ok) {
				const session = await resp.json();
				brandName = session.branding?.name || 'SetJoin';
				brandLogoUrl = session.branding?.logoUrl || '';
			}
		} catch { /* use defaults */ }

		// CA-3b: check if a client cert was presented but rejected; show a non-blocking
		// informational banner above the password form. Fail-open: any error is ignored.
		try {
			const cr = await fetch('/api/cert-hint');
			const cd = await cr.json() as { cert_status?: string };
			const s = cd.cert_status ?? '';
			if (s === 'expired' || s === 'untrusted' || s === 'no_match') certStatus = s;
		} catch { /* not critical — omit banner */ }
	});

	let forceChange = $state(false);
	let newPassword = $state('');
	let confirmPassword = $state('');

	let mfaRequired = $state(false);
	let mfaEnrollmentRequired = $state(false);
	let mfaToken = $state('');
	let totpCode = $state('');
	let totpEnrollmentSecret = $state('');
	// v7 §1.6: the setup-issued binding id the confirm arm must present.
	let totpEnrollmentId = $state('');

	// ── Possession scheme v7 §1.5.1: C1 passkey-holder bootstrap handoff ──
	// The enrollment_required login returns the SAME mfa_token for both
	// cohorts, but a passkey-holder gets NO password bootstrap grant: the bare
	// enroll/setup refuses with the typed 403 reauth_required, and the pending
	// grant is minted only by the webauthn_uv management ceremony (Mode B —
	// the mfa_token itself is the admission and the finish response is
	// {"granted": true}). bootstrapUvRequired shows the passkey step; after
	// the proof, setup is retried with the UNCHANGED token.
	let bootstrapUvRequired = $state(false);
	let bootstrapUvBusy = $state(false);

	// Auth-generation fencing (§3.1): a new login attempt or the back link
	// retires every in-flight bootstrap response — a late setup/ceremony
	// result for a superseded attempt never lands. UX fence only; the
	// server's mfa_pending JTI binding is the enforcement.
	let enrollGeneration = 0;
	function retireBootstrap(): void {
		enrollGeneration += 1;
		bootstrapUvRequired = false;
		bootstrapUvBusy = false;
		totpEnrollmentId = '';
		totpEnrollmentSecret = '';
	}

	// Threat state (Task 5 preparation)
	let threatState = $state<null | { category: string; captchaPrompt?: string; captchaToken?: string; retryAfterSecs?: number }>(null);
	let captchaAnswer = $state('');
	let countdown = $state(0);
	let countdownTimer: ReturnType<typeof setInterval> | null = null;

	onDestroy(() => {
		if (countdownTimer) clearInterval(countdownTimer);
	});

	function sanitizeTotpCode(e: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		totpCode = e.currentTarget.value.replace(/[^\d ]/g, '').slice(0, 7);
	}

	async function finishLoginNavigation() {
		if (oidcOPContinuation) {
			window.location.assign(oidcOPContinuation);
			return;
		}
		await goto('/apps');
	}

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		// The TOTP step lives inside the same <form>; an Enter-key submit there
		// must verify the code, not re-run the password flow.
		if (mfaEnrollmentRequired) {
			await handleMFAEnrollmentConfirm();
			return;
		}
		if (mfaRequired) {
			await handleMFAVerify();
			return;
		}
		error = '';
		loading = true;
		// A fresh password attempt supersedes any prior bootstrap attempt:
		// retire its in-flight setup/ceremony responses (§3.1 fencing).
		retireBootstrap();
		logger.log('login-form: submit clicked', { email });
		try {
			if (forceChange) {
				if (newPassword.length < 8) {
					error = t('login.password_min_length', { min: '8' });
					return;
				}
				if (newPassword !== confirmPassword) {
					error = t('login.passwords_mismatch');
					return;
				}
				await changePassword(password, newPassword);
				logger.log('login-form: password changed, navigating');
				await finishLoginNavigation();
			} else {
				const result = await login(email, password, rememberDevice);
				logger.log('login-form: login succeeded', result);
				await finishLoginNavigation();
			}
		} catch (err) {
			logger.error('login-form: login error', err);
			if (err instanceof ThreatBlockedError) {
				threatState = { category: err.category, captchaPrompt: err.captchaPrompt, captchaToken: err.captchaToken, retryAfterSecs: err.retryAfterSecs };
				if (err.retryAfterSecs && err.retryAfterSecs > 0) {
					countdown = err.retryAfterSecs;
					if (countdownTimer) clearInterval(countdownTimer);
					countdownTimer = setInterval(() => {
						countdown--;
						if (countdown <= 0 && countdownTimer) {
							clearInterval(countdownTimer);
							countdownTimer = null;
						}
					}, 1000);
				}
			} else if (err instanceof ForcePasswordChangeError) {
				forceChange = true;
				error = '';
			} else if (err instanceof MFAEnrollmentRequiredError) {
				mfaEnrollmentRequired = true;
				mfaToken = err.mfaToken;
				error = '';
				await beginBootstrapEnrollment(err.mfaToken);
			} else if (err instanceof MFARequiredError) {
				mfaRequired = true;
				mfaToken = err.mfaToken;
				error = '';
			} else {
				error = (err as Error).message;
			}
		} finally {
			loading = false;
			logger.log('login-form: loading reset');
		}
	}

	async function handleCaptchaSubmit() {
		if (!threatState?.captchaToken) return;
		error = '';
		loading = true;
		try {
			await loginWithCaptcha(email, password, threatState.captchaToken, captchaAnswer, rememberDevice);
			await finishLoginNavigation();
		} catch (err) {
			if (err instanceof ThreatBlockedError) {
				threatState = { category: err.category, captchaPrompt: err.captchaPrompt, captchaToken: err.captchaToken, retryAfterSecs: err.retryAfterSecs };
			} else if (err instanceof MFARequiredError) {
				mfaRequired = true;
				mfaToken = err.mfaToken;
				error = '';
			} else {
				error = (err as Error).message;
			}
		} finally {
			loading = false;
		}
	}

	async function handlePasskeyLogin() {
		error = '';
		loading = true;
		try {
			await startWebAuthnLogin(email);
			await finishLoginNavigation();
		} catch (err) {
			if (err instanceof MFARequiredError) {
				mfaRequired = true;
				mfaToken = err.mfaToken;
				error = '';
			} else {
				error = (err as Error).message;
			}
		} finally {
			loading = false;
		}
	}

	async function handleMFAVerify() {
		error = '';
		loading = true;
		try {
			await verifyTOTP(totpCode, mfaToken);
			await finishLoginNavigation();
		} catch (err) {
			error = (err as Error).message;
		} finally {
			loading = false;
		}
	}

	async function handleMFAEnrollmentConfirm() {
		error = '';
		loading = true;
		try {
			await confirmTOTPEnrollment(totpCode, mfaToken, totpEnrollmentId || undefined);
			await finishLoginNavigation();
		} catch (err) {
			error = (err as Error).message;
		} finally {
			loading = false;
		}
	}

	// Bootstrap enrollment setup: runs with the pending token alone. A C2/C3
	// account succeeds here (its password grant committed at login); a C1
	// passkey-holder hits the typed reauth_required refusal and is routed to
	// the UV ceremony below (v7 §1.5.1 step 5).
	async function beginBootstrapEnrollment(token: string) {
		const gen = ++enrollGeneration;
		bootstrapUvRequired = false;
		bootstrapUvBusy = false;
		totpEnrollmentSecret = '';
		totpEnrollmentId = '';
		try {
			const setup = await setupTOTPEnrollment(token);
			if (gen !== enrollGeneration) return;
			totpEnrollmentSecret = setup.secret;
			totpEnrollmentId = setup.enrollmentId ?? '';
		} catch (setupErr) {
			if (gen !== enrollGeneration) return;
			if (setupErr instanceof ReauthRequiredError) {
				// The passkey-holder path: offer the WebAuthn-UV proof. The
				// pending token itself stays valid and unchanged.
				bootstrapUvRequired = true;
				return;
			}
			mfaEnrollmentRequired = false;
			error = (setupErr as Error).message;
		}
	}

	// The webauthn_uv management ceremony (Mode B admission): begin + UV
	// assertion + finish with the SAME mfa_token mints the pending grant
	// ({"granted": true}); the setup arm is then retried with that token.
	async function handleBootstrapUvProof() {
		if (bootstrapUvBusy) return;
		const gen = enrollGeneration;
		bootstrapUvBusy = true;
		error = '';
		try {
			const proof = await provePossessionWebAuthn('bootstrap.totp.enroll', { mfaToken });
			if (gen !== enrollGeneration) return;
			if (proof.scope !== 'mfa_pending') {
				error = t('mfa.enroll_uv_error');
				return;
			}
		} catch (proofErr) {
			if (gen !== enrollGeneration) return;
			error = proofErr instanceof Error && proofErr.message ? proofErr.message : t('mfa.enroll_uv_error');
			bootstrapUvBusy = false;
			return;
		}
		bootstrapUvBusy = false;
		await beginBootstrapEnrollment(mfaToken);
	}
</script>

<div class="sj-login-page">
	<div class="sj-login-col">
		<!-- Wordmark -->
		<img class="sj-wordmark" src="/brand/logo-wordmark.svg" width="146" height="34" alt="setjoin" />

		<!-- Card -->
		<div class="sj-login-card">
			<!-- D-I.3: secured-relogin flash — shown when redirected here after secure-account -->
			{#if securedFlash}
				<div class="sj-secured-flash" role="status" aria-live="polite">{securedFlash}</div>
			{/if}

			<!-- CA-3b: failed-cert info banner (non-blocking; shown when the browser
			     presented a client cert that the gateway couldn't verify). -->
			{#if certStatus}
				{@const certReasonKey = certStatus === 'expired' ? 'login.cert_reason_expired' :
				                        certStatus === 'no_match' ? 'login.cert_reason_no_match' :
				                        'login.cert_reason_untrusted'}
				<div class="sj-cert-banner" role="status" aria-live="polite">
					{t('login.cert_failed', { reason: t(certReasonKey) })}
				</div>
			{/if}

			<!-- Step 1: Password (also handles force-change within the same card) -->
			<form class="sj-login-form" onsubmit={handleSubmit}>
				{#if mfaEnrollmentRequired}
					<h1 class="sj-login-title">{t('mfa.enroll_title')}</h1>
					<p class="sj-login-subtitle">{t('mfa.enroll_subtitle')}</p>

					{#if bootstrapUvRequired}
						<!-- v7 §1.5.1: C1 passkey-holder bootstrap — the pending grant
						     is minted by the webauthn_uv management ceremony (Mode B,
						     same mfa_token) before the setup arm accepts it. -->
						<p class="sj-login-subtitle" role="status">{t('mfa.enroll_uv_prompt')}</p>
						{#if error}
							<p class="sj-login-error" role="alert">{error}</p>
						{/if}
						<Button size="lg" variant="primary" disabled={bootstrapUvBusy || loading} type="button" onclick={handleBootstrapUvProof}>
							{bootstrapUvBusy ? t('mfa.enroll_uv_waiting') : t('mfa.enroll_uv_confirm')}
						</Button>
					{:else}
						{#if totpEnrollmentSecret}
							<div class="sj-enrollment-secret">
								<span>{t('mfa.enroll_secret')}</span>
								<pre aria-label={t('mfa.enroll_secret')}>{totpEnrollmentSecret}</pre>
							</div>
						{:else}
							<p class="sj-login-subtitle" role="status">{t('mfa.enroll_setting_up')}</p>
						{/if}

						<Input
							size="lg"
							mono
							inputmode="numeric"
							placeholder={t('mfa.totp_placeholder')}
							bind:value={totpCode}
							oninput={sanitizeTotpCode}
							autocomplete="one-time-code"
							maxlength={7}
							style="text-align:center"
						/>

						{#if error}
							<p class="sj-login-error" role="alert">{error}</p>
						{/if}

						<Button size="lg" variant="primary" disabled={!totpEnrollmentSecret || totpCode.replace(/\D/g, '').length < 6 || loading} type="button" onclick={handleMFAEnrollmentConfirm}>
							{loading ? t('mfa.verifying') : t('mfa.enroll_confirm')}
						</Button>
					{/if}

					<button type="button" class="sj-login-link" onclick={() => { retireBootstrap(); mfaEnrollmentRequired = false; mfaToken = ''; totpCode = ''; error = ''; }}>
						{t('mfa.back')}
					</button>

				{:else if mfaRequired}
					<h1 class="sj-login-title">{t('mfa.totp_title')}</h1>
					<p class="sj-login-subtitle">{t('mfa.totp_subtitle')}</p>

					<Input
						size="lg"
						mono
						inputmode="numeric"
						placeholder={t('mfa.totp_placeholder')}
						bind:value={totpCode}
						oninput={sanitizeTotpCode}
						autocomplete="one-time-code"
						maxlength={7}
						style="text-align:center"
					/>

					{#if error}
						<p class="sj-login-error" role="alert">{error}</p>
					{/if}

					<Button size="lg" variant="primary" disabled={totpCode.replace(/\D/g, '').length < 6 || loading} type="button" onclick={handleMFAVerify}>
						{loading ? t('mfa.verifying') : t('mfa.sign_in')}
					</Button>

					<button type="button" class="sj-login-link" onclick={handlePasskeyLogin}>
						{t('login.passkey_instead')}
					</button>

					<button type="button" class="sj-login-link" onclick={() => { mfaRequired = false; error = ''; }}>
						{t('mfa.back')}
					</button>

				{:else if threatState?.category === 'captcha'}
					<h1 class="sj-login-title">{t('login.threat.captcha_title')}</h1>
					<p class="sj-login-subtitle">{threatState.captchaPrompt}</p>

					<Input label={t('login.captcha_answer')} size="lg" type="text" inputmode="numeric" bind:value={captchaAnswer} />

					<Button size="lg" variant="primary" disabled={!captchaAnswer || loading} onclick={handleCaptchaSubmit}>
						{t('login.captcha_submit')}
					</Button>

					{#if error}
						<p class="sj-login-error" role="alert">{error}</p>
					{/if}

				{:else if threatState?.category === 'rate_limited' || threatState?.category === 'tarpit_applied'}
					<p class="sj-login-error" role="alert">{t('login.threat.rate_limited')}</p>
					{#if countdown > 0}
						<p class="sj-login-subtitle">{t('login.threat.retry_countdown', { secs: String(countdown) })}</p>
					{/if}

				{:else if threatState?.category === 'blocked' || threatState?.category === 'geo_blocked'}
					<p class="sj-login-error" role="alert">{t('login.threat.blocked')}</p>

				{:else}
					<h1 class="sj-login-title">{forceChange ? t('login.change_password') : t('login.title')}</h1>
					{#if !forceChange && hostname}
						<p class="sj-login-subtitle">{t('login.subtitle', { host: hostname })}</p>
					{/if}

					<Input
						label={t('login.email')}
						size="lg"
						type="email"
						value={email}
						oninput={(e) => onEmailInput((e.currentTarget as HTMLInputElement).value)}
						autocomplete="username"
						required
						disabled={forceChange}
					/>

					{#if discoveredServer}
						<div class="sj-discovery-badge">{t('login.server_found', { server: discoveredServer })}</div>
					{/if}

					{#if loginField === 'upn' && discoveredServer}
						<Input
							label={t('login.login_name')}
							size="md"
							type="text"
							placeholder={loginDomainHint || ''}
							bind:value={loginName}
						/>
					{/if}

					<Input
						label={forceChange ? t('login.current_password') : t('login.password')}
						size="lg"
						type="password"
						bind:value={password}
						autocomplete="current-password"
						required
					/>

					{#if forceChange}
						<Input
							label={t('login.new_password')}
							size="lg"
							type="password"
							bind:value={newPassword}
							autocomplete="new-password"
							required
							minlength={8}
						/>
						<Input
							label={t('login.confirm_password')}
							size="lg"
							type="password"
							bind:value={confirmPassword}
							autocomplete="new-password"
							required
							minlength={8}
						/>
					{/if}

					{#if !forceChange}
						<Checkbox bind:checked={rememberDevice} label={t('login.remember_device')} />
					{/if}

					{#if error}
						<p class="sj-login-error" role="alert">{error}</p>
					{/if}

					<Button size="lg" variant="primary" disabled={(!email || !password) && !forceChange || loading} type="submit">
						{loading ? (forceChange ? t('login.updating') : t('login.checking')) : (forceChange ? t('login.update_password') : t('login.continue'))}
					</Button>

					{#if !forceChange}
						<a href="/auth/forgot-password/begin" class="sj-login-link">{t('login.forgot_password')}</a>

						<button type="button" class="sj-login-link" onclick={handlePasskeyLogin}>
							{t('login.passkey_instead')}
						</button>

						<div class="sj-login-sso">
							<div class="sj-login-sso-divider"><span>{t('login.sso_divider')}</span></div>
							<div class="sj-login-sso-buttons">
								<a class="sj-login-sso-btn" href="/auth/saml/default/login">{t('login.sso_saml')}</a>
								<a class="sj-login-sso-btn" href="/auth/oidc/login">{t('login.sso_oidc')}</a>
							</div>
						</div>
					{/if}

					{#if !forceChange}
						<button type="button" class="sj-login-link" onclick={() => showManual = !showManual}>
							{showManual ? t('login.hide') : t('login.manual_setup')}
						</button>
						{#if showManual}
							<Input label={t('login.server_url')} size="md" type="url" bind:value={serverURL} placeholder="https://mail.company.com" />
						{/if}
					{/if}

					{#if forceChange}
						<button type="button" class="sj-login-link" onclick={() => { forceChange = false; newPassword = ''; confirmPassword = ''; error = ''; }}>
							{t('mfa.back')}
						</button>
					{/if}
				{/if}
			</form>
		</div>

		<!-- Footer -->
		<p class="sj-login-footer">
			{hostname} &middot; {t('login.footer_self_hosted')}<br />
			{t('login.footer_data_local')}
		</p>
	</div>
</div>

<style>
	/* ── Page ── */
	.sj-login-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 24px;
		background: var(--surface-page);
	}

	.sj-login-col {
		width: min(360px, 100%);
		display: flex;
		flex-direction: column;
		gap: 20px;
	}

	.sj-enrollment-secret {
		display: grid;
		gap: 8px;
		color: var(--text-secondary);
		font-size: 13px;
	}

	.sj-enrollment-secret pre {
		margin: 0;
		padding: 12px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-raised);
		color: var(--text-primary);
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.4;
		overflow-wrap: anywhere;
		white-space: pre-wrap;
	}

	/* ── Wordmark ── */
	.sj-wordmark {
		display: block;
		margin: 0 auto;
	}

	:global([data-theme="dark"]) .sj-wordmark {
		content: url('/brand/logo-wordmark-dark.svg');
	}

	/* ── Card ── */
	.sj-login-card {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-sm);
		padding: 24px;
	}

	.sj-login-form {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	/* ── Typography ── */
	.sj-login-title {
		font-size: var(--text-xl);
		font-weight: 600;
		letter-spacing: -0.01em;
		margin: 0;
		color: var(--text-primary);
	}

	.sj-login-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 2px 0 0;
		line-height: 1.4;
	}

	/* ── Error ── */
	.sj-login-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 0;
	}

	/* ── Links ── */
	.sj-login-link {
		border: none;
		background: none;
		font-size: var(--text-sm);
		color: var(--text-accent);
		text-decoration: none;
		text-align: center;
		display: block;
		cursor: pointer;
		padding: 0;
		font-family: inherit;
	}

	.sj-login-link:hover {
		text-decoration: underline;
	}

	/* ── SSO ── */
	.sj-login-sso {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.sj-login-sso-divider {
		display: flex;
		align-items: center;
		text-align: center;
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}

	.sj-login-sso-divider::before,
	.sj-login-sso-divider::after {
		content: '';
		flex: 1;
		height: 1px;
		background: var(--border-default);
	}

	.sj-login-sso-divider span {
		padding: 0 12px;
	}

	.sj-login-sso-buttons {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-login-sso-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 32px;
		padding: 0 12px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		text-decoration: none;
		cursor: pointer;
		font-family: inherit;
	}

	.sj-login-sso-btn:hover {
		background: var(--surface-hover);
	}

	/* ── Discovery ── */
	.sj-discovery-badge {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding: 4px 0;
	}

	/* ── Footer ── */
	.sj-login-footer {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		text-align: center;
		line-height: 1.5;
		margin: 0;
	}

	/* D-I.3: secured-relogin flash — shown after secure-account redirect */
	.sj-secured-flash {
		background: var(--info-bg);
		border: 1px solid var(--info-solid, var(--info-fg));
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		font-size: var(--text-sm);
		color: var(--info-fg);
		line-height: 1.5;
		margin-bottom: 4px;
	}

	/* CA-3b: failed-cert login banner — informational, non-blocking */
	.sj-cert-banner {
		background: var(--info-bg);
		border: 1px solid var(--info-solid, var(--info-fg));
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		font-size: var(--text-sm);
		color: var(--info-fg);
		line-height: 1.5;
		margin-bottom: 4px;
	}
</style>
