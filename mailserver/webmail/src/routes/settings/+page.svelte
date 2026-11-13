<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { user, checkAuth, authIdentity, authGeneration } from '$lib/stores/auth';
	import { formatBytes } from '$lib/utils/display';
	import { fetchPasskeyCredentials, setupTOTP, confirmTOTP, beginTOTPRemoval, removeTOTP, enrollPasskey, ReauthRequiredError, type PasskeyCredential, type MFAReauthOperation } from '$lib/stores/auth';
	import MfaReauthHandoff, { type ReauthProofMethod } from '$lib/components/MfaReauthHandoff.svelte';
	import { logger } from '$lib/logger';
	import { parseError } from '$lib/errors';
	import { switchLocale, type Locale } from '$lib/i18n';
	import { t } from '$lib/i18n';
	import { Card, Switch, Select, Input, Button, Badge, Avatar, showToast, Toast } from '$lib/components/ui';
	import { applyTheme as applyThemeShared, applyDensity as applyDensityShared } from '$lib/theme/apply';
	import type { OfflineCaps } from '$lib/offline/caps';
	import { offlineReason, cappedWindow } from '$lib/offline/caps';
	import { isOfflineAvailable } from '$lib/offline/store';
	import { offlineOptIn } from '$lib/admin/client';
	import { getStore } from '$lib/offline/store';
	import {
		recoveryCoverage,
		recoveryOptedIn as loadRecoveryOptIn,
		recoverableArtifacts,
		offerRecoveryArtifact,
		cancelRecoveryOffer,
		setRecoveryOptIn,
		type RecoverableArtifactSummary,
		type RecoveryCoverage,
	} from '$lib/offline/recovery';
	import { recoveryIncidentOffers, type RecoveryIncidentOffer } from '$lib/jmap/client';
	import { e5ui } from '$lib/offline/e5ui.svelte';
	import { readOwnDeviceId } from '$lib/native/deviceId';
	import {
		explainCrossedAdmission,
		AUTOMATIC_NETWORK_VALUES,
		ATTACHMENT_PREFETCH_VALUES,
		type E5AutomaticNetworkPref,
		type E5AttachmentPrefetchPref,
		type E5SettingsView,
	} from '$lib/offline/e5Settings';

	// ── Test-only props: seed the offline card deterministically in unit tests.
	// ponytail: __ prefix marks as test-hook, not a real product API. In production
	// these are undefined and the page derives values from the session / native bridge.
	let {
		__offlineCaps = undefined,
		__bridgePresent = undefined,
	}: {
		__offlineCaps?: OfflineCaps;
		__bridgePresent?: boolean;
	} = $props();

	// ── Profile state ──
	let displayName = $state('');
	let profileSaving = $state(false);
	let profileError = $state('');

	// ── Appearance & language state ──
	let theme = $state('light');
	let lang = $state('en');
	let compact = $state(false);

	// ── Mail prefs state ──
	let undoWindow = $state('10');
	let snoozeMorning = $state('8:00');
	let bundleNewsletters = $state(true);
	let keyboardShortcuts = $state(true);
	let desktopNotifications = $state(false);

	// ── Offline caps state ──
	// _liveCaps: fetched from server on mount; __offlineCaps overrides in tests.
	let _liveCaps = $state<OfflineCaps | undefined>(undefined);
	const offlineCaps    = $derived(__offlineCaps !== undefined ? __offlineCaps : _liveCaps);
	const bridgePresent  = $derived(__bridgePresent !== undefined ? __bridgePresent : isOfflineAvailable());
	// User's preferred window (defaults to server cap once caps load)
	let offlineWindowDays = $state(7);
	// ponytail: computed once, used in two places in the settings card
	const effectiveWindow = $derived(cappedWindow(offlineWindowDays, offlineCaps));
	// ponytail: starts true — ALLOWED state means user is already opted in
	let offlineOptedIn = $state(true);
	let optInBusy    = $state(false);
	let optInError   = $state(''); // inline error on BZ100/409 from opt-in endpoint
	let offlineLive  = $state(''); // aria-live polite for status changes
	let recoveryEnabled = $state(false);
	let recoveryBusy = $state(false);
	let recoveryError = $state('');
	let recoveryStats = $state<RecoveryCoverage>({ count: 0, bytes: 0, oldestAt: null, newestAt: null });
	let recoveryOffers = $state<RecoveryIncidentOffer[]>([]);
	let recoveryCandidates = $state<Record<string, RecoverableArtifactSummary[]>>({});
	let recoveryUploading = $state('');
	let recoveryOfferStatus = $state<Record<string, string>>({});
	const recoveryAvailable = $derived(
		bridgePresent && typeof window !== 'undefined' && !!window.setjoinNative?.db && !!window.setjoinNative?.recoveryBlob,
	);
	// offlineReasonKey: i18n key returned by offlineReason(); translated at render time
	const offlineReasonKey = $derived(offlineReason(offlineCaps, bridgePresent));

	// ── Security state ──
	let passkeyCreds = $state<PasskeyCredential[]>([]);
	let passkeysLoading = $state(false);

	let totpEnabled = $state(false);
	let totpLoading = $state(false);
	let totpSetup = $state<{ secret: string; provisioningUri: string; enrollmentId?: string }>({ secret: '', provisioningUri: '' });
	let totpConfirmCode = $state('');
	let totpError = $state('');

	// ── Possession scheme v7 §3.1 method-aware re-auth handoff ──
	// Passkey registration and TOTP setup/confirm are gated; the handoff mints
	// the fresh proof that retries them. Offered methods are the account's
	// ENROLLED proof methods — C1 proves with WebAuthn-UV or TOTP (the §3
	// possession endpoints); password only for the C2/C3 step-up cohorts.
	let reauthOpen = $state(false);
	let reauthOperation = $state<MFAReauthOperation | null>(null);
	let heldReauthToken = $state('');

	// Auth-generation fencing (§3.1): pending ceremony/grant state and returned
	// secrets drop whenever the SESSION lifecycle moves — a new session, a
	// /auth/refresh rotation, impersonation, logout, reset — or checkAuth
	// observes a changed account identity (r2 defect 10: identity-only fencing
	// let a SAME-ACCOUNT refresh keep a held grant (dead — grants bind the
	// access JTI) and returned secrets alive across the session boundary).
	// Stale in-flight responses are refused before assigning secrets/tokens.
	// UX fence only — the server's tuple binding is the enforcement.
	const accountIdentity = $derived($user ? authIdentity($user) : null);
	let mfaGeneration = 0;
	$effect(() => {
		void accountIdentity;
		void $authGeneration;
		mfaGeneration += 1;
		heldReauthToken = '';
		reauthOpen = false;
		reauthOperation = null;
		totpSetup = { secret: '', provisioningUri: '' };
		totpConfirmCode = '';
		return () => {
			mfaGeneration += 1;
		};
	});

	// Possession first, password fallback only when neither C1 method is
	// enrolled (uv_capable is optional on the wire — absent never offers the
	// WebAuthn-UV proof; fail-closed per §1.2).
	const reauthMethods = $derived.by(() => {
		const methods: ReauthProofMethod[] = [];
		if (passkeyCreds.some((c) => c.uv_capable === true)) methods.push('webauthn_uv');
		if (totpEnabled) methods.push('totp');
		if (methods.length === 0) methods.push('password');
		return methods;
	});

	// MFA de-enrollment step-up form: password + code (TOTP or recovery) and a
	// typed confirmation before the server will remove the factor.
	let totpRemoveOpen = $state(false);
	let totpRemovePassword = $state('');
	let totpRemoveCode = $state('');
	let totpRemoveConfirm = $state('');
	const totpRemoveReady = $derived(
		totpRemovePassword.length > 0 && totpRemoveCode.trim().length > 0 && totpRemoveConfirm === 'REMOVE'
	);

	let hostname = $derived(typeof window !== 'undefined' ? window.location.hostname : '');
	let userEmail = $derived($user?.email ?? '');

	// ── E5 requested-vs-effective preferences (gated; renders nothing while the
	// ── connectivity-aware-sync program is OFF — the shipped default) ──────────
	const e5Active = $derived(e5ui.active);
	// settingsRevision forces recomputation: the controller is a plain closure
	// (pure module), e5ui bumps the revision after every mutating call.
	const e5SettingsView = $derived.by((): E5SettingsView | null => {
		void e5ui.settingsRevision;
		return e5Active ? e5ui.settings.view() : null;
	});
	const e5SaveConfigured = $derived(e5ui.settingsSaver !== null);
	// Crossed-settings explanation (CAS-E5-CROSSED-NETWORK-ATTACHMENT): composed
	// ONLY from server-resolved effective values — the EFFECTIVE background
	// policy (the same authority class the admin preview renders), never the
	// draft switch — and the live capability/metering snapshot (e5ui.networkCost,
	// fed by native capability truth; a browser that cannot know stays unmetered
	// here and the copy makes no metered claim). The client never recomputes
	// precedence.
	const e5Explanation = $derived.by(() => {
		const view = e5SettingsView;
		if (view === null || view.acknowledged === null) return null;
		return explainCrossedAdmission({
			backgroundSyncEnabled: view.acknowledged.effective.backgroundAllowed,
			effectiveAutomaticNetwork: view.acknowledged.effective.automaticNetwork,
			effectiveAttachmentPrefetch: view.acknowledged.effective.attachmentPrefetch,
			meteredLink: e5ui.networkCost === 'metered',
		});
	});
	// The race guard binds the REAL lifecycle identity: the auth store's
	// account identity (JWT-claim user id, else email) and this device's
	// canonical secure-store 'device_id' — null when a plain browser has none.
	// Any account/device change re-binds and invalidates a pending response.
	const e5AccountIdentity = $derived($user ? authIdentity($user) : null);
	// Astra r2 P2: the device-ID read is async, so a lookup begun for one
	// identity must never land after the identity (or the E5 gate) changed —
	// the same generation fencing the save path uses. Every effect re-run
	// bumps the generation; a lookup whose captured generation is stale is
	// discarded, so a delayed read for the previous account can never re-bind
	// the singleton backwards. The cleanup also retires in-flight lookups on
	// unmount.
	let e5LookupGeneration = 0;
	$effect(() => {
		const generation = ++e5LookupGeneration;
		if (!e5Active) return;
		const account = e5AccountIdentity;
		if (account === null) return;
		void readOwnDeviceId().then((deviceId) => {
			if (e5LookupGeneration !== generation) return; // stale binding — never lands
			e5ui.bindSettingsAccount(account, deviceId);
		});
		return () => {
			e5LookupGeneration += 1; // re-run/unmount retires in-flight lookups
		};
	});
	function e5NetworkOptions(): { value: string; label: string }[] {
		return AUTOMATIC_NETWORK_VALUES.map((value) => ({ value, label: t(`offline.e5.settings.net.${value}`) }));
	}
	function e5AttachmentOptions(): { value: string; label: string }[] {
		return ATTACHMENT_PREFETCH_VALUES.map((value) => ({ value, label: t(`offline.e5.settings.att.${value}`) }));
	}
	async function e5SavePrefs(): Promise<void> {
		if (!e5SaveConfigured) return;
		const ok = await e5ui.submitSettings();
		if (ok) {
			// Single-announcer contract: this page's ONE polite live region
			// (offlineLive) owns E5 save outcomes — no competing toast (Astra
			// r2 P2: a toast role=status plus this region announced twice).
			offlineLive = t('offline.e5.settings.announce_saved');
		}
		// Failure: the inline remedy renders from the controller's failed status;
		// drafts are preserved by the controller — never a success.
	}

	// ── Initialization ──
	$effect(() => {
		// Read persisted prefs from localStorage
		if (typeof window !== 'undefined') {
			theme = localStorage.getItem('sj-theme') || 'light';
			lang = localStorage.getItem('sj-lang') || 'en';
			compact = localStorage.getItem('density') === 'compact';
			undoWindow = localStorage.getItem('sj-undo-window') || '10';
			snoozeMorning = localStorage.getItem('sj-snooze-morning') || '8:00';
			bundleNewsletters = localStorage.getItem('sj-bundle-newsletters') !== 'false';
			keyboardShortcuts = localStorage.getItem('sj-keyboard-shortcuts') !== 'false';
			desktopNotifications = localStorage.getItem('sj-desktop-notifications') === 'true';
			// Prefer the saved display name from the server; fall back to the email local-part.
			displayName = $user?.displayName || ($user?.email?.split('@')[0] ?? '');
		}
		// Sync TOTP status from auth store (server-enforced state)
		totpEnabled = $user?.totp_enabled ?? false;
	});

	onMount(async () => {
		// Load passkey credentials
		try {
			passkeysLoading = true;
			passkeyCreds = await fetchPasskeyCredentials();
		} catch (err) {
			logger.error('settings: failed to load passkeys', err);
		} finally {
			passkeysLoading = false;
		}

		// Load offline caps (best-effort; card stays hidden on failure)
		if (__offlineCaps === undefined && bridgePresent) {
			try {
				const res = await fetch('/api/user/offline/caps', { credentials: 'include' });
				if (res.ok) {
					_liveCaps = await res.json() as OfflineCaps;
					offlineWindowDays = _liveCaps.maxOfflineDays;
				}
			} catch {
				// ponytail: silently skip — card stays absent on plain-browser with no endpoint
			}
		} else if (__offlineCaps !== undefined) {
			// Test mode: seed user window from the injected caps
			offlineWindowDays = __offlineCaps.maxOfflineDays;
		}

		if (recoveryAvailable) {
			try {
				const store = getStore();
				await store?.init();
				const db = window.setjoinNative!.db!;
				recoveryEnabled = await loadRecoveryOptIn(db);
				recoveryStats = await recoveryCoverage(db);
				if (recoveryEnabled) await refreshRecoveryOffers();
			} catch (err) {
				logger.warn('settings: failed to load recovery coverage', err);
			}
		}
	});

	async function toggleRecovery(enabled: boolean) {
		if (!recoveryAvailable) return;
		recoveryBusy = true;
		recoveryError = '';
		try {
			await setRecoveryOptIn(window.setjoinNative!.db!, enabled);
			recoveryEnabled = enabled;
			if (enabled) await refreshRecoveryOffers();
			offlineLive = enabled ? t('settings.recovery.on_announce') : t('settings.recovery.off_announce');
		} catch (err) {
			recoveryError = parseError(err).message;
		} finally {
			recoveryBusy = false;
		}
	}

	async function refreshRecoveryOffers() {
		if (!recoveryAvailable) return;
		try {
			recoveryOffers = await recoveryIncidentOffers();
			const next: Record<string, RecoverableArtifactSummary[]> = {};
			for (const incident of recoveryOffers) {
				next[incident.id] = await recoverableArtifacts(window.setjoinNative!.db!, incident);
			}
			recoveryCandidates = next;
		} catch {
			// Intake and receipt flags are independent. An OFF/404 intake is the
			// expected default and does not affect encrypted local coverage.
			recoveryOffers = [];
			recoveryCandidates = {};
		}
	}

	async function offerRecoveryCopy(incident: RecoveryIncidentOffer, artifact: RecoverableArtifactSummary) {
		recoveryUploading = artifact.artifactIdentity;
		recoveryError = '';
		try {
			const result = await offerRecoveryArtifact(artifact.artifactIdentity, incident.id);
			recoveryOfferStatus = { ...recoveryOfferStatus, [artifact.artifactIdentity]: result.status };
		} catch (err) {
			recoveryError = parseError(err).message;
		} finally {
			recoveryUploading = '';
		}
	}


	// ── Profile ──
	async function saveProfile() {
		profileSaving = true;
		profileError = '';
		try {
			const res = await fetch('/api/user/profile', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ display_name: displayName })
			});
			if (!res.ok) {
				const d = await res.json().catch(() => ({})) as { error?: string };
				throw new Error(d.error || 'Failed to save profile');
			}
			await checkAuth(); // refresh $user so the new display name shows immediately
			showToast(t('settings.profile_saved'));
		} catch (err) {
			profileError = parseError(err).message;
			logger.error('settings: profile save failed', err);
		} finally {
			profileSaving = false;
		}
	}

	// ── Appearance ──
	function applyTheme(v: string) {
		theme = v;
		applyThemeShared(v as 'system' | 'dark' | 'light');
		showToast(t('settings.saved'));
	}

	async function applyLang(v: string) {
		await switchLocale(v as Locale);
		lang = v;
		localStorage.setItem('sj-lang', v);
		showToast(t('settings.saved'));
	}

	function applyCompact(checked: boolean) {
		compact = checked;
		applyDensityShared(checked ? 'compact' : 'comfortable');
		showToast(t('settings.saved'));
	}

	// ── Mail prefs ──
	function saveMailPrefs() {
		localStorage.setItem('sj-undo-window', undoWindow);
		localStorage.setItem('sj-snooze-morning', snoozeMorning);
		localStorage.setItem('sj-bundle-newsletters', String(bundleNewsletters));
		localStorage.setItem('sj-keyboard-shortcuts', String(keyboardShortcuts));
		localStorage.setItem('sj-desktop-notifications', String(desktopNotifications));
		showToast(t('settings.saved'));
	}

	// ── Security ──
	let passkeyError = $state('');

	async function beginPasskeyEnrollment() {
		// Generation fencing: a registration landing after an account identity
		// change must not refresh the passkey list or clear errors (§3.1).
		const gen = mfaGeneration;
		passkeyError = '';
		try {
			// Gated arm (v7 §3): the grant rides the X-MFA-Reauth header on
			// begin and the body member on finish; reauth_required surfaces the
			// method-aware handoff instead of a bare failure (§3.1).
			await enrollPasskey(heldReauthToken || undefined);
			if (gen !== mfaGeneration) return;
			heldReauthToken = '';
			showToast('Passkey added');
			passkeyCreds = await fetchPasskeyCredentials();
		} catch (err) {
			if (gen !== mfaGeneration) return;
			if (err instanceof ReauthRequiredError) {
				// The re-auth proof is missing, stale, or already consumed:
				// open the shared handoff for a fresh webauthn.register proof.
				heldReauthToken = '';
				reauthOperation = 'webauthn.register';
				reauthOpen = true;
				return;
			}
			passkeyError = parseError(err).message;
			logger.error('settings: passkey enrollment failed', err);
		}
	}

	function cancelReauth() {
		reauthOpen = false;
		reauthOperation = null;
		heldReauthToken = '';
	}

	async function handleReauthProof(proof: { method: ReauthProofMethod; token: string }) {
		const gen = mfaGeneration;
		heldReauthToken = proof.token;
		const operation = reauthOperation;
		reauthOpen = false;
		reauthOperation = null;
		if (gen !== mfaGeneration) return;
		// Retry the gated action with the fresh proof through the same
		// handlers, so a stale-proof loop reopens the handoff honestly (§4.3).
		if (operation === 'webauthn.register') {
			await beginPasskeyEnrollment();
		} else if (operation === 'totp.enroll' || operation === 'totp.replace') {
			await runSetupWithProof();
		} else {
			await runConfirmWithProof();
		}
	}

	async function handleSetupTOTP() {
		// Setup is only offered while no authenticator is enabled on this page,
		// so the gated arm is a first enrollment (§1.3 totp.enroll).
		heldReauthToken = '';
		reauthOperation = 'totp.enroll';
		await runSetupWithProof();
	}

	async function runSetupWithProof() {
		const gen = mfaGeneration;
		totpLoading = true;
		totpError = '';
		try {
			const details = await setupTOTP(heldReauthToken || undefined);
			if (gen !== mfaGeneration) return;
			totpSetup = details;
		} catch (e) {
			if (gen !== mfaGeneration) return;
			if (e instanceof ReauthRequiredError) {
				// A fresh proof is required before the server mints the secret.
				heldReauthToken = '';
				reauthOperation = 'totp.enroll';
				reauthOpen = true;
				return;
			}
			totpError = 'Failed to set up TOTP. Please try again.';
		} finally {
			totpLoading = false;
		}
	}

	async function handleConfirmTOTP() {
		await runConfirmWithProof();
	}

	async function runConfirmWithProof() {
		const gen = mfaGeneration;
		totpLoading = true;
		totpError = '';
		try {
			// The grant + the setup-issued enrollment binding ride the confirm
			// call (v7 §1.6, §3.1).
			await confirmTOTP(totpConfirmCode, {
				reauthToken: heldReauthToken || undefined,
				enrollmentId: totpSetup.enrollmentId
			});
			if (gen !== mfaGeneration) return;
			totpEnabled = true;
			totpSetup = { secret: '', provisioningUri: '' };
			totpConfirmCode = '';
			heldReauthToken = '';
			showToast('Authenticator enabled');
		} catch (e) {
			if (gen !== mfaGeneration) return;
			if (e instanceof ReauthRequiredError) {
				// The proof is missing, stale, or was consumed: reopen the
				// handoff for a fresh one — the typed code is kept and retried.
				heldReauthToken = '';
				reauthOperation = 'totp.enroll';
				reauthOpen = true;
				return;
			}
			totpError = 'Invalid code. Please try again.';
		} finally {
			totpLoading = false;
		}
	}

	function handleRemoveTOTP() {
		totpRemovePassword = '';
		totpRemoveCode = '';
		totpRemoveConfirm = '';
		totpError = '';
		totpRemoveOpen = true;
	}

	async function handleConfirmRemoveTOTP() {
		totpLoading = true;
		totpError = '';
		try {
			// Step-up first (password + TOTP/recovery code), then the typed-
			// confirmation removal; the server removes factor + recovery codes
			// in one serialized transaction.
			const stepUp = await beginTOTPRemoval(totpRemovePassword, totpRemoveCode.trim());
			await removeTOTP(stepUp.stepUpToken);
			totpEnabled = false;
			totpRemoveOpen = false;
			showToast('Authenticator disabled');
		} catch {
			totpError = 'Failed to remove TOTP. Please try again.';
		} finally {
			totpLoading = false;
		}
	}

	// ── Offline: request approval action ────────────────────────────────────────
	async function requestApproval() {
		optInBusy = true;
		try {
			await offlineOptIn(true);
			offlineLive = t('settings.offline.requested');
			showToast(t('settings.offline.requested'));
		} catch (e) {
			showToast(parseError(e).message);
		} finally {
			optInBusy = false;
		}
	}

	// ── Offline: ALLOWED state — opt-in toggle (user can opt out) ────────────
	async function toggleOptIn(checked: boolean) {
		offlineOptedIn = checked; // optimistic
		optInError = '';
		try {
			await offlineOptIn(checked);
			offlineLive = checked ? t('settings.offline.on_announce') : '';
			showToast(t('settings.saved'));
		} catch (e) {
			offlineOptedIn = !checked; // revert on error (BZ100 / 409)
			optInError = t('settings.offline.opt_in_error');
			showToast(parseError(e).message);
		}
	}

	// ── Offline: window days — persist to server as nearest valid window string ─
	// ponytail: snaps to nearest valid discrete window; best-effort save
	function daysToWindowStr(days: number): string {
		if (days <= 7) return '7d';
		if (days <= 30) return '30d';
		if (days <= 90) return '90d';
		if (days <= 180) return '180d';
		if (days <= 365) return '365d';
		return 'all';
	}

	async function saveWindowDays(days: number) {
		offlineWindowDays = days;
		try {
			await fetch('/api/settings/view', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ offlineWindow: daysToWindowStr(days) }),
			});
		} catch {
			// ponytail: best-effort pref; local state stays updated even on server fail
		}
	}

	function formatDate(iso: string): string {
		if (!iso) return '';
		try {
			return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
		} catch {
			return iso;
		}
	}
</script>

<div class="sj-settings-page">
	<div class="sj-settings-inner">
		<h1 class="sj-page-title">{t('settings.title')}</h1>
		<p class="sj-settings-subtitle">{t('settings.subtitle')}</p>

		<!-- Profile card -->
		<Card title={t('settings.profile_card')}>
			<div class="sj-form-row">
				<Avatar name={userEmail} size="xl" />
				<div class="sj-form-grid">
					<Input label={t('settings.display_name')} bind:value={displayName} />
					<Input label={t('login.email')} value={userEmail} mono disabled hint={t('settings.email_disabled_hint')} />
					<div class="sj-span-all">
						<Button variant="secondary" size="sm" onclick={saveProfile} disabled={profileSaving}>
							{profileSaving ? 'Saving…' : t('settings.save_profile')}
						</Button>
						{#if profileError}
							<p class="sj-settings-error" role="alert">{profileError}</p>
						{/if}
					</div>
				</div>
			</div>
		</Card>

		<!-- Appearance & language card -->
		<Card title={t('settings.appearance_card')}>
			<div class="sj-form-grid">
				<Select
					label={t('settings.theme')}
					options={[
						{ value: 'light', label: t('settings.theme_light') },
						{ value: 'dark', label: t('settings.theme_dark') },
						{ value: 'system', label: t('settings.theme_system') }
					]}
					value={theme}
					onchange={(e) => applyTheme((e.target as HTMLSelectElement).value)}
				/>
				<Select
					label={t('settings.language')}
					options={[
						{ value: 'en', label: 'English' },
						{ value: 'zh', label: '中文（简体）' },
						{ value: 'de', label: 'Deutsch' }
					]}
					value={lang}
					onchange={(e) => applyLang((e.target as HTMLSelectElement).value)}
				/>
				<div class="sj-span-all">
					<Switch
						label={t('settings.compact_rows')}
						description={t('settings.compact_rows_desc')}
						checked={compact}
						onchange={(e) => applyCompact(e.currentTarget.checked)}
					/>
				</div>
			</div>
		</Card>

		<!-- Mail card -->
		<Card title={t('settings.mail_card')}>
			<div class="sj-form-grid">
				<Select
					label={t('settings.undo_window')}
					options={[
						{ value: '5', label: t('settings.undo_5s') },
						{ value: '10', label: t('settings.undo_10s') },
						{ value: '30', label: t('settings.undo_30s') }
					]}
					value={undoWindow}
					onchange={(e) => { undoWindow = (e.target as HTMLSelectElement).value; saveMailPrefs(); }}
				/>
				<Select
					label={t('settings.snooze_morning')}
					options={[
						{ value: '7:00', label: '7:00' },
						{ value: '8:00', label: '8:00' },
						{ value: '9:00', label: '9:00' }
					]}
					value={snoozeMorning}
					onchange={(e) => { snoozeMorning = (e.target as HTMLSelectElement).value; saveMailPrefs(); }}
				/>
				<div class="sj-span-all"><Switch label={t('settings.bundle_newsletters')} description={t('settings.bundle_newsletters_desc')} checked={bundleNewsletters} onchange={(e) => { bundleNewsletters = e.currentTarget.checked; saveMailPrefs(); }} /></div>
				<div class="sj-span-all"><Switch label={t('settings.keyboard_shortcuts')} description={t('settings.keyboard_shortcuts_desc')} checked={keyboardShortcuts} onchange={(e) => { keyboardShortcuts = e.currentTarget.checked; saveMailPrefs(); }} /></div>
				<div class="sj-span-all"><Switch label={t('settings.desktop_notifications')} description={t('settings.desktop_notifications_desc')} checked={desktopNotifications} onchange={(e) => { desktopNotifications = e.currentTarget.checked; saveMailPrefs(); }} /></div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/signatures')}>
						{t('settings.signatures.manage')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/automatic-replies')}>
						{t('autoReply.manage')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/approval-delegation')}>
						{t('approvalDelegation.manage')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/privacy')}>
						{t('privacy.card_title')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/quick-steps')}>
						{t('quickSteps.title')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/rules')}>
						{t('rules.title')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/sharing')}>
						{t('sharing.title')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/booking')}>
						{t('booking.settings.title')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/templates')}>
						{t('templates.manage')}
					</Button>
				</div>
				<div class="sj-span-all">
					<Button variant="secondary" size="sm" onclick={() => goto('/settings/storage')}>
						{t('settings.storage.title')}
					</Button>
				</div>
			</div>
		</Card>

		<!-- Security card -->
		<Card title={t('settings.security_card')}>
			<!-- Passkey credentials -->
			{#if passkeyCreds.length > 0}
				{#each passkeyCreds as cred}
					<div class="sj-security-row">
						<Badge variant="success" dot />
						<span>{t('settings.passkey_added', { date: formatDate(cred.created_at), device: cred.device_name })}</span>
					</div>
				{/each}
			{/if}

			<!-- TOTP status -->
			{#if totpEnabled}
				<div class="sj-security-row">
					<Badge variant="success" dot />
					<span>{t('settings.totp_enrolled', { date: formatDate($user?.totp_enabled_at ?? '') })}</span>
				</div>
			{/if}

			<!-- TOTP setup -->
			{#if totpSetup.secret}
				<div class="sj-totp-setup">
					<pre class="sj-mono">{totpSetup.secret}</pre>
					<Input size="md" label="Verification code" bind:value={totpConfirmCode} mono inputmode="numeric" maxlength={6} />
					<Button variant="primary" size="sm" onclick={handleConfirmTOTP} disabled={totpLoading || totpConfirmCode.length < 6}>
						{totpLoading ? 'Verifying…' : 'Verify & enable'}
					</Button>
				</div>
			{/if}

			<!-- Action buttons -->
			<div class="sj-security-actions">
				<Button variant="secondary" size="sm" onclick={beginPasskeyEnrollment} disabled={passkeysLoading}>
					{t('settings.add_passkey')}
				</Button>
				<Button variant="secondary" size="sm" onclick={() => goto('/settings/security')}>
					{t('settings.change_password')}
				</Button>
				{#if !totpEnabled && !totpSetup.secret}
					<Button variant="secondary" size="sm" onclick={handleSetupTOTP} disabled={totpLoading}>
						Set up authenticator
					</Button>
				{:else if totpEnabled}
					<Button variant="secondary" size="sm" onclick={handleRemoveTOTP} disabled={totpLoading}>
						Disable authenticator
					</Button>
				{/if}
			</div>

			<!-- MFA de-enrollment step-up form -->
			{#if totpRemoveOpen}
				<div class="sj-totp-setup" data-testid="totp-remove-form">
					<Input size="md" label="Password" type="password" bind:value={totpRemovePassword} autocomplete="current-password" />
					<Input size="md" label="Authenticator or recovery code" bind:value={totpRemoveCode} mono inputmode="numeric" />
					<Input size="md" label="Type REMOVE to confirm" bind:value={totpRemoveConfirm} />
					<p class="sj-settings-hint">
						Lost your authenticator and have no recovery codes? Self-service removal is unavailable — contact support.
					</p>
					<div class="sj-security-actions">
						<Button variant="secondary" size="sm" onclick={() => (totpRemoveOpen = false)} disabled={totpLoading}>
							Cancel
						</Button>
						<Button
							variant="danger"
							size="sm"
							data-testid="totp-remove-confirm"
							onclick={handleConfirmRemoveTOTP}
							disabled={totpLoading || !totpRemoveReady}
						>
							{totpLoading ? 'Removing…' : 'Disable authenticator'}
						</Button>
					</div>
				</div>
			{/if}

			<!-- v7 §3.1: method-aware fresh-proof handoff for the gated passkey
			     registration / TOTP enrollment arms — C1 proves with WebAuthn-UV
			     or TOTP, password only for the C2/C3 cohorts. -->
			{#if reauthOpen && reauthOperation}
				<MfaReauthHandoff
					operation={reauthOperation}
					methods={reauthMethods}
					onproof={handleReauthProof}
					oncancel={cancelReauth}
				/>
			{/if}

			{#if totpError}
				<p class="sj-settings-error" role="alert">{totpError}</p>
			{/if}
			{#if passkeyError}
				<p class="sj-settings-error" role="alert">{passkeyError}</p>
			{/if}
		</Card>

		<!-- Offline mail storage card (T19 / #2a) — visible when caps are known or test-injected -->
		{#if offlineCaps !== undefined}
			<!-- ponytail: aria-live polite for status-badge swap (e.g. pending→approved push) -->
			<div role="status" aria-live="polite" aria-atomic="true" class="sj-settings-vh">{offlineLive}</div>
			<Card title={t('settings.offline.title')}>
				{#if !bridgePresent}
					<!-- PLAIN BROWSER: intentional capability statement — NOT an error -->
					<div class="sj-offline-card__branch">
						<p class="sj-offline-card__reason">{t(offlineReasonKey)}</p>
						<a
							href="https://setjoin.io/download"
							class="sj-offline-card__get-app"
							rel="noopener noreferrer"
							target="_blank"
						>{t('settings.offline.get_app')}</a>
					</div>
				{:else if offlineCaps.allowed && offlineCaps.approvalState === 'approved'}
					<!-- ALLOWED: badge reflects opt-in state + window caption + opt-in switch -->
					<div class="sj-offline-card__branch">
						<div class="sj-offline-card__badge-row">
							<Badge
								variant={offlineOptedIn ? 'success' : 'neutral'}
								label={offlineOptedIn ? t('settings.offline.on') : t('settings.offline.off')}
							/>
						</div>
						{#if effectiveWindow > 0 && offlineOptedIn}
							<p class="sj-offline-card__caption">
								{t('settings.offline.window_caption', { n: String(effectiveWindow) })}
							</p>
						{/if}
						<div class="sj-offline-card__controls">
							<Switch
								label={t('settings.offline.opt_in_label')}
								checked={offlineOptedIn}
								onchange={(e) => toggleOptIn(e.currentTarget.checked)}
							/>
						{#if effectiveWindow > 0 && offlineOptedIn}
							{#if !e5Active}
								<!-- Pre-E5 posture (unchanged default): editable window input.
								     E5 moves the write to /settings/storage (sole owner). -->
								<Input
									label={t('settings.offline.window_label')}
									type="number"
									min="1"
									max={String(offlineCaps.maxOfflineDays)}
									value={String(offlineWindowDays)}
									onchange={(e) => { saveWindowDays(Math.max(1, Math.min(offlineCaps!.maxOfflineDays, parseInt((e.target as HTMLInputElement).value) || 1))); }}
								/>
							{:else}
								<!-- E5 one-owner split: read-only effective summary + link;
								     /settings/storage becomes the only window writer and this
								     page no longer writes the window at all. -->
								<p class="sj-offline-card__caption" data-testid="e5-effective-window">
									{t('offline.e5.settings.window_effective', { n: String(effectiveWindow) })}
									<a class="sj-e5-settings-link" href="/settings/storage" data-testid="e5-storage-link">{t('offline.e5.settings.manage_storage')}</a>
								</p>
							{/if}
						{/if}
					</div>
					{#if e5Active && e5SettingsView}
						<!-- E5 requested-vs-effective block (R4). Pending save blocks
						     duplicate submission; failure preserves drafts with a remedy;
						     account/device changes invalidate pending responses. -->
						<div class="sj-e5-prefs" data-testid="e5-network-prefs">
							<div class="sj-e5-prefs__controls">
								<Switch
									label={t('offline.e5.settings.background_sync')}
									checked={e5SettingsView.draft.backgroundSyncEnabled}
									disabled={e5SettingsView.pending}
									onchange={(e) => e5ui.editSettings({ backgroundSyncEnabled: e.currentTarget.checked })}
								/>
								<Select
									label={t('offline.e5.settings.refresh_label')}
									options={e5NetworkOptions()}
									value={e5SettingsView.draft.automaticNetwork}
									disabled={e5SettingsView.pending}
									onchange={(e) => e5ui.editSettings({ automaticNetwork: (e.target as HTMLSelectElement).value as E5AutomaticNetworkPref })}
								/>
								<Select
									label={t('offline.e5.settings.attachment_label')}
									options={e5AttachmentOptions()}
									value={e5SettingsView.draft.attachmentPrefetch}
									disabled={e5SettingsView.pending}
									onchange={(e) => e5ui.editSettings({ attachmentPrefetch: (e.target as HTMLSelectElement).value as E5AttachmentPrefetchPref })}
								/>
							</div>
							{#if e5SettingsView.acknowledged}
								<dl class="sj-e5-prefs__effective" data-testid="e5-effective-prefs">
									<dt>{t('offline.e5.settings.effective_refresh')}</dt>
									<dd>{t(`offline.e5.settings.net.${e5SettingsView.acknowledged.effective.automaticNetwork}`)}</dd>
									<dt>{t('offline.e5.settings.effective_attachments')}</dt>
									<dd>{t(`offline.e5.settings.att.${e5SettingsView.acknowledged.effective.attachmentPrefetch}`)}</dd>
									<dt>{t('offline.e5.settings.effective_background')}</dt>
									<dd>{e5SettingsView.acknowledged.effective.backgroundAllowed ? t('offline.e5.admin.on') : t('offline.e5.admin.off')}</dd>
								</dl>
							{/if}
							{#if e5Explanation}
								<ul class="sj-e5-prefs__explanation" data-testid="e5-crossed-explanation">
									{#if e5Explanation.backgroundKey}<li>{t(e5Explanation.backgroundKey)}</li>{/if}
									<li>{t(e5Explanation.refreshKey)}</li>
									<li>{t(e5Explanation.attachmentKey)}</li>
									{#if e5Explanation.linkKey}<li>{t(e5Explanation.linkKey)}</li>{/if}
								</ul>
							{/if}
							<div class="sj-e5-prefs__actions">
								<Button
									variant="secondary"
									size="sm"
									data-testid="e5-save-prefs"
									disabled={e5SettingsView.pending || !e5SaveConfigured || !e5SettingsView.dirty}
									onclick={e5SavePrefs}
								>
									{e5SettingsView.pending ? t('offline.e5.settings.pending') : t('offline.e5.settings.save')}
								</Button>
								{#if !e5SaveConfigured}
									<span class="sj-e5-prefs__reason">{t('offline.e5.settings.save_unavailable')}</span>
								{/if}
							</div>
							{#if e5SettingsView.status.kind === 'failed'}
								<p role="alert" class="sj-e5-prefs__remedy" data-testid="e5-save-remedy">
									{t('offline.e5.settings.save_failed')}
									{e5SettingsView.status.remedyKey ? t(e5SettingsView.status.remedyKey) : ''}
								</p>
							{/if}
							<!-- Single-announcer contract (design Pass 5): this page's ONE
							     polite live region is the sr-only role=status region above
							     (offlineLive). The E5 block adds NO competing region — save
							     outcomes ride the same owner. -->
						</div>
					{/if}
						<!-- BZ100/409 inline error — revert already done in toggleOptIn -->
						{#if optInError}
							<p role="alert" class="sj-offline-card__opt-in-error">{optInError}</p>
						{/if}
						{#if recoveryAvailable}
							<div class="sj-recovery-setting">
								<div>
									<p class="sj-recovery-setting__title">{t('settings.recovery.title')}</p>
									<p class="sj-offline-card__helper">{t('settings.recovery.description')}</p>
								</div>
								<Switch
									label={t('settings.recovery.opt_in')}
									checked={recoveryEnabled}
									disabled={recoveryBusy}
									onchange={(event) => toggleRecovery(event.currentTarget.checked)}
								/>
								{#if recoveryEnabled}
									<p class="sj-offline-card__caption">
										{t('settings.recovery.coverage', {
											count: String(recoveryStats.count),
											bytes: formatBytes(recoveryStats.bytes),
										})}
									</p>
									{#each recoveryOffers as incident (incident.id)}
										<div class="sj-recovery-incident">
											<p><strong>{t('settings.recovery.incident')}</strong> {incident.reason}</p>
											<p class="sj-offline-card__helper">{t('settings.recovery.incident_expiry', { date: new Date(incident.expiresAt).toLocaleString() })}</p>
											{#each recoveryCandidates[incident.id] ?? [] as artifact (artifact.artifactIdentity)}
												<div class="sj-recovery-offer-row">
													<span>{t('settings.recovery.message_copy', { id: artifact.messageId, bytes: formatBytes(artifact.bytes) })}</span>
													{#if recoveryOfferStatus[artifact.artifactIdentity]}
														<Badge variant="success" label={recoveryOfferStatus[artifact.artifactIdentity]} />
													{:else}
														{#if recoveryUploading === artifact.artifactIdentity}
															<Button size="sm" variant="danger" onclick={() => cancelRecoveryOffer(artifact.artifactIdentity)}>{t('settings.recovery.cancel')}</Button>
														{:else}
															<Button size="sm" variant="secondary" disabled={!!recoveryUploading} onclick={() => offerRecoveryCopy(incident, artifact)}>{t('settings.recovery.offer')}</Button>
														{/if}
													{/if}
												</div>
											{/each}
										</div>
									{/each}
								{/if}
								{#if recoveryError}<p role="alert" class="sj-offline-card__opt-in-error">{recoveryError}</p>{/if}
							</div>
						{/if}
					</div>
				{:else if offlineCaps.approvalState === 'pending'}
					<!-- PENDING: hopeful, actionable — NOT an error -->
					<div class="sj-offline-card__branch">
						<div class="sj-offline-card__badge-row">
							<Badge variant="info" label={t('settings.offline.awaiting')} />
						</div>
						<p class="sj-offline-card__reason">{t(offlineReasonKey)}</p>
						<Button
							variant="primary"
							size="sm"
							aria-label={t('settings.offline.request_approval')}
							disabled={optInBusy}
							onclick={requestApproval}
						>{t('settings.offline.request_approval')}</Button>
					</div>
				{:else if offlineCaps.approvalState === 'denied'}
					<!-- DENIED: matter-of-fact, neutral — NOT alarming -->
					<div class="sj-offline-card__branch">
						<div class="sj-offline-card__badge-row">
							<Badge variant="neutral" label={t('settings.offline.not_available')} />
						</div>
						<p class="sj-offline-card__reason">{t(offlineReasonKey)}</p>
						<p class="sj-offline-card__helper">{t('settings.offline.ask_admin')}</p>
					</div>
				{:else if offlineCaps.approvalState === 'revoked'}
					<!-- REVOKED: reassure-don't-alarm -->
					<div class="sj-offline-card__branch">
						<div class="sj-offline-card__badge-row">
							<Badge variant="neutral" label={t('settings.offline.not_available')} />
						</div>
						<p class="sj-offline-card__reason">{t(offlineReasonKey)}</p>
						<p class="sj-offline-card__helper">{t('settings.offline.safe_online')}</p>
					</div>
				{:else}
					<!-- OFF BY POLICY / org master off -->
					<div class="sj-offline-card__branch">
						<div class="sj-offline-card__badge-row">
							<Badge variant="neutral" label={t('settings.offline.not_available')} />
						</div>
						<p class="sj-offline-card__reason">{t(offlineReasonKey)}</p>
					</div>
				{/if}
			</Card>
		{/if}

		<!-- Advanced sections (migrated from old settings — kept as collapsible) -->
		<details class="sj-settings-advanced">
			<summary>Advanced settings</summary>
			<p class="sj-settings-hint">App passwords, webhooks, IMAP visibility, and smart mute settings are now in their own pages. Visit <a href="/settings/security">Security</a> for app passwords and webhooks.</p>
		</details>
	</div>
</div>

<Toast />

<style>
	/* ── Page shell ── */
	.sj-settings-page {
		height: 100%;
		overflow-y: auto;
		background: var(--surface-page);
	}

	.sj-recovery-setting {
		margin-top: var(--space-4);
		padding-top: var(--space-4);
		border-top: 1px solid var(--border-subtle);
		display: grid;
		gap: var(--space-3);
	}

	.sj-recovery-setting__title {
		margin: 0 0 var(--space-1);
		font-weight: var(--font-weight-semibold);
	}

	.sj-recovery-incident {
		padding: var(--space-3);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		display: grid;
		gap: var(--space-2);
	}

	.sj-recovery-incident p { margin: 0; }

	.sj-recovery-offer-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		flex-wrap: wrap;
	}

	.sj-settings-inner {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	/* ── Typography ── */
	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}

	.sj-settings-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 4px 0 0;
	}

	.sj-settings-hint {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		margin: 8px 0;
	}

	.sj-settings-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 8px 0 0;
	}

	/* ── Form layout ── */
	.sj-form-row {
		display: flex;
		align-items: center;
		gap: 16px;
		flex-wrap: wrap;
	}

	.sj-form-grid {
		container-type: inline-size;
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		flex: 1;
	}

	.sj-span-all {
		grid-column: 1 / -1;
	}

	/* ── Security rows ── */
	.sj-security-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.sj-security-actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
		margin-top: 8px;
	}

	.sj-totp-setup {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 8px 0;
	}

	.sj-mono {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		background: var(--surface-sunken);
		padding: 8px;
		border-radius: var(--radius-sm);
		user-select: all;
	}

	/* ── Advanced section ── */
	.sj-settings-advanced {
		margin-top: 8px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.sj-settings-advanced summary {
		cursor: pointer;
		font-weight: 500;
		padding: 4px 0;
	}

	/* ── Responsive (container-query driven so it collapses in narrow
	   split-view/sidebar layouts, not just at viewport width) ── */
	@container (max-width: 460px) {
		.sj-form-grid {
			grid-template-columns: 1fr;
		}
	}

	/* ── Offline card (#2a T19) ── */
	.sj-settings-vh {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}
	.sj-offline-card__branch {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 2px 0;
	}
	.sj-offline-card__badge-row {
		display: flex;
		align-items: center;
		gap: 8px;
		/* cross-fade on state change — reduced-motion: instant */
		transition: opacity var(--duration-fast) var(--ease-out);
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-offline-card__badge-row { transition: none; }
	}
	.sj-offline-card__caption {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-family: var(--font-sans);
	}
	.sj-offline-card__reason {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-family: var(--font-sans);
	}
	.sj-offline-card__helper {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-sans);
	}
	.sj-offline-card__opt-in-error {
		margin: 6px 0 0;
		padding: 6px 10px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		font-family: var(--font-sans);
	}
	.sj-offline-card__controls {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}
	/* ── E5 requested-vs-effective prefs (token-only, both themes) ── */
	.sj-e5-settings-link {
		margin-left: var(--space-2);
		color: var(--accent);
	}
	.sj-e5-prefs {
		margin-top: var(--space-3);
		padding-top: var(--space-3);
		border-top: 1px solid var(--border-subtle);
		display: grid;
		gap: var(--space-3);
	}
	.sj-e5-prefs__controls {
		display: grid;
		gap: var(--space-3);
	}
	.sj-e5-prefs__effective {
		margin: 0;
		display: grid;
		grid-template-columns: minmax(10rem, max-content) 1fr;
		gap: var(--space-1) var(--space-3);
		font-size: var(--text-sm);
	}
	.sj-e5-prefs__effective dt { color: var(--text-secondary); }
	.sj-e5-prefs__effective dd { margin: 0; color: var(--text-primary); }
	/* Must-read policy/pause text: the AA-safe caption channel (see
	   theme/colors.css — --text-tertiary is below AA for body text) at a
	   readable size. This list is the actual-admission explanation. */
	.sj-e5-prefs__explanation {
		margin: 0;
		padding-left: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-e5-prefs__actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.sj-e5-prefs__reason {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.sj-e5-prefs__remedy {
		margin: 0;
		padding: var(--space-2) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.sj-offline-card__get-app {
		font-size: var(--text-sm);
		color: var(--accent-fg-on-subtle);
		font-family: var(--font-sans);
		text-decoration: underline;
	}
</style>
