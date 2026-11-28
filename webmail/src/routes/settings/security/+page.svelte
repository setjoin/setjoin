<svelte:options runes={true} />

<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { logger } from '$lib/logger';
	import { httpRequest } from '$lib/http';
	import { setupTOTP, confirmTOTP, beginTOTPRemoval, removeTOTP, generateBackupCodes, ReauthRequiredError, fetchPasskeyCredentials, user, authIdentity, authGeneration, type MFAReauthOperation } from '$lib/stores/auth';
	import MfaReauthHandoff, { type ReauthProofMethod } from '$lib/components/MfaReauthHandoff.svelte';
	import { Card, Tabs, type TabItem, Button, Input, Badge, Progress, Dialog, showToast, Toast, EmptyState } from '$lib/components/ui';
	import CertStatusCard, { type CertStatus } from '$lib/components/CertStatusCard.svelte';
	import { createSettingsResource } from '$lib/composables/settings-resource.svelte';
	import { authedBootstrap } from '$lib/composables/authed-bootstrap.svelte';

	// ── Existing interfaces ──

	interface Device {
		device_fingerprint: string;
		device_name: string;
		platform: string;
		last_seen: string;
		trust_tier: string;
		has_active_session: boolean;
		is_current_device: boolean;
	}

	interface SecurityCheck {
		name: string;
		pass: boolean;
		points: number;
		action?: string;
	}

	interface SecurityScore {
		score: number;
		checks: SecurityCheck[];
	}

	interface SmimeCert {
		id: string;
		label: string;
		isDefault: boolean;
		issuedAt: string;
		expiresAt: string;
	}

	// ── New interfaces for sign-in activity (Task 12) ──

	interface SignIn {
		id: number | string;
		success: boolean;
		current?: boolean;
		cluster?: boolean;
		newGeo?: boolean;
		device?: string;
		location?: string;
		occurred_at?: string;
		client?: string;
		authMethod?: string;
	}

	interface Session {
		id: string;
		current?: boolean;
		device?: string;
		location?: string;
		last_used_at?: string;
	}

	interface FailedDistinct {
		count: number;
		locations: number;
		since: string;
	}

	// ── Props (injectable for test isolation) ──
	// ponytail: prop injection pattern — real flow uses onMount; tests inject data directly.
	interface Props {
		initialSignIns?: SignIn[];
		signInsLoading?: boolean;
		signInsError?: boolean;
		signInsTotal?: number;
		failedDistinct?: FailedDistinct;
		initialSessions?: Session[];
		secureOpen?: boolean;
		secureListError?: boolean;
		initialTab?: string;
		initialLoading?: boolean;
	}

	let {
		initialSignIns,
		signInsLoading: initSignInsLoading = false,
		signInsError: initSignInsError = false,
		signInsTotal: initSignInsTotal,
		failedDistinct: initFailedDistinct,
		initialSessions,
		secureOpen: initSecureOpen = false,
		secureListError: initSecureListError = false,
		initialTab,
		initialLoading = true,
	}: Props = $props();

	// ── Legacy state ──

	let devices: Device[] = $state([]);
	let score: SecurityScore | null = $state(null);
	// untrack() captures initial prop value without reactive dependency
	let loading = $state(untrack(() => initialLoading));
	let error = $state('');
	let activeTab = $state(untrack(() => initialTab ?? 'devices'));

	// ── Route resources (WP5 completion): every load and action on this page
	// runs through the shared settings-resource composable or the $lib/http
	// seam (timeout/abort/401 handling, typed/display-safe errors) — no
	// hand-rolled fetch + res.ok chain remains. The possession/MFA arms keep
	// their stores/auth seam; the two FormData uploads call httpRequest
	// directly (the composable's save encodes JSON bodies) and secure-account
	// accepts its terminal 401 via the seam's allowStatuses.
	interface DevicesResponse {
		devices?: Device[];
	}
	interface MeResponse {
		totp_enabled?: boolean;
	}
	interface SessionsResponse {
		sessions?: Session[];
	}
	// snake_case wire shape of /api/user/login-history; mapped at the boundary.
	interface SignInApiEvent {
		id: number | string;
		success: boolean;
		current?: boolean;
		cluster?: boolean;
		new_geo?: boolean;
		device_name?: string;
		location?: string;
		occurred_at?: string;
		client?: string;
		auth_method?: string;
	}
	interface SignInsResponse {
		items?: SignInApiEvent[];
		total?: number;
		failed_distinct?: FailedDistinct | null;
	}
	interface SmimeCertsResponse {
		certs?: SmimeCert[];
	}
	interface ContactCertsResponse {
		certs?: ContactCert[];
	}
	// onLoadError preserves the pre-migration display text ("HTTP <status>")
	// for the two loaders whose message is rendered inline.
	const onLoadError = (res: Response): string => `HTTP ${res.status}`;
	const devicesRes = createSettingsResource<DevicesResponse>({
		load: { url: '/api/user/devices', method: 'GET' },
	});
	const scoreRes = createSettingsResource<SecurityScore | null>({
		load: { url: '/api/user/security-score', method: 'GET' },
	});
	const meRes = createSettingsResource<MeResponse>({
		load: { url: '/auth/me', method: 'GET' },
	});
	const signinsRes = createSettingsResource<SignInsResponse>({
		load: { url: '/api/user/login-history', method: 'GET' },
	});
	// Separate instances: the sessions list and the secure-dialog list are
	// independent surfaces (supersede in one must not cancel the other).
	const sessionsRes = createSettingsResource<SessionsResponse>({
		load: { url: '/api/user/sessions', method: 'GET' },
	});
	const secureListRes = createSettingsResource<SessionsResponse>({
		load: { url: '/api/user/sessions', method: 'GET' },
	});
	const smimeRes = createSettingsResource<SmimeCertsResponse>({
		load: { url: '/auth/me/smime/certs', method: 'GET', onError: onLoadError },
	});
	const contactCertsRes = createSettingsResource<ContactCertsResponse>({
		load: { url: '/auth/me/smime/recipient-certs', method: 'GET', onError: onLoadError },
	});
	const certRes = createSettingsResource<CertStatus>({
		load: { url: '/api/user/cert-status', method: 'GET' },
	});

	const tabs: TabItem[] = [
		{ id: 'devices', label: 'Login devices' },
		{ id: 'history', label: 'Login history' },
		{ id: 'totp', label: 'Authenticator' },
	];

	let totpEnabled = $state(false);
	let totpSetup = $state<{ secret: string; provisioningUri: string; enrollmentId?: string }>({ secret: '', provisioningUri: '' });
	let totpConfirmCode = $state('');
	let totpLoading = $state(false);
	let totpError = $state('');

	// ── Possession scheme v7 §3.1 method-aware re-auth handoff ──
	// Gated arms answer 403 reauth_required; the handoff mints the proof that
	// retries them. The offered methods are the account's ENROLLED proof
	// methods: a C1 account (totp enabled or an enrolled UV-capable passkey)
	// proves with WebAuthn-UV or a current TOTP code — the §3 possession
	// endpoints; the password challenge appears only for the C2/C3 password
	// step-up cohorts. The server stays the cohort authority: a mis-offered
	// proof is refused by the 403 contract and surfaces inline.
	type PendingReauthAction = { kind: 'setup' | 'confirm'; operation: 'totp.enroll' | 'totp.replace' } | { kind: 'recovery'; operation: 'recovery.regenerate' };
	let reauthOpen = $state(false);
	let pendingReauth = $state<PendingReauthAction | null>(null);
	let heldReauthToken = $state('');

	// UV-capable passkey presence (best-effort /auth/webauthn/credentials read):
	// the WebAuthn-UV method is offered only when a listed credential reports
	// uv_capable — the member is optional on the wire, so a pre-possession
	// gateway simply never offers it (fail-closed; §1.2 classifies cohort).
	let uvPasskeyEnrolled = $state(false);

	// Auth-generation fencing (§3.1, r4 #10): pending ceremony/grant state and
	// returned secrets drop whenever the SESSION lifecycle moves — a new
	// session, a /auth/refresh rotation, an admission recovery that discovered
	// the shared cookie's token rotated under this page (bumped via the same
	// auth-generation retire path), impersonation, logout, reset — or checkAuth
	// observes a changed account identity. Identity-only fencing missed the
	// same-account case on this page: a refresh kept a held grant (dead —
	// grants bind the access JTI) and returned secrets alive across the
	// session boundary. Stale in-flight responses are refused before assigning
	// secrets/tokens. UX fence only — the server's tuple binding is the
	// enforcement.
	const accountIdentity = $derived($user ? authIdentity($user) : null);
	let mfaGeneration = 0;
	$effect(() => {
		void accountIdentity;
		void $authGeneration;
		mfaGeneration += 1;
		heldReauthToken = '';
		reauthOpen = false;
		pendingReauth = null;
		totpSetup = { secret: '', provisioningUri: '' };
		totpConfirmCode = '';
		recoveryCodes = [];
		return () => {
			mfaGeneration += 1; // re-run/unmount retires in-flight responses
		};
	});

	// Possession first, password fallback only for the C2/C3 cohorts:
	// webauthn_uv (UV passkey enrolled) and totp (enabled authenticator) are
	// the C1 methods; with neither enrolled the account lands in C2/C3 and
	// proves with its password.
	const reauthMethods = $derived.by(() => {
		const methods: ReauthProofMethod[] = [];
		if (uvPasskeyEnrolled) methods.push('webauthn_uv');
		if (totpEnabled) methods.push('totp');
		if (methods.length === 0) methods.push('password');
		return methods;
	});

	// ── Recovery codes (regeneration is gated for EVERY account) ──
	let recoveryCodes: string[] = $state([]);
	let recoveryBusy = $state(false);
	let recoveryError = $state('');

	function openReauth(kind: PendingReauthAction) {
		pendingReauth = kind;
		// Any held proof is stale the moment the handoff opens: a fresh
		// re-authentication will mint a new single-use token.
		heldReauthToken = '';
		reauthOpen = true;
	}

	function cancelReauth() {
		reauthOpen = false;
		pendingReauth = null;
		heldReauthToken = '';
	}

	async function runSetup(reauthToken?: string) {
		// Returns the pending secret; the caller assigns it ONLY after its
		// generation check, so a late response never lands (§3.1 fencing).
		return setupTOTP(reauthToken);
	}

	async function runConfirm(reauthToken?: string) {
		// v7 §1.6: confirm references the setup-issued enrollment binding.
		await confirmTOTP(totpConfirmCode, { reauthToken, enrollmentId: totpSetup.enrollmentId });
	}

	async function runRegenerate(reauthToken?: string) {
		// Returns the codes; assigned by the caller after its generation check.
		return generateBackupCodes(reauthToken);
	}

	// The handoff delivered a freshly minted proof: hold it, close the form,
	// and retry the gated action through the same handlers, so their state
	// transitions and error arms stay authoritative (a stale-proof loop
	// reopens the handoff honestly — §4.3 retry-after-proof discipline).
	async function handleReauthProof(proof: { method: ReauthProofMethod; token: string }) {
		const gen = mfaGeneration;
		if (!pendingReauth) return;
		heldReauthToken = proof.token;
		reauthOpen = false;
		const action = pendingReauth;
		pendingReauth = null;
		if (gen !== mfaGeneration) return; // identity changed while proving
		if (action.kind === 'setup') {
			await handleSetupTOTP();
		} else if (action.kind === 'confirm') {
			// v7 §1.6 (r3 defect 8): the fresh proof's grant is UNBOUND — no
			// target_ref — so re-presenting the OLD enrollment id can never
			// satisfy the (grant, enrollment) tuple and would loop the handoff
			// forever. Restart SETUP with the fresh proof instead: the arm
			// stages a NEW pending secret and binds the grant to ITS enrollment
			// id; the user then confirms against the new binding with a fresh
			// code.
			totpConfirmCode = '';
			await handleSetupTOTP();
		} else {
			await handleRegenerateRecovery();
		}
	}

	// MFA de-enrollment step-up form: password + code (TOTP or recovery) and a
	// typed confirmation before the server will remove the factor.
	let totpRemoveOpen = $state(false);
	let totpRemovePassword = $state('');
	let totpRemoveCode = $state('');
	let totpRemoveConfirm = $state('');
	const totpRemoveReady = $derived(
		totpRemovePassword.length > 0 && totpRemoveCode.trim().length > 0 && totpRemoveConfirm === 'REMOVE'
	);

	let smimeCerts: SmimeCert[] = $state([]);
	let smimeLoading = $state(true);
	let smimeError = $state('');
	let smimeUploading = $state(false);
	let smimeUploadError = $state('');
	let smimeLabel = $state('');
	let smimeCertFile = $state<File | null>(null);
	let smimeKeyFile = $state<File | null>(null);
	let pendingDelete = $state<SmimeCert | null>(null);

	// ── Client cert status (Task E — mTLS cert shown as read-only security card) ──
	let certStatus = $state<CertStatus | undefined>(undefined);
	let certLoading = $state(false);
	let certError = $state(false);

	// ── Task 12 state ──

	// Sign-ins — mutable; seeded from props for test injection, updated by loadSignIns in real use.
	// ponytail: $derived for prop-seed; separate $state for mutations avoids Svelte 5 prop-capture warnings.
	let _signIns: SignIn[] = $state([]);
	let _signInsLoading = $state(false);
	let _signInsError = $state(false);
	let _total = $state(0);
	let _failedDistinct = $state<FailedDistinct | null>(null);
	let failedOnly = $state(false);

	// Derived from props OR live fetch result (props win when provided — test isolation)
	const signIns = $derived(initialSignIns !== undefined ? initialSignIns : _signIns);
	const signInsLoading = $derived(initialSignIns === undefined && !initSignInsError ? (initSignInsLoading || _signInsLoading) : false);
	const signInsError = $derived(initSignInsError || _signInsError);
	const total = $derived(initSignInsTotal !== undefined ? initSignInsTotal : (_total || signIns.length));
	const failedDistinct = $derived(initFailedDistinct !== undefined ? initFailedDistinct : _failedDistinct);

	// Sessions
	let _sessions: Session[] = $state([]);
	const sessions = $derived(initialSessions !== undefined ? initialSessions : _sessions);

	// Dialogs
	let showRevoke = $state(false);
	let revokeTarget = $state<Session | null>(null);
	let showRevokeAll = $state(false);
	let showSecure = $state(false);
	let secureToken = $state('');
	let secureCommitting = $state(false);
	let secureError = $state(false);
	let secureListLoading = $state(false);
	let _secureListError = $state(false);
	const secureListError = $derived(initSecureListError || _secureListError);
	let revocableSessions: Session[] = $state([]);

	// Open secure dialog immediately if prop says so (test injection)
	$effect(() => {
		if (initSecureOpen) showSecure = true;
	});

	// Aria-live region
	let liveMessage = $state('');

	function fmtTime(ts?: string): string {
		if (!ts) return '';
		try { return new Date(ts).toLocaleString(); } catch { return ts; }
	}

	// Contacts' certificates state (SP1 Phase 6)
	interface ContactCert {
		id: number;
		email: string;
		label: string;
		source: 'harvested' | 'imported';
		notBefore: string;
		notAfter: string;
		fingerprint: string;
		isEncryptCapable: boolean;
	}

	let contactCerts: ContactCert[] = $state([]);
	let contactCertsLoading = $state(true);
	let contactCertsError = $state('');
	let contactCertImporting = $state(false);
	let contactCertImportError = $state('');
	let contactCertLabel = $state('');
	let contactCertFile = $state<File | null>(null);
	let pendingDeleteContact = $state<ContactCert | null>(null);

	function isExpiredContact(c: ContactCert): boolean {
		return new Date(c.notAfter) < new Date();
	}

	function isExpiringSoonContact(c: ContactCert): boolean {
		const d = new Date(c.notAfter);
		const now = new Date();
		return d > now && d.getTime() - now.getTime() < 30 * 86400 * 1000;
	}

	async function loadContactCerts(signal?: AbortSignal) {
		contactCertsLoading = true;
		contactCertsError = '';
		const data = await contactCertsRes.load({ signal });
		if (data) {
			contactCerts = data.certs ?? [];
		} else if (contactCertsRes.error) {
			contactCertsError = contactCertsRes.error;
			logger.error('contacts-certs: load failed', contactCertsRes.error);
		}
		contactCertsLoading = false;
	}

	async function handleImportContactCert() {
		if (!contactCertFile) return;
		contactCertImporting = true;
		contactCertImportError = '';
		try {
			const form = new FormData();
			form.append('cert', contactCertFile);
			if (contactCertLabel.trim()) form.append('label', contactCertLabel.trim());
			await httpRequest('/auth/me/smime/recipient-certs', {
				method: 'POST',
				body: form,
				onError: async (res) => {
					let msg = t('settings.contacts_certs.import_error');
					try {
						const b = await res.json();
						if (b?.error) msg = b.error;
					} catch { /* ignore */ }
					return msg;
				},
			});
			contactCertLabel = '';
			contactCertFile = null;
			await loadContactCerts();
			showToast(t('settings.contacts_certs.import_btn'));
		} catch (e) {
			contactCertImportError = parseError(e).message || t('settings.contacts_certs.import_error');
		}
		contactCertImporting = false;
	}

	async function confirmDeleteContactCert() {
		const c = pendingDeleteContact;
		if (!c) return;
		pendingDeleteContact = null;
		const result = await contactCertsRes.save({
			url: `/auth/me/smime/recipient-certs/${c.id}`, method: 'DELETE',
		});
		if (result.ok) {
			await loadContactCerts();
			showToast(t('settings.contacts_certs.delete'));
		} else {
			logger.error('contacts-certs: delete failed', contactCertsRes.saveError);
		}
	}

	function isExpired(expiresAt: string): boolean {
		return new Date(expiresAt) < new Date();
	}

	// ── Task 12 async actions ──

	// append=true keeps the existing rows and fetches the next page at offset=count
	// (the /user/login-history endpoint pages on limit+offset); false re-fetches page 0.
	async function loadSignIns(append = false, signal?: AbortSignal) {
		_signInsLoading = true;
		_signInsError = false;
		const offset = append ? _signIns.length : 0;
		const params = new URLSearchParams({ limit: '200', offset: String(offset) });
		if (failedOnly) params.set('outcome', 'failed');
		const data = await signinsRes.load({ url: `/api/user/login-history?${params}`, signal });
		if (data) {
			// Map snake_case API fields to camelCase SignIn interface at the boundary.
			const mapped = (data.items ?? []).map((e: SignInApiEvent) => ({
				id: e.id,
				success: e.success,
				current: e.current,
				cluster: e.cluster,
				newGeo: e.new_geo,
				device: e.device_name,
				location: e.location,
				occurred_at: e.occurred_at,
				client: e.client,
				authMethod: e.auth_method,
			}));
			_signIns = append ? [..._signIns, ...mapped] : mapped;
			_total = data.total ?? _signIns.length;
			_failedDistinct = data.failed_distinct ?? null;
		} else {
			_signInsError = true;
			logger.error('security: failed to load sign-ins', signinsRes.error);
		}
		_signInsLoading = false;
	}

	async function loadSessions() {
		const data = await sessionsRes.load();
		if (data) _sessions = data.sessions ?? [];
		else if (sessionsRes.error) logger.error('security: failed to load sessions', sessionsRes.error);
	}

	async function loadMore() {
		await loadSignIns(true);
	}

	async function reload() {
		await loadSignIns(false);
	}

	function confirmRevoke(s: Session) {
		revokeTarget = s;
		showRevoke = true;
	}

	async function doRevoke() {
		if (!revokeTarget) return;
		const target = revokeTarget;
		showRevoke = false;
		revokeTarget = null;
		const result = await sessionsRes.save({
			url: `/api/user/sessions/${target.id}`, method: 'DELETE',
		});
		if (result.ok) {
			if (target.current) { goto('/login'); return; }
			liveMessage = t('security.sessions.revokedAnnounce', { device: target.device ?? '' });
			showToast(t('security.sessions.revokedToast', { device: target.device ?? '' }));
			await loadSessions();
		} else {
			logger.error('security: failed to revoke session', sessionsRes.saveError);
			showToast(t('security.sessions.revokeError'));
		}
	}

	async function doRevokeAll() {
		showRevokeAll = false;
		const result = await sessionsRes.save({
			url: '/api/user/sessions/revoke-all', method: 'POST',
		});
		if (result.ok) {
			liveMessage = t('security.sessions.revokedAllAnnounce');
			goto('/login');
		} else {
			logger.error('security: failed to revoke all sessions', sessionsRes.saveError);
			showToast(t('security.sessions.revokeAllError'));
		}
	}

	async function openSecureDialog() {
		showSecure = true;
		secureToken = '';
		secureError = false;
		if (!initSecureListError) {
			secureListLoading = true;
			const data = await secureListRes.load();
			if (data) revocableSessions = (data.sessions ?? []).filter((s: Session) => !s.current);
			else _secureListError = true;
			secureListLoading = false;
		}
	}

	async function secureAccount() {
		if (secureToken !== 'SECURE' || secureListError) return;
		secureCommitting = true;
		try {
			// Securing the account may kill the caller's own session, so a 401 is
			// this workflow's TERMINAL SUCCESS response — return it as-is through
			// the seam instead of triggering its login-redirect/throw arm.
			await httpRequest('/api/user/sign-ins/secure-account', { method: 'POST', allowStatuses: [401] });
			liveMessage = t('security.secured_announce');
			showToast(t('security.secured_toast'));
			goto('/?secured=1');
		} catch {
			secureError = true;
		} finally {
			secureCommitting = false;
		}
	}

	// ── Legacy async ──

	async function loadCertStatus(signal?: AbortSignal) {
		certLoading = true;
		certError = false;
		const data = await certRes.load({ signal });
		if (certRes.error) certError = true;
		else certStatus = data ?? undefined;
		certLoading = false;
	}

	async function loadSmimeCerts(signal?: AbortSignal) {
		smimeLoading = true;
		smimeError = '';
		const data = await smimeRes.load({ signal });
		if (data) {
			smimeCerts = data.certs ?? [];
		} else if (smimeRes.error) {
			smimeError = smimeRes.error;
			logger.error('settings/security: failed to load S/MIME certs', smimeRes.error);
		}
		smimeLoading = false;
	}

	async function handleSmimeUpload() {
		if (!smimeCertFile || !smimeKeyFile || !smimeLabel.trim()) return;
		smimeUploading = true;
		smimeUploadError = '';
		try {
			const form = new FormData();
			form.append('label', smimeLabel.trim());
			form.append('cert', smimeCertFile);
			form.append('key', smimeKeyFile);
			await httpRequest('/auth/me/smime/certs', {
				method: 'POST',
				body: form,
				onError: async (res) => {
					let msg = t('settings.smime.upload_error');
					try {
						const body = await res.json();
						if (body?.detail) msg = body.detail;
					} catch { /* ignore */ }
					return msg;
				},
			});
			smimeLabel = '';
			smimeCertFile = null;
			smimeKeyFile = null;
			await loadSmimeCerts();
			showToast(t('settings.smime.upload_btn') + ' — ' + t('settings.smime.title'));
		} catch (e) {
			smimeUploadError = parseError(e).message || t('settings.smime.upload_error');
		}
		smimeUploading = false;
	}

	async function handleSetDefault(cert: SmimeCert) {
		const result = await smimeRes.save({
			url: `/auth/me/smime/certs/${cert.id}/default`, method: 'POST',
		});
		if (result.ok) {
			await loadSmimeCerts();
			showToast(t('settings.smime.set_default'));
		} else {
			logger.error('settings/security: failed to set default S/MIME cert', smimeRes.saveError);
		}
	}

	function requestDeleteCert(cert: SmimeCert) {
		pendingDelete = cert;
	}

	async function confirmDeleteCert() {
		const cert = pendingDelete;
		if (!cert) return;
		pendingDelete = null;
		const result = await smimeRes.save({
			url: `/auth/me/smime/certs/${cert.id}`, method: 'DELETE',
		});
		if (result.ok) {
			await loadSmimeCerts();
			showToast(t('settings.smime.delete'));
		} else {
			logger.error('settings/security: failed to delete S/MIME cert', smimeRes.saveError);
		}
	}

	async function handleSetupTOTP() {
		// Generation fencing: a response landing after an account identity
		// change (or unmount) must not assign the pending secret (§3.1).
		const gen = mfaGeneration;
		totpLoading = true;
		totpError = '';
		try {
			const details = await runSetup(heldReauthToken || undefined);
			if (gen !== mfaGeneration) return;
			totpSetup = details;
		} catch (e) {
			if (gen !== mfaGeneration) return;
			if (e instanceof ReauthRequiredError) {
				// A fresh proof is required before the server will mint the
				// pending secret: totp.replace over an enabled authenticator,
				// totp.enroll for the first one (§1.3).
				totpLoading = false;
				openReauth({ kind: 'setup', operation: totpEnabled ? 'totp.replace' : 'totp.enroll' });
				return;
			}
			totpError = 'Failed to set up TOTP. Please try again.';
		} finally {
			totpLoading = false;
		}
	}

	async function handleConfirmTOTP() {
		const gen = mfaGeneration;
		totpLoading = true;
		totpError = '';
		try {
			await runConfirm(heldReauthToken || undefined);
			if (gen !== mfaGeneration) return;
			totpEnabled = true;
			totpSetup = { secret: '', provisioningUri: '' };
			totpConfirmCode = '';
			heldReauthToken = '';
			showToast('Authenticator enabled');
		} catch (e) {
			if (gen !== mfaGeneration) return;
			if (e instanceof ReauthRequiredError) {
				// The re-auth proof is missing, stale, or was already consumed:
				// surface the challenge handoff instead of a bare failure. The
				// delivered proof RESTARTS SETUP (v7 §1.6, r3 defect 8) — the
				// fresh grant is unbound, so the stale (grant, enrollment)
				// pairing can never confirm.
				totpLoading = false;
				openReauth({ kind: 'confirm', operation: totpEnabled ? 'totp.replace' : 'totp.enroll' });
				return;
			}
			totpError = 'Invalid code. Please try again.';
		} finally {
			totpLoading = false;
		}
	}

	async function handleRegenerateRecovery() {
		const gen = mfaGeneration;
		recoveryBusy = true;
		recoveryError = '';
		try {
			const codes = await runRegenerate(heldReauthToken || undefined);
			if (gen !== mfaGeneration) return;
			recoveryCodes = codes;
			heldReauthToken = '';
			showToast(t('security.recovery.generated'));
		} catch (e) {
			if (gen !== mfaGeneration) return;
			if (e instanceof ReauthRequiredError) {
				// Regeneration replaces every recovery code, so it is gated for
				// every account: offer the challenge handoff.
				recoveryBusy = false;
				openReauth({ kind: 'recovery', operation: 'recovery.regenerate' });
				return;
			}
			recoveryError = parseError(e).message || t('security.recovery.error');
		} finally {
			recoveryBusy = false;
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

	// Resource teardown for the composable-backed reads (the bootstrap below
	// cannot return a cleanup — Svelte requires a synchronous callback).
	onMount(() => {
		return () => {
			devicesRes.cleanup();
			scoreRes.cleanup();
			meRes.cleanup();
			signinsRes.cleanup();
			sessionsRes.cleanup();
			secureListRes.cleanup();
			smimeRes.cleanup();
			contactCertsRes.cleanup();
			certRes.cleanup();
		};
	});

	// WP5: the authenticated mount bootstrap. authedBootstrap probes the
	// session first and runs the protected initial loads ONLY after proven
	// authentication — expiry/anonymous handling stays in the auth/HTTP seams
	// (a 401 on any loader redirects there). An unproven page settles its
	// loading state instead of stranding the spinner; unmount aborts the rest.
	authedBootstrap(
		async (signal) => {
			// Load legacy data through the seam-owned initial-load resources. A
			// failed load resolves null (error state surfaces the display-safe
			// message); the page keeps its previous empty defaults otherwise.
			const [devData, scoreData] = await Promise.all([devicesRes.load({ signal }), scoreRes.load({ signal })]);
			devices = devData?.devices ?? [];
			score = scoreData ?? null;
			error = devicesRes.error || scoreRes.error;
			if (error) logger.error('settings/security: failed to load', error);
			loading = false;

			const me = await meRes.load({ signal });
			if (me) totpEnabled = !!me.totp_enabled;

			// Possession handoff inputs (§3.1): offer WebAuthn-UV only when an
			// enrolled credential reports uv_capable. Best-effort — failure simply
			// leaves the method unoffered (the password/TOTP arms stay authoritative).
			try {
				const creds = await fetchPasskeyCredentials();
				uvPasskeyEnrolled = creds.some((c) => c.uv_capable === true);
			} catch (e) {
				logger.warn('settings/security: passkey read for possession handoff failed', e);
			}

			await loadSmimeCerts(signal);
			await loadContactCerts(signal);
			await loadCertStatus(signal);

			// Load Task 12 data (skipped when injected via props for tests)
			if (initialSignIns === undefined && !initSignInsError && !initSignInsLoading) {
				await loadSignIns(false, signal);
			}
			if (initialSessions === undefined) {
				await loadSessions();
			}
		},
		{ onUnproven: () => { loading = false; } }
	);
</script>

<!-- Visually-hidden aria-live region for async outcomes (D-F) -->
<div data-testid="security-live" class="visually-hidden" aria-live="polite" aria-atomic="true">{liveMessage}</div>

<div class="sj-security-page">
	<h1 class="sj-page-title">{t('settings.security')}</h1>

	{#if loading}
		<p class="sj-loading">{t('common.loading')}</p>
	{:else if error}
		<p class="sj-error">{error}</p>
	{:else}
		<!-- Security Score -->
		{#if score}
			<Card title="Security score">
				<div class="sj-score-layout">
					<Progress value={score.score} max={100} label="Security score" />
					<div class="sj-score-checks">
						{#each score.checks as check}
							<div class="sj-check-row">
								<Badge variant={check.pass ? 'success' : 'danger'} dot />
								<span class="sj-check-name">{check.name}</span>
								{#if !check.pass && check.action}
									<span class="sj-check-action">&mdash; {check.action}</span>
								{/if}
							</div>
						{/each}
					</div>
				</div>
			</Card>
		{/if}

		<!-- Tabs -->
		<Tabs items={tabs} active={activeTab} onChange={(id) => activeTab = id} />

		<!-- Devices tab -->
		{#if activeTab === 'devices'}
			{#if devices.length === 0}
				<p class="sj-empty">No devices found.</p>
			{:else}
				<Card flush>
					<table class="sj-table">
						<thead>
							<tr><th>Device</th><th>Platform</th><th>Last Seen</th><th>Trust</th><th></th></tr>
						</thead>
						<tbody>
							{#each devices as d}
								<tr class:sj-current-row={d.is_current_device}>
									<td>{d.device_name} {d.is_current_device ? '(this device)' : ''}</td>
									<td><Badge variant="neutral" dot label={d.platform} /></td>
									<td class="sj-muted">{d.last_seen}</td>
									<td><Badge variant={d.trust_tier === 'trusted' ? 'accent' : 'neutral'} label={d.trust_tier} /></td>
									<td></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</Card>
			{/if}
		{/if}

		<!-- History tab — sign-ins + sessions (D-C surfaces 1+2) -->
		{#if activeTab === 'history'}
			<!-- ── Your sign-ins (D-C surface 1) ── -->
			<section aria-busy={signInsLoading}>
				<h2 class="sj-section-title">{t('security.signins.heading')}</h2>
				<p class="sj-card-desc">{t('security.signins.subtitle')}</p>

				<!-- failed_distinct banner + filter (D-C) -->
				{#if failedDistinct && failedDistinct.count > 0}
					<div data-testid="failed-summary" class="sj-failed-summary">
						<Badge variant="warning" dot label={t('security.signins.failedSummary', { count: String(failedDistinct.count), locations: String(failedDistinct.locations) })} />
					</div>
					<label class="sj-failed-toggle">
						<input
							type="checkbox"
							data-testid="failed-only-toggle"
							checked={failedOnly}
							onchange={async (e) => { failedOnly = (e.currentTarget as HTMLInputElement).checked; await reload(); }}
						/>
						{t('security.signins.failedOnly')}
					</label>
				{/if}

				{#if signInsLoading}
					<ul data-testid="signins-skeleton" role="status" aria-label={t('security.signins.loading')} class="sj-skeleton-list">
						{#each Array(5) as _}<li class="sj-skeleton-row"></li>{/each}
					</ul>
				{:else if signInsError}
					<div data-testid="signins-error" role="alert" class="sj-error-bed">
						<span>{t('security.signins.error')}</span>
						<Button variant="secondary" size="sm" onclick={() => reload()}>{t('common.retry')}</Button>
					</div>
				{:else if signIns.length === 0 && !failedOnly}
					<div data-testid="signins-empty"><EmptyState title={t('security.signins.empty')} /></div>
				{:else if signIns.length === 0 && failedOnly}
					<EmptyState title={t('security.signins.failedNone')} />
				{:else}
					<ul role="list" class="sj-signins-list">
						{#each signIns as ev, i (ev.id ?? i)}
							{@const outcome = ev.success ? t('security.signins.outcome.success') : t('security.signins.outcome.failed')}
							{@const clientLabel = ev.client ? (t(`security.client.${ev.client}`) || ev.client) : ''}
							{@const methodLabel = ev.authMethod ? (t(`security.authMethod.${ev.authMethod}`) || ev.authMethod) : clientLabel}
							{@const rowMethod = methodLabel || clientLabel}
							<li
								data-testid="signin-row-{ev.id}"
								role="listitem"
								aria-current={ev.current ? 'true' : undefined}
								aria-label={t('security.signins.rowAria', {
									outcome,
									location: ev.location || t('security.signins.unknownGeo'),
									device: ev.device || t('security.signins.unknownDevice'),
									time: fmtTime(ev.occurred_at),
									authMethod: rowMethod,
								})}
								class="sj-signin-row"
								class:sj-signin-row--current={ev.current}
							>
								<div class="sj-signin-primary">
									<span>{ev.device ?? t('security.signins.unknownDevice')}</span>
									<span class="sj-muted">{ev.location || t('security.signins.unknownGeo')}</span>
								</div>
								<span class="sj-caption">{fmtTime(ev.occurred_at)} · {rowMethod}</span>
								<div class="sj-signin-badges">
									{#if ev.current}
										<span data-tone="info"><Badge variant="info" dot label={t('security.signins.current')} /></span>
									{:else if ev.cluster}
										<span data-tone="danger"><Badge variant="danger" dot label={t('security.signins.outcome.failedCluster')} /></span>
									{:else if !ev.success}
										<span data-tone="warning"><Badge variant="warning" dot label={t('security.signins.outcome.failed')} /></span>
									{:else if ev.newGeo}
										<span data-tone="info"><Badge variant="info" dot label={t('security.signins.newGeo')} /></span>
									{/if}
								</div>
								{#if !ev.success || ev.cluster}
									<button class="sj-link-btn" onclick={() => openSecureDialog()}>{t('security.not_me')}</button>
								{/if}
							</li>
						{/each}
					</ul>
					{#if total > signIns.length}
						<div data-testid="signins-showing-of" class="sj-caption">{t('security.signins.showingOf', { shown: String(signIns.length), total: String(total) })}</div>
						<Button data-testid="signins-load-more" variant="ghost" size="sm" onclick={loadMore}>{t('security.signins.loadMore')}</Button>
					{/if}
				{/if}
			</section>

			<!-- ── Active sessions (D-C surface 2) ── -->
			<section class="sj-sessions-section">
				<h2 class="sj-section-title">{t('security.sessions.heading')}</h2>
				{#if sessions.length === 1 && sessions[0].current}
					<p data-testid="sessions-only-current" class="sj-card-desc">{t('security.sessions.empty')}</p>
				{/if}
				{#if sessions.length > 0}
					<ul role="list" class="sj-sessions-list">
						{#each sessions as s (s.id)}
							<li role="listitem" class="sj-session-row">
								<div class="sj-signin-primary">
									<span>{s.device ?? t('security.signins.unknownDevice')}</span>
									<span class="sj-muted">{s.location ?? t('security.signins.unknownGeo')}</span>
								</div>
								<span class="sj-caption">{t('security.sessions.lastUsed', { when: fmtTime(s.last_used_at) })}</span>
								{#if s.current}<Badge variant="info" dot label={t('security.sessions.current')} />{/if}
								<Button
									data-testid="session-revoke-{s.id}"
									variant="secondary"
									size="sm"
									aria-label={t('security.sessions.signOutAria', { device: s.device ?? '', location: s.location ?? '' })}
									onclick={() => confirmRevoke(s)}
								>{t('security.sessions.signOut')}</Button>
							</li>
						{/each}
					</ul>
				{/if}
				<div class="sj-sessions-actions">
					<Button data-testid="revoke-all-trigger" variant="ghost" size="sm" onclick={() => (showRevokeAll = true)}>{t('security.sessions.revokeAll')}</Button>
					<Button data-testid="secure-account-trigger" variant="danger" size="sm" onclick={openSecureDialog}>{t('security.secure_account')}</Button>
				</div>
			</section>
		{/if}

			<!-- TOTP tab -->
			{#if activeTab === 'totp'}
				<Card title="Authenticator (TOTP)">
					{#if totpSetup.secret}
						<p class="sj-card-desc">Scan this QR code with your authenticator app, then enter the code below.</p>
						<pre class="sj-totp-secret">{totpSetup.secret}</pre>
						<div class="sj-totp-row">
							<Input size="md" label="Verification code" bind:value={totpConfirmCode} mono inputmode="numeric" maxlength={6} />
							<Button variant="primary" size="sm" onclick={handleConfirmTOTP} disabled={totpLoading || totpConfirmCode.length < 6}>
								{totpLoading ? 'Verifying…' : 'Verify & enable'}
							</Button>
						</div>
					{:else if totpEnabled}
						<div class="sj-totp-status">
							<Badge variant="success" dot label="Active" />
							<Button variant="secondary" size="sm" onclick={handleSetupTOTP} disabled={totpLoading}>Re-enroll</Button>
							<Button variant="secondary" size="sm" onclick={handleRemoveTOTP} disabled={totpLoading}>Disable</Button>
						</div>
						{#if totpRemoveOpen}
							<div class="sj-totp-remove-form" data-testid="totp-remove-form">
								<Input size="md" label="Password" type="password" bind:value={totpRemovePassword} autocomplete="current-password" />
								<Input size="md" label="Authenticator or recovery code" bind:value={totpRemoveCode} mono inputmode="numeric" />
								<Input size="md" label="Type REMOVE to confirm" bind:value={totpRemoveConfirm} />
								<p class="sj-card-desc">
									Lost your authenticator and have no recovery codes? Self-service removal is unavailable — contact support.
								</p>
								<div class="sj-totp-row">
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
					{:else}
						<p class="sj-card-desc">Two-factor authentication is not configured. Add an extra layer of security to your account.</p>
						<Button variant="secondary" size="sm" onclick={handleSetupTOTP} disabled={totpLoading}>
							{totpLoading ? 'Setting up…' : 'Set up authenticator'}
						</Button>
					{/if}
					{#if totpError}<p class="sj-error" role="alert">{totpError}</p>{/if}

					<!-- v7 §3.1: fresh-proof handoff for the gated first-enrollment /
					     replacement / recovery-regeneration arms, method-aware for
					     C1 (WebAuthn-UV or TOTP) with password only for C2/C3. -->
					{#if reauthOpen && pendingReauth}
						<MfaReauthHandoff
							operation={pendingReauth.operation}
							methods={reauthMethods}
							onproof={handleReauthProof}
							oncancel={cancelReauth}
						/>
					{/if}

					<!-- Recovery codes: regeneration replaces every code, so it
					     rides the re-auth handoff for every account. -->
					<div class="sj-totp-remove-form">
						<h3 class="sj-section-title">{t('security.recovery.heading')}</h3>
						<p class="sj-card-desc">{t('security.recovery.desc')}</p>
						{#if recoveryCodes.length > 0}
							<pre class="sj-totp-secret" data-testid="recovery-codes">{recoveryCodes.join('\n')}</pre>
							<p class="sj-card-desc">{t('security.recovery.save_hint')}</p>
						{/if}
						{#if recoveryError}<p class="sj-error" role="alert">{recoveryError}</p>{/if}
						<Button
							variant="secondary"
							size="sm"
							data-testid="recovery-regenerate"
							onclick={handleRegenerateRecovery}
							disabled={recoveryBusy}
						>
							{recoveryBusy ? t('security.recovery.regenerating') : t('security.recovery.regenerate')}
						</Button>
					</div>
				</Card>
			{/if}
	{/if}

	<!-- Client cert status card (Task E — always visible, independent load) -->
	<CertStatusCard
		status={certStatus}
		loading={certLoading}
		error={certError}
		onRetry={loadCertStatus}
	/>

	<!-- S/MIME Certificates card (always visible, independent load) -->
	<Card title={t('settings.smime.title')}>
		{#if smimeLoading}
			<p class="sj-loading">{t('common.loading')}</p>
		{:else if smimeError}
			<p class="sj-error" role="alert">{smimeError}</p>
		{:else if smimeCerts.length === 0}
			<p class="sj-card-desc">{t('settings.smime.no_certs')}</p>
			<p class="sj-smime-hint">{t('settings.smime.empty_hint')}</p>
		{:else}
			<table class="sj-table sj-smime-table">
				<thead>
					<tr>
						<th>{t('settings.smime.label')}</th>
						<th>{t('settings.smime.expires')}</th>
						<th></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each smimeCerts as cert}
						<tr>
							<td>
								<span class="sj-smime-label">{cert.label}</span>
								{#if cert.isDefault}
									<Badge variant="success" label={t('settings.smime.default')} />
								{/if}
							</td>
							<td class="sj-muted">
								{new Date(cert.expiresAt).toLocaleDateString()}
								{#if isExpired(cert.expiresAt)}
									<Badge variant="warning" label={t('settings.smime.expired')} />
								{/if}
							</td>
							<td>
								{#if !cert.isDefault}
									<Button variant="secondary" size="sm" onclick={() => handleSetDefault(cert)}>
										{t('settings.smime.set_default')}
									</Button>
								{/if}
							</td>
							<td>
								<Button variant="secondary" size="sm" onclick={() => requestDeleteCert(cert)}>
									{t('settings.smime.delete')}
								</Button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}

		<!-- Upload form -->
		<div class="sj-smime-upload">
			<p class="sj-smime-upload-heading">{t('settings.smime.upload')}</p>
			<div class="sj-smime-upload-fields">
				<Input
					size="md"
					label={t('settings.smime.label')}
					bind:value={smimeLabel}
				/>
				<div class="sj-smime-file-group">
					<label class="sj-smime-file-label">
						<span class="sj-smime-file-name">{t('settings.smime.cert_file')}</span>
						<input
							type="file"
							accept=".pem,.crt,.cer"
							class="sj-smime-file-input"
							onchange={(e) => {
								smimeCertFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
							}}
						/>
					</label>
					<label class="sj-smime-file-label">
						<span class="sj-smime-file-name">{t('settings.smime.key_file')}</span>
						<input
							type="file"
							accept=".pem,.key"
							class="sj-smime-file-input"
							onchange={(e) => {
								smimeKeyFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
							}}
						/>
					</label>
				</div>
				<Button
					variant="primary"
					size="sm"
					onclick={handleSmimeUpload}
					disabled={smimeUploading || !smimeLabel.trim() || !smimeCertFile || !smimeKeyFile}
				>
					{smimeUploading ? t('common.loading') : t('settings.smime.upload_btn')}
				</Button>
			</div>
			{#if smimeUploadError}
				<p class="sj-error" role="alert">{smimeUploadError}</p>
			{/if}
		</div>
	</Card>
</div>

<!-- D-I.1 per-session revoke -->
<Dialog
	open={showRevoke}
	title={t('security.sessions.revokeTitle')}
	onClose={() => (showRevoke = false)}
>
	{#if revokeTarget?.current}
		<p data-testid="revoke-current-warning" class="sj-dialog-body">{t('security.sessions.revokeCurrentBody')}</p>
	{:else}
		<p class="sj-dialog-body">{t('security.sessions.revokeBody', { device: revokeTarget?.device ?? '', location: revokeTarget?.location ?? '' })}</p>
	{/if}
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => (showRevoke = false)}>{t('common.cancel')}</Button>
		<Button variant="danger" size="sm" onclick={doRevoke}>{t('security.sessions.revokeConfirm')}</Button>
	{/snippet}
</Dialog>

<!-- D-I.2 sign-out everywhere -->
<Dialog
	open={showRevokeAll}
	title={t('security.sessions.revokeAllTitle')}
	onClose={() => (showRevokeAll = false)}
>
	<p class="sj-dialog-body">{t('security.sessions.revokeAllBody', { count: String(sessions.length) })}</p>
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => (showRevokeAll = false)}>{t('common.cancel')}</Button>
		<Button data-testid="revoke-all-confirm" variant="danger" size="sm" onclick={doRevokeAll}>{t('security.sessions.revokeAllConfirm')}</Button>
	{/snippet}
</Dialog>

<!-- D-I.3 secure account (Tier-3) -->
<Dialog
	open={showSecure}
	title={t('security.secure_account.title')}
	onClose={() => (showSecure = false)}
>
	<p class="sj-dialog-body">{sessions.length > 1 ? t('security.secure_account.body_self') : t('security.secure_account.no_sessions')}</p>
	<ul class="sj-effect-list">
		<li>{t('security.effect.revoke_all')}</li>
		<li>{t('security.effect.force_reset')}</li>
	</ul>
	{#if secureListLoading}
		<ul role="status" aria-label={t('security.sessions.loading')} class="sj-skeleton-list"><li class="sj-skeleton-row"></li></ul>
	{:else if secureListError}
		<div data-testid="secure-list-error" role="alert" class="sj-error-bed">
			{t('security.secure_account.listError')}
			<Button variant="secondary" size="sm" onclick={() => { _secureListError = false; openSecureDialog(); }}>{t('common.retry')}</Button>
		</div>
	{:else}
		{#if revocableSessions.length > 0}
			<ul role="list" class="sj-sessions-mini">
				{#each revocableSessions as s}
					<li>{s.device ?? t('security.signins.unknownDevice')} · {t('security.sessions.lastUsed', { when: fmtTime(s.last_used_at) })}</li>
				{/each}
			</ul>
		{/if}
	{/if}
	<label class="sj-field__label" for="secure-type-input">{t('security.secure_account.typePrompt', { value: 'SECURE' })}</label>
	<Input id="secure-type-input" data-testid="secure-account-type" bind:value={secureToken} aria-describedby="secure-consequence" />
	{#if secureError}
		<p class="sj-error" role="alert">{t('security.secure_account.error')}</p>
	{/if}
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => (showSecure = false)}>{t('common.cancel')}</Button>
		<Button
			data-testid="secure-account-confirm"
			variant="danger"
			size="sm"
			disabled={secureToken !== 'SECURE' || secureListError || secureListLoading}
			aria-disabled={secureToken !== 'SECURE' || undefined}
			onclick={secureAccount}
		>{secureCommitting ? t('security.secure_account.committing') : t('security.secure_account.confirm')}</Button>
	{/snippet}
</Dialog>

<!-- Contacts' Certificates card (SP1 Phase 6) -->
<Card title={t('settings.contacts_certs.title')}>
	{#if contactCertsLoading}
		<p class="sj-loading">{t('common.loading')}</p>
	{:else if contactCertsError}
		<p class="sj-error" role="alert">{contactCertsError}</p>
	{:else if contactCerts.length === 0}
		<p class="sj-contacts-cert-empty-title">{t('settings.contacts_certs.empty_title')}</p>
		<p class="sj-card-desc">{t('settings.contacts_certs.empty_body')}</p>
	{:else}
		<table class="sj-table sj-contacts-cert-table">
			<thead>
				<tr>
					<th>{t('settings.contacts_certs.address')}</th>
					<th>{t('settings.contacts_certs.source')}</th>
					<th>{t('settings.contacts_certs.expires')}</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each contactCerts as cert}
					<tr>
						<td>
							<span class="sj-contacts-cert-email">{cert.email}</span>
							{#if cert.label}
								<span class="sj-contacts-cert-label">{cert.label}</span>
							{/if}
						</td>
						<td>
							<Badge
								variant="neutral"
								label={cert.source === 'harvested'
									? t('settings.contacts_certs.source_harvested')
									: t('settings.contacts_certs.source_imported')}
							/>
							{#if !cert.isEncryptCapable && cert.source === 'harvested'}
								<Badge variant="neutral" label={t('settings.contacts_certs.signing_only')} />
							{/if}
						</td>
						<td class="sj-muted">
							{cert.notAfter ? new Date(cert.notAfter).toLocaleDateString() : '—'}
							{#if isExpiredContact(cert)}
								<Badge variant="warning" label={t('settings.contacts_certs.expired')} />
							{:else if isExpiringSoonContact(cert)}
								<Badge variant="warning" label={t('settings.contacts_certs.expiring_soon')} />
							{/if}
						</td>
						<td>
							<Button variant="secondary" size="sm" onclick={() => (pendingDeleteContact = cert)}>
								{t('settings.contacts_certs.delete')}
							</Button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	<!-- Import form -->
	<div class="sj-smime-upload">
		<p class="sj-smime-upload-heading">{t('settings.contacts_certs.import_heading')}</p>
		<div class="sj-smime-upload-fields">
			<Input
				size="md"
				label={t('settings.contacts_certs.label')}
				bind:value={contactCertLabel}
			/>
			<div class="sj-smime-file-group">
				<label class="sj-smime-file-label">
					<span class="sj-smime-file-name">{t('settings.contacts_certs.cert_file')}</span>
					<input
						type="file"
						accept=".pem,.crt,.cer"
						class="sj-smime-file-input"
						onchange={(e) => {
							contactCertFile = (e.currentTarget as HTMLInputElement).files?.[0] ?? null;
						}}
					/>
				</label>
			</div>
			<Button
				variant="primary"
				size="sm"
				onclick={handleImportContactCert}
				disabled={contactCertImporting || !contactCertFile}
			>
				{contactCertImporting ? t('settings.contacts_certs.importing') : t('settings.contacts_certs.import_btn')}
			</Button>
		</div>
		{#if contactCertImportError}
			<p class="sj-error" role="alert">{contactCertImportError}</p>
		{/if}
	</div>
</Card>

<!-- Legacy dialogs -->
<Dialog
	open={pendingDelete !== null}
	title={t('settings.smime.delete') + ' — ' + (pendingDelete?.label ?? '')}
	onClose={() => (pendingDelete = null)}
>
	<p class="sj-dialog-body">{t('settings.smime.delete_confirm')}</p>
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => (pendingDelete = null)}>Cancel</Button>
		<Button variant="danger" size="sm" onclick={confirmDeleteCert}>{t('settings.smime.delete')}</Button>
	{/snippet}
</Dialog>

<Dialog
	open={pendingDeleteContact !== null}
	title={t('settings.contacts_certs.delete') + (pendingDeleteContact?.email ? ' — ' + pendingDeleteContact.email : '')}
	onClose={() => (pendingDeleteContact = null)}
>
	<p class="sj-dialog-body">{t('settings.contacts_certs.delete_confirm')}</p>
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => (pendingDeleteContact = null)}>Cancel</Button>
		<Button variant="danger" size="sm" onclick={confirmDeleteContactCert}>{t('settings.contacts_certs.delete')}</Button>
	{/snippet}
</Dialog>

<Toast />

<style>
	.visually-hidden {
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

	.sj-security-page {
		max-width: 800px;
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

	.sj-section-title {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		margin: 0 0 4px;
		color: var(--text-primary);
	}

	.sj-score-layout {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.sj-score-checks {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.sj-check-row {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.sj-check-name { font-weight: 500; }
	.sj-check-action { color: var(--text-tertiary); }

	.sj-table {
		width: 100%;
		border-collapse: collapse;
	}

	.sj-table th, .sj-table td {
		padding: 8px 12px;
		text-align: left;
		border-bottom: 1px solid var(--border-default);
	}

	.sj-table th {
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.sj-table td {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.sj-current-row {
		background: var(--surface-selected);
	}

	.sj-muted { color: var(--text-tertiary); }

	.sj-empty {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}

	.sj-card-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 8px;
		line-height: 1.5;
	}

	.sj-caption {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.sj-totp-secret {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		background: var(--surface-sunken);
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin: 8px 0;
		overflow-x: auto;
		user-select: all;
	}

	.sj-totp-row {
		display: flex;
		align-items: flex-end;
		gap: 10px;
		margin-top: 8px;
	}

	.sj-totp-remove-form {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 12px;
		padding-top: 12px;
		border-top: 1px solid var(--border);
	}

	.sj-totp-remove-form .sj-totp-row {
		align-items: center;
		margin-top: 0;
	}

	.sj-totp-status {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.sj-loading { color: var(--text-tertiary); }
	.sj-error { color: var(--danger-fg); font-size: var(--text-sm); }

	.sj-dialog-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: 1.5;
	}

	/* S/MIME card */
	.sj-smime-hint {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		margin: 0 0 12px;
		line-height: 1.5;
	}

	.sj-smime-table {
		margin-bottom: 16px;
	}

	.sj-smime-label {
		font-weight: 500;
		margin-right: 6px;
	}

	.sj-smime-upload {
		border-top: 1px solid var(--border-default);
		padding-top: 16px;
		margin-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.sj-smime-upload-heading {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0;
	}

	.sj-smime-upload-fields {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.sj-smime-file-group {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-smime-file-label {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.sj-smime-file-name {
		font-size: var(--text-xs);
		font-weight: 500;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}

	.sj-smime-file-input {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	/* Task 12 — Sign-ins */
	.sj-signins-list, .sj-sessions-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		overflow: hidden;
	}

	.sj-signin-row, .sj-session-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px 16px;
		border-bottom: 1px solid var(--border-subtle);
		font-size: var(--text-sm);
		min-height: 44px; /* a11y: 44px touch target */
	}

	.sj-signin-row:last-child, .sj-session-row:last-child {
		border-bottom: none;
	}

	.sj-signin-row--current {
		background: var(--surface-selected);
	}

	.sj-signin-primary {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 2px;
		color: var(--text-primary);
		font-weight: 500;
	}

	.sj-signin-badges {
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.sj-sessions-actions {
		display: flex;
		gap: 8px;
		margin-top: 8px;
	}

	.sj-failed-summary {
		margin-bottom: 8px;
	}

	.sj-failed-toggle {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: var(--text-sm);
		color: var(--text-primary);
		cursor: pointer;
		margin-bottom: 12px;
		min-height: 44px;
	}

	.sj-skeleton-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-skeleton-row {
		height: 44px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: sj-shimmer 1.4s ease-in-out infinite;
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-skeleton-row { animation: none; }
	}

	@keyframes sj-shimmer {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.5; }
	}

	.sj-error-bed {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px 16px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.sj-effect-list {
		padding-left: 20px;
		margin: 8px 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.6;
	}

	.sj-sessions-mini {
		list-style: none;
		padding: 8px 0;
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.sj-link-btn {
		background: none;
		border: none;
		padding: 0;
		color: var(--accent-fg);
		font-size: var(--text-xs);
		cursor: pointer;
		text-decoration: underline;
		min-height: 44px;
	}

	.sj-field__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		display: block;
		margin-top: 12px;
		margin-bottom: 4px;
	}

	.sj-sessions-section {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	/* D-G: responsive stacked cards at <760px */
	@media (max-width: 760px) {
		.sj-signin-row, .sj-session-row {
			flex-direction: column;
			align-items: flex-start;
		}
	}

	/* Contacts' Certificates card */
	.sj-contacts-cert-empty-title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.sj-contacts-cert-table {
		margin-bottom: 16px;
	}

	.sj-contacts-cert-email {
		font-weight: 500;
		margin-right: 6px;
	}

	.sj-contacts-cert-label {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
</style>
