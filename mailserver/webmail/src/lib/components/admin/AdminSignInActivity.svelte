<svelte:options runes={true} />
<!--
	AdminSignInActivity — admin per-user sign-in activity section (Task 13).
	Surfaces sign-in history + active sessions + admin secure-account dialog.
	Consumes: GET /admin/users/{id}/sign-ins, /sessions, POST /…/secure-account.
	D-C surface 4 + D-I.4 (dangerous action arc). D-G: Table desktop / stacked mobile.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { t } from '$lib/i18n';
	import { logger } from '$lib/logger';
	import { Badge, Button, Dialog, EmptyState, Input, showToast } from '$lib/components/ui';
	import {
		adminGetSignIns,
		adminGetSessions,
		adminSecureAccount,
		type AdminSignInEvent,
		type AdminSession,
	} from '$lib/admin/client';

	// ponytail: prop injection so vitest renders each D-C state in isolation.
	// Real use: userId drives onMount; props win when provided (injected in tests).
	interface Props {
		userId?: number;
		// Injection props (tests only)
		signIns?: AdminSignInEvent[];
		loading?: boolean;
		error?: boolean;
		status?: number; // 403 | 404 surface dedicated panels
		user?: { id: number; name?: string };
	}

	let {
		userId,
		signIns: injectedSignIns,
		loading: injectedLoading = false,
		error: injectedError = false,
		status: injectedStatus,
		user: injectedUser,
	}: Props = $props();

	// ── State ──
	let _signIns = $state<AdminSignInEvent[]>([]);
	let _sessions = $state<AdminSession[]>([]);
	let _loading = $state(false);
	let _error = $state(false);
	let _status = $state(0);

	// Derived from injected props or live fetch (props win for test isolation)
	const signIns = $derived(injectedSignIns !== undefined ? injectedSignIns : _signIns);
	const loading = $derived(injectedLoading || (injectedSignIns === undefined && _loading));
	const error = $derived(injectedError || _error);
	const httpStatus = $derived(injectedStatus !== undefined ? injectedStatus : _status);

	// Secure account dialog
	let showSecure = $state(false);
	let secureToken = $state('');
	let secureCommitting = $state(false);
	let secureError = $state(false);

	// Aria-live region (D-F)
	let liveMessage = $state('');

	function fmtTime(ts?: string): string {
		if (!ts) return '';
		try { return new Date(ts).toLocaleString(); } catch { return ts; }
	}

	async function load() {
		const uid = userId ?? injectedUser?.id;
		if (!uid) return;
		_loading = true;
		_error = false;
		_status = 0;
		try {
			const [si, sess] = await Promise.all([
				adminGetSignIns(uid),
				adminGetSessions(uid),
			]);
			if (si.status === 403 || si.status === 404) { _status = si.status; return; }
			if (!si.items && si.status !== 200) { _error = true; return; }
			_signIns = si.items;
			_sessions = sess.sessions;
		} catch (e) {
			_error = true;
			logger.error('admin sign-in activity: load failed', e);
		} finally {
			_loading = false;
		}
	}

	async function doSecure() {
		const uid = userId ?? injectedUser?.id;
		if (!uid || secureToken !== 'SECURE') return;
		secureCommitting = true;
		secureError = false;
		try {
			await adminSecureAccount(uid);
			liveMessage = t('security.admin.secure.announce');
			showToast(t('security.admin.secure.toast'));
			showSecure = false;
			secureToken = '';
			// Reload activity after securing
			await load();
		} catch (e) {
			secureError = true;
			logger.error('admin secure-account failed', e);
		} finally {
			secureCommitting = false;
		}
	}

	onMount(() => {
		// Skip if data was injected (test isolation)
		if (injectedSignIns === undefined && !injectedError && !injectedLoading) {
			load();
		}
	});
</script>

<!-- D-F: aria-live region for async outcomes -->
<div data-testid="admin-secure-live" class="visually-hidden" aria-live="polite" aria-atomic="true">{liveMessage}</div>

<section data-testid="admin-signin-activity" class="asa-section" aria-labelledby="asa-heading">
	<h2 id="asa-heading" class="asa-heading">{t('security.admin.heading')}</h2>
	<p class="asa-subtitle">{t('security.admin.subtitle')}</p>

	{#if loading}
		<!-- LOADING skeleton -->
		<ul data-testid="admin-signins-skeleton" role="status" aria-label={t('security.admin.loading')} class="asa-skeleton-list">
			{#each Array(5) as _}<li class="asa-skeleton-row"></li>{/each}
		</ul>

	{:else if httpStatus === 403}
		<!-- 403 not-permitted -->
		<div data-testid="admin-signins-forbidden" class="asa-panel asa-panel--neutral">
			<EmptyState title={t('security.admin.forbidden')} />
		</div>

	{:else if httpStatus === 404}
		<!-- 404 out-of-scope -->
		<div data-testid="admin-signins-notfound" class="asa-panel asa-panel--neutral">
			<EmptyState title={t('security.admin.notfound')} />
		</div>

	{:else if error}
		<!-- ERROR + retry -->
		<div data-testid="admin-signins-error" role="alert" class="asa-error-bed">
			<span>{t('security.admin.error')}</span>
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>

	{:else if signIns.length === 0}
		<!-- EMPTY -->
		<div data-testid="admin-signins-empty">
			<EmptyState title={t('security.admin.empty')} />
		</div>

	{:else}
		<!-- D-G desktop: table -->
		<div class="asa-table-wrap">
			<table class="asa-table" role="grid">
				<thead>
					<tr>
						<th scope="col">{t('security.admin.col.time')}</th>
						<th scope="col">{t('security.admin.col.location')}</th>
						<th scope="col">{t('security.admin.col.device')}</th>
						<th scope="col">{t('security.admin.col.client')}</th>
						<th scope="col">{t('security.admin.col.method')}</th>
						<th scope="col">{t('security.admin.col.outcome')}</th>
					</tr>
				</thead>
				<tbody>
					{#each signIns as ev (ev.id)}
						<tr data-testid="admin-signin-row-{ev.id}">
							<td class="asa-mono">{fmtTime(ev.occurred_at)}</td>
							<td>{ev.location || t('security.signins.unknownGeo')}</td>
							<td>{ev.device_name || ev.platform || t('security.signins.unknownDevice')}</td>
							<td>{ev.client || ev.protocol || '—'}</td>
							<td>{ev.auth_method || '—'}</td>
							<td>
								{#if ev.success}
									<Badge variant="success" dot label={t('security.admin.outcome.ok')} />
								{:else}
									<Badge variant="danger" dot label={t('security.admin.outcome.fail')} />
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<!-- D-G mobile: stacked cards (hidden on desktop via CSS) -->
		<ul class="asa-cards" role="list">
			{#each signIns as ev (ev.id)}
				<li class="asa-card" role="listitem">
					<div class="asa-card-primary">
						<span>{ev.device_name || ev.platform || t('security.signins.unknownDevice')}</span>
						<span class="asa-muted">{ev.location || t('security.signins.unknownGeo')}</span>
					</div>
					<span class="asa-caption">{fmtTime(ev.occurred_at)} · {ev.client || ev.auth_method || ''}</span>
					{#if ev.success}
						<Badge variant="success" dot label={t('security.admin.outcome.ok')} />
					{:else}
						<Badge variant="danger" dot label={t('security.admin.outcome.fail')} />
					{/if}
				</li>
			{/each}
		</ul>
	{/if}

	<!-- Active sessions sub-section (shown when data loaded + no HTTP error) -->
	{#if !loading && !error && httpStatus === 0 && signIns.length >= 0}
		<div class="asa-sessions-section">
			<h3 class="asa-subheading">{t('security.admin.sessions.heading')}</h3>
			{#if _sessions.length === 0}
				<p class="asa-muted">{t('security.admin.sessions.empty')}</p>
			{:else}
				<ul class="asa-sessions-list" role="list">
					{#each _sessions as s (s.id)}
						<li class="asa-session-row" role="listitem">
							<div class="asa-card-primary">
								<span>{s.kind === 'web' ? t('security.admin.sessions.kind.web') : t('security.admin.sessions.kind.oauth')}{s.device ? ` · ${s.device}` : ''}</span>
								{#if s.location}<span class="asa-muted">{s.location}</span>{/if}
							</div>
							<span class="asa-caption">{t('security.sessions.lastUsed', { when: fmtTime(s.last_used_at) })}</span>
						</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}

	<!-- D-D: attributed note -->
	<p class="asa-note">{t('security.admin.attributedNote')}</p>

	<!-- D-I.4: admin secure-account action (no self-logout) -->
	<div class="asa-actions">
		<Button
			data-testid="admin-secure-trigger"
			variant="danger"
			size="sm"
			onclick={() => { showSecure = true; secureToken = ''; secureError = false; }}
		>
			{t('security.admin.secure')}
		</Button>
	</div>
</section>

<!-- D-I.4: dangerous-action dialog — Tier-2 type-to-confirm, no self-logout -->
<Dialog
	open={showSecure}
	title={t('security.admin.secure.title')}
	onClose={() => { showSecure = false; secureToken = ''; secureError = false; }}
>
	{#snippet children()}
		<p class="asa-dialog-body">{t('security.admin.secure.body')}</p>
		<label class="asa-field-label" for="admin-secure-type-input">
			{t('security.admin.secure.typePrompt', { value: 'SECURE' })}
		</label>
		<Input
			id="admin-secure-type-input"
			data-testid="admin-secure-type"
			bind:value={secureToken}
		/>
		{#if secureError}
			<p class="asa-error" role="alert">{t('security.admin.secure.error')}</p>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" size="sm" onclick={() => { showSecure = false; secureToken = ''; secureError = false; }}>
			{t('common.cancel')}
		</Button>
		<Button
			data-testid="admin-secure-confirm"
			variant="danger"
			size="sm"
			disabled={secureToken !== 'SECURE' || secureCommitting}
			aria-disabled={secureToken !== 'SECURE' || undefined}
			onclick={doSecure}
		>
			{secureCommitting ? t('security.admin.secure.committing') : t('security.admin.secure.confirm')}
		</Button>
	{/snippet}
</Dialog>

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

	.asa-section {
		margin-top: 24px;
		display: flex;
		flex-direction: column;
		gap: 12px;
	}

	.asa-heading {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		margin: 0;
		color: var(--text-primary);
	}

	.asa-subheading {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		margin: 0 0 8px;
		color: var(--text-primary);
	}

	.asa-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}

	/* ── Desktop table (hidden on mobile via media query) ── */
	.asa-table-wrap {
		overflow-x: auto;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}

	.asa-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}

	.asa-table th {
		text-align: left;
		padding: 8px 12px;
		font-size: var(--text-2xs);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		color: var(--text-tertiary);
		font-weight: 600;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-sunken);
	}

	.asa-table td {
		padding: 10px 12px;
		color: var(--text-primary);
		border-bottom: 1px solid var(--border-subtle);
	}

	.asa-table tbody tr:last-child td {
		border-bottom: none;
	}

	.asa-mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		white-space: nowrap;
	}

	/* ── Mobile stacked cards (hidden on desktop) ── */
	.asa-cards {
		display: none;
		list-style: none;
		padding: 0;
		margin: 0;
		flex-direction: column;
		gap: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		overflow: hidden;
	}

	.asa-card, .asa-session-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px 16px;
		border-bottom: 1px solid var(--border-subtle);
		font-size: var(--text-sm);
		min-height: 44px; /* a11y: 44px touch target */
	}

	.asa-card:last-child, .asa-session-row:last-child {
		border-bottom: none;
	}

	.asa-card-primary {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 2px;
		color: var(--text-primary);
		font-weight: 500;
	}

	/* ── D-G: swap table ↔ cards at 760px ── */
	@media (max-width: 760px) {
		.asa-table-wrap { display: none; }
		.asa-cards { display: flex; }
	}

	/* ── Sessions ── */
	.asa-sessions-section {
		border-top: 1px solid var(--border-default);
		padding-top: 12px;
	}

	.asa-sessions-list {
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

	/* ── States ── */
	.asa-error-bed {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px 16px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.asa-panel {
		padding: 16px;
		border-radius: var(--radius-md);
	}

	.asa-panel--neutral {
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
	}

	.asa-skeleton-list {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.asa-skeleton-row {
		height: 44px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: asa-shimmer 1.4s ease-in-out infinite;
	}

	@media (prefers-reduced-motion: reduce) {
		.asa-skeleton-row { animation: none; }
	}

	@keyframes asa-shimmer {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.5; }
	}

	/* ── Utilities ── */
	.asa-muted { color: var(--text-tertiary); font-size: var(--text-xs); }
	.asa-caption { font-size: var(--text-xs); color: var(--text-tertiary); }

	.asa-note {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
		line-height: 1.5;
	}

	.asa-actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}

	/* ── Dialog ── */
	.asa-dialog-body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 12px;
		line-height: 1.5;
	}

	.asa-field-label {
		display: block;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-bottom: 4px;
	}

	.asa-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 8px 0 0;
	}
</style>
