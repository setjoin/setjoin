<!-- PromoteDialog.svelte — T3 dangerous-confirm for CA policy promotion.
     Three arcs: calm (would_block=0), caution (>0, no admins), danger (admins>0 or self-locked).
     ponytail: single component, three visual treatments via $derived conditions.
     Impact-fetch failure MUST block confirm (never show "0") — §e load-bearing rule.
     Gate contract: opening the dialog performs NO network request; the confirm:false
     preview POST is a pure server-side read that fires only on the explicit
     "Check impact" action; promotion is a separate explicit confirm:true commit. -->
<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Input, Spinner, Badge } from '$lib/components/ui';
	import { Checkbox } from '$lib/components/ui';
	import { t, formatNumber } from '$lib/i18n';
	import { showToast } from '$lib/components/ui';
	import { parseError } from '$lib/errors';
	import { adminFetch } from '$lib/admin/client';
	import { user as authUser } from '$lib/stores/auth';

	// The promote calls route through the shared admin transport seam
	// (adminFetch: DPoP proof, timeout/abort, 401/403 handling, /api namespace,
	// no-store) like every other admin call — the historical local caFetch
	// bypassed all of that. The 409 promote-preview body is preserved by passing
	// allowStatuses:[409]: httpRequest returns the raw Response for allowed
	// non-ok statuses instead of throwing, so parsePromotePreview can still read
	// the blast-radius body (the original reason for the raw-fetch detour).

	export interface BlockedUser {
		id: number;
		address: string;
		is_admin: boolean;
	}

	export interface PromotePreview {
		would_block_users: number;   // total would-block count
		would_block_admins: number;
		self_locked_out: boolean;
		blocked_users: BlockedUser[];
		admin_users: BlockedUser[];  // uncapped (all admins who would be blocked)
		shown: number;
		total: number;
		window: string;
	}

	// Validates an untrusted promote-preview body BEFORE it may drive the safety
	// gate. The historical `res.json() as PromotePreview` trusted any body: an
	// httputil problem shape ({"type","title","status","detail"}) cast into the
	// permissive `?? 0` defaults and selected the calm one-click confirm arc.
	// A VALID structured 409 preview (conflict/lockout result) passes; malformed
	// or error-shaped bodies return null → blocked-read error state (§e).
	function isBlockedUser(v: unknown): v is BlockedUser {
		if (typeof v !== 'object' || v === null) return false;
		const u = v as Record<string, unknown>;
		return (
			typeof u.id === 'number' && Number.isFinite(u.id) &&
			typeof u.address === 'string' && u.address !== ''
		);
	}

	function parsePromotePreview(body: unknown): PromotePreview | null {
		if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
		const b = body as Record<string, unknown>;
		const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
		if (!num(b.would_block_users) || !num(b.would_block_admins)) return null;
		if (!num(b.shown) || !num(b.total)) return null;
		if (typeof b.self_locked_out !== 'boolean') return null;
		if (!Array.isArray(b.blocked_users) || !b.blocked_users.every(isBlockedUser)) return null;
		if (!Array.isArray(b.admin_users) || !b.admin_users.every(isBlockedUser)) return null;
		if (typeof b.window !== 'string' || b.window === '') return null;
		return b as unknown as PromotePreview;
	}

	interface Props {
		open: boolean;
		policyId: number;
		policyName: string;
		actorAddress?: string;
		onClose: () => void;
		onEnforced: () => void;
	}

	let {
		open,
		policyId,
		policyName,
		actorAddress = '',
		onClose,
		onEnforced,
	}: Props = $props();

	// Session identity fallback for the self-lockout warning: the dialog is
	// reachable from callers that never pass actorAddress, and the personal
	// warning must stay reachable for the signed-in admin.
	const effectiveActorAddress = $derived(actorAddress || $authUser?.email || '');

	// ── fetch state ──
	// ponytail: cast needed — $state('idle') infers the literal; the union is the real type.
	// 'idle' = dialog open, no network request made yet: reading the impact is an
	// explicit user action, never an automatic fetch on open.
	let loadState = $state('idle' as 'idle' | 'loading' | 'error' | 'done');
	let preview = $state(null as PromotePreview | null);
	let fetchError = $state('');

	// Client-state TOCTOU guard: every loadPreview/reset writes shared dialog
	// state across awaits. previewGeneration tokens each request; a response
	// from a superseded run (retry raced, or dialog reset mid-flight) is
	// dropped instead of overwriting newer state.
	let previewGeneration = 0;

	// ── confirm state ──
	let ackChecked = $state(false);
	let typeConfirm = $state('');
	let promoting = $state(false);
	let promoteError = $state('');
	let enforceAnnounce = $state('');

	// ── derived arc ──
	const isDanger = $derived(
		(preview?.would_block_admins ?? 0) > 0 || (preview?.self_locked_out ?? false)
	);
	const isCaution = $derived(
		!isDanger && (preview?.would_block_users ?? 0) > 0
	);
	const isSafe = $derived(
		loadState === 'done' && !isDanger && !isCaution
	);

	const dialogTitle = $derived(
		loadState === 'idle'
			? t('admin.ca.promote.title_idle')
			: loadState !== 'done'
				? t('admin.ca.promote.loading')
				: isDanger
					? t('admin.ca.promote.title_danger')
					: isCaution
						? t('admin.ca.promote.title_caution', { count: formatNumber(preview?.would_block_users ?? 0) })
						: t('admin.ca.promote.title_safe')
	);

	// Confirm enabled only when safety gates cleared
	// ponytail: confirmBlocked covers the error case; no need to recheck loadState !== 'error' here.
	const canConfirm = $derived(
		loadState === 'done' &&
		!promoting &&
		(isSafe
			? true
			: isCaution
				? ackChecked
				: (ackChecked && typeConfirm.trim() === policyName))
	);

	// Check if we should block the confirm (impact-fetch failure — §e)
	const confirmBlocked = $derived(loadState === 'error');

	// Opening the dialog must NOT touch the network. The historical bare
	// `$effect(() => { if (!open) return; loadPreview(); })` fired the
	// confirm:false POST merely on open — and that POST reached the server's
	// promote step at would_block==0, so opening the dialog (then Cancel) could
	// enforce a report_only policy. The preview now loads ONLY from the explicit
	// "Check impact" action; this effect just resets to a clean idle slate.
	$effect(() => {
		if (!open) return;
		resetToIdle();
	});

	function resetToIdle() {
		previewGeneration++; // invalidate any in-flight preview writes
		loadState = 'idle';
		preview = null;
		fetchError = '';
		ackChecked = false;
		typeConfirm = '';
		promoteError = '';
		enforceAnnounce = '';
	}

	async function loadPreview() {
		resetToIdle();
		const generation = previewGeneration;
		loadState = 'loading';

		try {
			// POST confirm:false — the server's PURE PREVIEW arm: 409 blast radius
			// at would_block>0, 200 zeroed preview at would_block==0. It must never
			// mutate; promotion happens only via the separate confirm:true call.
			// allowStatuses:[409] keeps the structured preview body reachable
			// through the shared seam (see the adminFetch note above).
			const res = await adminFetch(`/admin/conditional-access/policies/${policyId}/promote`, {
				method: 'POST',
				body: JSON.stringify({ confirm: false }),
				allowStatuses: [409],
			});
			if (generation !== previewGeneration) return; // superseded — never present a stale arc
			if (res.status === 409 || res.ok) {
				// Distinguish a VALID structured preview (the conflict/lockout result
				// the preview legitimately returns) from transport/validation errors:
				// a valid 409/200 preview payload renders its content; a malformed or
				// httputil problem-shaped body is a blocked-read failure (§e), never
				// a permissive-default safe arc.
				let body: unknown;
				try {
					body = await res.json();
				} catch {
					throw new Error('promote preview returned a non-JSON body');
				}
				const parsed = parsePromotePreview(body);
				if (!parsed) {
					throw new Error(`promote preview body failed validation (status ${res.status})`);
				}
				if (generation !== previewGeneration) return; // re-check after the await
				preview = parsed;
				loadState = 'done';
			} else {
				throw new Error(String(res.status));
			}
		} catch (e) {
			if (generation !== previewGeneration) return; // superseded — swallow stale failure too
			fetchError = parseError(e).message;
			loadState = 'error';
			// §e: failure must announce the blocked-read state
			enforceAnnounce = t('admin.ca.promote.announce.blocked_read');
		}
	}

	// Maps a confirm:true failure to the calm copy the dialog shows: the
	// server's hint/detail/message (e.g. the BZ080 lockout guard) wins, with the
	// status fallback behind it. Runs inside httpRequest's onError, so the seam
	// throws exactly this display-safe message.
	async function promoteProblemOnError(r: Response): Promise<string> {
		let detail = '';
		try {
			const err = await r.json();
			detail = err?.hint ?? err?.detail ?? err?.message ?? '';
		} catch { /* non-JSON body — use the status fallback */ }
		return detail || t('admin.ca.error.save', { status: String(r.status) });
	}

	async function confirmPromote() {
		if (!canConfirm || confirmBlocked) return;
		promoting = true;
		promoteError = '';

		try {
			await adminFetch(`/admin/conditional-access/policies/${policyId}/promote`, {
				method: 'POST',
				body: JSON.stringify({ confirm: true }),
				onError: promoteProblemOnError,
			});
			enforceAnnounce = t('admin.ca.promote.announce.enforced', { policy: policyName });
			showToast(t('admin.ca.promoted_toast', { policy: policyName }));
			onEnforced();
		} catch (e) {
			promoteError = parseError(e).message;
		} finally {
			promoting = false;
		}
	}

	function handleTypeKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && canConfirm && !confirmBlocked) {
			e.preventDefault();
			confirmPromote();
		}
	}

	// aria-describedby uid for the type-to-confirm instruction
	// ponytail: $derived to avoid the "captures initial value" Svelte 5 runes warning.
	const typeDescId = $derived(`promote-type-desc-${policyId}`);
	const errorId = $derived(`promote-error-${policyId}`);
</script>

<Dialog
	{open}
	title={dialogTitle}
	wide={true}
	onClose={promoting ? undefined : onClose}
>
	{#snippet children()}
		<!-- aria-live assertive: announce enforced / blocked_read outcomes (§h) -->
		<div aria-live="assertive" aria-atomic="true" class="sr-only" data-testid="promote-announce">
			{enforceAnnounce}
		</div>

		{#if loadState === 'idle'}
			<!-- IDLE: no network request has been made. Reading the impact is an
			     explicit user action (the old fetch-on-open effect turned the preview
			     POST into an unsolicited promotion at would_block==0). -->
			<div class="promote-idle" data-testid="promote-idle">
				<p class="promote-idle__text">{t('admin.ca.promote.preview_intro')}</p>
				<Button
					variant="secondary"
					size="sm"
					onclick={loadPreview}
					data-testid="promote-check-impact"
				>
					{t('admin.ca.promote.check_impact')}
				</Button>
			</div>
		{:else if loadState === 'loading'}
			<!-- LOADING: centered spinner, confirm disabled (§f) -->
			<div class="promote-loading" data-testid="promote-loading">
				<Spinner size={20} />
				<span>{t('admin.ca.promote.loading')}</span>
			</div>
		{:else if loadState === 'error'}
			<!-- IMPACT-FETCH FAILURE: alert + Retry; confirm stays DISABLED (§e — never show 0) -->
			<div class="promote-impact-error" role="alert" data-testid="promote-impact-error">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
					<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
					<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
				</svg>
				<span>{t('admin.ca.promote.impact_error')}</span>
				<Button variant="ghost" size="sm" onclick={loadPreview}>{t('common.retry')}</Button>
			</div>
		{:else if preview !== null}
			<!-- ── LOADED: one of three arcs ── -->

			{#if isSafe}
				<!-- CALM ARC: success banner, one-click primary (§a, no type-to-confirm) -->
				<div class="promote-safe-banner" data-testid="promote-safe-banner">
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
						<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
					</svg>
					{t('admin.ca.promote.safe_banner')}
				</div>
			{:else}
				<!-- CAUTION or DANGER ARC -->

				{#if isDanger}
					<!-- DANGER: admins will be blocked -->
					<div class="promote-danger-admins" role="alert" data-testid="promote-danger-admins">
						<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
							<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
							<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
						</svg>
						<span>
							{t('admin.ca.promote.admins_warn', { count: String(preview.would_block_admins) })}
						</span>
					</div>
					{#if preview.self_locked_out && effectiveActorAddress}
						<p class="promote-self-locked" data-testid="promote-self-locked">
							{t('admin.ca.promote.self_locked', { address: effectiveActorAddress })}
						</p>
					{/if}
				{/if}

				<!-- Big count with aria-label (§k aria) -->
				<div
					class="promote-count"
					aria-label={t('admin.ca.promote.count_aria', {
						users: formatNumber(preview.would_block_users),
						admins: formatNumber(preview.would_block_admins),
					})}
					data-testid="promote-count"
				>
					<span class="promote-count__num">{formatNumber(preview.would_block_users)}</span>
					{#if isDanger && preview.would_block_admins > 0}
						<span class="promote-count__admins">
							<Badge variant="danger" label={formatNumber(preview.would_block_admins) + ' ' + t('admin.ca.impact.tile.would_block_admins')} />
						</span>
					{/if}
				</div>

				<!-- Blocked user list — admins pinned to top with Badge (§c) -->
				{#if preview.blocked_users.length > 0}
					<ul class="promote-user-list" data-testid="promote-user-list">
						{#each preview.admin_users as user (user.id)}
							<li class="promote-user promote-user--admin" data-testid="promote-admin-user">
								<span
									class="promote-user__addr"
									title={user.address}
									aria-label={user.address}
								>
									{user.address}
								</span>
								<Badge variant="danger" label="admin" />
							</li>
						{/each}
						{#each preview.blocked_users.filter(u => !u.is_admin) as user (user.id)}
							<li class="promote-user" data-testid="promote-blocked-user">
								<span
									class="promote-user__addr"
									title={user.address}
									aria-label={user.address}
								>
									{user.address}
								</span>
							</li>
						{/each}
					</ul>
				{/if}

				<!-- Overflow footer (§g) -->
				{#if preview.total > preview.shown}
					<div class="promote-overflow" data-testid="promote-overflow">
						<span class="promote-overflow__text">
							{t('admin.ca.promote.showing_n_of_total', {
								shown: String(preview.shown),
								total: String(preview.total),
							})}
						</span>
						<Button variant="ghost" size="sm" data-testid="promote-csv">
							{t('admin.ca.promote.download_csv')}
						</Button>
					</div>
				{/if}

				<!-- Caution: ack checkbox (§b) -->
				<div class="promote-ack" data-testid="promote-ack">
					<Checkbox
						checked={ackChecked}
						label={isCaution
							? t('admin.ca.promote.caution_ack', { count: formatNumber(preview.would_block_users) })
							: t('admin.ca.promote.caution_ack', { count: formatNumber(preview.would_block_users) })}
						onchange={(e) => (ackChecked = (e.target as HTMLInputElement).checked)}
					/>
				</div>

				{#if isDanger}
					<!-- Danger: type-to-confirm (§c) + break-glass remediation panel -->
					<div class="promote-type-wrap">
						<p id={typeDescId} class="promote-type-desc">
							{t('admin.ca.promote.type_to_confirm', { name: policyName })}
						</p>
						<Input
							value={typeConfirm}
							oninput={(e) => (typeConfirm = (e.target as HTMLInputElement).value)}
							aria-describedby={typeDescId}
							placeholder={policyName}
							disabled={promoting}
							data-testid="promote-type-input"
							onkeydown={handleTypeKeydown}
						/>
					</div>

					<!-- Break-glass remediation (proactive, not only on BZ101 — §c).
					     The CTA is a real affordance: there is no break-glass ROUTE —
					     the remediation surface is the break-glass banner + set/edit
					     dialog on the CA page itself, so the CTA closes this dialog and
					     hands the admin back to it (the historical href pointed at a
					     route that exists nowhere and dead-ended the danger arc). -->
					<div class="promote-breakglass" data-testid="promote-breakglass">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
							<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
						</svg>
						<span>{t('admin.ca.promote.breakglass_note')}</span>
						<Button
							variant="ghost"
							size="sm"
							onclick={onClose}
							disabled={promoting}
							data-testid="promote-breakglass-link"
						>
							{t('admin.ca.promote.breakglass_cta')}
						</Button>
					</div>
				{/if}
			{/if}

			<!-- Server error after confirm attempt -->
			{#if promoteError}
				<div id={errorId} class="promote-error" role="alert" data-testid="promote-error">
					{promoteError}
				</div>
			{/if}
		{/if}
	{/snippet}

	{#snippet footer()}
		<!-- §i: initial focus on Cancel (safe secondary) — placed first in DOM for focus-trap -->
		<!-- §m: ≥44px touch targets via min-height -->
		<Button
			variant="secondary"
			onclick={onClose}
			disabled={promoting}
			data-testid="promote-cancel"
		>
			{t('admin.ca.promote.cancel')}
		</Button>
		<Button
			variant={isSafe ? 'primary' : 'danger'}
			disabled={!canConfirm || confirmBlocked || promoting}
			onclick={confirmPromote}
			data-testid="promote-confirm-btn"
		>
			{#if promoting}
				<Spinner size={16} />
				{t('admin.ca.promote.enforcing')}
			{:else if isSafe}
				{t('admin.ca.promote.confirm_safe')}
			{:else}
				{t('admin.ca.promote.confirm_danger')}
			{/if}
		</Button>
	{/snippet}
</Dialog>

<style>
	.promote-idle {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 0;
	}

	.promote-idle__text {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.promote-loading {
		display: flex;
		align-items: center;
		gap: 10px;
		color: var(--text-secondary);
		font-size: var(--text-sm);
		padding: 12px 0;
	}

	.promote-impact-error {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.promote-safe-banner {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--success-bg);
		color: var(--success-fg);
		font-size: var(--text-sm);
		border: 1px solid var(--success-solid);
	}

	.promote-danger-admins {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
		border: 1px solid var(--danger-solid);
		font-weight: var(--weight-semibold);
	}

	.promote-self-locked {
		margin: 0;
		padding: 6px 14px;
		font-size: var(--text-sm);
		color: var(--danger-fg);
		font-weight: var(--weight-semibold);
	}

	.promote-count {
		display: flex;
		align-items: baseline;
		gap: 12px;
		padding: 8px 0;
	}

	.promote-count__num {
		font-size: var(--text-3xl);
		font-weight: var(--weight-bold);
		font-family: var(--font-mono);
		color: var(--text-primary);
		/* cross-fade on count change — §j motion */
		transition: color var(--duration-base) var(--ease-out);
	}

	.promote-count__admins {
		display: flex;
		align-items: center;
	}

	.promote-user-list {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 200px;
		overflow-y: auto;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
	}

	.promote-user {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 6px 12px;
		font-size: var(--text-xs);
		border-bottom: 1px solid var(--border-subtle);
	}

	.promote-user:last-child { border-bottom: none; }

	.promote-user--admin {
		background: var(--danger-bg);
	}

	.promote-user__addr {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--text-primary);
	}

	.promote-overflow {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 4px;
	}

	.promote-overflow__text {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.promote-ack {
		padding: 4px 0;
	}

	.promote-type-wrap {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}

	.promote-type-desc {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.promote-breakglass {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--info-bg);
		color: var(--info-fg);
		font-size: var(--text-sm);
		border: 1px solid var(--info-solid, var(--border-default));
	}

	.promote-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.sr-only {
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

	/* §m touch targets ≥44px on coarse pointers */
	@media (pointer: coarse) {
		:global(.sj-dialog__footer .sj-btn) {
			min-height: 44px;
		}
	}

	/* §j reduced-motion guard */
	@media (prefers-reduced-motion: reduce) {
		.promote-count__num {
			transition: none;
		}
	}
</style>
