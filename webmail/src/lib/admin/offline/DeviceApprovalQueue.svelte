<!--
  DeviceApprovalQueue — admin offline console tab 2 (T18/#2a).
  Pending-device triage queue: Approve / Deny (routine) + Revoke (T2 type-to-confirm wipe).
  Props:
    devices   — pre-filtered device list (pending for #2a; parent drives filter+refetch)
    loading   — parent is fetching
    error     — load error string ('' = none)
    filter    — active filter ('pending' default; others disabled in #2a)
    pageSize  — rows per page (default 25; client-paginated for #2a)
    onRetry   — retry load
    onChanged — called after an action so parent can refetch
-->
<svelte:options runes={true} />

<script lang="ts">
	import { t, locale } from '$lib/i18n';
	import { get } from 'svelte/store';
	import { parseError } from '$lib/errors';
	import {
		Button, Badge, Card, Input, EmptyState, Select, Spinner, Dialog, IconButton, Tooltip, Pagination
	} from '$lib/components/ui';
	import { showToast } from '$lib/components/ui';
	import {
		adminOfflineApproveDevice,
		adminOfflineDenyDevice,
		adminOfflineRevokeDevice,
		adminOfflineWipeDevice,
		type OfflinePendingDevice,
	} from '$lib/admin/client';
	import { Monitor, Smartphone, Trash2, RefreshCw } from 'lucide-svelte';

	let {
		devices,
		loading,
		error,
		filter = 'pending',
		pageSize = 25,
		firstTime = false,
		onRetry,
		onChanged,
	}: {
		devices: OfflinePendingDevice[];
		loading: boolean;
		error: string;
		filter?: 'pending' | 'approved' | 'denied' | 'revoked';
		pageSize?: number;
		firstTime?: boolean;
		onRetry?: () => void;
		onChanged?: () => void;
	} = $props();

	$locale; // reactive on locale switch

	// ── Local device list for optimistic updates ─────────────────────────────────
	let localDevices = $state<OfflinePendingDevice[]>([]);
	$effect(() => { localDevices = [...devices]; });

	// ── Pagination ───────────────────────────────────────────────────────────────
	let page = $state(1);
	let pageSizeLocal = $state(25);
	$effect(() => { pageSizeLocal = pageSize; });

	const totalDevices = $derived(localDevices.length);
	const pagedDevices = $derived(localDevices.slice((page - 1) * pageSizeLocal, page * pageSizeLocal));
	const showPager = $derived(totalDevices > pageSizeLocal);

	// ── Number formatting ────────────────────────────────────────────────────────
	function fmt(n: number): string {
		return new Intl.NumberFormat(get(locale)).format(n);
	}

	const showingText = $derived(
		showPager
			? t('admin.offline.devices.showing_of', { shown: fmt(pagedDevices.length), total: fmt(totalDevices) })
			: ''
	);

	const countText = $derived(t('admin.offline.devices.count', { n: String(totalDevices) }));

	// ── Aria-live regions ────────────────────────────────────────────────────────
	let liveStatus     = $state('');   // role="status" aria-live="polite"
	let liveAssertive  = $state('');   // aria-live="assertive" (no role — avoids double alert)

	// Clear on next action so repeated outcomes re-announce
	function clearLive() { liveStatus = ''; liveAssertive = ''; }

	// ── Reduced-motion guard ─────────────────────────────────────────────────────
	// ponytail: read once at render — matchMedia is stable; no JS-driven animation
	// so we just remove from state immediately (CSS handles the visual transition).
	// Guard against jsdom (no matchMedia by default); the REDUCED-MOTION test stubs it.
	const reducedMotion = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
		? window.matchMedia('(prefers-reduced-motion: reduce)').matches
		: false;

	// ── Compact (narrow-viewport) flag ───────────────────────────────────────────
	// ponytail: same read-once pattern as reducedMotion; controls which DOM branch
	// renders (card list vs table) so jsdom tests never see duplicate buttons.
	// Reactive resize upgrade: replace with $state + $effect + addEventListener.
	const compact = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
		? window.matchMedia('(max-width: 640px)').matches
		: false;

	// ── Platform badge ───────────────────────────────────────────────────────────
	type Platform = OfflinePendingDevice['platform'];
	const statusBadgeVariant: Record<OfflinePendingDevice['offline_approval'], 'neutral'|'success'|'warning'|'danger'> = {
		pending:  'warning',
		approved: 'success',
		denied:   'neutral',  // brief §3: denied is neutral, not danger
		revoked:  'danger',
	};

	// ── Approve ──────────────────────────────────────────────────────────────────
	async function approve(device: OfflinePendingDevice) {
		clearLive();
		// Optimistic removal — CSS transition is purely decorative; state drives the DOM
		localDevices = localDevices.filter((d) => d.id !== device.id);
		try {
			await adminOfflineApproveDevice(device.id);
			liveStatus = t('admin.offline.devices.approved_announce', { user: device.user_email ?? '' });
			showToast(t('admin.offline.devices.approved'));
			onChanged?.();
		} catch (e) {
			// Restore the row and surface the failure
			localDevices = [...localDevices, device];
			liveAssertive = t('admin.offline.devices.action_failed');
			showToast(t('admin.offline.devices.action_failed'));
		}
	}

	// ── Deny dialog ──────────────────────────────────────────────────────────────
	let denyTarget = $state<OfflinePendingDevice | null>(null);
	let denyOpen   = $state(false);
	let denyBusy   = $state(false);

	function openDeny(device: OfflinePendingDevice) {
		denyTarget = device;
		denyOpen   = true;
	}
	function closeDeny() { denyOpen = false; denyTarget = null; }

	async function confirmDeny() {
		if (!denyTarget) return;
		denyBusy = true;
		const target = denyTarget;
		try {
			await adminOfflineDenyDevice(target.id);
			closeDeny();
			localDevices = localDevices.filter((d) => d.id !== target.id);
			liveStatus = t('admin.offline.devices.denied_announce', { user: target.user_email ?? '' });
			showToast(t('admin.offline.devices.denied'));
			onChanged?.();
		} catch (e) {
			liveAssertive = t('admin.offline.devices.action_failed');
			showToast(parseError(e).message);
		} finally {
			denyBusy = false;
		}
	}

	// ── Revoke dialog (T2 type-to-confirm) ───────────────────────────────────────
	let revokeTarget = $state<OfflinePendingDevice | null>(null);
	let revokeOpen   = $state(false);
	let revokeBusy   = $state(false);
	let revokeInput  = $state('');
	let revokeError  = $state('');

	const revokeNameMatch = $derived(
		revokeTarget !== null && revokeInput === revokeTarget.device_name
	);

	function openRevoke(device: OfflinePendingDevice) {
		revokeTarget = device;
		revokeInput  = '';
		revokeError  = '';
		revokeOpen   = true;
	}
	function closeRevoke() { revokeOpen = false; revokeTarget = null; revokeError = ''; }

	async function confirmRevoke() {
		if (!revokeTarget || !revokeNameMatch) return;
		revokeBusy  = true;
		revokeError = '';
		const target = revokeTarget;
		try {
			await adminOfflineRevokeDevice(target.id);
			closeRevoke();
			localDevices = localDevices.filter((d) => d.id !== target.id);
			liveStatus = t('admin.offline.devices.revoked_announce', { device: target.device_name });
			showToast(t('admin.offline.devices.revoked', { device: target.device_name }));
			onChanged?.();
		} catch (e) {
			// Keep dialog open; in-dialog role="alert" is the unmissable surface
			revokeError = t('admin.offline.devices.revoke.failed', { message: parseError(e).message });
			liveAssertive = revokeError;
		} finally {
			revokeBusy = false;
		}
	}

	// ── Remote-wipe dialog (T2 type-to-confirm, #2b Task 5) ─────────────────────
	let wipeTarget = $state<OfflinePendingDevice | null>(null);
	let wipeOpen   = $state(false);
	let wipeBusy   = $state(false);
	let wipeInput  = $state('');
	let wipeError  = $state('');

	const wipeNameMatch = $derived(
		wipeTarget !== null && wipeInput.trim() === wipeTarget.device_name
	);

	function openWipe(device: OfflinePendingDevice) {
		wipeTarget = device;
		wipeInput  = '';
		wipeError  = '';
		wipeOpen   = true;
	}
	function closeWipe() { wipeOpen = false; wipeTarget = null; wipeError = ''; }

	async function confirmWipe() {
		if (!wipeTarget || !wipeNameMatch) return;
		wipeBusy  = true;
		wipeError = '';
		const target = wipeTarget;
		try {
			await adminOfflineWipeDevice(target.id);
			closeWipe();
			liveStatus = t('admin.offline.wipe_requested');
			showToast(t('admin.offline.wipe_requested'));
			onChanged?.();
		} catch (e) {
			// Keep dialog open; in-dialog role="alert" is the unmissable surface
			wipeError = t('admin.offline.wipe_error');
			liveAssertive = wipeError;
		} finally {
			wipeBusy = false;
		}
	}

	// ── Platform label ───────────────────────────────────────────────────────────
	function platformLabel(p: Platform): string {
		return t(`admin.offline.devices.platform.${p}`);
	}

	// ── Relative time ────────────────────────────────────────────────────────────
	function relativeTime(iso: string): string {
		try {
			const diff = (Date.now() - new Date(iso).getTime()) / 1000;
			if (diff < 60)   return new Intl.RelativeTimeFormat(get(locale), { numeric: 'always' }).format(-Math.round(diff), 'second');
			if (diff < 3600) return new Intl.RelativeTimeFormat(get(locale), { numeric: 'always' }).format(-Math.round(diff / 60), 'minute');
			if (diff < 86400) return new Intl.RelativeTimeFormat(get(locale), { numeric: 'always' }).format(-Math.round(diff / 3600), 'hour');
			return new Intl.RelativeTimeFormat(get(locale), { numeric: 'always' }).format(-Math.round(diff / 86400), 'day');
		} catch {
			return iso;
		}
	}
</script>

<!-- Aria-live regions: polite for success, assertive for failure (no role="alert" — avoids double with in-dialog alert) -->
<div role="status" aria-live="polite" aria-atomic="true" class="sj-daq__vh">{liveStatus}</div>
<div aria-live="assertive" aria-atomic="true" class="sj-daq__vh">{liveAssertive}</div>

<!-- ── Header strip ──────────────────────────────────────────────────────────── -->
<div class="sj-daq__header">
	<div class="sj-daq__header-left">
		<span class="sj-daq__title">{t('admin.offline.devices.title')}</span>
		{#if totalDevices > 0}
			<!-- count when non-zero; =0 form lives only in EmptyState to avoid duplicate text -->
			<span class="sj-daq__showing">{showingText || countText}</span>
		{/if}
	</div>
	<div class="sj-daq__header-right">
		<!-- M1 Select: focus-ring + label association match other admin selects; children snippet supports disabled options -->
		<Select
			value={filter}
			aria-label={t('admin.offline.devices.filter')}
			onchange={() => { page = 1; }}
		>
			{#snippet children()}
				<option value="pending">{t('device.status.pending')}</option>
				<option value="approved" disabled>{t('device.status.approved')}</option>
				<option value="denied"   disabled>{t('device.status.denied')}</option>
				<option value="revoked"  disabled>{t('device.status.revoked')}</option>
			{/snippet}
		</Select>
		<IconButton
			label={t('admin.offline.devices.refresh')}
			disabled={loading}
			onclick={() => onRetry?.()}
		>
			{#if loading}
				<Spinner size={16} />
			{:else}
				<RefreshCw size={16} aria-hidden="true" />
			{/if}
		</IconButton>
	</div>
</div>

<!-- ── Error banner ───────────────────────────────────────────────────────────── -->
{#if error}
	<div role="alert" class="sj-daq__error">
		<span>{error}</span>
		{#if onRetry}
			<Button variant="secondary" size="sm" onclick={onRetry}>{t('common.retry')}</Button>
		{/if}
	</div>
{/if}

<!-- ── Loading skeleton ───────────────────────────────────────────────────────── -->
{#if loading}
	<div class="sj-daq__skeletons" aria-hidden="true">
		{#each [1, 2, 3, 4, 5] as _}
			<div class="sj-daq__skeleton-row"></div>
		{/each}
	</div>

<!-- ── Empty state ────────────────────────────────────────────────────────────── -->
{:else if localDevices.length === 0}
	{#if firstTime}
		<Card>
			{#snippet children()}
				<p class="sj-daq__first-time">{t('admin.offline.devices.first_time')}</p>
			{/snippet}
		</Card>
	{/if}
	<EmptyState
		watermark
		title={t('admin.offline.devices.empty')}
	>
		{#snippet action()}
			<p class="sj-daq__empty-sub">{t('admin.offline.devices.empty_sub')}</p>
			<Button variant="secondary" onclick={() => onRetry?.()}>
				{t('admin.offline.devices.refresh')}
			</Button>
		{/snippet}
	</EmptyState>

<!-- ── Device table / card list (JS-switched by compact flag) ────────────────── -->
{:else}
	{#if compact}
		<!-- Narrow-viewport card list (each device = Card with full-width action row) -->
		<div class="sj-daq__card-list">
			{#each pagedDevices as device (device.id)}
				<Card title={device.user_email ?? '—'}>
					{#snippet children()}
						<div class="sj-daq__card-meta">
							<span class="sj-daq__card-device">{device.device_name}</span>
							<span class="sj-daq__platform">
								{#if device.platform === 'desktop'}
									<Monitor size={14} aria-hidden="true" />
								{:else}
									<Smartphone size={14} aria-hidden="true" />
								{/if}
								{platformLabel(device.platform)} · {relativeTime(device.last_seen_at)}
							</span>
						</div>
						<div class="sj-daq__card-actions">
							{#if device.offline_approval === 'pending'}
								<Button
									variant="primary"
									size="sm"
									aria-label={t('admin.offline.devices.approve_aria', { user: device.user_email ?? '', device: device.device_name })}
									onclick={() => approve(device)}
								>{t('admin.offline.devices.approve')}</Button>
								<Button
									variant="ghost"
									size="sm"
									aria-label={t('admin.offline.devices.deny_aria', { user: device.user_email ?? '', device: device.device_name })}
									onclick={() => openDeny(device)}
								>{t('admin.offline.devices.deny')}</Button>
							{:else if device.offline_approval === 'approved'}
								<Button
									variant="danger"
									size="sm"
									aria-label={t('admin.offline.devices.revoke_aria', { user: device.user_email ?? '', device: device.device_name })}
									onclick={() => openRevoke(device)}
								>
									{#snippet icon()}<Trash2 size={14} aria-hidden="true" />{/snippet}
									{t('admin.offline.devices.revoke')}
								</Button>
								<Button
									variant="danger"
									size="sm"
									aria-label={t('admin.offline.wipe_aria', { user: device.user_email ?? '', device: device.device_name })}
									onclick={() => openWipe(device)}
								>
									{t('admin.offline.wipe_device')}
								</Button>
							{:else}
								<Badge
									variant={statusBadgeVariant[device.offline_approval]}
									label={t(`device.status.${device.offline_approval}`)}
								/>
								{#if device.wipe_acked_at}
									<Badge variant="neutral" label={t('admin.offline.wiped', { date: device.wipe_acked_at })} />
								{:else if device.wipe_requested}
									<Badge variant="warning" label={t('admin.offline.wipe_pending')} />
								{/if}
							{/if}
						</div>
					{/snippet}
				</Card>
			{/each}
		</div>
	{:else}
		<!-- Wide-viewport table -->
		<!-- ponytail: plain table (not M1 Table) — needs id-keying for optimistic removal
		     and T extends Record<string,unknown> is incompatible with OfflinePendingDevice.
		     Matches AdminSignInActivity.svelte precedent. -->
		<div class="sj-daq__table-wrap">
			<table class="sj-daq__table">
				<thead>
					<tr>
						<th scope="col">{t('admin.offline.devices.col_user')}</th>
						<th scope="col">{t('admin.offline.devices.col_device')}</th>
						<th scope="col">{t('admin.offline.devices.col_platform')}</th>
						<th scope="col">{t('admin.offline.devices.col_lastseen')}</th>
						<th scope="col">{t('admin.offline.devices.col_actions')}</th>
					</tr>
				</thead>
				<tbody>
					{#each pagedDevices as device (device.id)}
						<tr class:sj-daq__row--reduced={reducedMotion}>
							<!-- User -->
							<td>
								<Tooltip text={device.user_email ?? ''}>
									<span class="sj-daq__truncate" title={device.user_email}>{device.user_email ?? '—'}</span>
								</Tooltip>
							</td>
							<!-- Device name -->
							<td>
								<Tooltip text={device.device_name}>
									<span class="sj-daq__truncate" title={device.device_name}>{device.device_name}</span>
								</Tooltip>
							</td>
							<!-- Platform -->
							<td>
								<span class="sj-daq__platform">
									{#if device.platform === 'desktop'}
										<Monitor size={14} aria-hidden="true" />
									{:else}
										<Smartphone size={14} aria-hidden="true" />
									{/if}
									<span>{platformLabel(device.platform)}</span>
								</span>
							</td>
							<!-- Last seen -->
							<td class="sj-daq__mono">{relativeTime(device.last_seen_at)}</td>
							<!-- Actions -->
							<td>
								<div class="sj-daq__actions">
									{#if device.offline_approval === 'pending'}
										<Button
											variant="primary"
											size="sm"
											aria-label={t('admin.offline.devices.approve_aria', { user: device.user_email ?? '', device: device.device_name })}
											onclick={() => approve(device)}
										>{t('admin.offline.devices.approve')}</Button>
										<Button
											variant="ghost"
											size="sm"
											aria-label={t('admin.offline.devices.deny_aria', { user: device.user_email ?? '', device: device.device_name })}
											onclick={() => openDeny(device)}
										>{t('admin.offline.devices.deny')}</Button>
									{:else if device.offline_approval === 'approved'}
										<Button
											variant="danger"
											size="sm"
											aria-label={t('admin.offline.devices.revoke_aria', { user: device.user_email ?? '', device: device.device_name })}
											onclick={() => openRevoke(device)}
										>
											{#snippet icon()}<Trash2 size={14} aria-hidden="true" />{/snippet}
											{t('admin.offline.devices.revoke')}
										</Button>
										<Button
											variant="danger"
											size="sm"
											aria-label={t('admin.offline.wipe_aria', { user: device.user_email ?? '', device: device.device_name })}
											onclick={() => openWipe(device)}
										>
											{t('admin.offline.wipe_device')}
										</Button>
									{:else}
										<!-- denied/revoked: show status badge + wipe state -->
										<Badge
											variant={statusBadgeVariant[device.offline_approval]}
											label={t(`device.status.${device.offline_approval}`)}
										/>
										{#if device.wipe_acked_at}
											<Badge variant="neutral" label={t('admin.offline.wiped', { date: device.wipe_acked_at })} />
										{:else if device.wipe_requested}
											<Badge variant="warning" label={t('admin.offline.wipe_pending')} />
										{/if}
									{/if}
								</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}

	{#if showPager}
		<nav aria-label={t('common.pagination')}>
			<Pagination
				{page}
				pageSize={pageSizeLocal}
				total={totalDevices}
				onPageChange={(p) => { page = p; }}
				onPageSizeChange={(s) => { pageSizeLocal = s; page = 1; }}
			/>
		</nav>
	{/if}
{/if}

<!-- ── Deny dialog (light confirm — deny is reversible) ──────────────────────── -->
{#if denyTarget}
	<Dialog
		open={denyOpen}
		title={t('admin.offline.devices.deny.title')}
		onClose={closeDeny}
	>
		{#snippet children()}
			<p>
				{t('admin.offline.devices.deny.body', {
					user: denyTarget!.user_email ?? '',
					device: denyTarget!.device_name,
				})}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="secondary" onclick={closeDeny} disabled={denyBusy}>
				{t('common.cancel')}
			</Button>
			<Button variant="danger" onclick={confirmDeny} disabled={denyBusy}>
				{#if denyBusy}<Spinner size={16} />{/if}
				{t('admin.offline.devices.deny.confirm')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- ── Remote-wipe dialog (T2 type-to-confirm, #2b Task 5) ──────────────────── -->
{#if wipeTarget}
	<Dialog
		open={wipeOpen}
		title={t('admin.offline.wipe_title')}
		onClose={closeWipe}
	>
		{#snippet children()}
			<!-- Blast radius first — AT users hear consequence before the input -->
			<p id="sj-daq-wipe-blast">
				{t('admin.offline.wipe_body', {
					device: wipeTarget!.device_name,
					user:   wipeTarget!.user_email ?? '',
				})}
			</p>
			<!-- Type-to-confirm: must match full (untruncated) device name -->
			<div class="sj-daq__revoke-input">
				<Input
					label={t('admin.offline.wipe_confirm_hint', { word: wipeTarget!.device_name })}
					bind:value={wipeInput}
					aria-label={t('admin.offline.wipe_confirm_aria')}
					aria-describedby="sj-daq-wipe-blast"
					disabled={wipeBusy}
					autocomplete="off"
				/>
			</div>
			{#if wipeError}
				<div role="alert" class="sj-daq__revoke-error">{wipeError}</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<!-- Cancel has initial focus (safe default — shared-doc §2) -->
			<Button variant="secondary" onclick={closeWipe} disabled={wipeBusy}>
				{t('common.cancel')}
			</Button>
			<Button
				variant="danger"
				onclick={confirmWipe}
				disabled={wipeBusy || !wipeNameMatch}
				aria-disabled={wipeNameMatch ? 'false' : 'true'}
			>
				{#if wipeBusy}<Spinner size={16} label={t('admin.offline.wiping')} />{/if}
				{t('admin.offline.wipe_confirm')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- ── Revoke dialog (T2 type-to-confirm — irreversible remote wipe) ─────────── -->
{#if revokeTarget}
	<Dialog
		open={revokeOpen}
		title={t('admin.offline.devices.revoke.title')}
		onClose={closeRevoke}
	>
		{#snippet children()}
			<!-- Danger header strip -->
			<div class="sj-daq__revoke-danger" aria-hidden="true">
				<Trash2 size={20} />
			</div>
			<!-- Blast radius — aria-describedby wired to the type-to-confirm input -->
			<p id="sj-daq-revoke-blast">
				{t('admin.offline.devices.revoke.blast', {
					user: revokeTarget!.user_email ?? '',
					device: revokeTarget!.device_name,
					platform: platformLabel(revokeTarget!.platform),
				})}
			</p>
			<p class="sj-daq__revoke-note">{t('admin.offline.devices.revoke.selective_note')}</p>

			<!-- Type-to-confirm input -->
			<div class="sj-daq__revoke-input">
				<Input
					label={t('admin.offline.devices.revoke.type_label')}
					bind:value={revokeInput}
					aria-describedby="sj-daq-revoke-blast"
					disabled={revokeBusy}
					autocomplete="off"
				/>
				{#if revokeNameMatch}
					<p class="sj-daq__revoke-hint" aria-live="polite">
						{t('admin.offline.devices.revoke.match_hint')}
					</p>
				{/if}
			</div>

			<!-- In-dialog failure alert (unmissable: wipe did NOT happen) -->
			{#if revokeError}
				<div role="alert" class="sj-daq__revoke-error">{revokeError}</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="secondary" onclick={closeRevoke} disabled={revokeBusy}>
				{t('common.cancel')}
			</Button>
			<Button
				variant="danger"
				onclick={confirmRevoke}
				disabled={revokeBusy || !revokeNameMatch}
				aria-disabled={revokeNameMatch ? 'false' : 'true'}
			>
				{#if revokeBusy}<Spinner size={16} />{/if}
				{t('admin.offline.devices.revoke.confirm')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	/* Visually hidden but AT-accessible */
	.sj-daq__vh {
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

	/* Header */
	.sj-daq__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 12px 0 8px;
		font-family: var(--font-sans);
	}
	.sj-daq__header-left {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.sj-daq__header-right {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-shrink: 0;
	}
	.sj-daq__title {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}
	.sj-daq__showing {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-mono);
	}

	/* Error banner */
	.sj-daq__error {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 10px 14px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		margin-block: 8px;
	}

	/* Loading skeleton */
	.sj-daq__skeletons {
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 8px 0;
	}
	.sj-daq__skeleton-row {
		height: 44px;
		border-radius: var(--radius-sm);
		background: var(--surface-hover);
		animation: sj-daq-shimmer 1.4s ease-in-out infinite;
	}

	@keyframes sj-daq-shimmer {
		0%, 100% { opacity: 1; }
		50%       { opacity: 0.45; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-daq__skeleton-row { animation: none; }
	}

	/* Empty sub-text */
	.sj-daq__empty-sub {
		margin: 0 0 8px;
		font-size: var(--text-sm);
		color: var(--text-caption);
		font-family: var(--font-sans);
		text-align: center;
		max-width: 360px;
	}

	/* Table */
	.sj-daq__table-wrap {
		overflow-x: auto;
	}
	.sj-daq__table {
		width: 100%;
		border-collapse: collapse;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sj-daq__table th {
		height: var(--row-height);
		padding: 0 12px;
		text-align: start;
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		border-bottom: 1px solid var(--border-subtle);
		white-space: nowrap;
	}
	.sj-daq__table td {
		height: 44px; /* touch target */
		min-height: 44px;
		padding: 0 12px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-daq__table tbody tr {
		transition: background var(--duration-fast) var(--ease-out),
		            opacity var(--duration-base) var(--ease-out),
		            height var(--duration-base) var(--ease-out);
	}
	.sj-daq__table tbody tr:hover {
		background: var(--surface-hover);
	}
	/* Instant removal under reduced motion */
	@media (prefers-reduced-motion: reduce) {
		.sj-daq__table tbody tr {
			transition: none;
		}
	}
	.sj-daq__mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-caption);
	}

	/* Truncation */
	.sj-daq__truncate {
		display: block;
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* Platform cell */
	.sj-daq__platform {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	/* Action buttons — logical properties for RTL */
	.sj-daq__actions {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap; /* de +35% expansion: buttons wrap rather than clip */
	}

	/* Revoke dialog danger strip */
	.sj-daq__revoke-danger {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 12px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		margin-block-end: 12px;
	}
	.sj-daq__revoke-note {
		margin: 4px 0 12px;
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-sans);
	}
	.sj-daq__revoke-input {
		margin-block-start: 12px;
	}
	.sj-daq__revoke-hint {
		margin: 4px 0 0;
		font-size: var(--text-xs);
		color: var(--success-fg);
		font-family: var(--font-sans);
	}
	.sj-daq__revoke-error {
		margin-block-start: 10px;
		padding: 8px 10px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		font-family: var(--font-sans);
	}

	/* First-time info */
	.sj-daq__first-time {
		margin: 0;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	/* Mobile card list — rendered only when JS compact flag is true */
	.sj-daq__card-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding-block: 8px;
	}
	.sj-daq__card-meta {
		display: flex;
		flex-direction: column;
		gap: 4px;
		margin-block-end: 12px;
	}
	.sj-daq__card-device {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		font-family: var(--font-sans);
	}
	/* Card action row: full-width, buttons grow equally, ≥44px touch target */
	.sj-daq__card-actions {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
	}
	.sj-daq__card-actions :global(button) {
		flex: 1;
		min-height: 44px;
	}
</style>
