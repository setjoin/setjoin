<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { TriangleAlert } from 'lucide-svelte';
	import { t } from '$lib/i18n';
	import { logger } from '$lib/logger';
	import { parseError } from '$lib/errors';
	import { Card, Button, Slider, Spinner, EmptyState, Dialog, Progress, showToast, Toast } from '$lib/components/ui';
	import type { OfflineCaps } from '$lib/offline/caps';
	import { offlineAllowed } from '$lib/offline/caps'; // pure resolver: caps.allowed && bridgePresent
	import {
		getOfflineSizeEstimate,
		getOfflineWindow,
		saveOfflineWindow,
		getMailboxQuota
	} from '$lib/api/offline';
	import {
		isOfflineAvailable,
		getCacheSizeBytes,
		getFreeSpaceBytes,
		clearOfflineCache,
		syncNow
	} from '$lib/offline/storeFacade';
	import { bytesForWindow, fitWindowToSpace, formatBytes, type SizeEstimate } from '$lib/offline/sizeFit';
	import { OFFLINE_WINDOWS, windowLabelKey, type OfflineWindow } from '$lib/offline/window';

	// Test-only seam: inject server caps without a network fetch (mirrors settings/+page.svelte).
	// ponytail: __ prefix marks a test hook, not a product API; undefined in production.
	let { __offlineCaps = undefined }: { __offlineCaps?: OfflineCaps } = $props();

	// Native-offline pivot: the Offline card renders ONLY in a native shell whose
	// bridge advertises the offline-core 'mail' store. Plain browser → Cloud card only.
	const offlineAvailable = isOfflineAvailable();

	// Server-resolved offline caps (GET /user/offline/caps); undefined until loaded → inert.
	let liveCaps = $state<OfflineCaps | undefined>(undefined);

	let estimate = $state<SizeEstimate>({ buckets: [] });
	let windowSel = $state<OfflineWindow>('30d');
	let cloudUsed = $state(0); // this user's total mailbox bytes used (GET /user/quota)
	let cloudQuota = $state(0); // this user's total mailbox quota bytes
	let cacheUsed = $state(0); // on-disk size of the 'mail' store (from native bridge)
	let deviceFree = $state(0); // free space on device volume (from native bridge)
	let loading = $state(true);
	let loadError = $state('');
	let actionError = $state('');
	let syncing = $state(false);
	let confirmClear = $state(false);
	let clearing = $state(false);

	// PARTIAL / INERT: server caps not allowed (or no native bridge) → slider +
	// actions disabled, explainer shown. offlineAllowed = caps.allowed && bridgePresent.
	let inert = $derived(!offlineAllowed(liveCaps, offlineAvailable));

	let windowIndex = $derived(Math.max(0, OFFLINE_WINDOWS.indexOf(windowSel)));
	let stopLabels = $derived(OFFLINE_WINDOWS.map((w) => t(windowLabelKey(w))));
	let neededBytes = $derived(bytesForWindow(estimate, windowSel));
	// OVERFLOW: needed > free AND free is known (>0). deviceFree=0 means "unknown"
	// from the bridge — suppress danger to avoid a false alarm (EDGE case, brief §deviceFree unknown).
	let overflow = $derived(offlineAvailable && neededBytes > deviceFree && deviceFree > 0);
	// FIRST-RUN: native shell, caps allowed, cache empty → warm EmptyState with Sync-now CTA.
	let firstRun = $derived(offlineAvailable && !inert && cacheUsed === 0);
	const estimateId = 'sj-offline-estimate';

	async function load() {
		loading = true;
		loadError = '';
		try {
			let quota: { usedBytes: number; quotaBytes: number };
			[estimate, windowSel, quota] = await Promise.all([
				getOfflineSizeEstimate(),
				getOfflineWindow(),
				getMailboxQuota()
			]);
			cloudUsed = quota.usedBytes;
			cloudQuota = quota.quotaBytes;
			if (offlineAvailable) {
				// Device + cache sizes come from the NATIVE BRIDGE only — never
				// navigator.storage.estimate() (that browser quota API measured
				// the deleted IndexedDB cache; removed in the native-offline pivot).
				[cacheUsed, deviceFree] = await Promise.all([getCacheSizeBytes(), getFreeSpaceBytes()]);
			}
		} catch (e) {
			loadError = parseError(e).message;
			logger.error('settings/storage: load failed', e);
		}
		loading = false;
	}

	onMount(async () => {
		await load();
		// Resolve offline caps. Test seam injects them; production best-effort fetches.
		// Any failure leaves liveCaps undefined → the section stays inert (safe default).
		if (__offlineCaps !== undefined) {
			liveCaps = __offlineCaps;
		} else if (offlineAvailable) {
			try {
				const res = await fetch('/api/user/offline/caps', { credentials: 'include' });
				if (res.ok) liveCaps = (await res.json()) as OfflineCaps;
			} catch {
				// ponytail: inert on failure — no offline controls without a server allow.
			}
		}
	});

	async function commitWindow(w: OfflineWindow) {
		windowSel = w;
		actionError = '';
		try {
			await saveOfflineWindow(w);
			// ponytail: no toast on slider move — immediate UI feedback is enough;
			// toasting every slider stop would spam the user.
		} catch (e) {
			actionError = parseError(e).message;
			logger.error('settings/storage: save window failed', e);
		}
	}

	function onSlide(index: number) {
		if (inert || syncing) return;
		commitWindow(OFFLINE_WINDOWS[index]);
	}

	function fitToSpace() {
		commitWindow(fitWindowToSpace(estimate, deviceFree));
	}

	async function onConfirmClear() {
		clearing = true;
		actionError = '';
		try {
			await clearOfflineCache();
			cacheUsed = await getCacheSizeBytes(); // → 0 B; returns card to FIRST-RUN
			showToast(t('settings.storage.cache_cleared'));
			confirmClear = false;
		} catch (e) {
			actionError = parseError(e).message; // dialog stays open, Confirm re-enabled
			logger.error('settings/storage: clear cache failed', e);
		}
		clearing = false;
	}

	async function onSyncNow() {
		syncing = true;
		actionError = '';
		try {
			await syncNow();
			cacheUsed = await getCacheSizeBytes();
			showToast(t('settings.storage.sync_done'));
		} catch (e) {
			actionError = parseError(e).message;
			logger.error('settings/storage: sync now failed', e);
		}
		syncing = false;
	}
</script>

<div class="sj-storage-page">
	<h1 class="sj-page-title">{t('settings.storage.title')}</h1>

	{#if loading}
		<!-- LOADING: card-shaped skeleton + status spinner; slider not yet present -->
		<div class="sj-loading"><Spinner size={28} label={t('common.loading')} /></div>
	{:else if loadError}
		<!-- ERROR: inline alert with Retry — reassure-don't-alarm, never raw JSON -->
		<div class="sj-load-error" role="alert">
			<p>{t('settings.storage.load_error')}</p>
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>
	{:else}
		<!-- SECONDARY: Cloud card — real server-mailbox used/quota bar -->
		<Card title={t('settings.storage.cloud_card')}>
			<Progress value={cloudUsed} max={cloudQuota} label={t('settings.storage.cloud_card')} />
			<p class="sj-row">
				{t('settings.storage.cloud_used', {
					used: formatBytes(cloudUsed),
					quota: formatBytes(cloudQuota)
				})}
			</p>
		</Card>

		{#if offlineAvailable}
			<!-- PRIMARY: Offline card — slider + native-bridge size readouts -->
			<Card title={t('settings.storage.offline_card')}>
				{#if firstRun}
					<!-- EMPTY / FIRST-RUN: 0 B cached → warm first-run EmptyState, Sync now as CTA -->
					<EmptyState title={t('settings.storage.first_run')}>
						{#snippet action()}
							<Button variant="primary" size="sm" disabled={syncing} onclick={onSyncNow}>
								{#if syncing}<Spinner size={16} label={t('settings.storage.syncing')} />{/if}
								{syncing ? t('settings.storage.syncing') : t('settings.storage.sync_now')}
							</Button>
						{/snippet}
					</EmptyState>
				{:else}
					<p class="sj-row">
						{t('settings.storage.cache_used')}: <strong>{formatBytes(cacheUsed)}</strong>
					</p>
				{/if}
				<p class="sj-row">
					{t('settings.storage.device_free')}: <strong>{formatBytes(deviceFree)}</strong>
				</p>

				{#if inert}
					<!-- PARTIAL: caps falsy — explain, never a dead control with no reason -->
					<p class="sj-inert" role="note">{t('settings.storage.offline_inert')}</p>
				{/if}

				<div class="sj-window">
					<Slider
						label={t('settings.storage.window_label')}
						value={windowIndex}
						stops={stopLabels}
						oninput={onSlide}
						tone={overflow ? 'danger' : 'normal'}
						disabled={inert || syncing}
						describedById={estimateId}
					/>

					<!-- Estimate line: live region so overflow copy change is SR-announced -->
					<p
						id={estimateId}
						class="sj-estimate"
						class:sj-estimate--danger={overflow}
						role="status"
						aria-live="polite"
					>
						{#if overflow}<TriangleAlert size={16} aria-hidden="true" />{/if}
						{overflow
							? t('settings.storage.estimate_overflow', {
									needed: formatBytes(neededBytes),
									free: formatBytes(deviceFree)
								})
							: t('settings.storage.estimate', {
									needed: formatBytes(neededBytes),
									free: formatBytes(deviceFree)
								})}
					</p>

					<!-- Focus order: Fit to space → Sync now → Clear cache -->
					<div class="sj-actions">
						<!-- OVERFLOW: Fit to space promoted to primary — the one-click recovery -->
						<Button
							variant={overflow ? 'primary' : 'secondary'}
							size="sm"
							disabled={inert || syncing}
							onclick={fitToSpace}
						>
							{t('settings.storage.fit_to_space')}
						</Button>
						<Button variant="secondary" size="sm" disabled={inert || syncing} onclick={onSyncNow}>
							{#if syncing}<Spinner size={16} label={t('settings.storage.syncing')} />{/if}
							{syncing ? t('settings.storage.syncing') : t('settings.storage.sync_now')}
						</Button>
						<!-- Clear cache disabled when cache is empty (cacheUsed===0); no-op wipe is confusing -->
						<Button
							variant="secondary"
							size="sm"
							disabled={inert || syncing || cacheUsed === 0}
							onclick={() => (confirmClear = true)}
						>
							{t('settings.storage.clear_cache')}
						</Button>
					</div>
				</div>
			</Card>
		{/if}

		{#if actionError}
			<p class="sj-error" role="alert">{actionError}</p>
		{/if}
	{/if}
</div>

<!-- DANGEROUS ACTION: Clear cache confirm dialog (Tier-1 simple-confirm per shared-doc §2).
     Blast radius shown BEFORE the confirm; danger-styled Confirm; Cancel is safe default. -->
<Dialog
	open={confirmClear}
	title={t('settings.storage.clear_confirm_title')}
	onClose={() => (confirmClear = false)}
>
	<p>{t('settings.storage.clear_confirm_body', { size: formatBytes(cacheUsed) })}</p>
	{#if actionError}<p class="sj-error" role="alert">{actionError}</p>{/if}
	{#snippet footer()}
		<Button variant="ghost" size="sm" disabled={clearing} onclick={() => (confirmClear = false)}>
			{t('common.cancel')}
		</Button>
		<Button variant="danger" size="sm" disabled={clearing} onclick={onConfirmClear}>
			{#if clearing}<Spinner size={16} label={t('settings.storage.clearing')} />{/if}
			{t('settings.storage.clear_cache')}
		</Button>
	{/snippet}
</Dialog>

<Toast />

<style>
	.sj-storage-page {
		max-width: 640px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
		display: flex;
		flex-direction: column;
		gap: var(--space-4, 16px);
	}
	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}
	.sj-row {
		margin: 4px 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		/* UI-UX-PRO-MAX 2026-06-23: tabular figures so cached/free readouts don't
		   reflow as digit widths change while syncing ("6.0 MB" → "12.3 MB"). */
		font-variant-numeric: tabular-nums;
	}
	.sj-window {
		margin-top: var(--space-3, 12px);
		display: flex;
		flex-direction: column;
		gap: var(--space-3, 10px);
	}
	.sj-estimate {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: 0;
		/* UI-UX-PRO-MAX 2026-06-23: tabular figures so "≈ X needed vs Y free" keeps
		   stable width as the user drags the slider — no horizontal jitter, and the
		   normal↔overflow swap stays a pure color/copy change, not a reflow. */
		font-variant-numeric: tabular-nums;
	}
	/* OVERFLOW: the load-bearing "won't fit" treatment — danger color + glyph. */
	.sj-estimate--danger {
		color: var(--danger-fg);
		font-weight: var(--weight-medium);
	}
	.sj-inert {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.sj-actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2, 8px);
	}
	.sj-loading {
		display: flex;
		justify-content: center;
		padding: 32px;
	}
	.sj-load-error {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-2, 8px);
		padding: var(--space-4, 16px);
		background: var(--danger-bg);
		border-radius: var(--radius-md);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sj-error {
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
</style>
