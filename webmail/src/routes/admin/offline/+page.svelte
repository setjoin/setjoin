<!--
  /admin/offline — offline mail console shell (#2a T19).
  Master toggle card + Tabs(Policies | Devices).
  Owns fetches; passes presentational props to T17 OfflinePolicyEditor + T18 DeviceApprovalQueue.
-->
<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		Card, Badge, Button, Switch, Spinner, Dialog, Tabs, type TabItem, showToast,
	} from '$lib/components/ui';
	import {
		adminOfflineGetEnabled,
		adminOfflineSetEnabled,
		adminOfflinePolicyList,
		adminOfflineListPendingDevices,
		type OfflinePolicy,
		type OfflinePendingDevice,
	} from '$lib/admin/client';
	import OfflinePolicyEditor from '$lib/admin/offline/OfflinePolicyEditor.svelte';
	import DeviceApprovalQueue from '$lib/admin/offline/DeviceApprovalQueue.svelte';

	// ── Master toggle state ──────────────────────────────────────────────────────
	let masterEnabled = $state(false);
	let masterLoading = $state(true);   // spinner until first fetch resolves
	let masterBusy    = $state(false);  // writing the toggle
	let masterError   = $state('');     // inline alert on write failure

	// ── Policy tab state ─────────────────────────────────────────────────────────
	let policies       = $state<OfflinePolicy[]>([]);
	let policiesLoading = $state(true);
	let policiesError   = $state('');

	// ── Device tab state ─────────────────────────────────────────────────────────
	let devices        = $state<OfflinePendingDevice[]>([]);
	let devicesLoading  = $state(true);
	let devicesError    = $state('');
	let firstTime       = $state(false);

	// ── Tab ──────────────────────────────────────────────────────────────────────
	let activeTab = $state('policies');
	const tabs = $derived<TabItem[]>([
		{ id: 'policies', label: t('admin.offline.tab.policies') },
		{ id: 'devices',  label: t('admin.offline.tab.devices'), count: devices.length || null },
	]);

	// ── ARIA-live regions ────────────────────────────────────────────────────────
	// ponytail: two regions — one polite (status, success), one alert (failure).
	// The disable-confirm dialog's footer also surfaces a role="alert" on write error.
	let liveStatus = $state('');
	let liveAlert  = $state('');

	// ── Disable-confirm dialog ───────────────────────────────────────────────────
	let disableDialogOpen = $state(false);
	let disableBusy       = $state(false);

	// ── Initial data fetch ───────────────────────────────────────────────────────
	async function loadMaster() {
		try {
			masterEnabled = await adminOfflineGetEnabled();
		} catch {
			masterEnabled = false; // default OFF on failure; user can retry via toggle
		} finally {
			masterLoading = false;
		}
	}

	async function loadPolicies() {
		policiesLoading = true;
		policiesError   = '';
		try {
			policies = await adminOfflinePolicyList();
		} catch (e) {
			policiesError = parseError(e).message;
		} finally {
			policiesLoading = false;
		}
	}

	async function loadDevices() {
		devicesLoading = true;
		devicesError   = '';
		try {
			devices = await adminOfflineListPendingDevices();
			// First-time heuristic: enabled + no devices yet → show the info card
			firstTime = masterEnabled && devices.length === 0;
		} catch (e) {
			devicesError = parseError(e).message;
		} finally {
			devicesLoading = false;
		}
	}

	$effect(() => {
		loadMaster();
		loadPolicies();
		loadDevices();
	});

	// ── Toggle handler ───────────────────────────────────────────────────────────
	function handleToggleChange(e: Event) {
		const checked = (e.currentTarget as HTMLInputElement).checked;
		if (!checked) {
			// ON → OFF: require confirm
			disableDialogOpen = true;
		} else {
			// OFF → ON: safe, no confirm
			void doSetEnabled(true);
		}
	}

	async function doSetEnabled(enabled: boolean) {
		masterBusy  = true;
		masterError = '';
		liveAlert   = '';
		const prev  = masterEnabled;
		// Optimistic update
		masterEnabled = enabled;
		try {
			await adminOfflineSetEnabled(enabled);
			liveStatus = enabled
				? t('admin.offline.master.enabled_announce')
				: t('admin.offline.master.disabled_announce');
			if (enabled) {
				showToast(t('admin.offline.master.enabled_announce'));
			} else {
				showToast(t('admin.offline.master.disabled_announce'));
			}
		} catch (e) {
			// Revert optimistic update
			masterEnabled = prev;
			masterError   = t('admin.offline.master.toggle_error', { message: parseError(e).message });
			liveAlert     = masterError;
		} finally {
			masterBusy = false;
		}
	}

	// ── Disable confirm ──────────────────────────────────────────────────────────
	function cancelDisable() {
		disableDialogOpen = false;
	}

	async function confirmDisable() {
		disableBusy = true;
		try {
			await doSetEnabled(false);
			disableDialogOpen = false;
		} finally {
			disableBusy = false;
		}
	}
</script>

<!-- Visually-hidden ARIA-live regions -->
<div role="status" aria-live="polite"  aria-atomic="true" class="sj-offline-page__vh">{liveStatus}</div>
<div role="alert"  aria-live="assertive" aria-atomic="true" class="sj-offline-page__vh">{liveAlert}</div>

<!-- Page header -->
<header class="sj-offline-page__header">
	<div>
		<h1 class="sj-offline-page__title">{t('admin.offline.title')}</h1>
		<p  class="sj-offline-page__subtitle">{t('admin.offline.subtitle')}</p>
	</div>
</header>

<!-- Master toggle card -->
<Card>
	{#snippet children()}
		<div class="sj-offline-page__master">
			<div class="sj-offline-page__master-left">
				{#if masterLoading}
					<!-- ponytail: Spinner in place of the switch until fetch resolves -->
					<Spinner size={20} />
				{:else}
					<Switch
						checked={masterEnabled}
						label={t('admin.offline.master.label')}
						disabled={masterBusy}
						onchange={handleToggleChange}
					/>
				{/if}
			</div>
			<div class="sj-offline-page__master-right">
				{#if !masterLoading}
					<Badge
						variant={masterEnabled ? 'success' : 'neutral'}
						label={masterEnabled ? t('admin.offline.master.on') : t('admin.offline.master.off')}
					/>
				{/if}
			</div>
		</div>
		<!-- Toggle write-error alert (inline, role="alert" visible to AT) -->
		{#if masterError}
			<div role="alert" class="sj-offline-page__master-error">{masterError}</div>
		{/if}
	{/snippet}
</Card>

<!-- Tabs -->
<div class="sj-offline-page__tabs-wrap">
	<Tabs items={tabs} active={activeTab} onChange={(id) => { activeTab = id; }} />
</div>

<!-- Tab panels: cross-fade via CSS transition -->
<div class="sj-offline-page__panel">
	{#if activeTab === 'policies'}
		<OfflinePolicyEditor
			{policies}
			loading={policiesLoading}
			error={policiesError}
			master={masterEnabled}
			onRetry={loadPolicies}
			onSaved={loadPolicies}
		/>
	{:else}
		<DeviceApprovalQueue
			{devices}
			loading={devicesLoading}
			error={devicesError}
			{firstTime}
			onRetry={loadDevices}
			onChanged={loadDevices}
		/>
	{/if}
</div>

<!-- Disable-confirm dialog (T1: Cancel is the safe default) -->
<Dialog
	open={disableDialogOpen}
	title={t('admin.offline.master.disable_title')}
	onClose={cancelDisable}
>
	{#snippet children()}
		<p>{t('admin.offline.master.disable_body')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={cancelDisable} disabled={disableBusy}>
			{t('common.cancel')}
		</Button>
		<Button variant="danger" onclick={confirmDisable} disabled={disableBusy}>
			{#if disableBusy}<Spinner size={16} />{/if}
			{t('admin.offline.master.disable_confirm')}
		</Button>
	{/snippet}
</Dialog>

<style>
	/* Visually hidden for AT-only live regions */
	.sj-offline-page__vh {
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

	/* Page header */
	.sj-offline-page__header {
		margin-block-end: 16px;
	}
	.sj-offline-page__title {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}
	.sj-offline-page__subtitle {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}

	/* Master toggle card interior */
	.sj-offline-page__master {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		min-height: 44px; /* touch target */
		flex-wrap: wrap;
	}
	.sj-offline-page__master-left {
		display: flex;
		align-items: center;
		flex: 1;
		min-width: 0;
	}
	.sj-offline-page__master-right {
		flex-shrink: 0;
	}
	.sj-offline-page__master-error {
		margin-block-start: 10px;
		padding: 8px 12px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	/* Tabs strip */
	.sj-offline-page__tabs-wrap {
		margin-block: 16px 0;
	}

	/* Tab panel: cross-fade on tab change (reduced-motion = instant) */
	.sj-offline-page__panel {
		margin-block-start: 4px;
		transition: opacity var(--duration-fast) var(--ease-out);
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-offline-page__panel { transition: none; }
	}
</style>
