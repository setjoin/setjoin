<svelte:options runes={true} />

<!--
	Chat compliance admin console (Chat A4a Task 12). One page, three tabs:
	Overview (the compliance officer's FIRST screen — design review #9) ·
	Retention policies (7-day grace + N4 re-arm, FIX 3 exposure guard) ·
	Channels (participant-projecting list + per-channel drill-in).
	Read gate: chat.compliance_view. Write gate: chat.compliance_manage.
	Copy sources named exactly by the plan: admin/(access)/approvals/+page.svelte
	(list table + inline confirm overlay shape), PolicyEditor.svelte (editor
	dialog shape) — see RetentionPolicyEditor.svelte / ChannelComplianceSheet.svelte.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Card, Button, Spinner, Tabs, Badge, Input, showToast } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatDateTime } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		adminGetChatComplianceOverview,
		adminPreviewChatPurge,
		adminListChatRetentionPolicies,
		adminDeleteChatRetentionPolicy,
		adminListChatChannels,
		type ChatComplianceOverview,
		type ChatRetentionPolicy,
		type ChatChannelRow,
		type ChatPurgePreview,
	} from '$lib/admin/client';
	import RetentionPolicyEditor from './RetentionPolicyEditor.svelte';
	import ChannelComplianceSheet from './ChannelComplianceSheet.svelte';
	import CaseHoldsPanel from './CaseHoldsPanel.svelte';
	import EDiscoveryPanel from './EDiscoveryPanel.svelte';
	import { ConfirmDestructive } from '$lib/components/ui';
	import { channelDisplayName, retentionLabel } from './channels.svelte';

	type TabId = 'overview' | 'policies' | 'channels' | 'holds' | 'ediscovery';

	let canView = $derived(
		hasPermission($adminPermissions, 'chat.compliance_view') ||
			hasPermission($adminPermissions, 'chat.compliance_manage')
	);
	let canManage = $derived(hasPermission($adminPermissions, 'chat.compliance_manage'));
	// D-A's SoD split, visible in the UI: chat.ediscovery is a DISTINCT
	// permission from chat.compliance_manage/_view — "may destroy"/"may
	// configure" does not imply "may read every employee's DMs" — so the
	// eDiscovery tab renders ONLY for a chat.ediscovery holder, not for
	// canManage/canView alone.
	let canEDiscovery = $derived(hasPermission($adminPermissions, 'chat.ediscovery'));

	let TABS = $derived<TabItem[]>([
		{ id: 'overview', label: t('admin.chatCompliance.tab.overview') },
		{ id: 'policies', label: t('admin.chatCompliance.tab.policies') },
		{ id: 'channels', label: t('admin.chatCompliance.tab.channels') },
		{ id: 'holds', label: t('admin.chatCompliance.tab.holds') },
		...(canEDiscovery ? [{ id: 'ediscovery', label: t('admin.chatCompliance.tab.ediscovery') }] : []),
	]);

	let activeTab = $state<TabId>('overview');

	let error = $state('');

	// ── overview ──────────────────────────────────────────────────────────────
	let overview = $state<ChatComplianceOverview | null>(null);
	let overviewLoading = $state(false);
	let overviewPreview = $state<ChatPurgePreview | null>(null);
	let overviewPreviewLoading = $state(false);

	async function loadOverview() {
		overviewLoading = true;
		error = '';
		try {
			overview = await adminGetChatComplianceOverview();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			overviewLoading = false;
		}
	}

	async function loadOverviewPreview() {
		overviewPreviewLoading = true;
		try {
			overviewPreview = await adminPreviewChatPurge();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			overviewPreviewLoading = false;
		}
	}

	// ── retention policies ───────────────────────────────────────────────────
	let policies = $state<ChatRetentionPolicy[]>([]);
	let policiesLoading = $state(false);
	let policyEditorOpen = $state(false);
	let policyEditTarget = $state<ChatRetentionPolicy | null>(null);
	let policyDeleteTarget = $state<ChatRetentionPolicy | null>(null);
	let policyDeleteExposed = $state(0);
	let policyDeleteConfirmOpen = $state(false);
	let policyDeleteBusy = $state(false);
	let policyDeleteError = $state('');

	async function loadPolicies() {
		policiesLoading = true;
		error = '';
		try {
			policies = await adminListChatRetentionPolicies();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			policiesLoading = false;
		}
	}

	function openCreatePolicy() {
		policyEditTarget = null;
		policyEditorOpen = true;
	}

	function openEditPolicy(p: ChatRetentionPolicy) {
		policyEditTarget = p;
		policyEditorOpen = true;
	}

	function onPolicySaved() {
		policyEditorOpen = false;
		showToast(t('admin.chatCompliance.policy.saved'));
		void loadPolicies();
	}

	async function requestDeletePolicy(p: ChatRetentionPolicy) {
		policyDeleteTarget = p;
		policyDeleteError = '';
		policyDeleteBusy = true;
		try {
			const conflict = await adminDeleteChatRetentionPolicy(p.id, false);
			if (conflict) {
				// FIX 3: refuses a delete that would shorten any channel's
				// effective retention — open the typed-DESTROY confirm and retry.
				policyDeleteExposed = conflict.exposedChannels;
				policyDeleteConfirmOpen = true;
			} else {
				showToast(t('admin.chatCompliance.policy.deleted'));
				policyDeleteTarget = null;
				void loadPolicies();
			}
		} catch (e) {
			error = parseError(e).message;
			policyDeleteTarget = null;
		} finally {
			policyDeleteBusy = false;
		}
	}

	async function confirmDeletePolicy() {
		if (!policyDeleteTarget) return;
		policyDeleteBusy = true;
		policyDeleteError = '';
		try {
			await adminDeleteChatRetentionPolicy(policyDeleteTarget.id, true);
			policyDeleteConfirmOpen = false;
			policyDeleteTarget = null;
			showToast(t('admin.chatCompliance.policy.deleted'));
			void loadPolicies();
		} catch (e) {
			policyDeleteError = parseError(e).message;
		} finally {
			policyDeleteBusy = false;
		}
	}

	// ── channels ──────────────────────────────────────────────────────────────
	let channelQuery = $state('');
	let channels = $state<ChatChannelRow[]>([]);
	let channelsLoading = $state(false);
	let sheetChannel = $state<ChatChannelRow | null>(null);
	let sheetOpen = $state(false);

	let userIdParam = $derived.by(() => {
		const raw = page.url.searchParams.get('userId');
		if (!raw) return null;
		const n = Number(raw);
		return Number.isFinite(n) ? n : null;
	});

	async function loadChannels() {
		channelsLoading = true;
		error = '';
		try {
			channels = await adminListChatChannels({ q: channelQuery || undefined, userId: userIdParam ?? undefined });
		} catch (e) {
			error = parseError(e).message;
		} finally {
			channelsLoading = false;
		}
	}

	function openChannel(c: ChatChannelRow) {
		sheetChannel = c;
		sheetOpen = true;
	}

	function onChannelChanged() {
		void loadChannels();
	}

	// ── tab switch ────────────────────────────────────────────────────────────
	function changeTab(id: string) {
		activeTab = id as TabId;
		error = '';
		loadTab(activeTab);
	}

	function loadTab(tab: TabId) {
		if (tab === 'overview') void loadOverview();
		else if (tab === 'policies') void loadPolicies();
		else if (tab === 'channels') void loadChannels();
		// 'holds' / 'ediscovery' are self-loading (their own onMount).
	}

	onMount(() => loadTab(activeTab));
</script>

<svelte:head><title>{t('admin.chatCompliance.title')} · setjoin</title></svelte:head>

<div class="cc-page">
	<div class="cc-header">
		<div>
			<h1 class="cc-title">{t('admin.chatCompliance.title')}</h1>
			<p class="cc-subtitle">{t('admin.chatCompliance.subtitle')}</p>
		</div>
		{#if canManage && activeTab === 'policies'}
			<Button variant="primary" onclick={openCreatePolicy}>
				<Icon name="Plus" size={16} />
				{t('admin.chatCompliance.policy.addPolicy')}
			</Button>
		{/if}
	</div>

	<Tabs items={TABS} active={activeTab} onChange={changeTab} />

	{#if error}<p class="cc-error" role="alert">{error}</p>{/if}

	{#if !canView}
		<Card><p class="cc-empty">{t('admin.chatCompliance.title')}</p></Card>
	{:else if activeTab === 'overview'}
		{#if overviewLoading}
			<div class="cc-loading"><Spinner /></div>
		{:else if overview}
			<div class="cc-stats">
				<Card>
					<p class="cc-stat__value">{overview.channelsUnderHold.length}</p>
					<p class="cc-stat__label">{t('admin.chatCompliance.overview.underHold', { n: String(overview.channelsUnderHold.length) })}</p>
				</Card>
				<Card>
					<p class="cc-stat__value">{overview.gxpChannels.length}</p>
					<p class="cc-stat__label">{t('admin.chatCompliance.overview.gxpChannels', { n: String(overview.gxpChannels.length) })}</p>
				</Card>
				<Card>
					<p class="cc-stat__value">{overview.channelsWithOverrides.length}</p>
					<p class="cc-stat__label">{t('admin.chatCompliance.overview.overrides', { n: String(overview.channelsWithOverrides.length) })}</p>
				</Card>
			</div>

			<Card>
				{#if overview.lastPurgeRun}
					<p>
						{t('admin.chatCompliance.overview.lastPurge', {
							date: formatDateTime(overview.lastPurgeRun.occurredAt),
							messages: String(overview.lastPurgeRun.messages),
							channels: String(overview.lastPurgeRun.channels),
						})}
					</p>
					{#if !overview.lastPurgeRun.drained}
						<p class="cc-warning" role="alert">{t('admin.chatCompliance.overview.notDrained')}</p>
					{/if}
				{:else}
					<p>{t('admin.chatCompliance.overview.lastPurgeNone')}</p>
				{/if}
				<p>{t('admin.chatCompliance.overview.nextRun', { date: formatDateTime(overview.nextRunAt) })}</p>
				<Button variant="ghost" size="sm" onclick={loadOverviewPreview} disabled={overviewPreviewLoading}>
					{t('admin.chatCompliance.overview.previewImpact')}
				</Button>
				{#if overviewPreview}
					<p class="cc-hint">
						{t('admin.chatCompliance.policy.previewNote', {
							messages: String(overviewPreview.totalMessages),
							channels: String(overviewPreview.totalChannels),
						})}
					</p>
				{/if}
			</Card>
		{/if}
	{:else if activeTab === 'policies'}
		{#if policiesLoading}
			<div class="cc-loading"><Spinner /></div>
		{:else if policies.length === 0}
			<Card>
				<div class="cc-empty-block">
					<p class="cc-empty__title">{t('admin.chatCompliance.policy.empty_title')}</p>
					<p class="cc-empty__body">{t('admin.chatCompliance.policy.empty_body')}</p>
					{#if canManage}
						<Button variant="primary" onclick={openCreatePolicy}>{t('admin.chatCompliance.policy.addPolicy')}</Button>
					{/if}
				</div>
			</Card>
		{:else}
			<Card flush>
				<div class="cc-scroll">
					<table class="cc-table">
						<thead>
							<tr>
								<th>{t('admin.chatCompliance.policy.col_name')}</th>
								<th>{t('admin.chatCompliance.policy.col_appliesTo')}</th>
								<th>{t('admin.chatCompliance.policy.col_duration')}</th>
								<th>{t('admin.chatCompliance.policy.col_enabled')}</th>
								<th>{t('admin.chatCompliance.policy.col_effective')}</th>
								{#if canManage}<th>{t('admin.chatCompliance.policy.col_actions')}</th>{/if}
							</tr>
						</thead>
						<tbody>
							{#each policies as p (p.id)}
								<tr>
									<td>{p.name}</td>
									<td>{t(`admin.chatCompliance.policy.appliesTo.${p.appliesTo}`)}</td>
									<td>{p.durationDays}</td>
									<td>{p.enabled ? t('admin.approvals.val_yes') : t('admin.approvals.val_no')}</td>
									<td>{t('admin.chatCompliance.policy.effectiveOn', { date: p.effectiveAt.slice(0, 10) })}</td>
									{#if canManage}
										<td class="cc-td-actions">
											<button type="button" class="cc-icon-btn" aria-label={t('admin.chatCompliance.policy.edit')} onclick={() => openEditPolicy(p)}>
												<Icon name="Pencil" size={16} />
											</button>
											<button type="button" class="cc-icon-btn cc-icon-btn--danger" aria-label={t('admin.chatCompliance.policy.delete')} onclick={() => requestDeletePolicy(p)}>
												<Icon name="Trash2" size={16} />
											</button>
										</td>
									{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</Card>
		{/if}
	{:else if activeTab === 'holds'}
		<CaseHoldsPanel {canManage} />
	{:else if activeTab === 'ediscovery'}
		{#if canEDiscovery}
			<EDiscoveryPanel />
		{/if}
	{:else}
		<!-- Channels -->
		<div class="cc-row">
			<Input
				label={t('admin.chatCompliance.channels.search_placeholder')}
				bind:value={channelQuery}
				onkeydown={(e: KeyboardEvent) => {
					if (e.key === 'Enter') void loadChannels();
				}}
			/>
			<Button variant="secondary" size="sm" onclick={loadChannels}>{t('admin.chatCompliance.channels.search_button')}</Button>
		</div>

		{#if channelsLoading}
			<div class="cc-loading"><Spinner /></div>
		{:else if channels.length === 0}
			<Card><p class="cc-empty">{t('admin.chatCompliance.channels.empty')}</p></Card>
		{:else}
			<Card flush>
				<div class="cc-scroll">
					<table class="cc-table">
						<thead>
							<tr>
								<th>{t('admin.chatCompliance.channels.col_name')}</th>
								<th>{t('admin.chatCompliance.channels.col_kind')}</th>
								<th>{t('admin.chatCompliance.channels.col_classification')}</th>
								<th>{t('admin.chatCompliance.channels.col_retention')}</th>
								<th>{t('admin.chatCompliance.channels.col_hold')}</th>
							</tr>
						</thead>
						<tbody>
							{#each channels as c (c.id)}
								<tr
									class="cc-row-clickable"
									role="button"
									tabindex="0"
									onclick={() => openChannel(c)}
									onkeydown={(e) => {
										if (e.key === 'Enter' || e.key === ' ') {
											e.preventDefault();
											openChannel(c);
										}
									}}
								>
									<td>{channelDisplayName(c)}</td>
									<td>{t(`admin.chatCompliance.channels.kind.${c.kind}`)}</td>
									<td><Badge variant={c.classification === 'gxp' ? 'accent' : 'neutral'} label={t(`admin.chatCompliance.class.${c.classification}`)} /></td>
									<td>{retentionLabel(c)}</td>
									<td>{#if c.legalHold}<Badge variant="danger" label={t('admin.chatCompliance.channels.holdBadge')} />{/if}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</Card>
		{/if}
	{/if}
</div>

<RetentionPolicyEditor
	open={policyEditorOpen}
	policy={policyEditTarget}
	onsaved={onPolicySaved}
	oncancel={() => (policyEditorOpen = false)}
/>

<ChannelComplianceSheet
	open={sheetOpen}
	channel={sheetChannel}
	{canManage}
	onClose={() => (sheetOpen = false)}
	onChanged={onChannelChanged}
/>

<ConfirmDestructive
	open={policyDeleteConfirmOpen}
	title={t('admin.chatCompliance.policy.deleteExposedTitle')}
	message={t('admin.chatCompliance.policy.deleteExposed', { n: String(policyDeleteExposed) })}
	confirmWord="DESTROY"
	confirmLabel={t('admin.chatCompliance.policy.delete')}
	busy={policyDeleteBusy}
	error={policyDeleteError}
	onConfirm={confirmDeletePolicy}
	onCancel={() => {
		policyDeleteConfirmOpen = false;
		policyDeleteTarget = null;
	}}
/>

<style>
	.cc-page {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		max-width: 980px;
	}
	.cc-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
	}
	.cc-title {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.cc-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: var(--space-1) 0 0;
	}
	.cc-error {
		font-size: var(--text-sm);
		color: var(--text-danger);
	}
	.cc-warning {
		font-size: var(--text-sm);
		color: var(--warning-fg, var(--text-danger));
	}
	.cc-loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6);
		color: var(--text-secondary);
	}
	.cc-empty,
	.cc-hint {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.cc-empty-block {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-8);
		text-align: center;
	}
	.cc-empty__title {
		font-size: var(--text-base);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0;
	}
	.cc-empty__body {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}
	.cc-stats {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
		gap: var(--space-3);
	}
	.cc-stat__value {
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.cc-stat__label {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		margin: var(--space-1) 0 0;
	}
	.cc-row {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.cc-scroll {
		overflow-x: auto;
	}
	.cc-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.cc-table th {
		text-align: left;
		padding: var(--space-2) var(--space-3);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.cc-table td {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
		white-space: nowrap;
	}
	.cc-row-clickable {
		cursor: pointer;
	}
	.cc-row-clickable:hover {
		background: var(--surface-hover);
	}
	.cc-td-actions {
		display: flex;
		align-items: center;
		gap: 4px;
	}
	.cc-icon-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-md);
		cursor: pointer;
		color: var(--text-secondary);
	}
	.cc-icon-btn:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}
	.cc-icon-btn--danger:hover {
		background: var(--red-50);
		color: var(--text-danger);
	}
</style>
