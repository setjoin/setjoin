<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import {
		Card, Button, Input, Select, EmptyState, Spinner, Dialog, IconButton,
		Badge, Tabs, Table, type TabItem, type TableColumn, showToast,
	} from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import DeviceEnrollBadge from '$lib/components/admin/DeviceEnrollBadge.svelte';
	import { actionsFor, relativeAge, queueEmptyKind, formatCount } from '$lib/components/admin/device-lockdown';

	interface DeviceRow {
		id: number;
		user_email: string;
		user_display_name?: string;
		enroll_state: string;
		platform?: string;
		requested_at?: string;
		last_seen_at?: string;
		enrolled_by?: string;
		device_name?: string;
	}

	// ponytail: cap at 100 — server's stated limit; no client pagination needed at ≤500 rows
	const LIMIT = 100;

	// Table column definitions for M1 Table; evaluated once (no rune needed)
	const QUEUE_COLS: TableColumn[] = [
		{ key: 'user',        label: t('admin.device_lockdown.col.user') },
		{ key: 'state',       label: t('admin.device_lockdown.col.state') },
		{ key: 'platform',    label: t('admin.device_lockdown.col.platform') },
		{ key: 'requested',   label: t('admin.device_lockdown.col.requested') },
		{ key: 'last_seen',   label: t('admin.device_lockdown.col.last_seen') },
		{ key: 'enrolled_by', label: t('admin.device_lockdown.col.enrolled_by') },
		{ key: 'actions',     label: t('admin.device_lockdown.col.actions') },
	];

	const BY_USER_COLS: TableColumn[] = [
		{ key: 'device',  label: t('admin.device_lockdown.col.device') },
		{ key: 'state',   label: t('admin.device_lockdown.col.state') },
		{ key: 'actions', label: t('admin.device_lockdown.col.actions') },
	];

	// Skeleton placeholder rows for M1 Table chrome during loading (no real fields needed)
	const SKELETON: Record<string, unknown>[] = Array.from({ length: 6 }, (_, i) => ({ _i: i }));

	let loading = $state(true);
	let error = $state('');
	let entries = $state<DeviceRow[]>([]);
	// Fix F4: enrolledCount tracked independently of current filter — never 0 on non-enrolled view
	let enrolledCount = $state(0);
	let stateFilter = $state('enrolled');
	let searchQuery = $state('');
	let activeTab = $state('queue');
	let busyId = $state<number | null>(null);
	let liveMsg = $state('');
	let reducedMotion = $state(false);

	// Revoke dialog state
	let revokeTarget = $state<DeviceRow | null>(null);
	let revokeReason = $state('');
	let revokeToken = $state('');
	let revoking = $state(false);
	// Fix F1/F5: inline warnbar in dialog — never swallowed to ephemeral toast
	let revokeError = $state('');

	// By-user tab state
	let byUserQuery = $state('');
	let byUserEntries = $state<DeviceRow[]>([]);
	let byUserLoading = $state(false);
	let byUserError = $state('');

	const emptyKind = $derived(queueEmptyKind({ state: stateFilter, query: searchQuery }));
	const isPartial = $derived(entries.length >= LIMIT);
	// Revoke commit requires REVOKE token + non-empty reason
	const revokeCanCommit = $derived(revokeToken === 'REVOKE' && revokeReason.trim() !== '');

	const TABS: TabItem[] = [
		{ id: 'queue', label: t('admin.device_lockdown.tab.queue') },
		{ id: 'by_user', label: t('admin.device_lockdown.tab.by_user') },
	];

	const STATE_OPTIONS = [
		{ value: 'enrolled', label: t('admin.device_lockdown.filter.waiting') },
		{ value: 'approved', label: t('admin.device_lockdown.filter.approved') },
		{ value: 'revoked', label: t('admin.device_lockdown.filter.revoked') },
		{ value: '', label: t('admin.device_lockdown.filter.all') },
	];

	async function load() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			params.set('state', stateFilter);
			if (searchQuery) params.set('q', searchQuery);
			params.set('limit', String(LIMIT));
			const res = await adminFetch('/admin/devices/queue?' + params.toString());
			entries = await res.json();
			// Fix F4: only update enrolledCount from the enrolled filter load
			if (stateFilter === 'enrolled') enrolledCount = entries.length;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function approve(row: DeviceRow) {
		busyId = row.id;
		try {
			await adminFetch(`/admin/devices/${row.id}/approve`, { method: 'POST' });
			entries = entries.filter((e) => e.id !== row.id);
			enrolledCount = Math.max(0, enrolledCount - 1);
			liveMsg = t('admin.device_lockdown.approved_announce', {
				user: row.user_display_name ?? row.user_email,
			});
		} catch (e) {
			showToast(parseError(e).message);
		} finally {
			busyId = null;
		}
	}

	function openRevoke(row: DeviceRow) {
		revokeTarget = row;
		revokeToken = '';
		revokeReason = '';
		revokeError = '';
	}

	async function confirmRevoke() {
		if (!revokeTarget) return;
		revoking = true;
		revokeError = '';
		try {
			await adminFetch(`/admin/devices/${revokeTarget.id}/revoke`, {
				method: 'POST',
				body: JSON.stringify({ reason: revokeReason }),
			});
			const device = revokeTarget.device_name ?? String(revokeTarget.id);
			// Fix F4: enrolled device being revoked decrements the waiting count
			if (revokeTarget.enroll_state === 'enrolled') enrolledCount = Math.max(0, enrolledCount - 1);
			entries = entries.map((e) =>
				e.id === revokeTarget!.id ? { ...e, enroll_state: 'revoked' } : e,
			);
			liveMsg = t('admin.device_lockdown.revoked_announce', { device });
			showToast(t('device.revoked_toast', { device }));
			revokeTarget = null;
		} catch (e) {
			// Fix F1/F5: any revoke error (incl. 409 state-change HINT) → inline warnbar; dialog stays open
			revokeError = parseError(e).message;
		} finally {
			revoking = false;
		}
	}

	async function lookupUser() {
		if (!byUserQuery.trim()) return;
		byUserLoading = true;
		byUserError = '';
		try {
			const res = await adminFetch(`/admin/devices?user_id=${encodeURIComponent(byUserQuery)}`);
			byUserEntries = await res.json();
		} catch (e) {
			byUserError = parseError(e).message;
		} finally {
			byUserLoading = false;
		}
	}

	onMount(() => {
		if (typeof window !== 'undefined' && window.matchMedia) {
			reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		}
		load();
	});
</script>

<!-- ponytail: single page-wrap carries data-reduced-motion for motion tests -->
<div class="page-wrap" data-reduced-motion={reducedMotion ? 'true' : undefined}>
	<!-- Polite live region: announces queue changes to screen readers -->
	<div aria-live="polite" aria-atomic="true" class="sr-only">{liveMsg}</div>

	<!-- Off-screen loading status (brief §4b: not a centered spinner during table load) -->
	{#if loading}
		<div role="status" class="sr-only">{t('admin.device_lockdown.loading')}</div>
	{/if}

	<header class="page-header">
		<div class="page-header-left">
			<h1>
				{t('admin.device_lockdown.title')}
				<!-- Fix F2: use i18n key with formatCount — "3 devices waiting" not "3" -->
				{#if !loading && !error}
					<Badge label={t('admin.device_lockdown.waiting_count', { n: formatCount(enrolledCount) })} />
				{/if}
			</h1>
		</div>
	</header>

	<Tabs items={TABS} active={activeTab} onChange={(id) => { activeTab = id; }} />

	{#if activeTab === 'queue'}
		<!-- filter-bar: mirrors auth-log pattern -->
		<div class="filter-bar">
			<div class="filter-input-wrap">
				<Select
					label={t('admin.device_lockdown.filter.state')}
					options={STATE_OPTIONS}
					bind:value={stateFilter}
					disabled={loading}
				/>
			</div>
			<div class="filter-input-wrap">
				<Input
					label={t('admin.common.search')}
					placeholder={t('admin.device_lockdown.search_placeholder')}
					bind:value={searchQuery}
					disabled={loading}
				/>
			</div>
			<Button variant="secondary" size="md" onclick={load} disabled={loading}>
				<Icon name="Search" size={14} strokeWidth={1.75} />
				{t('admin.common.search')}
			</Button>
		</div>

		{#if loading}
			<!-- Fix F3: M1 Table for skeleton — real chrome, no hand-rolled .sj-table* styles -->
			<Card flush={true}>
				{#snippet children()}
					<Table columns={QUEUE_COLS} rows={SKELETON}>
						{#snippet cell(_row, _col)}
							<span class="skeleton-cell"></span>
						{/snippet}
					</Table>
				{/snippet}
			</Card>
		{:else if error}
			<div role="alert" class="error-block">
				<Icon name="AlertTriangle" size={16} strokeWidth={1.75} aria-hidden={true} />
				<span>{t('admin.device_lockdown.load_error')}</span>
				<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
			</div>
		{:else if entries.length === 0}
			{#if emptyKind === 'caught_up'}
				<EmptyState title={t('admin.device_lockdown.queue_empty')} watermark={true}>
					{#snippet action()}
						<Button
							variant="secondary"
							size="sm"
							onclick={() => {
								stateFilter = '';
								load();
							}}
						>
							{t('admin.device_lockdown.show_all')}
						</Button>
					{/snippet}
				</EmptyState>
			{:else}
				<EmptyState title={t('admin.device_lockdown.no_match')} watermark={true}>
					{#snippet action()}
						<Button
							variant="secondary"
							size="sm"
							onclick={() => {
								searchQuery = '';
								stateFilter = 'enrolled';
								load();
							}}
						>
							{t('admin.device_lockdown.clear_filters')}
						</Button>
					{/snippet}
				</EmptyState>
			{/if}
		{:else}
			<!-- Fix F3: M1 Table with cell snippet — removes ~60 duplicate .sj-table* CSS lines -->
			<Card flush={true}>
				{#snippet children()}
					{@const qrows = entries as unknown as Record<string, unknown>[]}
					<Table columns={QUEUE_COLS} rows={qrows}>
						{#snippet cell(row, col)}
							{@const dr = row as unknown as DeviceRow}
							{#if col.key === 'user'}
								<div class="user-cell">
									<button
										type="button"
										class="user-btn"
										title={dr.user_display_name ?? dr.user_email}
										aria-label={t('admin.device_lockdown.view_user', {
											user: dr.user_display_name ?? dr.user_email,
										})}
										onclick={() => {
											activeTab = 'by_user';
											byUserQuery = dr.user_email;
											lookupUser();
										}}
									>
										<span class="user-name">{dr.user_display_name ?? dr.user_email}</span>
										{#if dr.user_display_name}
											<span class="user-email">{dr.user_email}</span>
										{/if}
									</button>
								</div>
							{:else if col.key === 'state'}
								<DeviceEnrollBadge state={dr.enroll_state} />
							{:else if col.key === 'platform'}
								{dr.platform ?? '—'}
							{:else if col.key === 'requested'}
								<span title={dr.requested_at}>
									{dr.requested_at ? relativeAge(dr.requested_at) : '—'}
								</span>
							{:else if col.key === 'last_seen'}
								{dr.last_seen_at ? relativeAge(dr.last_seen_at) : '—'}
							{:else if col.key === 'enrolled_by'}
								{dr.enrolled_by ?? '—'}
							{:else if col.key === 'actions'}
								<div class="actions-cell">
									{#each actionsFor(dr.enroll_state) as action (action)}
										{#if action === 'approve'}
											<Button
												variant="primary"
												size="sm"
												disabled={busyId === dr.id}
												onclick={() => approve(dr)}
											>
												{#if busyId === dr.id}
													<Spinner size={16} />
												{/if}
												{t('admin.device_lockdown.action.approve')}
											</Button>
										{:else if action === 'revoke'}
											<IconButton
												label={t('admin.device_lockdown.revoke_aria', {
													device: dr.device_name ?? String(dr.id),
												})}
												size="md"
												disabled={busyId === dr.id}
												onclick={() => openRevoke(dr)}
											>
												<Icon name="ShieldX" size={16} strokeWidth={1.75} />
											</IconButton>
										{/if}
									{/each}
								</div>
							{/if}
						{/snippet}
					</Table>
					{#if isPartial}
						<div class="truncated-footer">
							{t('admin.device_lockdown.truncated', { n: formatCount(entries.length) })}
						</div>
					{/if}
				{/snippet}
			</Card>
		{/if}
	{:else}
		<!-- By-user tab: per-user device list via ?user_id= drill-down -->
		<div class="by-user-panel">
			<div class="filter-bar">
				<div class="filter-input-wrap">
					<Input
						label={t('admin.device_lockdown.by_user_lookup_label')}
						placeholder={t('admin.device_lockdown.by_user_placeholder')}
						bind:value={byUserQuery}
					/>
				</div>
				<Button variant="secondary" size="md" onclick={lookupUser}>
					{t('admin.device_lockdown.by_user_search')}
				</Button>
			</div>
			{#if byUserLoading}
				<div class="loading-center"><Spinner size={28} /></div>
			{:else if byUserError}
				<div role="alert" class="error-block">
					<span>{byUserError}</span>
					<Button variant="secondary" size="sm" onclick={lookupUser}>{t('common.retry')}</Button>
				</div>
			{:else if byUserEntries.length === 0 && byUserQuery}
				<EmptyState title={t('admin.device_lockdown.no_match')} watermark={true} />
			{:else if byUserEntries.length > 0}
				<!-- Fix F3: M1 Table for by-user panel too -->
				<Card flush={true}>
					{#snippet children()}
						{@const urows = byUserEntries as unknown as Record<string, unknown>[]}
						<Table columns={BY_USER_COLS} rows={urows}>
							{#snippet cell(row, col)}
								{@const dr = row as unknown as DeviceRow}
								{#if col.key === 'device'}
									{dr.device_name ?? t('admin.device_lockdown.device_id', { id: String(dr.id) })}
								{:else if col.key === 'state'}
									<DeviceEnrollBadge state={dr.enroll_state} />
								{:else if col.key === 'actions'}
									<div class="actions-cell">
										{#each actionsFor(dr.enroll_state) as action (action)}
											{#if action === 'revoke'}
												<IconButton
													label={t('admin.device_lockdown.revoke_aria', {
														device: dr.device_name ?? String(dr.id),
													})}
													size="md"
													onclick={() => openRevoke(dr)}
												>
													<Icon name="ShieldX" size={16} strokeWidth={1.75} />
												</IconButton>
											{/if}
										{/each}
									</div>
								{/if}
							{/snippet}
						</Table>
					{/snippet}
				</Card>
			{/if}
		</div>
	{/if}

	<!-- Revoke confirm dialog (Tier-2 type-to-confirm per shared §2) -->
	<Dialog
		open={revokeTarget !== null}
		title={t('admin.device_lockdown.revoke_title')}
		onClose={revoking ? undefined : () => {
			revokeTarget = null;
		}}
	>
		{#snippet children()}
			{#if revokeTarget}
				<!-- Fix F1/F5: inline error warnbar — any revoke error (incl. 409 HINT) shown here, never toast -->
				{#if revokeError}
					<div class="warn-bar warn-bar--error" role="alert">
						<Icon name="AlertTriangle" size={16} strokeWidth={1.75} aria-hidden={true} />
						<span class="warn-bar-msg">{revokeError}</span>
						<Button
							variant="secondary"
							size="sm"
							onclick={() => { revokeTarget = null; load(); }}
						>
							{t('common.retry')}
						</Button>
					</div>
				{/if}
				<div class="warn-bar">
					<Icon name="AlertTriangle" size={16} strokeWidth={1.75} aria-hidden={true} />
					<span>{t('admin.device_lockdown.revoke_warn')}</span>
				</div>
				<p class="revoke-target-name">
					{revokeTarget.user_display_name ?? revokeTarget.user_email}
					{#if revokeTarget.device_name}&nbsp;— {revokeTarget.device_name}{/if}
				</p>
				<div class="revoke-field">
					<Input
						label={t('admin.device_lockdown.revoke_reason_label')}
						bind:value={revokeReason}
						disabled={revoking}
						aria-required="true"
					/>
				</div>
				<p class="type-confirm-hint">
					{t('common.type_to_confirm', { value: '' })}<code>REVOKE</code>
				</p>
				<div class="revoke-field">
					<Input
						bind:value={revokeToken}
						disabled={revoking}
						aria-label={t('admin.device_lockdown.revoke_type_aria')}
						placeholder="REVOKE"
					/>
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button
				variant="secondary"
				size="md"
				onclick={() => { revokeTarget = null; }}
				disabled={revoking}
			>
				{t('common.cancel')}
			</Button>
			<Button
				variant="danger"
				size="md"
				disabled={!revokeCanCommit || revoking}
				aria-disabled={!revokeCanCommit || revoking}
				onclick={confirmRevoke}
			>
				{#if revoking}
					<Spinner size={16} />
					{t('admin.device_lockdown.revoking')}
				{:else}
					{t('admin.device_lockdown.revoke_confirm')}
				{/if}
			</Button>
		{/snippet}
	</Dialog>
</div>

<style>
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

	.page-header {
		margin-bottom: 16px;
	}

	.page-header h1 {
		display: flex;
		align-items: center;
		gap: 8px;
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.filter-bar {
		display: flex;
		gap: 8px;
		margin: 12px 0;
		align-items: flex-end;
		flex-wrap: wrap;
	}

	.filter-input-wrap {
		flex: 1 1 160px;
		max-width: 220px;
		min-width: 120px;
	}

	/* Loading skeleton cells (inside M1 Table chrome) */
	.skeleton-cell {
		display: block;
		height: 14px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		/* ponytail: opacity pulse via CSS; reduced-motion honored by @media below */
		animation: skeleton-pulse var(--duration-slow, 1.2s) ease-in-out infinite alternate;
	}

	@media (prefers-reduced-motion: reduce) {
		.skeleton-cell {
			animation: none;
		}
	}

	@keyframes skeleton-pulse {
		from { opacity: 0.5; }
		to { opacity: 1; }
	}

	/* Error block */
	.error-block {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 12px 16px;
		border-radius: var(--radius-md);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		margin: 8px 0;
	}

	/* User cell (inside M1 Table td) */
	.user-cell {
		max-width: 220px;
	}

	.user-btn {
		display: flex;
		flex-direction: column;
		background: transparent;
		border: none;
		padding: 0;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		border-radius: var(--radius-sm);
	}

	.user-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.user-name {
		font-size: var(--text-sm);
		color: var(--text-primary);
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.user-email {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		max-width: 200px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.actions-cell {
		display: flex;
		gap: 6px;
		align-items: center;
		min-width: 44px; /* touch-target floor */
	}

	.truncated-footer {
		padding: 10px 12px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		border-top: 1px solid var(--border-subtle);
	}

	/* Revoke dialog warnbars */
	.warn-bar {
		display: flex;
		gap: 8px;
		align-items: flex-start;
		padding: 10px 12px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		margin-bottom: 12px;
	}

	/* Fix F1/F5: error warnbar variant — center-aligned with a grow message + retry button */
	.warn-bar--error {
		align-items: center;
	}

	.warn-bar-msg {
		flex: 1;
	}

	.revoke-target-name {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0 0 12px;
	}

	.revoke-field {
		margin-bottom: 10px;
	}

	.type-confirm-hint {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 6px;
	}

	.type-confirm-hint code {
		font-family: var(--font-mono);
		background: var(--gray-100);
		padding: 1px 5px;
		border-radius: var(--radius-sm);
	}

	/* By-user panel */
	.by-user-panel {
		padding-top: 4px;
	}

	.loading-center {
		display: flex;
		justify-content: center;
		padding: 40px;
	}

	/* Responsive: narrow view collapses M1 Table to card-style.
	   :global() required to pierce M1 Table's Svelte scoped styles. */
	@media (max-width: 719px) {
		:global(.sj-table thead) {
			display: none;
		}

		:global(.sj-table tbody tr) {
			display: flex;
			flex-direction: column;
			padding: 10px 12px;
			border-bottom: 1px solid var(--border-subtle);
		}

		:global(.sj-table td) {
			height: auto;
			padding: 2px 0;
			border-bottom: none;
			white-space: normal;
		}

		.actions-cell {
			padding-top: 8px;
		}

		.filter-input-wrap {
			max-width: 100%;
			flex: 1 1 100%;
		}
	}
</style>
