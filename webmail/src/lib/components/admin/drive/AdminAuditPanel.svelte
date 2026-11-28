<svelte:options runes={true} />

<script lang="ts">
	// P6 Task 16 — the audit console: filters, session-timeline grouping over
	// per-access rows (§9.3 — grouping is UI-only, drive_audit_query always
	// returns the raw list, see auditSessions.ts), a raw-table toggle, CSV
	// export, alarm-rule CRUD, and live "DriveAlarm" popups for admins.
	import { onMount } from 'svelte';
	import * as api from '$lib/drive/api';
	import { type DriveAuditRow, type DriveAuditAlarm, type AuditQueryParams } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { groupSessions, type AuditSession } from '$lib/drive/auditSessions';
	import { subscribeEvent } from '$lib/jmap/websocket';
	import { driveErrorMessage } from '$lib/drive/errors';
	import {
		Card,
		Button,
		Input,
		Select,
		Switch,
		Table,
		type TableColumn,
		EmptyState,
		Spinner,
		Dialog,
		showToast,
	} from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		spaceId,
		canManage,
	}: {
		spaceId: number;
		canManage: boolean;
	} = $props();

	// The closed §9.3 event catalog (Task 8: fetched from GET /api/drive/audit-actions,
	// which mirrors drive_audit_actions() server-side — the same closed-set posture,
	// now with one source of truth instead of a hand-copied literal).
	let auditActions = $state<string[]>([]);
	onMount(() => {
		void api.getAuditActions().then((a) => {
			auditActions = a;
			if (!alarmPattern) alarmPattern = a[0] ?? '';
		}).catch((e) => { error = driveErrorMessage(e); });
	});

	// ── filters + query ───────────────────────────────────────────────────
	let filterActor = $state('');
	let filterAction = $state('');
	let filterFrom = $state('');
	let filterTo = $state('');
	let filterQ = $state('');

	let items = $state<DriveAuditRow[]>([]);
	let hasMore = $state(false);
	let loading = $state(false);
	let error = $state('');
	let rawView = $state(false);

	function currentParams(beforeId?: number): AuditQueryParams {
		return {
			spaceId,
			actor: filterActor ? Number(filterActor) : null,
			action: filterAction || null,
			from: filterFrom ? new Date(filterFrom).toISOString() : null,
			to: filterTo ? new Date(filterTo).toISOString() : null,
			q: filterQ || null,
			max: 50,
			beforeId: beforeId ?? null,
		};
	}

	async function loadAudit(reset: boolean) {
		loading = true;
		try {
			const beforeId = reset ? undefined : items[items.length - 1]?.id;
			const res = await api.queryAudit(currentParams(beforeId));
			items = reset ? res.items : [...items, ...res.items];
			hasMore = res.hasMore;
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		spaceId; // re-run on space switch
		void loadAudit(true);
		void loadAlarms();
		void loadFiredFeed();
	});

	const sessions = $derived(rawView ? [] : groupSessions(items));
	let expanded = $state(new Set<string>());
	function sessionKey(s: AuditSession, i: number): string {
		return `${s.userId ?? 'system'}:${s.start}:${i}`;
	}
	function toggleExpanded(key: string) {
		const next = new Set(expanded);
		if (next.has(key)) next.delete(key);
		else next.add(key);
		expanded = next;
	}

	const RAW_COLUMNS: TableColumn[] = [
		{ key: 'occurredAt', label: t('drive.audit.filter.time') },
		{ key: 'userEmail', label: t('drive.audit.filter.actor') },
		{ key: 'action', label: t('drive.audit.filter.action') },
		{ key: 'ip', label: 'IP' },
		{ key: 'notes', label: t('drive.audit.filter.notes') },
	];
	function rawRows(rows: DriveAuditRow[]) {
		return rows.map((r) => ({ ...r })) as unknown as Record<string, unknown>[];
	}

	const csvUrl = $derived(api.auditCsvUrl(currentParams()));

	// ── alarm rules ───────────────────────────────────────────────────────
	let alarms = $state<DriveAuditAlarm[]>([]);
	let alarmsLoading = $state(false);
	let firedFeed = $state<DriveAuditRow[]>([]);

	async function loadAlarms() {
		alarmsLoading = true;
		try {
			alarms = await api.listAuditAlarms();
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			alarmsLoading = false;
		}
	}

	async function loadFiredFeed() {
		try {
			const res = await api.queryAudit({ spaceId, action: 'alarm.fire', max: 20 });
			firedFeed = res.items;
		} catch {
			/* the fired-alarm feed is a convenience read — a failure here doesn't block the console */
		}
	}

	async function toggleAlarmEnabled(alarm: DriveAuditAlarm) {
		try {
			await api.updateAuditAlarm(alarm.id, { enabled: !alarm.enabled });
			alarm.enabled = !alarm.enabled;
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	let showAlarmDialog = $state(false);
	let alarmPattern = $state('');
	let alarmWildcard = $state(false);
	let alarmScopeAll = $state(false);
	let alarmThreshold = $state('5');
	let alarmWindow = $state('10');
	let alarmSaving = $state(false);
	let deleteTarget = $state<DriveAuditAlarm | null>(null);

	function openCreateAlarm() {
		alarmPattern = auditActions[0] ?? '';
		alarmWildcard = false;
		alarmScopeAll = false;
		alarmThreshold = '5';
		alarmWindow = '10';
		showAlarmDialog = true;
	}

	async function submitAlarm() {
		alarmSaving = true;
		try {
			await api.createAuditAlarm({
				spaceId: alarmScopeAll ? null : spaceId,
				actionPattern: alarmWildcard ? `${alarmPattern}*` : alarmPattern,
				threshold: Number(alarmThreshold) || 5,
				windowMinutes: Number(alarmWindow) || 10,
			});
			showAlarmDialog = false;
			await loadAlarms();
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			alarmSaving = false;
		}
	}

	async function confirmDeleteAlarm() {
		if (!deleteTarget) return;
		const target = deleteTarget;
		deleteTarget = null;
		try {
			await api.deleteAuditAlarm(target.id);
			alarms = alarms.filter((a) => a.id !== target.id);
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	// ── live "DriveAlarm" popups (admin-only — the WS channel itself is
	// server-gated to drive.view/drive.manage sessions; this component only
	// mounts under the same gate its parent page already applies) ──────────
	let liveAnnouncement = $state('');
	$effect(() => {
		if (!canManage) return;
		const unsubscribe = subscribeEvent<{ ruleId?: number; spaceId?: number; pattern?: string; hits?: number }>('DriveAlarm', (event) => {
			const text = t('drive.audit.alarmToast', { pattern: event.pattern ?? '', hits: String(event.hits ?? '') });
			liveAnnouncement = text;
			showToast(text, {
				actionLabel: t('drive.audit.title'),
				onAction: () => {
					filterAction = 'alarm.fire';
					void loadAudit(true);
				},
			});
			void loadFiredFeed();
		});
		return unsubscribe;
	});
</script>

<div aria-live="polite" role="status" class="sr-only">{liveAnnouncement}</div>

<Card flush={true}>
	<div class="aap">
		<h2 class="aap__title">{t('drive.audit.title')}</h2>

		{#if error}
			<p class="aap__error" role="alert">{error}</p>
		{/if}

		<div class="aap__filters">
			<Input label={t('drive.audit.filter.actor')} placeholder="12345" inputmode="numeric" bind:value={filterActor} />
			<Select
				label={t('drive.audit.filter.action')}
				bind:value={filterAction}
				options={[{ value: '', label: t('drive.audit.filter.action') }, ...auditActions.map((a) => ({ value: a, label: a }))]}
			/>
			<div class="aap__field">
				<label class="aap__field-label" for="aap-from">{t('drive.audit.filter.from')}</label>
				<input id="aap-from" class="aap__native-input" type="datetime-local" bind:value={filterFrom} />
			</div>
			<div class="aap__field">
				<label class="aap__field-label" for="aap-to">{t('drive.audit.filter.to')}</label>
				<input id="aap-to" class="aap__native-input" type="datetime-local" bind:value={filterTo} />
			</div>
			<Input label={t('drive.audit.filter.keyword')} bind:value={filterQ} />
			<Button variant="primary" size="sm" onclick={() => loadAudit(true)}>{t('drive.audit.filter.action')}</Button>
		</div>

		<div class="aap__toolbar">
			<div class="aap__view-toggle" role="group" aria-label={t('drive.audit.timeline')}>
				<button type="button" class="aap__view-btn" aria-pressed={!rawView} onclick={() => (rawView = false)}>
					{t('drive.audit.timeline')}
				</button>
				<button type="button" class="aap__view-btn" aria-pressed={rawView} onclick={() => (rawView = true)}>
					{t('drive.audit.raw')}
				</button>
			</div>
			<a class="sj-btn-link" href={csvUrl} download>
				<Button variant="secondary" size="sm">
					<Icon name="Download" size={14} />
					{t('drive.audit.exportCsv')}
				</Button>
			</a>
		</div>

		{#if loading && items.length === 0}
			<div class="aap__loading"><Spinner /></div>
		{:else if items.length === 0}
			<EmptyState title={t('drive.audit.empty')} />
		{:else if rawView}
			<Table columns={RAW_COLUMNS} rows={rawRows(items)}>
				{#snippet cell(row, col)}
					{@const r = row as unknown as DriveAuditRow}
					{#if col.key === 'occurredAt'}
						{formatDateTime(r.occurredAt)}
					{:else if col.key === 'notes'}
						{r.notes || '—'}
					{:else}
						{String(row[col.key] ?? '')}
					{/if}
				{/snippet}
			</Table>
		{:else}
			<ul class="aap__sessions">
				{#each sessions as s, i (sessionKey(s, i))}
					{@const key = sessionKey(s, i)}
					{@const isOpen = expanded.has(key)}
					<li>
						<button
							type="button"
							class="aap__session-btn"
							aria-expanded={isOpen}
							aria-controls="aap-session-{key}"
							onclick={() => toggleExpanded(key)}
						>
							<Icon name={isOpen ? 'ChevronDown' : 'ChevronRight'} size={14} />
							{t('drive.audit.sessionSummary', {
								user: s.userEmail,
								start: formatDateTime(s.start),
								end: formatDateTime(s.end),
								n: String(s.count),
							})}
						</button>
						{#if isOpen}
							<div id="aap-session-{key}">
								<Table columns={RAW_COLUMNS} rows={rawRows(s.rows)}>
									{#snippet cell(row, col)}
										{@const r = row as unknown as DriveAuditRow}
										{#if col.key === 'occurredAt'}
											{formatDateTime(r.occurredAt)}
										{:else if col.key === 'notes'}
											{r.notes || '—'}
										{:else}
											{String(row[col.key] ?? '')}
										{/if}
									{/snippet}
								</Table>
							</div>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}

		{#if hasMore}
			<Button variant="ghost" size="sm" onclick={() => loadAudit(false)}>{t('drive.audit.filter.loadMore')}</Button>
		{/if}
	</div>
</Card>

<Card flush={true}>
	<div class="aap">
		<div class="aap__toolbar">
			<h2 class="aap__title">{t('drive.audit.alarms.title')}</h2>
			{#if canManage}
				<Button variant="primary" size="sm" onclick={openCreateAlarm}>{t('drive.audit.alarms.create')}</Button>
			{/if}
		</div>

		{#if alarmsLoading}
			<div class="aap__loading"><Spinner /></div>
		{:else if alarms.length === 0}
			<EmptyState title={t('drive.audit.empty')} />
		{:else}
			<ul class="aap__alarm-list">
				{#each alarms as alarm (alarm.id)}
					<li class="aap__alarm-row">
						<code class="aap__alarm-pattern">{alarm.actionPattern}</code>
						<span class="aap__alarm-meta">
							{alarm.spaceId === null ? t('drive.search.scope.all') : t('drive.audit.alarms.threshold')}
						</span>
						<span class="aap__alarm-meta">{t('drive.audit.alarms.threshold')}: {alarm.threshold}</span>
						<span class="aap__alarm-meta">{t('drive.audit.alarms.window')}: {alarm.windowMinutes}m</span>
						<Switch
							checked={alarm.enabled}
							disabled={!canManage}
							label={t('drive.audit.alarms.enabled')}
							onchange={() => toggleAlarmEnabled(alarm)}
						/>
						{#if canManage}
							<Button variant="ghost" size="sm" onclick={() => (deleteTarget = alarm)}>
								{t('drive.audit.alarms.delete')}
							</Button>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}

		<h3 class="aap__subtitle">{t('drive.audit.alarms.fired')}</h3>
		{#if firedFeed.length === 0}
			<EmptyState title={t('drive.audit.empty')} />
		{:else}
			<ul class="aap__fired-list">
				{#each firedFeed as f (f.id)}
					<li class="aap__fired-row">
						<Icon name="AlertTriangle" size={13} />
						<span>{formatDateTime(f.occurredAt)}</span>
						<span>{f.notes || '—'}</span>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</Card>

<Dialog open={showAlarmDialog} title={t('drive.audit.alarms.create')} onClose={() => (showAlarmDialog = false)}>
	<div class="aap__alarm-form">
		<Select label={t('drive.audit.alarms.pattern')} bind:value={alarmPattern} options={auditActions.map((a) => ({ value: a, label: a }))} />
		<label class="aap__checkbox">
			<input type="checkbox" bind:checked={alarmWildcard} />
			{t('drive.audit.alarms.pattern')} *
		</label>
		<label class="aap__checkbox">
			<input type="checkbox" bind:checked={alarmScopeAll} />
			{t('drive.search.scope.all')}
		</label>
		<Input label={t('drive.audit.alarms.threshold')} type="number" min="1" bind:value={alarmThreshold} />
		<Input label={t('drive.audit.alarms.window')} type="number" min="1" bind:value={alarmWindow} />
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={alarmSaving} onclick={submitAlarm}>{t('drive.audit.alarms.create')}</Button>
		<Button variant="secondary" onclick={() => (showAlarmDialog = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={deleteTarget !== null} title={t('drive.audit.alarms.delete')} onClose={() => (deleteTarget = null)}>
	<p>{t('drive.audit.alarms.confirmDelete', { pattern: deleteTarget?.actionPattern ?? '' })}</p>
	{#snippet footer()}
		<Button variant="danger" onclick={confirmDeleteAlarm}>{t('drive.audit.alarms.delete')}</Button>
		<Button variant="secondary" onclick={() => (deleteTarget = null)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.aap {
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.aap__title {
		font-size: var(--text-md);
		font-weight: 600;
		margin: 0;
	}
	.aap__subtitle {
		font-size: var(--text-sm);
		font-weight: 600;
		margin: var(--space-2) 0 0;
	}
	.aap__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.aap__filters {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.aap__field {
		display: flex;
		flex-direction: column;
		gap: 5px;
	}
	.aap__field-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.aap__native-input {
		height: 32px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-family: var(--font-sans);
	}
	.aap__native-input:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.aap__toolbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.aap__view-toggle {
		display: inline-flex;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		overflow: hidden;
	}
	.aap__view-btn {
		padding: 4px 12px;
		font-size: var(--text-sm);
		background: var(--surface-card);
		color: var(--text-secondary);
		border: none;
		cursor: pointer;
	}
	.aap__view-btn[aria-pressed='true'] {
		background: var(--accent);
		color: var(--text-on-accent);
	}
	.sj-btn-link {
		text-decoration: none;
	}
	.aap__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
	.aap__sessions {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.aap__session-btn {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-2);
		border: none;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		cursor: pointer;
		text-align: left;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.aap__session-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.aap__alarm-list,
	.aap__fired-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.aap__alarm-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.aap__alarm-pattern {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		border-radius: var(--radius-xs);
		padding: 1px 5px;
	}
	.aap__alarm-meta {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.aap__fired-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-caption);
		padding: var(--space-1) var(--space-2);
	}
	.aap__alarm-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.aap__checkbox {
		display: inline-flex;
		align-items: center;
		gap: 6px;
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
</style>
