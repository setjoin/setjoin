<svelte:options runes={true} />

<script lang="ts">
	import { untrack } from 'svelte';
	import type { DriveNode, DriveVersion, DriveBranch } from '$lib/drive/api';
	import * as api from '$lib/drive/api';
	import { contentUrl } from '$lib/drive/api';
	import { driveLocks } from '$lib/drive/locks.svelte';
	import { driveWatches } from '$lib/drive/watches.svelte';
	import { formatBytes } from '$lib/utils/display';
	import { formatDateTime } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import { Badge, Button, Dialog, IconButton, Spinner, Tabs } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';
	import CompareView from './CompareView.svelte';
	import ExportRequestButton from './ExportRequestButton.svelte';
	import { getNative, hasCapability } from '$lib/native';

	let {
		node,
		spaceId = 0,
		versions,
		loading,
		classification,
		canWrite,
		onClose,
		onRestoreAsNew,
		onUploadNewVersion,
		onView,
		onLabelsChanged,
	}: {
		node: DriveNode;
		spaceId?: number;
		versions: DriveVersion[];
		loading: boolean;
		classification: 'regular' | 'secure' | 'gxp';
		canWrite: boolean;
		onClose: () => void;
		onRestoreAsNew: (version: DriveVersion) => void;
		onUploadNewVersion: (file: File) => void;
		/** Opens the in-app SecureViewer (P3) for a secure/gxp version — regular
		 *  spaces keep the plain download link instead (spec §8.1). */
		onView: (version: DriveVersion) => void;
		/** Fired after a label add/remove so the parent can re-fetch versions. */
		onLabelsChanged?: () => void;
	} = $props();

	let fileInput = $state<HTMLInputElement | null>(null);
	let officeChoices = $state<api.OfficeChoice[]>([]);
	let localOfficeChoices = $state<Array<{ id: 'microsoft-office' | 'wps-office' | 'libreoffice' | 'collabora-office'; label: string }>>([]);
	let officeLoading = $state(false);
	let officeError = $state('');

	$effect(() => {
		const nodeId = node.id;
		const native = hasCapability('driveMirror') && getNative().driveMirror?.version === 3;
		officeChoices = [];
		localOfficeChoices = [];
		officeError = '';
		void api.officeChoices(nodeId, native ? 'electron' : 'web').then(async (result) => {
			officeChoices = result.choices.filter((choice) => choice.available);
			if (native && result.localOpenAllowed) {
				localOfficeChoices = await getNative().driveMirror?.officeChoices() ?? [];
			}
		}).catch(() => {
			// Provider discovery is progressive enhancement: OFF/older servers keep
			// the existing preview/download/version actions without a warning.
		});
	});

	async function openOnline(choice: api.OfficeChoice): Promise<void> {
		if (!node.headVersionId || officeLoading) return;
		officeLoading = true;
		officeError = '';
		try {
			const launch = await api.officeLaunch(node.id, {
				baseVersionId: node.headVersionId,
				providerId: choice.providerId,
				deviceId: crypto.randomUUID(),
				cohortKey: `file-${node.id}`,
			});
			const form = document.createElement('form');
			form.method = 'POST';
			form.action = launch.editorUrl;
			form.target = '_blank';
			for (const [name, value] of [
				['access_token', launch.accessToken],
				['access_token_ttl', String(Date.parse(launch.expiresAt))],
			] as const) {
				const input = document.createElement('input');
				input.type = 'hidden'; input.name = name; input.value = value; form.append(input);
			}
			document.body.append(form);
			form.submit();
			form.remove();
		} catch (e) {
			officeError = driveErrorMessage(e);
		} finally {
			officeLoading = false;
		}
	}

	async function openLocal(appId: 'microsoft-office' | 'wps-office' | 'libreoffice' | 'collabora-office'): Promise<void> {
		officeError = '';
		try {
			if (spaceId <= 0) throw new Error(t('drive.office.open_failed'));
			await getNative().driveMirror?.openOffice(spaceId, node.id, appId);
		} catch (e) {
			officeError = e instanceof Error ? e.message : t('drive.office.open_failed');
		}
	}

	function pickFile() {
		fileInput?.click();
	}

	function handleFileChange(e: Event) {
		const file = (e.target as HTMLInputElement).files?.[0];
		if (file) onUploadNewVersion(file);
		(e.target as HTMLInputElement).value = '';
	}

	// ── P4: branch lanes ─────────────────────────────────────────────────────
	// Versions are grouped by branchId — the Main lane (branchId null) plus one
	// section per branch, named from the branch list this drawer self-fetches
	// (DriveTree/BranchPanel precedent: each panel owns its own read). Lane
	// grouping only needs branchId (already on DriveVersion); names come from
	// this fetch. ponytail: no fork/merge annotation line ("merged from X") —
	// the P1 versionOut wire shape (content.go) doesn't carry
	// mergedFromVersionId, so that lineage isn't reachable from this read yet.
	let branches = $state<DriveBranch[]>([]);
	$effect(() => {
		api
			.listBranches(node.id, { all: true })
			.then((b) => {
				branches = b;
			})
			.catch(() => {
				branches = [];
			});
	});

	interface Lane {
		branchId: number | null;
		label: string;
		versions: DriveVersion[];
	}

	let lanes = $derived.by((): Lane[] => {
		const byBranch = new Map<number | null, DriveVersion[]>();
		for (const v of versions) {
			const key = v.branchId;
			const list = byBranch.get(key);
			if (list) list.push(v);
			else byBranch.set(key, [v]);
		}
		const result: Lane[] = [];
		const main = byBranch.get(null);
		if (main) result.push({ branchId: null, label: t('drive.branch.lane.main'), versions: main });
		for (const [branchId, vs] of byBranch) {
			if (branchId === null) continue;
			const b = branches.find((x) => x.id === branchId);
			result.push({ branchId, label: b ? b.name : t('drive.branch.panel'), versions: vs });
		}
		return result;
	});

	// ── P4: version labels ───────────────────────────────────────────────────
	let addingLabelFor = $state<number | null>(null);
	let labelValue = $state('');
	let error = $state('');

	// ── H0: normalized file history ──────────────────────────────────────────
	// History is deliberately additive.  The existing version/branch actions
	// remain available while an older server is rolling forward or when the
	// history endpoint is unavailable.
	type HistoryStatus = 'idle' | 'loading' | 'ready' | 'not-found' | 'error';
	type HistoryTab = 'current' | 'timeline' | 'details';

	const HISTORY_LIMIT = 50;
	let historyStatus = $state<HistoryStatus>('idle');
	let historyTab = $state<HistoryTab>('current');
	let historyItems = $state<api.DriveHistoryItem[]>([]);
	let historyCoverage = $state<api.DriveHistoryCoverage | null>(null);
	let historyGeneratedAt = $state<string | null>(null);
	let historyHasMore = $state(false);
	let historyNextCursor = $state<string | null>(null);
	let historyError = $state('');
	let historyLoadingMore = $state(false);
	let historyRequestId = 0;

	const historyTabs = $derived([
		{ id: 'current', label: t('drive.history.tab.current') },
		{ id: 'timeline', label: t('drive.history.tab.timeline') },
		{ id: 'details', label: t('drive.history.tab.details') },
	]);

	function isHistoryNotFound(e: unknown): boolean {
		if (e instanceof api.DriveError) return e.status === 404;
		return typeof e === 'object' && e !== null && 'status' in e && (e as { status?: unknown }).status === 404;
	}

	function historyKey(item: api.DriveHistoryItem): string {
		return `${item.sourceRank}:${item.source}:${String(item.sourceId)}`;
	}

	function historySourceLabel(source: string): string {
		switch (source.toLowerCase()) {
			case 'version':
			case 'versions':
				return t('drive.history.source.version');
			case 'branch':
			case 'branches':
				return t('drive.history.source.branch');
			case 'activity':
				return t('drive.history.source.activity');
			case 'audit':
				return t('drive.history.source.audit');
			case 'change':
			case 'changes':
				return t('drive.history.source.change');
			default:
				return source;
		}
	}

	function historyKindLabel(kind: string): string {
		switch (kind.toLowerCase()) {
			case 'version':
			case 'version_created':
			case 'save':
				return t('drive.history.kind.version');
			case 'branch':
			case 'branch_created':
			case 'branch_resolved':
				return t('drive.history.kind.branch');
			case 'rename':
				return t('drive.history.kind.rename');
			case 'move':
				return t('drive.history.kind.move');
			case 'restore':
				return t('drive.history.kind.restore');
			case 'lock':
			case 'checkout':
				return t('drive.history.kind.lock');
			case 'acl':
			case 'permission':
				return t('drive.history.kind.permission');
			case 'sync':
				return t('drive.history.kind.sync');
			default:
				return kind;
		}
	}

	function historyDetailsSummary(details: Record<string, unknown> | null): string {
		if (!details) return '';
		for (const key of ['summary', 'message', 'label', 'name', 'note', 'reason']) {
			const value = details[key];
			if (typeof value === 'string' && value.trim()) return value;
		}
		return '';
	}

	function historyDetailsJson(details: Record<string, unknown> | null): string {
		if (!details || Object.keys(details).length === 0) return t('drive.history.details.none');
		try {
			return JSON.stringify(details, null, 2);
		} catch {
			return t('drive.history.details.unavailable');
		}
	}

	function freshnessLevel(seconds: number | null | undefined): 'fresh' | 'warning' | 'stale' | 'unknown' {
		if (seconds == null || !Number.isFinite(seconds)) return 'unknown';
		if (seconds > 60) return 'stale';
		if (seconds >= 30) return 'warning';
		return 'fresh';
	}

	function historyFreshnessLabel(): string {
		if (!historyCoverage) return '';
		const level = freshnessLevel(historyCoverage.freshnessSeconds);
		if (level === 'fresh') return t('drive.history.coverage.fresh');
		if (level === 'warning') return t('drive.history.coverage.warning', { seconds: String(Math.round(historyCoverage.freshnessSeconds ?? 0)) });
		if (level === 'stale') return t('drive.history.coverage.stale', { seconds: String(Math.round(historyCoverage.freshnessSeconds ?? 0)) });
		return t('drive.history.coverage.unknown');
	}

	function historyCoverageLabel(): string {
		if (!historyCoverage) return '';
		if (historyCoverage.omissions.length === 0) return t('drive.history.coverage.complete');
		return t('drive.history.coverage.omissions', { sources: historyCoverage.omissions.join(', ') });
	}

	async function loadHistory(reset = true): Promise<void> {
		const id = node.id;
		const requestId = ++historyRequestId;
		if (reset) {
			historyStatus = 'loading';
			historyError = '';
			historyItems = [];
			historyCoverage = null;
			historyGeneratedAt = null;
			historyHasMore = false;
			historyNextCursor = null;
		} else {
			historyLoadingMore = true;
			historyError = '';
		}
		try {
			const result = await api.history(id, {
				limit: HISTORY_LIMIT,
				cursor: reset ? null : historyNextCursor,
			});
			if (requestId !== historyRequestId || id !== node.id) return;
			historyItems = reset ? result.items : [...historyItems, ...result.items];
			historyHasMore = result.hasMore;
			historyNextCursor = result.nextCursor;
			historyCoverage = result.coverage;
			historyGeneratedAt = result.generatedAt;
			historyStatus = 'ready';
		} catch (e) {
			if (requestId !== historyRequestId || id !== node.id) return;
			if (isHistoryNotFound(e)) {
				historyStatus = 'not-found';
				historyError = '';
			} else {
				historyStatus = 'error';
				historyError = driveErrorMessage(e, 'drive.history.loadFailed');
			}
		} finally {
			if (requestId === historyRequestId) historyLoadingMore = false;
		}
	}

	function retryHistory(): void {
		void loadHistory(true);
	}

	function loadMoreHistory(): void {
		if (!historyHasMore || !historyNextCursor || historyLoadingMore) return;
		void loadHistory(false);
	}

	$effect(() => {
		const id = node.id;
		historyTab = 'current';
		void loadHistory(true);
		return () => {
			// Invalidate an in-flight response when the drawer switches files.
			historyRequestId += 1;
		};
	});

	async function submitLabel(versionId: number): Promise<void> {
		const label = labelValue.trim();
		if (!label) return;
		try {
			await api.setLabel(versionId, label);
			labelValue = '';
			addingLabelFor = null;
			onLabelsChanged?.();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function removeVersionLabel(versionId: number, label: string): Promise<void> {
		try {
			await api.removeLabel(versionId, label);
			onLabelsChanged?.();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	// ── P4: compare (Task 13) ────────────────────────────────────────────────
	let currentVersion = $derived(versions.find((v) => v.id === node.headVersionId) ?? versions[0]);
	let compareTarget = $state<DriveVersion | null>(null);

	// ── P4 Task 14: soft auto-checkout on edit-open + explicit check-out ────
	// Opening this drawer for an office-edit file type (with write access) IS
	// this app's "edit-open" moment — the webmail has no in-place office
	// editor, so version management here (upload-new-version / restore /
	// resolve) is the closest analog to "the user is working on this file".
	// Escalating to a hard lock is always an explicit "Check out" click.
	// untrack: openForEdit/close read+write driveLocks' OWN $state (nodeId/
	// mode/presence) — without untrack, those reads register as dependencies
	// of THIS effect (any $state read reachable synchronously from an effect
	// counts, even through a called function), so the effect's own write
	// re-triggers itself → effect_update_depth_exceeded. This effect must
	// depend only on node/canWrite, never on driveLocks' internals.
	$effect(() => {
		const id = node.id;
		const name = node.name;
		const versionId = node.headVersionId ?? null;
		if (canWrite) {
			untrack(() => void driveLocks.openForEdit(id, { name, versionId, branchId: null }));
		}
		return () => untrack(() => driveLocks.close());
	});

	// ── P4 Task 14 / P6 Task 12 / Task 13: watch toggle ───────────────────────
	// `watching` reads the shared driveWatches store (§5.6) so a toggle from
	// this drawer, the FileList quick-toggle, or the SubscriptionsSheet all
	// stay in sync — no more private per-component cache.
	let watching = $derived(driveWatches.isWatched(node.id));
	$effect(() => {
		void driveWatches.load();
	});
	async function toggleWatch() {
		try {
			await driveWatches.toggle(node.id);
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}
</script>

<aside class="vd" aria-label={t('drive.version.timeline')}>
	<div class="vd__head">
		<span class="vd__title">{node.name}</span>
		{#if node.lock}
			<span class="vd__presence" aria-live="polite">
				<Icon name="Lock" size={12} />
				{t('drive.lock.editingSince', { name: node.lock.holderName, time: formatDateTime(node.lock.acquiredAt) })}
			</span>
		{/if}
		<div class="vd__head-actions">
			{#if canWrite}
				{#if driveLocks.mode === 'hard'}
					<Button variant="ghost" size="sm" onclick={() => driveLocks.close()}>{t('drive.lock.checkIn')}</Button>
				{:else}
					<Button variant="ghost" size="sm" onclick={() => driveLocks.checkOut()}>{t('drive.lock.checkOut')}</Button>
				{/if}
			{/if}
			<IconButton
				label={watching ? t('drive.watch.watching') : t('drive.watch.watch')}
				size="sm"
				active={watching}
				aria-pressed={watching}
				onclick={toggleWatch}
			>
				<Icon name={watching ? 'BellRing' : 'Bell'} size={16} />
			</IconButton>
			<IconButton label={t('common.close')} onclick={onClose}>
				<Icon name="X" size={16} />
			</IconButton>
		</div>
	</div>

	{#if canWrite}
		<div class="vd__upload">
			<input
				bind:this={fileInput}
				type="file"
				class="vd__file-input"
				onchange={handleFileChange}
				aria-hidden="true"
				tabindex="-1"
			/>
			<Button variant="secondary" size="sm" onclick={pickFile}>{t('drive.upload.drop')}</Button>
			{#each officeChoices as choice (choice.providerId)}
				<Button variant="primary" size="sm" onclick={() => openOnline(choice)} disabled={officeLoading}>
					{t('drive.office.edit_online', { provider: choice.providerId })}
				</Button>
			{/each}
			{#each localOfficeChoices as app (app.id)}
				<Button variant="secondary" size="sm" onclick={() => openLocal(app.id)}>
					{t('drive.office.open_local', { app: app.label })}
				</Button>
			{/each}
		</div>
		{#if officeError}<p class="vd__error" role="alert">{officeError}</p>{/if}
	{/if}

	{#if loading}
		<div class="vd__loading"><Spinner /></div>
	{:else}
		{#if error}
			<p class="vd__error" role="alert">{error}</p>
		{/if}

		{#if historyStatus === 'ready'}
			<Tabs
				items={historyTabs}
				active={historyTab}
				onChange={(id) => (historyTab = id as HistoryTab)}
			/>

			{#if historyTab === 'current'}
				<section class="vd__current" aria-label={t('drive.history.current.label')}>
					<h3 class="vd__section-title">{t('drive.history.current.heading')}</h3>
					<dl class="vd__facts">
						<div>
							<dt>{t('drive.history.current.version')}</dt>
							<dd>{currentVersion ? `v${currentVersion.id}` : t('drive.history.current.none')}</dd>
						</div>
						<div>
							<dt>{t('drive.history.current.saved')}</dt>
							<dd>{currentVersion ? formatDateTime(currentVersion.createdAt) : t('drive.history.current.none')}</dd>
						</div>
						<div>
							<dt>{t('drive.history.current.classification')}</dt>
							<dd>{t(`drive.space.classification.${classification}`)}</dd>
						</div>
						<div>
							<dt>{t('drive.history.current.access')}</dt>
							<dd>{canWrite ? t('drive.history.current.canEdit') : t('drive.history.current.viewOnly')}</dd>
						</div>
					</dl>
				</section>
			{:else if historyTab === 'timeline'}
				<section class="vd__history" aria-label={t('drive.history.timeline.label')}>
					{#if historyCoverage}
						<div
							class:vd__coverage--warning={freshnessLevel(historyCoverage.freshnessSeconds) === 'warning'}
							class:vd__coverage--stale={freshnessLevel(historyCoverage.freshnessSeconds) === 'stale'}
							class="vd__coverage"
							role={freshnessLevel(historyCoverage.freshnessSeconds) === 'stale' ? 'alert' : 'status'}
						>
							<strong>{historyFreshnessLabel()}</strong>
							<span>{historyCoverageLabel()}</span>
							{#if historyCoverage.omissions.length > 0}
								<span>{t('drive.history.coverage.omissionHint')}</span>
							{/if}
						</div>
					{/if}

					{#if historyItems.length === 0}
						<p class="vd__history-empty">{t('drive.history.empty')}</p>
					{:else}
						<ol class="vd__history-list" aria-label={t('drive.history.timeline.label')}>
							{#each historyItems as item (historyKey(item))}
								<li class="vd__history-row">
									<div class="vd__history-row-head">
										<strong>{historyKindLabel(item.kind)}</strong>
										<time datetime={item.occurredAt}>{formatDateTime(item.occurredAt)}</time>
									</div>
									<div class="vd__history-row-meta">
										<span>{historySourceLabel(item.source)}</span>
										{#if historyDetailsSummary(item.details)}
											<span>{historyDetailsSummary(item.details)}</span>
										{/if}
									</div>
								</li>
							{/each}
						</ol>
					{/if}

					{#if historyHasMore}
						<Button variant="ghost" size="sm" onclick={loadMoreHistory} disabled={historyLoadingMore}>
							{historyLoadingMore ? t('drive.history.loadingMore') : t('drive.history.loadMore')}
						</Button>
					{/if}
					{#if historyError}
						<p class="vd__history-error" role="alert">{historyError}</p>
					{/if}
				</section>
			{:else}
				<section class="vd__details" aria-label={t('drive.history.details.label')}>
					<dl class="vd__facts">
						<div>
							<dt>{t('drive.history.details.generatedAt')}</dt>
							<dd>{historyGeneratedAt ? formatDateTime(historyGeneratedAt) : t('drive.history.current.none')}</dd>
						</div>
						<div>
							<dt>{t('drive.history.details.mode')}</dt>
							<dd>{historyCoverage?.mode ?? t('drive.history.current.none')}</dd>
						</div>
						<div>
							<dt>{t('drive.history.details.sources')}</dt>
							<dd>{historyCoverage?.coveredSources.join(', ') || t('drive.history.current.none')}</dd>
						</div>
						<div>
							<dt>{t('drive.history.details.omissions')}</dt>
							<dd>{historyCoverage?.omissions.join(', ') || t('drive.history.details.none')}</dd>
						</div>
					</dl>
					{#if historyItems.length > 0}
						<h3 class="vd__section-title">{t('drive.history.details.events')}</h3>
						<ul class="vd__details-list">
							{#each historyItems as item (historyKey(item))}
								<li class="vd__details-row">
									<div class="vd__history-row-head">
										<strong>{historyKindLabel(item.kind)}</strong>
										<time datetime={item.occurredAt}>{formatDateTime(item.occurredAt)}</time>
									</div>
									<dl class="vd__details-fields">
										<div><dt>{t('drive.history.details.source')}</dt><dd>{item.source}</dd></div>
										<div><dt>{t('drive.history.details.sourceId')}</dt><dd>{item.sourceId}</dd></div>
										<div><dt>{t('drive.history.details.sourceRank')}</dt><dd>{item.sourceRank}</dd></div>
									</dl>
									<pre class="vd__details-json">{historyDetailsJson(item.details)}</pre>
								</li>
							{/each}
						</ul>
					{/if}
				</section>
			{/if}
		{:else if historyStatus === 'error'}
			<div class="vd__history-error" role="alert">
				<span>{historyError}</span>
				<Button variant="ghost" size="sm" onclick={retryHistory}>{t('drive.history.retry')}</Button>
			</div>
		{/if}

		{#if historyStatus !== 'ready' || historyTab !== 'details'}
		{#each lanes as lane (lane.branchId ?? 'main')}
			<section class="vd__lane" aria-label={lane.label}>
				<h3 class="vd__lane-title">{lane.label}</h3>
				<ol class="vd__list">
					{#each lane.versions as version (version.id)}
						{@const isCurrent = version.id === node.headVersionId}
						<li class="vd__row">
							<div class="vd__row-head">
								{#if isCurrent}
									<Badge variant="accent" label={t('drive.version.current')} />
								{/if}
								{#if version.conflictOf != null}
									<Badge variant="warning" label={t('drive.version.conflict')} />
								{/if}
								<span class="vd__meta">{formatDateTime(version.createdAt)}</span>
							</div>
							<div class="vd__row-body">
								<span class="vd__size">{formatBytes(version.size)}</span>
								{#if version.note}<span class="vd__note">{version.note}</span>{/if}
							</div>
							{#if version.labels.length > 0 || canWrite}
								<div class="vd__labels">
									{#each version.labels as label (label)}
										<span class="vd__label-chip">
											{label}
											{#if canWrite}
												<button
													type="button"
													class="vd__label-remove"
													aria-label={t('drive.label.remove', { label })}
													onclick={() => removeVersionLabel(version.id, label)}
												>
													<Icon name="X" size={10} />
												</button>
											{/if}
										</span>
									{/each}
									{#if canWrite}
										{#if addingLabelFor === version.id}
											<input
												class="vd__label-input"
												bind:value={labelValue}
												placeholder={t('drive.label.placeholder')}
												onblur={() => {
													if (!labelValue.trim()) addingLabelFor = null;
												}}
												onkeydown={(e) => {
													if (e.key === 'Enter') submitLabel(version.id);
													if (e.key === 'Escape') {
														addingLabelFor = null;
														labelValue = '';
													}
												}}
											/>
										{:else}
											<IconButton
												label={t('drive.label.add')}
												size="sm"
												onclick={() => {
													addingLabelFor = version.id;
													labelValue = '';
												}}
											>
												<Icon name="Plus" size={12} />
											</IconButton>
										{/if}
									{/if}
								</div>
							{/if}
							<div class="vd__row-actions">
								{#if classification === 'regular'}
									<a class="vd__download" href={contentUrl(version.id)} download={node.name}>
										<Icon name="Download" size={14} />
										{t('drive.version.download')}
									</a>
								{:else}
									<Button variant="ghost" size="sm" title={t('drive.version.viewerOnly')} onclick={() => onView(version)}>
										<Icon name="Eye" size={14} />
										{t('drive.version.view')}
									</Button>
									<ExportRequestButton versionId={version.id} action="download" {classification} />
									<ExportRequestButton versionId={version.id} action="print" {classification} />
								{/if}
								{#if !isCurrent}
									<Button variant="ghost" size="sm" onclick={() => (compareTarget = version)}>
										{t('drive.compare.action')}
									</Button>
								{/if}
								{#if canWrite && !isCurrent}
									<Button variant="ghost" size="sm" onclick={() => onRestoreAsNew(version)}>
										{t('drive.version.restoreAsNew')}
									</Button>
								{/if}
							</div>
						</li>
					{/each}
				</ol>
			</section>
		{/each}
		{/if}
	{/if}
</aside>

{#if compareTarget && currentVersion}
	<Dialog open={true} title={t('drive.compare.title')} onClose={() => (compareTarget = null)} wide>
		<CompareView left={compareTarget} right={currentVersion} fileName={node.name} />
	</Dialog>
{/if}

<style>
	.vd {
		width: 320px;
		flex-shrink: 0;
		border-left: 1px solid var(--border-default);
		display: flex;
		flex-direction: column;
		overflow-y: auto;
	}
	.vd__head {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: var(--space-1) var(--space-2);
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.vd__head-actions {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		margin-left: auto;
	}
	.vd__presence {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
		color: var(--text-caption);
		width: 100%;
	}
	.vd__title {
		font-weight: 600;
		font-size: var(--text-sm);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.vd__upload {
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.vd__file-input {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
	.vd__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
	.vd__section-title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
	}
	.vd__current,
	.vd__history,
	.vd__details {
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.vd__facts {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
		gap: var(--space-2) var(--space-3);
		margin: var(--space-3) 0 0;
	}
	.vd__facts > div,
	.vd__details-fields > div {
		min-width: 0;
	}
	.vd__facts dt,
	.vd__details-fields dt {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		text-transform: uppercase;
		letter-spacing: 0.02em;
	}
	.vd__facts dd,
	.vd__details-fields dd {
		margin: var(--space-1) 0 0;
		font-size: var(--text-xs);
		color: var(--text-primary);
		overflow-wrap: anywhere;
	}
	.vd__coverage {
		display: flex;
		flex-direction: column;
		gap: 2px;
		margin-bottom: var(--space-3);
		padding: var(--space-2);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
	}
	.vd__coverage--warning {
		border-color: var(--warning-border, var(--border-subtle));
		background: var(--warning-bg, var(--surface-sunken));
	}
	.vd__coverage--stale {
		border-color: var(--danger-border, var(--border-subtle));
		background: var(--danger-bg, var(--surface-sunken));
	}
	.vd__history-list,
	.vd__details-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.vd__history-row,
	.vd__details-row {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
	}
	.vd__history-row-head {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
	}
	.vd__history-row-head time {
		margin-left: auto;
		font-size: var(--text-xs);
		color: var(--text-caption);
		white-space: nowrap;
	}
	.vd__history-row-meta {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-top: var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.vd__history-row-meta span + span {
		padding-left: var(--space-2);
		border-left: 1px solid var(--border-subtle);
	}
	.vd__history-empty {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.vd__history-error {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		margin: var(--space-2) var(--space-3);
		padding: var(--space-2);
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
	}
	.vd__details-list {
		margin-top: var(--space-2);
	}
	.vd__details-fields {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: var(--space-2);
		margin: var(--space-2) 0 0;
	}
	.vd__details-json {
		max-height: 180px;
		margin: var(--space-2) 0 0;
		padding: var(--space-2);
		overflow: auto;
		font: var(--text-xs) / 1.4 var(--font-mono);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
		color: var(--text-secondary);
		background: var(--surface-sunken);
		border-radius: var(--radius-xs);
	}
	.vd__error {
		margin: var(--space-2) var(--space-3) 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.vd__lane-title {
		margin: 0;
		padding: var(--space-2) var(--space-3) 0;
		font-size: var(--text-xs);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.02em;
		color: var(--text-caption);
	}
	.vd__labels {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-1);
		margin-top: var(--space-1);
	}
	.vd__label-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-xs);
		padding: 1px 6px;
	}
	.vd__label-remove {
		display: inline-flex;
		border: none;
		background: none;
		padding: 0;
		color: var(--text-caption);
		cursor: pointer;
	}
	.vd__label-input {
		font-size: var(--text-xs);
		border: 1px solid var(--border-focus, var(--indigo-600));
		border-radius: var(--radius-xs);
		padding: 1px 6px;
		background: var(--surface-card);
		color: var(--text-primary);
		min-width: 100px;
	}
	.vd__list {
		list-style: none;
		margin: 0;
		padding: var(--space-2);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.vd__row {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
	}
	.vd__row-head {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.vd__meta {
		font-size: var(--text-xs);
		color: var(--text-caption);
		margin-left: auto;
	}
	.vd__row-body {
		display: flex;
		gap: var(--space-2);
		margin-top: var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.vd__note {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.vd__row-actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-2);
	}
	.vd__download {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
		color: var(--link);
		text-decoration: none;
	}
	.vd__download:hover {
		text-decoration: underline;
	}
</style>
