<svelte:options runes={true} />

<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t, locale } from '$lib/i18n';
	import { Card, Table, Badge, Button, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';

	interface JobRow {
		id: string;
		queue: string;
		status: string;
		normalized: string;
		label: string;
		attemptCount: number;
		nextAttemptAt: string | null;
		lastError: string | null;
		queuedAt: string;
	}
	interface Summary {
		active: number;
		failed: number;
		dead: number;
		done: number;
		total: number;
	}

	type QueueId = 'journal' | 'outbound' | 'scheduled';

	// Per-section reactive state — never a single global `loading` (D2).
	interface QueueState {
		summary: Summary | null;
		rows: JobRow[];
		loading: boolean;
		/** Inline section error (full failure before any data). */
		error: string;
		/** Refresh failed while rows were already shown — keep rows, strip on top (D6 PARTIAL). */
		stale: boolean;
		/** When this section was last successfully loaded (for the stale strip age). */
		loadedAt: number | null;
		/** false = attention-only (default), true = show all (D1). */
		showAll: boolean;
	}

	const QUEUE_IDS: QueueId[] = ['journal', 'outbound', 'scheduled'];

	function freshState(): QueueState {
		return { summary: null, rows: [], loading: false, error: '', stale: false, loadedAt: null, showAll: false };
	}

	let q = $state<Record<QueueId, QueueState>>({
		journal: freshState(),
		outbound: freshState(),
		scheduled: freshState()
	});

	// Verdict state — computed client-side from the three summaries (D1).
	let checkedAt = $state<number | null>(null);
	let verdictStale = $state(false);
	let verdictLoadError = $state(false);
	/** Page-level (tool-failure) error: the very first load failed entirely (D6). */
	let pageError = $state('');
	let firstLoadDone = $state(false);

	// Per-row inline confirm + retry tracking.
	let confirming = $state<Set<string>>(new Set());
	let retrying = $state<Set<string>>(new Set());

	// Reduced-motion: gate the row-exit animation (D6 Pass 6).
	let reduceMotion = $state(false);

	// `now` drives relative-time recompute so the verdict/stale ages refresh.
	let now = $state(Date.now());

	const canWrite = $derived(hasPermission($adminPermissions, 'queue.write'));

	// Columns are locale-reactive via the {#key $locale} layout wrap; reference
	// $locale so the labels recompute on a language switch.
	const COLUMNS = $derived.by<TableColumn[]>(() => {
		void $locale;
		return [
			{ key: 'status', label: t('admin.jobs.col.status'), sortable: false },
			{ key: 'item', label: t('admin.jobs.col.item'), sortable: false, mono: true },
			{ key: 'tries', label: t('admin.jobs.col.tries'), sortable: false, mono: true },
			{ key: 'age', label: t('admin.jobs.col.age'), sortable: false, mono: true },
			{ key: 'error', label: t('admin.jobs.col.error'), sortable: false },
			{ key: 'actions', label: '', sortable: false }
		];
	});

	function queueMeta(id: QueueId) {
		void $locale;
		return { title: t(`admin.jobs.queue.${id}.title`), desc: t(`admin.jobs.queue.${id}.desc`) };
	}

	onMount(() => {
		void loadAll();
		const id = setInterval(() => (now = Date.now()), 30_000);
		if (typeof window !== 'undefined' && window.matchMedia) {
			reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
		}
		return () => clearInterval(id);
	});

	function statusParam(state: QueueState): string {
		return state.showAll ? 'all' : 'attention';
	}

	/** Load one queue's summary + rows. Keeps stale rows on a refresh failure. */
	async function loadQueue(id: QueueId): Promise<boolean> {
		const state = q[id];
		state.loading = true;
		state.error = '';
		const hadRows = state.rows.length > 0 || state.summary !== null;
		try {
			const [sRes, lRes] = await Promise.all([
				adminFetch(`/admin/jobs/summary/${id}`),
				adminFetch(`/admin/jobs/${id}?status=${statusParam(state)}&limit=100`)
			]);
			state.summary = (await sRes.json()) as Summary;
			state.rows = ((await lRes.json()) ?? []) as JobRow[];
			state.stale = false;
			state.loadedAt = Date.now();
			return true;
		} catch (e) {
			const msg = parseError(e).message;
			if (hadRows) {
				// PARTIAL (D6): keep the visible data, show a non-blocking stale strip.
				state.stale = true;
			} else {
				state.error = msg || t('admin.jobs.loadError');
			}
			return false;
		} finally {
			state.loading = false;
		}
	}

	async function loadAll() {
		const results = await Promise.all(QUEUE_IDS.map((id) => loadQueue(id)));
		const allOk = results.every(Boolean);
		const anyData = QUEUE_IDS.some((id) => q[id].summary !== null);
		if (allOk) {
			checkedAt = Date.now();
			verdictStale = false;
			verdictLoadError = false;
			pageError = '';
		} else if (anyData) {
			// Some sections refreshed; verdict keeps its last value, muted re-check note.
			verdictStale = true;
		} else {
			// Tool-failure arc (D6): nothing loaded at all → page-level error state.
			verdictLoadError = true;
			pageError = t('admin.jobs.verdict.loadError');
		}
		firstLoadDone = true;
	}

	// ── Verdict (D1/D6) — worst-first, dead before failed ───────────────────────
	interface VerdictItem {
		queue: QueueId;
		state: 'dead' | 'failed';
		count: number;
	}

	const verdictItems = $derived.by<VerdictItem[]>(() => {
		const items: VerdictItem[] = [];
		for (const id of QUEUE_IDS) {
			const s = q[id].summary;
			if (!s) continue;
			if (s.dead > 0) items.push({ queue: id, state: 'dead', count: s.dead });
		}
		for (const id of QUEUE_IDS) {
			const s = q[id].summary;
			if (!s) continue;
			if (s.failed > 0) items.push({ queue: id, state: 'failed', count: s.failed });
		}
		return items;
	});

	const hasTrouble = $derived(verdictItems.length > 0);

	function formatSince(ms: number | null): string {
		if (!ms) return '';
		void now;
		const seconds = Math.floor((Date.now() - ms) / 1000);
		if (seconds < 60) return `${seconds}s`;
		if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
		if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
		return `${Math.floor(seconds / 86400)}d`;
	}

	function formatSinceIso(iso: string): string {
		if (!iso) return '';
		return formatSince(new Date(iso).getTime()) + ' ago';
	}

	function truncate(s: string, n: number): string {
		return s.length > n ? s.slice(0, n) + '…' : s;
	}

	function normalizedVariant(n: string): 'info' | 'danger' | 'warning' | 'neutral' {
		switch (n) {
			case 'active':
				return 'info';
			case 'failed':
				return 'warning';
			case 'dead':
				return 'danger';
			default:
				return 'neutral';
		}
	}

	async function toggleShowAll(id: QueueId) {
		q[id].showAll = !q[id].showAll;
		await loadQueue(id);
	}

	// Jump-to-queue: scroll AND move focus to the section heading (D1/D6).
	async function jumpTo(id: QueueId) {
		await tick();
		const el = document.getElementById(`sj-jobs-${id}`);
		if (el) {
			el.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
			el.focus();
		}
	}

	// ── Retry flow with inline confirm (D3) ─────────────────────────────────────
	function startConfirm(rowId: string) {
		confirming.add(rowId);
		confirming = new Set(confirming);
	}
	function cancelConfirm(rowId: string, triggerId: string) {
		confirming.delete(rowId);
		confirming = new Set(confirming);
		// Return focus to the Retry trigger on cancel (D6).
		queueMicrotask(() => document.getElementById(triggerId)?.focus());
	}

	async function confirmRetry(rowId: string) {
		confirming.delete(rowId);
		confirming = new Set(confirming);
		retrying.add(rowId);
		retrying = new Set(retrying);
		try {
			await adminFetch(`/admin/jobs/journal/${rowId}/retry`, { method: 'POST' });
			// Drop the row from the journal section, then move focus sensibly (D6).
			const j = q.journal;
			const idx = j.rows.findIndex((r) => r.id === rowId);
			j.rows = j.rows.filter((r) => r.id !== rowId);
			// Recompute the verdict from refreshed summaries (it may flip to green).
			await loadQueue('journal');
			const stillTrouble = QUEUE_IDS.some((id) => {
				const s = q[id].summary;
				return s ? s.dead > 0 || s.failed > 0 : false;
			});
			if (!stillTrouble) checkedAt = Date.now();
			showToast(t('admin.jobs.retry.success'));
			await moveFocusAfterDrop('journal', idx);
		} catch (e) {
			// Inline row error + toast (D2) — not the page-top banner.
			q.journal.error = parseError(e).message || t('admin.jobs.retry.error');
			showToast(t('admin.jobs.retry.error'));
		} finally {
			retrying.delete(rowId);
			retrying = new Set(retrying);
		}
	}

	async function moveFocusAfterDrop(id: QueueId, droppedIdx: number) {
		await tick();
		const rows = q[id].rows;
		const next = rows[droppedIdx] ?? rows[droppedIdx - 1];
		if (next) {
			document.getElementById(`sj-retry-${next.id}`)?.focus();
		} else {
			document.getElementById(`sj-jobs-${id}`)?.focus();
		}
	}
</script>

<div class="sj-jobs-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.jobs.title')}</h1>
			<p>{t('admin.jobs.subtitle')}</p>
		</div>
		<div class="sj-page-head-right">
			<Button
				variant="secondary"
				size="sm"
				onclick={loadAll}
				disabled={QUEUE_IDS.some((id) => q[id].loading)}
			>
				{t('admin.jobs.refresh')}
			</Button>
		</div>
	</header>

	<!-- Cross-queue health verdict (D1): role=status + aria-live polite. -->
	<div
		class="sj-verdict {hasTrouble ? 'sj-verdict--danger' : 'sj-verdict--ok'}"
		role="status"
		aria-live="polite"
	>
		{#if verdictLoadError}
			<p class="sj-verdict__text">{t('admin.jobs.verdict.loadError')}</p>
			<Button variant="secondary" size="sm" onclick={loadAll}>{t('admin.jobs.refresh')}</Button>
		{:else if !firstLoadDone}
			<div class="sj-verdict__skel" aria-hidden="true"></div>
		{:else if hasTrouble}
			<div class="sj-verdict__body">
				<p class="sj-verdict__text">{t('admin.jobs.verdict.actionLabel')}:</p>
				<ul class="sj-verdict__list">
					{#each verdictItems as it (it.queue + it.state)}
						<li>
							<button class="sj-verdict__jump" type="button" onclick={() => jumpTo(it.queue)}>
								{t('admin.jobs.verdict.summaryItem', {
									count: String(it.count),
									state: t(`admin.jobs.state.${it.state}`),
									queue: queueMeta(it.queue).title
								})}
							</button>
						</li>
					{/each}
				</ul>
			</div>
			{#if verdictStale}
				<span class="sj-verdict__note">{t('admin.jobs.verdict.staleCheck')}</span>
			{/if}
		{:else}
			<p class="sj-verdict__text">
				{t('admin.jobs.verdict.clear', { age: formatSince(checkedAt) })}
			</p>
			{#if verdictStale}
				<span class="sj-verdict__note">{t('admin.jobs.verdict.staleCheck')}</span>
			{/if}
		{/if}
	</div>

	{#each QUEUE_IDS as id (id)}
		{@const state = q[id]}
		{@const meta = queueMeta(id)}
		{@const s = state.summary}
		<section class="sj-queue-section">
			<div class="sj-section-head">
				<h2 id={`sj-jobs-${id}`} tabindex="-1">{meta.title}</h2>
				<p>{meta.desc}</p>
			</div>

			{#if s}
				<div class="sj-stat-grid">
					<Card>
						{#snippet children()}
							<div class="sj-stat">
								<span class="sj-stat-label">{t('admin.jobs.state.dead')}</span>
								<span class="sj-stat-value sj-stat-value--danger">{s.dead}</span>
							</div>
						{/snippet}
					</Card>
					<Card>
						{#snippet children()}
							<div class="sj-stat">
								<span class="sj-stat-label">{t('admin.jobs.state.failed')}</span>
								<span class="sj-stat-value sj-stat-value--warn">{s.failed}</span>
							</div>
						{/snippet}
					</Card>
					<Card>
						{#snippet children()}
							<div class="sj-stat">
								<span class="sj-stat-label">{t('admin.jobs.col.active')}</span>
								<span class="sj-stat-value">{s.active}</span>
							</div>
						{/snippet}
					</Card>
					<Card>
						{#snippet children()}
							<div class="sj-stat">
								<span class="sj-stat-label">{t('admin.jobs.col.done')}</span>
								<span class="sj-stat-value">{s.done}</span>
							</div>
						{/snippet}
					</Card>
				</div>
			{/if}

			<div class="sj-section-toolbar">
				<Button variant="ghost" size="sm" onclick={() => toggleShowAll(id)} disabled={state.loading}>
					{state.showAll ? t('admin.jobs.showAttention') : t('admin.jobs.showAll')}
				</Button>
				{#if state.loading}
					<span class="sj-section-spin"><Spinner size={16} /></span>
				{/if}
			</div>

			{#if state.stale}
				<div class="sj-stale-strip" role="status">
					{t('admin.jobs.staleStrip', { age: formatSince(state.loadedAt) })}
				</div>
			{/if}

			{#if state.error}
				<div class="sj-alert sj-alert--danger" role="alert">
					<span>{state.error}</span>
					<Button variant="secondary" size="sm" onclick={() => loadQueue(id)}>{t('admin.jobs.refresh')}</Button>
				</div>
			{/if}

			<Card flush={true}>
				{#if state.loading && state.rows.length === 0 && !state.error}
					<EmptyState title={t('admin.jobs.loading')} />
				{:else if state.rows.length === 0 && !state.error}
					{#if s && s.total > 0}
						<!-- Healthy empty: failures cleared, done count as subtext (D2). -->
						<EmptyState title={t('admin.jobs.empty.healthy')}>
							{#snippet action()}
								<span class="sj-empty-sub">{t('admin.jobs.empty.healthyDone', { count: String(s.done) })}</span>
							{/snippet}
						</EmptyState>
					{:else}
						<!-- Idle empty: nothing has ever queued (D2). -->
						<EmptyState title={t('admin.jobs.empty.idle')} />
					{/if}
				{:else if state.rows.length > 0}
					{@const tableRows = state.rows as unknown as Record<string, unknown>[]}
					<Table columns={COLUMNS} rows={tableRows}>
						{#snippet cell(row, col)}
							{@const item = row as unknown as JobRow}
							{#if col.key === 'status'}
								<Badge variant={normalizedVariant(item.normalized)} dot={true} label={item.status} />
							{:else if col.key === 'item'}
								<span class="sj-item-cell" title={item.label || ''}>{truncate(item.label || '', 40)}</span>
							{:else if col.key === 'tries'}
								{item.attemptCount}
							{:else if col.key === 'age'}
								{formatSinceIso(item.queuedAt)}
							{:else if col.key === 'error'}
								<span
									class="sj-error-cell"
									class:sj-error-cell--error={!!item.lastError}
									title={item.lastError || ''}
								>
									{truncate(item.lastError || '—', 48)}
								</span>
							{:else if col.key === 'actions'}
								<div class="sj-actions">
									{#if item.queue === 'journal' && item.normalized === 'dead'}
										{#if confirming.has(item.id)}
											<div class="sj-confirm" role="group" aria-label={t('admin.jobs.retry.confirm')}>
												<span class="sj-confirm__copy">{t('admin.jobs.retry.confirm')}</span>
												<Button
													variant="primary"
													size="sm"
													onclick={() => confirmRetry(item.id)}
													disabled={retrying.has(item.id)}
												>
													{retrying.has(item.id) ? t('admin.jobs.retrying') : t('admin.jobs.retry.confirmAction')}
												</Button>
												<Button
													variant="ghost"
													size="sm"
													onclick={() => cancelConfirm(item.id, `sj-retry-${item.id}`)}
												>
													{t('admin.jobs.retry.cancel')}
												</Button>
											</div>
										{:else}
											<Button
												variant="secondary"
												size="sm"
												onclick={() => startConfirm(item.id)}
												disabled={retrying.has(item.id) || !canWrite}
												id={`sj-retry-${item.id}`}
											>
												{retrying.has(item.id) ? t('admin.jobs.retrying') : t('admin.jobs.retry')}
											</Button>
										{/if}
									{/if}
								</div>
							{/if}
						{/snippet}
					</Table>
				{/if}
			</Card>
		</section>
	{/each}
</div>

<style>
	.sj-jobs-page {
		max-width: 980px;
		font-family: var(--font-sans);
	}
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left {
		flex: 1 1 260px;
		min-width: 0;
	}
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-head-left p {
		margin: 4px 0 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-page-head-right {
		display: flex;
		gap: 8px;
		align-items: center;
	}

	/* Verdict banner — token'd alert surfaces, no raw color (D6 Pass 5). */
	.sj-verdict {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 8px 14px;
		padding: 12px 14px;
		border-radius: var(--radius-md);
		border: 1px solid transparent;
		margin-bottom: 20px;
		font-size: var(--text-sm);
	}
	.sj-verdict--ok {
		background: var(--success-bg);
		color: var(--success-fg);
		border-color: var(--success-fg);
	}
	.sj-verdict--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-color: var(--danger-fg);
	}
	.sj-verdict__body {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: 6px 10px;
	}
	.sj-verdict__text {
		margin: 0;
		font-weight: 600;
	}
	.sj-verdict__list {
		display: flex;
		flex-wrap: wrap;
		gap: 6px 12px;
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.sj-verdict__jump {
		font-family: inherit;
		font-size: inherit;
		font-weight: 600;
		color: inherit;
		background: none;
		border: none;
		padding: 0;
		text-decoration: underline;
		cursor: pointer;
	}
	.sj-verdict__jump:focus-visible {
		outline: var(--focus-ring);
		outline-offset: 2px;
		border-radius: var(--radius-sm);
	}
	.sj-verdict__note {
		font-size: var(--text-sm);
		opacity: 0.85;
		font-weight: 400;
	}
	.sj-verdict__skel {
		height: 18px;
		width: 220px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		animation: sj-pulse 1.4s ease-in-out infinite;
	}

	@keyframes sj-pulse {
		0%,
		100% {
			opacity: 0.5;
		}
		50% {
			opacity: 1;
		}
	}

	.sj-queue-section {
		margin-bottom: 28px;
	}
	.sj-section-head h2 {
		margin: 0;
		font-size: var(--text-lg);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-section-head h2:focus-visible {
		outline: var(--focus-ring);
		outline-offset: 2px;
		border-radius: var(--radius-sm);
	}
	.sj-section-head p {
		margin: 2px 0 10px;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}

	/* Reuse the /admin/queue summary-tile pattern (D5/D6 Pass 5). */
	.sj-stat-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
		gap: 12px;
		margin-bottom: 12px;
	}
	.sj-stat {
		padding: 4px 0;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.sj-stat-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-caption);
		text-transform: capitalize;
	}
	.sj-stat-value {
		font-size: var(--text-xl);
		font-weight: 600;
		color: var(--text-primary);
		font-family: var(--font-mono);
	}
	.sj-stat-value--warn {
		color: var(--warning-fg);
	}
	.sj-stat-value--danger {
		color: var(--danger-fg);
	}

	.sj-section-toolbar {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-bottom: 8px;
	}
	.sj-section-spin {
		display: inline-flex;
	}

	.sj-stale-strip {
		padding: 6px 12px;
		margin-bottom: 8px;
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-sm);
	}

	.sj-alert {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 8px;
		font-size: var(--text-sm);
	}
	.sj-alert--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}

	.sj-item-cell {
		max-width: 240px;
		overflow: hidden;
		text-overflow: ellipsis;
		display: block;
		white-space: nowrap;
	}
	.sj-error-cell {
		max-width: 300px;
		overflow: hidden;
		text-overflow: ellipsis;
		display: block;
		white-space: nowrap;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-error-cell--error {
		color: var(--danger-fg);
		font-family: var(--font-mono);
	}
	.sj-empty-sub {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}

	.sj-actions {
		display: flex;
		gap: 6px;
		justify-content: flex-end;
	}
	.sj-confirm {
		display: flex;
		align-items: center;
		gap: 8px;
		justify-content: flex-end;
		flex-wrap: wrap;
	}
	.sj-confirm__copy {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-verdict__skel {
			animation: none;
		}
	}
</style>
