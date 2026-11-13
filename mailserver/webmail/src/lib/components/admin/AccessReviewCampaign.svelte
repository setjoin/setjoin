<svelte:options runes={true} />
<script lang="ts">
	import { onMount, tick } from 'svelte';
	import {
		Table,
		Badge,
		Button,
		Dialog,
		Input,
		EmptyState,
		Tag,
		Checkbox,
		Tooltip,
		showToast
	} from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import {
		getAccessReview,
		decideAccessReviewItem,
		decideAccessReviewBulk,
		closeAccessReview,
		type AccessReviewDetail,
		type AccessReviewItem
	} from '$lib/admin/accessReviews';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let { id, onBack }: { id: number; onBack: () => void } = $props();

	let detail = $state<AccessReviewDetail | null>(null);
	let loading = $state(true);
	let error = $state('');
	let filter = $state<'all' | 'undecided' | 'keep' | 'revoke'>('undecided');
	let search = $state('');
	let selected = $state<Set<number>>(new Set());
	let busyItems = $state<Set<number>>(new Set());
	let bulkBusy = $state(false);
	let closeOpen = $state(false);
	let closeBusy = $state(false);
	let headingEl = $state<HTMLElement | null>(null);

	// Progress derived values
	let kept = $derived(detail?.items.filter((i) => i.decision === 'keep').length ?? 0);
	let revoked = $derived(detail?.items.filter((i) => i.decision === 'revoke').length ?? 0);
	let undecided = $derived(detail?.items.filter((i) => i.decision === 'undecided').length ?? 0);
	let total = $derived(detail?.items.length ?? 0);
	let reviewed = $derived(kept + revoked);
	let readyToClose = $derived(undecided === 0 && total > 0);

	let isClosed = $derived(detail?.campaign.status === 'closed');

	// Filtered + searched items
	let filteredItems = $derived(
		(() => {
			if (!detail) return [] as AccessReviewItem[];
			let items = detail.items as AccessReviewItem[];
			if (filter !== 'all') items = items.filter((i) => i.decision === filter);
			if (search.trim()) {
				const q = search.trim().toLowerCase();
				items = items.filter(
					(i) =>
						i.userEmail.toLowerCase().includes(q) || i.roleName.toLowerCase().includes(q)
				);
			}
			return items;
		})()
	);

	let allSelectedOnPage = $derived(
		filteredItems.length > 0 && filteredItems.every((i) => selected.has(i.id))
	);
	let someSelectedOnPage = $derived(filteredItems.some((i) => selected.has(i.id)));
	let selectedCount = $derived(selected.size);

	// Undecided ids for "Keep all remaining"
	let undecidedIds = $derived(
		(detail?.items ?? []).filter((i) => i.decision === 'undecided').map((i) => i.id)
	);

	const COLUMNS: TableColumn[] = [
		{ key: 'select', label: '' },
		{ key: 'user', label: t('admin.access_reviews.col_user') },
		{ key: 'role', label: t('admin.access_reviews.col_role') },
		{ key: 'scope', label: t('admin.access_reviews.col_scope') },
		{ key: 'granted', label: t('admin.access_reviews.col_granted') },
		{ key: 'grantedby', label: t('admin.access_reviews.col_grantedby') },
		{ key: 'decision', label: t('admin.access_reviews.col_decision') }
	];

	async function load() {
		loading = true;
		error = '';
		try {
			detail = await getAccessReview(id);
			await tick();
			headingEl?.focus();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(load);

	function toggleSelectAll() {
		if (allSelectedOnPage) {
			const next = new Set(selected);
			filteredItems.forEach((i) => next.delete(i.id));
			selected = next;
		} else {
			const next = new Set(selected);
			filteredItems.forEach((i) => next.add(i.id));
			selected = next;
		}
	}

	function toggleItem(itemId: number) {
		const next = new Set(selected);
		if (next.has(itemId)) next.delete(itemId);
		else next.add(itemId);
		selected = next;
	}

	async function decide(item: AccessReviewItem, decision: 'keep' | 'revoke') {
		if (isClosed) return;
		if (decision === 'revoke' && item.isSso) return;
		const prev = item.decision;
		// Svelte 5 $state proxy — direct mutation is reactive
		item.decision = decision;
		busyItems = new Set(busyItems).add(item.id);
		try {
			await decideAccessReviewItem(id, item.id, decision);
		} catch (e) {
			// Revert
			item.decision = prev as typeof item.decision;
			showToast(t('admin.access_reviews.decide_error'));
		} finally {
			const next = new Set(busyItems);
			next.delete(item.id);
			busyItems = next;
		}
	}

	async function doBulk(decision: 'keep' | 'revoke') {
		const ids = [...selected].filter((sid) => {
			const item = detail?.items.find((i) => i.id === sid);
			return item && !(decision === 'revoke' && item.isSso);
		});
		if (ids.length === 0) return;
		bulkBusy = true;
		try {
			const result = await decideAccessReviewBulk(id, ids, decision);
			ids.forEach((itemId) => {
				const item = detail?.items.find((i) => i.id === itemId);
				if (item) item.decision = decision;
			});
			selected = new Set();
			if (result.skipped > 0) {
				showToast(
					t('admin.access_reviews.bulk_done', {
						applied: String(result.applied),
						skipped: String(result.skipped)
					})
				);
			} else {
				showToast(
					decision === 'keep'
						? t('admin.access_reviews.bulk_kept', { n: String(result.applied) })
						: t('admin.access_reviews.bulk_revoked', { n: String(result.applied) })
				);
			}
		} catch (e) {
			showToast(parseError(e).message);
		} finally {
			bulkBusy = false;
		}
	}

	async function doKeepAllRemaining() {
		if (undecidedIds.length === 0) return;
		bulkBusy = true;
		try {
			const result = await decideAccessReviewBulk(id, undecidedIds, 'keep');
			undecidedIds.forEach((itemId) => {
				const item = detail?.items.find((i) => i.id === itemId);
				if (item) item.decision = 'keep';
			});
			selected = new Set();
			showToast(t('admin.access_reviews.bulk_kept', { n: String(result.applied) }));
		} catch (e) {
			showToast(parseError(e).message);
		} finally {
			bulkBusy = false;
		}
	}

	async function doClose() {
		closeBusy = true;
		try {
			await closeAccessReview(id);
			showToast(
				t('admin.access_reviews.close_done', {
					revoked: String(revoked),
					applied: String(revoked)
				})
			);
			closeOpen = false;
			await load();
		} catch (e) {
			const msg = parseError(e).message;
			if (msg.includes('409') || msg.toLowerCase().includes('closed')) {
				// Already closed — refresh to read-only
				closeOpen = false;
				await load();
			} else {
				showToast(msg);
			}
		} finally {
			closeBusy = false;
		}
	}

</script>

{#if error && !detail}
	<div class="sj-arc-error">
		<div class="sj-alert-danger" role="alert">{error}</div>
		<Button variant="ghost" onclick={onBack}>{t('common.back')}</Button>
	</div>
{:else}
	<!-- Breadcrumb nav -->
	<nav class="sj-arc-breadcrumb" aria-label={t('admin.access_reviews.breadcrumb_label')}>
		<button class="sj-arc-back" onclick={onBack}>‹ {t('admin.access_reviews.title')}</button>
		{#if detail}
			<span class="sj-arc-sep" aria-hidden="true">/</span>
			<span class="sj-arc-current">{detail.campaign.name}</span>
		{/if}
	</nav>

	{#if loading}
		<div class="sj-arc-skeleton" aria-hidden="true">
			{#each [1, 2, 3, 4] as _}<div class="sj-arc-skel-row"></div>{/each}
		</div>
	{:else if detail}
		<!-- Campaign header -->
		<div class="sj-arc-header">
			<h2 class="sj-arc-name" tabindex="-1" bind:this={headingEl}>{detail.campaign.name}</h2>
			<div class="sj-arc-meta-row">
				<Badge
					variant={isClosed ? 'success' : 'warning'}
					dot={true}
					label={isClosed
						? t('admin.access_reviews.closed')
						: t('admin.access_reviews.open')}
				/>
				{#if isClosed && detail.campaign.closedAt}
					<span class="sj-arc-meta">
						{t('admin.access_reviews.closed_by', {
							date: detail.campaign.closedAt.slice(0, 10),
							by: detail.campaign.closedBy ?? ''
						})}
						·
						{t('admin.access_reviews.close_summary', {
							revoked: String(revoked),
							kept: String(kept),
							not_reviewed: String(undecided)
						})}
					</span>
				{:else}
					<span class="sj-arc-meta"
						>{detail.campaign.createdAt?.slice(0, 10)} · {detail.campaign.createdBy}</span
					>
				{/if}
			</div>
			<!-- Progress summary: aria-live so SR hears updates after each decision -->
			<div class="sj-arc-progress" aria-live="polite" aria-atomic="true">
				{#if readyToClose && !isClosed}
					<strong class="sj-arc-ready"
						>{t('admin.access_reviews.progress', {
							reviewed: String(reviewed),
							total: String(total)
						})} — {t('admin.access_reviews.ready_to_close')}</strong
					>
				{:else}
					{t('admin.access_reviews.progress', {
						reviewed: String(reviewed),
						total: String(total)
					})}
					{#if !isClosed}
						· {t('admin.access_reviews.progress_revoke', { n: String(revoked) })}
						· {t('admin.access_reviews.progress_kept', { n: String(kept) })}
						· {t('admin.access_reviews.progress_undecided', { n: String(undecided) })}
					{/if}
				{/if}
			</div>
		</div>

		<!-- Controls row -->
		<div class="sj-arc-controls">
			<div class="sj-arc-filters" role="group" aria-label={t('admin.access_reviews.filter_label')}>
				{#each (['all', 'undecided', 'keep', 'revoke'] as const) as f}
					<button
						class="sj-arc-filter"
						class:sj-arc-filter--active={filter === f}
						onclick={() => (filter = f)}
					>
						{t(`admin.access_reviews.filter_${f}`)}
					</button>
				{/each}
			</div>
			<Input
				placeholder={t('admin.access_reviews.search_placeholder')}
				bind:value={search}
			/>
			{#if !isClosed}
				{#if undecidedIds.length > 0}
					<Button variant="ghost" onclick={doKeepAllRemaining} disabled={bulkBusy}>
						{t('admin.access_reviews.keep_all_remaining')}
					</Button>
				{/if}
				<Button
					variant={readyToClose ? 'primary' : 'ghost'}
					onclick={() => (closeOpen = true)}
				>
					{t('admin.access_reviews.close')}
				</Button>
			{/if}
		</div>

		<!-- Select-all toolbar (only for open campaigns) -->
		{#if !isClosed && filteredItems.length > 0}
			<div class="sj-arc-select-bar">
				<Checkbox
					checked={allSelectedOnPage}
					indeterminate={!allSelectedOnPage && someSelectedOnPage}
					onchange={toggleSelectAll}
					label={t('admin.access_reviews.select_all')}
				/>
			</div>
		{/if}

		<!-- Bulk action bar: aria-live so SR hears selection changes -->
		{#if selectedCount > 0 && !isClosed}
			<div
				class="sj-arc-bulk-bar"
				aria-live="polite"
				role="region"
				aria-label={t('admin.access_reviews.bulk_bar_label')}
			>
				<span class="sj-arc-bulk-count"
					>{t('admin.access_reviews.selected', { n: String(selectedCount) })}</span
				>
				<Button variant="ghost" size="sm" onclick={() => doBulk('keep')} disabled={bulkBusy}
					>{t('admin.access_reviews.keep_selected')}</Button
				>
				<Button variant="ghost" size="sm" onclick={() => doBulk('revoke')} disabled={bulkBusy}
					>{t('admin.access_reviews.revoke_selected')}</Button
				>
			</div>
		{/if}

		{#if filteredItems.length === 0 && total === 0}
			<EmptyState title={t('admin.access_reviews.detail_empty')} />
		{:else if filteredItems.length === 0}
			<EmptyState title={t('admin.access_reviews.no_results')} />
		{:else}
			{@const tableRows = filteredItems as unknown as Record<string, unknown>[]}
			<div class="sj-arc-table-wrap">
				<Table columns={COLUMNS} rows={tableRows}>
					{#snippet cell(row, col)}
						{@const item = row as unknown as AccessReviewItem}
						{#if col.key === 'select'}
							{#if !isClosed}
								<Checkbox
									checked={selected.has(item.id)}
									ariaLabel={t("admin.access_reviews.select_row", { user: item.userEmail })}
									onchange={() => toggleItem(item.id)}
								/>
							{/if}
						{:else if col.key === 'user'}
							<span class="sj-arc-user">
								{item.userEmail}
								{#if item.isSelf}
									<Tag
										label={t('admin.access_reviews.self_review')}
										color="amber"
										size="sm"
										dot={false}
									/>
								{/if}
							</span>
						{:else if col.key === 'role'}
							{item.roleName}
						{:else if col.key === 'scope'}
							<span class="sj-arc-meta">
								{item.scope == null
									? t('admin.access_reviews.scope_global')
									: t('admin.access_reviews.scope_domain', { id: String(item.scope) })}
							</span>
						{:else if col.key === 'granted'}
							<span class="sj-arc-meta">{item.grantedAt?.slice(0, 10) ?? '—'}</span>
						{:else if col.key === 'grantedby'}
							{#if item.isSso}
								<Tag
									label={t('admin.access_reviews.sso')}
									color="blue"
									size="sm"
									dot={false}
								/>
							{:else}
								<span class="sj-arc-meta">{item.grantedBy ?? '—'}</span>
							{/if}
						{:else if col.key === 'decision'}
							{#if isClosed}
								<!-- Read-only: show decision -->
								<span class="sj-arc-decision-ro">
									{#if item.decision === 'keep'}
										<span class="sj-arc-dec-keep">{t('admin.access_reviews.keep')}</span>
									{:else if item.decision === 'revoke'}
										<span class="sj-arc-dec-revoke">{t('admin.access_reviews.revoke')}</span>
										{#if item.appliedAt == null}
											<Tag
												label={t('admin.access_reviews.not_applied')}
												color="gray"
												size="sm"
												dot={false}
											/>
										{/if}
									{:else}
										<span class="sj-arc-meta"
											>{t('admin.access_reviews.filter_undecided')}</span
										>
									{/if}
								</span>
							{:else}
								<!-- Keep/Revoke toggle group with aria-pressed -->
								<span
									class="sj-arc-btns"
									role="group"
									aria-label={t('admin.access_reviews.decision_label', {
										user: item.userEmail
									})}
								>
									<button
										class="sj-arc-toggle"
										class:sj-arc-toggle--active={item.decision === 'keep'}
										aria-pressed={item.decision === 'keep'}
										disabled={busyItems.has(item.id)}
										onclick={() => decide(item, 'keep')}
									>
										{t('admin.access_reviews.keep')}
									</button>
									{#if item.isSso}
										<Tooltip text={t('admin.access_reviews.revoke_sso_tooltip')}>
											{#snippet children()}
												<button
													class="sj-arc-toggle"
													aria-pressed={item.decision === 'revoke'}
													disabled={true}
													aria-label={t('admin.access_reviews.revoke_sso_tooltip')}
												>
													{t('admin.access_reviews.revoke')}
												</button>
											{/snippet}
										</Tooltip>
									{:else}
										<button
											class="sj-arc-toggle"
											class:sj-arc-toggle--active={item.decision === 'revoke'}
											aria-pressed={item.decision === 'revoke'}
											disabled={busyItems.has(item.id)}
											onclick={() => decide(item, 'revoke')}
										>
											{t('admin.access_reviews.revoke')}
										</button>
									{/if}
								</span>
							{/if}
						{/if}
					{/snippet}
				</Table>
			</div>
		{/if}
	{/if}
{/if}

<!-- Close confirm dialog -->
{#if closeOpen}
	<Dialog
		open={closeOpen}
		title={t('admin.access_reviews.close_title')}
		onClose={() => (closeOpen = false)}
	>
		{#snippet children()}
			<p class="sj-arc-close-body">
				{t('admin.access_reviews.close_confirm', {
					revoked: String(revoked),
					kept: String(kept),
					not_reviewed: String(undecided)
				})}
			</p>
			<div class="sj-arc-close-breakdown">
				<div class="sj-arc-close-stat">
					<strong>{revoked}</strong>
					{t('admin.access_reviews.revoke')}
				</div>
				<div class="sj-arc-close-stat">
					<strong>{kept}</strong>
					{t('admin.access_reviews.keep')}
				</div>
				<div class="sj-arc-close-stat">
					<strong>{undecided}</strong>
					{t('admin.access_reviews.filter_undecided')}
				</div>
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={doClose} disabled={closeBusy}
				>{t('admin.access_reviews.close')}</Button
			>
			<Button variant="ghost" onclick={() => (closeOpen = false)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-arc-breadcrumb {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
	}
	.sj-arc-back {
		background: none;
		border: none;
		cursor: pointer;
		font: inherit;
		color: var(--accent);
		padding: 0;
		font-size: var(--text-sm);
	}
	.sj-arc-back:hover {
		text-decoration: underline;
	}
	.sj-arc-sep {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.sj-arc-current {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-arc-header {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
	}
	.sj-arc-name {
		margin: 0;
		font-size: var(--text-xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		outline: none;
	}
	.sj-arc-meta-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.sj-arc-meta {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.sj-arc-progress {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-arc-ready {
		color: var(--success-fg);
	}
	.sj-arc-controls {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
		margin-bottom: var(--space-2);
	}
	.sj-arc-filters {
		display: flex;
		gap: var(--space-1);
	}
	.sj-arc-filter {
		padding: 0 var(--space-2);
		height: var(--control-height-sm);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: transparent;
		cursor: pointer;
		font: inherit;
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.sj-arc-filter--active {
		background: var(--accent);
		color: var(--text-inverse);
		border-color: var(--accent);
	}
	.sj-arc-select-bar {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-1);
		padding: 0 var(--space-3);
	}
	.sj-arc-bulk-bar {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		margin-bottom: var(--space-2);
	}
	.sj-arc-bulk-count {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-arc-table-wrap {
		overflow-x: auto;
	}
	.sj-arc-user {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sj-arc-btns {
		display: inline-flex;
		gap: var(--space-1);
		align-items: center;
	}
	.sj-arc-toggle {
		padding: 0 var(--space-2);
		height: var(--control-height-sm);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: transparent;
		cursor: pointer;
		font: inherit;
		font-size: var(--text-xs);
		color: var(--text-secondary);
		min-width: 44px; /* ≥44px touch target */
	}
	.sj-arc-toggle--active {
		background: var(--accent-subtle);
		color: var(--accent-fg-on-subtle);
		border-color: var(--accent);
		font-weight: var(--weight-semibold);
	}
	.sj-arc-toggle:hover:not(:disabled) {
		background: var(--surface-hover);
	}
	.sj-arc-toggle:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.sj-arc-decision-ro {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
	}
	.sj-arc-dec-keep {
		color: var(--success-fg);
		font-size: var(--text-sm);
	}
	.sj-arc-dec-revoke {
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sj-arc-error {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-alert-danger {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sj-arc-skeleton {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sj-arc-skel-row {
		height: var(--row-height, 36px);
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: sj-pulse 1.5s ease-in-out infinite;
	}
	.sj-arc-close-body {
		margin: 0 0 var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-arc-close-breakdown {
		display: flex;
		gap: var(--space-4);
	}
	.sj-arc-close-stat {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	@keyframes sj-pulse {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.5;
		}
	}

	/* Responsive: ≤768px stacked layout */
	@media (max-width: 768px) {
		.sj-arc-controls {
			flex-direction: column;
			align-items: stretch;
		}
		.sj-arc-filters {
			flex-wrap: wrap;
		}
		.sj-arc-btns {
			flex-wrap: wrap;
		}
		.sj-arc-toggle {
			min-height: 44px;
		}
	}
</style>
