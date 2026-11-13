<svelte:options runes={true} />
<script lang="ts">
	import { t } from '$lib/i18n';
	import { listSyncIssues, clearSyncIssue } from '$lib/offline/reconcile';
	import { offline } from '$lib/offline/state.svelte';
	import { showToast } from '$lib/components/ui/toasts.svelte';
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import EmptyState from '$lib/components/ui/EmptyState.svelte';
	import Spinner from '$lib/components/ui/Spinner.svelte';
	import type { SyncIssue } from '$lib/offline/store';
	import { queueAction } from '$lib/db/offline';
	import { AlertTriangle, Clock, RefreshCw, Trash2 } from 'lucide-svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	type LoadState = 'loading' | 'empty' | 'list' | 'error';

	let issues = $state<SyncIssue[]>([]);
	let loadState = $state<LoadState>('loading');
	// Per-issue busy set (retry in progress)
	let busyIds = $state(new Set<number>());
	// Which issue id has the discard confirm open
	let confirmId = $state<number | null>(null);

	const MAX_ROWS = 50;

	// ponytail: load on open flip; $effect re-runs when open goes true→false→true
	$effect(() => {
		if (!open) return;
		loadIssues();
	});

	async function loadIssues() {
		loadState = 'loading';
		try {
			const data = await listSyncIssues();
			issues = data;
			loadState = data.length === 0 ? 'empty' : 'list';
		} catch {
			loadState = 'error';
		}
	}

	// Resolve a human-readable subject from the issue payload
	function subjectFor(issue: SyncIssue): string {
		const p = issue.payload as Record<string, unknown> | undefined;
		const s = p?.subject;
		return typeof s === 'string' && s.length > 0 ? s : t('offline.conflict.no_subject');
	}

	// Human action label — forward-compat: falls back to raw actionType when key is missing
	function actionLabel(actionType: string): string {
		const key = 'offline.conflict.action.' + actionType;
		const result = t(key);
		// t() returns the key itself when missing — that IS the forward-compat fallback
		return result;
	}

	async function retry(issue: SyncIssue) {
		const id = issue.id!;
		busyIds = new Set([...busyIds, id]);
		try {
			// Re-enqueue the action so the sync engine can replay it, then clear the issue marker
			await queueAction(issue.actionType, issue.payload as Record<string, unknown>);
			await clearSyncIssue(id);
			issues = issues.filter(i => i.id !== id);
			loadState = issues.length === 0 ? 'empty' : 'list';
			await offline.refreshIssueCount();
			showToast(t('offline.toast.synced'));
		} finally {
			busyIds = new Set([...busyIds].filter(x => x !== id));
		}
	}

	async function discardConfirmed() {
		if (confirmId === null) return;
		const id = confirmId;
		confirmId = null;
		await clearSyncIssue(id);
		issues = issues.filter(i => i.id !== id);
		loadState = issues.length === 0 ? 'empty' : 'list';
		await offline.refreshIssueCount();
		// ponytail: no toast on discard — confirm body already stated "can't be recovered"
	}

	const displayedIssues = $derived(issues.slice(0, MAX_ROWS));
	const showingCap = $derived(issues.length > MAX_ROWS);
</script>

<Dialog
	open={open}
	title={t('offline.conflict.title')}
	wide
	onClose={() => (open = false)}
>
	{#snippet children()}
		<p class="subtitle">{t('offline.conflict.subtitle')}</p>

		{#if loadState === 'loading'}
			<div class="centered">
				<Spinner size={20} label={t('offline.conflict.loading')} />
				<span class="load-text">{t('offline.conflict.loading')}</span>
			</div>
		{:else if loadState === 'error'}
			<div role="alert" class="error-block">
				<AlertTriangle size={16} aria-hidden="true" />
				{t('offline.conflict.error')}
				<Button variant="secondary" size="sm" onclick={loadIssues}>{t('offline.status.retry')}</Button>
			</div>
		{:else if loadState === 'empty'}
			<EmptyState watermark title={t('offline.conflict.empty')} />
			<p class="empty-hint">{t('offline.conflict.empty_hint')}</p>
		{:else}
			{#if showingCap}
				<p class="cap-note">{t('offline.conflict.showing_of', { shown: String(MAX_ROWS), total: String(issues.length) })}</p>
			{/if}
			<ul class="issue-list" role="list">
				{#each displayedIssues as issue (issue.id)}
					{@const subject = subjectFor(issue)}
					{@const isStale = issue.kind === 'stale'}
					{@const isBusy = busyIds.has(issue.id!)}
					<li
						class="issue-row"
						class:issue-row--stale={isStale}
						class:issue-row--rejected={!isStale}
						role="listitem"
					>
						<div class="issue-primary">
							<span
								class="issue-subject"
								data-testid="issue-subject-{issue.id}"
								title={subject}
								aria-label={subject}
							>{subject}</span>
							<span class="issue-action">{actionLabel(issue.actionType)}</span>
						</div>
						<div class="issue-secondary">
							<span class="issue-cause">{t(isStale ? 'offline.conflict.cause_stale' : 'offline.conflict.cause_rejected')}</span>
						</div>
						<div class="issue-tertiary">
							{#if isStale}
							<Clock size={14} aria-hidden="true" class="kind-icon kind-icon--stale" />
						{:else}
							<AlertTriangle size={14} aria-hidden="true" class="kind-icon kind-icon--rejected" />
						{/if}
						<Badge
							variant={isStale ? 'warning' : 'danger'}
							label={t(isStale ? 'offline.conflict.kind_stale' : 'offline.conflict.kind_rejected')}
						/>
							<div class="issue-actions">
								{#if isBusy}
									<Spinner size={16} label={t('offline.conflict.retry')} />
								{:else}
									<Button
										variant="secondary"
										size="sm"
										onclick={() => retry(issue)}
										disabled={isBusy}
									>
										{#snippet icon()}<RefreshCw size={14} aria-hidden="true" />{/snippet}
										{t('offline.conflict.retry')}
									</Button>
									<Button
										variant="ghost"
										size="sm"
										data-testid="issue-discard-{issue.id}"
										onclick={() => (confirmId = issue.id!)}
									>
										{#snippet icon()}<Trash2 size={14} aria-hidden="true" />{/snippet}
										{t('offline.conflict.discard')}
									</Button>
								{/if}
							</div>
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	{/snippet}
</Dialog>

<!-- Discard confirm sub-dialog -->
<Dialog
	open={confirmId !== null}
	title={t('offline.conflict.discard_confirm_title')}
	onClose={() => (confirmId = null)}
>
	{#snippet children()}
		<p>{t('offline.conflict.discard_confirm_body')}</p>
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (confirmId = null)}>{t('offline.conflict.cancel')}</Button>
		<Button
			variant="danger"
			data-testid="issue-discard-confirm"
			onclick={discardConfirmed}
		>{t('offline.conflict.discard_confirm_cta')}</Button>
	{/snippet}
</Dialog>

<style>
	.subtitle {
		margin: 0 0 var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}

	.centered {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-6) 0;
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.load-text { font-size: var(--text-sm); color: var(--text-tertiary); }

	.error-block {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.empty-hint {
		margin: var(--space-2) 0 0;
		text-align: center;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		line-height: var(--leading-normal);
	}

	.cap-note {
		margin: 0 0 var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.issue-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	/* ponytail: border-inline-start is the RTL-safe accent bar — flips to the correct
	   visual edge in RTL automatically. Ceiling: if per-language visual customisation
	   needed, add a [dir=rtl] override. */
	.issue-row {
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-subtle);
		border-inline-start: 3px solid transparent;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.issue-row--stale {
		border-inline-start: 3px solid var(--warning-solid);
	}
	.issue-row--rejected {
		border-inline-start: 3px solid var(--danger-solid);
	}

	.issue-primary {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.issue-subject {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.issue-action {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.issue-secondary {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.issue-cause { font-style: italic; }

	.issue-tertiary {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}

	.issue-actions {
		display: flex;
		gap: var(--space-1);
		margin-inline-start: auto;
		align-items: center;
	}

	/* Row leave: instant removal (Svelte removes DOM node on reactivity update).
	   The empty-state arrival animates via Dialog's backdrop (--duration-base).
	   Reduced-motion: no transition on the rows. */
	@media (prefers-reduced-motion: reduce) {
		.issue-row {
			transition: none;
		}
	}

	/* Mobile: stack action buttons under text */
	@media (max-width: 640px) {
		.issue-tertiary {
			flex-direction: column;
			align-items: flex-start;
		}
		.issue-actions {
			margin-inline-start: 0;
		}
	}
</style>
