<svelte:options runes={true} />

<script lang="ts">
	// SubscriptionsSheet — P6 Task 14: the change-subscription manager. Lists
	// GET /api/drive/watches (the caller's own rows), edits each row's ops
	// filter via a labelled checkbox group, and removes a subscription.
	// "Watch this" from a FileList row (api.setWatch, no ops UI — watches all
	// events) is the quick entry point; this sheet is where ops get narrowed.
	import { type DriveWatchRow } from '$lib/drive/api';
	import { driveWatches } from '$lib/drive/watches.svelte';
	import { Dialog, IconButton, EmptyState, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		open,
		onClose,
	}: {
		open: boolean;
		onClose: () => void;
	} = $props();

	const OPS = ['create', 'update', 'move', 'rename', 'trash', 'restore', 'destroy', 'member', 'branch', 'lock'] as const;

	// Task 13: rows read the shared driveWatches store (§5.6) instead of a
	// private local cache — a toggle from here, the VersionDrawer bell, or the
	// FileList quick-toggle now all stay in sync.
	let loading = $state(true);
	let error = $state('');

	async function load() {
		loading = true;
		try {
			await driveWatches.load();
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (open) void load();
	});

	function hasOp(row: DriveWatchRow, op: string): boolean {
		return row.ops === null || row.ops.includes(op);
	}

	async function toggleOp(row: DriveWatchRow, op: string) {
		const current: string[] = row.ops === null ? [...OPS] : row.ops;
		const next = current.includes(op) ? current.filter((o) => o !== op) : [...current, op];
		// Selecting every op is equivalent to null ("all") — collapse back to it
		// so the wire shape matches what a fresh "watch this" toggle sends.
		const ops = next.length === OPS.length ? null : next;
		try {
			await driveWatches.watch(row.nodeId, ops ?? undefined);
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function remove(row: DriveWatchRow) {
		try {
			await driveWatches.unwatch(row.nodeId);
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}
</script>

<Dialog {open} title={t('drive.watch.title')} {onClose} wide>
	<div class="ss">
		{#if error}
			<p class="ss__error" role="alert">{error}</p>
		{/if}

		{#if loading}
			<div class="ss__loading"><Spinner /></div>
		{:else if driveWatches.list().length === 0}
			<EmptyState title={t('drive.watch.empty')} />
		{:else}
			<ul class="ss__list">
				{#each driveWatches.list() as row (row.nodeId)}
					<li class="ss__row">
						<div class="ss__row-header">
							<Icon name={row.kind === 'folder' ? 'Folder' : 'FileText'} size={16} />
							<span class="ss__name">{row.nodeName}</span>
							<IconButton label={t('drive.watch.remove')} size="sm" onclick={() => remove(row)}>
								<Icon name="X" size={14} />
							</IconButton>
						</div>
						<fieldset class="ss__ops">
							<legend class="sr-only">{t('drive.watch.allEvents')}</legend>
							{#each OPS as op (op)}
								<label class="ss__op">
									<input type="checkbox" checked={hasOp(row, op)} onchange={() => toggleOp(row, op)} />
									{t(`drive.watch.op.${op}`)}
								</label>
							{/each}
						</fieldset>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</Dialog>

<style>
	.ss {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.ss__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.ss__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
	.ss__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.ss__row {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.ss__row-header {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.ss__name {
		flex: 1;
		font-size: var(--text-sm);
		font-weight: 600;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.ss__ops {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1) var(--space-3);
		border: none;
		margin: var(--space-2) 0 0;
		padding: 0;
	}
	.ss__op {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
		color: var(--text-caption);
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
