<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import { DriveError, type DriveBranch, type ResolveVerb } from '$lib/drive/api';
	import { Button, Dialog, Input } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		open,
		branch,
		nodeId,
		fileName,
		onClose,
		onResolved,
	}: {
		open: boolean;
		branch: DriveBranch;
		/** For the BZ150 re-fetch — a mid-dialog status change on this branch. */
		nodeId: number;
		fileName: string;
		onClose: () => void;
		/** Fired after a successful resolve so the parent can refresh (badges, versions, branch list). */
		onResolved?: (result: { verb: ResolveVerb; headVersionId: number | null; newNodeId: number | null }) => void;
	} = $props();

	// BZ150 (main moved / branch closed mid-dialog) re-fetches this file's
	// branches and stores the fresh row here so the ff option disappears
	// without the caller needing to re-render us; reset whenever a different
	// branch is opened.
	let refetched = $state<DriveBranch | null>(null);
	let currentBranch = $derived(refetched ?? branch);
	$effect(() => {
		branch;
		refetched = null;
	});

	let error = $state('');
	let submitting = $state(false);
	let showKeepBoth = $state(false);
	let showDiscardConfirm = $state(false);
	let keepBothName = $state('');

	function defaultKeepBothName(): string {
		const dot = fileName.lastIndexOf('.');
		const ext = dot > 0 ? fileName.slice(dot) : '';
		const base = dot > 0 ? fileName.slice(0, dot) : fileName;
		return `${base} — ${currentBranch.name}${ext}`;
	}

	async function resolve(verb: ResolveVerb, newName?: string) {
		submitting = true;
		error = '';
		try {
			const res = await api.resolveBranch(currentBranch.id, verb, newName);
			onResolved?.(res);
			onClose();
		} catch (e) {
			error = driveErrorMessage(e);
			if (e instanceof DriveError && e.code === 'BZ150') {
				try {
					const fresh = await api.listBranches(nodeId, { all: true });
					const match = fresh.find((b) => b.id === currentBranch.id);
					if (match) refetched = match;
				} catch {
					/* keep the shown error; branch state stays stale-but-safe */
				}
			}
		} finally {
			submitting = false;
		}
	}

	function openKeepBoth() {
		keepBothName = defaultKeepBothName();
		showKeepBoth = true;
	}
</script>

<Dialog {open} title={t('drive.resolve.title', { name: currentBranch.name })} onClose={submitting ? undefined : onClose}>
	<div class="rd">
		{#if error}
			<p class="rd__error" role="alert">{error}</p>
		{/if}

		{#if showKeepBoth}
			<div class="rd__keep-both">
				<Input label={t('drive.resolve.keepBothName')} bind:value={keepBothName} />
				<div class="rd__row">
					<Button variant="primary" size="sm" disabled={submitting || !keepBothName.trim()} onclick={() => resolve('keep_both', keepBothName.trim())}>
						{t('common.confirm')}
					</Button>
					<Button variant="ghost" size="sm" onclick={() => (showKeepBoth = false)}>{t('common.cancel')}</Button>
				</div>
			</div>
		{:else if showDiscardConfirm}
			<div class="rd__discard-confirm">
				<p>{t('drive.resolve.discardConfirm')}</p>
				<div class="rd__row">
					<Button variant="danger" size="sm" disabled={submitting} onclick={() => resolve('discard')}>{t('common.confirm')}</Button>
					<Button variant="ghost" size="sm" onclick={() => (showDiscardConfirm = false)}>{t('common.cancel')}</Button>
				</div>
			</div>
		{:else}
			<div class="rd__verbs">
				{#if currentBranch.ffEligible}
					<Button variant="primary" disabled={submitting} onclick={() => resolve('ff')}>
						{t('drive.resolve.ff')}
					</Button>
				{/if}
				<Button variant="secondary" disabled={submitting} onclick={() => resolve('adopt')}>
					{t('drive.resolve.adopt')}
				</Button>
				<Button variant="secondary" disabled={submitting} onclick={openKeepBoth}>
					{t('drive.resolve.keepBoth')}
				</Button>
				<Button variant="ghost" disabled={submitting} onclick={() => (showDiscardConfirm = true)}>
					{t('drive.resolve.discard')}
				</Button>
			</div>
		{/if}
	</div>
</Dialog>

<style>
	.rd {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.rd__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.rd__verbs {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		align-items: flex-start;
	}
	.rd__row {
		display: flex;
		gap: var(--space-2);
	}
	.rd__keep-both,
	.rd__discard-confirm {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
</style>
