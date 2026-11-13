<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import { type DriveFolderAdmin } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { Dialog, Button, IconButton, Input } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		open,
		nodeId,
		onClose,
	}: {
		open: boolean;
		nodeId: number;
		onClose: () => void;
	} = $props();

	let admins = $state<DriveFolderAdmin[]>([]);
	let loading = $state(true);
	let error = $state('');
	let inviteUserId = $state('');

	async function load() {
		loading = true;
		try {
			admins = await api.listFolderAdmins(nodeId);
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		nodeId;
		if (open) void load();
	});

	async function grant() {
		const id = Number(inviteUserId);
		if (!id || !Number.isInteger(id)) return;
		try {
			await api.grantFolderAdmin(nodeId, id);
			inviteUserId = '';
			await load();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function revoke(userId: number) {
		try {
			await api.revokeFolderAdmin(nodeId, userId);
			await load();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}
</script>

<Dialog {open} title={t('drive.folderAdmin.title')} {onClose}>
	<div class="fas">
		<p class="fas__powers">{t('drive.folderAdmin.powers')}</p>

		{#if error}
			<p class="fas__error" role="alert">{error}</p>
		{/if}

		<div class="fas__invite">
			<!-- ponytail: numeric userId, same MembersSheet precedent (no
			     email->userId directory lookup on the drive surface yet). -->
			<Input label={t('drive.folderAdmin.grant')} placeholder="12345" inputmode="numeric" bind:value={inviteUserId} />
			<Button variant="primary" size="sm" onclick={grant}>{t('drive.folderAdmin.grant')}</Button>
		</div>

		{#if !loading}
			<ul class="fas__list">
				{#each admins as a (a.userId)}
					<li class="fas__row">
						<span class="fas__name">{a.displayName}</span>
						<span class="fas__meta">{formatDateTime(a.grantedAt)}</span>
						<IconButton label={t('drive.folderAdmin.remove', { name: a.displayName })} size="sm" onclick={() => revoke(a.userId)}>
							<Icon name="X" size={14} />
						</IconButton>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</Dialog>

<style>
	.fas {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.fas__powers {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.fas__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.fas__invite {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.fas__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.fas__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
	}
	.fas__name {
		flex: 1;
		font-size: var(--text-sm);
	}
	.fas__meta {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
