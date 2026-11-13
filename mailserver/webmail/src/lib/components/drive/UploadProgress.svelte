<svelte:options runes={true} />

<script lang="ts">
	import { formatBytes } from '$lib/utils/display';
	import Icon from '$lib/components/Icon.svelte';
	import { Progress, IconButton } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import type { UploadItem } from './uploads';

	let { uploads, onDismiss }: {
		uploads: UploadItem[];
		onDismiss: (id: string) => void;
	} = $props();
</script>

{#if uploads.length > 0}
	<div class="up-tray" role="region" aria-label={t('drive.upload.progress')}>
		{#each uploads as item (item.id)}
			<div class="up-item">
				<div class="up-item__head">
					<span class="up-item__name">{item.name}</span>
					<IconButton label={t('common.close')} size="sm" onclick={() => onDismiss(item.id)}>
						<Icon name="X" size={12} />
					</IconButton>
				</div>
				{#if item.status === 'uploading'}
					<Progress
						value={item.sent}
						max={item.total}
						label={t('drive.upload.progress')}
					/>
					<span class="up-item__meta">{formatBytes(item.sent)} / {formatBytes(item.total)}</span>
				{:else if item.status === 'done'}
					<span class="up-item__status up-item__status--done">
						<Icon name="CheckCircle" size={12} />
						{t('drive.upload.complete')}
					</span>
				{:else if item.status === 'error'}
					<span class="up-item__status up-item__status--error" role="alert">
						<Icon name="AlertTriangle" size={12} />
						{item.errorMessage ?? t('drive.upload.failed')}
					</span>
				{/if}
			</div>
		{/each}
	</div>
{/if}

<style>
	.up-tray {
		position: fixed;
		right: var(--space-4);
		bottom: var(--space-4);
		width: 280px;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		z-index: 40;
	}
	.up-item {
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		box-shadow: var(--shadow-md);
		padding: var(--space-2) var(--space-3);
	}
	.up-item__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.up-item__name {
		font-size: var(--text-sm);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		flex: 1;
	}
	.up-item__meta {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.up-item__status {
		display: flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
	}
	.up-item__status--done {
		color: var(--success-fg);
	}
	.up-item__status--error {
		color: var(--danger-fg);
	}
</style>
