<svelte:options runes={true} />

<script lang="ts">
	import type { DriveSpace } from '$lib/drive/api';
	import { formatBytes } from '$lib/utils/display';
	import Icon from '$lib/components/Icon.svelte';
	import { Progress, Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let { spaces, selectedId, quickView = null, governanceEnabled = false, onSelect, onSelectQuickView, onNewSpace }: {
		spaces: DriveSpace[];
		selectedId: number | null;
		quickView?: 'shared' | 'shares' | 'requests' | null;
		governanceEnabled?: boolean;
		onSelect: (id: number) => void;
		onSelectQuickView?: (view: 'shared' | 'shares' | 'requests') => void;
		onNewSpace: () => void;
	} = $props();

	// Classification is conveyed by an icon AND text together — never color
	// alone (a11y §11.4). 'regular' shows no badge (the common case).
	function badgeIcon(c: DriveSpace['classification']) {
		return c === 'gxp' ? 'ShieldCheck' : c === 'secure' ? 'Lock' : null;
	}
</script>

<div class="sp-list">
	<div class="sp-list__head">
		<span class="sp-list__title">{t('drive.space.list')}</span>
		<Button variant="secondary" size="sm" onclick={onNewSpace}>{t('drive.space.create')}</Button>
	</div>
	<nav class="sp-list__quick" aria-label={t('drive.quick.title')}>
		<button class:selected={quickView === 'shared'} onclick={() => onSelectQuickView?.('shared')}><Icon name="Users" size={16} /><span>{t('drive.quick.shared')}</span></button>
		<button class:selected={quickView === 'shares'} onclick={() => onSelectQuickView?.('shares')}><Icon name="Share2" size={16} /><span>{t('drive.quick.shares')}</span></button>
		{#if governanceEnabled}<button class:selected={quickView === 'requests'} onclick={() => onSelectQuickView?.('requests')}><Icon name="Inbox" size={16} /><span>{t('drive.quick.requests')}</span></button>{/if}
	</nav>
	<ul class="sp-list__items">
		{#each spaces as space (space.id)}
			<li>
				<button
					class="sp-row"
					class:selected={selectedId === space.id}
					onclick={() => onSelect(space.id)}
				>
					<Icon name="HardDrive" size={16} />
					<span class="sp-row__name">{space.name}</span>
					{#if badgeIcon(space.classification)}
						<span class="sp-row__badge" title={t(`drive.space.classification.tooltip.${space.classification}`)}>
							<Icon name={badgeIcon(space.classification) as 'ShieldCheck' | 'Lock'} size={12} />
							{t(`drive.space.classification.${space.classification}`)}
						</span>
					{/if}
				</button>
				{#if space.quotaBytes != null}
					<div class="sp-row__quota">
						<Progress
							value={space.usedBytes}
							max={space.quotaBytes}
							label={t('drive.space.quota.used', { used: formatBytes(space.usedBytes), quota: formatBytes(space.quotaBytes) })}
						/>
					</div>
				{:else}
					<span class="sp-row__quota-unlimited">{t('drive.space.quota.unlimited')}</span>
				{/if}
			</li>
		{/each}
	</ul>
</div>

<style>
	.sp-list {
		display: flex;
		flex-direction: column;
		height: 100%;
		border-right: 1px solid var(--border-default);
		width: 240px;
		flex-shrink: 0;
	}
	.sp-list__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.sp-list__title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.sp-list__items {
		list-style: none;
		margin: 0;
		padding: var(--space-2);
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sp-list__quick { display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-2); border-bottom: 1px solid var(--border-subtle); }
	.sp-list__quick button { display: flex; align-items: center; gap: var(--space-2); border: 0; background: transparent; color: var(--text-primary); padding: var(--space-2); border-radius: var(--radius-sm); text-align: left; }
	.sp-list__quick button:hover,.sp-list__quick button:focus-visible { background: var(--surface-hover); }
	.sp-list__quick button.selected { background: var(--surface-selected); }
	.sp-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		border: none;
		background: none;
		cursor: pointer;
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
		text-align: left;
	}
	.sp-row:hover {
		background: var(--surface-hover);
	}
	.sp-row.selected {
		background: var(--surface-selected);
	}
	.sp-row:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sp-row__name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.sp-row__badge {
		display: inline-flex;
		align-items: center;
		gap: 3px;
		font-size: var(--text-xs);
		color: var(--text-caption);
		flex-shrink: 0;
	}
	.sp-row__quota {
		padding: 0 var(--space-2) var(--space-2);
	}
	.sp-row__quota-unlimited {
		display: block;
		padding: 0 var(--space-2) var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-caption);
	}

	@media (max-width: 700px) {
		.sp-list {
			width: 100%;
			height: auto;
			max-height: 168px;
			border-right: 0;
			border-bottom: 1px solid var(--border-default);
		}
		.sp-list__head {
			padding: var(--space-2);
		}
		.sp-list__quick {
			flex-direction: row;
			overflow-x: auto;
			padding: var(--space-1) var(--space-2);
		}
		.sp-list__quick button {
			flex: 0 0 auto;
			padding: var(--space-1) var(--space-2);
		}
		.sp-list__items {
			flex-direction: row;
			overflow: auto hidden;
			padding: var(--space-1) var(--space-2);
		}
		.sp-list__items li {
			flex: 0 0 180px;
			min-width: 0;
		}
		.sp-row {
			padding: var(--space-1) var(--space-2);
		}
		.sp-row__quota,
		.sp-row__quota-unlimited {
			display: none;
		}
	}
</style>
