<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import { mirrorBridge } from '$lib/drive/mirrorBridge.svelte';
	import { Dialog, Button, Checkbox, EmptyState, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { open, onClose }: { open: boolean; onClose: () => void } = $props();

	interface SpaceRow {
		id: number;
		name: string;
		included: boolean;
		excludes: string[];
		folders: string[];
		foldersLoaded: boolean;
		aclMode: 'legacy' | 'shadow' | 'acl';
		acceptUnmanagedAclRisk: boolean;
	}

	let rows = $state<SpaceRow[]>([]);
	let loading = $state(false);

	/** kebab-case -> camelCase, matching every SyncIssue code / mirror status
	 *  state to its `drive.sync.{issues,status}.<key>` i18n suffix. */
	function toCamel(s: string): string {
		return s.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
	}

	$effect(() => {
		if (open) void loadSpaces();
	});

	async function loadSpaces(): Promise<void> {
		loading = true;
		try {
			const spaces = await api.listSpaces();
			const configured = new Map(mirrorBridge.status.perSpace.map((p) => [p.spaceId, p]));
			rows = spaces.map((s) => {
				const current = configured.get(s.id);
				return {
					id: s.id,
					name: s.name,
					included: current != null,
					excludes: [],
					folders: [],
					foldersLoaded: false,
					aclMode: s.aclMode ?? 'legacy',
					acceptUnmanagedAclRisk: current?.unmanagedAclRiskAccepted === true,
				};
			});
			for (const row of rows) {
				if (row.included) await loadFolders(row);
			}
		} finally {
			loading = false;
		}
	}

	async function loadFolders(row: SpaceRow): Promise<void> {
		const children = await api.tree(row.id, { parent: null });
		row.folders = children.filter((c) => c.kind === 'folder').map((c) => c.name);
		row.foldersLoaded = true;
	}

	async function toggleIncluded(row: SpaceRow): Promise<void> {
		row.included = !row.included;
		if (row.included && !row.foldersLoaded) await loadFolders(row);
		await saveConfig();
	}

	async function toggleExclude(row: SpaceRow, folderName: string): Promise<void> {
		row.excludes = row.excludes.includes(folderName)
			? row.excludes.filter((f) => f !== folderName)
			: [...row.excludes, folderName];
		await saveConfig();
	}

	async function toggleUnmanagedRisk(row: SpaceRow): Promise<void> {
		row.acceptUnmanagedAclRisk = !row.acceptUnmanagedAclRisk;
		await saveConfig();
	}

	async function saveConfig(): Promise<void> {
		await mirrorBridge.configure(rows.filter((r) => r.included).map((r) => ({
			spaceId: r.id,
			excludes: r.excludes,
			...(r.aclMode === 'acl' ? { acceptUnmanagedAclRisk: r.acceptUnmanagedAclRisk } : {}),
		})));
	}

	function statusFor(spaceId: number) {
		return mirrorBridge.status.perSpace.find((p) => p.spaceId === spaceId);
	}
</script>

<Dialog {open} title={t('drive.sync.sheet.title')} onClose={onClose} wide>
	{#if loading}
		<div class="dss-loading"><Spinner /></div>
	{:else}
		<div class="dss-list">
			{#each rows as row (row.id)}
				{@const st = statusFor(row.id)}
				<div class="dss-space">
					<Checkbox checked={row.included} label={row.name} onchange={() => void toggleIncluded(row)} />
					{#if row.included}
						{#if row.aclMode === 'acl'}
							<div class="dss-risk" role="note">
								<Icon name="AlertTriangle" size={16} />
								<div>
									<strong>{t('drive.sync.sheet.aclRiskTitle')}</strong>
									<p>{t('drive.sync.sheet.aclRiskDetail')}</p>
									<Checkbox
										checked={row.acceptUnmanagedAclRisk}
										label={t('drive.sync.sheet.acceptAclRisk')}
										onchange={() => void toggleUnmanagedRisk(row)}
									/>
								</div>
							</div>
						{/if}
						<div class="dss-space__meta">
							{#if st}
								<span class="dss-space__state">{t(`drive.sync.status.${toCamel(st.state)}`)}</span>
								{#if st.pendingUploads > 0}
									<span>{t('drive.sync.sheet.pendingUploads', { n: String(st.pendingUploads) })}</span>
								{/if}
								{#if st.lastSyncMs}
									<span>{t('drive.sync.sheet.lastSync', { time: new Date(st.lastSyncMs).toLocaleString() })}</span>
								{:else}
									<span>{t('drive.sync.sheet.neverSynced')}</span>
								{/if}
							{/if}
							{#if st?.state !== 'policy-blocked'}
								<Button variant="ghost" size="sm" onclick={() => void mirrorBridge.openRoot(row.id)}>
									<Icon name="Folder" size={14} />
									{t('drive.sync.sheet.openFolder')}
								</Button>
								<Button variant="ghost" size="sm" onclick={() => void mirrorBridge.resync(row.id)}>
									<Icon name="RefreshCw" size={14} />
									{t('drive.sync.sheet.resync')}
								</Button>
							{/if}
						</div>
						{#if row.folders.length > 0}
							<!-- ponytail: top-level folder excludes only (v1) — a nested
							     role="tree" picker for sub-folder excludes is deferred; the
							     server-side exclude match already prefix-matches, so this
							     list stays correct when that lands, just coarser today. -->
							<div class="dss-folders" role="group" aria-label={t('drive.sync.sheet.excludeFolders')}>
								{#each row.folders as folder (folder)}
									<Checkbox
										checked={!row.excludes.includes(folder)}
										label={folder}
										onchange={() => void toggleExclude(row, folder)}
									/>
								{/each}
							</div>
						{/if}
					{/if}
				</div>
			{/each}
		</div>

		<div class="dss-issues">
			<h3 class="dss-issues__title">{t('drive.sync.issues.title')}</h3>
			{#if mirrorBridge.status.issues.length === 0}
				<EmptyState title={t('drive.sync.issues.empty')} />
			{:else}
				<ul class="dss-issues__list">
					{#each mirrorBridge.status.issues as issue, i (i)}
						<li class="dss-issues__row">
							<Icon name="AlertTriangle" size={14} />
							<span>{t(`drive.sync.issues.${toCamel(issue.code)}`)}</span>
							<span class="dss-issues__path">{issue.relPath}</span>
						</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}

	{#snippet footer()}
		<Button variant="secondary" onclick={() => void mirrorBridge.setPaused(!mirrorBridge.status.paused)}>
			{mirrorBridge.status.paused ? t('drive.sync.sheet.resume') : t('drive.sync.sheet.pause')}
		</Button>
		<Button variant="primary" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.dss-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.dss-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.dss-space {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding-bottom: var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
	}
	.dss-space__meta {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: var(--space-2);
		padding-left: var(--space-5);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.dss-space__state {
		font-weight: var(--weight-medium);
	}
	.dss-risk {
		display: flex;
		gap: var(--space-2);
		margin-left: var(--space-5);
		padding: var(--space-3);
		border: 1px solid var(--warning-solid);
		border-radius: var(--radius-md);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-sm);
	}
	.dss-risk p {
		margin: var(--space-1) 0 var(--space-2);
		color: var(--text-secondary);
	}
	.dss-folders {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding-left: var(--space-5);
	}
	.dss-issues {
		margin-top: var(--space-3);
	}
	.dss-issues__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		margin: 0 0 var(--space-2);
	}
	.dss-issues__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.dss-issues__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-xs);
		color: var(--warning-fg);
	}
	.dss-issues__path {
		color: var(--text-tertiary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>
