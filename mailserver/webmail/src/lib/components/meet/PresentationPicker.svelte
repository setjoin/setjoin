<svelte:options runes={true} />

<script lang="ts">
	// PresentationPicker — MEET plan M3. The Drive picker dialog: source/file
	// → version → rendition readiness/warnings → private preview → Present
	// (the plan's own picker flow). Reuses the authorized Drive list/version
	// APIs (`$lib/drive/api` listSpaces/tree/listVersions) — never a second
	// file store, never unqualified discovery (ACLs stay Drive's). Launch
	// modes are PDF + Office presentations (ppt/pptx/odp/dps); everything
	// else is filtered out and the empty state says so.
	//
	// State coverage (plan "Interaction states", Document picker + Rendition
	// rows): skeleton/cancellable load; empty explains supported files and
	// offers Drive; error offers retry; a stale tree keeps the current
	// selection labelled; rendition progress is page-count-shaped and
	// cancellable; zero-page/failed renditions surface the named failure;
	// the private preview renders the fidelity-warning banner BEFORE Present.
	import { onMount } from 'svelte';
	import { Dialog, Button, Badge, EmptyState, Progress, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import * as driveApi from '$lib/drive/api';
	import type { DriveNode, DriveSpace, DriveVersion } from '$lib/drive/api';
	import { renditionWarningKey, presentationFailureKey } from '$lib/meet/presentationClient';
	import type { RenditionWarningCode } from '$lib/meet/presentationApi';
	import type { PresentationStore } from '$lib/meet/presentationStore.svelte';

	let {
		presentation,
		onClose,
	}: {
		presentation: PresentationStore;
		onClose: () => void;
	} = $props();

	// ── browse state ────────────────────────────────────────────────────────
	let spaces = $state<DriveSpace[] | null>(null);
	let spacesLoading = $state(true);
	let spacesError = $state(false);
	let spaceId = $state<number | null>(null);
	let nodes = $state<DriveNode[] | null>(null);
	let nodesLoading = $state(false);
	let nodesError = $state(false);
	let folderStack = $state<{ id: number; name: string }[]>([]);
	let selectedNode = $state<DriveNode | null>(null);
	/** The stale-list posture: a reloaded tree that no longer contains the
	 *  current selection keeps it rendered, labelled — never silently
	 *  switched. */
	let selectionStale = $state(false);
	let versions = $state<DriveVersion[] | null>(null);
	let versionId = $state<number | null>(null);

	// Launch modes (plan "Supported document modes"): PDF and Office
	// presentations. Everything else never renders as pickable.
	const SUPPORTED_EXTENSIONS = ['pdf', 'ppt', 'pptx', 'odp', 'dps'];

	function supportedFile(node: DriveNode): boolean {
		if (node.kind !== 'file') return false;
		const dot = node.name.lastIndexOf('.');
		if (dot < 0) return false;
		return SUPPORTED_EXTENSIONS.includes(node.name.slice(dot + 1).toLowerCase());
	}

	async function loadSpaces(): Promise<void> {
		spacesLoading = true;
		spacesError = false;
		try {
			spaces = await driveApi.listSpaces();
			if (spaces.length > 0 && spaceId === null) {
				await selectSpace(spaces[0].id);
			} else if (spaceId !== null) {
				await loadTree();
			}
		} catch {
			spacesError = true;
		} finally {
			spacesLoading = false;
		}
	}

	async function selectSpace(id: number): Promise<void> {
		spaceId = id;
		folderStack = [];
		selectedNode = null;
		versions = null;
		await loadTree();
	}

	async function loadTree(): Promise<void> {
		if (spaceId === null) return;
		nodesLoading = true;
		nodesError = false;
		const parent = folderStack.length > 0 ? folderStack[folderStack.length - 1].id : null;
		try {
			const list = await driveApi.tree(spaceId, { parent });
			// Stale-selection labelling: the current selection is kept even
			// when this refresh no longer lists it.
			const current = selectedNode;
			selectionStale = current !== null && !list.some((n) => n.id === current.id);
			nodes = list.filter(supportedFile).concat(current !== null && selectionStale ? [current] : []);
		} catch {
			nodesError = true;
			nodes = [];
		} finally {
			nodesLoading = false;
		}
	}

	async function openFolder(node: DriveNode): Promise<void> {
		folderStack = [...folderStack, { id: node.id, name: node.name }];
		await loadTree();
	}

	async function popFolder(): Promise<void> {
		folderStack = folderStack.slice(0, -1);
		await loadTree();
	}

	async function pickFile(node: DriveNode): Promise<void> {
		selectedNode = node;
		selectionStale = false;
		versions = null;
		versionId = null;
		if (spaceId === null) return;
		try {
			const list = await driveApi.listVersions(node.id);
			versions = list;
			versionId = list.find((v) => v.id === node.headVersionId)?.id ?? list[0]?.id ?? null;
		} catch {
			versions = [];
		}
	}

	// ── prepare → preview → present (delegates to the store) ──────────────
	function prepare(): void {
		if (selectedNode === null || versionId === null) return;
		previewPageShown = false;
		void presentation.prepare(selectedNode.id, versionId);
	}

	let previewPageShown = $state(false);
	// The private preview shows page 0 regardless of any later shared state.
	$effect(() => {
		if (presentation.isPreviewing && !previewPageShown) {
			presentation.previewPageIndex = 0;
			previewPageShown = true;
		}
	});

	function close(): void {
		// Retire preparation even before its ID arrives, so late acceptance is
		// drained. An already live session belongs to the stage, not this dialog.
		if (!presentation.isLive) presentation.cancelPrepare();
		onClose();
	}

	onMount(() => {
		void loadSpaces();
	});
</script>

<Dialog open={true} title={t('meet.presentation.picker.title')} wide onClose={close}>
	{#snippet children()}
		<div class="pres-picker" data-testid="presentation-picker">
			{#if presentation.isPreviewing}
				<!-- ── private preview: page 0 + fidelity warnings → Present ── -->
				<div class="pres-picker__preview">
					<p class="pres-picker__preview-note">{t('meet.presentation.picker.previewNote')}</p>
					{#if presentation.currentPage}
						<img class="pres-picker__preview-img" src={presentation.currentPage.fullPage.path} alt={t('meet.presentation.picker.previewAlt')} />
					{:else}
						<div class="pres-picker__preview-loading"><Spinner /></div>
					{/if}
					{#if presentation.manifest && presentation.manifest.warnings.length > 0}
						<div class="pres-picker__warnings" role="note" data-testid="picker-warnings">
							<p class="pres-picker__warnings-head">{t('meet.presentation.picker.warningsHeading')}</p>
							<ul role="list">
								{#each presentation.manifest.warnings as w (w)}
									<li data-testid="picker-warning-{w}">{t(renditionWarningKey(w as RenditionWarningCode))}</li>
								{/each}
							</ul>
						</div>
					{/if}
				</div>
			{:else if presentation.prep}
				<!-- ── rendition readiness: bounded poll of the authorized read.
				     The M2 wire carries status only (page-count progress arrives
				     with M1's rendition serving), so the phase is indeterminate. ── -->
				<div class="pres-picker__prep" data-testid="picker-prep">
					<Spinner />
					<p>{t('meet.presentation.picker.preparing')}</p>
					<Progress value={0} max={100} label={t('meet.presentation.picker.progress')} indeterminate />
					<Button variant="secondary" size="sm" onclick={() => presentation.cancelPrepare()}>
						{t('meet.presentation.picker.cancelPrepare')}
					</Button>
				</div>
			{:else}
				<!-- ── browse: source/file → version ── -->
				<div class="pres-picker__browse">
					{#if spacesLoading}
						<div class="pres-picker__loading" data-testid="picker-loading"><Spinner /> {t('meet.presentation.picker.loading')}</div>
					{:else if spacesError}
						<EmptyState title={t('common.error')}>
							{#snippet action()}
								<Button variant="secondary" size="sm" onclick={() => void loadSpaces()} data-testid="picker-retry-spaces">
									{t('meet.presentation.picker.retry')}
								</Button>
							{/snippet}
						</EmptyState>
					{:else if spaces && spaces.length === 0}
						<EmptyState title={t('meet.presentation.picker.empty')}>
							{#snippet action()}
								<a class="pres-picker__drive-link" href="/drive">{t('meet.presentation.picker.openDrive')}</a>
							{/snippet}
						</EmptyState>
					{:else}
						<label class="pres-picker__space-label" for="pres-picker-space">{t('meet.presentation.picker.space')}</label>
						<select
							id="pres-picker-space"
							class="pres-picker__select"
							data-testid="picker-space"
							value={spaceId ?? undefined}
							onchange={(e) => void selectSpace(Number(e.currentTarget.value))}
						>
							{#each spaces ?? [] as s (s.id)}
								<option value={s.id}>{s.name}</option>
							{/each}
						</select>

						<div class="pres-picker__crumbs">
							<button type="button" class="pres-picker__crumb" onclick={() => void popFolder()} disabled={folderStack.length === 0}>
								<Icon name="ChevronLeft" size={14} />
								{folderStack.length > 0 ? folderStack[folderStack.length - 1].name : t('meet.presentation.picker.spaceRoot')}
							</button>
						</div>

						{#if nodesLoading}
							<div class="pres-picker__loading"><Spinner /> {t('meet.presentation.picker.loading')}</div>
						{:else if nodesError}
							<EmptyState title={t('common.error')}>
								{#snippet action()}
									<Button variant="secondary" size="sm" onclick={() => void loadTree()} data-testid="picker-retry">
										{t('meet.presentation.picker.retry')}
									</Button>
								{/snippet}
							</EmptyState>
						{:else if nodes && nodes.length === 0}
							<EmptyState title={t('meet.presentation.picker.empty')}>
								{#snippet action()}
									<a class="pres-picker__drive-link" href="/drive">{t('meet.presentation.picker.openDrive')}</a>
								{/snippet}
							</EmptyState>
						{:else}
							<ul class="pres-picker__files" role="list">
								{#each nodes ?? [] as node (node.id)}
									<li>
										{#if node.kind === 'folder'}
											<button type="button" class="pres-picker__row" onclick={() => void openFolder(node)}>
												<Icon name="Folder" size={16} />
												<span class="pres-picker__name">{node.name}</span>
											</button>
										{:else}
											<button
												type="button"
												class="pres-picker__row"
												class:pres-picker__row--selected={selectedNode?.id === node.id}
												data-testid="picker-file-{node.id}"
												onclick={() => void pickFile(node)}
											>
												<Icon name="FileText" size={16} />
												<span class="pres-picker__name">{node.name}</span>
												{#if selectedNode?.id === node.id && selectionStale}
													<Badge variant="neutral" label={t('meet.presentation.picker.staleSelection')} />
												{/if}
											</button>
										{/if}
									</li>
								{/each}
							</ul>
						{/if}

						{#if selectedNode}
							<div class="pres-picker__versions" data-testid="picker-versions">
								<label class="pres-picker__space-label" for="pres-picker-version">{t('meet.presentation.picker.version')}</label>
								<select
									id="pres-picker-version"
									class="pres-picker__select"
									data-testid="picker-version"
									value={versionId ?? undefined}
									onchange={(e) => (versionId = Number(e.currentTarget.value))}
								>
									{#each versions ?? [] as v (v.id)}
										<option value={v.id}>{t('meet.presentation.picker.versionLabel', { n: String(v.id) })}</option>
									{/each}
								</select>
								{#if versionId === null}
									<p class="pres-picker__no-versions">{t('meet.presentation.picker.noVersions')}</p>
								{/if}
								<Button
									variant="primary"
									onclick={prepare}
									disabled={versionId === null}
									data-testid="picker-prepare"
								>
									{t('meet.presentation.picker.prepare')}
								</Button>
							</div>
						{/if}
					{/if}
				</div>
			{/if}
			{#if presentation.failure}
				<div class="pres-picker__failure" role="alert" data-testid="picker-failure">
					{t(presentationFailureKey(presentation.failure.code))}
				</div>
			{/if}
		</div>
	{/snippet}
	{#snippet footer()}
		{#if presentation.isPreviewing}
			<Button variant="primary" onclick={() => void presentation.present()} data-testid="picker-present">
				{t('meet.presentation.picker.present')}
			</Button>
		{/if}
		<Button variant="secondary" onclick={close} data-testid="picker-close">{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.pres-picker {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		min-height: 280px;
	}
	.pres-picker__loading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		padding: var(--space-3) 0;
	}
	.pres-picker__space-label {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.pres-picker__select {
		width: 100%;
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-base);
		color: var(--text-primary);
	}
	.pres-picker__crumbs {
		display: flex;
	}
	.pres-picker__crumb {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		border: none;
		background: none;
		color: var(--text-secondary);
		font-size: var(--text-sm);
		cursor: pointer;
		padding: var(--space-1) 0;
	}
	.pres-picker__crumb:disabled {
		cursor: default;
		opacity: 0.6;
	}
	.pres-picker__files {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 240px;
		overflow-y: auto;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
	}
	.pres-picker__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-2) var(--space-3);
		min-height: 44px;
		border: none;
		background: none;
		color: var(--text-primary);
		font-size: var(--text-sm);
		text-align: left;
		cursor: pointer;
	}
	.pres-picker__row:hover {
		background: var(--surface-hover);
	}
	.pres-picker__row--selected {
		background: var(--surface-selected);
	}
	.pres-picker__name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.pres-picker__versions {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		padding-top: var(--space-3);
	}
	.pres-picker__no-versions {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.pres-picker__prep {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-6) var(--space-3);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		width: 100%;
	}
	.pres-picker__preview {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.pres-picker__preview-note {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.pres-picker__preview-img {
		max-width: 100%;
		max-height: 320px;
		object-fit: contain;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		align-self: center;
	}
	.pres-picker__preview-loading {
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 200px;
	}
	.pres-picker__warnings {
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.pres-picker__warnings-head {
		margin: 0 0 var(--space-1);
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.pres-picker__warnings ul {
		margin: 0;
		padding: 0 0 0 var(--space-4);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.pres-picker__failure {
		border: 1px solid var(--border-danger, var(--border-default));
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-sunken);
	}
	.pres-picker__drive-link {
		color: var(--accent);
		font-size: var(--text-sm);
	}
</style>
