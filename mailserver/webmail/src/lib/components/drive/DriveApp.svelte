<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import {
		type DriveSpace,
		type DriveNode,
		type DriveVersion,
		type PutVersionResult,
		type DriveSearchItem,
	} from '$lib/drive/api';
	import { uploadFile } from '$lib/drive/upload';
	import { user } from '$lib/stores/auth';
	import { Button, Dialog, Input, Select, Spinner, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatDateTime } from '$lib/i18n';
	import { formatBytes } from '$lib/utils/display';
	import { driveErrorMessage } from '$lib/drive/errors';
	import SpaceList from './SpaceList.svelte';
	import DriveTree from './DriveTree.svelte';
	import FileList from './FileList.svelte';
	import VersionDrawer from './VersionDrawer.svelte';
	import BranchPanel from './BranchPanel.svelte';
	import ActivityFeed from './ActivityFeed.svelte';
	import FolderAdminsSheet from './FolderAdminsSheet.svelte';
	import MembersSheet from './MembersSheet.svelte';
	import UploadProgress from './UploadProgress.svelte';
	import SyncStatusPill from './SyncStatusPill.svelte';
	import SelectiveSyncSheet from './SelectiveSyncSheet.svelte';
	import SecureViewer from './SecureViewer.svelte';
	import ChangeNoteDialog from './ChangeNoteDialog.svelte';
	import SubscriptionsSheet from './SubscriptionsSheet.svelte';
	import NodeAccessDrawer from './NodeAccessDrawer.svelte';
	import DriveQuickView from './DriveQuickView.svelte';
	import { inAppRenderer } from '$lib/drive/opener.svelte';
	import { DriveSearchStore } from '$lib/drive/search.svelte';
	import { driveWatches } from '$lib/drive/watches.svelte';
	import { subscribeEvent } from '$lib/jmap/websocket';
	import { uploadOrchestrator, uploadErrorMessage } from '$lib/drive/uploadOrchestrator.svelte';
	import { VersionSaveFlow } from '$lib/drive/versionSave.svelte';

	const POLL_MS = 30_000; // §4.2 floor: SSE nudge is P2's sync engine

	let spaces = $state<DriveSpace[]>([]);
	let spacesLoading = $state(true);
	let selectedSpaceId = $state<number | null>(null);
	let selectedSpace = $derived(spaces.find((s) => s.id === selectedSpaceId) ?? null);
	let isManager = $derived(selectedSpace?.role === 'manager');
	let governanceEnabled = $derived(spaces.some((space) => space.accessGovernanceEnabled));
	let quickView = $state<'shared' | 'shares' | 'requests' | null>(null);
	let quickItems = $state<api.DriveQuickViewItem[]>([]);
	let quickLoading = $state(false);
	let quickError = $state('');
	let virtualAnchor = $state<api.DriveQuickViewItem | null>(null);

	let currentFolderId = $state<number | null>(null);
	let currentFolderCapabilities = $state<api.DriveCapability[]>([]);
	let canCreate = $derived(currentFolderCapabilities.includes('create_child'));
	let deletedView = $state(false);
	let listing = $state<DriveNode[]>([]);
	let listingLoading = $state(false);
	let sinceSeq = $state(0);

	let selectedFile = $state<DriveNode | null>(null);
	let accessNode = $state<DriveNode | null>(null);
	let selectedCanModify = $derived(selectedFile?.capabilities?.includes('modify_content') ?? false);
	let versions = $state<DriveVersion[]>([]);
	let versionsLoading = $state(false);

	let showSyncSheet = $state(false);
	let showActivity = $state(false);
	let folderAdminsFor = $state<DriveNode | null>(null);

	let showMembers = $state(false);

	let showNewSpaceDialog = $state(false);
	let newSpaceName = $state('');
	let newSpaceClassification = $state<'regular' | 'secure' | 'gxp'>('regular');
	let creatingSpace = $state(false);

	let showNewFolderDialog = $state(false);
	let newFolderName = $state('');

	// ── P6 Task 13: name search ────────────────────────────────────────────
	let searchQuery = $state('');
	let searchScope = $state<'current' | 'all'>('current');
	const driveSearch = new DriveSearchStore();

	function runSearch() {
		driveSearch.query(searchQuery, { spaceId: searchScope === 'current' ? selectedSpaceId : null });
	}

	async function openSearchResult(item: DriveSearchItem) {
		searchQuery = '';
		driveSearch.clear();
		if (selectedSpaceId !== item.spaceId) selectedSpaceId = item.spaceId;
		selectedFile = null;
		deletedView = false;
		asOfMode = false;
		try {
			if (item.kind === 'folder') {
				await selectFolderFromTree(item.id);
			} else {
				currentFolderId = item.parentId;
				if (item.parentId === null) currentFolderCapabilities = selectedSpace?.rootCapabilities ?? [];
				else currentFolderCapabilities = (await api.getNodeAccess(item.parentId)).capabilities;
				await loadListing();
				const found = listing.find((n) => n.id === item.id);
				if (found) await selectFile(found);
			}
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	// ── P6 Task 14: change-subscription manager ────────────────────────────
	let showSubscriptions = $state(false);

	// ── P6 Task 17: "space as of…" time-point view ──────────────────────────
	let showAsOfDialog = $state(false);
	let asOfInputValue = $state('');
	let asOfMode = $state(false);
	let asOfAt = $state<string | null>(null);
	let asOfItems = $state<api.DriveAsOfItem[]>([]);
	let asOfLoading = $state(false);

	async function applyAsOf(at: string) {
		if (selectedSpaceId === null || !at) return;
		showAsOfDialog = false;
		asOfLoading = true;
		try {
			const iso = new Date(at).toISOString();
			const res = await api.spaceAsOf(selectedSpaceId, iso);
			asOfItems = res.items;
			asOfAt = iso;
			asOfMode = true;
			selectedFile = null;
		} catch (e) {
			bannerError = driveErrorMessage(e);
		} finally {
			asOfLoading = false;
		}
	}

	function exitAsOf() {
		asOfMode = false;
		asOfAt = null;
		asOfItems = [];
	}

	async function restoreAsOfVersion(item: api.DriveAsOfItem) {
		if (item.versionId === null || !selectedSpace) return;
		try {
			const result = await api.restoreVersion(item.id, item.versionId, {
				note: t('drive.version.restoreAsNew'),
			});
			surfaceWormPending(result);
			exitAsOf();
			await loadListing();
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	let bannerError = $state('');
	// P5: a passive (never-error) notice — e.g. "version saved; storage lock
	// in progress" when a gxp save returns wormPending:true.
	let bannerNotice = $state('');
	let uploadInput = $state<HTMLInputElement | null>(null);

	function surfaceWormPending(result: PutVersionResult) {
		if (result.wormPending) bannerNotice = t('drive.version.wormPendingBanner');
	}

	// ── P5 Task 11 / P4 Task 14: version-save flow ───────────────────────────
	// The gxp change-control note gate (spec §2.1: a gxp space requires a
	// change note on every save) and the save-as-branch offer on a BZ149 hard
	// lock — see versionSave.svelte.ts for the state machine. DriveApp keeps
	// the dialog markup and this glue: which space/file is selected, the tree
	// reload, and the shared version/banner state.
	const versionSave = new VersionSaveFlow({
		getSpaceId: () => selectedSpaceId,
		getSelectedFile: () => selectedFile,
		isGxpSpace: () => selectedSpace?.classification === 'gxp',
		startNewUpload: (file, note) => void startUpload(file, note),
		onVersionsUpdated: (v) => (versions = v),
		reloadListing: () => loadListing(),
		onWormPending: surfaceWormPending,
		onError: (message) => (bannerError = message),
	});

	async function loadSpaces() {
		spacesLoading = true;
		try {
			spaces = await api.listSpaces();
			if (selectedSpaceId === null && spaces.length > 0) {
				selectSpace(spaces[0].id);
			}
		} catch (e) {
			bannerError = driveErrorMessage(e);
		} finally {
			spacesLoading = false;
		}
	}

	function selectSpace(id: number) {
		quickView = null;
		virtualAnchor = null;
		selectedSpaceId = id;
		currentFolderId = null;
		currentFolderCapabilities = spaces.find((space) => space.id === id)?.rootCapabilities ?? [];
		deletedView = false;
		selectedFile = null;
		accessNode = null;
		sinceSeq = 0;
		exitAsOf();
		void loadListing();
	}

	async function loadQuickView() {
		if (!quickView) return;
		quickLoading = true;
		quickError = '';
		try { quickItems = await api.listDriveQuickView(quickView); }
		catch (e) { quickError = driveErrorMessage(e); }
		finally { quickLoading = false; }
	}

	function selectQuickView(view: 'shared' | 'shares' | 'requests') {
		quickView = view;
		virtualAnchor = null;
		selectedFile = null;
		accessNode = null;
		void loadQuickView();
	}

	async function openQuickItem(item: api.DriveQuickViewItem) {
		const nodeId = Number(item.nodeId);
		const spaceId = Number(item.spaceId);
		if (!Number.isSafeInteger(nodeId) || !Number.isSafeInteger(spaceId)) {
			quickError = t('drive.quick.invalidItem');
			return;
		}
		selectedSpaceId = spaceId;
		quickView = null;
		virtualAnchor = item;
		selectedFile = null;
		accessNode = null;
		deletedView = false;
		try {
			const detail = await api.getNodeAccess(nodeId);
			if (item.nodeKind === 'folder') {
				currentFolderId = nodeId;
				currentFolderCapabilities = detail.capabilities;
				await loadListing();
			} else {
				currentFolderId = null;
				currentFolderCapabilities = spaces.find((space) => space.id === spaceId)?.rootCapabilities ?? [];
				await selectFile({ id: nodeId, parentId: null, kind: 'file', name: item.name, branchCount: 0, lock: null, capabilities: detail.capabilities, traverseOnly: detail.traverseOnly });
			}
		} catch (e) {
			quickView = item.kind === 'share' ? 'shares' : item.kind === 'request' ? 'requests' : 'shared';
			virtualAnchor = null;
			quickError = driveErrorMessage(e);
		}
	}

	async function loadListing() {
		if (selectedSpaceId === null) return;
		listingLoading = true;
		try {
			listing = await api.tree(selectedSpaceId, { parent: currentFolderId, deleted: deletedView });
		} catch (e) {
			bannerError = driveErrorMessage(e);
		} finally {
			listingLoading = false;
		}
	}

	function openFolder(id: number) {
		const folder = listing.find((item) => item.id === id);
		currentFolderId = id;
		currentFolderCapabilities = folder?.capabilities ?? [];
		selectedFile = null;
		accessNode = null;
		exitAsOf();
		void loadListing();
	}

	// DriveTree selection includes the synthetic root (null) — DriveTree's own
	// "onSelect" folder id already means "current folder", root included.
	async function selectFolderFromTree(id: number | null) {
		currentFolderId = id;
		selectedFile = null;
		accessNode = null;
		if (id === null) currentFolderCapabilities = selectedSpace?.rootCapabilities ?? [];
		else {
			try { currentFolderCapabilities = (await api.getNodeAccess(id)).capabilities; }
			catch { currentFolderCapabilities = []; }
		}
		exitAsOf();
		void loadListing();
	}

	function toggleTrashView() {
		deletedView = !deletedView;
		selectedFile = null;
		exitAsOf();
		void loadListing();
	}

	async function selectFile(node: DriveNode) {
		accessNode = null;
		selectedFile = node;
		versionsLoading = true;
		try {
			versions = await api.listVersions(node.id);
		} catch (e) {
			bannerError = driveErrorMessage(e);
		} finally {
			versionsLoading = false;
		}
	}

	function openAccess(node: DriveNode) {
		selectedFile = null;
		accessNode = node;
	}

	// Re-fetch the version list + tree row after a P4 mutation that can move
	// head_version_id (branch resolve) or the row's branchCount/lock badges
	// (branch create/label set — BranchPanel/VersionDrawer's onChanged hooks).
	async function refreshSelectedFile() {
		if (!selectedFile) return;
		try {
			versions = await api.listVersions(selectedFile.id);
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
		await loadListing();
	}

	// ── polling (§4.2 floor) ────────────────────────────────────────────────
	$effect(() => {
		void loadSpaces();
		const timer = setInterval(() => {
			if (selectedSpaceId === null) return;
			api
				.changes(selectedSpaceId, sinceSeq)
				.then((res) => {
					if (res.cannotCalculateChanges) {
						sinceSeq = 0;
						void loadListing();
						return;
					}
					if (res.changed && res.changed.length > 0) {
						sinceSeq = res.newState ?? sinceSeq;
						void loadListing();
					}
				})
				.catch(() => {
					/* transient poll failure — next tick retries */
				});
		}, POLL_MS);
		return () => clearInterval(timer);
	});

	// ── P6 Task 14: watch push toasts (WS {"@type":"DriveWatch",event:{nodeId,op,spaceId}}) ──
	// Task 13: nodeName for the toast text now reads the shared driveWatches
	// store (§5.6) instead of a private local cache — see watchToastText.
	$effect(() => {
		void driveWatches.load();
		const unsubscribe = subscribeEvent<{ nodeId?: number; op?: string }>('DriveWatch', (event) => {
			if (!event.nodeId || !event.op) return;
			showToast(watchToastText(event.nodeId, event.op));
		});
		return unsubscribe;
	});

	// ── node actions ─────────────────────────────────────────────────────────
	async function handleRename(node: DriveNode, newName: string) {
		try {
			await api.renameNode(node.id, newName);
			await loadListing();
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	async function handleTrash(node: DriveNode) {
		try {
			await api.trashNode(node.id);
			await loadListing();
			if (selectedFile?.id === node.id) selectedFile = null;
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	async function handleRestore(node: DriveNode) {
		try {
			await api.restoreNode(node.id);
			await loadListing();
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	async function handleDestroy(node: DriveNode) {
		try {
			await api.destroyNode(node.id);
			await loadListing();
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	// ── P6 Task 14: watch quick-toggle + live push toasts ────────────────────
	// Node names for toast text come from the shared driveWatches store's rows
	// (§5.6/Task 13) rather than a private cache. A DriveWatch push for a node
	// not in the store (an ancestor watch firing for an unvisited descendant)
	// falls back to a generic sentence rather than a blocking name lookup —
	// ponytail: good enough for a live nudge; the Subscription manager list is
	// the durable source of truth.
	async function handleWatchToggle(node: DriveNode) {
		try {
			await driveWatches.watch(node.id);
			showToast(t('drive.watch.watchingToast', { name: node.name }), {
				actionLabel: t('common.undo'),
				onAction: () => void driveWatches.unwatch(node.id).catch(() => {}),
			});
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	function watchToastText(nodeId: number, op: string): string {
		const name = driveWatches.list().find((w) => w.nodeId === nodeId)?.nodeName;
		const key = `drive.watch.toast.${op}`;
		if (name) return t(key, { name });
		return t('drive.watch.toast.generic');
	}

	function submitNewFolder() {
		const name = newFolderName.trim();
		if (!name || selectedSpaceId === null) return;
		api
			.createNode({ spaceId: selectedSpaceId, parentId: currentFolderId, kind: 'folder', name })
			.then(() => {
				showNewFolderDialog = false;
				newFolderName = '';
				return loadListing();
			})
			.catch((e) => {
				bannerError = driveErrorMessage(e);
			});
	}

	// ── space create ────────────────────────────────────────────────────────
	async function submitNewSpace() {
		const name = newSpaceName.trim();
		if (!name) return;
		creatingSpace = true;
		try {
			const { id } = await api.createSpace({ name, classification: newSpaceClassification });
			showNewSpaceDialog = false;
			newSpaceName = '';
			newSpaceClassification = 'regular';
			await loadSpaces();
			selectSpace(id);
		} catch (e) {
			bannerError = driveErrorMessage(e);
		} finally {
			creatingSpace = false;
		}
	}

	// ── upload ──────────────────────────────────────────────────────────────
	// Progress-tray bookkeeping (entry push, onProgress wiring, done/error
	// transitions, error mapping) lives in uploadOrchestrator.svelte.ts — see
	// task-14-report.md. This site's own job is just: create the node first,
	// then hand the file to the orchestrator.
	async function startUpload(file: File, note?: string) {
		if (selectedSpaceId === null) return;
		const spaceId = selectedSpaceId;
		let node: { id: number };
		try {
			node = await api.createNode({
				spaceId,
				parentId: currentFolderId,
				kind: 'file',
				name: file.name,
				contentType: file.type || null,
			});
		} catch (e) {
			bannerError = uploadErrorMessage(e);
			return;
		}
		const outcome = await uploadOrchestrator.start(spaceId, node.id, file, {
			baseVersionId: null,
			contentType: file.type || null,
			note,
		});
		if (!outcome.ok) {
			bannerError = uploadErrorMessage(outcome.error);
			return;
		}
		surfaceWormPending(outcome.result);
		await loadListing();
	}

	function handleFilePicked(e: Event) {
		const files = (e.target as HTMLInputElement).files;
		if (!files) return;
		const list = Array.from(files);
		(e.target as HTMLInputElement).value = '';
		versionSave.handleFilePicked(list);
	}

	// Restore is server-side: protected originals and manifests never transit
	// the browser. The reducer binds the source to this file and reuses the
	// canonical save authority for capability, lock, conflict, quota and WORM.
	async function handleRestoreAsNew(version: DriveVersion) {
		if (!selectedFile || !selectedSpace) return;
		try {
			const result = await api.restoreVersion(selectedFile.id, version.id, {
				baseVersionId: selectedFile.headVersionId ?? null,
				note: t('drive.version.restoreAsNew'),
			});
			surfaceWormPending(result);
			versions = await api.listVersions(selectedFile.id);
			await loadListing();
		} catch (e) {
			bannerError = driveErrorMessage(e);
		}
	}

	function dismissUpload(id: string) {
		uploadOrchestrator.remove(id);
	}

	// ── in-app viewer (P3 SecureViewer) ─────────────────────────────────────
	// Regular-space versions keep VersionDrawer's plain download link (never
	// routed through here); secure/gxp versions open in-app instead of a raw
	// download link (spec §8.1). Source is always 'online' — no UI here saves
	// a version into the P3 vault yet, so the 'vault' ContentSource is
	// exercised at the unit level (VaultStore/SecureViewer tests) but not yet
	// reachable from this screen. ponytail: wire a "pin for offline" action
	// through VaultStore.putLocal + open({kind:'vault', manifest}) if/when
	// that UI ships.
	function handleViewVersion(version: DriveVersion) {
		if (!selectedSpace) return;
		inAppRenderer.open(
			{
				versionId: version.id,
				name: selectedFile?.name ?? '',
				contentType: version.contentType ?? null,
				size: version.size,
				classification: selectedSpace.classification,
				previewStatus: version.previewStatus,
			},
			{ kind: 'online' },
		);
	}
</script>

<div class="drive-app">
	<div class="drive-app__banner" aria-live="polite">
		{#if bannerError}
			<div class="drive-app__error" role="alert">
				<Icon name="AlertTriangle" size={14} />
				<span>{bannerError}</span>
				<Button variant="ghost" size="sm" onclick={() => (bannerError = '')}>{t('common.close')}</Button>
			</div>
		{/if}
		{#if bannerNotice}
			<div class="drive-app__notice" role="status">
				<Icon name="Lock" size={14} />
				<span>{bannerNotice}</span>
				<Button variant="ghost" size="sm" onclick={() => (bannerNotice = '')}>{t('common.close')}</Button>
			</div>
		{/if}
	</div>

	{#if spacesLoading}
		<div class="drive-app__loading"><Spinner /></div>
	{:else}
		<div class="drive-app__body">
			<SpaceList {spaces} selectedId={quickView ? null : selectedSpaceId} {quickView} {governanceEnabled} onSelect={selectSpace} onSelectQuickView={selectQuickView} onNewSpace={() => (showNewSpaceDialog = true)} />

			{#if selectedSpace}
				<div class="drive-app__main">
					<div class="drive-app__toolbar">
						<span class="drive-app__space-name">{quickView ? t(`drive.quick.${quickView}`) : virtualAnchor ? `${t('drive.quick.shared')} › ${virtualAnchor.name}` : selectedSpace.name}</span>
						{#if virtualAnchor}<Button variant="ghost" size="sm" onclick={() => selectQuickView(virtualAnchor?.kind === 'share' ? 'shares' : 'shared')}><Icon name="ArrowLeft" size={14} />{t('drive.quick.back')}</Button>{/if}
						{#if !quickView}<div class="drive-app__search">
							<Input
								type="search"
								placeholder={t('drive.search.placeholder')}
								aria-label={t('drive.search.label')}
								bind:value={searchQuery}
								oninput={runSearch}
							/>
							<Select
								aria-label={t('drive.search.label')}
								bind:value={searchScope}
								onchange={runSearch}
								options={[
									{ value: 'current', label: selectedSpace.name },
									{ value: 'all', label: t('drive.search.scope.all') },
								]}
							/>
						</div>{/if}
						{#if !quickView}<div class="drive-app__toolbar-actions">
							<SyncStatusPill onclick={() => (showSyncSheet = true)} />
							<Button variant="ghost" size="sm" onclick={() => (showActivity = true)}>
								<Icon name="History" size={14} />
								{t('drive.activity.title')}
							</Button>
							<Button variant="ghost" size="sm" onclick={() => (showSubscriptions = true)}>
								<Icon name="Bell" size={14} />
								{t('drive.watch.title')}
							</Button>
							<Button variant="ghost" size="sm" onclick={() => (showAsOfDialog = true)}>
								<Icon name="Clock" size={14} />
								{t('drive.asof.title')}
							</Button>
							{#if !asOfMode}
								<Button variant="ghost" size="sm" onclick={toggleTrashView}>
									<Icon name="Trash2" size={14} />
									{deletedView ? t('drive.tree.root') : t('drive.tree.trashView')}
								</Button>
							{/if}
							<Button variant="ghost" size="sm" onclick={() => (showMembers = true)}>
								<Icon name="Users" size={14} />
								{t('drive.members.title')}
							</Button>
							{#if canCreate && !deletedView && !asOfMode}
								<Button variant="secondary" size="sm" onclick={() => (showNewFolderDialog = true)}>
									<Icon name="Folder" size={14} />
									{t('drive.tree.newFolder')}
								</Button>
								<input
									bind:this={uploadInput}
									type="file"
									multiple
									onchange={handleFilePicked}
									class="drive-app__file-input"
									aria-hidden="true"
									tabindex="-1"
								/>
								<Button variant="primary" size="sm" onclick={() => uploadInput?.click()}>
									<Icon name="Upload" size={14} />
									{t('drive.upload.drop')}
								</Button>
							{/if}
						</div>{/if}
					</div>

					<!-- Task 15: the only markup search rows and as-of rows genuinely share
					     (icon + name + optional size) — the rest of each row (search's
					     navigate-away click vs as-of's notLive badge / restore-version
					     button) diverges enough that a shared row/list component isn't
					     worth it (measured against FileList too: it's bound to full
					     DriveNode CRUD — rename/trash/watch/folder-admins — none of which
					     either read-only listing has). -->
					{#snippet nodeIconName(kind: 'folder' | 'file', name: string, sizeBytes?: number)}
						<Icon name={kind === 'folder' ? 'Folder' : 'FileText'} size={16} />
						<span class="drive-app__search-name">{name}</span>
						{#if sizeBytes != null}
							<span class="drive-app__search-size">{formatBytes(sizeBytes)}</span>
						{/if}
					{/snippet}

					{#if searchQuery.trim().length >= 2}
						<div class="drive-app__search-results">
							{#if driveSearch.loading}
								<div class="drive-app__search-status"><Spinner size={16} /></div>
							{:else if driveSearch.error}
								<p class="drive-app__search-status" role="alert">{driveErrorMessage(driveSearch.error)}</p>
							{:else if driveSearch.results.length === 0}
								<p class="drive-app__search-status" aria-live="polite">
									{t('drive.search.noResults', { q: searchQuery })}
								</p>
							{:else}
								<p class="drive-app__search-count" aria-live="polite">
									{t('drive.search.resultCount', { n: String(driveSearch.results.length) })}
								</p>
								<ul class="drive-app__search-list">
									{#each driveSearch.results as item (item.id)}
										<li>
											<button type="button" class="drive-app__search-row" onclick={() => openSearchResult(item)}>
												{@render nodeIconName(item.kind, item.name, item.kind === 'file' ? item.sizeBytes : undefined)}
											</button>
										</li>
									{/each}
								</ul>
							{/if}
						</div>
					{/if}

					{#if asOfMode && asOfAt}
						<div class="drive-app__asof-banner" role="status">
							<Icon name="Clock" size={14} />
							<span>{t('drive.asof.banner', { space: selectedSpace.name, at: formatDateTime(asOfAt) })}</span>
							<Button variant="ghost" size="sm" onclick={exitAsOf}>{t('drive.asof.exit')}</Button>
						</div>
					{/if}

					<div class="drive-app__panes">
						{#if quickView}
							<DriveQuickView view={quickView} items={quickItems} loading={quickLoading} error={quickError} onOpen={openQuickItem} onRetry={loadQuickView} onOpenSpace={() => selectSpace(selectedSpace.id)} />
						{:else if asOfMode}
							<div class="drive-app__asof-list">
								{#if asOfLoading}
									<div class="fl__loading"><Spinner /></div>
								{:else}
									<ul class="drive-app__search-list">
										{#each asOfItems as item (item.id)}
											<li class="drive-app__asof-row">
												{@render nodeIconName(item.kind, item.name, item.sizeBytes)}
												{#if !item.liveNow}
													<span class="drive-app__asof-badge">
														<Icon name="AlertTriangle" size={12} />
														{t('drive.asof.notLive')}
													</span>
												{/if}
												{#if item.kind === 'file' && item.versionId !== null}
													<Button variant="ghost" size="sm" onclick={() => restoreAsOfVersion(item)}>
														{t('drive.asof.restoreVersion')}
													</Button>
												{/if}
											</li>
										{/each}
									</ul>
								{/if}
							</div>
						{:else}
							{#if !virtualAnchor}<DriveTree spaceId={selectedSpace.id} selectedFolderId={currentFolderId} onSelect={selectFolderFromTree} />{/if}
							<FileList
								nodes={listing}
								loading={listingLoading}
								{deletedView}
								onOpenFolder={openFolder}
								onSelectFile={selectFile}
								onRename={handleRename}
								onTrash={handleTrash}
								onRestore={handleRestore}
								onDestroy={handleDestroy}
								onManageFolderAdmins={(node) => (folderAdminsFor = node)}
								onManageAccess={openAccess}
								onWatch={handleWatchToggle}
							/>
							{#if selectedFile}
								<VersionDrawer
									node={selectedFile}
									spaceId={selectedSpace.id}
									{versions}
									loading={versionsLoading}
									classification={selectedSpace.classification}
									canWrite={selectedCanModify}
									onClose={() => (selectedFile = null)}
									onRestoreAsNew={handleRestoreAsNew}
									onUploadNewVersion={(file) => versionSave.requestUploadNewVersion(file)}
									onView={handleViewVersion}
									onLabelsChanged={refreshSelectedFile}
								/>
								<BranchPanel
									nodeId={selectedFile.id}
									fromVersionId={selectedFile.headVersionId ?? versions[0]?.id ?? 0}
									canWrite={selectedCanModify}
									fileName={selectedFile.name}
									onChanged={refreshSelectedFile}
								/>
							{/if}
							{#if accessNode}
								<NodeAccessDrawer node={accessNode} onClose={() => (accessNode = null)} onChanged={loadListing} />
							{/if}
						{/if}
					</div>
				</div>
			{:else}
				<div class="drive-app__empty">{t('drive.space.list')}</div>
			{/if}
		</div>
	{/if}
</div>

<SelectiveSyncSheet open={showSyncSheet} onClose={() => (showSyncSheet = false)} />

<MembersSheet
	open={showMembers}
	spaceId={selectedSpaceId}
	{isManager}
	selfEmail={$user?.email ?? ''}
	onClose={() => (showMembers = false)}
	onLeft={() => void loadSpaces()}
/>

<Dialog open={showNewSpaceDialog} title={t('drive.space.create')} onClose={() => (showNewSpaceDialog = false)}>
	<div class="ns-form">
		<Input label={t('drive.space.name')} bind:value={newSpaceName} />
		<Select
			label={t('drive.space.list')}
			bind:value={newSpaceClassification}
			options={[
				{ value: 'regular', label: t('drive.space.classification.regular') },
				{ value: 'secure', label: t('drive.space.classification.secure') },
				{ value: 'gxp', label: t('drive.space.classification.gxp') },
			]}
		/>
		{#if newSpaceClassification !== 'regular'}
			<p class="ns-form__warning" role="alert">{t('drive.space.noDowngradeWarning')}</p>
		{/if}
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={creatingSpace || !newSpaceName.trim()} onclick={submitNewSpace}>
			{creatingSpace ? t('common.loading') : t('drive.space.create')}
		</Button>
		<Button variant="secondary" onclick={() => (showNewSpaceDialog = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showNewFolderDialog} title={t('drive.tree.newFolder')} onClose={() => (showNewFolderDialog = false)}>
	<Input label={t('drive.tree.newFolder')} bind:value={newFolderName} />
	{#snippet footer()}
		<Button variant="primary" disabled={!newFolderName.trim()} onclick={submitNewFolder}>{t('common.save')}</Button>
		<Button variant="secondary" onclick={() => (showNewFolderDialog = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<UploadProgress uploads={uploadOrchestrator.uploads} onDismiss={dismissUpload} />

{#if versionSave.saveAsBranchPrompt}
	<Dialog
		open={true}
		title={t('drive.lock.saveAsBranch')}
		onClose={() => versionSave.dismissSaveAsBranch()}
	>
		<p>{t('drive.lock.saveAsBranchPrompt', { name: versionSave.saveAsBranchPrompt.holderLabel })}</p>
		{#snippet footer()}
			<Button variant="primary" onclick={() => versionSave.confirmSaveAsBranch()}>{t('drive.lock.saveAsBranch')}</Button>
			<Button variant="secondary" onclick={() => versionSave.dismissSaveAsBranch()}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

{#if showActivity && selectedSpace}
	<Dialog open={true} title={t('drive.activity.title')} onClose={() => (showActivity = false)} wide>
		<ActivityFeed spaceId={selectedSpace.id} />
	</Dialog>
{/if}

{#if folderAdminsFor}
	<FolderAdminsSheet open={true} nodeId={folderAdminsFor.id} onClose={() => (folderAdminsFor = null)} />
{/if}

{#if inAppRenderer.current}
	<SecureViewer
		version={inAppRenderer.current.version}
		source={inAppRenderer.current.source}
		onclose={() => inAppRenderer.close()}
	/>
{/if}

<ChangeNoteDialog
	open={versionSave.showChangeNote}
	onSubmit={(note) => versionSave.submitChangeNote(note)}
	onCancel={() => versionSave.cancelChangeNote()}
/>

<Dialog open={showAsOfDialog} title={t('drive.asof.title')} onClose={() => (showAsOfDialog = false)}>
	<div class="ns-form">
		<Input type="datetime-local" label={t('drive.asof.title')} bind:value={asOfInputValue} />
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={!asOfInputValue} onclick={() => applyAsOf(asOfInputValue)}>
			{t('drive.asof.apply')}
		</Button>
		<Button variant="secondary" onclick={() => (showAsOfDialog = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<SubscriptionsSheet open={showSubscriptions} onClose={() => (showSubscriptions = false)} />

<style>
	.drive-app {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
	}
	.drive-app__banner:empty {
		display: none;
	}
	.drive-app__error {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.drive-app__error span {
		flex: 1;
	}
	.drive-app__notice {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--info-bg);
		color: var(--info-fg);
		font-size: var(--text-sm);
	}
	.drive-app__notice span {
		flex: 1;
	}
	.drive-app__loading,
	.drive-app__empty {
		display: flex;
		align-items: center;
		justify-content: center;
		flex: 1;
		color: var(--text-caption);
	}
	.drive-app__body {
		display: flex;
		flex: 1;
		min-height: 0;
	}
	.drive-app__main {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
	}
	.drive-app__toolbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-default);
		flex-wrap: wrap;
	}
	.drive-app__search {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex: 1 1 320px;
		max-width: 480px;
		min-width: 200px;
	}
	.drive-app__search :global(.sj-field) {
		flex: 1;
	}
	.drive-app__search :global(.sj-select-wrap) {
		flex: 0 0 160px;
	}
	.drive-app__space-name {
		font-weight: 600;
		font-size: var(--text-sm);
	}
	.drive-app__toolbar-actions {
		display: flex;
		gap: var(--space-2);
		align-items: center;
	}
	.drive-app__file-input {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
	.drive-app__panes {
		flex: 1;
		display: flex;
		min-height: 0;
		position: relative;
	}
	.ns-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.ns-form__warning {
		font-size: var(--text-sm);
		color: var(--warning-fg);
		background: var(--warning-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}

	/* ── P6 Task 13: search results ──────────────────────────────────────── */
	.drive-app__search-results {
		border-bottom: 1px solid var(--border-default);
		max-height: 280px;
		overflow-y: auto;
	}
	.drive-app__search-status,
	.drive-app__search-count {
		margin: 0;
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.drive-app__search-list {
		list-style: none;
		margin: 0;
		padding: 0 var(--space-2) var(--space-2);
	}
	.drive-app__search-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-2);
		border: none;
		background: none;
		border-radius: var(--radius-sm);
		cursor: pointer;
		text-align: left;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.drive-app__search-row:hover {
		background: var(--surface-hover);
	}
	.drive-app__search-row:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.drive-app__search-name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.drive-app__search-size {
		font-size: var(--text-xs);
		color: var(--text-caption);
		flex-shrink: 0;
	}

	/* ── P6 Task 17: "space as of…" view ─────────────────────────────────── */
	.drive-app__asof-banner {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--info-bg);
		color: var(--info-fg);
		font-size: var(--text-sm);
	}
	.drive-app__asof-banner span {
		flex: 1;
	}
	.drive-app__asof-list {
		flex: 1;
		min-width: 0;
		overflow-y: auto;
	}
	.drive-app__asof-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
	}
	.drive-app__asof-badge {
		display: inline-flex;
		align-items: center;
		gap: 3px;
		font-size: var(--text-xs);
		color: var(--warning-fg);
		flex-shrink: 0;
	}

	@media (max-width: 700px) {
		.drive-app__body {
			flex-direction: column;
			overflow: hidden;
		}
		.drive-app__main {
			min-height: 0;
		}
		.drive-app__toolbar {
			align-items: stretch;
			gap: var(--space-2);
			padding: var(--space-2);
		}
		.drive-app__space-name {
			width: 100%;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}
		.drive-app__search {
			flex: 1 1 100%;
			min-width: 0;
			max-width: none;
		}
		.drive-app__search :global(.sj-select-wrap) {
			flex-basis: 112px;
		}
		.drive-app__toolbar-actions {
			width: 100%;
			overflow-x: auto;
			padding-bottom: 1px;
		}
		.drive-app__toolbar-actions :global(button) {
			flex: 0 0 auto;
		}
		.drive-app__panes {
			flex-direction: column;
			overflow: hidden;
		}
	}
</style>
