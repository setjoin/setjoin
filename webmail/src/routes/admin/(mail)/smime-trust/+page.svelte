<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import { Card, Badge, Button, Dialog, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	interface TrustAnchor {
		id: number;
		label: string;
		subjectCn: string;
		fingerprint: string;
		domainId: number | null;
		notBefore: string;
		notAfter: string;
		createdAt: string;
	}

	let anchors = $state<TrustAnchor[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Import form
	let importLabel = $state('');
	let importFile = $state<File | null>(null);
	let importing = $state(false);
	let importError = $state('');
	let fileInputEl = $state<HTMLInputElement | undefined>(undefined);

	// Delete dialog
	let deleteTarget = $state<TrustAnchor | null>(null);
	let deleting = $state(false);

	onMount(() => { load(); });

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await adminFetch('/admin/smime/trust-anchors');
			if (!res.ok) {
				const body = await res.json().catch(() => ({}));
				error = (body as { error?: string }).error ?? `HTTP ${res.status}`;
				return;
			}
			const data = await res.json() as { anchors: TrustAnchor[] };
			anchors = data.anchors ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load trust anchors';
		} finally {
			loading = false;
		}
	}

	function isExpired(notAfter: string): boolean {
		return new Date(notAfter) < new Date();
	}

	function formatDate(iso: string): string {
		return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}

	function onFileChange(e: Event) {
		const input = e.target as HTMLInputElement;
		importFile = input.files?.[0] ?? null;
	}

	async function doImport() {
		if (!importFile) {
			importError = 'Select a PEM file to import.';
			return;
		}
		importing = true;
		importError = '';
		try {
			const form = new FormData();
			form.append('label', importLabel.trim() || importFile.name);
			form.append('cert', importFile);
			const res = await adminFetch('/admin/smime/trust-anchors', { method: 'POST', body: form });
			if (!res.ok) {
				const body = await res.json().catch(() => ({}));
				importError = (body as { error?: string }).error ?? `HTTP ${res.status}`;
				return;
			}
			importLabel = '';
			importFile = null;
			if (fileInputEl) fileInputEl.value = '';
			showToast(t('admin.smime_trust.imported'));
			await load();
		} catch (e) {
			importError = e instanceof Error ? e.message : 'Import failed';
		} finally {
			importing = false;
		}
	}

	function openDelete(anchor: TrustAnchor) {
		deleteTarget = anchor;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		deleting = true;
		const id = deleteTarget.id;
		try {
			const res = await adminFetch(`/admin/smime/trust-anchors/${id}`, { method: 'DELETE' });
			if (!res.ok) {
				const body = await res.json().catch(() => ({}));
				error = (body as { error?: string }).error ?? `HTTP ${res.status}`;
				return;
			}
			deleteTarget = null;
			await load();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Delete failed';
		} finally {
			deleting = false;
		}
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.smime_trust.title')}</h1>
			<p>{t('admin.smime_trust.desc')}</p>
		</div>
	</header>

	{#if error}
		<div class="sj-alert sj-alert--danger" role="alert">{error}</div>
	{/if}

	<Card title={t('admin.smime_trust.title')}>
		{#snippet children()}
			{#if loading}
				<div class="sj-center"><Spinner /></div>
			{:else if anchors.length === 0}
				<EmptyState title={t('admin.smime_trust.none')} />
			{:else}
				<table class="sj-table">
					<thead>
						<tr>
							<th>{t('admin.smime_trust.label')}</th>
							<th>Subject CN</th>
							<th>{t('admin.smime_trust.expires')}</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each anchors as anchor (anchor.id)}
							<tr>
								<td class="sj-cell-label">{anchor.label}</td>
								<td class="sj-cell-mono">{anchor.subjectCn || '—'}</td>
								<td>
									<span class:sj-expired={isExpired(anchor.notAfter)}>
										{formatDate(anchor.notAfter)}
									</span>
									{#if isExpired(anchor.notAfter)}
										<Badge variant="warning" label={t('admin.smime_trust.expired')} />
									{/if}
								</td>
								<td class="sj-cell-action">
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openDelete(anchor)}
									>
										<Icon name="Trash2" size={14} />
										{t('admin.smime_trust.delete')}
									</Button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		{/snippet}
	</Card>

	<div style="margin-top:12px">
		<Card title={t('admin.smime_trust.import')}>
			{#snippet children()}
				<div class="sj-import-form">
					<div class="sj-field">
						<label for="import-label" class="sj-label">{t('admin.smime_trust.label')}</label>
						<input
							id="import-label"
							class="sj-input"
							type="text"
							maxlength="128"
							placeholder="e.g. Corporate CA"
							bind:value={importLabel}
						/>
					</div>
					<div class="sj-field">
						<label for="import-cert" class="sj-label">{t('admin.smime_trust.cert')}</label>
						<input
							id="import-cert"
							class="sj-input"
							type="file"
							accept=".pem,.crt,.cer"
							onchange={onFileChange}
							bind:this={fileInputEl}
						/>
					</div>
					{#if importError}
						<div class="sj-field-error" role="alert">{importError}</div>
					{/if}
					<div class="sj-btn-row">
						<Button
							variant="primary"
							size="sm"
							onclick={doImport}
							disabled={importing || !importFile}
						>
							{#if importing}
								<Spinner size={16} />
							{:else}
								<Icon name="Plus" size={14} />
							{/if}
							{t('admin.smime_trust.import')}
						</Button>
					</div>
				</div>
			{/snippet}
		</Card>
	</div>
</div>

<!-- Delete confirmation dialog -->
<Dialog
	open={deleteTarget !== null}
	title={t('admin.smime_trust.delete')}
	onClose={() => { deleteTarget = null; }}
>
	{#snippet children()}
		<p>{t('admin.smime_trust.delete_confirm')}</p>
		{#if deleteTarget}
			<p class="sj-delete-target">{deleteTarget.label}</p>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" size="sm" onclick={() => { deleteTarget = null; }} disabled={deleting}>
			{t('admin.common.cancel')}
		</Button>
		<Button variant="danger" size="sm" onclick={confirmDelete} disabled={deleting}>
			{#if deleting}<Spinner size={16} />{/if}
			{t('admin.smime_trust.delete')}
		</Button>
	{/snippet}
</Dialog>

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-page-head-left p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }
	.sj-alert { padding: 10px 14px; border-radius: var(--radius-md); font-size: var(--text-sm); margin-bottom: 12px; }
	.sj-alert--danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
	.sj-center { display: flex; justify-content: center; padding: 24px 0; }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); vertical-align: middle; }
	.sj-cell-label { font-weight: var(--weight-medium); color: var(--text-primary); }
	.sj-cell-mono { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
	.sj-cell-action { text-align: right; white-space: nowrap; }
	.sj-expired { color: var(--warning-fg); }
	.sj-import-form { display: flex; flex-direction: column; gap: 12px; max-width: 480px; }
	.sj-field { display: flex; flex-direction: column; gap: 4px; }
	.sj-label { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
	.sj-input { width: 100%; height: 32px; padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-input); color: var(--text-primary); font-family: var(--font-sans); font-size: var(--text-sm); box-sizing: border-box; }
	.sj-input[type="file"] { height: auto; padding: 6px 10px; }
	.sj-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-field-error { font-size: var(--text-sm); color: var(--danger-fg); }
	.sj-btn-row { display: flex; gap: 8px; align-items: center; }
	.sj-delete-target { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); margin-top: 8px; }
</style>
