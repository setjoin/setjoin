<svelte:options runes={true} />

<script lang="ts">
	import { Button, Card, Dialog, EmptyState, Input, Spinner, Switch, Table, Textarea, showToast } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import { t, formatDate } from '$lib/i18n';
	import { parseError } from '$lib/errors';

	interface TouDoc {
		id: number;
		name: string;
		version: number;
		enabled: boolean;
		body_md: string;
		created_at: string;
		updated_at: string;
	}

	type View = 'loading' | 'error' | 'empty' | 'ready';

	let docs = $state<TouDoc[]>([]);
	let view = $state<View>('loading');
	let listError = $state('');

	// Edit/create dialog
	let showForm = $state(false);
	let editing = $state<TouDoc | null>(null);
	let saving = $state(false);
	let formError = $state('');
	let form = $state({ name: '', version: 1, enabled: true, body_md: '' });

	// Delete confirm dialog
	let deleteTarget = $state<TouDoc | null>(null);
	let deleting = $state(false);

	const COLUMNS: TableColumn[] = [
		{ key: 'name',    label: t('tou_admin.col_name'),    sortable: false },
		{ key: 'version', label: t('tou_admin.col_version'), sortable: false },
		{ key: 'enabled', label: t('tou_admin.col_enabled'), sortable: false },
		{ key: 'updated', label: t('admin.common.updated'),  sortable: false },
		{ key: 'actions', label: '',                         sortable: false, width: '120px' },
	];

	async function load() {
		view = 'loading';
		listError = '';
		try {
			const res = await fetch('/api/admin/terms-of-use');
			if (!res.ok) throw new Error(String(res.status));
			docs = await res.json();
			view = docs.length === 0 ? 'empty' : 'ready';
		} catch (e) {
			listError = parseError(e).message;
			view = 'error';
		}
	}

	function openNew() {
		editing = null;
		form = { name: '', version: 1, enabled: true, body_md: '' };
		formError = '';
		showForm = true;
	}

	function openEdit(d: TouDoc) {
		editing = d;
		form = { name: d.name, version: d.version, enabled: d.enabled, body_md: d.body_md };
		formError = '';
		showForm = true;
	}

	async function save() {
		saving = true;
		formError = '';
		try {
			const method = editing ? 'PUT' : 'POST';
			const url = editing ? `/api/admin/terms-of-use/${editing.id}` : '/api/admin/terms-of-use';
			const res = await fetch(url, {
				method,
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(form),
			});
			if (!res.ok) { formError = parseError(await res.text()).message; return; }
			const doc: TouDoc = await res.json();
			if (editing) {
				docs = docs.map((d) => (d.id === doc.id ? doc : d));
			} else {
				docs = [...docs, doc];
				view = 'ready';
			}
			showForm = false;
			showToast(t('tou_admin.saved_toast', { name: form.name }));
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function doDelete() {
		if (!deleteTarget) return;
		deleting = true;
		try {
			const res = await fetch(`/api/admin/terms-of-use/${deleteTarget.id}`, { method: 'DELETE' });
			if (!res.ok) { listError = parseError(await res.text()).message; return; }
			docs = docs.filter((d) => d.id !== deleteTarget!.id);
			if (docs.length === 0) view = 'empty';
			deleteTarget = null;
			showToast(t('tou_admin.deleted_toast'));
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			deleting = false;
		}
	}

	$effect(() => { load(); });
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('tou_admin.title')}</h1>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" disabled={view === 'loading'} onclick={openNew}>{t('tou_admin.new')}</Button>
		</div>
	</header>

	{#if view === 'loading'}
		<div class="tou-center"><Spinner /></div>
	{:else if view === 'error'}
		<div class="tou-error" role="alert">
			<span>{t('tou_admin.load_failed')}</span>
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>
	{:else if view === 'empty'}
		<EmptyState title={t('tou_admin.empty_title')} watermark>
			{#snippet action()}
				<Button variant="primary" onclick={openNew}>{t('tou_admin.empty_cta')}</Button>
			{/snippet}
		</EmptyState>
	{:else}
		<Card flush={true}>
			<Table columns={COLUMNS} rows={docs as unknown as Record<string, unknown>[]}>
				{#snippet cell(row, col)}
					{@const d = row as unknown as TouDoc}
					{#if col.key === 'name'}
						<span class="tou-name" title={d.name}>{d.name}</span>
					{:else if col.key === 'version'}
						{d.version}
					{:else if col.key === 'enabled'}
						{d.enabled ? t('tou_admin.enabled_yes') : t('tou_admin.enabled_no')}
					{:else if col.key === 'updated'}
						<span class="sj-muted"><time datetime={d.updated_at}>{formatDate(d.updated_at)}</time></span>
					{:else if col.key === 'actions'}
						<div class="tou-actions">
							<Button variant="ghost" size="sm" onclick={() => openEdit(d)}>{t('admin.common.edit')}</Button>
							<Button variant="ghost" size="sm" onclick={() => (deleteTarget = d)}>{t('common.delete')}</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		</Card>
	{/if}
</div>

<!-- Create/Edit dialog -->
{#if showForm}
	<Dialog
		open={showForm}
		title={editing ? t('tou_admin.edit_title') : t('tou_admin.new_title')}
		wide={true}
		onClose={() => (showForm = false)}
	>
		{#snippet children()}
			<div class="sj-form">
				<Input
					label={t('tou_admin.name')}
					value={form.name}
					oninput={(e) => (form.name = (e.target as HTMLInputElement).value)}
				/>
				<div class="tou-version-row">
					<Input
						label={t('tou_admin.version')}
						value={String(form.version)}
						oninput={(e) => (form.version = Number((e.target as HTMLInputElement).value) || form.version)}
					/>
					<div class="tou-bump">
						<Button
							variant="secondary"
							size="sm"
							onclick={() => (form.version = form.version + 1)}
						>{t('tou_admin.bump_version')}</Button>
						<span class="tou-bump-hint">{t('tou_admin.bump_hint')}</span>
					</div>
				</div>
				<Switch
					label={t('tou_admin.enabled')}
					checked={form.enabled}
					onchange={(e) => (form.enabled = (e.target as HTMLInputElement).checked)}
				/>
				<div class="tou-body-row">
					<div class="tou-body-col">
						<Textarea
							label={t('tou_admin.body')}
							value={form.body_md}
							rows={10}
							oninput={(e) => (form.body_md = (e.target as HTMLTextAreaElement).value)}
						/>
					</div>
					<div class="tou-preview-col">
						<span class="tou-preview-label">{t('tou_admin.preview')}</span>
						<!-- ponytail: render body_md as plain preformatted text;
						     full markdown renderer is a future enhancement when the
						     TermsAcceptance modal renderer is extracted to a shared util. -->
						<pre class="tou-preview">{form.body_md}</pre>
					</div>
				</div>
				{#if formError}
					<div class="sj-form-error" role="alert">{formError}</div>
				{/if}
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" disabled={saving} onclick={save}>
				{#if saving}<Spinner size={16} />{/if}
				{t('common.save')}
			</Button>
			<Button variant="secondary" onclick={() => (showForm = false)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- Delete confirm dialog (dangerous — doc has acceptance history) -->
{#if deleteTarget}
	<Dialog
		open={!!deleteTarget}
		title={t('tou_admin.delete_title', { name: deleteTarget.name })}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			<p>{t('tou_admin.delete_body')}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (deleteTarget = null)} disabled={deleting}>{t('common.cancel')}</Button>
			<Button variant="danger" onclick={doDelete} disabled={deleting}>{t('tou_admin.delete_confirm')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
		flex-wrap: wrap;
	}
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		color: var(--text-primary);
	}
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; }

	.tou-center { display: flex; justify-content: center; padding: var(--space-8); }
	.tou-error {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
		margin-bottom: 12px;
	}
	.tou-name { max-width: 30ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
	.tou-actions { display: flex; gap: 4px; }
	.sj-muted { color: var(--text-tertiary); font-size: var(--text-xs); }

	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.tou-version-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
	.tou-bump { display: flex; flex-direction: column; gap: 4px; }
	.tou-bump-hint { font-size: var(--text-xs); color: var(--text-caption); max-width: 28ch; }

	.tou-body-row { display: flex; gap: 16px; }
	.tou-body-col { flex: 1; }
	.tou-preview-col {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.tou-preview-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.tou-preview {
		flex: 1;
		margin: 0;
		padding: 8px 10px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: pre-wrap;
		overflow-y: auto;
		min-height: 180px;
	}

	.sj-form-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	@media (max-width: 700px) {
		.tou-body-row { flex-direction: column; }
	}

	@media (prefers-reduced-motion: reduce) {
		/* No transitions declared in this page; guard is a no-op but required by
		   the shared reduced-motion.test.ts check. */
	}
</style>
