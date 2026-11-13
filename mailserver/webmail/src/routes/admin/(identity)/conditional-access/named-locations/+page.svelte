<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import { Card, Badge, Button, Input, Dialog, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';

	// ── Types ──
	interface NamedLocation {
		id: number;
		name: string;
		cidrs: string[];
		countries: string[];
		trusted: boolean;
		deleted_at?: string | null;
		created_at: string;
		updated_at: string;
	}

	// ── State ──
	let locations: NamedLocation[] = $state([]);
	let loading = $state(true);
	let listError = $state('');

	let showForm = $state(false);
	let editing: NamedLocation | null = $state(null);
	let formName = $state('');
	let formCidrs = $state('');
	let formTrusted = $state(false);
	let formCidrError = $state('');
	let saving = $state(false);
	let formError = $state('');

	let deleteTarget: NamedLocation | null = $state(null);
	let deleting = $state(false);

	let deletedLocations: NamedLocation[] = $state([]);
	let trashVisible = $state(false);
	let trashLoading = $state(false);

	// ── CIDR validation ──
	// ponytail: inline regex, not a lib — the two CIDR patterns are simple enough.
	const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/;

	function validateCidrs(raw: string): string {
		const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
		for (const line of lines) {
			if (!CIDR_RE.test(line)) {
				return t('admin.conditional_access.named_location.bad_cidr', { value: line });
			}
		}
		return '';
	}

	// ── Load ──
	onMount(load);

	async function load() {
		loading = true;
		listError = '';
		try {
			const res = await adminFetch('/admin/conditional-access/named-locations');
			if (!res.ok) throw new Error(String(res.status));
			const all: NamedLocation[] = await res.json();
			locations = all.filter((l) => !l.deleted_at);
			deletedLocations = all.filter((l) => !!l.deleted_at);
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// ── CRUD ──
	function openNew() {
		editing = null;
		formName = '';
		formCidrs = '';
		formTrusted = false;
		formCidrError = '';
		formError = '';
		showForm = true;
	}

	function openEdit(loc: NamedLocation) {
		editing = loc;
		formName = loc.name;
		formCidrs = loc.cidrs.join('\n');
		formTrusted = loc.trusted;
		formCidrError = '';
		formError = '';
		showForm = true;
	}

	function handleCidrBlur() {
		formCidrError = validateCidrs(formCidrs);
	}

	async function save() {
		formCidrError = validateCidrs(formCidrs);
		if (formCidrError) return;

		const cidrs = formCidrs.split('\n').map((l) => l.trim()).filter(Boolean);
		const body = { name: formName, cidrs, countries: [], trusted: formTrusted };
		saving = true;
		formError = '';
		try {
			const method = editing ? 'PUT' : 'POST';
			const url = editing
				? `/admin/conditional-access/named-locations/${editing.id}`
				: '/admin/conditional-access/named-locations';
			const res = await adminFetch(url, { method, body: JSON.stringify(body) });
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				formError = (err as Record<string, string>)?.message ?? String(res.status);
				return;
			}
			const saved: NamedLocation = await res.json();
			if (editing) {
				const idx = locations.findIndex((l) => l.id === editing!.id);
				if (idx >= 0) locations[idx] = saved;
			} else {
				locations = [...locations, saved];
			}
			showForm = false;
			showToast(t('admin.conditional_access.named_location.saved_toast', { name: formName }));
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		const target = deleteTarget;
		deleting = true;
		try {
			const res = await adminFetch(`/admin/conditional-access/named-locations/${target.id}`, { method: 'DELETE' });
			if (!res.ok) throw new Error(String(res.status));
			locations = locations.filter((l) => l.id !== target.id);
			deletedLocations = [...deletedLocations, { ...target, deleted_at: new Date().toISOString() }];
			showToast(t('admin.conditional_access.named_location.deleted_toast', { name: target.name }));
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			deleting = false;
			deleteTarget = null;
		}
	}

	async function loadTrash() {
		trashLoading = true;
		try {
			const res = await adminFetch('/admin/conditional-access/named-locations?include_deleted=1');
			if (!res.ok) throw new Error(String(res.status));
			const all: NamedLocation[] = await res.json();
			deletedLocations = all.filter((l) => !!l.deleted_at);
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			trashLoading = false;
		}
	}

	async function restore(loc: NamedLocation) {
		try {
			const res = await adminFetch(`/admin/conditional-access/named-locations/${loc.id}/restore`, { method: 'POST' });
			if (!res.ok) throw new Error(String(res.status));
			const restored: NamedLocation = await res.json();
			deletedLocations = deletedLocations.filter((l) => l.id !== loc.id);
			locations = [...locations, restored];
		} catch (e) {
			listError = parseError(e).message;
		}
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.conditional_access.named_location.page_title')}</h1>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" onclick={openNew} data-testid="nl-new-btn">
				{t('admin.conditional_access.named_location.empty_cta')}
			</Button>
		</div>
	</header>

	{#if loading}
		<div aria-busy="true" data-testid="nl-loading">
			<span class="sr-only" role="status">{t('common.loading')}</span>
			<div class="nl-skeleton-rows">
				{#each [1, 2, 3] as _, i (i)}
					<div class="nl-skeleton-card"></div>
				{/each}
			</div>
		</div>
	{:else if listError}
		<div class="nl-error" role="alert" data-testid="nl-error">
			<span>{t('admin.conditional_access.named_location.load_error')}</span>
			<Button variant="secondary" size="sm" onclick={load} data-testid="nl-retry">
				{t('common.retry')}
			</Button>
		</div>
	{:else if locations.length === 0}
		<div data-testid="nl-empty">
			<EmptyState title={t('admin.conditional_access.named_location.empty')}>
				{#snippet action()}
					<Button variant="primary" size="sm" onclick={openNew} data-testid="nl-empty-cta">
						{t('admin.conditional_access.named_location.empty_cta')}
					</Button>
				{/snippet}
			</EmptyState>
		</div>
	{:else}
		<div class="nl-grid">
			{#each locations as loc (loc.id)}
				<Card>
					<div class="nl-card" data-testid="nl-card-{loc.id}">
						<div class="nl-card-head">
							<span
								class="nl-name"
								data-testid="nl-name-{loc.id}"
								title={loc.name}
							>{loc.name}</span>
							<div class="nl-badges">
								{#if loc.trusted}
									<span data-testid="nl-trusted-badge-{loc.id}">
										<Badge
											variant="success"
											label={t('admin.conditional_access.named_location.trusted_badge')}
										/>
									</span>
								{/if}
							</div>
						</div>
						<div class="nl-cidrs">
							{#each loc.cidrs as cidr}
								<span class="nl-cidr-chip">{cidr}</span>
							{/each}
						</div>
						<div class="nl-actions">
							<Button variant="ghost" size="sm" onclick={() => openEdit(loc)}>
								{t('admin.common.edit')}
							</Button>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => (deleteTarget = loc)}
								data-testid="nl-delete-btn-{loc.id}"
							>
								{t('admin.common.delete')}
							</Button>
						</div>
					</div>
				</Card>
			{/each}
		</div>
	{/if}

	<!-- Trash section -->
	{#if deletedLocations.length > 0}
		<details class="nl-trash">
			<summary
				class="nl-trash-summary"
				onclick={() => { trashVisible = !trashVisible; if (trashVisible) loadTrash(); }}
				data-testid="nl-trash-toggle"
			>
				{t('admin.conditional_access.named_location.trash_section')}
				{#if trashLoading}<Spinner size={16} />{/if}
			</summary>
			<div class="nl-trash-list">
				{#each deletedLocations as dl (dl.id)}
					<div class="nl-trash-row">
						<span class="nl-trash-name">{dl.name}</span>
						<Button
							variant="secondary"
							size="sm"
							onclick={() => restore(dl)}
							data-testid="nl-restore-btn-{dl.id}"
						>
							{t('admin.conditional_access.named_location.restore')}
						</Button>
					</div>
				{/each}
			</div>
		</details>
	{/if}
</div>

<!-- Create / Edit dialog -->
{#if showForm}
	<Dialog
		open={showForm}
		title={editing
			? t('admin.conditional_access.named_location.form_edit')
			: t('admin.conditional_access.named_location.form_new')}
		onClose={() => (showForm = false)}
	>
		{#snippet children()}
			<div class="sj-form" data-testid="nl-form-dialog">
				<Input
					label={t('admin.conditional_access.named_location.name_label')}
					value={formName}
					oninput={(e) => (formName = (e.target as HTMLInputElement).value)}
					data-testid="nl-name-input"
				/>
				<div class="sj-form-group">
					<label class="sj-form-label" for="nl-cidrs">
						{t('admin.conditional_access.named_location.cidr_label')}
					</label>
					<textarea
						id="nl-cidrs"
						class="nl-textarea"
						rows={4}
						bind:value={formCidrs}
						oninput={() => { if (formCidrError) formCidrError = validateCidrs(formCidrs); }}
						onblur={handleCidrBlur}
						data-testid="nl-cidr-input"
					></textarea>
					{#if formCidrError}
						<div class="nl-field-error" role="alert" data-testid="nl-cidr-error">
							{formCidrError}
						</div>
					{/if}
				</div>
				<label class="nl-trusted-row">
					<input type="checkbox" bind:checked={formTrusted} />
					<span>{t('admin.conditional_access.named_location.trusted_label')}</span>
				</label>
				{#if formError}
					<div class="nl-form-error" role="alert">{formError}</div>
				{/if}
			</div>
		{/snippet}
		{#snippet footer()}
			<Button variant="primary" disabled={saving} onclick={save} data-testid="nl-save-btn">
				{#if saving}<Spinner size={16} />{/if}
				{t('common.save')}
			</Button>
			<Button variant="secondary" onclick={() => (showForm = false)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- Delete confirm dialog -->
{#if deleteTarget}
	<Dialog
		open={!!deleteTarget}
		title={t('admin.conditional_access.named_location.delete_title', { name: deleteTarget.name })}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			<div data-testid="nl-delete-dialog">
				<p>{t('admin.conditional_access.named_location.delete_title', { name: deleteTarget!.name })}</p>
			</div>
		{/snippet}
		{#snippet footer()}
			<Button
				variant="primary"
				disabled={deleting}
				onclick={confirmDelete}
				data-testid="nl-delete-confirm-btn"
			>
				{#if deleting}<Spinner size={16} />{/if}
				{t('admin.common.delete')}
			</Button>
			<Button variant="secondary" onclick={() => (deleteTarget = null)}>{t('common.cancel')}</Button>
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
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-head-right { display: flex; gap: 8px; align-items: center; }

	.nl-error {
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

	.nl-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
		gap: 12px;
	}

	.nl-card {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 12px;
	}

	.nl-card-head {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}

	.nl-name {
		flex: 1;
		font-weight: var(--weight-medium);
		font-size: var(--text-sm);
		color: var(--text-primary);
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.nl-badges { display: flex; gap: 4px; flex-shrink: 0; }

	.nl-cidrs {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}

	.nl-cidr-chip {
		display: inline-block;
		padding: 2px 6px;
		border-radius: var(--radius-xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-secondary);
	}

	.nl-actions {
		display: flex;
		gap: 4px;
		margin-top: 4px;
	}

	/* Skeleton */
	.nl-skeleton-rows { display: flex; flex-direction: column; gap: 8px; }
	.nl-skeleton-card {
		height: 100px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		position: relative;
		overflow: hidden;
	}
	.nl-skeleton-card::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: nl-shimmer var(--duration-slow) ease-in-out infinite;
	}

	/* Form */
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-form-group { display: flex; flex-direction: column; gap: 5px; }
	.sj-form-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.nl-textarea {
		width: 100%;
		padding: 8px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		resize: vertical;
		box-sizing: border-box;
	}
	.nl-textarea:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.nl-field-error {
		padding: 6px 10px;
		border-radius: var(--radius-xs);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-xs);
		border: 1px solid var(--danger-solid);
	}
	.nl-form-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
	}
	.nl-trusted-row {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: var(--text-sm);
		color: var(--text-primary);
		cursor: pointer;
	}

	/* Trash */
	.nl-trash {
		margin-top: 24px;
		border-top: 1px solid var(--border-subtle);
		padding-top: 12px;
	}
	.nl-trash-summary {
		cursor: pointer;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
		display: flex;
		align-items: center;
		gap: 8px;
		list-style: none;
		padding: 4px 0;
		user-select: none;
	}
	.nl-trash-summary::-webkit-details-marker { display: none; }
	.nl-trash-list {
		margin-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.nl-trash-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
	}
	.nl-trash-name {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		text-decoration: line-through;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* sr-only: do NOT re-define; global.css owns it — ponytail: omit local definition, use global. */

	@keyframes nl-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.nl-skeleton-card::after { animation: none; }
	}

	@media (pointer: coarse) {
		.nl-trash-summary { min-height: 44px; }
		.nl-actions :global(.sj-btn) { min-height: 44px; }
	}
</style>
