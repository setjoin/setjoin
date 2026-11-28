<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import { Card, Badge, Button, Input, Select, Dialog, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import AuthStrengthMatrix from './AuthStrengthMatrix.svelte';

	// ── Types ──
	interface AuthStrength {
		id: number;
		name: string;
		builtin: boolean;
		min_acr: string;
		combinations: string[][];
		deleted_at?: string | null;
	}

	// ── State ──
	let strengths: AuthStrength[] = $state([]);
	let loading = $state(true);
	let listError = $state('');

	let showForm = $state(false);
	let editing: AuthStrength | null = $state(null);
	let formName = $state('');
	let formMinAcr = $state('aal1');
	let formCombinations: string[][] = $state([[]]);
	let showMatrixValidation = $state(false);
	let saving = $state(false);
	let formError = $state('');

	// Delete confirm (T2: type-to-confirm "DELETE")
	let deleteTarget: AuthStrength | null = $state(null);
	let deleteTypeInput = $state('');
	let deleting = $state(false);

	const deleteConfirmEnabled = $derived(deleteTypeInput === 'DELETE');

	// ── Load ──
	onMount(load);

	async function load() {
		loading = true;
		listError = '';
		try {
			const res = await adminFetch('/admin/conditional-access/auth-strengths-list');
			if (!res.ok) throw new Error(String(res.status));
			strengths = await res.json();
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
		formMinAcr = 'aal1';
		formCombinations = [[]];
		showMatrixValidation = false;
		formError = '';
		showForm = true;
	}

	function openEdit(s: AuthStrength) {
		if (s.builtin) return; // built-ins are read-only
		editing = s;
		formName = s.name;
		formMinAcr = s.min_acr;
		formCombinations = s.combinations.map((r) => [...r]);
		showMatrixValidation = false;
		formError = '';
		showForm = true;
	}

	async function save() {
		// validate: must have at least one non-empty combination
		const valid = formCombinations.some((r) => r.length > 0);
		if (!valid) {
			showMatrixValidation = true;
			return;
		}

		const body = { name: formName, min_acr: formMinAcr, combinations: formCombinations };
		saving = true;
		formError = '';
		try {
			const method = editing ? 'PUT' : 'POST';
			const url = editing
				? `/admin/conditional-access/auth-strengths/${editing.id}`
				: '/admin/conditional-access/auth-strengths';
			const res = await adminFetch(url, { method, body: JSON.stringify(body) });
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				formError = (err as Record<string, string>)?.message ?? String(res.status);
				return;
			}
			const saved: AuthStrength = await res.json();
			if (editing) {
				const idx = strengths.findIndex((s) => s.id === editing!.id);
				if (idx >= 0) strengths[idx] = saved;
			} else {
				strengths = [...strengths, saved];
			}
			showForm = false;
			showToast(t('admin.conditional_access.auth_strength.saved_toast', { name: formName }));
		} catch (e) {
			formError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function confirmDelete() {
		if (!deleteTarget || !deleteConfirmEnabled) return;
		const target = deleteTarget;
		deleting = true;
		try {
			const res = await adminFetch(`/admin/conditional-access/auth-strengths/${target.id}`, { method: 'DELETE' });
			if (!res.ok) throw new Error(String(res.status));
			strengths = strengths.filter((s) => s.id !== target.id);
			showToast(t('admin.conditional_access.auth_strength.deleted_toast', { name: target.name }));
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			deleting = false;
			deleteTarget = null;
			deleteTypeInput = '';
		}
	}

	const ACR_OPTIONS = [
		{ value: 'aal1', label: 'AAL1' },
		{ value: 'aal2', label: 'AAL2' },
		{ value: 'aal3', label: 'AAL3' },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.conditional_access.auth_strength.page_title')}</h1>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" onclick={openNew} data-testid="as-new-btn">
				{t('admin.conditional_access.auth_strength.empty_cta')}
			</Button>
		</div>
	</header>

	{#if loading}
		<div aria-busy="true" data-testid="as-loading">
			<span class="sr-only" role="status">{t('common.loading')}</span>
			<div class="as-skeleton-rows">
				{#each [1, 2, 3] as _, i (i)}
					<div class="as-skeleton-card"></div>
				{/each}
			</div>
		</div>
	{:else if listError}
		<div class="as-error" role="alert" data-testid="as-error">
			<span>{t('admin.conditional_access.auth_strength.load_error')}</span>
			<Button variant="secondary" size="sm" onclick={load} data-testid="as-retry">
				{t('common.retry')}
			</Button>
		</div>
	{:else if strengths.length === 0}
		<div data-testid="as-empty">
			<EmptyState title={t('admin.conditional_access.auth_strength.empty')}>
				{#snippet action()}
					<Button variant="primary" size="sm" onclick={openNew} data-testid="as-empty-cta">
						{t('admin.conditional_access.auth_strength.empty_cta')}
					</Button>
				{/snippet}
			</EmptyState>
		</div>
	{:else}
		<div class="as-grid">
			{#each strengths as s (s.id)}
				<Card>
					<div class="as-card" data-testid="as-card-{s.id}">
						<div class="as-card-head">
							<span
								class="as-name"
								data-testid="as-name-{s.id}"
								title={s.name}
							>{s.name}</span>
							<div class="as-badges">
								{#if s.builtin}
									<span data-testid="as-builtin-badge-{s.id}">
										<Badge
											variant="info"
											label={t('admin.conditional_access.auth_strength.builtin_badge')}
										/>
									</span>
								{/if}
							</div>
						</div>
						<div class="as-combos">
							{#each s.combinations as combo, ci}
								{#if ci > 0}<span class="as-or-sep">OR</span>{/if}
								<span class="as-combo-chip">{combo.join(' + ') || '—'}</span>
							{/each}
						</div>
						<div class="as-actions">
							{#if !s.builtin}
								<Button variant="ghost" size="sm" onclick={() => openEdit(s)}>
									{t('admin.common.edit')}
								</Button>
								<Button
									variant="ghost"
									size="sm"
									onclick={() => { deleteTarget = s; deleteTypeInput = ''; }}
									data-testid="as-delete-btn-{s.id}"
								>
									{t('admin.common.delete')}
								</Button>
							{/if}
						</div>
					</div>
				</Card>
			{/each}
		</div>
	{/if}
</div>

<!-- Create / Edit dialog -->
{#if showForm}
	<Dialog
		open={showForm}
		title={editing
			? t('admin.conditional_access.auth_strength.form_edit')
			: t('admin.conditional_access.auth_strength.form_new')}
		wide={true}
		onClose={() => (showForm = false)}
	>
		{#snippet children()}
			<div class="sj-form">
				<Input
					label={t('admin.conditional_access.auth_strength.name_label')}
					value={formName}
					oninput={(e) => (formName = (e.target as HTMLInputElement).value)}
				/>
				<Select
					label={t('admin.conditional_access.auth_strength.min_acr_label')}
					value={formMinAcr}
					options={ACR_OPTIONS}
					onchange={(e) => (formMinAcr = (e.target as HTMLSelectElement).value)}
				/>
				<div class="sj-form-group">
					<span class="sj-form-label">Factor combinations</span>
					<AuthStrengthMatrix
						combinations={formCombinations}
						onChange={(v) => (formCombinations = v)}
						showValidation={showMatrixValidation}
					/>
				</div>
				{#if formError}
					<div class="as-form-error" role="alert">{formError}</div>
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

<!-- Delete confirm dialog (T2: type DELETE) -->
{#if deleteTarget}
	<Dialog
		open={!!deleteTarget}
		title={t('admin.conditional_access.auth_strength.delete_title', { name: deleteTarget.name })}
		onClose={() => { deleteTarget = null; deleteTypeInput = ''; }}
	>
		{#snippet children()}
			<div class="as-delete-body" data-testid="as-delete-dialog">
				<p class="as-delete-blast">
					{t('admin.conditional_access.auth_strength.delete_body')}
				</p>
				<div class="sj-form-group">
					<label class="sj-form-label" for="as-delete-type">
						Type <strong>DELETE</strong> to confirm
					</label>
					<input
						id="as-delete-type"
						type="text"
						class="as-type-input"
						bind:value={deleteTypeInput}
						autocomplete="off"
						data-testid="as-delete-type-input"
					/>
				</div>
			</div>
		{/snippet}
		{#snippet footer()}
			<Button
				variant="primary"
				disabled={!deleteConfirmEnabled || deleting}
				onclick={confirmDelete}
				data-testid="as-delete-confirm-btn"
			>
				{#if deleting}<Spinner size={16} />{/if}
				{t('admin.conditional_access.auth_strength.delete_token')}
			</Button>
			<Button variant="secondary" onclick={() => { deleteTarget = null; deleteTypeInput = ''; }}>
				{t('common.cancel')}
			</Button>
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

	.as-error {
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

	.as-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
		gap: 12px;
	}

	.as-card {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 12px;
	}

	.as-card-head {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}

	.as-name {
		flex: 1;
		font-weight: var(--weight-medium);
		font-size: var(--text-sm);
		color: var(--text-primary);
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.as-badges { display: flex; gap: 4px; flex-shrink: 0; }

	.as-combos {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 4px;
		min-height: 24px;
	}

	.as-combo-chip {
		display: inline-block;
		padding: 2px 8px;
		border-radius: var(--radius-xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		font-size: var(--text-2xs);
		font-family: var(--font-mono);
		color: var(--text-secondary);
	}

	.as-or-sep {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		font-weight: var(--weight-medium);
	}

	.as-actions {
		display: flex;
		gap: 4px;
		margin-top: 4px;
	}

	/* Skeleton */
	.as-skeleton-rows { display: flex; flex-direction: column; gap: 8px; }
	.as-skeleton-card {
		height: 100px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		position: relative;
		overflow: hidden;
	}
	.as-skeleton-card::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: as-shimmer var(--duration-slow) ease-in-out infinite;
	}

	/* Form */
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-form-group { display: flex; flex-direction: column; gap: 5px; }
	.sj-form-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.as-form-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
	}

	/* Delete dialog */
	.as-delete-body { display: flex; flex-direction: column; gap: 12px; }
	.as-delete-blast {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.as-type-input {
		padding: 8px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		width: 100%;
		box-sizing: border-box;
	}
	.as-type-input:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	@keyframes as-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.as-skeleton-card::after { animation: none; }
	}

	@media (pointer: coarse) {
		.as-actions :global(.sj-btn) { min-height: 44px; }
	}
</style>
