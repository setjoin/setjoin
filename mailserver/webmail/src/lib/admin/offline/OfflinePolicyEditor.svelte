<!--
  OfflinePolicyEditor — CRUD list + inline form for offline_policies.
  Includes PrecedenceExplainer above the list.
  Props:
    policies  — current list (parent refetches on onSaved)
    loading   — parent is fetching the list
    error     — load error string ('' = none)
    onRetry   — retry load callback
    onSaved   — called after create/update/delete so parent refetches
-->
<svelte:options runes={true} />

<script lang="ts">
	import { t, locale } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		Card, Button, Badge, Switch, Input, Select, EmptyState,
		Spinner, Dialog, showToast
	} from '$lib/components/ui';
	import {
		adminOfflinePolicyCreate,
		adminOfflinePolicyUpdate,
		adminOfflinePolicyDelete,
		type OfflinePolicy,
		type OfflinePolicyInput
	} from '$lib/admin/client';
	import PrecedenceExplainer from './PrecedenceExplainer.svelte';
	import PrincipalPicker from '$lib/components/admin/PrincipalPicker.svelte';
	import OfflinePolicyPreview from './OfflinePolicyPreview.svelte';
	import { e5ui } from '$lib/offline/e5ui.svelte';
	import { adminFetch } from '$lib/admin/transport';

	let { policies, loading, error, master = true, onRetry, onSaved }: {
		policies: OfflinePolicy[];
		loading: boolean;
		error: string;
		master?: boolean;
		onRetry?: () => void;
		onSaved?: () => void;
	} = $props();

	$locale; // reactive on locale switch

	// ── Derived ─────────────────────────────────────────────────────────────
	// The global base layer: scope_type='global' && scope_id=null (seeded by V038)
	const basePol = $derived(
		policies.find((p) => p.scope_type === 'global' && p.scope_id === null) ?? null
	);
	const scopedPols = $derived(
		policies.filter((p) => !(p.scope_type === 'global' && p.scope_id === null))
	);
	// ── Form state ──────────────────────────────────────────────────────────
	let formOpen = $state(false);
	let editId = $state<number | null>(null);         // null = new policy
	let isBaseEdit = $state(false);                   // editing the immutable base row

	let formName = $state('');
	let formScopeType = $state('global');
	let formScopeId = $state('');
	let formEnabled = $state(true);
	let formMaxDays = $state('30');
	let formRequireApproval = $state(false);
	let formWipe = $state('admin_default');
	let formPriority = $state('0');

	let saving = $state(false);
	let saveError = $state('');

	// ── Delete dialog state ──────────────────────────────────────────────────
	let deleteTarget = $state<OfflinePolicy | null>(null);
	let deleteDialogOpen = $state(false);
	let deleting = $state(false);

	// ── Announce live region ─────────────────────────────────────────────────
	let liveMsg = $state('');

	// ── Helpers ─────────────────────────────────────────────────────────────
	function scopeLabel(p: OfflinePolicy): string {
		if (p.scope_type === 'global') return t('admin.offline.scope.global');
		const base = p.scope_type === 'group'
			? t('admin.offline.scope.group')
			: t('admin.offline.scope.user');
		return p.scope_id != null ? `${base} #${p.scope_id}` : base;
	}

	function fallbackFor(target: OfflinePolicy): string {
		const rest = [...policies]
			.filter((p) => p.id !== target.id)
			.sort((a, b) => b.priority - a.priority);
		return rest[0]?.name ?? t('admin.offline.base_layer');
	}

	function openNew() {
		editId = null;
		isBaseEdit = false;
		formName = '';
		formScopeType = 'global';
		formScopeId = '';
		formEnabled = true;
		formMaxDays = '30';
		formRequireApproval = false;
		formWipe = 'admin_default';
		formPriority = '0';
		saveError = '';
		formOpen = true;
	}

	function openEdit(p: OfflinePolicy) {
		editId = p.id;
		isBaseEdit = p.scope_type === 'global' && p.scope_id === null;
		formName = p.name;
		formScopeType = p.scope_type;
		formScopeId = p.scope_id != null ? String(p.scope_id) : '';
		formEnabled = p.enabled;
		formMaxDays = String(p.max_offline_days);
		formRequireApproval = p.require_approval;
		formWipe = p.wipe_on_logout;
		formPriority = String(p.priority);
		saveError = '';
		formOpen = true;
	}

	function closeForm() {
		formOpen = false;
		saveError = '';
	}

	async function save() {
		saving = true;
		saveError = '';
		try {
			const body: OfflinePolicyInput = {
				name: formName,
				scope_type: formScopeType as OfflinePolicyInput['scope_type'],
				scope_id: formScopeId ? Number(formScopeId) : null,
				enabled: formEnabled,
				max_offline_days: Math.max(0, parseInt(formMaxDays) || 0),
				require_approval: formRequireApproval,
				wipe_on_logout: formWipe as OfflinePolicyInput['wipe_on_logout'],
				priority: parseInt(formPriority) || 0,
			};
			if (editId !== null) {
				await adminOfflinePolicyUpdate(editId, body);
			} else {
				await adminOfflinePolicyCreate(body);
			}
			liveMsg = t('admin.offline.saved_announce', { name: formName });
			formOpen = false;
			onSaved?.();
		} catch (e) {
			saveError = t('admin.offline.save_error', { message: parseError(e).message });
		} finally {
			saving = false;
		}
	}

	function openDelete(p: OfflinePolicy) {
		deleteTarget = p;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		deleting = true;
		try {
			await adminOfflinePolicyDelete(deleteTarget.id);
			liveMsg = t('admin.offline.deleted_announce', { scope: scopeLabel(deleteTarget) });
			deleteDialogOpen = false;
			deleteTarget = null;
			onSaved?.();
		} catch (e) {
			showToast(parseError(e).message);
		} finally {
			deleting = false;
		}
	}

	// preview chip for max_offline_days
	const maxDaysNum = $derived(parseInt(formMaxDays) || 0);
	const windowPreview = $derived(
		maxDaysNum === 0
			? t('admin.offline.no_cache_label')
			: t('admin.offline.window_preview', { n: String(maxDaysNum) })
	);

	const wipeOptions = $derived([
		{ value: 'always',        label: t('admin.offline.wipe.always') },
		{ value: 'admin_default', label: t('admin.offline.wipe.admin_default') },
		{ value: 'never',         label: t('admin.offline.wipe.never') },
	]);
	const wipeHints: Record<string, string> = $derived({
		always:        t('admin.offline.wipe.always_hint'),
		admin_default: t('admin.offline.wipe.admin_default_hint'),
		never:         t('admin.offline.wipe.never_hint'),
	});

	const scopeOptions = $derived([
		{ value: 'global', label: t('admin.offline.scope.global') },
		{ value: 'group',  label: t('admin.offline.scope.group') },
		{ value: 'user',   label: t('admin.offline.scope.user') },
	]);

	// ── E5 gated server-resolved preview (R4) ────────────────────────────────
	// Renders ONLY while the connectivity-aware-sync program is active; the
	// shipped default (flag OFF / mode off) renders nothing new. The loader is
	// the E1 auth-first preview endpoint; the client never recomputes policy.
	async function loadSyncPolicyPreview(target: { targetUserId: string; deviceId: string }): Promise<unknown> {
		const res = await adminFetch('/admin/offline/policy-preview', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ targetUserId: target.targetUserId, deviceId: target.deviceId }),
		});
		if (!res.ok) {
			if (res.status === 403 || res.status === 401) throw { forbidden: true };
			throw { forbidden: false };
		}
		return res.json();
	}
</script>

<!-- Polite live-region for save/delete announcements -->
<div role="status" aria-live="polite" class="sr-only">{liveMsg}</div>

<!-- Precedence explainer above the list -->
<PrecedenceExplainer {policies} {master} />

<!-- E5 gated server-resolved preview: nothing renders while the program is OFF -->
{#if e5ui.active}
	<OfflinePolicyPreview load={loadSyncPolicyPreview} />
{/if}

<!-- Error banner -->
{#if error}
	<div role="alert" class="sj-ope__error">
		<span>{error}</span>
		{#if onRetry}
			<Button variant="secondary" size="sm" onclick={onRetry}>{t('common.retry')}</Button>
		{/if}
	</div>
{/if}

<!-- Policy list header -->
<div class="sj-ope__header">
	<span class="sj-ope__title">{t('admin.offline.tab.policies')}</span>
	<Button disabled={loading} onclick={openNew}>{t('admin.offline.policies.new')}</Button>
</div>

<!-- Loading skeletons -->
{#if loading}
	<div class="sj-ope__skeletons" aria-hidden="true">
		{#each [1, 2, 3] as _}
			<div class="sj-ope__skeleton"></div>
		{/each}
	</div>
{:else}
	<!-- Policy list -->
	<div class="sj-ope__list">
		<!-- Base layer row (always pinned first) -->
		{#if basePol}
			<div class="sj-ope__row sj-ope__row--base">
				<div class="sj-ope__row-info">
					<span class="sj-ope__row-name" title={basePol.name}>{basePol.name}</span>
					<Badge variant="neutral" label={t('admin.offline.base_layer')} />
					{#if !basePol.enabled}<Badge variant="warning" label={t('admin.offline.policy.off')} />{/if}
				</div>
				<Button variant="ghost" size="sm" onclick={() => openEdit(basePol!)}>{t('admin.common.edit')}</Button>
				<!-- ponytail: no delete button for base — deleting would strand the resolver -->
			</div>
		{/if}

		<!-- Scoped policies -->
		{#each scopedPols as pol (pol.id)}
			<div class="sj-ope__row">
				<div class="sj-ope__row-info">
					<span class="sj-ope__row-name" title={pol.name}>{pol.name}</span>
					<Badge variant="neutral" label={scopeLabel(pol)} />
					{#if !pol.enabled}<Badge variant="warning" label={t('admin.offline.policy.off')} />{/if}
				</div>
				<div class="sj-ope__row-actions">
					<Button variant="ghost" size="sm" onclick={() => openEdit(pol)}>{t('admin.common.edit')}</Button>
					<Button
						variant="ghost"
						size="sm"
						aria-label={t('admin.offline.delete.aria', { name: pol.name })}
						onclick={() => openDelete(pol)}
					>{t('admin.offline.delete.confirm')}</Button>
				</div>
			</div>
		{/each}

		<!-- Empty state (only base exists) — header already has the New policy button -->
		{#if scopedPols.length === 0}
			<EmptyState title={t('admin.offline.policies.empty')} />
		{/if}
	</div>
{/if}

<!-- Inline form panel -->
{#if formOpen}
	<div class="sj-ope__form-wrap">
		<Card title={editId === null ? t('admin.offline.policies.new') : formName}>
			<form
				class="sj-ope__form"
				onsubmit={(e) => { e.preventDefault(); save(); }}
			>
				<!-- 1. Identity row: name + scope -->
				<Input
					label={t('admin.offline.field.name')}
					bind:value={formName}
					required
					disabled={saving}
				/>

				<Select
					label={t('admin.offline.field.scope')}
					options={scopeOptions}
					bind:value={formScopeType}
					disabled={saving || isBaseEdit}
				/>

				{#if formScopeType === 'user'}
					<!-- ponytail: rung 2 — PrincipalPicker already has chips+typeahead+combobox a11y -->
					<PrincipalPicker
						kind="user"
						value={formScopeId ? [Number(formScopeId)] : []}
						onChange={(ids) => { formScopeId = ids.length > 0 ? String(ids[ids.length - 1]) : ''; }}
					/>
				{:else if formScopeType === 'group'}
					<PrincipalPicker
						kind="group"
						value={formScopeId ? [Number(formScopeId)] : []}
						onChange={(ids) => { formScopeId = ids.length > 0 ? String(ids[ids.length - 1]) : ''; }}
					/>
				{/if}

				<!-- 2. Grant row: enabled switch -->
				<div class="sj-ope__field">
					<Switch
						label={t('admin.offline.field.enabled')}
						description={t('admin.offline.enabled_caption')}
						bind:checked={formEnabled}
						disabled={saving}
					/>
				</div>

				<!-- 3. Window row: max_offline_days -->
				<div class="sj-ope__field">
					<Input
						label={t('admin.offline.field.max_days')}
						type="number"
						min="0"
						max="365"
						step="1"
						bind:value={formMaxDays}
						hint={t('admin.offline.max_days_hint')}
						disabled={saving}
					/>
					<span class="sj-ope__preview">{windowPreview}</span>
				</div>

				<!-- 4. Approval row -->
				<div class="sj-ope__field">
					<Switch
						label={t('admin.offline.field.require_approval')}
						description={t('admin.offline.require_approval_caption')}
						bind:checked={formRequireApproval}
						disabled={saving}
					/>
				</div>

				<!-- 5. Logout row: wipe_on_logout -->
				<div class="sj-ope__field">
					<Select
						label={t('admin.offline.field.wipe')}
						options={wipeOptions}
						bind:value={formWipe}
						disabled={saving}
					/>
					<p class="sj-ope__hint">{wipeHints[formWipe] ?? ''}</p>
				</div>

				<!-- 6. Priority row -->
				<Input
					label={t('admin.offline.field.priority')}
					type="number"
					min="0"
					max="9999"
					step="1"
					bind:value={formPriority}
					hint={t('admin.offline.priority_hint')}
					disabled={saving}
				/>

				<!-- Save error -->
				{#if saveError}
					<p role="alert" class="sj-ope__save-error">{saveError}</p>
				{/if}

				<div class="sj-ope__form-footer">
					<Button variant="secondary" type="button" onclick={closeForm} disabled={saving}>
						{t('common.cancel')}
					</Button>
					<Button variant="primary" type="submit" disabled={saving}>
						{#if saving}<Spinner size={16} />{/if}
						{t('admin.common.save')}
					</Button>
				</div>
			</form>
		</Card>
	</div>
{/if}

<!-- Delete confirm dialog -->
{#if deleteTarget}
	<Dialog
		open={deleteDialogOpen}
		title={t('admin.offline.delete.title')}
		onClose={() => { deleteDialogOpen = false; deleteTarget = null; }}
	>
		{#snippet children()}
			<p>
				{t('admin.offline.delete.body', {
					scope: scopeLabel(deleteTarget!),
					fallback: fallbackFor(deleteTarget!),
				})}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button
				variant="secondary"
				onclick={() => { deleteDialogOpen = false; deleteTarget = null; }}
				disabled={deleting}
			>{t('common.cancel')}</Button>
			<Button
				variant="danger"
				onclick={confirmDelete}
				disabled={deleting}
			>
				{#if deleting}<Spinner size={16} />{/if}
				{t('admin.offline.delete.confirm')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-ope__error {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 10px 14px;
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		margin-block: 8px;
	}
	.sj-ope__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 12px 0 8px;
		font-family: var(--font-sans);
	}
	.sj-ope__title {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}
	.sj-ope__skeletons {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 8px 0;
	}
	.sj-ope__skeleton {
		height: 44px;
		border-radius: var(--radius-sm);
		background: var(--surface-hover);
		animation: sj-shimmer 1.4s ease-in-out infinite;
	}

	@keyframes sj-shimmer {
		0%, 100% { opacity: 1; }
		50% { opacity: 0.45; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-ope__skeleton { animation: none; }
	}
	.sj-ope__list {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.sj-ope__row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 10px 12px;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		font-family: var(--font-sans);
	}
	.sj-ope__row--base {
		border-color: var(--accent);
		background: var(--accent-subtle);
	}
	.sj-ope__row-info {
		display: flex;
		align-items: center;
		gap: 8px;
		min-width: 0;
	}
	.sj-ope__row-name {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 200px;
	}
	.sj-ope__row-actions {
		display: flex;
		gap: 4px;
	}
	.sj-ope__form-wrap {
		margin-block-start: 12px;
	}
	.sj-ope__form {
		display: flex;
		flex-direction: column;
		gap: 14px;
		max-width: 560px;
	}
	.sj-ope__field {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.sj-ope__preview {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-sans);
	}
	.sj-ope__hint {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-sans);
	}
	.sj-ope__save-error {
		margin: 0;
		padding: 8px 10px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
		font-family: var(--font-sans);
	}
	.sj-ope__form-footer {
		display: flex;
		gap: 8px;
		justify-content: flex-end;
		padding-block-start: 4px;
	}
</style>
