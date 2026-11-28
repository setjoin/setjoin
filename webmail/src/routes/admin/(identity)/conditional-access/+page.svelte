<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { parseError } from '$lib/errors';
	import {
		Card,
		Badge,
		Button,
		Input,
		Select,
		Dialog,
		Table,
		EmptyState,
		Spinner,
		Tabs,
		showToast,
	} from '$lib/components/ui';
	import type { TableColumn, TabItem } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { t } from '$lib/i18n';
	import BreakGlassBanner from '$lib/components/admin/BreakGlassBanner.svelte';
	import BreakGlassImpactCard from '$lib/components/admin/BreakGlassImpactCard.svelte';
	import PrincipalPicker from '$lib/components/admin/PrincipalPicker.svelte';
	import SignInTrace from '$lib/components/admin/SignInTrace.svelte';
	import PromoteDialog from '$lib/components/ca/PromoteDialog.svelte';
	import ImpactCard from '$lib/components/ca/ImpactCard.svelte';
	import {
		stateLabelKey,
		stateBadgeVariant,
		saveErrorMessage,
		needsTypedConfirm,
		preflightImpact,
		promoteMode,
		type ErrorKey,
	} from './state-helpers';

	// ── Types ──
	interface Grant {
		type: string;         // 'block' | 'allow' | 'notify' | 'step_up' | 'require_acr' | 'require_strength'
		acr?: string;         // for require_acr
		strength_id?: number; // for require_strength
	}

	interface Policy {
		id: number;
		priority: number;
		name: string;
		description: string;
		state: string; // 'off' | 'report_only' | 'on'
		scope_type: string;
		scope_target: string;
		action: string;
		exclude_users: number[];
		exclude_groups: number[];
		conditions: unknown;
		actions: unknown;
		deleted_at?: string | null;
		created_at: string;
		updated_at: string;
	}

	// Grant types with enforceability
	// ponytail: inline map, not a separate file — used only here.
	const GRANT_TYPES = [
		{ value: 'block',            labelKey: 'admin.ca.grant.type.block',            http: false },
		{ value: 'allow',            labelKey: 'admin.ca.grant.type.allow',            http: false },
		{ value: 'notify',           labelKey: 'admin.ca.grant.type.notify',           http: false },
		{ value: 'step_up',          labelKey: 'admin.ca.grant.type.step_up',          http: true  },
		{ value: 'require_acr',      labelKey: 'admin.ca.grant.type.require_acr',      http: true  },
		{ value: 'require_strength', labelKey: 'admin.ca.grant.type.require_strength', http: true  },
	] as const;

	function enforceBadgeVariant(grantType: string): 'neutral' | 'warning' {
		return ['block', 'allow', 'notify'].includes(grantType) ? 'neutral' : 'warning';
	}

	function enforceBadgeLabel(grantType: string): string {
		return enforceBadgeVariant(grantType) === 'neutral'
			? t('admin.ca.grant.enforce_everywhere')
			: t('admin.ca.grant.enforce_http');
	}

	const DEFAULT_FORM = {
		name: '',
		description: '',
		state: 'off',
		scope_type: 'user',
		scope_target: '',
		action: 'block',
		exclude_users: [] as number[],
		exclude_groups: [] as number[],
		conditions: '{}',
		// grant-array shape (§6.4)
		grants: [{ type: 'block' }] as Grant[],
		grant_operator: 'all' as 'all' | 'one',
	};

	// ── Tab state (Policies / Diagnostics) ──
	let activeTab = $state('policies');
	const TABS: TabItem[] = [
		{ id: 'policies', label: t('admin.ca.tab.policies') },
		{ id: 'diagnostics', label: t('admin.ca.tab.diagnostics') },
	];

	// ── Page state ──
	let policies: Policy[] = $state([]);
	let loading = $state(true);
	let listError = $state('');

	let showForm = $state(false);
	let editing: Policy | null = $state(null);
	let form = $state({ ...DEFAULT_FORM });
	let saving = $state(false);
	let formError: string | ErrorKey | null = $state(null);

	let bgAdminIds: number[] = $state([]);
	let bgDialogOpen = $state(false);

	// Promote confirm dialog — now delegated to PromoteDialog component
	let promoteDialogOpen = $state(false);
	let promoting = $state(false);
	// Set while a CREATE save is rerouting the enable through the promotion
	// dialog (S19 hardening: no one-click enforcement, even on create).
	let creatingForPromotion = $state(false);

	// Trash section
	let deletedPolicies: Policy[] = $state([]);
	let trashLoading = $state(false);

	// Pre-flight (derived from bgAdminIds + form exclude sets)
	// adminIds/adminGroups: we use the break-glass admin set as a proxy for admins
	// (Task 9 would provide a real admin list; until then we use bg admins)
	const pfResult = $derived(
		preflightImpact({
			adminIds: bgAdminIds,
			excludeUsers: form.exclude_users,
			excludeGroups: form.exclude_groups,
			breakGlass: bgAdminIds,
			adminGroups: {},
		})
	);

	// The ENFORCED action is the head of the grant array (doSave serializes
	// grants, never the legacy scalar), so every promotion check must read the
	// same source — reading `form.action` here goes stale the moment the grant
	// editor changes the head grant type (S19 consistency hardening).
	const effectiveAction = $derived(form.grants[0]?.type ?? form.action ?? 'block');

	const currentPromoteMode = $derived(
		promoteMode(
			{ state: form.state, scope_type: form.scope_type, action: effectiveAction },
			pfResult.remaining
		)
	);

	// ── Table columns ──
	const COLUMNS: TableColumn[] = [
		{ key: 'priority', label: t('admin.ca.col.priority'), sortable: false },
		{ key: 'name', label: t('admin.ca.col.name'), sortable: false },
		{ key: 'state', label: t('admin.ca.col.state'), sortable: false },
		{ key: 'scope', label: t('admin.ca.col.scope'), sortable: false },
		{ key: 'updated', label: t('admin.common.updated'), sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	// ── Load ──
	onMount(async () => {
		await load();
	});

	async function load() {
		loading = true;
		listError = '';
		try {
			const res = await adminFetch('/admin/conditional-access/policies');
			if (!res.ok) throw new Error(String(res.status));
			policies = await res.json();
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// ── CRUD ──
	function openNew() {
		editing = null;
		form = { ...DEFAULT_FORM };
		formError = null;
		creatingForPromotion = false;
		showForm = true;
	}

	function openEdit(p: Policy) {
		editing = p;
		// ponytail: parse grant-array from actions blob if present, else derive from legacy action field.
		let grants: Grant[] = [{ type: p.action || 'block' }];
		let grant_operator: 'all' | 'one' = 'all';
		const acts = p.actions as { operator?: string; grants?: Grant[] } | null;
		if (acts && Array.isArray(acts.grants)) {
			grants = acts.grants;
			grant_operator = acts.operator === 'one' ? 'one' : 'all';
		}
		form = {
			name: p.name,
			description: p.description || '',
			state: p.state || 'off',
			scope_type: p.scope_type || 'user',
			scope_target: p.scope_target || '',
			action: p.action || 'block',
			exclude_users: p.exclude_users || [],
			exclude_groups: p.exclude_groups || [],
			conditions: JSON.stringify(p.conditions, null, 2),
			grants,
			grant_operator,
		};
		formError = null;
		showForm = true;
	}

	/** Serialize grant array into the canonical JSONB shape. */
	function serializeGrants(): { operator: string; grants: Grant[] } {
		return { operator: form.grant_operator, grants: form.grants };
	}

	async function savePolicy() {
		// Validate conditions JSON
		let parsedConditions: unknown;
		try {
			parsedConditions = JSON.parse(form.conditions);
		} catch {
			formError = t('admin.ca.error.invalid') + ' (conditions)';
			return;
		}

	// Check if type-to-confirm needed first (opens PromoteDialog instead of saving directly).
	// The promotion shape is evaluated against the grant-derived effective action,
	// and the arc applies to the CREATE path too (S19 hardening): a brand-new
	// global block/step-up policy is saved in the designed pre-enforcement state
	// ('report_only') and then routed through the SAME typed promotion dialog an
	// edit uses — never directly enforced with one click.
	const isPromotion =
		form.state === 'on' &&
		(!editing || editing.state !== 'on') &&
		needsTypedConfirm({ state: form.state, scope_type: form.scope_type, action: effectiveAction });

	if (isPromotion) {
		if (editing) {
			promoteDialogOpen = true;
			return;
		}
		form.state = 'report_only';
		creatingForPromotion = true;
		await doSave(parsedConditions);
		return;
	}

	await doSave(parsedConditions);
}

	async function doSave(parsedConditions?: unknown, skipToast = false) {
		// Re-parse conditions if not provided (from promote confirm path)
		let conds = parsedConditions;
		if (conds === undefined) {
			try { conds = JSON.parse(form.conditions); } catch { formError = t('admin.ca.error.invalid') + ' (conditions)'; return; }
		}

		const body = {
			name: form.name,
			description: form.description,
			state: form.state,
			scope_type: form.scope_type,
			scope_target: form.scope_target,
			action: form.grants[0]?.type ?? 'block',
			exclude_users: form.exclude_users,
			exclude_groups: form.exclude_groups,
			conditions: conds,
			actions: serializeGrants(),
		};

		saving = true;
		formError = null;
		try {
			const method = editing ? 'PUT' : 'POST';
			const url = editing
				? `/admin/conditional-access/policies/${editing.id}`
				: '/admin/conditional-access/policies';
			const res = await adminFetch(url, {
				method,
				body: JSON.stringify(body),
			});
			if (!res.ok) {
				let detail = '';
				try {
					const errData = await res.json();
					detail = errData?.hint ?? errData?.detail ?? errData?.message ?? '';
				} catch { /* ignore */ }
				formError = saveErrorMessage(res.status, detail);
				creatingForPromotion = false;
				// Also flip the impact card red if it's a 409 (handled visually by the card via state)
				return;
			}
			const policy: Policy = await res.json();
			if (editing) {
				const idx = policies.findIndex((p) => p.id === editing!.id);
				if (idx >= 0) policies[idx] = policy;
			} else {
				policies = [...policies, policy];
			}
			if (creatingForPromotion) {
				// S19 create-path hardening: the policy exists now (saved
				// report_only); hand it to the typed promotion dialog. The form
				// stays open behind the dialog so a cancel leaves the admin on a
				// coherent "editing a report-only policy" view.
				creatingForPromotion = false;
				editing = policy;
				promoteDialogOpen = true;
				if (!skipToast) showToast(t('admin.ca.saved_toast', { name: form.name }));
				return;
			}
			showForm = false;
			promoteDialogOpen = false;
			if (!skipToast) showToast(t('admin.ca.saved_toast', { name: form.name }));
		} catch (e) {
			formError = parseError(e).message;
			creatingForPromotion = false;
		} finally {
			saving = false;
		}
	}

	async function deletePolicy(p: Policy) {
		const prev = policies;
		policies = policies.filter((x) => x.id !== p.id);
		try {
			const res = await adminFetch(`/admin/conditional-access/policies/${p.id}`, {
				method: 'DELETE',
			});
			if (!res.ok) throw new Error(String(res.status));
			deletedPolicies = [...deletedPolicies, { ...p, deleted_at: new Date().toISOString() }];
			showToast(t('admin.ca.trash.deleted_toast', { name: p.name }), {
				actionLabel: t('admin.ca.trash.undo'),
				onAction: () => restorePolicy(p),
			});
		} catch (e) {
			policies = prev;
			listError = parseError(e).message;
		}
	}

	async function restorePolicy(p: Policy) {
		try {
			const res = await adminFetch(`/admin/conditional-access/policies/${p.id}/restore`, {
				method: 'POST',
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				if (res.status === 409) {
					listError = t('admin.ca.trash.restore_conflict');
				} else {
					listError = err?.message ?? String(res.status);
				}
				return;
			}
			const restored: Policy = await res.json();
			deletedPolicies = deletedPolicies.filter((x) => x.id !== p.id);
			policies = [...policies, restored];
			showToast(t('admin.ca.trash.deleted_toast', { name: p.name }));
		} catch (e) {
			listError = parseError(e).message;
		}
	}

	async function loadDeleted() {
		trashLoading = true;
		try {
			const res = await adminFetch('/admin/conditional-access/policies?include_deleted=1');
			if (!res.ok) throw new Error(String(res.status));
			const all: Policy[] = await res.json();
			deletedPolicies = all.filter((p) => p.deleted_at);
		} catch (e) {
			listError = parseError(e).message;
		} finally {
			trashLoading = false;
		}
	}

	async function reorder(from: number, to: number) {
		if (to < 0 || to >= policies.length) return;
		const prevIds = policies.map((p) => p.id);
		const newIds = [...prevIds];
		[newIds[from], newIds[to]] = [newIds[to], newIds[from]];
		const reordered = [...policies];
		[reordered[from], reordered[to]] = [reordered[to], reordered[from]];
		policies = reordered;
		try {
			const res = await adminFetch('/admin/conditional-access/policies/reorder', {
				method: 'POST',
				body: JSON.stringify(newIds), // raw []int64 array as the Go handler expects
			});
			if (!res.ok) throw new Error(String(res.status));
		} catch (e) {
			// Restore on error
			policies = prevIds.map((id) => policies.find((p) => p.id === id)!).filter(Boolean);
			listError = parseError(e).message;
		}
	}

	// ── Promote confirm — called by PromoteDialog on confirmed arc ──
	async function handlePromoteEnforced() {
		// PromoteDialog calls the D3 promote endpoint itself; on success it fires onEnforced.
		// We just update the policy in the list.
		promoteDialogOpen = false;
		showForm = false;
		await load();
		showToast(t('admin.ca.promoted_toast', { policy: form.name }));
	}

	// ── Break-glass banner callbacks ──
	function handleBgSet() {
		bgDialogOpen = true;
	}

	function handleBgEdit() {
		bgDialogOpen = true;
	}

	// ── Error rendering helper ──
	function renderFormError(err: string | ErrorKey | null): string {
		if (!err) return '';
		if (typeof err === 'string') return err;
		return t(err.key, err.params as Record<string, string> | undefined);
	}
</script>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.ca.page.title')}</h1>
		</div>
		<div class="sj-page-head-right">
			<Button variant="primary" size="sm" onclick={openNew}>{t('admin.ca.list.empty_cta')}</Button>
		</div>
	</header>

	<!-- Step-zero break-glass banner (always shown) -->
	<BreakGlassBanner
		onSetBg={handleBgSet}
		onEditBg={handleBgEdit}
		onAdminIds={(ids) => (bgAdminIds = ids)}
	/>

	<!-- Tab strip: Policies / Diagnostics -->
	<Tabs items={TABS} active={activeTab} onChange={(id) => (activeTab = id)} />

	<!-- DX navigation tiles: quick access to F3 sub-surfaces — §brief (impact card + DX tiles) -->
	<nav class="ca-dx-tiles" aria-label={t('admin.ca.page.title')}>
		<a class="ca-dx-tile" href="/admin/conditional-access/simulate">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.simulate.run')}</span>
		</a>
		<a class="ca-dx-tile" href="/admin/conditional-access/coverage">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.coverage.gaps_heading')} &amp; {t('admin.conditional_access.coverage.shadowed_heading')}</span>
		</a>
		<a class="ca-dx-tile" href="/admin/conditional-access/why">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.why.page_title')}</span>
		</a>
		<a class="ca-dx-tile" href="/admin/conditional-access/named-locations">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.named_location.page_title')}</span>
		</a>
		<a class="ca-dx-tile" href="/admin/conditional-access/auth-strengths">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.auth_strength.page_title')}</span>
		</a>
		<a class="ca-dx-tile" href="/admin/conditional-access/templates">
			<span class="ca-dx-tile__label">{t('admin.conditional_access.wizard.page_title')}</span>
		</a>
	</nav>

	<!-- Diagnostics tab: sign-in trace pane -->
	{#if activeTab === 'diagnostics'}
		<SignInTrace />
	{/if}

	<!-- List area (Policies tab) -->
	{#if activeTab === 'policies'}
	{#if loading}
		<div aria-busy="true" aria-label={t('admin.ca.list.loading')}>
			<span class="sr-only" role="status">{t('admin.ca.list.loading')}</span>
			<div class="sj-skeleton-rows">
				{#each [1, 2, 3] as _, i (i)}
					<div class="sj-skeleton-row"></div>
				{/each}
			</div>
		</div>
	{:else if listError}
		<div class="sj-list-error" role="alert" data-testid="list-error">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
				<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
				<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
			</svg>
			<span>{t('admin.ca.list.load_error')}</span>
			<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
		</div>
	{:else if policies.length === 0}
		<EmptyState title={t('admin.ca.list.empty_title')}>
			{#snippet action()}
				<div class="sj-empty-body">
					<p>{t('admin.ca.list.empty_body')}</p>
					<Button variant="primary" size="sm" onclick={openNew}>{t('admin.ca.list.empty_cta')}</Button>
				</div>
			{/snippet}
		</EmptyState>
	{:else}
		<Card flush={true}>
			{@const rows = policies as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const p = row as unknown as Policy}
					{@const i = policies.findIndex((x) => x.id === p.id)}
					{#if col.key === 'priority'}{p.priority}
					{:else if col.key === 'name'}
						<Button variant="ghost" size="sm" onclick={() => openEdit(p)}>{p.name}</Button>
					{:else if col.key === 'state'}
						<span data-testid="ca-state-badge">
							<Badge
								variant={stateBadgeVariant(p.state)}
								label={t(stateLabelKey(p.state))}
							/>
						</span>
					{:else if col.key === 'scope'}
						{p.scope_type}:{p.scope_target || '*'}
					{:else if col.key === 'updated'}
						<span class="sj-muted">{p.updated_at}</span>
					{:else if col.key === 'actions'}
						<div class="sj-actions">
							<Button variant="ghost" size="sm" onclick={() => reorder(i, i - 1)} disabled={i === 0}>{t('admin.ca.col.move_up')}</Button>
							<Button variant="ghost" size="sm" onclick={() => reorder(i, i + 1)} disabled={i >= policies.length - 1}>{t('admin.ca.col.move_down')}</Button>
							<Button variant="ghost" size="sm" onclick={() => deletePolicy(p)}>{t('admin.common.delete')}</Button>
						</div>
					{/if}
				{/snippet}
			</Table>
		</Card>
	{/if}

	<!-- Trash section — collapsible, loads on expand (D2 soft-delete) -->
	{#if activeTab === 'policies' && deletedPolicies.length > 0}
		<details class="ca-trash-section" data-testid="trash-section">
			<summary class="ca-trash-summary" onclick={loadDeleted}>
				{t('admin.ca.trash.section_title')}
				{#if trashLoading}<Spinner size={16} />{/if}
			</summary>
			<div class="ca-trash-list">
				{#each deletedPolicies as dp (dp.id)}
					<div class="ca-trash-row" data-testid="trash-row">
						<span class="ca-trash-name">{dp.name}</span>
						<Badge variant="neutral" label={t('admin.ca.state.off')} />
						<Button
							variant="secondary"
							size="sm"
							onclick={() => restorePolicy(dp)}
							data-testid="trash-restore-btn"
						>
							{t('admin.ca.trash.restore')}
						</Button>
					</div>
				{/each}
			</div>
		</details>
	{/if}
	{/if}

	<!-- Policy form dialog -->
	{#if showForm}
		<Dialog
			open={showForm}
			title={editing ? t('admin.ca.form.edit_title') : t('admin.ca.form.new_title')}
			wide={true}
			onClose={() => (showForm = false)}
		>
			{#snippet children()}
				<div class="sj-form">
					<Input
						label={t('admin.common.edit') + ' — ' + t('admin.ca.col.name')}
						value={form.name}
						oninput={(e) => (form.name = (e.target as HTMLInputElement).value)}
						placeholder={t('admin.ca.form.name_placeholder')}
					/>
					<Input
						label={t('admin.table.detail')}
						value={form.description}
						oninput={(e) => (form.description = (e.target as HTMLInputElement).value)}
						placeholder={t('admin.ca.form.description_placeholder')}
					/>

					<!-- Tri-state enforcement state Select -->
					<Select
						label={t('admin.ca.field.state')}
						value={form.state}
						options={[
							{ value: 'off', label: t('admin.ca.state.off') },
							{ value: 'report_only', label: t('admin.ca.state.report_only') },
							{ value: 'on', label: t('admin.ca.state.on') },
						]}
						onchange={(e) => (form.state = (e.target as HTMLSelectElement).value)}
					/>
					<p class="sj-field-hint">{t('admin.ca.state.help')}</p>

					<!-- Scope + target -->
					<div class="sj-form-row">
						<div class="sj-form-col">
							<Select
								label={t('admin.ca.col.scope')}
								value={form.scope_type}
								onchange={(e) => {
									form.scope_type = (e.target as HTMLSelectElement).value;
									if (form.scope_type === 'global' || form.scope_type === 'guests') form.scope_target = '';
								}}
							>
								{#snippet children()}
									<option value="user">{t('admin.ca.scope.user')}</option>
									<option value="group">{t('admin.ca.scope.group')}</option>
									<option value="role">{t('admin.ca.scope.role')}</option>
									<option value="guests">{t('admin.ca.scope.guests')}</option>
									<option value="global">{t('admin.ca.scope.global')}</option>
								{/snippet}
							</Select>
						</div>
						<div class="sj-form-col">
							<Input
								label={t('admin.ca.form.target_label')}
								value={form.scope_target}
								oninput={(e) => (form.scope_target = (e.target as HTMLInputElement).value)}
								placeholder={t('admin.ca.form.target_placeholder')}
								disabled={form.scope_type === 'global' || form.scope_type === 'guests'}
							/>
						</div>
					</div>

					<!-- Grant-array builder (§6.4) — operator + grant rows with enforceability badge -->
					<div class="sj-form-group">
						<span class="sj-form-label">{t('admin.ca.grant.operator_label')}</span>
						<div class="ca-grant-operator">
							<Select
								label=""
								value={form.grant_operator}
								onchange={(e) => (form.grant_operator = (e.target as HTMLSelectElement).value as 'all' | 'one')}
							>
								{#snippet children()}
									<option value="all">{t('admin.ca.grant.all')}</option>
									<option value="one">{t('admin.ca.grant.one')}</option>
								{/snippet}
							</Select>
						</div>
						{#each form.grants as g, gi (gi)}
							<div class="ca-grant-row">
								<Select
									label={t('admin.ca.grant.type_label')}
									value={g.type}
									onchange={(e) => { form.grants = form.grants.map((x, j) => j === gi ? { ...x, type: (e.target as HTMLSelectElement).value } : x); }}
								>
									{#snippet children()}
										{#each GRANT_TYPES as gt (gt.value)}
											<option value={gt.value}>{t(gt.labelKey)}</option>
										{/each}
									{/snippet}
								</Select>
								<Badge
									variant={enforceBadgeVariant(g.type)}
									label={enforceBadgeLabel(g.type)}
								/>
								{#if form.grants.length > 1}
									<Button variant="ghost" size="sm" onclick={() => { form.grants = form.grants.filter((_, j) => j !== gi); }}>
										{t('admin.ca.grant.remove')}
									</Button>
								{/if}
							</div>
						{/each}
						<Button variant="secondary" size="sm" onclick={() => { form.grants = [...form.grants, { type: 'notify' }]; }}>
							{t('admin.ca.grant.add')}
						</Button>
					</div>

					<!-- Resolved exclude user picker -->
					<div class="sj-form-group">
						<span class="sj-form-label" aria-hidden="true">{t('admin.ca.field.exclude_users')}</span>
						<PrincipalPicker
							kind="user"
							value={form.exclude_users}
							onChange={(ids) => (form.exclude_users = ids)}
						/>
					</div>

					<!-- Resolved exclude group picker -->
					<div class="sj-form-group">
						<span class="sj-form-label" aria-hidden="true">{t('admin.ca.field.exclude_groups')}</span>
						<PrincipalPicker
							kind="group"
							value={form.exclude_groups}
							onChange={(ids) => (form.exclude_groups = ids)}
						/>
					</div>

					<!-- Pre-flight impact card -->
					<BreakGlassImpactCard
						state={form.state}
						scopeType={form.scope_type}
						action={form.action}
						remaining={pfResult.remaining}
						loading={bgAdminIds.length === 0 && (form.exclude_users.length > 0 || form.exclude_groups.length > 0)}
						excludeUserIds={form.exclude_users}
					/>

					<!-- Historical sign-in impact (F1 ImpactCard) — only when editing an existing policy -->
					{#if editing}
						<ImpactCard policyId={editing.id} fetchData />
					{/if}

					<!-- Conditions (JSON) — actions now use the grant-array builder above -->
					<div class="sj-form-group">
						<label class="sj-form-label" for="ca-conditions">{t('admin.ca.form.conditions')}</label>
						<textarea
							id="ca-conditions"
							class="sj-textarea"
							rows={4}
							bind:value={form.conditions}
						></textarea>
					</div>

					<!-- Inline error area (409 HINT surfaced here) -->
					{#if formError}
						<div class="sj-form-error" role="alert" data-testid="form-error">
							{renderFormError(formError)}
						</div>
					{/if}
				</div>
			{/snippet}
			{#snippet footer()}
				<Button
					variant="primary"
					disabled={saving}
					onclick={savePolicy}
				>
					{#if saving}<Spinner size={16} />{/if}
					{t('common.save')}
				</Button>
				<Button variant="secondary" onclick={() => (showForm = false)}>{t('common.cancel')}</Button>
			{/snippet}
		</Dialog>
	{/if}

	<!-- Promote confirm dialog — T3 three-arc component (F1) -->
	{#if promoteDialogOpen && editing}
		<PromoteDialog
			open={promoteDialogOpen}
			policyId={editing.id}
			policyName={editing.name}
			onClose={() => (promoteDialogOpen = false)}
			onEnforced={handlePromoteEnforced}
		/>
	{/if}

	<!-- Break-glass set/edit dialog (placeholder — wired to Task 9 backend) -->
	{#if bgDialogOpen}
		<Dialog
			open={bgDialogOpen}
			title={t('admin.ca.bg.set_cta')}
			onClose={() => (bgDialogOpen = false)}
		>
			{#snippet children()}
				<div class="sj-bg-picker">
					<PrincipalPicker
						kind="user"
						value={bgAdminIds}
						onChange={(ids) => (bgAdminIds = ids)}
					/>
				</div>
			{/snippet}
			{#snippet footer()}
				<Button variant="primary" onclick={() => (bgDialogOpen = false)}>{t('common.save')}</Button>
				<Button variant="secondary" onclick={() => (bgDialogOpen = false)}>{t('common.cancel')}</Button>
			{/snippet}
		</Dialog>
	{/if}
</div>

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

	.sj-muted { color: var(--text-tertiary); font-size: var(--text-xs); }
	.sj-actions { display: flex; gap: 4px; }
	.sj-form { display: flex; flex-direction: column; gap: 12px; }
	.sj-form-row { display: flex; gap: 12px; }
	.sj-form-col { flex: 1; }
	.sj-form-group { display: flex; flex-direction: column; gap: 5px; }
	.sj-form-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-field-hint {
		margin: -6px 0 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.sj-textarea {
		width: 100%;
		padding: 8px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		resize: vertical;
	}
	.sj-textarea:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-form-error {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
	}

	/* List loading skeleton */
	.sj-skeleton-rows { display: flex; flex-direction: column; gap: 8px; margin-bottom: 8px; }
	.sj-skeleton-row {
		height: 36px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		position: relative;
		overflow: hidden;
	}
	.sj-skeleton-row::after {
		content: '';
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: sj-shimmer var(--duration-slow) ease-in-out infinite;
	}

	/* List error */
	.sj-list-error {
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

	/* Empty state body */
	.sj-empty-body {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	/* Break-glass picker in dialog */
	.sj-bg-picker { min-height: 80px; }

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	@keyframes sj-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-skeleton-row::after {
			animation: none;
		}
	}

	/* DX navigation tiles: quick-access to simulate/coverage/why sub-surfaces */
	.ca-dx-tiles {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
		margin: 12px 0 16px;
	}
	.ca-dx-tile {
		display: flex;
		align-items: center;
		padding: 8px 14px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		text-decoration: none;
		transition: background var(--duration-base) var(--ease-out);
	}
	.ca-dx-tile:hover { background: var(--surface-hover); }
	.ca-dx-tile:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.ca-dx-tile__label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}

	@media (pointer: coarse) {
		.ca-dx-tile { min-height: 44px; }
	}

	@media (prefers-reduced-motion: reduce) {
		.ca-dx-tile { transition: none; }
	}

	/* Grant-array builder */
	.ca-grant-operator { max-width: 160px; margin-bottom: 8px; }
	.ca-grant-row {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
		margin-bottom: 8px;
	}

	/* Trash section */
	.ca-trash-section {
		margin-top: 24px;
		border-top: 1px solid var(--border-subtle);
		padding-top: 12px;
	}
	.ca-trash-summary {
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
	.ca-trash-summary::-webkit-details-marker { display: none; }
	.ca-trash-list {
		margin-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.ca-trash-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
	}
	.ca-trash-name {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		text-decoration: line-through;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	@media (pointer: coarse) {
		.ca-trash-summary { min-height: 44px; }
	}
</style>
