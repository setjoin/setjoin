<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Table, Dialog, Button, Select, Input, Badge, EmptyState, Spinner, showToast, Tooltip } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import { adminGetRole, adminAssignMember, adminRemoveMember, type RoleMember } from '$lib/admin/roles';
	import { sodMode } from '$lib/stores/session';
	import { isExpiringSoon } from '$lib/rbac/memberExpiry';
	import { adminUserList, adminDeptTree, bulkAssignRole, bulkRevokeRole, getBulkRoleJob, getAuditPolicy, adminListScopeSets, adminGetScopeSet, adminFeatureList, type AdminUser, type BulkRoleJob, type ScopeSet, type ScopeSetMember } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import ReasonPrompt from './ReasonPrompt.svelte';
	import DepartmentTreePicker from './DepartmentTreePicker.svelte';
	import RoleActivationPolicyEditor from './RoleActivationPolicyEditor.svelte';

	let { roleId = 0, domains = [], canEdit = false }:
		{ roleId?: number; domains?: { id: number; name: string }[]; canEdit?: boolean } = $props();

	let members = $state<RoleMember[]>([]);
	let roleSodClass = $state<string | null>(null);
	let loading = $state(true);
	let error = $state('');
	let showAssign = $state(false);
	let removeTarget = $state<RoleMember | null>(null);
	let userQuery = $state('');
	let userResults = $state<AdminUser[]>([]);
	let pickedUserStr = $state('');
	let domainOverrideStr = $state('');
	let expiresAt = $state('');
	// ── Scope picker for single-assign: Whole org / One department / A scope-set ──
	let scopeMode = $state<'whole' | 'ou' | 'set'>('whole');
	let ouScope = $state<{ scopeType: 'ou'; scopeId: number } | null>(null);
	let setScopeIdStr = $state('');
	let scopeSets = $state<ScopeSet[]>([]);
	let setMembers = $state<ScopeSetMember[]>([]);
	// ponytail: flat dept id→name lookup for scope column labels; populated once on mount
	let deptMap = $state<Map<number, string>>(new Map());
	let deptFetchFailed = $state(false);

	// ── Audit policy: reason-required gate ──
	// ponytail: fetched once on mount; false = no prompt (default policy)
	let rolesReasonRequired = $state(false);

	// ── JIT grant type (decision 14): when rbac.jit is on, the assign control
	// offers Active (standing) vs Eligible (JIT). Off → hidden, everything standing.
	let jitEnabled = $state(false);
	let grantMode = $state<'standing' | 'eligible'>('standing');

	// ── Bulk selection (remove) ──
	let selectedIds = $state(new Set<number>());
	let showBulkRevoke = $state(false);

	// ── Bulk add picker ──
	let showBulkAdd = $state(false);
	let bulkQuery = $state('');
	let bulkUserResults = $state<AdminUser[]>([]);
	let bulkSelectedIds = $state(new Set<number>());
	let bulkExpiresAt = $state('');
	let bulkReason = $state('');
	// ── OU scope picker for bulk-assign (mirrors single-assign; null = whole domain) ──
	let bulkScope = $state<{ scopeType: 'ou'; scopeId: number } | null>(null);

	// ── Bulk job polling ──
	type BulkReport = { job: BulkRoleJob } | null;
	let bulkReport = $state<BulkReport>(null);
	let bulkPending = $state(false);
	let _pollIv: ReturnType<typeof setInterval> | null = null;
	onDestroy(() => { if (_pollIv !== null) clearInterval(_pollIv); });

	const COLUMNS: TableColumn[] = [
		{ key: 'select', label: '' },
		{ key: 'member', label: t('admin.roles.member') },
		{ key: 'scope', label: t('admin.roles.scope') },
		{ key: 'expires', label: t('admin.roles.expires') },
		{ key: 'actions', label: '' },
	];

	onMount(async () => {
		// ponytail: fire all three in parallel; audit policy + dept tree failures are non-fatal
		void getAuditPolicy().then((p) => {
			rolesReasonRequired = p.reasonRequiredAreas.includes('roles');
		}).catch(() => { /* non-fatal: default = no prompt */ });
		void adminDeptTree().then((nodes) => {
			// ponytail: flatten tree to id→name for scope-column lookup
			const map = new Map<number, string>();
			function walk(ns: typeof nodes) {
				for (const n of ns) { map.set(n.id, n.name); walk(n.children); }
			}
			walk(nodes);
			deptMap = map;
		}).catch(() => { deptFetchFailed = true; /* non-fatal: show "unavailable" instead of "removed" */ });
		// ponytail: one toggle read; default standing when off or on failure.
		void adminFeatureList().then((list) => {
			jitEnabled = list.find((f) => f.key === 'rbac.jit')?.enabled ?? false;
		}).catch(() => { /* non-fatal: JIT grant control stays hidden */ });
		await load();
	});

	async function load() {
		loading = true;
		error = '';
		try {
			const detail = await adminGetRole(roleId);
			members = detail.members;
			roleSodClass = detail.role.sodClass ?? null;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function expiringSoon(m: RoleMember): boolean {
		return isExpiringSoon(m.expiresAt, Date.now());
	}

	async function searchUsers() {
		try {
			userResults = await adminUserList(userQuery || undefined);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function openAssign() {
		pickedUserStr = '';
		domainOverrideStr = '';
		expiresAt = '';
		userQuery = '';
		grantMode = 'standing';
		scopeMode = 'whole';
		ouScope = null;
		setScopeIdStr = '';
		setMembers = [];
		showAssign = true;
		void searchUsers();
		// Lazily load scope-sets for the "A scope-set" arm (non-fatal if forbidden).
		void adminListScopeSets().then((s) => { scopeSets = s; }).catch(() => { scopeSets = []; });
	}

	// Load the selected set's members for the reach preview (composition + chips).
	async function loadSetMembers() {
		setMembers = [];
		if (setScopeIdStr === '') return;
		try {
			const full = await adminGetScopeSet(Number(setScopeIdStr));
			setMembers = full.members ?? [];
		} catch {
			setMembers = [];
		}
	}

	let setOptions = $derived([
		{ value: '', label: '—' },
		...scopeSets.map((s) => ({ value: String(s.id), label: s.name })),
	]);

	// Reach preview composition for the selected set.
	let setReach = $derived({
		depts: setMembers.filter((m) => m.memberType === 'ou').length,
		groups: setMembers.filter((m) => m.memberType === 'group').length,
		users: setMembers.filter((m) => m.memberType === 'user').length,
	});
	// Department chips (resolvable by name); group/user shown as aggregate chips.
	let setDeptChips = $derived(
		setMembers.filter((m) => m.memberType === 'ou').map((m) => deptMap.get(m.memberId) ?? `#${m.memberId}`)
	);

	async function assign(reason?: string) {
		const userId = pickedUserStr === '' ? null : Number(pickedUserStr);
		if (!userId) {
			error = t('admin.roles.pick_user');
			return;
		}
		// Guard: incomplete scope selection must not silently fall through to whole-org grant.
		if (scopeMode === 'set' && !setScopeIdStr) {
			error = t('admin.roles.pick_scope_set');
			return;
		}
		if (scopeMode === 'ou' && !ouScope) {
			error = t('admin.roles.pick_dept');
			return;
		}
		// Build the single scope from the radio choice: OU subtree, scope-set, or null.
		const scope: { scopeType: 'ou' | 'set'; scopeId: number } | null =
			scopeMode === 'ou'
				? ouScope
				: scopeMode === 'set' && setScopeIdStr !== ''
					? { scopeType: 'set', scopeId: Number(setScopeIdStr) }
					: null;
		try {
			await adminAssignMember(
				roleId,
				{
					userId,
					domainOverride: domainOverrideStr === '' ? null : Number(domainOverrideStr),
					expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
					...(scope ? { scopeType: scope.scopeType, scopeId: scope.scopeId } : {}),
					// Only send eligible when JIT is on; off keeps today's standing-only default.
					...(jitEnabled ? { eligible: grantMode === 'eligible' } : {}),
				},
				reason
			);
			showToast(t('admin.roles.member_added'));
			showAssign = false;
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// Called when assign dialog submits (reason prompt or direct)
	function handleAssign(reason?: string) {
		void assign(rolesReasonRequired ? (reason ?? '') || undefined : undefined);
	}

	function remove(m: RoleMember) {
		removeTarget = m;
	}

	async function doRemove(reason?: string) {
		if (!removeTarget) return;
		try {
			await adminRemoveMember(roleId, removeTarget.userId, reason);
			showToast(t('admin.roles.member_removed'));
			removeTarget = null;
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function handleRemove(reason?: string) {
		void doRemove(rolesReasonRequired ? (reason ?? '') || undefined : undefined);
	}

	function domainName(id: number | null | undefined): string {
		if (id == null) return t('admin.roles.scope_inherit');
		return domains.find((d) => d.id === id)?.name ?? String(id);
	}

	let userOptions = $derived([
		{ value: '', label: '—' },
		...userResults.map((u) => ({ value: String(u.id), label: u.email })),
	]);

	let domainOptions = $derived([
		{ value: '', label: t('admin.roles.scope_inherit') },
		...domains.map((d) => ({ value: String(d.id), label: d.name })),
	]);

	// ── Bulk add ──

	async function searchBulkUsers() {
		try {
			const all = await adminUserList(bulkQuery || undefined);
			// Exclude un-manageable users from the selectable set
			// ponytail: manageable flag is the same gate the single-add path uses
			bulkUserResults = all.filter((u) => u.manageable);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function openBulkAdd() {
		bulkQuery = '';
		bulkSelectedIds = new Set();
		bulkExpiresAt = '';
		bulkReason = '';
		bulkScope = null;
		bulkReport = null;
		showBulkAdd = true;
		void searchBulkUsers();
	}

	function toggleBulkUser(id: number) {
		const next = new Set(bulkSelectedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		bulkSelectedIds = next;
	}

	async function pollJob(jobId: number): Promise<BulkRoleJob> {
		// ponytail: simple poll loop — no library needed
		return new Promise((resolve, reject) => {
			const iv = setInterval(async () => {
				try {
					const job = await getBulkRoleJob(jobId);
					if (job.status === 'done' || job.status === 'error') {
						clearInterval(iv);
						_pollIv = null;
						resolve(job);
					}
				} catch (e) {
					clearInterval(iv);
					_pollIv = null;
					reject(e);
				}
			}, 1000);
			_pollIv = iv;
			// Kick off an immediate first check
			getBulkRoleJob(jobId).then((job) => {
				if (job.status === 'done' || job.status === 'error') {
					clearInterval(iv);
					_pollIv = null;
					resolve(job);
				}
			}).catch((e) => { clearInterval(iv); _pollIv = null; reject(e); });
		});
	}

	async function submitBulkAdd() {
		if (bulkSelectedIds.size === 0) return;
		bulkPending = true;
		error = '';
		try {
			const { jobId } = await bulkAssignRole(
				roleId,
				Array.from(bulkSelectedIds),
				bulkExpiresAt ? new Date(bulkExpiresAt).toISOString() : undefined,
				bulkReason.trim() || undefined,
				bulkScope
			);
			const job = await pollJob(jobId);
			bulkReport = { job };
			await load();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			bulkPending = false;
		}
	}

	// ── Bulk remove ──

	function toggleSelect(m: RoleMember) {
		if (m.manageable === false) return;
		const next = new Set(selectedIds);
		if (next.has(m.userId)) next.delete(m.userId);
		else next.add(m.userId);
		selectedIds = next;
	}

	let hasSelection = $derived(selectedIds.size > 0);

	async function doRemoveSelected(reason?: string) {
		if (selectedIds.size === 0) return;
		bulkPending = true;
		error = '';
		bulkReport = null;
		try {
			const { jobId } = await bulkRevokeRole(
				roleId,
				Array.from(selectedIds),
				reason
			);
			const job = await pollJob(jobId);
			bulkReport = { job };
			selectedIds = new Set();
			await load();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			bulkPending = false;
		}
	}

	function handleRemoveSelected(reason?: string) {
		void doRemoveSelected(rolesReasonRequired ? (reason ?? '') || undefined : undefined);
	}

	// report helpers
	function reportAssigned(job: BulkRoleJob) {
		return job.results.filter((r) => r.status === 'assigned').length;
	}
	function reportUpdated(job: BulkRoleJob) {
		return job.results.filter((r) => r.status === 'updated').length;
	}
	function reportRevoked(job: BulkRoleJob) {
		return job.results.filter((r) => r.status === 'revoked').length;
	}
	function reportNotMember(job: BulkRoleJob) {
		return job.results.filter((r) => r.status === 'not_member').length;
	}
	function reportBlocked(job: BulkRoleJob) {
		return job.results.filter((r) => r.status === 'blocked');
	}
	function reasonLabel(reason: string | undefined): string {
		if (!reason) return reason ?? '';
		const key = `admin.bulkRole.reason.${reason}`;
		return t(key) ?? reason;
	}
	function groupByReason(blocked: BulkRoleJob['results']) {
		const map = new Map<string, number[]>();
		for (const r of blocked) {
			const k = r.reason ?? 'unknown';
			if (!map.has(k)) map.set(k, []);
			map.get(k)!.push(r.user_id);
		}
		return map;
	}
</script>

{#if error}
	<div class="sj-alert-danger" role="alert">{error}</div>
{/if}

{#if jitEnabled && canEdit}
	<!-- Per-role activation policy (§7F): only meaningful when JIT is on. -->
	<div class="sj-members-policy">
		<RoleActivationPolicyEditor {roleId} />
	</div>
{/if}

{#if canEdit}
	<div class="sj-members-toolbar">
		<Button variant="primary" size="sm" onclick={openAssign}>{t('admin.roles.add_member')}</Button>
		<Button variant="secondary" size="sm" onclick={openBulkAdd}>{t('admin.bulkRole.addMembers')}</Button>
		{#if hasSelection}
			{#if rolesReasonRequired}
				<!-- ponytail: open reason dialog before submitting bulk revoke -->
				<Button variant="danger" size="sm" disabled={bulkPending} onclick={() => { showBulkRevoke = true; }}>
					{t('admin.bulkRole.removeSelected')}
				</Button>
			{:else}
				<Button variant="danger" size="sm" disabled={bulkPending} onclick={() => handleRemoveSelected()}>
					{t('admin.bulkRole.removeSelected')}
				</Button>
			{/if}
		{/if}
		{#if bulkPending}
			<Spinner size={16} label={t('admin.bulkRole.queued')} />
		{/if}
	</div>
{/if}

{#if bulkReport}
	{@const job = bulkReport.job}
	{@const blocked = reportBlocked(job)}
	{@const grouped = groupByReason(blocked)}
	<div class="sj-bulk-report" role="status">
		{#if job.op === 'assign'}
			<span>{t('admin.bulkRole.report.assigned')}: {reportAssigned(job)}</span>
			{#if reportUpdated(job) > 0}
				<span>{t('admin.bulkRole.report.updated')}: {reportUpdated(job)}</span>
			{/if}
		{:else}
			<span>{reportRevoked(job)} {t('admin.bulkRole.report.revoked')}</span>
			{#if reportNotMember(job) > 0}
				<span>{t('admin.bulkRole.reportNotMember', { n: String(reportNotMember(job)) })}</span>
			{/if}
		{/if}
		{#if blocked.length > 0}
			<div class="sj-bulk-blocked">
				<strong>{t('admin.bulkRole.report.blocked')}: {blocked.length}</strong>
				{#each [...grouped.entries()] as [reason, ids]}
					<div class="sj-bulk-reason">
						<span class="sj-bulk-reason-label">{reasonLabel(reason)}</span>
						<span class="sj-muted">({ids.length})</span>
					</div>
				{/each}
			</div>
		{/if}
		<a href="/admin/jobs" class="sj-bulk-jobs-link">{t('admin.bulkRole.viewConsole')}</a>
	</div>
{/if}

{#if loading}
	<div class="sj-members-loading">
		<Spinner size={20} label={t('common.loading')} />
	</div>
{:else if members.length === 0}
	<EmptyState title={t('admin.roles.no_members')} />
{:else}
	{@const rows = members as unknown as Record<string, unknown>[]}
	<Table columns={COLUMNS} {rows}>
		{#snippet cell(row, col)}
			{@const m = row as unknown as RoleMember}
			{#if col.key === 'select'}
				{#if canEdit}
					<input
						type="checkbox"
						disabled={m.manageable === false}
						checked={selectedIds.has(m.userId)}
						aria-label={m.displayName || m.userEmail}
						onclick={() => toggleSelect(m)}
					/>
				{/if}
			{:else if col.key === 'member'}
				<div class="sj-member-cell">
					<div class="sj-member-name-group">
						<strong>{m.displayName || m.userEmail}</strong>
						<span class="sj-muted">{m.userEmail}</span>
					</div>
					{#if m.manageable === false}
						<Tooltip text={t('admin.protection.reason_protected', { email: m.userEmail })}>
							<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
							<span tabindex="0" class="sj-protection-indicator">
								<Icon name="ShieldCheck" size={13} strokeWidth={1.75} aria-hidden={true} />
								<Badge label={t('admin.protection.badge_protected')} />
							</span>
						</Tooltip>
					{/if}
				</div>
			{:else if col.key === 'scope'}
				{#if m.scopeType === 'ou'}
					{#if m.scopeId != null && deptMap.has(m.scopeId)}
						{t('admin.roles.scope_ou_label')}: {deptMap.get(m.scopeId)}
					{:else}
						<!-- V041 drops the grant on dept-delete, so a stale OU scope no longer exists; an un-resolvable id means the tree hasn't loaded yet. -->
						<span class="sj-scope-stale">{t('admin.roles.scope_dept_unavailable')}</span>
					{/if}
				{:else if m.scopeType === 'set'}
					{#if m.setName}
						<a class="sj-scope-set-chip" href="/admin/scope-sets?id={m.scopeId}">{t('admin.roles.scope_set_label')}: {m.setName}</a>
					{:else}
						<span class="sj-scope-stale">{t('admin.roles.scope_set_unavailable')}</span>
					{/if}
				{:else}
					{domainName(m.domainOverride)}
				{/if}
			{:else if col.key === 'expires'}
				{#if m.expiresAt}
					<span class="sj-expires">
						{new Date(m.expiresAt).toLocaleDateString()}
						{#if expiringSoon(m)}
							<Badge variant="warning" label={t('admin.roles.expiring_soon')} />
						{/if}
					</span>
				{:else}
					{t('admin.roles.never')}
				{/if}
			{:else if col.key === 'actions'}
				{#if canEdit}
					<Button
						variant="danger"
						size="sm"
						disabled={m.manageable === false}
						onclick={() => remove(m)}
					>{t('common.remove')}</Button>
				{/if}
			{/if}
		{/snippet}
	</Table>
{/if}

<!-- Single-add dialog -->
<Dialog open={showAssign} title={t('admin.roles.add_member')} onClose={() => (showAssign = false)}>
	{#snippet children()}
		<div class="sj-assign-form">
			{#if $sodMode && roleSodClass}
				<div class="sj-sod-block" role="alert">
					<strong>{t('admin.sod.cross_class_blocked')}</strong>
					<p>{t('admin.sod.cross_class_reason', { targetClass: roleSodClass })}</p>
				</div>
			{/if}
			<Input
				label={t('admin.roles.search_user')}
				bind:value={userQuery}
				oninput={() => void searchUsers()}
			/>
			<Select
				label={t('admin.roles.user')}
				options={userOptions}
				bind:value={pickedUserStr}
			/>
			<Select
				label={t('admin.roles.domain_override')}
				options={domainOptions}
				bind:value={domainOverrideStr}
			/>
			<div class="sj-assign-scope-section">
				<fieldset class="sj-scope-radio">
					<legend>{t('admin.roles.scope')}</legend>
					<label class="sj-scope-opt">
						<input type="radio" name="assign-scope" value="whole" checked={scopeMode === 'whole'} onchange={() => (scopeMode = 'whole')} />
						<span class="sj-scope-opt-text">
							<strong>{t('admin.roles.scope_picker_whole_org')}</strong>
							<span class="sj-scope-opt-hint">{t('admin.roles.scope_picker_whole_org_hint')}</span>
						</span>
					</label>
					<label class="sj-scope-opt">
						<input type="radio" name="assign-scope" value="ou" checked={scopeMode === 'ou'} onchange={() => (scopeMode = 'ou')} />
						<span class="sj-scope-opt-text">
							<strong>{t('admin.roles.scope_picker_one_dept')}</strong>
							<span class="sj-scope-opt-hint">{t('admin.roles.scope_picker_one_dept_hint')}</span>
						</span>
					</label>
					<label class="sj-scope-opt">
						<input type="radio" name="assign-scope" value="set" checked={scopeMode === 'set'} onchange={() => (scopeMode = 'set')} />
						<span class="sj-scope-opt-text">
							<span class="sj-scope-opt-label-row">
								<strong>{t('admin.roles.scope_picker_a_set')}</strong>
								<Tooltip text={t('admin.roles.scope_set_concept_tip')}>
									<button type="button" class="sj-scope-info" aria-label={t('admin.roles.scope_picker_a_set')} onclick={(e) => e.preventDefault()}>
										<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden={true} />
									</button>
								</Tooltip>
							</span>
							<span class="sj-scope-opt-hint">{t('admin.roles.scope_picker_a_set_hint')}</span>
						</span>
					</label>
				</fieldset>
				{#if scopeMode === 'ou'}
					<DepartmentTreePicker bind:value={ouScope} embedded />
				{:else if scopeMode === 'set'}
					{#if scopeSets.length === 0}
						<div class="sj-scope-set-empty">
							<strong>{t('admin.roles.scope_set_empty_title')}</strong>
							<p>{t('admin.roles.scope_set_empty_body')}</p>
							<a class="sj-scope-set-link" href="/admin/scope-sets">{t('admin.roles.scope_set_empty_cta')}</a>
						</div>
					{:else}
						<div class="sj-scope-set-pick">
							<Select label={t('admin.roles.scope_set_pick')} options={setOptions} bind:value={setScopeIdStr} onchange={() => void loadSetMembers()} />
							<a class="sj-scope-set-link" href="/admin/scope-sets">{t('admin.roles.scope_set_new')}</a>
						</div>
						{#if setScopeIdStr !== ''}
							<div class="sj-scope-set-reach" aria-live="polite">
								<span class="sj-scope-set-reach-line">{t('admin.roles.scope_set_reach_preview', { depts: String(setReach.depts), groups: String(setReach.groups), users: String(setReach.users) })}</span>
								<div class="sj-scope-set-chips">
									{#each setDeptChips.slice(0, 4) as d}
										<span class="sj-set-chip sj-set-chip--dept">{d}</span>
									{/each}
									{#if setDeptChips.length > 4}
										<Tooltip text={setDeptChips.slice(4).join(', ')}>
											<button type="button" class="sj-set-chip sj-set-chip--more">{t('admin.roles.scope_set_reach_more', { n: String(setDeptChips.length - 4) })}</button>
										</Tooltip>
									{/if}
									{#if setReach.groups > 0}
										<span class="sj-set-chip sj-set-chip--grp">{t('admin.roles.scope_set_groups_chip', { n: String(setReach.groups) })}</span>
									{/if}
									{#if setReach.users > 0}
										<span class="sj-set-chip sj-set-chip--usr">{t('admin.roles.scope_set_users_chip', { n: String(setReach.users) })}</span>
									{/if}
								</div>
							</div>
						{/if}
					{/if}
				{/if}
			</div>
			{#if jitEnabled}
				<fieldset class="sj-scope-radio">
					<legend>{t('admin.jit.grant_label')}</legend>
					<label class="sj-scope-opt">
						<input type="radio" name="grant-mode" value="standing" checked={grantMode === 'standing'} onchange={() => (grantMode = 'standing')} />
						<span class="sj-scope-opt-text">
							<strong>{t('admin.jit.grant_standing')}</strong>
							<span class="sj-scope-opt-hint">{t('admin.jit.grant_standing_hint')}</span>
						</span>
					</label>
					<label class="sj-scope-opt">
						<input type="radio" name="grant-mode" value="eligible" checked={grantMode === 'eligible'} onchange={() => (grantMode = 'eligible')} />
						<span class="sj-scope-opt-text">
							<span class="sj-scope-opt-label-row">
								<strong>{t('admin.jit.grant_eligible')}</strong>
								<Tooltip text={t('admin.jit.grant_eligible_tip')}>
									<button type="button" class="sj-scope-info" aria-label={t('admin.jit.grant_eligible')} onclick={(e) => e.preventDefault()}>
										<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden={true} />
									</button>
								</Tooltip>
							</span>
							<span class="sj-scope-opt-hint">{t('admin.jit.grant_eligible_tip')}</span>
						</span>
					</label>
				</fieldset>
			{/if}
			<Input
				label={t('admin.roles.expires_optional')}
				type="date"
				bind:value={expiresAt}
			/>
			{#if rolesReasonRequired}
				<!-- ponytail: reason prompt only when policy requires it -->
				<ReasonPrompt
					area="roles"
					onSubmit={(r) => handleAssign(r)}
					submitLabel={t('admin.roles.assign')}
				/>
			{:else}
				<Button variant="primary" onclick={() => handleAssign()}>{t('admin.roles.assign')}</Button>
			{/if}
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (showAssign = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<!-- Bulk add dialog -->
<Dialog open={showBulkAdd} title={t('admin.bulkRole.addMembers')} onClose={() => (showBulkAdd = false)}>
	{#snippet children()}
		<div class="sj-assign-form">
			<Input
				label={t('admin.roles.search_user')}
				bind:value={bulkQuery}
				oninput={() => void searchBulkUsers()}
			/>
			{#if bulkUserResults.length > 0}
				<div class="sj-bulk-picker-list" role="listbox" aria-label={t('admin.roles.search_user')}>
					{#each bulkUserResults as u}
						<label class="sj-bulk-picker-item">
							<input
								type="checkbox"
								checked={bulkSelectedIds.has(u.id)}
								onclick={() => toggleBulkUser(u.id)}
							/>
							<span>{u.email}</span>
							{#if u.displayName}
								<span class="sj-muted">{u.displayName}</span>
							{/if}
						</label>
					{/each}
				</div>
			{/if}
			<!-- Chips of selected users -->
			{#if bulkSelectedIds.size > 0}
				<div class="sj-bulk-chips" aria-live="polite">
					{#each bulkUserResults.filter((u) => bulkSelectedIds.has(u.id)) as u}
						<span class="sj-chip">
							{u.email}
							<button
								type="button"
								class="sj-chip-remove"
								aria-label="Remove {u.email}"
								onclick={() => toggleBulkUser(u.id)}
							>×</button>
						</span>
					{/each}
				</div>
			{/if}
			<div class="sj-assign-scope-section">
				<DepartmentTreePicker bind:value={bulkScope} />
			</div>
			<Input
				label={t('admin.roles.expires_optional')}
				type="date"
				bind:value={bulkExpiresAt}
			/>
			{#if rolesReasonRequired}
				<!-- ponytail: ONE reason for the whole bulk batch, only when required -->
				<ReasonPrompt
					area="roles"
					onSubmit={(r) => { bulkReason = r; void submitBulkAdd(); }}
					submitLabel="{t('admin.bulkRole.addMembers')} ({bulkSelectedIds.size})"
				/>
			{:else}
				<Button
					variant="primary"
					disabled={bulkSelectedIds.size === 0}
					onclick={() => void submitBulkAdd()}
				>{t('admin.bulkRole.addMembers')} ({bulkSelectedIds.size})</Button>
			{/if}
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (showBulkAdd = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

{#if removeTarget}
	<Dialog
		open={removeTarget != null}
		title={t('admin.roles.confirm_remove_title')}
		onClose={() => { removeTarget = null; }}
	>
		{#snippet children()}
			<p>{t('admin.roles.confirm_remove_body', { name: removeTarget!.displayName || removeTarget!.userEmail })}</p>
			{#if rolesReasonRequired}
				<div class="sj-assign-form" style="margin-top: var(--space-3)">
					<ReasonPrompt
						area="roles"
						onSubmit={(r) => handleRemove(r)}
						submitLabel={t('common.remove')}
					/>
				</div>
			{/if}
		{/snippet}
		{#snippet footer()}
			{#if !rolesReasonRequired}
				<Button variant="danger" onclick={() => handleRemove()}>{t('common.remove')}</Button>
			{/if}
			<Button variant="ghost" onclick={() => { removeTarget = null; }}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- Bulk revoke reason dialog (only shown when rolesReasonRequired) -->
{#if showBulkRevoke}
	<Dialog
		open={showBulkRevoke}
		title={t('admin.bulkRole.removeSelected')}
		onClose={() => { showBulkRevoke = false; }}
	>
		{#snippet children()}
			<ReasonPrompt
				area="roles"
				onSubmit={(r) => { showBulkRevoke = false; handleRemoveSelected(r); }}
				submitLabel="{t('admin.bulkRole.removeSelected')} ({selectedIds.size})"
			/>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => { showBulkRevoke = false; }}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-members-policy {
		margin-bottom: var(--space-3);
	}
	.sj-members-toolbar {
		margin-bottom: var(--space-3);
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.sj-members-loading {
		padding: 24px;
		display: flex;
		justify-content: center;
	}
	.sj-member-cell {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sj-member-name-group {
		display: flex;
		flex-direction: column;
		gap: 2px; /* sub-token: no --space-0_5 exists; 4px grid minimum */
		min-width: 0;
	}
	.sj-muted {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.sj-protection-indicator {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		cursor: default;
		border-radius: var(--radius-sm);
		outline-offset: 2px;
		flex-shrink: 0;
	}
	.sj-protection-indicator:focus-visible {
		outline: 2px solid var(--accent);
	}
	.sj-expires {
		display: inline-flex;
		align-items: center;
		gap: 6px; /* sub-token: between --space-1 (4px) and --space-2 (8px); no exact token */
	}
	.sj-assign-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-sod-block {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		font-size: var(--text-sm);
	}
	.sj-sod-block p {
		margin: var(--space-1) 0 0;
		font-size: var(--text-xs);
	}
	/* Bulk picker */
	.sj-bulk-picker-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-height: 240px;
		overflow-y: auto;
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
	}
	.sj-bulk-picker-item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		cursor: pointer;
		padding: var(--space-1) 0;
		font-size: var(--text-sm);
	}
	.sj-bulk-chips {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.sj-chip {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		background: var(--surface-2);
		border-radius: var(--radius-full, 9999px);
		padding: 2px var(--space-2);
		font-size: var(--text-sm);
	}
	.sj-chip-remove {
		background: none;
		border: none;
		cursor: pointer;
		padding: 0;
		color: var(--text-tertiary);
		font-size: var(--text-base);
		line-height: 1;
	}
	/* Bulk report */
	.sj-bulk-report {
		background: var(--surface-2);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-3);
		font-size: var(--text-sm);
	}
	.sj-bulk-blocked {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		color: var(--danger-fg);
	}
	.sj-bulk-reason {
		display: flex;
		align-items: center;
		gap: var(--space-1);
	}
	.sj-bulk-reason-label {
		font-weight: 500;
	}
	.sj-bulk-jobs-link {
		font-size: var(--text-sm);
		color: var(--accent);
		text-decoration: none;
	}
	.sj-bulk-jobs-link:hover {
		text-decoration: underline;
	}
	.sj-scope-stale {
		color: var(--text-tertiary);
		font-style: italic;
		font-size: var(--text-sm);
	}
	.sj-assign-scope-section {
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	/* 3-radio scope picker */
	.sj-scope-radio {
		border: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sj-scope-radio legend {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		margin-bottom: var(--space-1);
		padding: 0;
	}
	.sj-scope-opt {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		min-height: 44px;
		padding: var(--space-1) 0;
		cursor: pointer;
	}
	.sj-scope-opt input[type='radio'] {
		margin-top: 3px;
		accent-color: var(--accent);
		width: 16px;
		height: 16px;
		flex-shrink: 0;
	}
	.sj-scope-opt-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.sj-scope-opt-text strong {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-scope-opt-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sj-scope-opt-label-row {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
	}
	.sj-scope-info {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: none;
		border: none;
		padding: 1px;
		cursor: help;
		color: var(--text-tertiary);
		border-radius: var(--radius-xs);
	}
	.sj-scope-info:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-scope-set-pick {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.sj-scope-set-link {
		font-size: var(--text-sm);
		color: var(--text-accent);
		text-decoration: none;
		white-space: nowrap;
		padding-bottom: var(--space-2);
	}
	.sj-scope-set-link:hover {
		text-decoration: underline;
	}
	.sj-scope-set-empty {
		background: var(--surface-sunken, var(--surface-2));
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		font-size: var(--text-sm);
	}
	.sj-scope-set-empty strong {
		display: block;
		color: var(--text-primary);
	}
	.sj-scope-set-empty p {
		margin: var(--space-1) 0 var(--space-2);
		color: var(--text-tertiary);
		font-size: var(--text-xs);
	}
	.sj-scope-set-reach {
		background: var(--surface-sunken, var(--surface-2));
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sj-scope-set-reach-line {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.sj-scope-set-chips {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.sj-set-chip {
		display: inline-flex;
		align-items: center;
		padding: 2px var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		border: none;
		font-family: inherit;
	}
	.sj-set-chip--dept {
		background: var(--accent-subtle);
		color: var(--accent-fg);
	}
	.sj-set-chip--grp {
		background: var(--success-bg, var(--surface-2));
		color: var(--success-fg, var(--text-secondary));
	}
	.sj-set-chip--usr {
		background: var(--warning-bg, var(--surface-2));
		color: var(--warning-fg, var(--text-secondary));
	}
	.sj-set-chip--more {
		background: var(--surface-2);
		color: var(--text-secondary);
		cursor: help;
	}
	.sj-set-chip--more:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.sj-scope-set-chip {
		color: var(--text-accent);
		text-decoration: none;
		font-size: var(--text-sm);
	}
	.sj-scope-set-chip:hover {
		text-decoration: underline;
	}
</style>
