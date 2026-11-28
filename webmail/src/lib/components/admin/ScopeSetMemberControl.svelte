<svelte:options runes={true} />

<!--
	ScopeSetMemberControl — the combined member control for an admin scope-set
	(spec §7B/§7C/§7G/§7I). One control, three source tabs (Departments tree ·
	Directory groups · People search) feeding a single typed chip tray (DEPT /
	GROUP / USER chips) + a live reach count. Reuses DepartmentTreePicker for the
	Departments tab (its WAI-ARIA tree + subtree affordance), Tabs for the
	tablist, Tooltip for disabled-group reasons, and showToast(Undo) for removes.

	Members are bound out so the host editor can diff/save them. The footer Save
	bar lives here (so the control is independently testable): empty tray =
	danger + disabled save.
-->

<script lang="ts" module>
	export interface ScopeChipMember {
		memberType: 'ou' | 'group' | 'user';
		memberId: number;
		/** Display name resolved at add-time (dept name / group name / user email). */
		name: string;
		/** Seat approximation for the reach summary: dept userCount / group memberCount / 1. */
		seats?: number;
	}
</script>

<script lang="ts">
	import { onMount } from 'svelte';
	import { Tabs, Tooltip, Button, Input, Spinner, showToast } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import DepartmentTreePicker from './DepartmentTreePicker.svelte';
	import {
		adminDeptTree,
		adminListDirectoryGroups,
		adminUserList,
		type TreeNode,
		type DirectoryGroup,
		type AdminUser
	} from '$lib/admin/client';
	import { t } from '$lib/i18n';

	interface Props {
		/** The typed members — bound out to the host editor. */
		members?: ScopeChipMember[];
		/** True while the host is saving (disables + spins the Save button). */
		saving?: boolean;
		/** Extra save gate from the host (e.g. invalid name). */
		saveDisabled?: boolean;
		/** Save-bar consequence copy. */
		consequence?: string;
		onSave?: () => void;
		onCancel?: () => void;
	}

	let {
		members = $bindable([]),
		saving = false,
		saveDisabled = false,
		consequence,
		onSave,
		onCancel
	}: Props = $props();

	type SourceTab = 'departments' | 'groups' | 'people';
	let activeTab = $state<SourceTab>('departments');

	// ── Departments (reuse DepartmentTreePicker; resolve names via the tree) ──
	let deptMap = $state<Map<number, { name: string; userCount: number }>>(new Map());
	let deptTreeEmpty = $state(false);
	let deptFetchFailed = $state(false);
	// Bound to the embedded picker; an $effect lifts each pick into a chip then resets.
	let deptPick = $state<{ scopeType: 'ou'; scopeId: number } | null>(null);

	// ── Directory groups ──
	let groups = $state<DirectoryGroup[]>([]);
	let groupsLoading = $state(false);
	let groupsFailed = $state(false);

	// ── People search (debounced) ──
	let peopleQuery = $state('');
	let peopleResults = $state<AdminUser[]>([]);
	let peopleLoading = $state(false);
	let peopleDebounce: ReturnType<typeof setTimeout> | null = null;

	// ── Rejection announcement (polite) ──
	let announce = $state('');

	const TABS: TabItem[] = [
		{ id: 'departments', label: t('admin.scope_sets.tab_departments') },
		{ id: 'groups', label: t('admin.scope_sets.tab_groups') },
		{ id: 'people', label: t('admin.scope_sets.tab_people') }
	];

	onMount(() => {
		void adminDeptTree()
			.then((nodes) => {
				const map = new Map<number, { name: string; userCount: number }>();
				const walk = (ns: TreeNode[]) => {
					for (const n of ns) {
						map.set(n.id, { name: n.name, userCount: n.userCount });
						walk(n.children);
					}
				};
				walk(nodes);
				deptMap = map;
				deptTreeEmpty = nodes.length === 0;
			})
			.catch(() => {
				deptFetchFailed = true;
			});
		void loadGroups();
	});

	async function loadGroups() {
		groupsLoading = true;
		groupsFailed = false;
		try {
			groups = await adminListDirectoryGroups();
		} catch {
			// No directory-groups endpoint / transient failure → degrade to the
			// "scope by department or person" fallback (spec §7D).
			groupsFailed = true;
			groups = [];
		} finally {
			groupsLoading = false;
		}
	}

	function groupEligible(g: DirectoryGroup): boolean {
		return !g.isDynamic && (g.scimSynced || g.usableAsAdminScope);
	}

	function groupDisabledReason(g: DirectoryGroup): { short: string; tip: string } | null {
		if (g.isDynamic) {
			return {
				short: t('admin.scope_sets.group_disabled_dynamic'),
				tip: t('admin.scope_sets.group_disabled_dynamic_tip')
			};
		}
		if (!(g.scimSynced || g.usableAsAdminScope)) {
			return {
				short: t('admin.scope_sets.group_disabled_not_eligible'),
				tip: t('admin.scope_sets.group_disabled_not_eligible_tip')
			};
		}
		return null;
	}

	function groupSource(g: DirectoryGroup): string {
		if (g.scimSynced) return t('admin.scope_sets.group_source_scim');
		if (g.usableAsAdminScope) return t('admin.scope_sets.group_source_ldap');
		return t('admin.scope_sets.group_source_local');
	}

	// ── Membership helpers ──
	function has(memberType: ScopeChipMember['memberType'], memberId: number): boolean {
		return members.some((m) => m.memberType === memberType && m.memberId === memberId);
	}

	function addMember(m: ScopeChipMember) {
		if (has(m.memberType, m.memberId)) return;
		members = [...members, m];
	}

	function removeMember(m: ScopeChipMember) {
		members = members.filter((x) => !(x.memberType === m.memberType && x.memberId === m.memberId));
		// Act-then-undo (reversible — DESIGN.md §6), not a confirm.
		showToast(t('admin.scope_sets.member_removed', { name: m.name }), {
			actionLabel: t('common.undo'),
			onAction: () => addMember(m)
		});
	}

	// Lift each department pick into a DEPT chip, then reset the picker.
	$effect(() => {
		const p = deptPick;
		if (!p) return;
		const meta = deptMap.get(p.scopeId);
		addMember({
			memberType: 'ou',
			memberId: p.scopeId,
			name: meta?.name ?? `#${p.scopeId}`,
			seats: meta?.userCount ?? 0
		});
		deptPick = null;
	});

	function addGroup(g: DirectoryGroup) {
		if (!groupEligible(g)) {
			announce = t('admin.scope_sets.add_rejected', { name: g.name });
			return;
		}
		addMember({ memberType: 'group', memberId: g.id, name: g.name, seats: g.memberCount });
	}

	function addPerson(u: AdminUser) {
		if (u.manageable === false) {
			announce = t('admin.scope_sets.add_rejected', { name: u.email });
			return;
		}
		addMember({ memberType: 'user', memberId: u.id, name: u.email, seats: 1 });
	}

	function onPeopleInput() {
		if (peopleDebounce) clearTimeout(peopleDebounce);
		peopleDebounce = setTimeout(() => void runPeopleSearch(), 250);
	}

	async function runPeopleSearch() {
		peopleLoading = true;
		try {
			peopleResults = await adminUserList(peopleQuery || undefined);
		} catch {
			peopleResults = [];
		} finally {
			peopleLoading = false;
		}
	}

	// ── Reach summary (composition — no people-reach endpoint exists, so we count
	// member kinds; "~seats" is an upper bound the host uses for the confirm gate). ──
	let deptCount = $derived(members.filter((m) => m.memberType === 'ou').length);
	let groupCount = $derived(members.filter((m) => m.memberType === 'group').length);
	let userCount = $derived(members.filter((m) => m.memberType === 'user').length);
	let reachSummary = $derived(
		t('admin.scope_sets.reach_summary', {
			depts: String(deptCount),
			groups: String(groupCount),
			users: String(userCount)
		})
	);

	let isEmpty = $derived(members.length === 0);

	function kindLabel(memberType: ScopeChipMember['memberType']): string {
		return memberType === 'ou'
			? t('admin.scope_sets.kind_dept')
			: memberType === 'group'
				? t('admin.scope_sets.kind_group')
				: t('admin.scope_sets.kind_user');
	}
	function chipClass(memberType: ScopeChipMember['memberType']): string {
		return memberType === 'ou' ? 'ssm-chip--dept' : memberType === 'group' ? 'ssm-chip--grp' : 'ssm-chip--usr';
	}
</script>

<div class="ssm">
	<span class="ssm-label">
		{t('admin.scope_sets.members_label')}
		<span class="ssm-label-hint">— {t('admin.scope_sets.members_hint')}</span>
	</span>

	<Tabs items={TABS} active={activeTab} onChange={(id: string) => (activeTab = id as SourceTab)} />

	<!-- ── Departments tab ──────────────────────────────────────────────── -->
	{#if activeTab === 'departments'}
		<div class="ssm-pane">
			{#if deptTreeEmpty && !deptFetchFailed}
				<div class="ssm-note ssm-note--info" role="note">
					<span class="ssm-note-dot"></span>
					<span>{t('admin.scope_sets.depts_none_info')}</span>
				</div>
			{:else if deptFetchFailed}
				<div class="ssm-note ssm-note--info" role="note">
					<span class="ssm-note-dot"></span>
					<span>{t('admin.scope_sets.depts_load_failed')}</span>
				</div>
			{:else}
				<DepartmentTreePicker bind:value={deptPick} embedded />
			{/if}
		</div>
	{/if}

	<!-- ── Directory groups tab ─────────────────────────────────────────── -->
	{#if activeTab === 'groups'}
		<div class="ssm-pane">
			{#if groupsLoading}
				<div class="ssm-loading"><Spinner size={16} label={t('common.loading')} /></div>
			{:else if groupsFailed || groups.length === 0}
				<div class="ssm-note ssm-note--info" role="note">
					<span class="ssm-note-dot"></span>
					<span>{t('admin.scope_sets.groups_none_info')}</span>
				</div>
			{:else}
				<ul class="ssm-glist">
					{#each groups as g (g.id)}
						{@const reason = groupDisabledReason(g)}
						{@const added = has('group', g.id)}
						<li class="ssm-grow" class:ssm-grow--disabled={reason != null}>
							<div class="ssm-gname">
								<span>{g.name}</span>
								<span class="ssm-meta">· {groupSource(g)} · {t('admin.scope_sets.group_members', { n: String(g.memberCount) })}</span>
							</div>
							{#if reason}
								<!-- aria-disabled (not `disabled`) keeps the control focusable so the
								     keyboard reaches the reason tooltip; the add is no-op'd. -->
								<Tooltip text={reason.tip}>
									<button type="button" class="ssm-reason-btn" aria-disabled="true" aria-label={reason.short} onclick={(e) => e.preventDefault()}>
										<span class="ssm-note-dot ssm-note-dot--muted" aria-hidden="true"></span>
										<span>{reason.short}</span>
										<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden={true} />
									</button>
								</Tooltip>
							{:else}
								<Button variant="secondary" size="sm" disabled={added} onclick={() => addGroup(g)}>
									{added ? t('admin.scope_sets.added') : t('admin.scope_sets.add')}
								</Button>
							{/if}
						</li>
					{/each}
				</ul>
				<div class="ssm-note ssm-note--warn" role="note">
					<span class="ssm-note-dot"></span>
					<span>{t('admin.scope_sets.groups_drift_note')}</span>
				</div>
			{/if}
		</div>
	{/if}

	<!-- ── People tab ───────────────────────────────────────────────────── -->
	{#if activeTab === 'people'}
		<div class="ssm-pane">
			<Input
				type="search"
				label={t('admin.scope_sets.people_search')}
				placeholder={t('admin.scope_sets.people_search_placeholder')}
				bind:value={peopleQuery}
				oninput={onPeopleInput}
			/>
			{#if peopleLoading}
				<div class="ssm-loading"><Spinner size={16} label={t('common.loading')} /></div>
			{:else if peopleResults.length > 0}
				<ul class="ssm-glist">
					{#each peopleResults as u (u.id)}
						{@const added = has('user', u.id)}
						{@const outOfReach = u.manageable === false}
						<li class="ssm-grow" class:ssm-grow--disabled={outOfReach}>
							<div class="ssm-gname">
								<span>{u.email}</span>
								{#if u.displayName}<span class="ssm-meta">· {u.displayName}</span>{/if}
							</div>
							{#if outOfReach}
								<Tooltip text={t('admin.scope_sets.people_out_of_reach_tip')}>
									<button type="button" class="ssm-reason-btn" aria-disabled="true" aria-label={t('admin.scope_sets.people_out_of_reach')} onclick={(e) => e.preventDefault()}>
										<span class="ssm-note-dot ssm-note-dot--muted" aria-hidden="true"></span>
										<span>{t('admin.scope_sets.people_out_of_reach')}</span>
										<Icon name="Info" size={13} strokeWidth={1.75} aria-hidden={true} />
									</button>
								</Tooltip>
							{:else}
								<Button variant="secondary" size="sm" disabled={added} onclick={() => addPerson(u)}>
									{added ? t('admin.scope_sets.added') : t('admin.scope_sets.add')}
								</Button>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</div>
	{/if}

	<!-- ── Typed chip tray + live reach ─────────────────────────────────── -->
	<div class="ssm-tray">
		<div class="ssm-tray-head">
			<span class="ssm-tray-title">{t('admin.scope_sets.selected_members', { n: String(members.length) })}</span>
			<span class="ssm-reach" aria-live="polite">{reachSummary}</span>
		</div>
		{#if isEmpty}
			<div class="ssm-note ssm-note--danger" role="alert">
				<span class="ssm-note-dot"></span>
				<span>{t('admin.scope_sets.empty_blocks_save')}</span>
			</div>
		{:else}
			<ul class="ssm-chips" role="list" aria-label={t('admin.scope_sets.members_label')}>
				{#each members as m (m.memberType + ':' + m.memberId)}
					<li class="ssm-chip {chipClass(m.memberType)}">
						<span class="ssm-chip-kind">{kindLabel(m.memberType)}</span>
						<span class="ssm-chip-name">{m.name}</span>
						<button
							type="button"
							class="ssm-chip-x"
							aria-label={t('admin.scope_sets.remove_member', { name: m.name })}
							onclick={() => removeMember(m)}
						>
							<Icon name="X" size={12} strokeWidth={2} aria-hidden={true} />
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	<!-- Polite announcement for a rejected add (the reach line is already polite). -->
	<div class="ssm-sr-only" aria-live="polite" aria-atomic="true">{announce}</div>

	<!-- ── Save bar ─────────────────────────────────────────────────────── -->
	<div class="ssm-foot">
		<span class="ssm-consequence">{consequence ?? t('admin.scope_sets.save_consequence')}</span>
		<div class="ssm-foot-actions">
			{#if onCancel}
				<Button variant="ghost" onclick={onCancel} disabled={saving}>{t('common.cancel')}</Button>
			{/if}
			<Button variant="primary" disabled={isEmpty || saving || saveDisabled} onclick={() => onSave?.()}>
				{#if saving}<Spinner size={16} label={t('admin.scope_sets.saving')} />{/if}
				{t('admin.scope_sets.save')}
			</Button>
		</div>
	</div>
</div>

<style>
	.ssm {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		font-family: var(--font-sans);
	}
	.ssm-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.ssm-label-hint {
		font-weight: var(--weight-regular);
		color: var(--text-tertiary);
	}
	.ssm-pane {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		min-height: 80px;
	}
	.ssm-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-3);
	}
	/* Inline notes — dot + text, never colour alone */
	.ssm-note {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		font-size: var(--text-xs);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.ssm-note-dot {
		width: 7px;
		height: 7px;
		border-radius: var(--radius-full, 9999px);
		flex-shrink: 0;
		margin-top: 5px;
	}
	.ssm-note-dot--muted {
		background: var(--text-tertiary);
		margin-top: 0;
		align-self: center;
	}
	.ssm-note--info {
		background: var(--info-bg, var(--surface-2));
		color: var(--info-fg, var(--text-secondary));
	}
	.ssm-note--info .ssm-note-dot {
		background: var(--info-fg, var(--accent));
	}
	.ssm-note--warn {
		background: var(--warning-bg, var(--surface-2));
		color: var(--warning-fg, var(--text-secondary));
	}
	.ssm-note--warn .ssm-note-dot {
		background: var(--warning-fg, var(--warning));
	}
	.ssm-note--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
	}
	.ssm-note--danger .ssm-note-dot {
		background: var(--danger-fg);
	}
	/* Group / people rows */
	.ssm-glist {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		max-height: 260px;
		overflow-y: auto;
	}
	.ssm-grow {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		min-height: 44px;
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-sm);
	}
	.ssm-grow:hover {
		background: var(--surface-hover);
	}
	.ssm-grow--disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}
	.ssm-gname {
		font-size: var(--text-sm);
		color: var(--text-primary);
		min-width: 0;
	}
	.ssm-meta {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
	}
	.ssm-reason-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
		background: none;
		border: none;
		padding: 2px;
		cursor: not-allowed;
		font-family: inherit;
		border-radius: var(--radius-xs);
	}
	.ssm-reason-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	/* Chip tray */
	.ssm-tray {
		border-top: 1px solid var(--border-default);
		padding-top: var(--space-3);
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.ssm-tray-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.ssm-tray-title {
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: var(--weight-medium);
		color: var(--text-tertiary);
	}
	.ssm-reach {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.ssm-chips {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
	}
	.ssm-chip {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		max-width: 220px;
	}
	.ssm-chip-kind {
		font-size: 9.5px;
		font-weight: var(--weight-bold, 700);
		letter-spacing: 0.03em;
		opacity: 0.7;
	}
	.ssm-chip-name {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.ssm-chip-x {
		display: inline-flex;
		align-items: center;
		background: none;
		border: none;
		padding: 0;
		cursor: pointer;
		opacity: 0.55;
		color: inherit;
		border-radius: var(--radius-xs);
	}
	.ssm-chip-x:hover {
		opacity: 1;
	}
	.ssm-chip-x:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.ssm-chip--dept {
		background: var(--accent-subtle);
		color: var(--accent-fg);
	}
	.ssm-chip--grp {
		background: var(--success-bg, var(--surface-2));
		color: var(--success-fg, var(--text-secondary));
	}
	.ssm-chip--usr {
		background: var(--warning-bg, var(--surface-2));
		color: var(--warning-fg, var(--text-secondary));
	}
	/* Footer */
	.ssm-foot {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		border-top: 1px solid var(--border-default);
		padding-top: var(--space-3);
	}
	.ssm-consequence {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.ssm-foot-actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.ssm-sr-only {
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
</style>
