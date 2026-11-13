<svelte:options runes={true} />

<!--
	ScopeSetEditor — create / edit dialog for an admin scope-set (spec §7B/§7D/§7I).
	Wraps ScopeSetMemberControl (members + reach + save bar) and owns: name +
	description fields with on-blur validation (required + duplicate → the 409
	message), the large-population confirm dialog, the unsaved-changes guard, the
	submit spinner, and the create-vs-edit save orchestration. Super-only
	(scope_sets.manage); every mutation is audited server-side.
-->

<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { Dialog, Input, Textarea, Button, showToast } from '$lib/components/ui';
	import ScopeSetMemberControl, { type ScopeChipMember } from './ScopeSetMemberControl.svelte';
	import {
		adminGetScopeSet,
		adminCreateScopeSet,
		adminUpdateScopeSet,
		adminAddScopeSetMember,
		adminRemoveScopeSetMember,
		adminDeptTree,
		adminListDirectoryGroups,
		getAuditPolicy,
		type ScopeSet,
		type TreeNode
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	interface Props {
		/** The set being edited (id + name + description); null/undefined = create. */
		set?: ScopeSet | null;
		/** Existing set names for instant on-blur duplicate detection. */
		existingNames?: string[];
		onClose: () => void;
		onSaved: () => void;
	}

	let { set = null, existingNames = [], onClose, onSaved }: Props = $props();

	// `set` is passed once when the dialog opens and never reactively changes;
	// snapshot it so seeding mutable state from it doesn't trip state_referenced_locally.
	const initial = untrack(() => set);
	const editing = initial != null;

	let name = $state(initial?.name ?? '');
	let description = $state(initial?.description ?? '');
	let members = $state<ScopeChipMember[]>([]);
	let originalKeys = $state<Set<string>>(new Set());

	let nameError = $state('');
	let error = $state('');
	let saving = $state(false);
	let showLargeConfirm = $state(false);
	let showDiscard = $state(false);

	// Audit-reason gate (no-op by default — reason_required_areas defaults to '{}').
	let reasonRequired = $state(false);
	let reason = $state('');

	// ponytail: an upper-bound seat count (members overlap, so this over-counts) —
	// only used to decide whether the large-population confirm fires. Real reach
	// resolution isn't exposed by the backend.
	const LARGE_THRESHOLD = 200;

	function memberKey(m: { memberType: string; memberId: number }): string {
		return `${m.memberType}:${m.memberId}`;
	}

	onMount(async () => {
		void getAuditPolicy()
			.then((p) => {
				reasonRequired = p.reasonRequiredAreas.includes('scope_sets');
			})
			.catch(() => {
				/* non-fatal: default = no prompt */
			});

		if (!editing || initial == null) return;
		// Resolve existing members to named chips (dept/group names; users fall back
		// to #id — there is no user-by-id endpoint).
		try {
			const [full, tree, groups] = await Promise.all([
				adminGetScopeSet(initial.id),
				adminDeptTree().catch(() => [] as TreeNode[]),
				adminListDirectoryGroups().catch(() => [])
			]);
			const deptMap = new Map<number, { name: string; userCount: number }>();
			const walk = (ns: TreeNode[]) => {
				for (const n of ns) {
					deptMap.set(n.id, { name: n.name, userCount: n.userCount });
					walk(n.children);
				}
			};
			walk(tree);
			const groupMap = new Map(groups.map((g) => [g.id, g]));
			const chips: ScopeChipMember[] = (full.members ?? []).map((m) => {
				if (m.memberType === 'ou') {
					const d = deptMap.get(m.memberId);
					return { memberType: 'ou', memberId: m.memberId, name: d?.name ?? m.label ?? `#${m.memberId}`, seats: d?.userCount ?? 0 };
				}
				if (m.memberType === 'group') {
					const g = groupMap.get(m.memberId);
					return { memberType: 'group', memberId: m.memberId, name: g?.name ?? m.label ?? `#${m.memberId}`, seats: g?.memberCount ?? 0 };
				}
				return { memberType: 'user', memberId: m.memberId, name: m.label ?? `#${m.memberId}`, seats: 1 };
			});
			members = chips;
			originalKeys = new Set(chips.map(memberKey));
			description = full.description ?? description;
		} catch (e) {
			error = parseError(e).message;
		}
	});

	function validateName(): boolean {
		const n = name.trim();
		if (!n) {
			nameError = t('admin.scope_sets.name_required');
			return false;
		}
		const dup = existingNames.some(
			(e) => e.toLowerCase() === n.toLowerCase() && !(editing && initial && e.toLowerCase() === initial.name.toLowerCase())
		);
		if (dup) {
			nameError = t('admin.scope_sets.name_duplicate');
			return false;
		}
		nameError = '';
		return true;
	}

	let dirty = $derived(
		name.trim() !== (initial?.name ?? '') ||
			description.trim() !== (initial?.description ?? '') ||
			members.length !== originalKeys.size ||
			members.some((m) => !originalKeys.has(memberKey(m)))
	);

	let saveDisabled = $derived(name.trim() === '' || (reasonRequired && reason.trim() === ''));

	function requestClose() {
		if (dirty) {
			showDiscard = true;
		} else {
			onClose();
		}
	}

	function onSaveClicked() {
		void doSave(false);
	}

	async function doSave(confirmedLarge: boolean) {
		if (!validateName()) return;
		if (members.length === 0) return;
		const seats = members.reduce((acc, m) => acc + (m.seats ?? 0), 0);
		if (!confirmedLarge && seats > LARGE_THRESHOLD) {
			showLargeConfirm = true;
			return;
		}
		saving = true;
		error = '';
		const r = reasonRequired ? reason.trim() || undefined : undefined;
		try {
			let id = initial?.id;
			if (id == null) {
				const created = await adminCreateScopeSet(
					{ name: name.trim(), description: description.trim() || undefined },
					r
				);
				id = created.id;
				for (const m of members) {
					await adminAddScopeSetMember(id, { memberType: m.memberType, memberId: m.memberId }, r);
				}
			} else {
				await adminUpdateScopeSet(id, { name: name.trim(), description: description.trim() }, r);
				const curKeys = new Set(members.map(memberKey));
				for (const m of members) {
					if (!originalKeys.has(memberKey(m))) {
						await adminAddScopeSetMember(id, { memberType: m.memberType, memberId: m.memberId }, r);
					}
				}
				for (const key of originalKeys) {
					if (!curKeys.has(key)) {
						const [mt, mid] = key.split(':');
						await adminRemoveScopeSetMember(id, { memberType: mt as ScopeChipMember['memberType'], memberId: Number(mid) }, r);
					}
				}
			}
			showToast(t('admin.scope_sets.saved'));
			onSaved();
			onClose();
		} catch (e) {
			const msg = parseError(e).message;
			if (/already exists/i.test(msg)) {
				nameError = msg;
			} else {
				error = msg;
			}
		} finally {
			saving = false;
		}
	}
</script>

<Dialog
	open
	wide
	title={editing ? t('admin.scope_sets.edit_title') : t('admin.scope_sets.new_title')}
	onClose={requestClose}
>
	{#snippet children()}
		<div class="sse">
			<p class="sse-super">{t('admin.scope_sets.super_only')}</p>

			{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

			<div class="sse-field">
				<Input
					label={t('admin.scope_sets.name_label')}
					hint={t('admin.scope_sets.name_hint')}
					error={nameError}
					bind:value={name}
					onblur={validateName}
					required
				/>
			</div>

			<div class="sse-field">
				<Textarea
					label={t('admin.scope_sets.description_optional')}
					bind:value={description}
					rows={2}
					maxlength={500}
				/>
			</div>

			{#if reasonRequired}
				<div class="sse-field">
					<Textarea
						label={t('admin.audit.reason.label')}
						hint={t('admin.audit.reason.helper', { area: 'scope_sets' })}
						bind:value={reason}
						rows={2}
						maxlength={1000}
					/>
				</div>
			{/if}

			<ScopeSetMemberControl
				bind:members
				{saving}
				{saveDisabled}
				onSave={onSaveClicked}
				onCancel={requestClose}
			/>
		</div>
	{/snippet}
</Dialog>

<!-- Large-population confirm (the one place a dialog is right — DESIGN.md §6) -->
{#if showLargeConfirm}
	<Dialog open title={t('admin.scope_sets.large_pop_title')} onClose={() => (showLargeConfirm = false)}>
		{#snippet children()}
			<p>{t('admin.scope_sets.large_pop_body', { n: String(members.reduce((a, m) => a + (m.seats ?? 0), 0)) })}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (showLargeConfirm = false)}>{t('common.cancel')}</Button>
			<Button variant="primary" onclick={() => { showLargeConfirm = false; void doSave(true); }}>
				{t('admin.scope_sets.confirm_save')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- Unsaved-changes guard (data loss → irreversible-dialog rule, DESIGN.md §6) -->
{#if showDiscard}
	<Dialog open title={t('admin.scope_sets.discard_title')} onClose={() => (showDiscard = false)}>
		{#snippet children()}
			<p>{t('admin.scope_sets.discard_body')}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (showDiscard = false)}>{t('admin.scope_sets.keep_editing')}</Button>
			<Button variant="danger" onclick={() => { showDiscard = false; onClose(); }}>{t('admin.scope_sets.discard')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sse {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		font-family: var(--font-sans);
	}
	.sse-super {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.sse-field {
		display: flex;
		flex-direction: column;
	}
</style>
