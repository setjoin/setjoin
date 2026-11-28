<svelte:options runes={true} />

<!--
	Admin scope-sets console (spec §7). Super-only (scope_sets.manage). Lists the
	named scope containers with a per-set member composition, opens ScopeSetEditor
	to create / edit, and deletes (blocked by the backend RESTRICT → the 409
	"N admins are scoped to this set" message surfaces inline).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { Card, Table, Button, Dialog, Spinner, showToast } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import ScopeSetEditor from '$lib/components/admin/ScopeSetEditor.svelte';
	import {
		adminListScopeSets,
		adminGetScopeSet,
		adminDeleteScopeSet,
		type ScopeSet
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let sets = $state<ScopeSet[]>([]);
	let composition = $state<Map<number, { depts: number; groups: number; users: number }>>(new Map());
	let loading = $state(true);
	let error = $state('');

	let editorOpen = $state(false);
	let editTarget = $state<ScopeSet | null>(null);

	let deleteTarget = $state<ScopeSet | null>(null);
	let deleteError = $state('');
	let deleting = $state(false);

	let canManage = $derived(hasPermission($adminPermissions, 'scope_sets.manage'));

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: t('admin.scope_sets.col_name') },
		{ key: 'reach', label: t('admin.scope_sets.col_reach') },
		{ key: 'actions', label: '' }
	];

	onMount(async () => {
		await load();
		// Deep link from the member-list "Scope set: …" chip → open that set.
		const id = $page.url.searchParams.get('id');
		if (id && Number.isFinite(Number(id))) {
			const target = sets.find((s) => s.id === Number(id));
			if (target && canManage) openEdit(target);
		}
	});

	async function load() {
		loading = true;
		error = '';
		try {
			sets = await adminListScopeSets();
			// The list endpoint carries no member composition; resolve it per set so
			// the list shows reach at a glance (sets are few — admin surface).
			const comp = new Map<number, { depts: number; groups: number; users: number }>();
			await Promise.all(
				sets.map(async (s) => {
					try {
						const full = await adminGetScopeSet(s.id);
						const m = full.members ?? [];
						comp.set(s.id, {
							depts: m.filter((x) => x.memberType === 'ou').length,
							groups: m.filter((x) => x.memberType === 'group').length,
							users: m.filter((x) => x.memberType === 'user').length
						});
					} catch {
						/* leave this row without a composition badge */
					}
				})
			);
			composition = comp;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editTarget = null;
		editorOpen = true;
	}

	function openEdit(s: ScopeSet) {
		editTarget = s;
		editorOpen = true;
	}

	function reachText(id: number): string {
		const c = composition.get(id);
		if (!c) return '—';
		return t('admin.scope_sets.reach_summary', {
			depts: String(c.depts),
			groups: String(c.groups),
			users: String(c.users)
		});
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		deleting = true;
		deleteError = '';
		try {
			await adminDeleteScopeSet(deleteTarget.id);
			showToast(t('admin.scope_sets.deleted'));
			deleteTarget = null;
			await load();
		} catch (e) {
			// The RESTRICT trigger 409 ("N admins are scoped to this set …") lands here.
			deleteError = parseError(e).message;
		} finally {
			deleting = false;
		}
	}
</script>

<div class="sj-admin-page">
	<header class="sj-admin-head">
		<div>
			<h1>{t('admin.scope_sets.title')}</h1>
			<p class="sj-sub">{t('admin.scope_sets.subtitle')}</p>
		</div>
		{#if canManage}
			<Button variant="primary" onclick={openCreate}>{t('admin.scope_sets.create')}</Button>
		{/if}
	</header>

	{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

	<Card flush={true}>
		{#if loading}
			<div class="sj-loading"><Spinner size={20} label={t('common.loading')} /></div>
		{:else if sets.length === 0}
			<div class="sj-empty-teach">
				<p class="sj-empty-title">{t('admin.scope_sets.none_title')}</p>
				<p class="sj-empty-body">{t('admin.scope_sets.none_body')}</p>
				{#if canManage}
					<Button variant="primary" onclick={openCreate}>{t('admin.scope_sets.create')}</Button>
				{/if}
			</div>
		{:else}
			{@const rows = sets as unknown as Record<string, unknown>[]}
			<Table columns={COLUMNS} {rows}>
				{#snippet cell(row, col)}
					{@const s = row as unknown as ScopeSet}
					{#if col.key === 'name'}
						<button type="button" class="sj-set-name" onclick={() => canManage && openEdit(s)}>
							<Icon name="Boxes" size={15} strokeWidth={1.75} aria-hidden={true} />
							<span>{s.name}</span>
						</button>
						{#if s.description}<div class="sj-sub">{s.description}</div>{/if}
					{:else if col.key === 'reach'}
						<span class="sj-reach">{reachText(s.id)}</span>
					{:else if col.key === 'actions'}
						{#if canManage}
							<Button variant="ghost" size="sm" onclick={() => openEdit(s)}>{t('admin.scope_sets.edit')}</Button>
							<Button variant="ghost" size="sm" onclick={() => { deleteTarget = s; deleteError = ''; }}>{t('common.delete')}</Button>
						{/if}
					{/if}
				{/snippet}
			</Table>
		{/if}
	</Card>
</div>

{#if editorOpen}
	<ScopeSetEditor
		set={editTarget}
		existingNames={sets.map((s) => s.name)}
		onClose={() => (editorOpen = false)}
		onSaved={load}
	/>
{/if}

{#if deleteTarget}
	<Dialog open title={t('admin.scope_sets.delete_title')} onClose={() => (deleteTarget = null)}>
		{#snippet children()}
			<p>{t('admin.scope_sets.delete_body', { name: deleteTarget!.name })}</p>
			{#if deleteError}<div class="sj-alert-danger" role="alert">{deleteError}</div>{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (deleteTarget = null)}>{t('common.cancel')}</Button>
			<Button variant="danger" disabled={deleting} onclick={() => void confirmDelete()}>
				{#if deleting}<Spinner size={16} label={t('common.loading')} />{/if}
				{t('common.delete')}
			</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-admin-page {
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.sj-admin-head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--space-3);
	}
	.sj-admin-head h1 {
		margin: 0;
	}
	.sj-sub {
		margin: 2px 0 0;
		color: var(--text-tertiary);
		font-size: var(--text-sm);
	}
	.sj-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-5, 24px);
	}
	.sj-set-name {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		background: none;
		border: none;
		padding: 0;
		cursor: pointer;
		font: inherit;
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-set-name:hover {
		color: var(--text-accent);
	}
	.sj-set-name:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-xs);
	}
	.sj-reach {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-empty-teach {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-2);
		padding: 32px 16px;
		text-align: center;
	}
	.sj-empty-title {
		margin: 0;
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.sj-empty-body {
		margin: 0;
		max-width: 420px;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
</style>
