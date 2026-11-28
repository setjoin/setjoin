<svelte:options runes={true} />

<script lang="ts">
	// TaskListMembersDialog.svelte — shared task lists (Phase 1): roster
	// management. Owner-only add row; a member may remove only themselves
	// (leave); the owner may remove anyone but themselves. Mirrors the
	// task_list_add_member/task_list_remove_member reducer authz exactly —
	// this dialog just surfaces the buttons the server already gates.
	import { loadSession } from '$lib/jmap/client';
	import { addTaskListMember, removeTaskListMember, taskLists } from '$lib/stores/taskLists';
	import { parseError } from '$lib/errors';
	import { Dialog, Button, IconButton, Input } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import type { TaskList } from '$lib/types/jmap';

	let { list, onClose }: { list: TaskList; onClose: () => void } = $props();

	// The store re-fetches TaskList/get on every add/remove — read the LIVE
	// roster for this list out of the shared store instead of the possibly-
	// stale snapshot passed in as a prop.
	const liveList = $derived($taskLists.find((l) => l.id === list.id) ?? list);
	const members = $derived(liveList.members ?? []);
	const isOwner = $derived(liveList.role === 'owner');

	let myEmail = $state('');
	let addEmail = $state('');
	let adding = $state(false);
	let addError = $state('');
	let removingId = $state<string | null>(null);

	$effect(() => {
		loadSession().then((s) => { myEmail = s.username; });
	});

	async function submitAdd() {
		const email = addEmail.trim();
		if (!email || adding) return;
		adding = true;
		addError = '';
		try {
			await addTaskListMember(list.id, email);
			addEmail = '';
		} catch (e) {
			addError = parseError(e).message;
		} finally {
			adding = false;
		}
	}

	async function remove(userId: string) {
		if (removingId) return;
		removingId = userId;
		try {
			await removeTaskListMember(list.id, userId);
		} catch (e) {
			addError = parseError(e).message;
		} finally {
			removingId = null;
		}
	}
</script>

<Dialog open={true} title={t('tasks.lists.members') + ': ' + liveList.name} onClose={onClose}>
	{#snippet children()}
		<table class="roster-table">
			<thead>
				<tr>
					<th>Name</th>
					<th>Role</th>
					<th><span class="sr-only">{t('tasks.lists.remove')}</span></th>
				</tr>
			</thead>
			<tbody>
				{#each members as m (m.userId)}
					<tr>
						<td>
							<div class="roster-name">{m.displayName || m.email}</div>
							<div class="roster-email">{m.email}</div>
						</td>
						<td class="roster-role">
							{m.role === 'owner' ? t('tasks.lists.roleOwner') : t('tasks.lists.roleMember')}
						</td>
						<td class="roster-actions">
							{#if m.role !== 'owner' && (isOwner || m.email === myEmail)}
								<IconButton
									label={m.email === myEmail ? t('tasks.lists.leave') : t('tasks.lists.remove')}
									variant="ghost"
									size="sm"
									disabled={removingId === m.userId}
									onclick={() => remove(m.userId)}
								>
									<Icon name="X" size={14} />
								</IconButton>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>

		{#if addError}
			<div class="roster-error" role="alert">{addError}</div>
		{/if}

		{#if isOwner}
			<form class="add-row" onsubmit={(e) => { e.preventDefault(); submitAdd(); }}>
				<Input
					value={addEmail}
					oninput={(e) => (addEmail = e.currentTarget.value)}
					placeholder={t('tasks.lists.addMemberPlaceholder')}
					aria-label={t('tasks.lists.addMember')}
					maxlength={320}
				/>
				<Button variant="secondary" size="sm" type="submit" disabled={adding || !addEmail.trim()}>
					{t('tasks.lists.addMember')}
				</Button>
			</form>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={onClose}>Close</Button>
	{/snippet}
</Dialog>

<style>
	.roster-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}

	.roster-table th {
		text-align: left;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-weight: var(--weight-semibold);
		padding: 0.3rem 0.5rem;
		border-bottom: 1px solid var(--border-subtle);
	}

	.roster-table td {
		padding: 0.4rem 0.5rem;
		border-bottom: 1px solid var(--border-subtle);
		vertical-align: middle;
	}

	.roster-name {
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.roster-email {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.roster-role {
		color: var(--text-secondary);
		font-size: var(--text-xs);
	}

	.roster-actions {
		width: 2.5rem;
	}

	.roster-error {
		margin-top: 0.75rem;
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.add-row {
		display: flex;
		gap: 0.5rem;
		align-items: flex-start;
		margin-top: 0.75rem;
	}

	.add-row :global(.sj-field) {
		flex: 1;
	}

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
</style>
