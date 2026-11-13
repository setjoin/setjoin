<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import type { DriveMember } from '$lib/drive/api';
	import { directorySearch, setDirectoryAccountId } from '$lib/stores/directory';
	import type { DirectoryMember } from '$lib/stores/directory';
	import { Dialog, Button, IconButton, Input, Select, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		open,
		spaceId,
		isManager,
		selfEmail,
		onClose,
		onLeft,
	}: {
		open: boolean;
		spaceId: number | null;
		isManager: boolean;
		selfEmail: string;
		onClose: () => void;
		/** Called after a successful self-leave — DriveApp reloads the space list
		 *  (the left space no longer belongs to `spaces`) and owns closing here. */
		onLeft?: () => void;
	} = $props();

	let members = $state<DriveMember[]>([]);
	let loading = $state(true);
	let error = $state('');
	let query = $state('');
	let results = $state<DirectoryMember[]>([]);
	let selected = $state<DirectoryMember | null>(null);
	let searching = $state(false);
	let searchError = $state('');
	let adding = $state(false);
	let searchGeneration = 0;
	let inviteRole = $state('viewer');

	function resetPicker() {
		searchGeneration += 1;
		query = '';
		results = [];
		selected = null;
		searching = false;
		searchError = '';
		inviteRole = 'viewer';
	}

	function close() {
		resetPicker();
		onClose();
	}

	async function load() {
		if (spaceId === null) return;
		loading = true;
		try {
			members = await api.listMembers(spaceId);
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (open && spaceId !== null) {
			// This sheet remains mounted when a manager switches spaces. Never
			// carry a person, role, or search from one grant context into another.
			resetPicker();
			void load();
		}
	});

	async function grant(userId: number, role: string): Promise<boolean> {
		if (spaceId === null) return false;
		try {
			await api.grantMember(spaceId, userId, role);
			await load();
			return true;
		} catch (e) {
			error = driveErrorMessage(e);
			return false;
		}
	}

	async function revoke(userId: number) {
		if (spaceId === null) return;
		try {
			await api.revokeMember(spaceId, userId);
			await load();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function leave() {
		const self = members.find((m) => m.email === selfEmail);
		if (!self) return;
		await revoke(self.userId);
		close();
		onLeft?.();
	}

	// The grant endpoint intentionally remains ID-based; directorySearch is the
	// existing authenticated identity resolver and returns users.id as a decimal
	// string. Its shared SQL visibility seam excludes guests, matching the Drive
	// reducer's authoritative prohibition on ad-hoc guest grants.
	async function runSearch() {
		selected = null;
		const generation = ++searchGeneration;
		const trimmed = query.trim();
		if (trimmed.length < 2) {
			results = [];
			searching = false;
			searchError = '';
			return;
		}

		searching = true;
		searchError = '';
		results = [];
		try {
			setDirectoryAccountId('-1');
			const found = await directorySearch(trimmed, 8);
			if (generation !== searchGeneration) return;
			const currentMemberIds = new Set(members.map((member) => member.userId));
			results = found.filter((candidate) => {
				const id = Number(candidate.id);
				return Number.isSafeInteger(id) && id > 0 && !currentMemberIds.has(id);
			});
		} catch {
			if (generation !== searchGeneration) return;
			results = [];
			searchError = t('drive.members.searchFailed');
		} finally {
			if (generation === searchGeneration) searching = false;
		}
	}

	function pick(candidate: DirectoryMember) {
		searchGeneration += 1;
		selected = candidate;
		query = '';
		results = [];
		searching = false;
		searchError = '';
	}

	function changeSelection() {
		selected = null;
		query = '';
		results = [];
		searchError = '';
	}

	async function submitInvite() {
		if (!selected || adding) return;
		const id = Number(selected.id);
		if (!Number.isSafeInteger(id) || id <= 0) {
			error = t('drive.members.invalidSelection');
			return;
		}
		adding = true;
		if (await grant(id, inviteRole)) changeSelection();
		adding = false;
	}
</script>

<Dialog {open} title={t('drive.members.title')} onClose={close}>
	{#if error}
		<p class="ms__error" role="alert">{error}</p>
	{/if}

	{#if isManager}
		<div class="ms__invite">
			<div class="ms__picker">
				{#if selected}
					<span class="ms__picker-label">{t('drive.members.person')}</span>
					<div class="ms__selection">
						<span>
							<strong>{selected.displayName || selected.email}</strong>
							<small>{selected.email}</small>
						</span>
						<Button variant="secondary" size="sm" onclick={changeSelection}>
							{t('drive.members.change')}
						</Button>
					</div>
				{:else}
					<Input
						label={t('drive.members.person')}
						placeholder={t('drive.members.searchPlaceholder')}
						autocomplete="off"
						bind:value={query}
						oninput={() => void runSearch()}
					/>
					<div class="ms__search-status" aria-live="polite">
						{#if searching}
							<span>{t('drive.members.searching')}</span>
						{:else if searchError}
							<span class="ms__search-error" role="alert">{searchError}</span>
						{:else if query.trim().length >= 2 && results.length === 0}
							<span>{t('drive.members.noResults')}</span>
						{/if}
					</div>
					{#if results.length > 0}
						<ul class="ms__results" aria-label={t('drive.members.searchResults')}>
							{#each results as candidate (candidate.id)}
								<li>
									<button type="button" class="ms__result" onclick={() => pick(candidate)}>
										<strong>{candidate.displayName || candidate.email}</strong>
										<small>{candidate.email}</small>
									</button>
								</li>
							{/each}
						</ul>
					{/if}
				{/if}
			</div>
			<Select label={t('drive.members.roleLabel')} bind:value={inviteRole} options={[
				{ value: 'viewer', label: t('drive.members.role.viewer') },
				{ value: 'editor', label: t('drive.members.role.editor') },
				{ value: 'manager', label: t('drive.members.role.manager') },
			]} />
			<Button variant="primary" size="sm" disabled={!selected || adding} onclick={submitInvite}>
				{t('drive.members.add')}
			</Button>
		</div>
	{/if}

	{#if loading}
		<div class="ms__loading"><Spinner /></div>
	{:else}
		<ul class="ms__list">
			{#each members as member (member.userId)}
				<li class="ms__row">
					<span class="ms__name">{member.displayName || member.email}</span>
					<span class="ms__role">{t(`drive.members.role.${member.role}`)}</span>
					{#if isManager && member.email !== selfEmail}
						<IconButton label={t('drive.members.remove')} size="sm" onclick={() => revoke(member.userId)}>
							<Icon name="X" size={14} />
						</IconButton>
					{:else if member.email === selfEmail && member.role !== 'manager'}
						<Button variant="ghost" size="sm" onclick={leave}>{t('drive.space.leave')}</Button>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</Dialog>

<style>
	.ms__invite {
		display: grid;
		grid-template-columns: minmax(0, 1fr) minmax(8rem, auto) auto;
		align-items: flex-end;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.ms__picker {
		position: relative;
		min-width: 0;
	}
	.ms__picker-label {
		display: block;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-bottom: 5px;
	}
	.ms__selection {
		min-height: var(--control-height);
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
	}
	.ms__selection > span,
	.ms__result {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}
	.ms__selection strong,
	.ms__selection small,
	.ms__result strong,
	.ms__result small {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.ms__selection strong,
	.ms__result strong {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.ms__selection small,
	.ms__result small,
	.ms__search-status {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.ms__search-status {
		min-height: 1.25rem;
		padding-top: var(--space-1);
	}
	.ms__search-error {
		color: var(--danger-fg);
	}
	.ms__results {
		position: absolute;
		z-index: 2;
		left: 0;
		right: 0;
		list-style: none;
		margin: 0;
		padding: var(--space-1);
		max-height: 14rem;
		overflow-y: auto;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		box-shadow: var(--shadow-md);
	}
	.ms__result {
		width: 100%;
		padding: var(--space-2);
		text-align: left;
		font: inherit;
		background: transparent;
		border: 0;
		border-radius: var(--radius-sm);
		cursor: pointer;
	}
	.ms__result:hover,
	.ms__result:focus-visible {
		background: var(--surface-hover);
		outline: none;
	}
	.ms__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0 0 var(--space-3);
	}
	.ms__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.ms__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.ms__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.ms__row:hover {
		background: var(--surface-hover);
	}
	.ms__name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: var(--text-sm);
	}
	.ms__role {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}

	@media (max-width: 640px) {
		.ms__invite {
			grid-template-columns: 1fr;
			align-items: stretch;
		}
	}
</style>
