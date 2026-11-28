<svelte:options runes={true} />

<!--
	SharingDefaultEditor — create dialog for a sharing_defaults rule (spec §7).
	Owner scope (org domain / OU via DepartmentTreePicker / group) × audience
	(everyone / OU / group) × level (无/闲忙/详细 LevelSegment). The D4
	precedence note is inline. Submit errors render IN the dialog (role=alert).
	The backend upserts on the (scope, ref, audience, ref) key, so re-saving an
	existing combination edits it.
-->

<script lang="ts">
	import { Dialog, Button, Select } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import DepartmentTreePicker from '$lib/components/admin/DepartmentTreePicker.svelte';
	import LevelSegment from '$lib/components/LevelSegment.svelte';
	import {
		adminDomainList,
		adminListDirectoryGroups,
		type Domain,
		type DirectoryGroup,
		type SharingDefaultAdminRow
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';

	type OwnerScope = SharingDefaultAdminRow['ownerScope'];
	type Audience = SharingDefaultAdminRow['audience'];
	type Level = SharingDefaultAdminRow['level'];

	let {
		open = false,
		/** Locks the owner scope to one user — the §7 per-user override path. */
		lockUser = null,
		onSubmit,
		oncancel
	}: {
		open?: boolean;
		lockUser?: { userId: number; email: string } | null;
		onSubmit: (data: {
			ownerScope: OwnerScope;
			ownerRef: number;
			audience: Audience;
			audienceRef: number;
			level: Level;
		}) => Promise<void>;
		oncancel: () => void;
	} = $props();

	let ownerScope = $state<OwnerScope>('org');
	let ownerDomainId = $state('');
	let ownerOu = $state<{ scopeType: 'ou'; scopeId: number } | null>(null);
	let ownerGroupId = $state('');
	let audience = $state<Audience>('everyone');
	let audienceDomainId = $state('');
	let audienceOu = $state<{ scopeType: 'ou'; scopeId: number } | null>(null);
	let audienceGroupId = $state('');
	let level = $state<Level>('freebusy');
	let saving = $state(false);
	let error = $state('');

	let domains = $state<Domain[]>([]);
	let groups = $state<DirectoryGroup[]>([]);

	$effect(() => {
		if (!open) return;
		error = '';
		// Pickers are lazy-loaded once per open; failures surface inline.
		adminDomainList()
			.then((d) => (domains = d))
			.catch((e) => (error = parseError(e).message));
		adminListDirectoryGroups()
			.then((g) => (groups = g))
			.catch(() => {
				/* group picker stays empty — org/OU rules still work */
			});
	});

	const domainOptions = $derived([
		{ value: '', label: t('admin.sharing.editor.pick_domain') },
		...domains.map((d) => ({ value: String(d.id), label: d.name }))
	]);
	const groupOptions = $derived([
		{ value: '', label: t('admin.sharing.editor.pick_group') },
		...groups.map((g) => ({ value: String(g.id), label: g.name }))
	]);
	const scopeOptions = $derived(
		lockUser
			? [{ value: 'user', label: t('admin.sharing.scope.user') + ` — ${lockUser.email}` }]
			: [
					{ value: 'org', label: t('admin.sharing.scope.org') },
					{ value: 'ou', label: t('admin.sharing.scope.ou') },
					{ value: 'group', label: t('admin.sharing.scope.group') }
				]
	);
	const audienceOptions = $derived([
		{ value: 'everyone', label: t('admin.sharing.audience.everyone') },
		{ value: 'ou', label: t('admin.sharing.audience.ou') },
		{ value: 'group', label: t('admin.sharing.audience.group') }
	]);

	const effectiveScope = $derived<OwnerScope>(lockUser ? 'user' : ownerScope);

	function ownerRef(): number {
		if (lockUser) return lockUser.userId;
		if (ownerScope === 'org') return Number(ownerDomainId) || 0;
		if (ownerScope === 'ou') return ownerOu?.scopeId ?? 0;
		return Number(ownerGroupId) || 0;
	}

	function audienceRef(): number {
		if (audience === 'everyone') return Number(audienceDomainId) || 0;
		if (audience === 'ou') return audienceOu?.scopeId ?? 0;
		return Number(audienceGroupId) || 0;
	}

	async function save() {
		if (saving) return;
		const oRef = ownerRef();
		const aRef = audienceRef();
		if (!oRef || !aRef) {
			error = t('admin.sharing.editor.incomplete');
			return;
		}
		saving = true;
		error = '';
		try {
			await onSubmit({ ownerScope: effectiveScope, ownerRef: oRef, audience, audienceRef: aRef, level });
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}
</script>

<Dialog {open} title={t('admin.sharing.editor.title')} onClose={oncancel} wide>
	<div class="sde">
		<p class="sde__precedence">{t('admin.sharing.precedence_hint')}</p>

		<div class="sde__row">
			<Select
				label={t('admin.sharing.editor.owner_scope')}
				value={effectiveScope}
				options={scopeOptions}
				disabled={lockUser !== null}
				onchange={(e: Event) => (ownerScope = (e.currentTarget as HTMLSelectElement).value as OwnerScope)}
			/>
			{#if !lockUser}
				{#if ownerScope === 'org'}
					<Select
						label={t('admin.sharing.editor.domain')}
						value={ownerDomainId}
						options={domainOptions}
						onchange={(e: Event) => (ownerDomainId = (e.currentTarget as HTMLSelectElement).value)}
					/>
				{:else if ownerScope === 'group'}
					<Select
						label={t('admin.sharing.editor.group')}
						value={ownerGroupId}
						options={groupOptions}
						onchange={(e: Event) => (ownerGroupId = (e.currentTarget as HTMLSelectElement).value)}
					/>
				{/if}
			{/if}
		</div>
		{#if !lockUser && ownerScope === 'ou'}
			<div class="sde__tree">
				<span class="sde__tree-label">{t('admin.sharing.editor.department')}</span>
				<DepartmentTreePicker bind:value={ownerOu} embedded />
			</div>
		{/if}

		<div class="sde__row">
			<Select
				label={t('admin.sharing.editor.audience')}
				value={audience}
				options={audienceOptions}
				onchange={(e: Event) => (audience = (e.currentTarget as HTMLSelectElement).value as Audience)}
			/>
			{#if audience === 'everyone'}
				<Select
					label={t('admin.sharing.editor.audience_domain')}
					value={audienceDomainId}
					options={domainOptions}
					onchange={(e: Event) => (audienceDomainId = (e.currentTarget as HTMLSelectElement).value)}
				/>
			{:else if audience === 'group'}
				<Select
					label={t('admin.sharing.editor.group')}
					value={audienceGroupId}
					options={groupOptions}
					onchange={(e: Event) => (audienceGroupId = (e.currentTarget as HTMLSelectElement).value)}
				/>
			{/if}
		</div>
		{#if audience === 'ou'}
			<div class="sde__tree">
				<span class="sde__tree-label">{t('admin.sharing.editor.audience_department')}</span>
				<DepartmentTreePicker bind:value={audienceOu} embedded />
			</div>
		{/if}

		<div class="sde__level">
			<LevelSegment value={level} label={t('sharing.level_label')} onChange={(l) => (level = l)} />
		</div>

		{#if error}
			<p class="sde__error" role="alert">{error}</p>
		{/if}
	</div>

	{#snippet footer()}
		<Button variant="ghost" size="md" onclick={oncancel} disabled={saving}>{t('common.cancel')}</Button>
		<Button variant="primary" size="md" onclick={save} disabled={saving}>{t('common.save')}</Button>
	{/snippet}
</Dialog>

<style>
	.sde {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		min-width: 26rem;
	}
	.sde__precedence {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sde__row {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
		flex-wrap: wrap;
	}
	.sde__tree {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sde__tree-label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sde__level {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sde__error {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
</style>
