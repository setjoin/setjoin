<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, IconButton, Input, Select } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { isEmail, normalize, validate } from '$lib/validation';
	import { contacts } from '$lib/stores/contacts';
	import { createGroup, renameGroup, setMembers } from '$lib/stores/contactGroups';
	import type { ContactCard, ContactGroup, ContactGroupMember } from '$lib/types/jmap';

	// `group` null → create mode; non-null → edit (rename + member edit) mode.
	let {
		open = false,
		group = null,
		onClose,
		onSaved
	}: {
		open?: boolean;
		group?: ContactGroup | null;
		onClose: () => void;
		onSaved?: () => void;
	} = $props();

	let name = $state('');
	let members = $state<ContactGroupMember[]>([]);
	let emailDraft = $state('');
	let pickContactId = $state('');
	let error = $state('');
	let saving = $state(false);

	// Snapshot the original members so an edit computes the add/remove delta.
	let originalMembers = $state<ContactGroupMember[]>([]);

	// Re-seed the form whenever the modal opens (or the target group changes).
	$effect(() => {
		if (!open) return;
		name = group?.name ?? '';
		// Build one local snapshot. Reading `members` again after assigning it
		// makes this effect subscribe to the state it writes and causes an
		// effect_update_depth_exceeded loop whenever the dialog opens.
		const seededMembers = group?.members ? group.members.map((m) => ({ ...m })) : [];
		members = seededMembers;
		originalMembers = seededMembers.map((m) => ({ ...m }));
		emailDraft = '';
		pickContactId = '';
		error = '';
	});

	// Contacts not already in the member list, offered in the picker.
	let availableContacts = $derived.by(() => {
		const chosen = new Set(members.map((m) => m.contactId).filter(Boolean) as string[]);
		return $contacts.filter((c: ContactCard) => !chosen.has(c.id));
	});

	function memberLabel(m: ContactGroupMember): string {
		return m.displayName || m.email || m.contactId || '';
	}

	function memberKey(m: ContactGroupMember): string {
		return m.contactId ? `c:${m.contactId}` : `e:${(m.email || '').toLowerCase()}`;
	}

	function addContactMember() {
		if (!pickContactId) return;
		const c = $contacts.find((x: ContactCard) => x.id === pickContactId);
		if (!c) return;
		const primary =
			c.emails?.find((e) => e.is_primary || e.type === 'work')?.address ||
			c.emails?.[0]?.address ||
			c.email ||
			'';
		members = [
			...members,
			{ contactId: c.id, email: primary, displayName: c.displayName || primary }
		];
		pickContactId = '';
	}

	function addEmailMember() {
		const addr = normalize(emailDraft);
		if (!addr) return;
		const res = validate({ email: [isEmail()] }, { email: addr });
		if (!res.valid) {
			error = res.errors.email ?? 'Invalid email address';
			return;
		}
		const lower = addr.toLowerCase();
		if (members.some((m) => !m.contactId && (m.email || '').toLowerCase() === lower)) {
			emailDraft = '';
			return;
		}
		members = [...members, { email: addr }];
		emailDraft = '';
		error = '';
	}

	function removeMember(m: ContactGroupMember) {
		const key = memberKey(m);
		members = members.filter((x) => memberKey(x) !== key);
	}

	function memberDelta() {
		const origKeys = new Set(originalMembers.map(memberKey));
		const curKeys = new Set(members.map(memberKey));
		// JMAP member patch carries only the discriminating field (contactId XOR email).
		const add = members
			.filter((m) => !origKeys.has(memberKey(m)))
			.map((m) => (m.contactId ? { contactId: m.contactId } : { email: m.email }));
		const remove = originalMembers
			.filter((m) => !curKeys.has(memberKey(m)))
			.map((m) => (m.contactId ? { contactId: m.contactId } : { email: m.email }));
		return { add, remove };
	}

	async function save() {
		if (saving) return;
		const trimmed = normalize(name);
		if (!trimmed) {
			error = t('contacts.group.name_required');
			return;
		}
		saving = true;
		error = '';
		try {
			let groupId = group?.id;
			if (groupId) {
				if (trimmed !== group!.name) await renameGroup(groupId, trimmed);
			} else {
				groupId = await createGroup(trimmed);
			}
			if (groupId) {
				const { add, remove } = group ? memberDelta() : { add: members.map((m) => (m.contactId ? { contactId: m.contactId } : { email: m.email })), remove: [] };
				if (add.length || remove.length) {
					await setMembers(groupId, add as ContactGroupMember[], remove as ContactGroupMember[]);
				}
			}
			onSaved?.();
			onClose();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}
</script>

<Dialog
	{open}
	title={group ? t('contacts.group.edit') : t('contacts.group.new')}
	onClose={onClose}
>
	{#snippet children()}
		<div class="cg-form">
			{#if error}<div class="cg-error" role="alert">{error}</div>{/if}
			<Input
				label={t('contacts.group.name')}
				bind:value={name}
				maxlength={255}
				placeholder={t('contacts.group.name')}
			/>

			<div class="cg-section-label">{t('contacts.group.members')}</div>
			{#if members.length === 0}
				<div class="cg-empty">{t('contacts.group.empty')}</div>
			{:else}
				<ul class="cg-members">
					{#each members as m (memberKey(m))}
						<li>
							<span class="cg-member-label">{memberLabel(m)}</span>
							<IconButton
								label={t('contacts.group.delete')}
								variant="ghost"
								size="sm"
								onclick={() => removeMember(m)}
							>
								<Icon name="X" size={14} />
							</IconButton>
						</li>
					{/each}
				</ul>
			{/if}

			<div class="cg-add-row">
				<Select
					bind:value={pickContactId}
					options={[
						{ value: '', label: t('contacts.group.add_member') },
						...availableContacts.map((c: ContactCard) => ({
							value: c.id,
							label: c.displayName || c.id
						}))
					]}
				/>
				<Button variant="secondary" size="sm" onclick={addContactMember} disabled={!pickContactId}>
					{t('contacts.group.add_member')}
				</Button>
			</div>

			<div class="cg-add-row">
				<Input
					type="email"
					bind:value={emailDraft}
					placeholder={t('contacts.group.add_email')}
					aria-label={t('contacts.group.add_email')}
				/>
				<Button variant="secondary" size="sm" onclick={addEmailMember} disabled={!emailDraft.trim()}>
					{t('contacts.group.add_email')}
				</Button>
			</div>
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="primary" disabled={saving} onclick={save}>
			{saving ? t('common.loading') : t('contacts.group.save')}
		</Button>
		<Button variant="secondary" onclick={onClose}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.cg-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.cg-error {
		color: var(--danger-fg);
		background: var(--danger-bg);
		font-size: var(--text-sm);
		padding: 0.4rem 0.6rem;
		border-radius: var(--radius-sm);
	}
	.cg-section-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.cg-empty {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}
	.cg-members {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.cg-members li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0.3rem 0.5rem;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.cg-member-label {
		font-size: var(--text-sm);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.cg-add-row {
		display: flex;
		gap: 0.5rem;
		align-items: flex-end;
	}
	.cg-add-row :global(.sj-select-wrap),
	.cg-add-row :global(.sj-field) {
		flex: 1;
		min-width: 0;
	}
</style>
