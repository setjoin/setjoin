<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';

	import { loadSession, uploadBlob, sha256Hex, putBlob } from '$lib/jmap/client';
	import { composeStore } from '$lib/stores/compose';
	import { PushHandlerStore } from '$lib/stores/pushHandler.svelte';
	import { parseError } from '$lib/errors';
	import { validate, required, maxLength, isEmail, normalize } from '$lib/validation';
	import {
		Dialog, Button, IconButton, Input, Select, Textarea,
		Avatar, Spinner, EmptyState, showToast
	} from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import PimShell from '$lib/components/PimShell.svelte';
	import {
		addressBooks, contacts, selectedAddressBookId, galResults,
		viewMode, searchText, isGAL, duplicates, duplicateContacts,
		loadAddressBooks, loadContacts, searchGAL,
		createContact, updateContact, deleteContact,
		findDuplicates, merge
	} from '$lib/stores/contacts';
	import type { ContactCard } from '$lib/types/jmap';
	import { directoryTree, directoryMembers, setDirectoryAccountId } from '$lib/stores/directory';
	import type { DirectoryNode, DirectoryMember } from '$lib/stores/directory';
	import DirectorySidebar from '$lib/components/DirectorySidebar.svelte';
	import DirectoryMemberList from '$lib/components/DirectoryMemberList.svelte';
	import ContactGroupModal from '$lib/components/ContactGroupModal.svelte';
	import CsvImportModal from '$lib/components/CsvImportModal.svelte';
	import { contactGroups, loadGroups, deleteGroup, expandGroup } from '$lib/stores/contactGroups';
	import type { ContactGroup } from '$lib/types/jmap';
	import { normalizeAddresses, addressKindKey } from '$lib/utils/directoryAddresses';
	import { t } from '$lib/i18n';

	let directoryMode = $state(localStorage.getItem('directoryMode') !== 'false');
	let dirNodes = $state<DirectoryNode[]>([]);
	let dirError = $state('');
	let selectedDeptId = $state<string | null>(null);
	let selectedDeptNumId = $state(0);
	let dirSearch = $state('');

	// Client-side filter of the directory tree by department name. Matched
	// nodes plus their ancestors are kept so the tree hierarchy is preserved.
	let filteredDirNodes = $derived.by(() => {
		const q = dirSearch.trim().toLowerCase();
		if (!q) return dirNodes;
		const byId = new Map(dirNodes.map((n) => [n.id, n]));
		const keep = new Set<string>();
		for (const n of dirNodes) {
			if (n.name.toLowerCase().includes(q)) {
				keep.add(n.id);
				let pid = n.parentId;
				while (pid && byId.has(pid) && !keep.has(pid)) {
					keep.add(pid);
					pid = byId.get(pid)!.parentId;
				}
			}
		}
		return dirNodes.filter((n) => keep.has(n.id));
	});

	let loading = $state(false);
	let abortController: AbortController | null = null;
	let error = $state('');
	let saving = $state(false);
	let deleting = $state(false);
	let importing = $state(false);
	let uploading = $state(false);
	let forwarding = $state(false);
	let showModal = $state(false);
	let modalMode = $state<'create' | 'edit' | 'detail'>('create');
	let editingContact = $state<ContactCard | null>(null);
	let formErrors = $state<Record<string, string>>({});

	// -- Personal contact groups (A4) --
	let showGroupModal = $state(false);
	let editingGroup = $state<ContactGroup | null>(null);
	let selectedGroupId = $state<string | null>(null);
	let groupMembers = $state<ContactCard[]>([]);
	// -- CSV import (A4) --
	let showCsvModal = $state(false);
	// -- Find & merge duplicates --
	let showDuplicates = $state(false);
	let merging = $state(false);
	// Per-cluster keep choice (keyed by shared email); default = most-complete.
	let keepChoice = $state<Record<string, string>>({});

	let form = $state({
		addressbookId: '',
		displayName: '',
		firstName: '',
		lastName: '',
		company: '',
		jobTitle: '',
		department: '',
		emails: [{ type: 'home', address: '' }],
		phones: [{ type: 'home', number: '' }],
		notes: '',
		avatar: ''
	});

	const push = new PushHandlerStore();

	onMount(async () => {
		try {
			await loadSession();
			setDirectoryAccountId($selectedAddressBookId || '-1');
			await loadAddressBooks();
			await loadDirectory();
			try {
				await loadGroups();
			} catch {
				// Groups are non-critical; a load failure shouldn't block the contacts UI.
			}
			if ($selectedAddressBookId) {
				await refreshContacts();
			}
			// Cross-tab/device reactivity: re-fetch on any Contact push
			// (notify_contact_state → contact:{mailbox_id}); the producer is already
			// live, this wires the consumer.
			push.register(['Contact'], (changes) => {
				if (changes && (changes as Record<string, unknown>).Contact) {
					refreshContacts();
				}
			});
		} catch (e) {
			error = parseError(e).message;
		}
	});

	onDestroy(() => {
		push.teardown();
	});

	function openCreateGroup() {
		editingGroup = null;
		showGroupModal = true;
	}

	function openEditGroup(g: ContactGroup) {
		editingGroup = g;
		showGroupModal = true;
	}

	async function handleDeleteGroup(g: ContactGroup) {
		try {
			await deleteGroup(g.id);
			if (selectedGroupId === g.id) {
				selectedGroupId = null;
				groupMembers = [];
			}
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// Selecting a group filters the main pane to its expanded recipients. The
	// group's resolved members render as lightweight contact cards.
	async function selectGroup(g: ContactGroup) {
		selectedGroupId = g.id;
		showDuplicates = false;
		isGAL.set(false);
		try {
			const recipients = await expandGroup(g.id);
			groupMembers = recipients.map((r, i) => ({
				id: `grp-${g.id}-${i}`,
				displayName: r.name || r.email,
				email: r.email,
				emails: [{ type: 'work', address: r.email }]
			})) as ContactCard[];
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function clearGroupSelection() {
		selectedGroupId = null;
		groupMembers = [];
	}

	// The list rendered in the main pane: a selected group's expanded members win,
	// otherwise GAL results or the address-book contacts.
	let displayedContacts = $derived(
		selectedGroupId ? groupMembers : $isGAL ? $galResults : $contacts
	);

	function onCsvDone() {
		showCsvModal = false;
		refreshContacts();
	}

	async function refreshContacts() {
		abortController?.abort();
		abortController = new AbortController();
		const signal = abortController.signal;
		loading = true;
		try {
			if ($isGAL) {
				await searchGAL($searchText, signal);
			} else {
				await loadContacts($selectedAddressBookId, $searchText, signal);
			}
		} catch (e) {
			if ((e as Error).name !== 'AbortError') {
				error = parseError(e).message;
			}
		} finally {
			loading = false;
		}
	}

	let searchTimeout: ReturnType<typeof setTimeout> | null = null;

	$effect(() => {
		clearTimeout(searchTimeout ?? undefined);
		searchTimeout = setTimeout(() => {
			if ($selectedAddressBookId || $searchText || $isGAL) {
				refreshContacts();
			}
		}, 300);
		return () => clearTimeout(searchTimeout ?? undefined);
	});

	function selectAddressBook(ab: { id: string; name: string }) {
		clearGroupSelection();
		showDuplicates = false;
		selectedAddressBookId.set(ab.id);
		isGAL.set(false);
	}

	function toggleGAL() {
		clearGroupSelection();
		showDuplicates = false;
		isGAL.update((v) => !v);
		if ($isGAL) {
			searchGAL($searchText);
		} else {
			refreshContacts();
		}
	}

	function openCreateModal() {
		modalMode = 'create';
		editingContact = null;
		form = {
			addressbookId: $selectedAddressBookId || '',
			displayName: '',
			firstName: '',
			lastName: '',
			company: '',
			jobTitle: '',
			department: '',
			emails: [{ type: 'home', address: '' }],
			phones: [{ type: 'home', number: '' }],
			notes: '',
			avatar: ''
		};
		showModal = true;
	}

	function openEditModal(contact: ContactCard) {
		modalMode = 'edit';
		editingContact = contact;
		form = {
			addressbookId: contact.addressbookId || $selectedAddressBookId || '',
			displayName: contact.displayName || '',
			firstName: contact.firstName || '',
			lastName: contact.lastName || '',
			company: contact.company || '',
			jobTitle: contact.jobTitle || '',
			department: contact.department || '',
			emails: contact.emails?.length ? contact.emails : [{ type: 'home', address: '' }],
			phones: contact.phones?.length ? contact.phones : [{ type: 'home', number: '' }],
			notes: contact.notes || '',
			avatar: typeof contact.avatar === 'string' ? contact.avatar : contact.avatar?.blobId || ''
		};
		showModal = true;
	}

	function openDetailModal(contact: ContactCard) {
		modalMode = 'detail';
		editingContact = contact;
		showModal = true;
	}

	function closeModal() {
		showModal = false;
		editingContact = null;
	}

	function addEmail() {
		form.emails = [...form.emails, { type: 'home', address: '' }];
	}
	function removeEmail(i: number) {
		form.emails = form.emails.filter((_, idx) => idx !== i);
	}
	function addPhone() {
		form.phones = [...form.phones, { type: 'home', number: '' }];
	}
	function removePhone(i: number) {
		form.phones = form.phones.filter((_, idx) => idx !== i);
	}

	async function saveContact() {
		if (saving) return;
		error = '';
		formErrors = {};
		const result = validate({
			displayName: [required('Display name is required'), maxLength(255)],
			firstName:   [maxLength(128)],
			lastName:    [maxLength(128)],
			company:     [maxLength(128)],
			jobTitle:    [maxLength(128)],
			department:  [maxLength(128)],
			notes:       [maxLength(5000)],
		}, {
			displayName: normalize(form.displayName),
			firstName:   normalize(form.firstName),
			lastName:    normalize(form.lastName),
			company:     normalize(form.company),
			jobTitle:    normalize(form.jobTitle),
			department:  normalize(form.department),
			notes:       normalize(form.notes),
		});
		if (!result.valid) { formErrors = result.errors; return; }
		// Validate emails
		for (const email of form.emails) {
			if (email.address && email.address.trim()) {
				const eResult = validate({ email: [isEmail()] }, { email: normalize(email.address) });
				if (!eResult.valid) { formErrors.emails = 'One or more email addresses are invalid'; return; }
			}
		}
		// Validate phones
		for (const phone of form.phones) {
			if (phone.number && phone.number.trim()) {
				const pResult = validate({ phone: [maxLength(32)] }, { phone: normalize(phone.number) });
				if (!pResult.valid) { formErrors.phones = 'One or more phone numbers are too long'; return; }
			}
		}
		saving = true;
		try {
			const data: Partial<ContactCard> = {
				addressbookId: form.addressbookId,
				displayName: form.displayName,
				firstName: form.firstName,
				lastName: form.lastName,
				company: form.company,
				jobTitle: form.jobTitle,
				department: form.department,
				emails: form.emails.filter((e) => e.address),
				phones: form.phones.filter((p) => p.number),
				notes: form.notes,
				avatar: form.avatar
			};
			if (modalMode === 'create') {
				await createContact(data);
			} else {
				await updateContact(editingContact!.id, data);
			}
			closeModal();
			await refreshContacts();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function handleDelete() {
		if (!editingContact || deleting) return;
		error = '';
		deleting = true;
		try {
			await deleteContact(editingContact.id);
			closeModal();
			await refreshContacts();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			deleting = false;
		}
	}

	async function handlePhotoUpload(e: Event) {
		const target = e.currentTarget as HTMLInputElement;
		const file = target.files?.[0];
		if (!file || uploading) return;
		error = '';
		uploading = true;
		try {
			const result = await uploadBlob(file);
			form.avatar = result.blobId;
		} catch (err) {
			error = parseError(err).message;
		} finally {
			uploading = false;
		}
	}

	// #11 "Forward as business card": export the open contact as a single .vcf,
	// stage it as a blob (same hash+PUT path as any attachment), and hand off to
	// compose as a prefilled attachment. GAL contacts have no owned-contact row to
	// export (guarded by !$isGAL in the footer below).
	async function forwardAsVCard() {
		if (!editingContact || forwarding) return;
		error = '';
		forwarding = true;
		try {
			const res = await fetch(`/api/contacts/export/vcf?contactId=${editingContact.id}`);
			if (!res.ok) throw new Error(`export failed (${res.status})`);
			const text = await res.text();
			const displayName = editingContact.displayName || 'contact';
			const file = new File([text], `${displayName}.vcf`, { type: 'text/vcard' });
			const { blobId } = await uploadBlob(file);
			closeModal();
			composeStore.open({
				subject: t('contacts.forward_vcard_subject', { name: displayName }),
				attachments: [{ name: file.name, size: file.size, blobId, type: 'text/vcard' }]
			});
		} catch (e) {
			error = parseError(e).message;
		} finally {
			forwarding = false;
		}
	}

	async function importFromGAL() {
		if (!editingContact || importing) return;
		error = '';
		importing = true;
		try {
			await createContact({
				addressbookId: $selectedAddressBookId || editingContact.addressbookId || '',
				displayName: editingContact.displayName || '',
				firstName: editingContact.firstName || '',
				lastName: editingContact.lastName || '',
				company: editingContact.company || '',
				jobTitle: editingContact.jobTitle || '',
				department: editingContact.department || '',
				emails: editingContact.emails || [],
				phones: editingContact.phones || [],
				notes: editingContact.notes || ''
			});
			closeModal();
			await refreshContacts();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			importing = false;
		}
	}

	// avatarSrc mirrors the OrgChart/DirectoryMemberList blob-avatar pattern, but
	// ContactCard.avatar is `string | ContactAvatar` (a bare blobId or {blobId}) so
	// it narrows first. Empty → Avatar falls back to initials. A non-image/dead blob
	// just fails to load and shows nothing over the initials bg.
	function avatarSrc(c: ContactCard): string {
		const blobId = typeof c.avatar === 'string' ? c.avatar : c.avatar?.blobId;
		return blobId ? `/api/blobs/${blobId}` : '';
	}

	function getPrimaryEmail(contact: ContactCard) {
		// GAL/directory cards carry the full address set in `addresses` (ARCH-004);
		// personal contacts carry `emails`. Prefer the directory primary.
		if (contact.addresses?.length) {
			return normalizeAddresses(contact.addresses, contact.email).primary;
		}
		return contact.emails?.find((e) => e.is_primary || e.type === 'work')?.address
			|| contact.emails?.[0]?.address
			|| contact.email || '';
	}

	// -- Find & merge duplicates --

	async function runFindDuplicates() {
		error = '';
		loading = true;
		try {
			await findDuplicates();
			keepChoice = {};
			showDuplicates = true;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// Rough "how much data does this card carry" score, so the fuller contact is the
	// default keeper (the user can still override with the radio).
	function completeness(c: ContactCard): number {
		let n = (c.emails?.length ?? 0) + (c.phones?.length ?? 0);
		for (const v of [c.firstName, c.lastName, c.company, c.jobTitle, c.department, c.notes]) {
			if (v) n++;
		}
		return n;
	}

	// The chosen keeper id for a cluster: explicit radio pick, else the fullest card.
	function keepFor(cluster: { email: string; contactIds: string[] }): string {
		const picked = keepChoice[cluster.email];
		if (picked) return picked;
		let best = cluster.contactIds[0];
		let bestScore = -1;
		for (const id of cluster.contactIds) {
			const c = $duplicateContacts[id];
			const s = c ? completeness(c) : 0;
			if (s > bestScore) { bestScore = s; best = id; }
		}
		return best;
	}

	async function handleMerge(cluster: { email: string; contactIds: string[] }) {
		if (merging) return;
		const keepId = keepFor(cluster);
		// Drop the first other member of the cluster; clusters >2 re-detect after.
		const dropId = cluster.contactIds.find((id) => id !== keepId);
		if (!dropId) return;
		error = '';
		merging = true;
		try {
			await merge(keepId, dropId);
			showToast(t('contacts.duplicates.merged'), { variant: 'success' });
		} catch (e) {
			error = parseError(e).message;
		} finally {
			merging = false;
		}
	}

	async function loadDirectory() {
		try {
			dirNodes = await directoryTree();
		} catch {
			dirError = 'Failed to load directory. Please try again.';
		}
	}

	function selectDepartment(id: string) {
		selectedDeptId = id;
		selectedDeptNumId = parseInt(id);
	}

	function toggleDirectoryMode() {
		directoryMode = !directoryMode;
		localStorage.setItem('directoryMode', String(directoryMode));
	}
</script>

{#if error}
	<div class="contacts-error">{error}</div>
{/if}

<PimShell title="Contacts">
		{#snippet sidebar()}
			{#if directoryMode}
				{#if dirError}
					<div class="contacts-error">{dirError}</div>
				{/if}
				<aside class="sidebar">
					<div class="dir-search-bar">
						<Input bind:value={dirSearch} placeholder="Search directory" aria-label="Search directory" size="md" />
					</div>
					<DirectorySidebar nodes={filteredDirNodes} onsetSelect={selectDepartment} />
					<div class="mode-toggle">
						<Button variant="secondary" size="sm" onclick={() => {}} disabled>Directory</Button>
						<Button variant="ghost" size="sm" onclick={toggleDirectoryMode}>Contacts</Button>
					</div>
				</aside>
			{:else}
				<aside class="sidebar">
					<h3>Address Books</h3>
					<ul>
						{#each $addressBooks as ab}
							<li class:active={!$isGAL && $selectedAddressBookId === ab.id}>
								<button onclick={() => selectAddressBook(ab)}>{ab.name}</button>
							</li>
						{/each}
					</ul>
					<div class="gal-toggle">
						<button class:active={$isGAL} onclick={toggleGAL}>Company Directory (GAL)</button>
					</div>
					<div class="groups-section">
						<div class="groups-head">
							<h3>{t('contacts.groups')}</h3>
							<IconButton label={t('contacts.group.new')} variant="ghost" size="sm" onclick={openCreateGroup}>
								<Icon name="Plus" size={14} />
							</IconButton>
						</div>
						{#if $contactGroups.length === 0}
							<p class="groups-empty">{t('contacts.group.empty')}</p>
						{:else}
							<ul class="groups-list">
								{#each $contactGroups as g (g.id)}
									<li class:active={selectedGroupId === g.id}>
										<button class="group-row" onclick={() => selectGroup(g)}>
											<span class="group-name">{g.name}</span>
											<span class="group-count">{t('contacts.group.member_count', { count: String(g.memberCount) })}</span>
										</button>
										<span class="group-actions">
											<IconButton label={t('contacts.group.edit')} variant="ghost" size="sm" onclick={() => openEditGroup(g)}>
												<Icon name="Pencil" size={13} />
											</IconButton>
											<IconButton label={t('contacts.group.delete')} variant="ghost" size="sm" onclick={() => handleDeleteGroup(g)}>
												<Icon name="Trash2" size={13} />
											</IconButton>
										</span>
									</li>
								{/each}
							</ul>
						{/if}
					</div>
					<div class="mode-toggle">
						<Button variant="ghost" size="sm" onclick={toggleDirectoryMode}>Directory</Button>
						<Button variant="secondary" size="sm" onclick={() => {}} disabled>Contacts</Button>
					</div>
				</aside>
			{/if}
		{/snippet}

		{#snippet topbarActions()}
			{#if directoryMode}
				<h4>{selectedDeptId ? (dirNodes.find(n => n.id === selectedDeptId)?.name || 'Department') : 'Company Directory'}</h4>
			{:else}
				<div class="search-bar">
					<Input bind:value={$searchText} placeholder="Search contacts" aria-label="Search contacts" maxlength={255} size="md" />
				</div>
				<div class="view-toggle">
					<IconButton label="List view" variant={$viewMode === 'list' ? 'outline' : 'ghost'} active={$viewMode === 'list'} onclick={() => viewMode.set('list')}>
						<Icon name="List" size={18} />
					</IconButton>
					<IconButton label="Grid view" variant={$viewMode === 'grid' ? 'outline' : 'ghost'} active={$viewMode === 'grid'} onclick={() => viewMode.set('grid')}>
						<Icon name="LayoutGrid" size={18} />
					</IconButton>
				</div>
				{#if !$isGAL}
					<Button variant="primary" size="md" onclick={openCreateModal}>
						New contact
					</Button>
					<Button variant="secondary" size="md" onclick={() => (showCsvModal = true)}>
						{t('contacts.import_csv')}
					</Button>
					<Button variant="secondary" size="md" onclick={() => { window.location.href = `/api/contacts/export/csv?addressBookId=${encodeURIComponent($selectedAddressBookId || '')}`; }}>
						{t('contacts.export_csv')}
					</Button>
					<Button variant="secondary" size="md" onclick={() => { window.location.href = `/api/contacts/export/vcf?addressBookId=${encodeURIComponent($selectedAddressBookId || '')}`; }}>
						{t('contacts.export_vcf')}
					</Button>
					<Button variant={showDuplicates ? 'primary' : 'secondary'} size="md" onclick={runFindDuplicates}>
						{t('contacts.duplicates.find')}
					</Button>
				{/if}
			{/if}
		{/snippet}

		{#snippet main()}
			{#if directoryMode}
				<DirectoryMemberList departmentId={selectedDeptNumId} />
			{:else if showDuplicates}
				<div class="dup-view">
					<div class="dup-head">
						<h4>{t('contacts.duplicates.count', { count: String($duplicates.length) })}</h4>
						<Button variant="ghost" size="sm" onclick={() => (showDuplicates = false)}>
							{t('contacts.duplicates.back')}
						</Button>
					</div>
					{#if loading}
						<div class="loading-state">
							<Spinner size={20} label={t('contacts.duplicates.title')} />
						</div>
					{:else if $duplicates.length === 0}
						<EmptyState title={t('contacts.duplicates.none')} />
					{:else}
						{#each $duplicates as cluster (cluster.email)}
							{@const members = cluster.contactIds.map((id) => $duplicateContacts[id]).filter(Boolean)}
							{#if members.length >= 2}
								<div class="dup-cluster">
									<div class="dup-email">{cluster.email}</div>
									<div class="dup-members">
										{#each members as m (m.id)}
											<label class="dup-member" class:keep={keepFor(cluster) === m.id}>
												<input
													type="radio"
													name={'keep-' + cluster.email}
													value={m.id}
													checked={keepFor(cluster) === m.id}
													onchange={() => (keepChoice = { ...keepChoice, [cluster.email]: m.id })}
													aria-label={t('contacts.duplicates.keep')}
												/>
												<Avatar name={m.displayName || ''} src={avatarSrc(m)} size="sm" />
												<div class="info">
													<div class="name">{m.displayName || getPrimaryEmail(m)}</div>
													{#if m.jobTitle || m.company}
														<div class="meta">{[m.jobTitle, m.company].filter(Boolean).join(' · ')}</div>
													{/if}
												</div>
											</label>
										{/each}
									</div>
									<div class="dup-actions">
										<Button variant="primary" size="sm" disabled={merging} onclick={() => handleMerge(cluster)}>
											{merging ? t('contacts.duplicates.merging') : t('contacts.duplicates.merge')}
										</Button>
									</div>
								</div>
							{/if}
						{/each}
					{/if}
				</div>
			{:else}
				{#if loading}
					<div class="loading-state">
						<Spinner size={20} label="Loading contacts" />
					</div>
				{:else if displayedContacts.length === 0}
					<EmptyState title="No contacts found" />
				{:else}
					<div class="contact-list" class:grid={$viewMode === 'grid'}>
						{#each displayedContacts as contact (contact.id)}
							<div
								class="contact-card"
								role="button"
								tabindex="0"
								onclick={() => openDetailModal(contact)}
								onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetailModal(contact); } }}
							>
								<Avatar name={contact.displayName || ''} src={avatarSrc(contact)} size="md" />
								<div class="info">
									<div class="name">{contact.displayName}</div>
									<div class="email">
										{getPrimaryEmail(contact)}
										{#if contact.addresses && normalizeAddresses(contact.addresses, contact.email).hasMultiple}
											{@const extra = normalizeAddresses(contact.addresses, contact.email).secondary.length}
											<span class="addr-more">{t('directory.address.more', { count: String(extra) })}</span>
										{/if}
									</div>
									{#if contact.jobTitle}
										<div class="meta">{contact.jobTitle}</div>
									{:else if contact.company}
										<div class="meta">{contact.company}</div>
									{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			{/if}
		{/snippet}
	</PimShell>

	<!-- Create / Edit modal -->
	<Dialog
		open={showModal && modalMode !== 'detail'}
		title={modalMode === 'create' ? 'New contact' : 'Edit contact'}
		onClose={closeModal}
		wide
	>
		{#snippet children()}
			<form class="contacts-form" onsubmit={(e) => { e.preventDefault(); saveContact(); }}>
				<div class="form-group">
					<label for="contact-photo">Photo</label>
					<input id="contact-photo" type="file" accept="image/*" onchange={handlePhotoUpload} disabled={uploading} />
					{#if uploading}
						<span class="upload-text">Uploading...</span>
					{/if}
					{#if form.avatar}
						<img src="/api/blobs/{form.avatar}" class="preview" alt="preview" />
					{/if}
				</div>
				<div class="form-row">
					<div class="form-group">
						<Input label="First Name" bind:value={form.firstName} maxlength={128} error={formErrors.firstName} />
					</div>
					<div class="form-group">
						<Input label="Last Name" bind:value={form.lastName} maxlength={128} error={formErrors.lastName} />
					</div>
				</div>
				<div class="form-group">
					<Input id="contact-displayName" label="Display Name" bind:value={form.displayName} maxlength={255} required error={formErrors.displayName} />
				</div>
				<div class="form-row">
					<div class="form-group">
						<Input label="Company" bind:value={form.company} maxlength={128} error={formErrors.company} />
					</div>
					<div class="form-group">
						<Input label="Job Title" bind:value={form.jobTitle} maxlength={128} error={formErrors.jobTitle} />
					</div>
				</div>
				<div class="form-group">
					<Input label="Department" bind:value={form.department} maxlength={128} error={formErrors.department} />
				</div>
				<div class="form-group">
					<Select label="Address Book" bind:value={form.addressbookId} options={$addressBooks.map(ab => ({ value: ab.id, label: ab.name }))} />
				</div>
				<div class="form-group">
					<div class="label-row">
						<span>Emails</span>
						<IconButton label="Add email" variant="ghost" size="sm" onclick={addEmail}>
							<Icon name="Plus" size={14} />
						</IconButton>
					</div>
					{#if formErrors.emails}<span class="field-error">{formErrors.emails}</span>{/if}
					{#each form.emails as email, i}
						<div class="multi-row">
							<Select bind:value={email.type} options={['home', 'work', 'other']} />
							<Input type="email" bind:value={email.address} placeholder="email@example.com" />
							{#if form.emails.length > 1}
								<IconButton label="Remove email" variant="ghost" size="sm" onclick={() => removeEmail(i)}>
									<Icon name="X" size={14} />
								</IconButton>
							{/if}
						</div>
					{/each}
				</div>
				<div class="form-group">
					<div class="label-row">
						<span>Phones</span>
						<IconButton label="Add phone" variant="ghost" size="sm" onclick={addPhone}>
							<Icon name="Plus" size={14} />
						</IconButton>
					</div>
					{#if formErrors.phones}<span class="field-error">{formErrors.phones}</span>{/if}
					{#each form.phones as phone, i}
						<div class="multi-row">
							<Select bind:value={phone.type} options={['home', 'work', 'mobile', 'other']} />
							<Input type="tel" bind:value={phone.number} placeholder="+1-555-0100" />
							{#if form.phones.length > 1}
								<IconButton label="Remove phone" variant="ghost" size="sm" onclick={() => removePhone(i)}>
									<Icon name="X" size={14} />
								</IconButton>
							{/if}
						</div>
					{/each}
				</div>
				<div class="form-group">
					<Textarea label="Notes" bind:value={form.notes} rows={3} maxlength={5000} error={formErrors.notes} />
				</div>
			</form>
		{/snippet}
		{#snippet footer()}
			<div class="form-actions">
				<Button variant="primary" type="submit" disabled={saving} onclick={saveContact}>
					{saving ? 'Saving...' : (modalMode === 'create' ? 'Create' : 'Save')}
				</Button>
				{#if modalMode === 'edit'}
					<Button variant="danger" size="sm" disabled={deleting} onclick={handleDelete}>
						{deleting ? 'Deleting...' : 'Delete'}
					</Button>
				{/if}
				<Button variant="secondary" onclick={closeModal}>Cancel</Button>
			</div>
		{/snippet}
	</Dialog>

	<!-- Detail modal -->
	<Dialog
		open={showModal && modalMode === 'detail'}
		title={editingContact?.displayName ?? ''}
		onClose={closeModal}
	>
		{#snippet children()}
			<div class="detail-content">
				<div class="detail-avatar">
					{#if editingContact}
						<Avatar name={editingContact.displayName || ''} src={avatarSrc(editingContact)} size="xl" />
					{/if}
				</div>
				{#if editingContact?.firstName || editingContact?.lastName}
					<div class="detail-row"><span class="label">Name:</span> {editingContact.firstName} {editingContact.lastName}</div>
				{/if}
				{#if editingContact?.company}
					<div class="detail-row"><span class="label">Company:</span> {editingContact.company}</div>
				{/if}
				{#if editingContact?.jobTitle}
					<div class="detail-row"><span class="label">Title:</span> {editingContact.jobTitle}</div>
				{/if}
				{#if editingContact?.department}
					<div class="detail-row"><span class="label">Department:</span> {editingContact.department}</div>
				{/if}
				{#if editingContact?.addresses?.length}
					{@const addr = normalizeAddresses(editingContact.addresses, editingContact.email)}
					<div class="detail-row">
						<span class="label">{t('directory.address.emails')}</span>
						<div class="multi">
							<div class="addr-line">
								<a href="mailto:{addr.primary}">{addr.primary}</a>
								<span class="addr-kind">{t('directory.address.primary')}</span>
							</div>
							{#each addr.secondary as a (a.email)}
								<div class="addr-line">
									<a href="mailto:{a.email}">{a.email}</a>
									<span class="addr-kind">{t(addressKindKey(a.type))}</span>
								</div>
							{/each}
						</div>
					</div>
				{:else if editingContact?.emails?.length}
					<div class="detail-row">
						<span class="label">{t('directory.address.emails')}</span>
						<div class="multi">
							{#each editingContact.emails as e}
								<div>{e.type}: {e.address}</div>
							{/each}
						</div>
					</div>
				{/if}
				{#if editingContact?.phones?.length}
					<div class="detail-row">
						<span class="label">Phones:</span>
						<div class="multi">
							{#each editingContact.phones as p}
								<div>{p.type}: {p.number}</div>
							{/each}
						</div>
					</div>
				{/if}
				{#if editingContact?.notes}
					<div class="detail-row"><span class="label">Notes:</span> {editingContact.notes}</div>
				{/if}
			</div>
		{/snippet}
		{#snippet footer()}
			<div class="detail-actions">
				{#if !$isGAL}
					<Button variant="secondary" size="sm" onclick={() => { modalMode = 'edit'; openEditModal(editingContact!); }}>Edit</Button>
					<Button variant="secondary" size="sm" disabled={forwarding} onclick={forwardAsVCard}>
						{forwarding ? t('contacts.forward_vcard_busy') : t('contacts.forward_vcard')}
					</Button>
					<Button variant="danger" size="sm" disabled={deleting} onclick={handleDelete}>
						{deleting ? 'Deleting...' : 'Delete'}
					</Button>
				{/if}
				{#if $isGAL}
					<Button variant="primary" size="sm" disabled={importing} onclick={importFromGAL}>
						{importing ? 'Importing...' : 'Add to Contacts'}
					</Button>
				{/if}
			</div>
		{/snippet}
	</Dialog>

	<!-- Personal contact group create/edit modal (A4) -->
	<ContactGroupModal
		open={showGroupModal}
		group={editingGroup}
		onClose={() => (showGroupModal = false)}
		onSaved={() => { if (selectedGroupId && editingGroup) selectGroup(editingGroup); }}
	/>

	<!-- CSV import modal (A4) -->
	<CsvImportModal
		open={showCsvModal}
		addressBookId={$selectedAddressBookId || ''}
		onClose={() => (showCsvModal = false)}
		onDone={onCsvDone}
	/>

<style>
	.contacts-error {
		color: var(--danger-fg);
		padding: 0.5rem 1rem;
		margin: 0;
		background: var(--danger-bg);
		font-size: var(--text-sm);
	}
	.sidebar {
		padding: 1rem;
	}
	.sidebar h3 {
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		color: var(--text-tertiary);
		margin: 0 0 0.5rem;
	}
	.sidebar ul {
		list-style: none;
		padding: 0;
		margin: 0;
	}
	.sidebar li {
		margin-bottom: 0.25rem;
	}
	.sidebar li.active button {
		background: var(--surface-selected);
		font-weight: var(--weight-semibold);
	}
	.sidebar button {
		width: 100%;
		text-align: left;
		background: none;
		border: none;
		padding: 0.4rem 0.6rem;
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sidebar button:hover {
		background: var(--surface-hover);
	}
	.gal-toggle {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid var(--border-default);
	}
	.gal-toggle button {
		width: 100%;
		padding: 0.5rem;
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.gal-toggle button.active {
		background: var(--accent);
		color: var(--text-inverse);
		border-color: var(--accent);
	}
	.groups-section {
		margin-top: 1rem;
		padding-top: 1rem;
		border-top: 1px solid var(--border-default);
	}
	.groups-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.groups-head h3 {
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		color: var(--text-tertiary);
		margin: 0;
	}
	.groups-empty {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0.4rem 0 0;
	}
	.groups-list {
		list-style: none;
		margin: 0.25rem 0 0;
		padding: 0;
	}
	.groups-list li {
		display: flex;
		align-items: center;
		gap: 0.2rem;
		border-radius: var(--radius-sm);
	}
	.groups-list li.active {
		background: var(--surface-selected);
	}
	.group-row {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		text-align: left;
		background: none;
		border: none;
		padding: 0.35rem 0.5rem;
		cursor: pointer;
		color: var(--text-primary);
	}
	.group-row:hover {
		background: var(--surface-hover);
		border-radius: var(--radius-sm);
	}
	.group-name {
		font-size: var(--text-sm);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 100%;
	}
	.group-count {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.group-actions {
		display: flex;
		gap: 0.1rem;
		opacity: 0;
	}
	.groups-list li:hover .group-actions,
	.groups-list li.active .group-actions {
		opacity: 1;
	}
	.search-bar {
		flex: 1;
		min-width: 200px;
	}
	.view-toggle {
		display: flex;
		gap: 0.25rem;
	}
	.contact-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0 1rem 1rem;
	}
	.contact-list.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
	}
	.contact-card {
		display: flex;
		gap: 0.75rem;
		padding: 0.75rem;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		cursor: pointer;
		align-items: center;
	}
	.contact-card:hover {
		background: var(--surface-hover);
	}
	.info {
		flex: 1;
		min-width: 0;
	}
	.name {
		font-weight: var(--weight-medium);
		font-size: var(--text-md);
		color: var(--text-primary);
	}
	.email {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.addr-more {
		margin-left: 0.35rem;
		font-size: var(--text-2xs);
		color: var(--text-accent);
		white-space: nowrap;
	}
	.meta {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.loading-state {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}

	/* Find & merge duplicates */
	.dup-view {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		padding: 0 1rem 1rem;
	}
	.dup-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.dup-head h4 {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.dup-cluster {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: 0.75rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.dup-email {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.dup-members {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.dup-member {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.5rem;
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		cursor: pointer;
	}
	.dup-member:hover {
		background: var(--surface-hover);
	}
	.dup-member.keep {
		border-color: var(--accent);
		background: var(--surface-selected);
	}
	.dup-actions {
		display: flex;
		justify-content: flex-end;
	}

	/* Form */
	.contacts-form {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.form-group {
		display: flex;
		flex-direction: column;
	}
	.form-group > label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin-bottom: 0.25rem;
	}
	.form-row {
		display: flex;
		gap: 0.5rem;
	}
	.form-row .form-group {
		flex: 1;
	}
	.form-actions {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
	}
	.multi-row {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.25rem;
		align-items: center;
	}
	.multi-row :global(.sj-select) {
		width: 7rem;
		flex: none;
	}
	.multi-row :global(.sj-input) {
		flex: 1;
		min-width: 0;
	}
	.preview {
		width: 60px;
		height: 60px;
		border-radius: 50%;
		object-fit: cover;
		margin-top: 0.25rem;
	}
	.upload-text {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.detail-content {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.detail-avatar {
		margin-bottom: 0.75rem;
	}
	.detail-row {
		font-size: var(--text-md);
		line-height: var(--leading-normal);
	}
	.detail-row .label {
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.detail-actions {
		display: flex;
		gap: 0.5rem;
		justify-content: flex-end;
	}
	.multi {
		margin-top: 0.25rem;
	}
	.addr-line {
		display: flex;
		align-items: baseline;
		gap: 0.4rem;
		min-width: 0;
	}
	.addr-line a {
		color: var(--text-accent);
		text-decoration: none;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.addr-line a:hover {
		text-decoration: underline;
	}
	.addr-kind {
		flex: none;
		font-size: var(--text-2xs);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		color: var(--text-tertiary);
	}
	.label-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.label-row > span {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.mode-toggle {
		margin-top: auto;
		padding-top: 0.75rem;
		border-top: 1px solid var(--border-default);
		display: flex;
		gap: 0.25rem;
	}
	.dir-search-bar {
		padding: 0.5rem 0;
	}
	.field-error {
		color: var(--danger-fg);
		font-size: var(--text-xs);
		display: block;
		margin-top: 0.2rem;
	}
</style>
