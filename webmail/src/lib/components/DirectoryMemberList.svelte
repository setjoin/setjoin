<svelte:options runes={true} />

<script lang="ts">
	import type { DirectoryMember, DirectoryMembersResponse } from '$lib/stores/directory';
	import { directoryMembers } from '$lib/stores/directory';
	import { Avatar, Pagination } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { normalizeAddresses, addressKindKey } from '$lib/utils/directoryAddresses';
	import { t } from '$lib/i18n';

	let { departmentId = 0 } = $props();
	let members = $state<DirectoryMember[]>([]);
	let total = $state(0);
	let offset = $state(0);
	let loading = $state(false);

	const limit = 50;
	const page = $derived(Math.floor(offset / limit) + 1);

	async function load() {
		if (!departmentId) return;
		loading = true;
		try {
			const res: DirectoryMembersResponse = await directoryMembers(departmentId, offset, limit);
			members = res.list;
			total = res.total;
		} catch {
			members = [];
		} finally {
			loading = false;
		}
	}

	async function goToPage(p: number) {
		offset = Math.max(0, (p - 1) * limit);
		await load();
	}

	$effect(() => {
		if (departmentId) { offset = 0; load(); }
	});
</script>

<div class="member-list">
	{#if loading}
		<p class="loading-text">{t('directory.members.loading')}</p>
	{:else if members.length === 0}
		<p class="empty-text">{t('directory.members.empty')}</p>
	{:else}
		{#each members as m}
			{@const addr = normalizeAddresses(m.addresses, m.email)}
			<div class="member-card">
				<Avatar name={m.displayName} src={m.avatar?.blobId ? `/api/blobs/${m.avatar.blobId}` : ''} size="lg" />
				<div class="member-info">
					<div class="member-name">
						{m.displayName}
						{#if m.isManager}
							<span class="manager-badge" title={t('directory.members.manager')}>
								<Icon name="Star" size={12} />
							</span>
						{/if}
					</div>
					{#if m.jobTitle}<div class="member-title">{m.jobTitle}</div>{/if}
					{#if m.department}<div class="member-dept">{m.department}</div>{/if}
					<div class="member-contact">
						<a href="mailto:{addr.primary}">{addr.primary}</a>
						{#if m.phone}<span class="member-phone"> · {m.phone}</span>{/if}
					</div>
					{#if addr.hasMultiple}
						<ul class="member-addresses" aria-label={t('directory.address.other')}>
							{#each addr.secondary as a (a.email)}
								<li>
									<a href="mailto:{a.email}">{a.email}</a>
									<span class="address-kind">{t(addressKindKey(a.type))}</span>
								</li>
							{/each}
						</ul>
					{/if}
				</div>
			</div>
		{/each}

		{#if total > limit}
			<Pagination
				{page}
				pageSize={limit}
				{total}
				pageSizeOptions={[limit]}
				onPageChange={goToPage}
			/>
		{/if}
	{/if}
</div>

<style>
	.member-list {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.loading-text, .empty-text {
		color: var(--text-tertiary);
		font-size: var(--text-sm);
		padding: 1rem;
	}
	.member-card {
		display: flex;
		gap: 0.75rem;
		padding: 0.5rem;
		border-radius: var(--radius-md);
		border-bottom: 1px solid var(--border-default);
	}
	.member-card:hover {
		background: var(--surface-hover);
	}
	.member-info {
		flex: 1;
		min-width: 0;
	}
	.member-name {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		font-weight: 600;
		font-size: var(--text-md);
		color: var(--text-primary);
	}
	.manager-badge {
		display: inline-flex;
		color: var(--warning-fg);
	}
	.member-title {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.member-dept {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.member-contact {
		font-size: var(--text-xs);
		margin-top: 0.15rem;
	}
	.member-contact a {
		color: var(--text-accent);
		text-decoration: none;
	}
	.member-contact a:hover {
		text-decoration: underline;
	}
	.member-phone {
		color: var(--text-tertiary);
	}
	.member-addresses {
		list-style: none;
		margin: 0.15rem 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 0.1rem;
	}
	.member-addresses li {
		font-size: var(--text-xs);
		display: flex;
		align-items: baseline;
		gap: 0.35rem;
		min-width: 0;
	}
	.member-addresses a {
		color: var(--text-accent);
		text-decoration: none;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.member-addresses a:hover {
		text-decoration: underline;
	}
	.address-kind {
		flex: none;
		font-size: var(--text-2xs);
		text-transform: uppercase;
		letter-spacing: var(--tracking-caps);
		color: var(--text-tertiary);
	}
</style>
