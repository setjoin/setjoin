<svelte:options runes={true} />

<!--
	ShareMailboxDialog — mailbox delegate grant/revoke (spec
	2026-06-27-sharing-delegation-design.md §6-B). Mirrors ShareCalendarDialog's
	shape: current-delegates list with revoke + an add-delegate row (grantee
	email + permission select over the mailbox_delegates levels, each with a
	one-line helper). Always the caller's own primary mailbox (server-forced).
	No default-scope section here (D2 — mailbox sharing is explicit-grant-only).
-->

<script lang="ts">
	import { Dialog, Button, Input, Select, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import {
		getSharingOverview,
		grantDelegate,
		revokeDelegate,
		type DelegatePermission,
		type SharingDelegate
	} from '$lib/api/sharing';
	import { parseError } from '$lib/errors';

	let {
		open = false,
		onClose,
		onChanged
	}: {
		open?: boolean;
		onClose: () => void;
		/** Fires after a successful grant or revoke so the host list can refresh. */
		onChanged?: () => void;
	} = $props();

	const PERMISSIONS: DelegatePermission[] = ['read', 'send_as', 'send_on_behalf', 'full_access', 'manage_calendar'];

	let delegates = $state<SharingDelegate[]>([]);
	let loading = $state(false);
	let loadError = $state('');
	let newEmail = $state('');
	let newPermission = $state<DelegatePermission>('read');
	let busy = $state(false);
	let actionError = $state('');
	let announce = $state('');

	$effect(() => {
		if (open) void refresh();
	});

	async function refresh() {
		loading = true;
		loadError = '';
		try {
			delegates = (await getSharingOverview()).delegates;
		} catch (e) {
			loadError = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	const permissionOptions = $derived(
		PERMISSIONS.map((p) => ({ value: p, label: t(`sharing.perm.${p}`) }))
	);

	async function add() {
		const email = newEmail.trim();
		if (!email || busy) return;
		busy = true;
		actionError = '';
		try {
			await grantDelegate(email, newPermission);
			showToast(t('sharing.granted_toast', { email }));
			announce = t('sharing.granted_toast', { email });
			newEmail = '';
			onChanged?.();
			await refresh();
		} catch (e) {
			actionError = parseError(e).message;
		} finally {
			busy = false;
		}
	}

	async function revoke(d: SharingDelegate) {
		if (busy) return;
		busy = true;
		actionError = '';
		try {
			await revokeDelegate(d.userId);
			announce = t('sharing.revoked_announce');
			onChanged?.();
			await refresh();
		} catch (e) {
			actionError = parseError(e).message;
		} finally {
			busy = false;
		}
	}
</script>

<Dialog {open} title={t('sharing.delegate_title')} onClose={onClose}>
	<div class="smd">
		<p class="smd__intro">{t('sharing.delegate_intro')}</p>

		<div class="smd__announce" role="status" aria-live="polite" aria-atomic="true">{announce}</div>

		<h4 class="smd__section">{t('sharing.current_delegates')}</h4>
		{#if loading}
			<ul class="smd__skeleton" role="status" aria-label={t('common.loading')}>
				{#each Array(2) as _unused}<li class="smd__skeleton-row"></li>{/each}
			</ul>
		{:else if loadError}
			<p class="smd__error" role="alert">
				{loadError}
				<Button variant="ghost" size="sm" onclick={refresh}>{t('common.retry')}</Button>
			</p>
		{:else if delegates.length === 0}
			<p class="smd__empty">{t('sharing.delegates_empty')}</p>
		{:else}
			<ul class="smd__list">
				{#each delegates as d (`${d.userId}-${d.permission}`)}
					<li class="smd__row">
						<div class="smd__person">
							<span class="smd__email">{d.email}</span>
							<span class="smd__level">{t(`sharing.perm.${d.permission}`)}</span>
						</div>
						<Button variant="ghost" size="sm" disabled={busy} onclick={() => revoke(d)}>
							{t('sharing.revoke')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}

		<div class="smd__add">
			<div class="smd__add-row">
				<Input label={t('sharing.grantee_email')} type="email" bind:value={newEmail} />
				<Select
					label={t('sharing.permission')}
					value={newPermission}
					options={permissionOptions}
					onchange={(e: Event) => (newPermission = (e.currentTarget as HTMLSelectElement).value as DelegatePermission)}
				/>
				<Button variant="primary" size="sm" disabled={busy} onclick={add}>
					{t('sharing.add_delegate')}
				</Button>
			</div>
			<p class="smd__helper">{t(`sharing.perm_help.${newPermission}`)}</p>
			{#if actionError}
				<p class="smd__error" role="alert">{actionError}</p>
			{/if}
		</div>
	</div>

	{#snippet footer()}
		<Button variant="secondary" size="md" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.smd {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		min-width: 24rem;
	}
	.smd__intro {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.smd__section {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.smd__announce {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.smd__skeleton {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.smd__skeleton-row {
		height: 44px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: smd-shimmer 1.4s ease-in-out infinite;
	}

	@media (prefers-reduced-motion: reduce) {
		.smd__skeleton-row {
			animation: none;
		}
	}

	@keyframes smd-shimmer {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.5;
		}
	}
	.smd__empty {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0;
	}
	.smd__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.smd__row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.smd__person {
		display: flex;
		flex-direction: column;
	}
	.smd__email {
		color: var(--text-primary);
	}
	.smd__level {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.smd__add {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		padding-top: var(--space-3);
	}
	.smd__add-row {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
	}
	.smd__helper {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.smd__error {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
</style>
