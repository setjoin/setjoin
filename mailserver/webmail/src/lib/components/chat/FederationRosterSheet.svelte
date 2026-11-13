<svelte:options runes={true} />

<script lang="ts">
	// FederationRosterSheet — Pillar C2 Task 7. The room-federation roster
	// surface: any channel member may open it (federation_room_roster's own
	// R1 proof — no min-role restriction), but the invite/remove/re-admit
	// affordances only render for a hub-shaped room's owner/admin
	// (`canManage`) — a spoke mirror is read-only here by construction (its
	// mutating routes refuse BZ211 server-side; this sheet never even shows
	// the buttons that would hit that wall). The invite dialog carries the
	// RATIFIED Q1 divergence warning at invite time (not only in the export
	// manifest, per the grill hardening) — surfaced here, not a separate
	// component, since it only ever appears inside this flow.
	import * as chatApi from '$lib/chat/api';
	import type { FederationRoomRoster } from '$lib/chat/api';
	import { chatErrorMessage } from '$lib/chat/store.svelte';
	import { Dialog, Button, Input, Badge, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		open,
		channelId,
		canManage,
		onClose,
		onChanged,
	}: {
		open: boolean;
		channelId: number;
		canManage: boolean;
		onClose: () => void;
		/** Called after any successful invite/remove — lets the caller (ChatApp)
		 *  refresh its own header-badge copy of the roster without this sheet
		 *  owning that state. */
		onChanged?: () => void;
	} = $props();

	let loading = $state(false);
	let loadError = $state('');
	let roster = $state<FederationRoomRoster | null>(null);

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			roster = await chatApi.getFederationRoomRoster(channelId);
		} catch (e) {
			loadError = chatErrorMessage(e);
			roster = null;
		} finally {
			loading = false;
		}
	}

	// Reload whenever the sheet (re)opens for a (possibly different) channel —
	// the ChannelSettingsSheet reseed-guard pattern (lastKey), never mid-view.
	// Pillar C2 Task 7 review (M3): lastKey must be RESET on close, or
	// reopening for the SAME channel never refetches (the key `true:5` seen
	// on the first open is still lastKey when it reopens — `!open` on close
	// returned early WITHOUT clearing it) — the documented "remove last org
	// then reopen settings" flow would wedge on stale roster state until a
	// full page reload.
	let lastKey: string | null = null;
	$effect(() => {
		if (!open) {
			lastKey = null;
			return;
		}
		const key = `${open}:${channelId}`;
		if (lastKey === key) return;
		lastKey = key;
		void load();
	});

	let showInvite = $state(false);
	let inviteDomain = $state('');
	let inviteContact = $state('');
	let inviting = $state(false);

	function openInvite(prefillDomain = ''): void {
		inviteDomain = prefillDomain;
		inviteContact = '';
		showInvite = true;
	}

	async function submitInvite(): Promise<void> {
		const domain = inviteDomain.trim();
		const contact = inviteContact.trim();
		if (!domain || !contact) return;
		inviting = true;
		try {
			await chatApi.inviteFederationMember(channelId, domain, contact);
			showInvite = false;
			await load();
			onChanged?.();
		} catch (e) {
			showToast(chatErrorMessage(e), { variant: 'danger' });
		} finally {
			inviting = false;
		}
	}

	let removingDomain = $state<string | null>(null);

	async function doRemove(domain: string): Promise<void> {
		removingDomain = domain;
		try {
			await chatApi.removeFederationMember(channelId, domain);
			await load();
			onChanged?.();
		} catch (e) {
			showToast(chatErrorMessage(e), { variant: 'danger' });
		} finally {
			removingDomain = null;
		}
	}

	// Badge variant per Q9-split state (Task 7's plan text: "amber depth-warn
	// / red parked / revoked / left states") — depthWarn is an amber OVERLAY
	// on an otherwise-active member, not its own state.
	function stateVariant(state: string, depthWarn: boolean): 'success' | 'warning' | 'danger' | 'neutral' {
		if (state === 'active') return depthWarn ? 'warning' : 'success';
		if (state === 'parked' || state === 'revoked') return 'danger';
		return 'neutral';
	}
	function stateLabel(state: string): string {
		if (state === 'active') return t('chat.federation.roster.state.active');
		if (state === 'parked') return t('chat.federation.roster.state.parked');
		if (state === 'revoked') return t('chat.federation.roster.state.revoked');
		return t('chat.federation.roster.state.left');
	}
</script>

<Dialog {open} title={t('chat.federation.roster.title')} {onClose}>
	<div class="fed-roster">
		{#if loading}
			<Spinner size={20} />
		{:else if loadError}
			<p class="fed-roster__error" role="alert">{loadError}</p>
		{:else if roster}
			{#if !roster.isHub}
				<p class="fed-roster__hub-note">{t('chat.federation.roster.hub', { domain: roster.hubDomain })}</p>
			{/if}
			{#if roster.members.length === 0}
				<EmptyState title={t('chat.federation.roster.empty')} />
			{:else}
				<ul class="fed-roster__list">
					{#each roster.members as m (m.domain)}
						<li class="fed-roster__row">
							<Badge variant={stateVariant(m.state, m.depthWarn)} label={stateLabel(m.state)} />
							<span class="fed-roster__domain">{m.domain}</span>
							{#if m.depthWarn}
								<span
									class="fed-roster__warn-icon"
									title={t('chat.federation.roster.depthWarn')}
									aria-label={t('chat.federation.roster.depthWarn')}
								>
									<Icon name="AlertTriangle" size={14} />
								</span>
							{/if}
							{#if roster.isHub && canManage}
								{#if m.state === 'active' || m.state === 'parked'}
									<Button
										variant="ghost"
										size="sm"
										disabled={removingDomain === m.domain}
										onclick={() => void doRemove(m.domain)}
									>
										{t('chat.federation.roster.remove')}
									</Button>
								{:else}
									<Button variant="ghost" size="sm" onclick={() => openInvite(m.domain)}>
										{t('chat.federation.roster.readmit')}
									</Button>
								{/if}
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
			{#if roster.isHub && canManage}
				<Button variant="secondary" onclick={() => openInvite()}>{t('chat.federation.roster.invite')}</Button>
			{/if}
		{/if}
	</div>
	{#snippet footer()}
		<Button variant="secondary" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showInvite} title={t('chat.federation.invite.title')} onClose={() => (showInvite = false)}>
	<div class="fed-roster__invite-form">
		<p class="fed-roster__warning">{t('chat.federation.invite.warning')}</p>
		<Input
			label={t('chat.federation.invite.memberDomain')}
			hint={t('chat.federation.invite.memberDomainHint')}
			bind:value={inviteDomain}
		/>
		<Input
			label={t('chat.federation.invite.contactAddr')}
			hint={t('chat.federation.invite.contactAddrHint')}
			placeholder="user@domain.example"
			bind:value={inviteContact}
		/>
	</div>
	{#snippet footer()}
		<Button
			variant="primary"
			disabled={inviting || !inviteDomain.trim() || !inviteContact.trim()}
			onclick={() => void submitInvite()}
		>
			{inviting ? t('common.loading') : t('chat.federation.invite.submit')}
		</Button>
		<Button variant="secondary" onclick={() => (showInvite = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.fed-roster {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.fed-roster__error {
		font-size: var(--text-sm);
		color: var(--text-danger);
		margin: 0;
	}
	.fed-roster__hub-note {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.fed-roster__list {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.fed-roster__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.fed-roster__domain {
		flex: 1;
		font-size: var(--text-sm);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.fed-roster__warn-icon {
		color: var(--warning-solid);
		display: inline-flex;
	}
	.fed-roster__invite-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.fed-roster__warning {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
		white-space: pre-line;
	}
</style>
