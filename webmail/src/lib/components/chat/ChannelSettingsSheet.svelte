<svelte:options runes={true} />

<script lang="ts">
	// ChannelSettingsSheet — A3 QoL Task 16. Gear icon in the conversation
	// header opens this. Two different authority levels share one sheet:
	// the per-channel notification level (Task 7) is the CALLER's own
	// preference — every member may set it, muting is not an admin
	// privilege — while post-permission/broadcast-permission (Task 8) are
	// channel-wide policy, owner/admin-only (BZ161). `canManage` (the same
	// selfRole==='owner'||'admin' check ChatApp already computes for
	// broadcast gating) decides whether the two permission selects render at
	// all; a plain member gets the notif-level control plus a one-line note
	// explaining why the rest is absent, never a disabled-and-confusing
	// select. DMs/group-DMs (`kind !== 'channel'`) never show the permission
	// selects even for a canManage caller — chat_channel_update's
	// post/broadcast params only ever mean something for a real channel.
	import { onDestroy } from 'svelte';
	import * as chatApi from '$lib/chat/api';
	import type { GuestPreview, RosterMember } from '$lib/chat/api';
	import { Dialog, Select, Input, Badge, Button, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { retentionNotice, chatErrorMessage } from '$lib/chat/store.svelte';
	import InviteGuestButton from '$lib/components/InviteGuestButton.svelte';
	import { effectiveCaps, isGuestSession } from '$lib/stores/session';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		inviteGuest as inviteGuestAdmin,
		reinviteGuest,
		InviteDeliveryUnconfirmedError,
	} from '$lib/admin/guests';

	let {
		open,
		channelId,
		kind,
		canManage,
		notifLevel,
		postPermission,
		broadcastPermission,
		classification = 'regular',
		retentionDays = null,
		federatedRoomId = null,
		isFederatedRoomHub = false,
		federatedRoomRemoved = false,
		roster = [],
		onClose,
		onSaved,
	}: {
		open: boolean;
		channelId: number;
		kind: string;
		canManage: boolean;
		notifLevel: 'all' | 'mentions' | 'none';
		postPermission: 'all' | 'admins';
		broadcastPermission: 'admins' | 'all';
		/** A4a Task 13 — read-only display: this sheet never edits compliance
		 *  state (that's Task 12's admin-only ChannelComplianceSheet). Optional
		 *  with a 'regular'/null default so every pre-A4a caller/test keeps
		 *  working untouched. */
		classification?: 'regular' | 'gxp';
		retentionDays?: number | null;
		/** Pillar C2 Task 7 — room-federation binding markers, threaded from
		 *  the conversation envelope. */
		federatedRoomId?: string | null;
		isFederatedRoomHub?: boolean;
		federatedRoomRemoved?: boolean;
		/** Guest G2: the already-fetched active channel roster. Lifecycle badges
		 *  render only from its server-projected external/removed booleans. */
		roster?: RosterMember[];
		onClose: () => void;
		onSaved: () => void;
	} = $props();

	let retention = $derived(retentionNotice(classification, retentionDays));

	// Seeded by the open-time run of the effect below, not directly from
	// props here (see SearchView's identical comment on this pattern).
	let editNotif = $state<'all' | 'mentions' | 'none'>('all');
	let editPost = $state<'all' | 'admins'>('all');
	let editBroadcast = $state<'admins' | 'all'>('admins');
	let saving = $state(false);
	let guestEmail = $state('');
	let guestPreview = $state<GuestPreview | null>(null);
	let guestPreviewing = $state(false);
	let guestAdding = $state(false);
	let guestInviting = $state(false);
	let guestDisplayName = $state('');
	let guestError = $state('');
	let guestSuccess = $state('');
	let guestDeliveryWarning = $state<{ guestUserId: number; inviteId: string } | null>(null);
	let guestInviteNeedsRefresh = $state(false);
	let guestPreviewBinding = $state<{ channelId: number; email: string } | null>(null);
	let guestPreviewRequestId = 0;

	function normalizedGuestEmail(): string {
		return guestEmail.trim().toLowerCase();
	}

	function invalidateGuestPreview(): void {
		guestPreviewRequestId += 1;
		guestPreview = null;
		guestPreviewBinding = null;
		guestPreviewing = false;
		guestDisplayName = '';
		guestError = '';
		guestSuccess = '';
		guestDeliveryWarning = null;
		guestInviteNeedsRefresh = false;
	}

	// Reseed the editable copies whenever the sheet is (re)opened for a
	// (possibly different) channel — never mid-edit, so a background
	// conversations reload can't clobber an in-progress edit.
	let lastKey: string | null = null;
	$effect(() => {
		const key = `${open}:${channelId}`;
		if (!open) {
			lastKey = null;
			invalidateGuestPreview();
			return;
		}
		if (lastKey === key) return;
		lastKey = key;
		editNotif = notifLevel;
		editPost = postPermission;
		editBroadcast = broadcastPermission;
		guestEmail = '';
		invalidateGuestPreview();
	});

	onDestroy(() => {
		guestPreviewRequestId += 1;
	});

	function resetGuestPreview(): void {
		invalidateGuestPreview();
	}

	async function previewExactGuest(): Promise<void> {
		const email = normalizedGuestEmail();
		if (!email) return;
		const previewChannelId = channelId;
		const requestId = ++guestPreviewRequestId;
		guestPreviewing = true;
		guestPreview = null;
		guestPreviewBinding = null;
		guestError = '';
		guestSuccess = '';
		try {
			const preview = await chatApi.previewGuest(previewChannelId, email);
			if (
				requestId !== guestPreviewRequestId ||
				!open ||
				channelId !== previewChannelId ||
				normalizedGuestEmail() !== email
			) return;
			guestPreview = preview;
			guestPreviewBinding = { channelId: previewChannelId, email };
			guestInviteNeedsRefresh = false;
		} catch (e) {
			if (requestId === guestPreviewRequestId) guestError = chatErrorMessage(e);
		} finally {
			if (requestId === guestPreviewRequestId) guestPreviewing = false;
		}
	}

	async function addPreviewedGuest(): Promise<void> {
		const preview = guestPreview;
		if (
			preview?.kind !== 'activeGuest' ||
			guestPreviewBinding?.channelId !== channelId ||
			guestPreviewBinding.email !== normalizedGuestEmail()
		) return;
		guestAdding = true;
		guestError = '';
		try {
			await chatApi.addMember(channelId, preview.userId);
			showToast(t('chat.guestAdd.added'), { variant: 'success' });
			onSaved();
			resetGuestPreview();
			guestEmail = '';
		} catch (e) {
			guestError = chatErrorMessage(e);
		} finally {
			guestAdding = false;
		}
	}

	async function inviteGuestDirect(): Promise<void> {
		const email = guestEmail.trim();
		const displayName = guestDisplayName.trim();
		if (!email || !displayName || !hasPermission($adminPermissions, 'guests.manage')) return;
		guestInviting = true;
		guestError = '';
		try {
			await inviteGuestAdmin({ email, displayName });
			guestDeliveryWarning = null;
			guestInviteNeedsRefresh = false;
			guestSuccess = t('chat.guestAdd.invited');
		} catch (e) {
			if (e instanceof InviteDeliveryUnconfirmedError) {
				guestDeliveryWarning = { guestUserId: e.guestUserId, inviteId: e.inviteId };
				guestSuccess = '';
			} else {
				// A lost response can hide a committed invite. Require an explicit
				// status refresh before the initial-create action is available again.
				guestInviteNeedsRefresh = true;
				guestError = t('chat.guestAdd.refreshBeforeRetry');
			}
		} finally {
			guestInviting = false;
		}
	}

	async function replaceUnconfirmedInvite(): Promise<void> {
		const warning = guestDeliveryWarning;
		if (!warning || guestInviting) return;
		guestInviting = true;
		guestError = '';
		try {
			await reinviteGuest(warning.guestUserId);
			guestDeliveryWarning = null;
			guestInviteNeedsRefresh = false;
			guestSuccess = t('chat.guestAdd.invited');
		} catch (e) {
			if (e instanceof InviteDeliveryUnconfirmedError) {
				guestDeliveryWarning = { guestUserId: e.guestUserId, inviteId: e.inviteId };
			} else {
				guestInviteNeedsRefresh = true;
				guestError = t('chat.guestAdd.refreshBeforeRetry');
			}
		} finally {
			guestInviting = false;
		}
	}

	async function save(): Promise<void> {
		saving = true;
		try {
			if (editNotif !== notifLevel) await chatApi.setChannelNotif(channelId, editNotif);
			if (canManage && kind === 'channel' && (editPost !== postPermission || editBroadcast !== broadcastPermission)) {
				await chatApi.updateChannel(channelId, { postPermission: editPost, broadcastPermission: editBroadcast });
			}
			onSaved();
			onClose();
		} finally {
			saving = false;
		}
	}

	// ── Pillar C2 Task 7: bind-to-federation + the Q13 archive-affordance
	// gating. Archiving needs to know whether a HUB room still has active
	// member orgs (federation_room_members is FORCE-RLS deny-all — only the
	// federation_room_roster DEFINER read can see it), so a hub-shaped
	// channel triggers its own small roster fetch on open, defaulting the
	// active-member count to a NON-ZERO (blocked) assumption until the fetch
	// resolves — never a flash of "enabled" before the truth is known. ─────
	let fedHubActiveCount = $state<number | null>(null);
	let binding = $state(false);
	let archiving = $state(false);

	// Pillar C2 Task 7 review (M3): fedKey must be RESET on close, or
	// reopening the sheet for the SAME channel never re-fetches the hub's
	// active-member count — the documented "remove last org, reopen settings,
	// archive still blocked" flow wedges on the stale count until reload.
	let fedKey: string | null = null;
	$effect(() => {
		if (!open) {
			fedKey = null;
			return;
		}
		const key = `${open}:${channelId}:${federatedRoomId}:${isFederatedRoomHub}`;
		if (fedKey === key) return;
		fedKey = key;
		if (!federatedRoomId || !isFederatedRoomHub) {
			fedHubActiveCount = null;
			return;
		}
		fedHubActiveCount = null; // unknown -> archive stays blocked until this resolves
		chatApi
			.getFederationRoomRoster(channelId)
			.then((r) => {
				fedHubActiveCount = r.members.filter((m) => m.state === 'active' || m.state === 'parked').length;
			})
			.catch(() => {
				fedHubActiveCount = null;
			});
	});

	// Q13 (the plan's own gate, enforced server-side by BZ209 — this is the
	// honesty affordance, not the enforcement): a hub may not archive while
	// any non-left member org remains; a spoke mirror may not archive while
	// still live (no self-serve leave in v1) EXCEPT once the hub has kicked
	// it (federatedRoomRemoved) — a purely local act at that point.
	let archiveDisabledReason = $derived.by(() => {
		if (!federatedRoomId) return null;
		if (isFederatedRoomHub) return fedHubActiveCount === 0 ? null : t('chat.federation.archive.hubBlocked');
		return federatedRoomRemoved ? null : t('chat.federation.archive.spokeBlocked');
	});

	async function bindFederation(): Promise<void> {
		binding = true;
		try {
			await chatApi.bindFederationRoom(channelId);
			onSaved();
		} catch (e) {
			showToast(chatErrorMessage(e), { variant: 'danger' });
		} finally {
			binding = false;
		}
	}

	async function archiveChannel(): Promise<void> {
		archiving = true;
		try {
			await chatApi.updateChannel(channelId, { archived: true });
			onSaved();
			onClose();
		} catch (e) {
			showToast(chatErrorMessage(e), { variant: 'danger' });
		} finally {
			archiving = false;
		}
	}
</script>

<Dialog {open} title={t('chat.settings.title')} {onClose}>
	<div class="chan-settings">
		<Select
			label={t('chat.settings.notifLevel')}
			bind:value={editNotif}
			options={[
				{ value: 'all', label: t('chat.settings.notifLevel.all') },
				{ value: 'mentions', label: t('chat.settings.notifLevel.mentions') },
				{ value: 'none', label: t('chat.settings.notifLevel.none') },
			]}
		/>
		{#if canManage && kind === 'channel'}
			<Select
				label={t('chat.settings.postPermission')}
				bind:value={editPost}
				options={[
					{ value: 'all', label: t('chat.settings.postPermission.all') },
					{ value: 'admins', label: t('chat.settings.postPermission.admins') },
				]}
			/>
			<Select
				label={t('chat.settings.broadcastPermission')}
				bind:value={editBroadcast}
				options={[
					{ value: 'all', label: t('chat.settings.broadcastPermission.all') },
					{ value: 'admins', label: t('chat.settings.broadcastPermission.admins') },
				]}
			/>
		{:else if kind === 'channel'}
			<p class="chan-settings__note">{t('chat.settings.adminOnlyNote')}</p>
		{/if}
		{#if retention}
			<div class="chan-settings__retention">
				<span class="chan-settings__retention-label">{t('chat.settings.retention')}</span>
				<p class="chan-settings__note">{retention}</p>
			</div>
		{/if}
		{#if roster.length > 0}
			<section class="chan-settings__members" aria-labelledby="channel-member-roster-heading">
				<h3 id="channel-member-roster-heading">{t('chat.guestAdd.members')}</h3>
				<ul>
					{#each roster as member (member.userId)}
						<li>
							<span>{member.displayName}</span>
							{#if member.external}<Badge label={t('chat.externalBadge')} />{/if}
							{#if member.removed}<Badge label={t('chat.removedBadge')} variant="warning" />{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}
		{#if canManage && kind === 'channel' && !$isGuestSession && $effectiveCaps.guestAccounts}
			<section class="chan-settings__guest-add" aria-labelledby="channel-guest-add-heading">
				<h3 id="channel-guest-add-heading">{t('chat.guestAdd.title')}</h3>
				<div class="chan-settings__guest-lookup">
					<Input
						label={t('chat.guestAdd.email')}
						type="email"
						bind:value={guestEmail}
						oninput={resetGuestPreview}
					/>
					<Button
						variant="secondary"
						disabled={guestPreviewing || !guestEmail.trim()}
						onclick={() => void previewExactGuest()}
					>
						{guestPreviewing ? t('common.loading') : t('chat.guestAdd.preview')}
					</Button>
				</div>
				{#if guestPreview?.kind === 'activeGuest'}
					<div class="chan-settings__guest-preview">
						<div class="chan-settings__guest-identity">
							<strong>{guestPreview.displayName}</strong>
							<Badge label={t('chat.externalBadge')} />
						</div>
						<p class="chan-settings__note">
							{guestPreview.historyFromJoin ? t('chat.guestAdd.historyJoin') : t('chat.guestAdd.historyFull')}
						</p>
						<Button variant="secondary" disabled={guestAdding} onclick={() => void addPreviewedGuest()}>
							{guestAdding ? t('common.loading') : t('chat.guestAdd.add')}
						</Button>
					</div>
				{:else if guestPreview?.kind === 'inviteRequired'}
					<div class="chan-settings__guest-preview">
						<p class="chan-settings__note">{t('chat.guestAdd.inviteRequired')}</p>
						{#if guestDeliveryWarning}
							<div class="chan-settings__delivery-warning" role="status" aria-live="polite">
								<strong>{t('chat.guestAdd.deliveryUnconfirmed')}</strong>
								<p class="chan-settings__note">{t('chat.guestAdd.deliveryUnconfirmedCopy')}</p>
								<code>{guestDeliveryWarning.inviteId}</code>
								<div class="chan-settings__guest-actions">
									<Button variant="secondary" disabled={guestPreviewing} onclick={() => void previewExactGuest()}>{t('chat.guestAdd.refreshStatus')}</Button>
									<Button variant="secondary" disabled={guestInviting} onclick={() => void replaceUnconfirmedInvite()}>{t('chat.guestAdd.createReplacement')}</Button>
								</div>
							</div>
						{:else if hasPermission($adminPermissions, 'guests.manage')}
							<Input label={t('chat.guestAdd.displayName')} bind:value={guestDisplayName} />
							<Button
								variant="secondary"
								disabled={guestInviting || guestInviteNeedsRefresh || !guestDisplayName.trim()}
								onclick={() => void inviteGuestDirect()}
							>
								{guestInviting ? t('common.loading') : t('chat.guestAdd.invite')}
							</Button>
						{:else}
							<InviteGuestButton guestAccountsEnabled={$effectiveCaps.guestAccounts} guestInviteEnabled={$effectiveCaps.guestInvite} />
						{/if}
					</div>
				{/if}
				<div class="chan-settings__guest-status" aria-live="polite">
					{#if guestSuccess}<p>{guestSuccess}</p>{/if}
					{#if guestError}<p class="chan-settings__error" role="alert">{guestError}</p>{/if}
				</div>
			</section>
		{/if}
		<!-- Pillar C2 Task 7 — the room-federation bind entry point (owner/admin,
		     real channel, not yet bound) and the Q13 archive affordance
		     (disabled+messaged while a hub still has active members, or a
		     spoke mirror is still live). -->
		{#if canManage && kind === 'channel' && !federatedRoomId}
			<Button variant="secondary" disabled={binding} onclick={() => void bindFederation()}>
				{binding ? t('common.loading') : t('chat.federation.bind.action')}
			</Button>
		{/if}
		{#if canManage && kind === 'channel' && federatedRoomId}
			<div class="chan-settings__archive">
				<Button
					variant="secondary"
					disabled={archiving || archiveDisabledReason != null}
					title={archiveDisabledReason ?? undefined}
					onclick={() => void archiveChannel()}
				>
					{archiving ? t('common.loading') : t('chat.federation.archive.action')}
				</Button>
				{#if archiveDisabledReason}
					<p class="chan-settings__note">{archiveDisabledReason}</p>
				{/if}
			</div>
		{/if}
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={saving} onclick={save}>{saving ? t('common.loading') : t('common.save')}</Button>
		<Button variant="secondary" onclick={onClose}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.chan-settings {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.chan-settings__note {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.chan-settings__retention {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.chan-settings__retention-label {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.chan-settings__archive {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		align-items: flex-start;
	}
	.chan-settings__members,
	.chan-settings__guest-add,
	.chan-settings__guest-preview {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-subtle);
	}
	.chan-settings__delivery-warning {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-2);
		border: 1px solid var(--warning-fg);
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		color: var(--warning-fg);
	}
	.chan-settings__guest-actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
	.chan-settings__members h3,
	.chan-settings__guest-add h3 {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.chan-settings__members ul {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.chan-settings__members li,
	.chan-settings__guest-identity {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
	}
	.chan-settings__guest-lookup {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto;
		align-items: end;
		gap: var(--space-2);
	}
	.chan-settings__guest-preview {
		padding: var(--space-2);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		align-items: flex-start;
	}
	.chan-settings__guest-status p {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--success-fg);
	}
	.chan-settings__guest-status .chan-settings__error {
		color: var(--danger-fg);
	}

	@media (max-width: 520px) {
		.chan-settings__guest-lookup {
			grid-template-columns: 1fr;
		}
	}
</style>
