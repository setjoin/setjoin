<svelte:options runes={true} />

<script lang="ts">
	import { Badge, Button, Card, Dialog, EmptyState, Input, Select, Spinner, Switch, Table, showToast } from '$lib/components/ui';
	import AppAccessEditor from '$lib/components/admin/AppAccessEditor.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { formatDate, formatDateTime, t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { focusTrap } from '$lib/actions/focusTrap';
	import {
		assignGuestProfile, createGuestProfile, deleteGuestProfile, disableGuest, enableGuest,
		extendGuest, getGuest, inviteGuest, listGuestProfileDomains, listGuestProfiles, listGuests,
		listGuestSponsorOptions, reinviteGuest, revokeGuestInvite, transferGuest, updateGuestProfile,
		InviteDeliveryUnconfirmedError, GuestInviteStateError, type GuestDetail, type GuestProfile, type GuestProfileDomain,
		type GuestProfileInput, type GuestStatus, type GuestSummary,
		type GuestSponsorOption,
	} from '$lib/admin/guests';
	import type { TableColumn } from '$lib/components/ui';

	type GuestRow = GuestSummary & Record<string, unknown>;
	type ProfileRow = GuestProfile & Record<string, unknown>;

	const guestColumns: TableColumn[] = [
		{ key: 'displayName', label: t('admin.guests.col.identity') },
		{ key: 'effectiveStatus', label: t('admin.guests.col.status') },
		{ key: 'expiresAt', label: t('admin.guests.col.expiry') },
		{ key: 'sponsorDisplayName', label: t('admin.guests.col.sponsor') },
		{ key: 'profileName', label: t('admin.guests.col.profile') },
		{ key: 'channelGrantCount', label: t('admin.guests.col.grants') },
	];
	const profileColumns: TableColumn[] = [
		{ key: 'name', label: t('admin.guests.profile.name') },
		{ key: 'apps', label: t('admin.guests.profile.apps') },
		{ key: 'assignedCount', label: t('admin.guests.profile.assignments') },
		{ key: 'actions', label: t('admin.guests.profile.actions') },
	];

	let guests = $state<GuestSummary[]>([]);
	let profiles = $state<GuestProfile[]>([]);
	let profileDomains = $state<GuestProfileDomain[]>([]);
	let detail = $state<GuestDetail | null>(null);
	let detailRequestedId = $state<number | null>(null);
	let detailRequestGeneration = 0;
	let loading = $state(false);
	let detailLoading = $state(false);
	let error = $state('');
	let loaded = $state(false);
	let assignedProfile = $state('');
	let lifecycle = $state<'disable' | 'enable' | 'extend' | null>(null);
	let lifecycleBusy = $state(false);
	let assignBusy = $state(false);
	let reinviteOpen = $state(false);
	let reinviteBusy = $state(false);
	let reinviteExpiryAt = $state('');
	let revokeBusy = $state(false);
	let deliveryWarnings = $state<Record<number, string>>({});
	let extendAt = $state('');
	let profileEditor = $state<GuestProfile | 'new' | null>(null);
	let profileDelete = $state<GuestProfile | null>(null);
	let profileBusy = $state(false);
	let profileForm = $state<GuestProfileInput>(blankProfile());
	let hostDomainId = $state('');
	let expiryDays = $state('');
	let transferOpen = $state(false);
	let transferBusy = $state(false);
	let sponsorSearch = $state('');
	let sponsorOptions = $state<GuestSponsorOption[]>([]);
	let selectedSponsor = $state('');

	let canView = $derived(hasPermission($adminPermissions, 'guests.view') || hasPermission($adminPermissions, 'guests.manage'));
	let canManage = $derived(hasPermission($adminPermissions, 'guests.manage'));
	let guestRows = $derived(guests as GuestRow[]);
	let profileRows = $derived(profiles as ProfileRow[]);
	let loadingGuest = $derived(guests.find((guest) => guest.id === detailRequestedId) ?? null);
	let canEnableGuest = $derived(detail?.status === 'disabled' && detail.effectiveStatus !== 'expired');
	let canDisableGuest = $derived(detail?.effectiveStatus === 'active' || detail?.effectiveStatus === 'invited');
	let reinviteNeedsExpiry = $derived(detail !== null && detail.expiresAt !== null && new Date(detail.expiresAt).getTime() <= Date.now());
	let reinviteExpiryError = $derived.by(() => {
		if (!reinviteExpiryAt) return '';
		const expiresAt = new Date(reinviteExpiryAt);
		return Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()
			? t('admin.guests.expiryFuture')
			: '';
	});
	let extendError = $derived.by(() => {
		if (!extendAt) return '';
		const expiresAt = new Date(extendAt);
		return Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()
			? t('admin.guests.expiryFuture')
			: '';
	});

	function blankProfile(): GuestProfileInput {
		return {
			hostDomainId: profileDomains[0]?.id ?? 0,
			name: '', canPost: true, historyFromJoin: true, allowDownload: false,
			allowMeetCreate: false, allowMeetHost: false, canInitiateDm: false,
			allowNativeShell: true, defaultExpiryDays: null, apps: ['chat'],
		};
	}

	function fail(e: unknown) {
		showToast(parseError(e).message, { variant: 'danger' });
	}

	async function loadAll() {
		loading = true;
		error = '';
		try {
			[guests, profiles, profileDomains] = await Promise.all([
				listGuests(), listGuestProfiles(), listGuestProfileDomains(),
			]);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function openDetail(id: number) {
		const generation = ++detailRequestGeneration;
		detailRequestedId = id;
		detail = null;
		detailLoading = true;
		try {
			const nextDetail = await getGuest(id);
			if (generation !== detailRequestGeneration || detailRequestedId !== id) return;
			if (deliveryWarnings[id] && nextDetail.pendingInvite?.inviteId !== deliveryWarnings[id]) {
				const nextWarnings = { ...deliveryWarnings };
				delete nextWarnings[id];
				deliveryWarnings = nextWarnings;
			}
			detail = nextDetail;
			assignedProfile = nextDetail.profileId === null ? '' : String(nextDetail.profileId);
		} catch (e) {
			if (generation === detailRequestGeneration && detailRequestedId === id) {
				// A current-request failure is terminal for this modal generation: do
				// not leave a backdrop/loading shell with no detail behind.
				closeDetail();
				fail(e);
			}
		} finally {
			if (generation === detailRequestGeneration) detailLoading = false;
		}
	}

	function closeDetail() {
		detailRequestGeneration += 1;
		detailRequestedId = null;
		detailLoading = false;
		detail = null;
	}

	async function refreshDetail() {
		if (detail) await openDetail(detail.id);
		await loadAll();
	}

	async function assignProfile() {
		if (!detail || assignBusy) return;
		assignBusy = true;
		try {
			await assignGuestProfile(detail.id, assignedProfile ? Number(assignedProfile) : null);
			showToast(t('admin.guests.profileAssigned'), { variant: 'success' });
			await refreshDetail();
		} catch (e) { fail(e); }
		finally { assignBusy = false; }
	}

	function openReinvite() {
		reinviteExpiryAt = '';
		reinviteOpen = true;
	}

	async function confirmReinvite() {
		if (!detail || reinviteBusy) return;
		if (reinviteNeedsExpiry && (!reinviteExpiryAt || reinviteExpiryError)) {
			showToast(t('admin.guests.reinviteExpiryRequired'), { variant: 'danger' });
			return;
		}
		reinviteBusy = true;
		try {
			await reinviteGuest(detail.id, reinviteNeedsExpiry ? new Date(reinviteExpiryAt).toISOString() : undefined);
			const nextWarnings = { ...deliveryWarnings };
			delete nextWarnings[detail.id];
			deliveryWarnings = nextWarnings;
			showToast(t('admin.guests.reinvited'), { variant: 'success' });
			reinviteOpen = false;
			await refreshDetail();
		} catch (e) {
			if (e instanceof InviteDeliveryUnconfirmedError) {
				deliveryWarnings = { ...deliveryWarnings, [e.guestUserId]: e.inviteId };
				reinviteOpen = false;
				await refreshDetail();
			} else fail(e);
		}
		finally { reinviteBusy = false; }
	}

	async function revokeCurrentInvite() {
		if (!detail?.pendingInvite || revokeBusy) return;
		revokeBusy = true;
		try {
			await revokeGuestInvite(detail.id, detail.pendingInvite.inviteId);
			const nextWarnings = { ...deliveryWarnings };
			delete nextWarnings[detail.id];
			deliveryWarnings = nextWarnings;
			showToast(t('admin.guests.inviteRevoked'), { variant: 'success' });
			await refreshDetail();
		} catch (e) {
			if (e instanceof GuestInviteStateError) {
				showToast(t(e.status === 409 ? 'admin.guests.inviteChanged' : 'admin.guests.inviteGone'), { variant: 'danger' });
				await refreshDetail();
			} else fail(e);
		} finally { revokeBusy = false; }
	}

	async function confirmLifecycle() {
		if (!detail || !lifecycle) return;
		if (lifecycle === 'extend' && (!extendAt || extendError)) return;
		lifecycleBusy = true;
		try {
			if (lifecycle === 'disable') await disableGuest(detail.id);
			if (lifecycle === 'enable') await enableGuest(detail.id);
			if (lifecycle === 'extend') await extendGuest(detail.id, new Date(extendAt).toISOString());
			showToast(t('admin.guests.lifecycleSaved'), { variant: 'success' });
			lifecycle = null;
			await refreshDetail();
		} catch (e) { fail(e); }
		finally { lifecycleBusy = false; }
	}

	async function loadSponsorOptions() {
		if (!detail) return;
		try {
			sponsorOptions = await listGuestSponsorOptions(detail.id, sponsorSearch);
			if (!sponsorOptions.some((option) => String(option.id) === selectedSponsor)) selectedSponsor = '';
		} catch (e) { fail(e); }
	}

	async function openTransfer() {
		transferOpen = true;
		sponsorSearch = '';
		selectedSponsor = '';
		sponsorOptions = [];
		await loadSponsorOptions();
	}

	async function confirmTransfer() {
		if (!detail || !selectedSponsor || transferBusy) return;
		transferBusy = true;
		try {
			const result = await transferGuest(detail.id, Number(selectedSponsor));
			showToast(t('admin.guests.transferSaved', {
				channels: String(result.channelOwnersTransferred), spaces: String(result.driveSpacesTransferred),
			}), { variant: 'success' });
			transferOpen = false;
			await refreshDetail();
		} catch (e) { fail(e); }
		finally { transferBusy = false; }
	}

	function editProfile(profile: GuestProfile | 'new') {
		profileEditor = profile;
		profileForm = profile === 'new' ? blankProfile() : {
			hostDomainId: profile.hostDomainId, name: profile.name, canPost: profile.canPost,
			historyFromJoin: profile.historyFromJoin, allowDownload: profile.allowDownload,
			allowMeetCreate: profile.allowMeetCreate, allowMeetHost: profile.allowMeetHost,
			canInitiateDm: profile.canInitiateDm, allowNativeShell: profile.allowNativeShell,
			defaultExpiryDays: profile.defaultExpiryDays, apps: [...profile.apps],
		};
		hostDomainId = String(profile === 'new' ? (profileDomains[0]?.id ?? '') : profile.hostDomainId);
		expiryDays = profile === 'new' ? '' : String(profile.defaultExpiryDays ?? '');
	}

	function setProfileApp(app: 'chat' | 'drive' | 'meet', enabled: boolean) {
		profileForm.apps = enabled
			? [...new Set([...profileForm.apps, app])]
			: profileForm.apps.filter((value) => value !== app);
	}

	async function saveProfile() {
		if (!profileEditor || !profileForm.name.trim() || Number(hostDomainId) <= 0) return;
		profileBusy = true;
		try {
			const input = { ...profileForm, hostDomainId: Number(hostDomainId), name: profileForm.name.trim(), defaultExpiryDays: expiryDays ? Number(expiryDays) : null };
			if (profileEditor === 'new') await createGuestProfile(input);
			else await updateGuestProfile(profileEditor.id, input);
			showToast(t('admin.guests.profileSaved'), { variant: 'success' });
			profileEditor = null;
			await loadAll();
		} catch (e) { fail(e); }
		finally { profileBusy = false; }
	}

	async function confirmProfileDelete() {
		if (!profileDelete) return;
		profileBusy = true;
		try {
			await deleteGuestProfile(profileDelete.id);
			showToast(t('admin.guests.profileDeleted'), { variant: 'success' });
			profileDelete = null;
			await loadAll();
		} catch (e) { fail(e); }
		finally { profileBusy = false; }
	}

	function statusVariant(status: GuestStatus): 'success' | 'warning' | 'danger' | 'neutral' {
		if (status === 'active') return 'success';
		if (status === 'invited') return 'warning';
		if (status === 'disabled') return 'danger';
		return 'neutral';
	}

	function lifecycleCopy(): string {
		if (!detail || !lifecycle) return '';
		if (lifecycle === 'disable') return t('admin.guests.disableCopy', { n: String(detail.channelGrantCount) });
		if (lifecycle === 'extend') return t('admin.guests.extendCopy', { n: String(detail.channelGrantCount) });
		return t('admin.guests.enableCopy');
	}

	function openLifecycle(action: 'disable' | 'enable' | 'extend') {
		lifecycle = action;
		if (action === 'extend') extendAt = '';
	}

	function grantPostingLabel(canPost: boolean | null): string {
		if (canPost === true) return t('admin.guests.canPost');
		if (canPost === false) return t('admin.guests.readOnly');
		return t('admin.guests.channelPolicy');
	}

	$effect(() => {
		if (canView && !loaded) {
			loaded = true;
			void loadAll();
		}
	});
</script>

<svelte:head><title>{t('admin.guests.title')} · setjoin</title></svelte:head>

<div class="guest-admin">
	<header class="guest-admin__header">
		<div>
			<h1>{t('admin.guests.title')}</h1>
			<p>{t('admin.guests.subtitle')}</p>
		</div>
		{#if canManage}<Button variant="primary" onclick={() => editProfile('new')}>{t('admin.guests.newProfile')}</Button>{/if}
	</header>

	{#if !canView}
		<EmptyState title={t('admin.guests.noAccess')} />
	{:else if error}
		<p class="guest-admin__error" role="alert">{error}</p>
	{:else if loading}
		<div class="guest-admin__loading"><Spinner /></div>
	{:else}
		<Card title={t('admin.guests.listTitle')} flush>
			{#if guests.length === 0}
				<EmptyState title={t('admin.guests.empty')} />
			{:else}
				<Table columns={guestColumns} rows={guestRows}>
					{#snippet cell(row, col)}
						{#if col.key === 'displayName'}
							<button class="guest-admin__identity" type="button" onclick={() => openDetail(row.id as number)}>{row.displayName as string}</button>
							<span class="guest-admin__email">{row.invitedEmail as string}</span>
							<Badge variant="info" label={t('admin.guests.external')} />
						{:else if col.key === 'effectiveStatus'}
							<Badge dot variant={statusVariant(row.effectiveStatus as GuestStatus)} label={t(`admin.guests.status.${row.effectiveStatus as string}`)} />
						{:else if col.key === 'expiresAt'}
							{row.expiresAt ? formatDate(row.expiresAt as string) : t('admin.guests.never')}
						{:else if col.key === 'sponsorDisplayName'}
							{(row.sponsorDisplayName as string | null) || '—'}
							{#if Boolean(row.sponsorNeedsReview)}<Badge variant="warning" label={t('admin.guests.sponsorReview')} />{/if}
						{:else if col.key === 'profileName'}
							{(row.profileName as string | null) || t('admin.guests.noProfile')}
						{:else if col.key === 'channelGrantCount'}
							{t('admin.guests.grantCount', { n: String(row.channelGrantCount) })}
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>

		<Card title={t('admin.guests.profilesTitle')} flush>
			{#if profiles.length === 0}
				<EmptyState title={t('admin.guests.profilesEmpty')} />
			{:else}
				<Table columns={profileColumns} rows={profileRows}>
					{#snippet cell(row, col)}
						{#if col.key === 'name'}{row.name as string}
						{:else if col.key === 'apps'}{(row.apps as string[]).map((app) => t(`app.${app}`)).join(', ') || '—'}
						{:else if col.key === 'assignedCount'}{String(row.assignedCount)}
						{:else if col.key === 'actions' && canManage}
							<div class="guest-admin__row-actions">
								<Button size="sm" variant="ghost" aria-label={t('admin.guests.editProfile', { name: row.name as string })} onclick={() => editProfile(row as ProfileRow)}>{t('common.edit')}</Button>
								<Button size="sm" variant="ghost" aria-label={t('admin.guests.deleteProfile', { name: row.name as string })} disabled={(row.assignedCount as number) > 0} onclick={() => profileDelete = row as ProfileRow}>{t('common.delete')}</Button>
							</div>
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>
	{/if}
</div>

{#if detailRequestedId !== null}
	<div class="guest-sheet-backdrop" aria-hidden="true" onclick={closeDetail}></div>
{/if}

{#if detailLoading && !detail}
	<div
		class="guest-sheet"
		role="dialog"
		aria-modal="true"
		aria-labelledby="guest-detail-loading-title"
		tabindex="-1"
		use:focusTrap={{ onEscape: closeDetail }}
	>
		<header class="guest-sheet__header">
			<div><h2 id="guest-detail-loading-title">{loadingGuest?.displayName ?? t('admin.guests.listTitle')}</h2></div>
			<button type="button" class="guest-sheet__close" aria-label={t('common.close')} onclick={closeDetail}><Icon name="X" size={18} /></button>
		</header>
		<div class="guest-sheet--loading"><Spinner /></div>
	</div>
{:else if detail}
	<div
		class="guest-sheet"
		role="dialog"
		aria-modal="true"
		aria-labelledby="guest-detail-title"
		tabindex="-1"
		use:focusTrap={{ onEscape: closeDetail }}
	>
		<header class="guest-sheet__header">
			<div><h2 id="guest-detail-title">{detail.displayName}</h2><p>{detail.invitedEmail}</p></div>
			<button type="button" class="guest-sheet__close" aria-label={t('common.close')} onclick={closeDetail}><Icon name="X" size={18} /></button>
		</header>
		<div class="guest-sheet__badges">
			<Badge variant="info" label={t('admin.guests.external')} />
			<Badge dot variant={statusVariant(detail.effectiveStatus)} label={t(`admin.guests.status.${detail.effectiveStatus}`)} />
			{#if detail.pendingInvite}<Badge variant="warning" label={t('admin.guests.invitePending')} />{/if}
		</div>
		<dl class="guest-sheet__facts">
			<div><dt>{t('admin.guests.col.expiry')}</dt><dd>{detail.expiresAt ? formatDateTime(detail.expiresAt) : t('admin.guests.never')}</dd></div>
			<div><dt>{t('admin.guests.col.sponsor')}</dt><dd>{detail.sponsorDisplayName || '—'} {#if detail.sponsorNeedsReview}<Badge variant="warning" label={t('admin.guests.sponsorReview')} />{/if}</dd></div>
			<div><dt>{t('admin.guests.created')}</dt><dd>{formatDateTime(detail.createdAt)}</dd></div>
			<div><dt>{t('admin.guests.updated')}</dt><dd>{formatDateTime(detail.updatedAt)}</dd></div>
		</dl>

		{#if deliveryWarnings[detail.id]}
			<section class="guest-sheet__delivery-warning" role="status" aria-live="polite">
				<h3>{t('admin.guests.deliveryUnconfirmed')}</h3>
				<p>{t('admin.guests.deliveryUnconfirmedCopy')}</p>
				<code>{deliveryWarnings[detail.id]}</code>
				<div class="guest-sheet__row-actions">
					<Button variant="secondary" onclick={refreshDetail}>{t('admin.guests.refreshStatus')}</Button>
					{#if canManage}<Button variant="secondary" onclick={openReinvite}>{t('admin.guests.createReplacement')}</Button>{/if}
				</div>
			</section>
		{/if}

		<section aria-labelledby="guest-current-invite-heading">
			<h3 id="guest-current-invite-heading">{t('admin.guests.currentInvite')}</h3>
			{#if detail.pendingInvite}
				<div class="guest-sheet__current-invite">
					<div class="guest-sheet__invite-title">
						<Badge dot variant="warning" label={t('admin.guests.inviteState.pending')} />
						<code>{detail.pendingInvite.inviteId}</code>
					</div>
					<dl class="guest-sheet__invite-meta">
						<div><dt>{t('admin.guests.inviteExpires')}</dt><dd>{formatDateTime(detail.pendingInvite.expiresAt)}</dd></div>
						<div><dt>{t('admin.guests.inviteCreatedBy')}</dt><dd>{detail.pendingInvite.createdByEmail || t('admin.guests.creatorUnavailable')}</dd></div>
					</dl>
					{#if canManage}<Button variant="danger" disabled={revokeBusy} aria-busy={revokeBusy} onclick={revokeCurrentInvite}>{revokeBusy ? t('common.loading') : t('admin.guests.revokeInvite')}</Button>{/if}
				</div>
			{:else}
				<p class="guest-sheet__muted">{t('admin.guests.noCurrentInvite')}</p>
			{/if}
		</section>

		<section aria-labelledby="guest-invite-history-heading">
			<h3 id="guest-invite-history-heading">{t('admin.guests.inviteHistory')}</h3>
			{#if detail.inviteHistory.length === 0}
				<p class="guest-sheet__muted">{t('admin.guests.noInviteHistory')}</p>
			{:else}
				<ul class="guest-sheet__invite-history">
					{#each detail.inviteHistory as invite (invite.inviteId)}
						<li>
							<div class="guest-sheet__invite-title">
								<Badge variant={invite.state === 'pending' ? 'warning' : 'neutral'} label={t(`admin.guests.inviteState.${invite.state}`)} />
								<code>{invite.inviteId}</code>
							</div>
							<p>{t('admin.guests.inviteCreated')} {formatDateTime(invite.createdAt)}</p>
							{#if invite.terminalAt}<p>{t('admin.guests.inviteTerminal')} {formatDateTime(invite.terminalAt)}</p>{/if}
							<p>{invite.createdByEmail || t('admin.guests.creatorUnavailable')}</p>
						</li>
					{/each}
				</ul>
				{#if detail.inviteHistoryHasMore}<p class="guest-sheet__muted">{t('admin.guests.recentInviteHistory')}</p>{/if}
			{/if}
		</section>

		<section><h3>{t('admin.guests.profileAssignment')}</h3>
			<div class="guest-sheet__assign">
				<Select label={t('admin.guests.profile.label')} bind:value={assignedProfile} disabled={!canManage}>
					{#snippet children()}<option value="">{t('admin.guests.noProfile')}</option>{#each profiles as profile}<option value={profile.id}>{profile.name}</option>{/each}{/snippet}
				</Select>
				{#if canManage}<Button variant="secondary" aria-busy={assignBusy} disabled={assignBusy} onclick={assignProfile}>{assignBusy ? t('common.loading') : t('admin.guests.assignProfile')}</Button>{/if}
			</div>
		</section>

		<section><h3>{t('admin.guests.appAccess')}</h3>
			<AppAccessEditor embedded userId={detail.id} userEmail={detail.invitedEmail} guestEntitlements={detail.appEntitlements} guestProfileName={detail.profileName || ''} />
		</section>

		<section><h3>{t('admin.guests.channelGrants')}</h3>
			{#if detail.channelGrants.length === 0}<p class="guest-sheet__muted">{t('admin.guests.noGrants')}</p>
			{:else}<ul class="guest-sheet__grants">{#each detail.channelGrants as grant}<li>
				<span>{grant.name || (grant.kind === 'dm' ? t('admin.guests.directMessage') : `#${grant.channelId}`)}</span>
				<div class="guest-sheet__grant-badges">
					<Badge variant={grant.canPost === true ? 'success' : 'neutral'} label={grantPostingLabel(grant.canPost)} />
					<Badge variant="neutral" label={grant.historyFloorSeq === null ? t('admin.guests.fullHistory') : t('admin.guests.postJoinHistory')} />
				</div>
			</li>{/each}</ul>{/if}
		</section>

		{#if canManage}
			<footer class="guest-sheet__actions">
				<Button variant="secondary" onclick={openTransfer}>{t('admin.guests.transfer')}</Button>
				<Button variant="secondary" disabled={reinviteBusy} onclick={openReinvite}>{t('admin.guests.reinvite')}</Button>
				<Button variant="secondary" onclick={() => openLifecycle('extend')}>{t('admin.guests.extend')}</Button>
				{#if canEnableGuest}<Button variant="secondary" onclick={() => openLifecycle('enable')}>{t('admin.guests.enable')}</Button>{/if}
				{#if canDisableGuest}<Button variant="danger" onclick={() => openLifecycle('disable')}>{t('admin.guests.disable')}</Button>{/if}
			</footer>
		{/if}
	</div>
{/if}

<Dialog open={lifecycle !== null} title={lifecycle ? t(`admin.guests.lifecycle.${lifecycle}`) : ''} onClose={() => lifecycle = null}>
	{#snippet children()}
		<p>{lifecycleCopy()}</p>
		{#if lifecycle === 'extend'}<Input type="datetime-local" label={t('admin.guests.newExpiry')} error={extendError} bind:value={extendAt} required />{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => lifecycle = null}>{t('common.cancel')}</Button>
		<Button variant={lifecycle === 'disable' ? 'danger' : 'primary'} disabled={lifecycleBusy || (lifecycle === 'extend' && (!extendAt || !!extendError))} onclick={confirmLifecycle}>
			{lifecycle === 'disable' ? t('admin.guests.confirmDisable') : t('common.confirm')}
		</Button>
	{/snippet}
</Dialog>

<Dialog open={reinviteOpen} title={t('admin.guests.reinviteTitle')} onClose={() => reinviteOpen = false}>
	{#snippet children()}
		<p>{t('admin.guests.reinviteCopy')}</p>
		{#if reinviteNeedsExpiry}
			<Input type="datetime-local" label={t('admin.guests.newExpiry')} error={reinviteExpiryError} bind:value={reinviteExpiryAt} required />
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" disabled={reinviteBusy} onclick={() => reinviteOpen = false}>{t('common.cancel')}</Button>
		<Button variant="primary" aria-busy={reinviteBusy} disabled={reinviteBusy || (reinviteNeedsExpiry && (!reinviteExpiryAt || !!reinviteExpiryError))} onclick={confirmReinvite}>
			{reinviteBusy ? t('common.loading') : t('admin.guests.reinviteConfirm')}
		</Button>
	{/snippet}
</Dialog>

<Dialog open={transferOpen} title={t('admin.guests.transferTitle')} onClose={() => transferOpen = false}>
	{#snippet children()}
		<p>{t('admin.guests.transferCopy')}</p>
		<div class="guest-sheet__assign">
			<Input label={t('admin.guests.transferSearch')} bind:value={sponsorSearch} />
			<Button variant="secondary" onclick={loadSponsorOptions}>{t('admin.common.search')}</Button>
		</div>
		<Select label={t('admin.guests.transferSponsor')} bind:value={selectedSponsor} required>
			{#snippet children()}
				<option value="">{t('admin.guests.transferChoose')}</option>
				{#each sponsorOptions as option}<option value={String(option.id)}>{option.displayName} · {option.email}</option>{/each}
			{/snippet}
		</Select>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => transferOpen = false}>{t('common.cancel')}</Button>
		<Button variant="primary" aria-busy={transferBusy} disabled={!selectedSponsor || transferBusy} onclick={confirmTransfer}>{t('admin.guests.transferConfirm')}</Button>
	{/snippet}
</Dialog>

<Dialog open={profileEditor !== null} title={profileEditor === 'new' ? t('admin.guests.newProfile') : t('admin.guests.editProfileTitle')} onClose={() => profileEditor = null} wide>
	{#snippet children()}
		<div class="profile-form">
			<Select label={t('admin.guests.profile.domain')} bind:value={hostDomainId} disabled={profileEditor !== 'new'} required>
				{#snippet children()}
					{#if profileDomains.length === 0}<option value="">{t('admin.guests.profile.noDomains')}</option>{/if}
					{#each profileDomains as domain}<option value={String(domain.id)}>{domain.name}</option>{/each}
				{/snippet}
			</Select>
			<Input label={t('admin.guests.profile.name')} bind:value={profileForm.name} maxlength={120} required />
			<Input type="number" min="1" label={t('admin.guests.profile.defaultExpiry')} bind:value={expiryDays} />
			<Switch label={t('admin.guests.profile.canPost')} bind:checked={profileForm.canPost} />
			<Switch label={t('admin.guests.profile.historyFromJoin')} bind:checked={profileForm.historyFromJoin} />
			<Switch label={t('admin.guests.profile.allowDownload')} description={t('admin.guests.profile.downloadAdvisory')} bind:checked={profileForm.allowDownload} />
			<Switch label={t('admin.guests.profile.allowMeetCreate')} bind:checked={profileForm.allowMeetCreate} />
			<Switch label={t('admin.guests.profile.allowMeetHost')} bind:checked={profileForm.allowMeetHost} />
			<Switch label={t('admin.guests.profile.canInitiateDm')} bind:checked={profileForm.canInitiateDm} />
			<Switch label={t('admin.guests.profile.allowNativeShell')} description={t('admin.guests.profile.nativeAdvisory')} bind:checked={profileForm.allowNativeShell} />
			<fieldset><legend>{t('admin.guests.profile.apps')}</legend>
				{#each ['chat', 'drive', 'meet'] as app}<Switch label={t(`app.${app}`)} checked={profileForm.apps.includes(app as 'chat' | 'drive' | 'meet')} onchange={(event) => setProfileApp(app as 'chat' | 'drive' | 'meet', event.currentTarget.checked)} />{/each}
			</fieldset>
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => profileEditor = null}>{t('common.cancel')}</Button>
		<Button variant="primary" disabled={profileBusy || !profileForm.name.trim() || Number(hostDomainId) <= 0} onclick={saveProfile}>{profileEditor === 'new' ? t('admin.guests.createProfile') : t('admin.guests.saveProfile')}</Button>
	{/snippet}
</Dialog>

<Dialog open={profileDelete !== null} title={t('admin.guests.deleteProfileTitle')} onClose={() => profileDelete = null}>
	{#snippet children()}<p>{t('admin.guests.deleteProfileCopy', { name: profileDelete?.name || '' })}</p>{/snippet}
	{#snippet footer()}<Button variant="ghost" onclick={() => profileDelete = null}>{t('common.cancel')}</Button><Button variant="danger" disabled={profileBusy} onclick={confirmProfileDelete}>{t('admin.guests.confirmDeleteProfile')}</Button>{/snippet}
</Dialog>

<style>
	.guest-admin { display: flex; flex-direction: column; gap: var(--space-5); }
	.guest-admin__header { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-4); }
	.guest-admin h1, .guest-sheet h2, .guest-sheet h3 { margin: 0; color: var(--text-primary); }
	.guest-admin h1 { font-size: var(--text-2xl); }
	.guest-admin__header p, .guest-sheet__header p { margin: var(--space-1) 0 0; color: var(--text-caption); font-size: var(--text-sm); }
	.guest-admin__loading { display: flex; justify-content: center; padding: var(--space-8); }
	.guest-admin__error { padding: var(--space-3); color: var(--danger-fg); background: var(--danger-bg); border: 1px solid var(--danger-fg); border-radius: var(--radius-sm); }
	.guest-admin__identity { display: block; border: 0; padding: 0; background: transparent; color: var(--accent); font: inherit; font-weight: var(--weight-medium); cursor: pointer; }
	.guest-admin__identity:focus-visible, .guest-sheet__close:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.guest-admin__email { display: block; color: var(--text-caption); font-size: var(--text-sm); margin: var(--space-1) 0; }
	.guest-admin__row-actions, .guest-sheet__actions, .guest-sheet__badges { display: flex; flex-wrap: wrap; gap: var(--space-2); }
	.guest-sheet__row-actions, .guest-sheet__invite-title { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }
	.guest-sheet { position: fixed; inset-block: 0; inset-inline-end: 0; width: min(100%, 34rem); overflow: auto; z-index: 900; padding: var(--space-5); background: var(--surface-card); border-inline-start: 1px solid var(--border-default); box-shadow: var(--shadow-lg); display: flex; flex-direction: column; gap: var(--space-5); }
	.guest-sheet-backdrop { position: fixed; inset: 0; z-index: 899; background: var(--scrim); }
	.guest-sheet--loading { display: flex; flex: 1; align-items: center; justify-content: center; }
	.guest-sheet__header { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-3); }
	.guest-sheet__close { border: 0; background: transparent; color: var(--text-secondary); padding: var(--space-2); border-radius: var(--radius-sm); cursor: pointer; }
	.guest-sheet section { display: flex; flex-direction: column; gap: var(--space-3); }
	.guest-sheet h3 { font-size: var(--text-base); }
	.guest-sheet__facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); margin: 0; }
	.guest-sheet__facts div { padding: var(--space-3); background: var(--surface-sunken); border-radius: var(--radius-sm); }
	.guest-sheet__facts dt { color: var(--text-caption); font-size: var(--text-sm); }
	.guest-sheet__facts dd { margin: var(--space-1) 0 0; color: var(--text-primary); font-size: var(--text-sm); }
	.guest-sheet__delivery-warning { padding: var(--space-3); color: var(--warning-fg); background: var(--warning-bg); border: 1px solid var(--warning-fg); border-radius: var(--radius-sm); }
	.guest-sheet__delivery-warning p { margin: 0; }
	.guest-sheet__current-invite { display: flex; flex-direction: column; align-items: flex-start; gap: var(--space-3); padding: var(--space-3); background: var(--surface-sunken); border-radius: var(--radius-sm); }
	.guest-sheet__invite-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); margin: 0; width: 100%; }
	.guest-sheet__invite-meta dt { color: var(--text-caption); font-size: var(--text-sm); }
	.guest-sheet__invite-meta dd { margin: var(--space-1) 0 0; color: var(--text-primary); font-size: var(--text-sm); overflow-wrap: anywhere; }
	.guest-sheet__invite-history { list-style: none; padding: 0; margin: 0; border-block-start: 1px solid var(--border-subtle); }
	.guest-sheet__invite-history li { display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-3) 0; border-block-end: 1px solid var(--border-subtle); }
	.guest-sheet__invite-history p { margin: 0; color: var(--text-caption); font-size: var(--text-sm); }
	.guest-sheet code { color: var(--text-secondary); font-size: var(--text-sm); overflow-wrap: anywhere; }
	.guest-sheet__assign { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: var(--space-2); }
	.guest-sheet__grants { list-style: none; padding: 0; margin: 0; border-block-start: 1px solid var(--border-subtle); }
	.guest-sheet__grants li { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); padding: var(--space-2) 0; border-block-end: 1px solid var(--border-subtle); }
	.guest-sheet__grant-badges { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: var(--space-1); }
	.guest-sheet__muted { color: var(--text-caption); font-size: var(--text-sm); }
	.profile-form { display: grid; gap: var(--space-3); }
	.profile-form fieldset { border: 1px solid var(--border-default); border-radius: var(--radius-sm); padding: var(--space-3); display: grid; gap: var(--space-2); }
	.profile-form legend { color: var(--text-primary); font-size: var(--text-sm); font-weight: var(--weight-medium); }

	@media (max-width: 40rem) { .guest-admin__header { flex-direction: column; } .guest-sheet__facts, .guest-sheet__invite-meta { grid-template-columns: 1fr; } }
</style>
