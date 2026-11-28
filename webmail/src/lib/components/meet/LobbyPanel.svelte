<svelte:options runes={true} />

<script lang="ts">
	// LobbyPanel — Meet B1 Task 16. Host/cohost-only in-room panel: the
	// pending join-request queue (admit/deny, aria-live announce on arrival)
	// + the guestAllowed toggle (CEO #4 — flip guests on mid-meeting, the
	// settings route; affects FUTURE knocks only, never evicts anyone
	// already in). Calls $lib/meet/api directly (the ChannelSettingsSheet
	// convention) — removing a decided row from its own local list on
	// success, same optimistic-then-confirm shape as chat's toggle helpers.
	import * as meetApi from '$lib/meet/api';
	import { MeetError, type PendingJoinRequest } from '$lib/meet/api';
	import { Button, IconButton, Switch, EmptyState, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		meetingId,
		pendingRequests,
		guestAllowed,
		onClose,
	}: {
		meetingId: number;
		pendingRequests: PendingJoinRequest[];
		guestAllowed: boolean;
		/** UX #9: LobbyPanel joined the `.meet-app__side` exclusive slot (was
		 *  unconditionally docked whenever host/cohost — the MeetChatPanel
		 *  close-button precedent, needed because on a narrow viewport this
		 *  panel is now a full-screen overlay with no other way to dismiss it). */
		onClose?: () => void;
	} = $props();

	// Seeded by the effects below, not directly from props (see
	// ChannelSettingsSheet's identical comment on this pattern — reading a
	// $props() value as a $state initializer only captures its value at
	// mount and would silently go stale on prop updates).
	let rows = $state<PendingJoinRequest[]>([]);
	$effect(() => {
		rows = pendingRequests;
	});

	let guestAllowedState = $state(false);
	$effect(() => {
		guestAllowedState = guestAllowed;
	});
	let togglingGuestAccess = $state(false);

	async function decide(requestId: number, action: 'admit' | 'deny'): Promise<void> {
		const before = rows;
		rows = rows.filter((r) => r.requestId !== requestId); // optimistic removal
		try {
			await meetApi.decideRequest(meetingId, requestId, action);
		} catch (err) {
			rows = before; // restore the row on failure — nothing was actually decided
			// D-3: BZ199 (guest admit blocked while recording) gets its own
			// toast so the host learns WHY the admit bounced — every other
			// error keeps the existing silent row-restore.
			if (err instanceof MeetError && err.code === 'BZ199') {
				showToast(t('meet.recording.admitBlocked'));
			}
		}
	}

	async function toggleGuestAllowed(): Promise<void> {
		const next = !guestAllowedState;
		guestAllowedState = next;
		togglingGuestAccess = true;
		try {
			await meetApi.setGuestAllowed(meetingId, next);
		} catch {
			guestAllowedState = !next;
		} finally {
			togglingGuestAccess = false;
		}
	}
</script>

<div class="lobby-panel">
	<div class="lobby-panel__header">
		<h3 class="lobby-panel__title">{t('meet.lobby.title')}</h3>
		{#if onClose}
			<IconButton label={t('common.close')} size="sm" onclick={onClose}>
				<Icon name="X" size={16} />
			</IconButton>
		{/if}
	</div>

	<div class="lobby-panel__guest-row">
		<Switch
			checked={guestAllowedState}
			label={t('meet.lobby.guestAllowed')}
			disabled={togglingGuestAccess}
			onchange={() => void toggleGuestAllowed()}
		/>
	</div>

	<div aria-live="polite" class="lobby-panel__live-region">
		{#if rows.length > 0}{t('meet.lobby.knockRequested', { name: rows[0].displayName })}{/if}
	</div>

	<div class="lobby-panel__body">
		{#if rows.length === 0}
			<EmptyState title={t('meet.lobby.empty')} />
		{:else}
			<ul class="lobby-panel__list" role="list">
				{#each rows as req (req.requestId)}
					<li class="lobby-panel__row" data-testid={`knock-${req.requestId}`}>
						<span class="lobby-panel__name">{req.displayName}</span>
						<div class="lobby-panel__actions">
							<Button variant="primary" size="sm" onclick={() => void decide(req.requestId, 'admit')}>
								{t('meet.lobby.admit')}
							</Button>
							<Button variant="secondary" size="sm" onclick={() => void decide(req.requestId, 'deny')}>
								{t('meet.lobby.deny')}
							</Button>
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>

<style>
	.lobby-panel {
		display: flex;
		flex-direction: column;
		height: 100%;
		min-height: 0;
		overflow: hidden;
	}
	.lobby-panel__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0 var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		min-height: 44px;
		flex: none;
	}
	.lobby-panel__guest-row {
		padding: var(--space-2) var(--space-3) var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
	}
	.lobby-panel__body {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: 0 var(--space-3) var(--space-3);
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.lobby-panel__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.lobby-panel__live-region {
		/* visually hidden — the aria-live announcement itself is the point */
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
	.lobby-panel__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.lobby-panel__row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.lobby-panel__name {
		font-size: var(--text-sm);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.lobby-panel__actions {
		display: flex;
		gap: var(--space-1);
		flex: none;
	}
</style>
