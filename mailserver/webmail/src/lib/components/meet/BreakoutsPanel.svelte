<svelte:options runes={true} />

<script lang="ts">
	// BreakoutsPanel — Meet B3 Task 7, spec §8. Host/cohost-only in-room panel
	// (mounted per design D6 in the exclusive `.meet-app__side` slot shared
	// with MeetChatPanel — MeetApp toggles which one shows). Calls
	// $lib/meet/api directly (the LobbyPanel convention).
	//
	// Two independent local-state mirrors, both re-seeded whenever the
	// caller's props change (the LobbyPanel/ChannelSettingsSheet pattern —
	// reading a $props() value as a $state initializer only captures its
	// value at mount and would silently go stale on prop updates):
	//   - `rows`: the structural room list (id/idx/title) — grows on THIS
	//     panel's own `open()`, shrinks to `[]` on its own `closeAll()`.
	//   - `localAssignments`: identity -> current breakoutId (absent/null =
	//     main room) — mutated optimistically by THIS panel's own `assign()`
	//     calls, and kept current by MeetApp's live `assignments` prop
	//     (updated on every `breakout_assigned` push, never a re-fetch — see
	//     MeetApp's own comment on that map).
	//
	// D3: the assign selects list ONLY currently-connected, non-guest,
	// non-self participants — `participants` is MeetApp's LIVE LiveKit
	// roster (`sheetParticipants`), so a banned/departed identity is already
	// absent by construction (they were evicted); only `g:` guests (never
	// assignable, D7) and the caller themself need filtering here. That
	// closes design D3's promise: the only reachable server answer for an
	// offered row is success or a genuine 422.
	import * as meetApi from '$lib/meet/api';
	import { MeetError, type Breakout } from '$lib/meet/api';
	import type { SheetParticipant } from './ControlsBar.svelte';
	import { Button, Select, Switch, EmptyState, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		meetingId,
		breakouts,
		assignments,
		participants,
		selfIdentity,
		selfCurrentBreakoutId = null,
		onJoinRoom,
		onReturnToMain,
	}: {
		meetingId: number;
		breakouts: Breakout[];
		/** identity -> current breakoutId (absent/null = main room). MeetApp's
		 *  live panel map — the source of truth for grouping, fresher than any
		 *  `assignees[]` embedded on `breakouts` (that field only seeds
		 *  MeetApp's map once per load/refetch). */
		assignments: Record<string, number | null>;
		participants: SheetParticipant[];
		selfIdentity: string;
		/** B3 retro fix (design finding #1 — host roaming): which room the
		 *  CALLER is currently connected to (MeetApp's own currentBreakoutId).
		 *  A host/cohost's OWN `meeting_participants.breakout_id` stays NULL
		 *  even while roaming in a child room (D7) — this client-tracked value
		 *  is the only place that fact is knowable. null = main room. */
		selfCurrentBreakoutId?: number | null;
		/** Host/cohost roaming (retro fix — design finding #1): joins the
		 *  target room via the SAME moveToBreakout choreography a forced
		 *  assignment uses. Undefined hides every Join button (the
		 *  onOpenChat hide-when-undefined idiom) — the caller decides who
		 *  gets to roam; this panel is host/cohost-only to begin with (only
		 *  ever mounted for that role by MeetApp), so a plain member never
		 *  reaches this component, let alone a Join button. */
		onJoinRoom?: (breakoutId: number) => void;
		/** Returns a roaming host/cohost to main — a plain rejoinMain works
		 *  for them since they carry no server-side assignment to redirect
		 *  against (D7). Undefined hides the affordance. */
		onReturnToMain?: () => void;
	} = $props();

	let rows = $state<Breakout[]>([]);
	$effect(() => {
		rows = breakouts;
	});

	let localAssignments = $state<Record<string, number | null>>({});
	$effect(() => {
		localAssignments = assignments;
	});

	// D3: banned/departed participants are never in the live roster to begin
	// with (they were evicted) — only guests and self need filtering here.
	let assignable = $derived(participants.filter((p) => !p.identity.startsWith('g:') && p.identity !== selfIdentity));

	function roomLabel(b: Breakout): string {
		return b.title ?? t('meet.breakouts.defaultName', { n: String(b.idx) });
	}

	let selectOptions = $derived([
		{ value: '', label: t('meet.breakouts.mainRoom') },
		...rows.map((b) => ({ value: String(b.breakoutId), label: roomLabel(b) })),
	]);

	// ponytail: no per-room custom-title input in v1 — every opened room
	// rides the client-rendered default name (defaultName). Add a titles[]
	// input row if a customer asks for named rooms at open time; the
	// reducer already accepts `p_titles` for exactly that.
	let countStr = $state('2');
	let autoAssign = $state(false);
	let opening = $state(false);
	let closing = $state(false);

	async function open(): Promise<void> {
		opening = true;
		try {
			const res = await meetApi.openBreakouts(meetingId, Number(countStr), undefined, autoAssign);
			rows = res.breakouts;
		} catch {
			showToast(t('meet.breakouts.openFailed'));
		} finally {
			opening = false;
		}
	}

	async function closeAll(): Promise<void> {
		closing = true;
		try {
			await meetApi.closeBreakouts(meetingId);
			rows = [];
			localAssignments = {};
		} catch {
			showToast(t('meet.breakouts.closeFailed'));
		} finally {
			closing = false;
		}
	}

	/** Optimistic for a 5xx (never reverted): the reducer's own assignment
	 *  already committed even when the route's OWN `RemoveParticipant`
	 *  eviction call 502s — the worker heals the eviction, so the honest
	 *  toast says "saved", not "failed" (D3 wire note).
	 *
	 *  B3 retro fix (design finding #4): a genuine failure never committed
	 *  server-side at all (a 4xx — bad target/role/foreign meeting, BZ201 —
	 *  or a network/transport error, which never reaches a status at all) —
	 *  those REVERT the optimistic write and show a real failure string,
	 *  distinct from the eviction-502 "saved" copy above. */
	async function assign(identity: string, breakoutId: number | null): Promise<void> {
		const previous = localAssignments[identity] ?? null;
		localAssignments = { ...localAssignments, [identity]: breakoutId };
		const targetUserId = Number(identity.slice(2)); // 'u:123' -> 123
		try {
			await meetApi.assignBreakout(meetingId, targetUserId, breakoutId);
		} catch (err) {
			const status = err instanceof MeetError ? err.status : 0;
			if (status >= 500) {
				showToast(t('meet.breakouts.assignFailed'));
			} else {
				// B3 confirm-pass note (design, NIT): `previous` can be stale if a
				// fresher breakout_assigned push re-seeded localAssignments while
				// this call was in flight — a sub-second window that self-corrects
				// on the next push/refetch, accepted rather than tracked.
				localAssignments = { ...localAssignments, [identity]: previous };
				showToast(t('meet.breakouts.assignRejected'));
			}
		}
	}

	const COUNT_OPTIONS = Array.from({ length: 20 }, (_, i) => String(i + 1));
</script>

<div class="breakouts-panel">
	<h3 class="breakouts-panel__title">{t('meet.breakouts.title')}</h3>

	{#if rows.length === 0}
		<div class="breakouts-panel__open">
			<Select label={t('meet.breakouts.count')} options={COUNT_OPTIONS} bind:value={countStr} data-testid="breakouts-count" />
			<Switch checked={autoAssign} label={t('meet.breakouts.autoAssign')} onchange={() => (autoAssign = !autoAssign)} />
			<Button variant="primary" onclick={() => void open()} disabled={opening} data-testid="breakouts-open">
				{t('meet.breakouts.open')}
			</Button>
		</div>
	{:else}
		<Button variant="secondary" onclick={() => void closeAll()} disabled={closing} data-testid="breakouts-close-all">
			{t('meet.breakouts.closeAll')}
		</Button>

		{#if onReturnToMain && selfCurrentBreakoutId !== null}
			<!-- B3 retro fix (design finding #1 — host roaming): a roaming
			     host/cohost has no server-side assignment to redirect against
			     (D7) — a plain rejoinMain returns them. -->
			<Button variant="ghost" size="sm" onclick={onReturnToMain} data-testid="breakouts-return-main">
				{t('meet.breakouts.mainRoom')}
			</Button>
		{/if}

		<ul class="breakouts-panel__rooms" role="list">
			{#each rows as b (b.breakoutId)}
				<li class="breakouts-panel__room-row">
					<span>{roomLabel(b)}</span>
					{#if onJoinRoom && b.breakoutId !== selfCurrentBreakoutId}
						<Button
							variant="ghost"
							size="sm"
							onclick={() => onJoinRoom?.(b.breakoutId)}
							data-testid={`breakouts-join-${b.breakoutId}`}
						>
							{t('meet.breakouts.joinRoom')}
						</Button>
					{/if}
				</li>
			{/each}
		</ul>

		{#if assignable.length === 0}
			<EmptyState title={t('meet.lobby.empty')} />
		{:else}
			<div class="breakouts-panel__assign-head">{t('meet.breakouts.assignTo')}</div>
			<ul class="breakouts-panel__assignees" role="list">
				{#each assignable as p (p.identity)}
					<li class="breakouts-panel__assignee-row">
						<span class="breakouts-panel__assignee-name">{p.displayName}</span>
						<Select
							aria-label={`${t('meet.breakouts.assignTo')} ${p.displayName}`}
							data-testid={`breakouts-assign-${p.identity}`}
							options={selectOptions}
							value={String(localAssignments[p.identity] ?? '')}
							onchange={(e: Event & { currentTarget: HTMLSelectElement }) =>
								void assign(p.identity, e.currentTarget.value ? Number(e.currentTarget.value) : null)}
						/>
					</li>
				{/each}
			</ul>
		{/if}
	{/if}
</div>

<style>
	.breakouts-panel {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-3);
		height: 100%;
		overflow-y: auto;
	}
	.breakouts-panel__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.breakouts-panel__open {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.breakouts-panel__rooms {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.breakouts-panel__room-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.breakouts-panel__assign-head {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-tertiary);
		text-transform: uppercase;
	}
	.breakouts-panel__assignees {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.breakouts-panel__assignee-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.breakouts-panel__assignee-name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: var(--text-sm);
	}
</style>
