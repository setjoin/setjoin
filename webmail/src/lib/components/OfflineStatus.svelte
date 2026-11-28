<svelte:options runes={true} />
<script lang="ts">
	import { offline } from '$lib/offline/state.svelte';
	import { requestSync } from '$lib/offline/sync';
	import { DEFAULT_OFFLINE_WINDOW } from '$lib/offline/window';
	import { e5ui } from '$lib/offline/e5ui.svelte';
	import { e5StatusText } from '$lib/offline/e5.uiProjection';
	import { t, formatRelativeTime } from '$lib/i18n';
	import { Cloud, CloudOff, RefreshCw, Lock, AlertTriangle } from 'lucide-svelte';
	import Progress from '$lib/components/ui/Progress.svelte';
	import Spinner from '$lib/components/ui/Spinner.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import { showToast } from '$lib/components/ui/toasts.svelte';
	import SyncIssuesInspector from './SyncIssuesInspector.svelte';

	let inspectorOpen = $state(false);
	const busy = $derived(offline.syncPhase === 'provisioning' || offline.syncPhase === 'syncing');

	// E5 consumer-parity display (Phase 2 pass 3): rendered ONLY while the
	// connectivity-aware-sync program is active on top of the existing native
	// offline gate — the shipped OFF posture renders nothing new below.
	const e5Section = $derived(offline.controlsActive && e5ui.active);
	const e5Projection = $derived(e5Section ? e5ui.projection(offline.workOffline ? 'workOffline' : 'online') : null);
	const e5Text = $derived(e5Projection === null ? null : e5StatusText(e5Projection));

	// UI-UX-PRO-MAX: quiet, dismissible auto-merge confirmation via the global Toast
	// stack (auto-dismiss + hover-pause + built-in dismiss X = dismissible-without-
	// nagging; NO actionLabel/Undo — the merge already happened, nothing to revert).
	// Fires ONCE per sync pass when syncWindow auto-resolved flag/keyword/mailbox
	// conflicts (autoMergedCount > 0), then resets the count so it never re-fires.
	$effect(() => {
		if (offline.autoMergedCount > 0) {
			const n = offline.autoMergedCount;
			showToast(t(n === 1 ? 'offline.toast.automerged' : 'offline.toast.automerged_plural', { n: String(n) }));
			offline.autoMergedCount = 0; // aggregate, one-shot — never a per-item entry
		}
	});

	function toggleWorkOffline() {
		offline.setWorkOffline(!offline.workOffline);
		if (offline.workOffline) requestSync(DEFAULT_OFFLINE_WINDOW);
	}

	// ponytail: inline relative-time helper using the existing i18n Intl.RelativeTimeFormat
	// wrapper (formatRelativeTime). Ceiling: extract to a shared util if more callers emerge.
	function ago(ts: number | null): string {
		if (ts === null) return t('offline.status.online');
		const diffSec = (Date.now() - ts) / 1000;
		const absSec = Math.abs(diffSec);
		if (absSec < 60) return formatRelativeTime(-Math.round(absSec), 'second');
		if (absSec < 3600) return formatRelativeTime(-Math.round(absSec / 60), 'minute');
		if (absSec < 86400) return formatRelativeTime(-Math.round(absSec / 3600), 'hour');
		return formatRelativeTime(-Math.round(absSec / 86400), 'day');
	}

	// E5 action dispatch: at most ONE context-correct action, wired to its REAL
	// owning flow (Phase 2 Pass 3). Work Offline can never start the network (a
	// Retry hint arrives as goOnline already).
	function runE5Action(hint: string): void {
		switch (hint) {
			case 'retry':
			case 'syncNow':
				requestSync();
				break;
			case 'goOnline':
				offline.setWorkOffline(false);
				break;
			case 'unlock':
				offline.setLockState('unlocking');
				break;
			case 'viewSettings':
				window.location.assign('/settings');
				break;
			case 'signIn':
				// Owning flow for an auth-required block: the app's sign-in screen.
				window.location.assign('/');
				break;
			case 'freeStorage':
				// /settings/storage is the sole storage owner (fit-to-space, clear cache).
				window.location.assign('/settings/storage');
				break;
			case 'resolve':
				// Resolve routes through the owning flow: the sync-issues inspector.
				inspectorOpen = true;
				break;
		}
	}

	// Single-announcer contract (design Pass 5): ONE offscreen polite region
	// owns async outcomes for this surface. The most recent outcome — legacy
	// offline or E5 — is what a screen reader hears; the visual container is
	// NOT live. E5's announcement seq is carried into the keyed render so
	// identical consecutive messages still re-announce.
	let announcerText = $state('');
	let announcerSeq = $state(0);
	$effect(() => {
		const msg = offline.liveMessage;
		if (msg) announcerText = t(msg, offline.liveParams as Record<string, string> | undefined);
	});
	$effect(() => {
		const ann = e5Section ? e5ui.announcement : null;
		if (ann) {
			announcerText = t(ann.key, ann.params);
			announcerSeq = ann.seq;
		}
	});

	// The stale primary ("Not current — last synced {ago}") takes its {ago} from
	// the lastCurrentAt axis (final server state) — never an invented time.
	const e5PrimaryParams = $derived.by(() => {
		const text = e5Text;
		if (text === null) return undefined;
		if (text.primaryKey === 'offline.e5.status.not_current') {
			return {
				ago: e5ui.lastCurrentAt === null
					? t('offline.e5.status.last_sync_unknown')
					: ago(e5ui.lastCurrentAt),
			};
		}
		return text.primaryParams;
	});
</script>

{#if offline.controlsActive}
	<div
		class="offline-status"
		role="group"
		aria-label={t('offline.status.aria')}
		data-testid="offline-status"
	>
		<button
			type="button"
			class="offline-toggle"
			data-testid="work-offline-toggle"
			aria-pressed={String(offline.workOffline) as 'true' | 'false'}
			disabled={busy}
			onclick={toggleWorkOffline}
		>
			{#if offline.workOffline}
				<CloudOff size={16} aria-hidden="true" />
			{:else}
				<Cloud size={16} aria-hidden="true" />
			{/if}
			<span class="lbl">{offline.workOffline ? t('offline.working_offline') : t('offline.work_offline')}</span>
		</button>

		{#if e5Section && e5Text}
			<!-- E5 freshness/scheduler display (Phase 2 pass 3). Freshness stays
			     primary; scheduler activity/pause is secondary; at most one action.
			     The visual container is NOT live — the single offscreen announcer
			     below owns async outcomes. The role=alert row is reserved for
			     action-required. -->
			<div class="phase e5-status" data-testid="e5-status">
				<span class="e5-status__primary" data-testid="e5-status-primary">{t(e5Text.primaryKey, e5PrimaryParams)}</span>
				{#if e5Text.secondary}
					<span class="e5-status__secondary" data-testid="e5-status-secondary">
						{t(e5Text.secondary.key, e5Text.secondary.kind === 'runningProgress' ? e5Text.secondary.params : undefined)}
						{#if e5Text.secondary.kind === 'backoff'}
							· {ago(e5Text.secondary.retryAt)}
						{/if}
					</span>
				{/if}
				{#if e5Text.action}
					{@const e5Hint = e5Text.action.hint}
					<button type="button" class="link-btn" data-testid="e5-status-action" onclick={() => runE5Action(e5Hint)}>
						{t(e5Text.action.key)}
					</button>
				{/if}
				{#if e5Text.alert}
					<span class="sr-only" role="alert">{t(e5Text.primaryKey)}</span>
				{/if}
			</div>
		{/if}

		{#if offline.syncPhase === 'provisioning'}
			<span class="phase phase--info" data-testid="offline-provisioning">
				<Spinner size={16} label={t('offline.status.provisioning')} />
				{t('offline.status.provisioning')}
				<Progress
					value={offline.syncProgress.done}
					max={Math.max(offline.syncProgress.total, 1)}
					label={t('offline.status.provisioning')}
				/>
			</span>
		{:else if offline.syncPhase === 'syncing'}
			<span class="phase phase--info" data-testid="offline-syncing">
				<Spinner size={16} label={t('offline.status.syncing', { done: String(offline.syncProgress.done), total: String(offline.syncProgress.total) })} />
				{t('offline.status.syncing', { done: String(offline.syncProgress.done), total: String(offline.syncProgress.total) })}
			</span>
		{:else if offline.syncPhase === 'stale'}
			<span class="phase phase--warn">
				{t('offline.status.stale', { ago: ago(offline.lastSyncAt) })}
				<button type="button" class="link-btn" data-testid="offline-resync" onclick={() => requestSync()}>
					<RefreshCw size={14} aria-hidden="true" />
					{t('offline.status.resync')}
				</button>
			</span>
		{:else if offline.syncPhase === 'error'}
			<span class="phase phase--danger" role="alert" data-testid="offline-error">
				<AlertTriangle size={14} aria-hidden="true" />
				{t('offline.status.error')}
				<button type="button" class="link-btn" data-testid="offline-retry" onclick={() => requestSync()}>
					{t('offline.status.retry')}
				</button>
			</span>
		{/if}

		{#if offline.effectiveOffline && offline.lockState !== 'unlocked'}
			<!-- ponytail: click signals the unlock flow by transitioning to 'unlocking',
			     which BiometricUnlock reads via offline.needsUnlock. Sets nothing destructive. -->
			<button
				type="button"
				class="lock-btn"
				data-testid="offline-locked"
				aria-label={t('offline.status.locked')}
				onclick={() => offline.setLockState('unlocking')}
			>
				<Lock size={14} aria-hidden="true" />
				{t('offline.status.locked')}
			</button>
		{/if}

		{#if offline.syncIssueCount > 0}
			<!-- Rare + higher-signal now (F1 auto-merges flag/keyword/mailbox conflicts):
			     the badge explains itself ("Needs your choice") instead of a bare count. -->
			<button
				type="button"
				class="badge-btn"
				data-testid="sync-issues-badge"
				aria-label={t(
					offline.syncIssueCount === 1 ? 'offline.issues.badge_aria' : 'offline.issues.badge_aria_plural',
					{ n: String(offline.syncIssueCount) }
				)}
				onclick={() => (inspectorOpen = true)}
			>
				<AlertTriangle size={14} aria-hidden="true" />
				<span class="badge-lbl">{t('offline.issues.badge_label')}</span>
				<!-- M1 Badge: count prop caps at 99+ natively; variant=danger matches phase colour -->
				<Badge variant="danger" count={offline.syncIssueCount} />
			</button>
		{/if}
	</div>

	<SyncIssuesInspector bind:open={inspectorOpen} />

	<!-- UI-UX-PRO-MAX: the quiet auto-merge confirmation is pushed to the global
	     <Toast /> stack (role="status", auto-dismiss + hover-pause, dismissible, NO
	     Undo) by the $effect above — NOT a per-item entry. AT hears the same outcome
	     via the single polite live region below. -->

	<!-- THE one polite live region of this surface (design Pass 5): announces
	     async outcomes — legacy offline events AND E5 (phase changes, 10%
	     transfer thresholds, group results, settings) — whichever changed most
	     recently. announcerSeq keys the content so identical consecutive E5
	     messages still re-announce. There is no second competing region. -->
	<span
		class="sr-only"
		role="status"
		aria-live="polite"
		data-testid="offline-live"
	>{#key announcerSeq}{announcerText}{/key}</span>
{/if}

<style>
	.offline-status {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}
	.offline-toggle {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		min-height: 44px;
		padding: var(--space-1) var(--space-2);
		font: inherit;
		color: var(--text-secondary);
		background: transparent;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: background var(--duration-fast) var(--ease-out), color var(--duration-fast) var(--ease-out);
	}
	.offline-toggle[aria-pressed='true'] {
		color: var(--accent-fg-on-subtle);
		background: var(--accent-subtle);
		border-color: var(--border-accent);
	}
	.offline-toggle:disabled { opacity: 0.6; cursor: default; }
	.offline-toggle:focus-visible,
	.link-btn:focus-visible,
	.badge-btn:focus-visible,
	.lock-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.phase {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 0 var(--space-2);
		border-radius: var(--radius-sm);
		color: var(--text-tertiary);
		transition: opacity var(--duration-fast) var(--ease-out);
	}
	.phase--info { color: var(--info-fg); background: var(--info-bg); }
	.phase--warn { color: var(--warning-fg); background: var(--warning-bg); }
	.phase--danger { color: var(--danger-fg); background: var(--danger-bg); }
	/* E5 status: freshness primary, scheduler secondary; token-only, both themes. */
	.e5-status {
		max-width: 100%;
		flex-wrap: wrap;
	}
	.e5-status__primary { color: var(--text-secondary); }
	.e5-status__secondary { color: var(--text-tertiary); }
	.link-btn {
		font: inherit;
		color: inherit;
		text-decoration: underline;
		background: transparent;
		border: none;
		cursor: pointer;
		padding: var(--space-1);
	}
	.badge-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		background: transparent;
		border: none;
		cursor: pointer;
		padding: var(--space-1);
		min-height: 44px;
		color: var(--danger-fg);
	}
	.badge-lbl { font-size: var(--text-sm); }
	.lock-btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		background: transparent;
		border: none;
		cursor: pointer;
		padding: var(--space-1) var(--space-2);
		font: inherit;
		color: var(--text-tertiary);
		border-radius: var(--radius-sm);
		min-height: 44px;
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	/* Narrow native shell: labels collapse to icon-only; SR text stays via aria-label. */
	@media (max-width: 640px) {
		.lbl,
		.badge-lbl { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
	}
	/* Token-calibrated transitions; reduced-motion collapses to 0s (also covered globally). */
	@media (prefers-reduced-motion: reduce) {
		.phase,
		.offline-toggle { transition: none; }
	}
</style>
