<svelte:options runes={true} />

<!--
	/settings/sharing — the §6-C "who can see my calendar / mail" review panel
	(spec 2026-06-27-sharing-delegation-design.md). Two read-only lists from
	GET /api/me/sharing with inline revoke (the single "stop sharing" surface),
	plus the "Delegate access" entry point to ShareMailboxDialog (§6-B).
	States per §6-D: skeleton lists · "Only you can see this" · load-fail retry ·
	revoke announces "Access removed" via aria-live.
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Toast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import {
		getSharingOverview,
		revokeDelegate,
		clearMyDefault,
		type SharingOverview
	} from '$lib/api/sharing';
	import { revokeShare } from '$lib/stores/calendar';
	import ShareMailboxDialog from '$lib/components/ShareMailboxDialog.svelte';
	import { parseError } from '$lib/errors';

	let overview = $state<SharingOverview | null>(null);
	let loading = $state(true);
	let loadError = $state('');
	let busy = $state(false);
	let announce = $state('');
	let delegateOpen = $state(false);

	onMount(load);

	async function load() {
		loading = true;
		loadError = '';
		try {
			overview = await getSharingOverview();
		} catch (e) {
			loadError = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// Most specific active default (user > group > ou > org) for the banner.
	const activeDefault = $derived.by(() => {
		if (!overview) return null;
		if (overview.myDefaults.length > 0) return overview.myDefaults[0];
		for (const scope of ['group', 'ou', 'org'] as const) {
			const row = overview.inheritedDefaults.find((r) => r.ownerScope === scope);
			if (row) return row;
		}
		return null;
	});

	const calendarEmpty = $derived(
		overview !== null && overview.calendarGrants.length === 0 && activeDefault === null
	);

	async function revoked(action: () => Promise<void>) {
		if (busy) return;
		busy = true;
		try {
			await action();
			announce = t('sharing.revoked_announce');
			await load();
		} catch (e) {
			loadError = parseError(e).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>{t('sharing.title')} · setjoin</title></svelte:head>

<div class="sj-sharing-page">
	<div class="sj-sharing-inner">
		<h1 class="sj-page-title">{t('sharing.title')}</h1>
		<p class="sj-sharing-subtitle">{t('sharing.subtitle')}</p>

		<div class="sj-sharing-announce" role="status" aria-live="polite" aria-atomic="true">{announce}</div>

		{#if loading}
			<Card title={t('sharing.calendar_section')}>
				<ul class="sj-sharing-skeleton" role="status" aria-label={t('common.loading')} data-testid="sharing-skeleton">
					{#each Array(3) as _unused}<li class="sj-sharing-skeleton__row"></li>{/each}
				</ul>
			</Card>
			<Card title={t('sharing.mail_section')}>
				<ul class="sj-sharing-skeleton" role="status" aria-label={t('common.loading')}>
					{#each Array(2) as _unused}<li class="sj-sharing-skeleton__row"></li>{/each}
				</ul>
			</Card>
		{:else if loadError}
			<Card>
				<p class="sj-sharing-error" role="alert">{loadError}</p>
				<Button variant="secondary" size="sm" onclick={load}>{t('common.retry')}</Button>
			</Card>
		{:else if overview}
			<!-- Calendar -->
			<Card title={t('sharing.calendar_section')}>
				{#if activeDefault}
					<p class="sj-sharing-banner">
						{t('sharing.default_banner', {
							audience: t(`sharing.audience.${activeDefault.audience}`),
							level: t(`sharing.level.${activeDefault.level}`)
						})}
					</p>
				{/if}
				{#if calendarEmpty}
					<p class="sj-sharing-empty">{t('sharing.only_you')}</p>
				{:else}
					<ul class="sj-sharing-list">
						{#each overview.myDefaults as d (d.id)}
							<li class="sj-sharing-row">
								<div class="sj-sharing-who">
									<span class="sj-sharing-name">{t('sharing.my_default_row', { audience: t(`sharing.audience.${d.audience}`) })}</span>
									<span class="sj-sharing-perm">{t(`sharing.level.${d.level}`)}</span>
								</div>
								<Button variant="ghost" size="sm" disabled={busy} onclick={() => revoked(() => clearMyDefault(d.id))}>
									{t('sharing.revoke')}
								</Button>
							</li>
						{/each}
						{#each overview.calendarGrants as g (`${g.calendarId}-${g.userEmail}`)}
							<li class="sj-sharing-row">
								<div class="sj-sharing-who">
									<span class="sj-sharing-name">{g.userEmail}</span>
									<span class="sj-sharing-perm">{t(`calendar.share.level.${g.level}`)} — {g.calendarName}</span>
								</div>
								<Button
									variant="ghost"
									size="sm"
									disabled={busy}
									onclick={() => revoked(() => revokeShare(String(g.calendarId), g.userEmail))}
								>
									{t('sharing.revoke')}
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
			</Card>

			<!-- Mail -->
			<Card title={t('sharing.mail_section')}>
				{#if overview.delegates.length === 0}
					<p class="sj-sharing-empty">{t('sharing.only_you')}</p>
				{:else}
					<ul class="sj-sharing-list">
						{#each overview.delegates as d (`${d.userId}-${d.permission}`)}
							<li class="sj-sharing-row">
								<div class="sj-sharing-who">
									<span class="sj-sharing-name">{d.email}</span>
									<span class="sj-sharing-perm">{t(`sharing.perm.${d.permission}`)}</span>
								</div>
								<Button variant="ghost" size="sm" disabled={busy} onclick={() => revoked(() => revokeDelegate(d.userId))}>
									{t('sharing.revoke')}
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
				<div class="sj-sharing-actions">
					<Button variant="secondary" size="sm" onclick={() => (delegateOpen = true)}>
						{t('sharing.delegate_access')}
					</Button>
				</div>
			</Card>
		{/if}
	</div>
</div>

<ShareMailboxDialog open={delegateOpen} onClose={() => (delegateOpen = false)} onChanged={load} />
<Toast />

<style>
	.sj-sharing-page {
		height: 100%;
		overflow-y: auto;
		background: var(--surface-page);
	}
	.sj-sharing-inner {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}
	.sj-sharing-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 4px 0 0;
	}
	.sj-sharing-announce {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
	.sj-sharing-skeleton {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.sj-sharing-skeleton__row {
		height: 44px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: sj-sharing-shimmer 1.4s ease-in-out infinite;
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-sharing-skeleton__row {
			animation: none;
		}
	}

	@keyframes sj-sharing-shimmer {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.5;
		}
	}
	.sj-sharing-banner {
		margin: 0 0 8px;
		padding: 8px 12px;
		background: var(--info-bg);
		color: var(--text-secondary);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.sj-sharing-empty {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sj-sharing-error {
		margin: 0 0 8px;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
	.sj-sharing-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sj-sharing-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.sj-sharing-who {
		display: flex;
		flex-direction: column;
	}
	.sj-sharing-name {
		color: var(--text-primary);
	}
	.sj-sharing-perm {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-sharing-actions {
		margin-top: 12px;
	}
</style>
