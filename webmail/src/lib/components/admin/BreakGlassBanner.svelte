<svelte:options runes={true} />
<!--
  BreakGlassBanner — step-zero persistent banner at the top of the CA page.
  Shows the break-glass set/unset status; loud when unset, quiet when set.

  Props:
    onSetBg ()=>void    — called to open the set-break-glass picker dialog
    onEditBg ()=>void   — called to open the edit dialog

  API consumed:
    GET /admin/conditional-access/break-glass
    Response: { admins: [{id,email,display_name}] }
    (Task 9 will wire the backend; this component degrades gracefully until then.)
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { Avatar, Spinner, Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { adminFetch } from '$lib/admin/client';

	interface BgAdmin {
		id: number;
		email: string;
		display_name: string;
	}

	let {
		onSetBg,
		onEditBg,
		onAdminIds,
	}: {
		onSetBg: () => void;
		onEditBg: () => void;
		onAdminIds?: (ids: number[]) => void;
	} = $props();

	// ── State ──
	type BannerState = 'loading' | 'error' | 'unset' | 'set';
	let bannerState: BannerState = $state('loading');
	let admins: BgAdmin[] = $state([]);
	let errorMsg = $state('');

	onMount(async () => {
		await loadBg();
	});

	async function loadBg() {
		bannerState = 'loading';
		errorMsg = '';
		try {
			const res = await adminFetch('/admin/conditional-access/break-glass');
			if (!res.ok) {
				if (res.status === 404) {
					// Task 9 not yet wired — 404 = treat as unset (not an error yet)
					admins = [];
					bannerState = 'unset';
					onAdminIds?.([]);
					return;
				}
				throw new Error(String(res.status));
			}
			const data: { admins: BgAdmin[] } = await res.json();
			admins = data.admins ?? [];
			bannerState = admins.length === 0 ? 'unset' : 'set';
			onAdminIds?.(admins.map((a) => a.id));
		} catch (e) {
			errorMsg = String(e);
			bannerState = 'error';
			admins = [];
		}
	}

	// Export the loaded admins for parent use in preflightImpact
	export function getAdminIds(): number[] {
		return admins.map((a) => a.id);
	}
</script>

<div class="bg-banner" data-testid="bg-banner">
	{#if bannerState === 'loading'}
		<!-- Loading skeleton -->
		<div class="bg-banner__skeleton" role="status" aria-label={t('admin.ca.list.loading')}>
			<span class="sr-only">{t('admin.ca.list.loading')}</span>
			<div class="bg-banner__skel-line"></div>
		</div>

	{:else if bannerState === 'error'}
		<!-- Error + retry -->
		<div class="bg-banner__error" role="alert" data-testid="bg-banner-error">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
				<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
				<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
			</svg>
			<span>{errorMsg || t('admin.ca.bg.load_error')}</span>
			<Button variant="secondary" size="sm" onclick={loadBg}>{t('common.retry')}</Button>
		</div>

	{:else if bannerState === 'unset'}
		<!-- Unset — LOUD: primary action prominent -->
		<div class="bg-banner__unset" role="status" data-testid="bg-banner-unset">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" class="bg-banner__icon bg-banner__icon--warn">
				<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
				<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
			</svg>
			<span class="bg-banner__msg">{t('admin.ca.bg.unset')}</span>
			<Button variant="primary" size="sm" onclick={onSetBg} data-testid="bg-banner-set-cta">
				{t('admin.ca.bg.set_cta')}
			</Button>
		</div>

	{:else}
		<!-- Set — quiet: success-tinted, chips + edit button -->
		<div class="bg-banner__set" role="status" data-testid="bg-banner-set">
			<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" class="bg-banner__icon bg-banner__icon--ok">
				<path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/>
				<polyline points="16 10 11 15 8 12"/>
			</svg>
			<span class="bg-banner__msg bg-banner__msg--quiet">
				{t('admin.ca.bg.set', { n: String(admins.length) })}
			</span>
			<!-- Resolved chips (read-only) -->
			<div class="bg-banner__chips" aria-label="Break-glass admins">
				{#each admins.slice(0, 5) as a (a.id)}
					<span class="bg-banner__chip" title={a.display_name || a.email}>
						<Avatar name={a.display_name || a.email} size="sm" />
						<span class="bg-banner__chip-name">{a.display_name || a.email}</span>
					</span>
				{/each}
				{#if admins.length > 5}
					<span class="bg-banner__more">+{admins.length - 5}</span>
				{/if}
			</div>
			<Button variant="secondary" size="sm" onclick={onEditBg} data-testid="bg-banner-edit-cta">
				{t('admin.ca.bg.edit_cta')}
			</Button>
		</div>
	{/if}
</div>

<style>
	.bg-banner {
		margin-bottom: 16px;
		font-family: var(--font-sans);
	}

	/* Loading skeleton */
	.bg-banner__skeleton {
		height: 40px;
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		overflow: hidden;
		position: relative;
	}
	.bg-banner__skel-line {
		position: absolute;
		inset: 0;
		background: linear-gradient(90deg, var(--gray-100) 25%, var(--gray-200) 50%, var(--gray-100) 75%);
		background-size: 400% 100%;
		animation: bg-shimmer var(--duration-slow) ease-in-out infinite;
	}

	/* Error */
	.bg-banner__error {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	/* Unset — warning bed */
	.bg-banner__unset {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 10px 14px;
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-sm);
	}

	/* Set — success bed (quiet) */
	.bg-banner__set {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 8px;
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		background: var(--success-bg);
		color: var(--success-fg);
		font-size: var(--text-sm);
	}

	.bg-banner__icon--warn {
		flex: none;
		margin-top: 2px;
		color: var(--warning-solid);
	}
	.bg-banner__icon--ok {
		flex: none;
		color: var(--success-solid);
	}

	.bg-banner__msg {
		flex: 1;
		line-height: var(--leading-normal);
	}
	.bg-banner__msg--quiet {
		font-weight: var(--weight-medium);
	}

	.bg-banner__chips {
		display: flex;
		align-items: center;
		gap: 6px;
		flex-wrap: wrap;
	}

	.bg-banner__chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-xs);
	}

	.bg-banner__chip-name {
		max-width: 100px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		color: var(--success-fg);
	}

	.bg-banner__more {
		font-size: var(--text-xs);
		color: var(--success-fg);
		opacity: 0.7;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	@keyframes bg-shimmer {
		0% { background-position: 100% 50%; }
		100% { background-position: 0% 50%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.bg-banner__skel-line {
			animation: none;
		}
	}
</style>
