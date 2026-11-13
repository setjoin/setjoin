<svelte:options runes={true} />

<script lang="ts">
	import { goto } from '$app/navigation';
	import { user, logout } from '$lib/stores/auth';
	import { jmapSession, effectiveCaps, loadSessionStore } from '$lib/stores/session';
	import { onMount } from 'svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { Button } from '$lib/components/ui';
	import type { ComponentProps } from 'svelte';
	import type { AppId } from '$lib/types/jmap';
	import { RAIL_APPS } from '$lib/nav/navConfig';
	import { t } from '$lib/i18n';

	type IconName = ComponentProps<typeof Icon>['name'];

	type AppTile = {
		id: string;
		name: string;
		desc: string;
		icon: IconName;
		accent: string;
		path: string;
		show: boolean | undefined;
	};

	// Per-app accent color, keyed the same as RAIL_APPS/AppId (the rail itself
	// doesn't need one — its icons are single-color — so this map lives here).
	const ACCENTS: Record<AppId, string> = {
		mail: 'var(--app-mail)',
		calendar: 'var(--app-calendar)',
		contacts: 'var(--success-solid)',
		tasks: 'var(--warning-solid)',
		approvals: 'var(--app-approvals)',
		drive: 'var(--app-drive)',
		chat: 'var(--app-chat)',
		meet: 'var(--app-meeting)',
	};

	// App visibility derives from the per-user effective-capabilities list
	// (single source of truth shared with the rail, drawer, and command palette),
	// not the coarser mailbox-only flag. Admin is gated separately on isAdmin.
	let enabledApps = $derived($effectiveCaps.enabledApps);
	const isEnabled = (id: AppId) => enabledApps.includes(id);

	// Tiles are driven off RAIL_APPS — the SAME list (and the SAME enabledApps
	// gate) the rail/drawer/palette use — so this page can never drift behind
	// them again (it previously hand-duplicated a stale 4-app subset). Admin
	// stays a separate, hardcoded tile: it isn't part of RAIL_APPS (the rail
	// exposes it as a set of sub-consoles, RAIL_ADMIN) and is gated on
	// isAdmin, not enabledApps.
	let apps = $derived<AppTile[]>([
		...RAIL_APPS.map((a) => ({
			id: a.id,
			name: t(`app.${a.id}`),
			desc: t(`apps.${a.id}.desc`),
			icon: a.icon,
			accent: ACCENTS[a.id],
			path: a.path,
			show: isEnabled(a.id),
		})),
		{ id: 'admin', name: t('app.admin'), desc: t('apps.admin.desc'), icon: 'Shield', accent: 'var(--app-admin)', path: '/admin', show: $user?.isAdmin },
	]);

	let visibleApps = $derived(apps.filter((a) => a.show));
	let loggingOut = $state(false);
	let logoutError = $state("");

	let brandName = $derived($jmapSession?.branding?.name || 'SetJoin');
	let brandLogoUrl = $derived($jmapSession?.branding?.logoUrl || '');

	onMount(() => {
		// Populate the shared session store (branding + effective capabilities)
		// once; the rail/drawer/palette read from the same store.
		if (!$jmapSession) void loadSessionStore();
	});

	async function doLogout() {
		if (loggingOut) return;
		loggingOut = true;
		logoutError = '';
		try {
			await logout();
			goto('/');
		} catch {
			logoutError = t('apps.logout_error');
			goto('/');
		} finally {
			loggingOut = false;
		}
	}
</script>

{#snippet signOutIcon()}<Icon name="LogOut" size={14} />{/snippet}

<div class="apps-page">
	<header class="apps-header toolbar">
		<div class="brand">
			{#if brandLogoUrl}
				<img class="brand-logo" src={brandLogoUrl} alt={brandName} />
			{:else}
				<span class="brand-mark"><Icon name="LayoutGrid" size={18} /></span>
			{/if}
			<span class="brand-name">{brandName}</span>
			<span class="brand-tagline">集合</span>
		</div>
		<div class="user-menu">
			<span class="user-email">{$user?.email}</span>
			<Button variant="secondary" size="sm" onclick={doLogout} disabled={loggingOut} icon={signOutIcon}>
				{loggingOut ? 'Signing out…' : 'Sign out'}
			</Button>
			{#if logoutError}
				<span class="logout-error">{logoutError}</span>
			{/if}
		</div>
	</header>

	<main class="apps-main">
		<div class="apps-inner">
			<h1 class="apps-title">{t('apps.title')}</h1>
			{#if visibleApps.length === 0}
				<div class="empty-state">
					<span class="empty-state-icon"><Icon name="LayoutGrid" size={28} /></span>
					<div class="empty-state-title">{t('apps.empty')}</div>
					<div class="empty-state-desc">{t('apps.empty_hint')}</div>
				</div>
			{:else}
				<div class="apps-grid">
					{#each visibleApps as app (app.id)}
						<a href={app.path} class="app-tile" style="--tile-accent: {app.accent};">
							<span class="app-accent-bar"></span>
							<span class="app-icon"><Icon name={app.icon} size={26} /></span>
							<span class="app-name">{app.name}</span>
							<span class="app-desc">{app.desc}</span>
						</a>
					{/each}
				</div>
			{/if}
		</div>
	</main>
</div>

<style>
	.apps-page {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
		background: transparent;
	}

	/* ---- header ---- */
	.apps-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-3) var(--space-6);
		position: sticky;
		top: 0;
		z-index: 10;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-family: var(--font-sans);
		font-size: var(--text-lg);
		font-weight: var(--weight-bold);
		color: var(--text-primary);
		letter-spacing: -0.01em;
	}

	.brand-mark {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 30px;
		height: 30px;
		border-radius: var(--radius-sm);
		background: var(--accent-subtle);
		color: var(--accent);
	}

	.brand-logo {
		height: 30px;
		width: auto;
	}

	.brand-name {
		font-weight: var(--weight-bold);
	}

	.brand-tagline {
		font-family: "Noto Sans SC", var(--font-sans);
		font-size: var(--text-xs);
		font-weight: var(--weight-regular);
		color: var(--text-tertiary);
		letter-spacing: 0.08em;
		padding-left: var(--space-1);
		border-left: 1px solid var(--border-default);
	}

	.user-menu {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.user-email {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}

	.logout-error {
		color: var(--danger);
		font-size: var(--text-xs);
		white-space: nowrap;
	}

	/* ---- main ---- */
	.apps-main {
		flex: 1;
		display: flex;
		justify-content: center;
		padding: var(--space-12) var(--space-6);
	}

	.apps-inner {
		width: 100%;
		max-width: 840px;
	}

	.apps-title {
		font-family: var(--font-sans);
		font-size: var(--text-3xl);
		line-height: var(--leading-tight);
		font-weight: var(--weight-bold);
		letter-spacing: -0.02em;
		color: var(--text-primary);
		margin: 0 0 var(--space-8) 0;
	}

	/* ---- grid ---- */
	.apps-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
		gap: var(--space-5);
	}

	.app-tile {
		position: relative;
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-1);
		padding: var(--space-6) var(--space-5) var(--space-5);
		overflow: hidden;
		text-decoration: none;
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-xs);
		transition: transform var(--duration-base) var(--ease-out),
					box-shadow var(--duration-base) var(--ease-out);
	}

	.app-tile:hover {
		transform: translateY(-4px);
		box-shadow: var(--shadow-md);
	}

	.app-tile:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.app-accent-bar {
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		height: 3px;
		background: var(--tile-accent);
	}

	.app-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 48px;
		height: 48px;
		border-radius: var(--radius-md);
		color: var(--tile-accent);
		background: color-mix(in srgb, var(--tile-accent) 14%, transparent);
		margin-bottom: var(--space-1);
	}

	.app-name {
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		letter-spacing: -0.005em;
	}

	.app-desc {
		font-size: var(--text-xs);
		line-height: var(--leading-normal);
		color: var(--text-tertiary);
	}

	/* ---- empty state ---- */
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: var(--space-1);
		padding: var(--space-16) var(--space-6);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}

	.empty-state-icon {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 56px;
		height: 56px;
		border-radius: var(--radius-full);
		background: var(--surface-sunken);
		color: var(--text-tertiary);
		margin-bottom: var(--space-1);
	}

	.empty-state-title {
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.empty-state-desc {
		font-size: var(--text-md);
		color: var(--text-tertiary);
		max-width: 36ch;
	}

	/* ---- mobile ---- */
	@media (max-width: 640px) {
		.apps-header {
			padding: var(--space-2) var(--space-4);
		}

		.apps-main {
			padding: var(--space-6) var(--space-4);
		}

		.apps-title {
			margin-bottom: var(--space-5);
		}

		.apps-grid {
			grid-template-columns: repeat(2, 1fr);
			gap: var(--space-3);
		}

		.app-tile {
			padding: var(--space-4) var(--space-3);
		}

		.brand-tagline,
		.user-email {
			display: none;
		}
	}
</style>
