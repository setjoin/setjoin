<svelte:options runes={true} />

<script lang="ts">
	import { Avatar } from '$lib/components/ui';
	import Icon, { type IconName } from '$lib/components/Icon.svelte';
	import type { AppId } from '$lib/types/jmap';
	import { GUEST_APPS, RAIL_APPS, RAIL_ADMIN } from '$lib/nav/navConfig';
	import type { AdminConsoleId } from '$lib/nav/navConfig';
	import { t } from '$lib/i18n';
	import { user } from '$lib/stores/auth';

	interface Props {
		enabledApps: AppId[];
		activeApp: string;
		adminConsoles: AdminConsoleId[];
		theme: 'light' | 'dark';
		userName: string;
		userEmail: string;
		appBadges?: Partial<Record<AppId, number>>;
		guest?: boolean;
		onNavigate: (path: string) => void;
		onToggleTheme?: () => void;
		onSignOut: () => void;
	}

	let {
		enabledApps,
		activeApp,
		adminConsoles,
		theme,
		userName,
		userEmail,
		appBadges,
		guest = false,
		onNavigate,
		onToggleTheme,
		onSignOut,
	}: Props = $props();

	// A guest's rail is fail-closed CLIENT-side too — the server
	// caps intersection alone isn't enough (an absent-caps gateway enables
	// every app, FALLBACK_CAPS). GUEST_APPS contains only the guest-capable
	// Chat and Meet surfaces; the resolved capability set narrows it further.
	let guestSession = $derived(guest || $user?.accountType === 'guest');
	let visibleApps = $derived(
		RAIL_APPS.filter(
			(a) =>
				enabledApps.includes(a.id) &&
				(!guestSession || GUEST_APPS.includes(a.id))
		)
	);
	let visibleAdmin = $derived(guestSession ? [] : RAIL_ADMIN.filter((a) => adminConsoles.includes(a.id)));
	let themeLabel = $derived(theme === 'light' ? t('shell.dark_mode') : t('shell.light_mode'));
	let themeIcon: IconName = $derived(theme === 'light' ? 'Moon' : 'Sun');

	function appLabel(id: AppId): string {
		return t(`app.${id}`);
	}

	function adminLabel(id: AdminConsoleId): string {
		return t(`admin.console.${id}`);
	}
</script>

<nav class="sj-rail" aria-label="Main navigation" data-tour="apps">
	<!-- Logomark -->
	<img src="/brand/logo-mark.svg" class="sj-ink" alt="SetJoin" width="26" height="26" />

	<!-- App buttons -->
	{#each visibleApps as app (app.id)}
		{@const isActive = activeApp === app.id}
		{@const label = appLabel(app.id)}
		<button
			class="sj-rail-btn"
			class:sj-rail-btn--active={isActive}
			aria-label={label}
			title={label}
			aria-current={isActive ? 'page' : undefined}
			onclick={() => onNavigate(app.path)}
		>
			<span class="sj-rail-app-icon">
				<Icon name={app.icon} size={18} strokeWidth={1.75} />
				{#if (appBadges?.[app.id] ?? 0) > 0}
					<span class="sj-rail-badge" aria-label="{appBadges![app.id]} pending">{(appBadges![app.id] ?? 0) > 99 ? '99+' : appBadges![app.id]}</span>
				{/if}
			</span>
		</button>
	{/each}

	<!-- Admin section (only when adminConsoles is non-empty) -->
	{#if visibleAdmin.length > 0}
		<div class="sj-rail-divider" aria-hidden="true"></div>
		{#each visibleAdmin as admin (admin.id)}
			{@const isActive = activeApp === admin.id}
			{@const label = adminLabel(admin.id)}
			<button
				class="sj-rail-btn"
				class:sj-rail-btn--active={isActive}
				aria-label={label}
				title={label}
				aria-current={isActive ? 'page' : undefined}
				onclick={() => onNavigate(admin.path)}
			>
				<Icon name={admin.icon} size={18} strokeWidth={1.75} />
			</button>
		{/each}
	{/if}

	<!-- Spacer pushes bottom cluster down -->
	<div class="sj-rail-spacer"></div>

	<!-- Theme toggle (only when handler provided) -->
	{#if onToggleTheme}
		<button
			class="sj-rail-btn"
			aria-label={themeLabel}
			title={themeLabel}
			onclick={onToggleTheme}
		>
			<Icon name={themeIcon} size={18} strokeWidth={1.75} />
		</button>
	{/if}

	{#if !guestSession}
		<!-- Settings is a member surface; guest self-service is intentionally absent in G2. -->
		<button
			class="sj-rail-btn"
			class:sj-rail-btn--active={activeApp === 'settings'}
			aria-label={t('app.settings')}
			title={t('app.settings')}
			aria-current={activeApp === 'settings' ? 'page' : undefined}
			onclick={() => onNavigate('/settings')}
		>
			<Icon name="Settings" size={18} strokeWidth={1.75} />
		</button>
	{/if}

	<!-- Avatar / sign-out -->
	<button
		class="sj-rail-avatar-btn"
		aria-label={t('shell.sign_out')}
		title="{userEmail} — {t('shell.sign_out').toLowerCase()}"
		onclick={onSignOut}
	>
		<Avatar name={userName} size="md" />
	</button>

	<!-- P14: a guest's own self-marker — so a guest always knows it is a guest. -->
	{#if guestSession}
		<span class="sj-rail-external-badge">{t('chat.externalBadge')}</span>
	{/if}
</nav>

<style>
	.sj-rail {
		display: none;
		width: 56px;
		flex: none;
		flex-direction: column;
		align-items: center;
		gap: 4px;
		padding: 10px 0;
		background: var(--surface-card);
		border-right: 1px solid var(--border-default);
		height: 100%;
		overflow: hidden;
	}

	@media (min-width: 768px) {
		.sj-rail {
			display: flex;
		}
	}

	.sj-ink {
		margin-bottom: 8px;
		flex: none;
	}

	.sj-rail-btn {
		width: 38px;
		height: 38px;
		flex: none;
		border: none;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: var(--radius-sm);
		background: transparent;
		color: var(--text-secondary);
		transition:
			background var(--duration-fast) var(--ease-out),
			color var(--duration-fast) var(--ease-out);
	}

	.sj-rail-btn:hover {
		background: var(--surface-hover);
		color: var(--text-secondary);
	}

	.sj-rail-btn--active {
		background: var(--surface-selected);
		color: var(--accent-fg-on-subtle);
	}

	.sj-rail-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-rail-divider {
		width: 24px;
		height: 1px;
		background: var(--border-default);
		margin: 8px 0 4px;
		flex: none;
	}

	.sj-rail-spacer {
		flex: 1;
	}

	.sj-rail-avatar-btn {
		border: none;
		background: none;
		padding: 0;
		cursor: pointer;
		margin-top: 4px;
		flex: none;
		border-radius: var(--radius-full);
	}

	.sj-rail-avatar-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-rail-app-icon {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.sj-rail-external-badge {
		flex: none;
		margin-top: 4px;
		padding: 1px 5px;
		border-radius: var(--radius-sm);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: 9px;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.02em;
	}

	.sj-rail-badge {
		position: absolute;
		top: -6px;
		right: -8px;
		background: var(--accent);
		color: var(--text-inverse);
		font-family: var(--font-mono);
		font-size: 9px;
		font-weight: 700;
		min-width: 14px;
		height: 14px;
		border-radius: var(--radius-full);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 0 3px;
		line-height: 1;
	}
</style>
