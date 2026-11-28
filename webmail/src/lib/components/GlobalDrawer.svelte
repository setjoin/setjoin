<svelte:options runes={true} />

<script lang="ts">
	import Icon, { type IconName } from '$lib/components/Icon.svelte';
	import type { AppId } from '$lib/types/jmap';
	import { GUEST_APPS, RAIL_APPS, RAIL_ADMIN } from '$lib/nav/navConfig';
	import type { AdminConsoleId } from '$lib/nav/navConfig';
	import { t } from '$lib/i18n';
	import { focusTrap } from '$lib/actions/focusTrap';
	import { user } from '$lib/stores/auth';

	interface Props {
		open: boolean;
		enabledApps: AppId[];
		activeApp: string;
		adminConsoles: AdminConsoleId[];
		theme: 'light' | 'dark';
		userName: string;
		userEmail: string;
		onNavigate: (path: string) => void;
		onToggleTheme?: () => void;
		onSignOut: () => void;
		onClose: () => void;
		guest?: boolean;
	}

	let {
		open,
		enabledApps,
		activeApp,
		adminConsoles,
		theme,
		userName,
		userEmail,
		onNavigate,
		onToggleTheme,
		onSignOut,
		onClose,
		guest = false,
	}: Props = $props();

	let guestSession = $derived(guest || $user?.accountType === 'guest');
	let visibleApps = $derived(RAIL_APPS.filter((a) => enabledApps.includes(a.id) && (!guestSession || GUEST_APPS.includes(a.id))));
	let visibleAdmin = $derived(guestSession ? [] : RAIL_ADMIN.filter((a) => adminConsoles.includes(a.id)));
	let themeLabel = $derived(theme === 'light' ? t('shell.dark_mode') : t('shell.light_mode'));
	let themeIcon: IconName = $derived(theme === 'light' ? 'Moon' : 'Sun');

	function appLabel(id: AppId): string {
		return t(`app.${id}`);
	}

	function adminLabel(id: AdminConsoleId): string {
		return t(`admin.console.${id}`);
	}

	function handleRowClick(path: string) {
		onNavigate(path);
		onClose();
	}
</script>

{#if open}
	<!-- Backdrop -->
	<div class="sj-drawer-backdrop" onclick={onClose} aria-hidden="true"></div>

	<!-- Drawer panel -->
	<div class="sj-drawer" role="dialog" aria-modal="true" aria-label="Navigation menu" tabindex="-1" use:focusTrap={{ onEscape: () => onClose() }}>
		<!-- App rows -->
		{#each visibleApps as app (app.id)}
			{@const isActive = activeApp === app.id}
			<button
				class="sj-drawer-row"
				class:is-active={isActive}
				aria-current={isActive ? 'page' : undefined}
				onclick={() => handleRowClick(app.path)}
			>
				<Icon name={app.icon} size={17} strokeWidth={1.75} />
				<span>{appLabel(app.id)}</span>
			</button>
		{/each}

		<div class="sj-drawer-divider" aria-hidden="true"></div>

		<!-- Admin rows (only when non-empty) -->
		{#if visibleAdmin.length > 0}
			{#each visibleAdmin as admin (admin.id)}
				{@const isActive = activeApp === admin.id}
				<button
					class="sj-drawer-row"
					class:is-active={isActive}
					aria-current={isActive ? 'page' : undefined}
					onclick={() => handleRowClick(admin.path)}
				>
					<Icon name={admin.icon} size={17} strokeWidth={1.75} />
					<span>{adminLabel(admin.id)}</span>
				</button>
			{/each}

			<div class="sj-drawer-divider" aria-hidden="true"></div>
		{/if}

		<!-- Theme row (only when handler provided) -->
		{#if onToggleTheme}
			<button
				class="sj-drawer-row"
				onclick={() => { onToggleTheme?.(); onClose(); }}
			>
				<Icon name={themeIcon} size={17} strokeWidth={1.75} />
				<span>{themeLabel}</span>
			</button>
		{/if}

		{#if !guestSession}
			<!-- Settings row -->
			<button class="sj-drawer-row" onclick={() => handleRowClick('/settings')}>
				<Icon name="Settings" size={17} strokeWidth={1.75} />
				<span>{t('app.settings')}</span>
			</button>
		{/if}

		<!-- Sign out row -->
		<button
			class="sj-drawer-row"
			onclick={() => { onSignOut(); onClose(); }}
		>
			<Icon name="LogOut" size={17} strokeWidth={1.75} />
			<span>{t('shell.sign_out')}</span>
		</button>

		<!-- User email footer -->
		<div class="sj-drawer-footer">{userEmail}</div>
	</div>
{/if}

<style>
	.sj-drawer-backdrop {
		position: fixed;
		inset: 0;
		background: var(--scrim);
		z-index: 900;
	}

	.sj-drawer {
		position: fixed;
		top: 0;
		left: 0;
		bottom: 0;
		width: min(304px, 85vw);
		background: var(--surface-card);
		border-right: 1px solid var(--border-default);
		z-index: 901;
		overflow-y: auto;
		padding: 12px 10px;
		animation: sjDrawerIn var(--duration-base) var(--ease-out);
		outline: none;
	}

	@keyframes sjDrawerIn {
		from {
			transform: translateX(-16px);
			opacity: 0;
		}
		to {
			transform: none;
			opacity: 1;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-drawer {
			animation: none;
		}
	}

	.sj-drawer-row {
		display: flex;
		align-items: center;
		gap: 12px;
		width: 100%;
		min-height: 44px;
		padding: 0 10px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-md);
		font-weight: 500;
		color: var(--text-primary);
		cursor: pointer;
		text-align: left;
	}

	.sj-drawer-row:hover,
	.sj-drawer-row:active {
		background: var(--surface-hover);
	}

	.sj-drawer-row.is-active {
		background: var(--surface-selected);
		color: var(--accent-fg-on-subtle);
	}

	.sj-drawer-divider {
		height: 1px;
		background: var(--border-default);
		margin: 8px 0;
	}

	.sj-drawer-footer {
		padding: 10px 10px 0;
		font-size: var(--text-2xs);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
</style>
