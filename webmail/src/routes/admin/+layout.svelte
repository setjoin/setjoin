<svelte:options runes={true} />

<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { authenticated, user, logout, authInitializing, adminConsoles, adminPermissions, hasPermission } from '$lib/stores/auth';
	import { effectiveCaps, sessionResolved } from '$lib/stores/session';
	import { t } from '$lib/i18n';
	import { CONSOLES, navForConsoles, type ConsoleId } from '$lib/admin/consoles';
	import { consoleForPath, allowedPath, firstConsolePath } from '$lib/admin/guard';
	import { SidebarItem, IconButton, Spinner, Button } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import AssistDrawer from '$lib/components/admin/AssistDrawer.svelte';

	let { children } = $props();

	let mobileOpen = $state(false);
	let activeConsole = $state<ConsoleId | null>(null);
	let assistOpen = $state(false);
	let sidebarEl = $state<HTMLElement | null>(null);
	let hamburgerEl = $state<HTMLButtonElement | null>(null);

	const FOCUSABLE =
		'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

	/** Mobile-drawer keydown: Escape closes, Tab/Shift+Tab trap focus inside the panel. */
	function onDrawerKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			e.preventDefault();
			mobileOpen = false;
			return;
		}
		if (e.key !== 'Tab' || !sidebarEl) return;
		const items = Array.from(sidebarEl.querySelectorAll<HTMLElement>(FOCUSABLE));
		if (items.length === 0) {
			e.preventDefault();
			sidebarEl.focus();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		const inside = active !== null && sidebarEl.contains(active);
		if (e.shiftKey) {
			if (!inside || active === first || active === sidebarEl) {
				e.preventDefault();
				last.focus();
			}
		} else if (!inside || active === last || active === sidebarEl) {
			e.preventDefault();
			first.focus();
		}
	}

	// Focus the drawer when it opens on mobile; return focus to the hamburger on close.
	$effect(() => {
		if (!mobileOpen) return;
		const previouslyFocused = document.activeElement as HTMLElement | null;
		sidebarEl?.focus();
		return () => {
			(previouslyFocused ?? hamburgerEl)?.focus();
		};
	});

	// Keep active console in sync with the current URL.
	$effect(() => {
		const resolved = consoleForPath(page.url.pathname);
		if (resolved) {
			activeConsole = resolved;
		} else if ($adminConsoles.length > 0) {
			activeConsole = $adminConsoles[0];
		}
	});

	// Route guard — redirect unauthenticated users, users with zero consoles,
	// and users navigating to a console they cannot see (S6 layer 1 UX).
	$effect(() => {
		if ($authInitializing) return;
		if (!$authenticated) { goto('/'); return; }
		// My-roles is self-service (requireAuth only): reachable by any authenticated
		// user — a dormant-eligible admin with zero live consoles, and the cold-start
		// case where is_admin isn't true yet. Never bounce it.
		if (page.url.pathname === '/admin/my-roles') return;
		// Wait for capabilities to resolve before deciding on zero-console redirects:
		// checkAuth fires loadSessionStore fire-and-forget, so $adminConsoles is briefly
		// [] right after auth init even for a full admin — without this gate a fresh
		// load / refresh of a deep console link bounces to my-roles. (my-roles itself
		// returned above, so a genuinely dormant admin still reaches it once resolved.)
		if (!$sessionResolved) return;
		if ($adminConsoles.length === 0) {
			// D10 dormant-admin gate: a dormant-eligible admin (is_admin true, zero
			// live perms) lands on My-roles to activate — not a shown-then-403 console,
			// and not /apps.
			if ($user?.isAdmin) { goto('/admin/my-roles'); return; }
			goto('/apps');
			return;
		}
		if (!allowedPath(page.url.pathname, $adminConsoles)) {
			goto(firstConsolePath($adminConsoles));
		}
	});

	async function doLogout() {
		await logout();
		goto('/');
	}

	function switchConsole(id: ConsoleId) {
		activeConsole = id;
		const def = CONSOLES.find((c) => c.id === id);
		if (def && def.items.length > 0) {
			goto(def.items[0].path);
		}
	}

	function isActive(path: string): boolean {
		if (path === '/admin') return page.url.pathname === '/admin';
		return page.url.pathname.startsWith(path);
	}

	function consoleLabel(id: ConsoleId): string {
		return t(CONSOLES.find((c) => c.id === id)?.label ?? 'admin.console.mail');
	}

	function hasItemPermission(perm: string | readonly string[] | undefined): boolean {
		if (!perm) return true;
		return Array.isArray(perm)
			? perm.some((candidate) => hasPermission($adminPermissions, candidate))
			: hasPermission($adminPermissions, perm as string);
	}

	// Visible consoles and active console's nav items.
	let visibleConsoles = $derived(navForConsoles($adminConsoles));
	let activeConsoleDef = $derived(CONSOLES.find((c) => c.id === activeConsole));
	// Per-item permission gate: a Super-only surface (e.g. scope-sets) stays hidden
	// from a caller who can see the console but lacks the item's permission.
	let sidebarItems = $derived(
		(activeConsoleDef?.items ?? []).filter((i) => hasItemPermission(i.perm))
	);
</script>

{#if $authInitializing}
	<div class="loading-screen">
		<Spinner size={28} />
		<p>{t('common.loading')}</p>
	</div>
{:else if $adminConsoles.length > 0}
	<div class="admin-layout">
		<!-- ── Mobile hamburger ── -->
		<button
			class="hamburger"
			bind:this={hamburgerEl}
			onclick={() => (mobileOpen = !mobileOpen)}
			aria-label={mobileOpen ? t('admin.sidebar.close_menu') : t('admin.sidebar.open_menu')}
		>
			<Icon name={mobileOpen ? 'X' : 'Menu'} size={20} strokeWidth={1.75} />
		</button>

		{#if mobileOpen}
			<div
				class="overlay"
				role="presentation"
				onmousedown={() => (mobileOpen = false)}
			></div>
		{/if}

		<!-- ── Console sidebar (200px) — mobile drawer is a focus-trapped dialog ── -->
		<!-- svelte-ignore a11y_no_static_element_interactions, a11y_no_noninteractive_tabindex -->
		<aside
			class="console-sidebar"
			class:mobile-visible={mobileOpen}
			bind:this={sidebarEl}
			role={mobileOpen ? 'dialog' : undefined}
			aria-modal={mobileOpen ? 'true' : undefined}
			aria-label={mobileOpen ? t('admin.sidebar.open_menu') : undefined}
			tabindex={mobileOpen ? -1 : undefined}
			onkeydown={mobileOpen ? onDrawerKeydown : undefined}
		>
			<!-- Console switcher tabs at top -->
			<div class="console-switcher">
				{#each visibleConsoles as c (c.id)}
					{@const isActiveC = activeConsole === c.id}
					<button
						class="console-tab"
						class:console-tab--active={isActiveC}
						aria-label={consoleLabel(c.id)}
						title={consoleLabel(c.id)}
						onclick={() => switchConsole(c.id)}
					>
						<Icon name={c.icon} size={16} strokeWidth={1.75} />
						{#if isActiveC}
							<span class="console-tab-label">{consoleLabel(c.id)}</span>
						{/if}
					</button>
				{/each}
			</div>

			<nav class="console-nav">
				{#each sidebarItems as item}
					{#snippet sideIcon()}<Icon name={item.icon} size={16} strokeWidth={1.75} />{/snippet}
					<SidebarItem
						label={t(item.label)}
						active={isActive(item.path)}
						onclick={() => {
							goto(item.path);
							mobileOpen = false;
						}}
						icon={sideIcon}
					>
					</SidebarItem>
				{/each}
			</nav>

			<div class="console-sidebar-footer">
				<span class="sidebar-user">{$user?.email}</span>
				<IconButton
					label={t('layout.nav.logout')}
					variant="ghost"
					size="sm"
					onclick={doLogout}
				>
					<Icon name="LogOut" size={16} strokeWidth={1.75} />
				</IconButton>
			</div>
		</aside>

		<!-- ── Main content ── -->
		<main class="admin-content">
			<div class="sj-admin-main">
				{@render children()}
			</div>
		</main>

		<!-- Assist toggle + drawer (admin-kit §2.4, §6) -->
		{#if $effectiveCaps.assist}
			<button
				class="assist-toggle-btn"
				onclick={() => (assistOpen = !assistOpen)}
				aria-label={assistOpen ? t('shell.close_panel') : t('admin.assist.title')}
				title={t('admin.assist.title')}
			>
				<Icon name="Sparkles" size={16} strokeWidth={1.75} />
			</button>

			<AssistDrawer
				open={assistOpen}
				onClose={() => (assistOpen = false)}
			/>
		{/if}
	</div>
{/if}

<style>
	.admin-layout {
		display: flex;
		height: 100%;
		overflow: hidden;
		background: var(--surface-page);
	}

	/* ── Hamburger ── */
	.hamburger {
		display: flex;
		align-items: center;
		justify-content: center;
		position: fixed;
		top: 12px;
		left: 12px;
		z-index: 901;
		width: 44px;
		height: 44px;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		cursor: pointer;
		color: var(--text-secondary);
		padding: 0;
	}

	.hamburger:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	@media (min-width: 768px) {
		.hamburger { display: none; }
	}

	.overlay {
		display: block;
		position: fixed;
		inset: 0;
		background: var(--scrim);
		z-index: 899;
	}

	@media (min-width: 768px) {
		.overlay { display: none; }
	}

	/* ── Console sidebar (200px, desktop) ── */
	.console-sidebar {
		display: flex;
		flex-direction: column;
		width: 200px;
		min-width: 200px;
		flex: none;
		background: var(--surface-sidebar);
		border-right: 1px solid var(--border-default);
		overflow: hidden;
		outline: none;
	}

	@media (max-width: 767px) {
		.console-sidebar { display: none; }

		.console-sidebar.mobile-visible {
			display: flex;
			position: fixed;
			left: 0;
			top: 0;
			bottom: 0;
			z-index: 901;
			width: min(304px, 85vw);
			min-width: min(304px, 85vw);
			box-shadow: var(--shadow-lg);
			animation: sjDrawerIn var(--duration-base) var(--ease-out);
		}
	}

	@keyframes sjDrawerIn {
		from { transform: translateX(-16px); opacity: 0; }
		to   { transform: none; opacity: 1; }
	}

	@media (prefers-reduced-motion: reduce) {
		.console-sidebar.mobile-visible { animation: none; }
	}

	/* ── Console switcher tabs ── */
	.console-switcher {
		display: flex;
		gap: 2px;
		padding: 10px 8px 4px;
		border-bottom: 1px solid var(--border-default);
	}

	.console-tab {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 8px;
		border: none;
		border-radius: var(--radius-sm);
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		white-space: nowrap;
		transition: background var(--duration-fast) var(--ease-out),
		            color var(--duration-fast) var(--ease-out);
	}

	.console-tab:hover {
		background: var(--surface-hover);
		color: var(--text-primary);
	}

	.console-tab--active {
		background: var(--surface-selected);
		color: var(--accent-fg-on-subtle);
	}

	.console-tab:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.console-tab-label {
		overflow: hidden;
		text-overflow: ellipsis;
	}

	/* ── Nav ── */
	.console-nav {
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: 1px;
		padding: 8px;
		overflow-y: auto;
	}

	.console-sidebar-footer {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 12px;
		border-top: 1px solid var(--border-default);
		font-size: var(--text-xs);
	}

	.sidebar-user {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		flex: 1;
	}

	/* ── Main content ── */
	.admin-content {
		flex: 1;
		min-width: 0;
		overflow-y: auto;
		padding: clamp(14px, 3vw, 28px);
		background: var(--surface-page);
	}

	/* 980px max-width content wrapper */
	.sj-admin-main {
		max-width: 980px;
	}

	/* ── Loading screen ── */
	.loading-screen {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		height: 100vh;
		gap: 16px;
		background: var(--surface-page);
		color: var(--text-secondary);
		font-family: var(--font-sans);
	}

	/* ── Assist toggle button ── */
	.assist-toggle-btn {
		position: fixed;
		bottom: 20px;
		right: 20px;
		z-index: 700;
		width: 38px;
		height: 38px;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		cursor: pointer;
		color: var(--accent);
		padding: 0;
		transition: background var(--duration-fast) var(--ease-out),
		            box-shadow var(--duration-fast) var(--ease-out);
	}

	.assist-toggle-btn:hover {
		background: var(--surface-hover);
		box-shadow: var(--shadow-lg);
	}

	.assist-toggle-btn:active {
		background: var(--surface-selected);
	}

	.assist-toggle-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
