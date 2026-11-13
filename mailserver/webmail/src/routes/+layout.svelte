<svelte:options runes={true} />

<script lang="ts">
  import '../app.css';
  import { goto } from '$app/navigation';
  import { parseOIDCOPContinuation } from '$lib/auth/oidcContinue';
  import { page } from '$app/state';
  import { version as buildVersion } from '$app/environment';
  import { onMount, setContext } from 'svelte';
  import { authenticated, user, logout, checkAuth, ensureInitialAuthProbe, authInitializing, authResolution, impersonating, adminConsoles } from '$lib/stores/auth';
  import { deviceBlock } from '$lib/stores/deviceBlock';
  import { touRemediation } from '$lib/stores/touRemediation';
  import { riskRemediation } from '$lib/stores/riskRemediation';
  import { typedFetch } from '$lib/http';
  import TermsAcceptance from '$lib/components/TermsAcceptance.svelte';
  import RiskRemediation from '$lib/components/RiskRemediation.svelte';
  import { effectiveCaps, firstEnabledApp, jmapSession } from '$lib/stores/session';
  import { approvalsCount } from '$lib/stores/approvals.svelte';
  // ponytail: mirrors approvalsCount's own pattern — updated by ChatApp on load/
  // push, not globally polled from here; the badge shows 0/stale until the
  // user has opened Chat at least once this session (same tradeoff approvals
  // already accepted).
  import { chatStore } from '$lib/chat/store.svelte';
  import { composeStore } from '$lib/stores/compose';
  import { t } from '$lib/i18n';
  import Icon from '$lib/components/Icon.svelte';
  import AppRail from '$lib/components/AppRail.svelte';
  import AppTopbar from '$lib/components/AppTopbar.svelte';
  import GlobalDrawer from '$lib/components/GlobalDrawer.svelte';
  import CommandPalette from '$lib/components/CommandPalette.svelte';
  import WelcomeTour from '$lib/components/WelcomeTour.svelte';
  import DeviceNotApprovedBanner from '$lib/components/DeviceNotApprovedBanner.svelte';
  import RemindersWindow from '$lib/components/RemindersWindow.svelte';
  import { requestTour, shouldAutoRequestTour } from '$lib/onboarding/tour.svelte';
  import {
    TOUR_HOST_CONTEXT,
    type InboxReadiness,
    type TourHostContext,
  } from '$lib/onboarding/host';
  import { installWipeHandler, installCapsHandler } from '$lib/offline/wipe';
  import { composeOfflineCoordinatorForSession } from '$lib/offline/boot';
  import { installPushActionHandler } from '$lib/native/pushAction.svelte';
  import { installServiceWorkerGenerationCoordinator, type ServiceWorkerGenerationCoordinator } from '$lib/native/sw-coordinator';
  import { markProductInteractive, markProductReady } from '$lib/performance/marks';
  import { registerNativePush } from '$lib/push/subscribe';
  import type { AppId } from '$lib/types/jmap';
  import { GUEST_APPS, appForPath, type AdminConsoleId } from '$lib/nav/navConfig';

  let { children } = $props();

  // Shell state
  let drawerOpen = $state(false);
  let tourRequestedFor = $state<string | null>(null);
  let inboxReadiness = $state<InboxReadiness>('inactive');
  setContext<TourHostContext>(TOUR_HOST_CONTEXT, {
    setInboxReadiness(readiness) {
      inboxReadiness = readiness;
    },
  });

  // Multi-compose (QoL #18): announce the auto-minimize swap politely. When a new
  // compose opens over one or more existing windows they are minimized to the dock;
  // focus is moved into the new window by ComposeScreen — this narrates that for AT.
  let composeAnnounce = $state('');
  let prevComposeCount = 0;
  $effect(() => {
    const n = $composeStore.sessions.length;
    if (n > prevComposeCount && prevComposeCount > 0) {
      composeAnnounce = t('compose.auto_minimized_announce');
    }
    prevComposeCount = n;
  });
  let showCommandPalette = $state(false);
  let loggingOut = $state(false);
	let swGenerationCoordinator: ServiceWorkerGenerationCoordinator | null = null;
  let logoutError = $state('');
  let theme = $state<'light' | 'dark'>('light');
  // Guest identity comes from authenticated server state, independently of
  // capability loading. This keeps the shell constrained while JMAP caps are
  // absent, in flight, or failed.
  let guestSession = $derived($user?.accountType === 'guest' || $jmapSession?.isGuest === true);
  let shellEnabledApps = $derived<AppId[]>(
    guestSession
      ? ($jmapSession?.effectiveCapabilities
          ? $effectiveCaps.enabledApps.filter((app) => GUEST_APPS.includes(app))
          : ['chat'])
      : $effectiveCaps.enabledApps
  );

  // ToU remediation: pending ToU list fetched when http.ts signals remediation=="terms".
  interface PendingTou { id: number; name: string; version: number; body_md: string; require_scroll: boolean; }
  let touPendingList = $state<PendingTou[] | null>(null);
  let composeSurfaceOpen = $derived($composeStore.sessions.some((session) => !session.minimized));
	let swActivationSafe = $derived(
		$composeStore.sessions.length === 0 &&
		!page.url.pathname.startsWith('/meet') &&
		!page.url.pathname.startsWith('/drive')
	);
  let tourHostBlocked = $derived(
    drawerOpen ||
    showCommandPalette ||
    composeSurfaceOpen ||
    (touPendingList !== null && touPendingList.length > 0) ||
    $riskRemediation.pending
  );

  $effect(() => {
		swGenerationCoordinator?.setSafeToActivate(swActivationSafe);
	});

	$effect(() => {
    if (!$touRemediation.pending) {
      touPendingList = null;
      return;
    }
    void typedFetch<PendingTou[]>('/terms/pending', {
      loginRedirect: null,
      onError: () => 'Failed to load terms'
    }).then(list => {
      touPendingList = list;
    }).catch(() => { /* leave null — original blocked-request error is already surfaced */ });
  });

  // Offline caps are authenticated user state. Installing this while logged
  // out made every public page issue a doomed bootstrap request and, before the
  // API namespace cut-over was fixed, allowed the SPA fallback's 200 HTML to
  // masquerade as a successful response. The effect follows session changes
  // and tears the listener down automatically on logout.
  $effect(() => {
    if (!$authenticated) return;
    return installCapsHandler();
  });

  // E4-I production boot composition (lib/offline/boot.ts): composes the real
  // coordinator ONLY when the session document projects the connectivity flag
  // pair (`effectiveCapabilities.offline.syncQoS` — the gateway strips the
  // block unless BOTH feature.offline_mail and feature.connectivity_aware_sync
  // are ON) with a non-off policy mode — or, harness pairs only, the shell's
  // bridge seam (SETJOIN_E6_CONNECTIVITY_SYNC_MODE) admits — and the native
  // shell proves the durable-storage capability. The shipped default (no
  // syncQoS block, no seam) keeps the coordinator uncomposed with zero
  // subscriptions. Same session-scoped genre as installCapsHandler above:
  // cleanup disposes the engine on logout or any session change.
  $effect(() => {
    if (!$authenticated) return;
    return composeOfflineCoordinatorForSession($jmapSession, $user);
  });

  // Active app detection from current route
  let activeApp = $derived.by((): string => {
    const p = page.url.pathname;
    const app = appForPath(p);
    if (app) return app;
    if (p.startsWith('/settings'))  return 'settings';
    if (p.startsWith('/admin'))     return 'admin';
    return 'mail';
  });

  // Admin consoles — guard by isAdmin first (UX only; real enforcement is 403),
  // then derive from the session's admin.consoles (Go admin.ConsolesForPerms).
  let adminConsoleIds = $derived<AdminConsoleId[]>(
    $user?.isAdmin ? $adminConsoles : []
  );
  let publicRoute = $derived(
    page.url.pathname === '/' ||
    page.url.pathname === '/setup' ||
    page.url.pathname === '/recover' ||
    page.url.pathname.startsWith('/security-event') ||
    page.url.pathname.startsWith('/guest-invite/') ||
    page.url.pathname.startsWith('/book') ||
    page.url.pathname.startsWith('/meet/join')
  );

  // Public booking is a standalone unauthenticated app. Start the one auth
  // bootstrap only when this persistent layout first enters a protected route.
  $effect(() => {
    if (!publicRoute) ensureInitialAuthProbe();
  });

  // Product marks describe useful states for the real-gateway performance
  // rail. Public content is intentionally independent of the auth probe;
  // protected shell visibility still requires authenticated resolution.
  $effect(() => {
    if (publicRoute) {
      markProductReady('public-visible');
      return markProductInteractive('public-interactive');
    }
    if ($authenticated && !$authInitializing) markProductReady('shell-visible');
  });

  // Auth guard
  $effect(() => {
    if (!$authInitializing && !$authenticated && $authResolution.state === 'anonymous') {
      const p = page.url.pathname;
      // '/' is the login page itself; /setup, /recover, /security-event, and
      // /guest-invite/* are the
      // other public landing pages — none should redirect. Redirecting '/' → '/'
      // re-fires this effect on every navigation, an infinite loop that pegs the
      // main thread so the login form never renders (a logged-out / post-logout
      // user is locked out). Excluding '/' breaks the loop. /book/* (feature #6)
      // is the FIRST unauthenticated PUBLIC app surface — a stranger with no
      // session must be able to land on a booking page/confirm link without
      // ever bouncing through login. /meet/join/* (Meet B1 Task 17) is the
      // second: the guest lobby page — an authenticated visitor who lands
      // there is redirected into the app by the page itself (/meet?slug=…),
      // not by this guard.
      if (p !== '/' && p !== '/setup' && p !== '/recover' && !p.startsWith('/security-event') && !p.startsWith('/guest-invite/') && !p.startsWith('/book') && !p.startsWith('/meet/join')) goto('/');
    }
  });

  // Post-login redirect to first enabled app
  $effect(() => {
    if ($authenticated && page.url.pathname === '/') {
      const oidcContinuation = parseOIDCOPContinuation(page.url.searchParams.get('continue'));
      if (oidcContinuation) {
        window.location.assign(oidcContinuation);
      } else {
        goto($firstEnabledApp, { replaceState: true });
      }
    }
  });

  // First-run welcome tour: request once per email on inbox landing.
  // WelcomeTour itself decides whether to show (checks the per-user seen flag).
  $effect(() => {
    const email = $user?.email;
    if (
      shouldAutoRequestTour({
        authInitializing: $authInitializing,
        authenticated: $authenticated,
        pathname: page.url.pathname,
        email,
        alreadyRequested: tourRequestedFor === email,
      }) && !guestSession
    ) {
      tourRequestedFor = email ?? null;
      requestTour(false);
    }
  });

  // CA-2 device lockdown: navigate to /blocked when jmapCall receives 403 BZ095.
  $effect(() => {
    if ($deviceBlock.blocked) {
      const ref = $deviceBlock.ref;
      const url = '/blocked' + (ref ? '?ref=' + encodeURIComponent(ref) : '');
      goto(url);
    }
  });

  // Route guard for blocked apps (only when B8 is active — not fallback).
  // Guests (G3, preserving P11c/codex C-6): a ROUTE ALLOWLIST — only
  // entitlement-backed Chat and Meet. Never the member prefix map below (it
  // omits /approvals /apps /settings /admin — deny-list rot, not meant to
  // fail closed for a guest) and never $firstEnabledApp (its FALLBACK_CAPS
  // derivation resolves to '/inbox' when caps are absent, which is itself a
  // guarded route a guest can't enter — /inbox -> /inbox is an infinite
  // redirect loop). Deny-by-default: fails CLOSED whether or not server caps
  // ever arrive. (/blocked is NOT added to this allowlist: deviceBlock is set
  // only by jmap/client.ts's jmapCall 403 BZ095 path, which chat's own
  // chatFetch never calls in G2 — a guest session cannot reach it.)
  // Members: byte-identical to the pre-G0 effect — only enforce when
  // capabilities came from the server (not the stub fallback).
  $effect(() => {
    if (!$authenticated || $authInitializing) return;
    const p = page.url.pathname;
    if ($user?.accountType === 'guest') {
      const app = appForPath(p);
      if (!app || !shellEnabledApps.includes(app)) {
        const fallback = shellEnabledApps.includes('chat') ? '/chat'
          : shellEnabledApps.includes('meet') ? '/meet'
          : '/apps';
        if (p !== fallback) goto(fallback, { replaceState: true });
      }
      return;
    }
    // Only enforce when capabilities came from the server (not the stub fallback)
    if (!$jmapSession?.effectiveCapabilities) return;
    const app = appForPath(p);
    if (app && !$effectiveCaps.enabledApps.includes(app)) {
      goto($firstEnabledApp, { replaceState: true });
    }
  });

  // Theme
  onMount(() => {
    theme = (document.documentElement.dataset.theme as 'light' | 'dark') ?? 'light';

    // Cmd+K / Ctrl+K
    function onKeydown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        const tag = (e.target as HTMLElement)?.tagName;
        const editable = (e.target as HTMLElement)?.isContentEditable;
        if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT' && !editable) {
          e.preventDefault();
          showCommandPalette = !showCommandPalette;
        }
      }
    }
    document.addEventListener('keydown', onKeydown);

    // Wire the remote-wipe push handler. The logout passed here MUST navigate to
    // /security-event (not the plain login form) — honest-recovery-path requirement
    // (brief §DESIGN). The wipe handler owns session teardown; this bootstrap just
    // composes the correct destination. Returns an unsubscribe cleaned up on unmount.
    const offWipe = installWipeHandler({
      logout: () => {
        // Fire auth logout (clears tokens/cookies) then navigate to the security-event
        // screen. Errors are ignored — we navigate regardless so the user is never
        // left in a limbo half-auth state.
        void logout().finally(() => goto('/security-event?reason=remote-wipe'));
      },
    });
    // Native-shell push action bridge (QoL #9): window.__setjoinPushAction.
    const offPushAction = installPushActionHandler();
    // Native-shell push-MFA registration: capture the OS push token + device
    // ECDH key and register them with the server. No-op on web / shells without
    // `push`; never prompts. Fire-and-forget — a failure must not block boot.
    void registerNativePush().catch(() => {});
		swGenerationCoordinator = installServiceWorkerGenerationCoordinator(buildVersion, swActivationSafe);

    return () => {
      document.removeEventListener('keydown', onKeydown);
      offWipe();
      offPushAction();
			swGenerationCoordinator?.dispose();
			swGenerationCoordinator = null;
    };
  });

  function toggleTheme() {
    theme = theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme-mode', theme);
  }

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

  function onTouAllAccepted() {
    touRemediation.set({ pending: false });
    location.reload(); // re-issue the blocked request with satisfied gate
  }

  function onRiskVerified() {
    riskRemediation.set({ pending: false });
    location.reload(); // re-issue the blocked request with refreshed auth
  }

  function appTitle(): string {
    if (activeApp === 'mail')      return t('app.mail') || 'Mail';
    if (activeApp === 'calendar')  return t('app.calendar') || 'Calendar';
    if (activeApp === 'contacts')  return t('app.contacts') || 'Contacts';
    if (activeApp === 'tasks')     return t('app.tasks') || 'Tasks';
    if (activeApp === 'approvals') return t('app.approvals') || 'Approvals';
    if (activeApp === 'chat')      return t('app.chat') || 'Chat';
    if (activeApp === 'meet')      return t('app.meet') || 'Meet';
    if (activeApp === 'drive')     return t('app.drive') || 'Drive';
    if (activeApp === 'settings')  return t('app.settings') || 'Settings';
    return 'Admin';
  }
</script>

{#if $authInitializing && !publicRoute}
  <div class="sj-shell-loading" role="status" aria-label={t('loading') || 'Loading'}>
    {#await import('$lib/components/ui/Spinner.svelte') then Mod}
      <Mod.default size={28} label={t('loading') || 'Loading'} />
    {/await}
  </div>
{:else if $authenticated && !page.url.pathname.startsWith('/blocked') && !page.url.pathname.startsWith('/security-event')}
  {#if $impersonating}
    <div class="sj-impersonation-banner" role="alert">
      <span>{t('shell.impersonation_banner', { email: $user?.email ?? '' })}</span>
      <button class="sj-impersonation-exit" onclick={async () => { await logout(); impersonating.set(false); goto('/'); }}>
        {t('shell.impersonation_exit')}
      </button>
    </div>
  {/if}

  <!-- CA-2 report-only: show when admin enabled device_lockdown but web browser has no proof -->
  <DeviceNotApprovedBanner lockedDown={$effectiveCaps.deviceLockdown} approved={false} />

  <div class="sj-shell">
    <AppRail
      enabledApps={shellEnabledApps}
      activeApp={activeApp}
      adminConsoles={adminConsoleIds}
      theme={theme}
      userName={$user?.email ?? ''}
      userEmail={$user?.email ?? ''}
      appBadges={{ approvals: approvalsCount.count, chat: chatStore.railBadge.count }}
      guest={guestSession}
      onNavigate={(path) => goto(path)}
      onToggleTheme={toggleTheme}
      onSignOut={doLogout}
    />

    <GlobalDrawer
      open={drawerOpen}
      enabledApps={shellEnabledApps}
      activeApp={activeApp}
      adminConsoles={adminConsoleIds}
      theme={theme}
      userName={$user?.email ?? ''}
      userEmail={$user?.email ?? ''}
      guest={guestSession}
      onNavigate={(path) => goto(path)}
      onToggleTheme={toggleTheme}
      onSignOut={doLogout}
      onClose={() => (drawerOpen = false)}
    />

    <div class="sj-shell-content">
      <!-- Per-app topbar; each route may provide its own via context/slot in M3+ -->
      <AppTopbar
        title={appTitle()}
        showBurger={true}
        onBurger={() => (drawerOpen = true)}
      />

      <!-- Primary app content. (UX #19: this used to be pane A of an outer
           SplitPane whose pane B mounted SideDock — a keep-alive split-view
           slot with no producer anywhere in the app ever passed it content
           and no UI ever called openDock(), so on any desktop-width viewport
           it rendered as a permanent ~40%-width empty panel with a live
           app-switcher select going nowhere. Removed: SideDock.svelte, its
           mount, and the dead dockOpen/dockApp/openDock/handleDockCollapse
           state — a real, wire-or-remove call, not a cosmetic one. See
           mailserver/webmail/AGENTS.md's App shell section.) -->
      <div class="sj-shell-body">
        <div class="sj-primary-pane">
          <!-- Multi-compose (QoL #18): one ComposeScreen per open session, keyed
               by id so each keeps its own live editor + in-flight uploads. Only
               the maximized one is visible; minimized ones are CSS-hidden. -->
          {#if !guestSession && $composeStore.sessions.length > 0}
            {#await import('$lib/components/ComposeScreen.svelte') then Mod}
              {#each $composeStore.sessions as composeSession (composeSession.id)}
                <Mod.default session={composeSession} />
              {/each}
            {/await}
          {/if}
          <main class="sj-main-content" id="main-content">
            {@render children?.()}
          </main>
        </div>
      </div>
    </div>
  </div>

  <CommandPalette
    open={showCommandPalette}
    guest={guestSession}
    enabledApps={shellEnabledApps}
    onclose={() => (showCommandPalette = false)}
  />

  <!-- Toast stack (M1 Toast component renders itself via toasts.svelte.ts store) -->
  {#await import('$lib/components/ui/Toast.svelte') then Mod}
    <Mod.default />
  {/await}

  <!-- Multi-compose (QoL #18): minimized-compose dock + a polite live region that
       announces the auto-minimize swap when a new compose opens over existing ones. -->
  {#if !guestSession && $composeStore.sessions.some((s) => s.minimized)}
    {#await import('$lib/components/ComposeDock.svelte') then Mod}
      <Mod.default />
    {/await}
  {/if}
  <div aria-live="polite" aria-atomic="true" class="sr-only">{composeAnnounce}</div>

  {#if !guestSession}
    <WelcomeTour
      userEmail={$user?.email ?? ''}
      pathname={page.url.pathname}
      hostBlocked={tourHostBlocked}
      escapeAllowed={!tourHostBlocked}
      inboxReadiness={inboxReadiness}
    />

    <!-- Reminder toasts (event VALARM / task reminder_at / flagged mail) — A6 surface. -->
    <RemindersWindow />
  {/if}

  {#if touPendingList !== null && touPendingList.length > 0}
    <TermsAcceptance pending={touPendingList} onAllAccepted={onTouAllAccepted} />
  {/if}

  {#if $riskRemediation.pending}
    <RiskRemediation
      signals={$riskRemediation.signals}
      correlationId={$riskRemediation.correlationId}
      onVerified={onRiskVerified}
    />
  {/if}
{:else if $authResolution.state === 'unavailable' && !publicRoute}
  <main class="sj-auth-unavailable" role="alert">
    <h1>{t('auth.unavailable.title')}</h1>
    <p>{t('auth.unavailable.body')}</p>
    <button type="button" onclick={() => void checkAuth()}>{t('common.retry')}</button>
  </main>
{:else}
  <!-- Unauthenticated: login, setup, recover pages render without shell -->
  <main class="sj-unauthenticated-content">{@render children?.()}</main>
{/if}

<style>
  .sj-shell-loading {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-page);
  }

  .sj-auth-unavailable {
    min-height: 100dvh;
    display: grid;
    place-content: center;
    gap: var(--space-3);
    padding: var(--space-6);
    text-align: center;
    background: var(--surface-page);
    color: var(--text-primary);
  }

  .sj-auth-unavailable h1 { font-size: var(--text-xl); }
  .sj-auth-unavailable p { max-width: 42ch; color: var(--text-secondary); }
  .sj-auth-unavailable button {
    justify-self: center;
    min-height: 40px;
    padding: 0 var(--space-4);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: var(--text-inverse);
    font: inherit;
    cursor: pointer;
  }

  .sj-impersonation-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    background: var(--warning-bg);
    border-bottom: 1px solid var(--warning-solid);
    font-size: var(--text-sm);
    color: var(--warning-fg);
    position: sticky;
    top: 0;
    z-index: 200;
  }

  .sj-impersonation-exit {
    padding: 2px 10px;
    border: 1px solid var(--warning-solid);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--warning-fg);
    cursor: pointer;
    font-size: var(--text-sm);
  }

  .sj-impersonation-exit:hover {
    background: var(--warning-solid);
  }

  .sj-shell {
    display: flex;
    height: 100vh;
    overflow: hidden;
    background: var(--surface-page);
  }

  .sj-shell-content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
  }

  .sj-shell-body {
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: hidden;
  }

  .sj-primary-pane {
    flex: 1;
    min-width: 0;
    height: 100%;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    position: relative; /* anchors ComposeScreen overlay */
  }

  .sj-main-content {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  .sj-unauthenticated-content {
    height: 100vh;
    height: 100dvh;
    min-height: 0;
    overflow-y: auto;
    overscroll-behavior-y: contain;
  }
</style>
