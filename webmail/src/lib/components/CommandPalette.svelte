<svelte:options runes={true} />

<script lang="ts">
  import { goto } from '$app/navigation';
  import { t } from '$lib/i18n';
  import { requestTour } from '$lib/onboarding/tour.svelte';
  import Icon from './Icon.svelte';
  import { user } from '$lib/stores/auth';
  import type { AppId } from '$lib/types/jmap';

  // Mirror of Icon.svelte's IconName type — all icon names registered in iconMap.
  type IconName =
    | 'Archive' | 'Bold' | 'Calendar' | 'CheckSquare' | 'Clock' | 'Command'
    | 'FileText' | 'Forward' | 'Inbox' | 'Italic' | 'LayoutGrid'
    | 'Link' | 'List' | 'ListOrdered' | 'LogOut' | 'MailCheck' | 'Maximize2'
    | 'Menu' | 'Minimize2' | 'PanelLeftClose' | 'PanelLeftOpen' | 'Pencil'
    | 'Quote' | 'Reply' | 'Search' | 'Send' | 'Settings' | 'Shield'
    | 'Sparkles' | 'Star' | 'Strikethrough' | 'Trash2' | 'Underline'
    | 'MessageSquare' | 'Users' | 'Video' | 'X';

  interface Action {
    label: string;
    icon: IconName;
    shortcut: string;
    category: 'navigation' | 'compose' | 'actions' | 'settings';
    action: () => void;
  }

  interface Props {
    open: boolean;
    actions?: Action[];
    onclose?: () => void;
    guest?: boolean;
    enabledApps?: AppId[];
  }

  let { open = false, actions, onclose, guest = false, enabledApps = [] }: Props = $props();

  let guestSession = $derived(guest || $user?.accountType === 'guest');

  function guestActions(): Action[] {
    const guestNav: Partial<Record<AppId, Action>> = {
      chat: { label: t('app.chat'), icon: 'MessageSquare', shortcut: '', category: 'navigation', action: () => goto('/chat') },
      meet: { label: t('app.meet'), icon: 'Video', shortcut: '', category: 'navigation', action: () => goto('/meet') },
    };
    return enabledApps.flatMap((app) => guestNav[app] ? [guestNav[app]!] : []);
  }

  function defaultActions(): Action[] {
    return [
      { label: 'Compose', icon: 'Pencil', shortcut: 'C', category: 'compose', action: () => goto('/inbox?compose=1') },
      { label: 'Inbox', icon: 'Inbox', shortcut: 'G I', category: 'navigation', action: () => goto('/inbox') },
      { label: 'Sent', icon: 'Send', shortcut: 'G S', category: 'navigation', action: () => goto('/inbox?folder=sent') },
      { label: 'Drafts', icon: 'FileText', shortcut: 'G D', category: 'navigation', action: () => goto('/inbox?folder=drafts') },
      { label: 'Starred', icon: 'Star', shortcut: 'G T', category: 'navigation', action: () => goto('/inbox?folder=starred') },
      { label: 'Calendar', icon: 'Calendar', shortcut: 'G C', category: 'navigation', action: () => goto('/calendar') },
      { label: 'Contacts', icon: 'Users', shortcut: 'G P', category: 'navigation', action: () => goto('/contacts') },
      { label: 'Tasks', icon: 'CheckSquare', shortcut: 'G K', category: 'navigation', action: () => goto('/tasks') },
      { label: 'Reply', icon: 'Reply', shortcut: 'R', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:reply')) },
      { label: 'Forward', icon: 'Forward', shortcut: 'F', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:forward')) },
      { label: 'Archive', icon: 'Archive', shortcut: 'E', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:archive')) },
      { label: 'Delete', icon: 'Trash2', shortcut: '#', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:delete')) },
      { label: 'Mark as Read', icon: 'MailCheck', shortcut: 'Shift+I', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:markRead')) },
      { label: 'Snooze', icon: 'Clock', shortcut: 'Z', category: 'actions', action: () => document.dispatchEvent(new CustomEvent('shortcut:snooze')) },
      { label: 'Search Mail', icon: 'Search', shortcut: '/', category: 'actions', action: () => document.querySelector<HTMLInputElement>('[data-search]')?.focus() },
      { label: 'Settings', icon: 'Settings', shortcut: 'G ,', category: 'settings', action: () => goto('/settings') },
      { label: 'Command Palette', icon: 'Command', shortcut: '⌘K', category: 'actions', action: () => {} },
      { label: t('onboarding.show_tour'), icon: 'Sparkles', shortcut: '', category: 'navigation',
        action: () => { goto('/inbox'); requestTour(true); } },
    ];
  }

  let search = $state('');
  let selectedIndex = $state(0);
  let inputEl: HTMLInputElement | undefined = $state() as HTMLInputElement | undefined;
  let dialogEl: HTMLDivElement | undefined = $state() as HTMLDivElement | undefined;
  let paletteEl: HTMLDivElement | undefined = $state() as HTMLDivElement | undefined;

  const uid = $props.id();
  const titleId = `cmdpalette-${uid}-title`;

  const FOCUSABLE =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function focusables(): HTMLElement[] {
    if (!paletteEl) return [];
    return Array.from(paletteEl.querySelectorAll<HTMLElement>(FOCUSABLE));
  }

  function trapTab(e: KeyboardEvent) {
    if (e.key !== 'Tab' || !paletteEl) return;
    const items = focusables();
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement as HTMLElement | null;
    const inside = active !== null && paletteEl.contains(active);
    if (e.shiftKey) {
      if (!inside || active === first) {
        e.preventDefault();
        last.focus();
      }
    } else if (!inside || active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // Ignore even caller-supplied actions for a guest: custom member commands must
  // never bypass the constrained-shell projection.
  let resolvedActions = $derived(guestSession ? guestActions() : (actions ?? defaultActions()));

  let filtered = $derived(
    search.trim() === ''
      ? resolvedActions
      : resolvedActions.filter((a) =>
          a.label.toLowerCase().includes(search.toLowerCase())
        )
  );

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      onclose?.();
      return;
    }
    if (e.key === 'Tab') {
      trapTab(e);
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, filtered.length - 1);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      return;
    }
    if (e.key === 'Enter' && filtered[selectedIndex]) {
      e.preventDefault();
      filtered[selectedIndex].action();
      onclose?.();
      return;
    }
  }

  function selectAction(act: Action) {
    act.action();
    onclose?.();
  }

  function onOverlayClick(e: MouseEvent) {
    // Close only when clicking the backdrop itself, not the palette
    if (e.target === dialogEl) {
      onclose?.();
    }
  }

  $effect(() => {
    if (!open) return;
    search = '';
    selectedIndex = 0;
    // Capture the trigger so focus can return to it on close.
    const previouslyFocused = document.activeElement as HTMLElement | null;
    // Focus input after DOM update.
    requestAnimationFrame(() => inputEl?.focus());
    return () => {
      previouslyFocused?.focus();
    };
  });
</script>

{#if open}
  <div
    class="command-overlay"
    role="presentation"
    bind:this={dialogEl}
    onkeydown={handleKeydown}
    onclick={onOverlayClick}
  >
    <div
      class="command-palette"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      bind:this={paletteEl}
    >
      <h2 id={titleId} class="sr-only">Command palette</h2>
      <div class="search-bar">
        <Icon name="Search" size={16} />
        <input
          bind:this={inputEl}
          type="text"
          placeholder="Type a command…"
          bind:value={search}
          class="search-input"
          onkeydown={(e: KeyboardEvent) => {
            // Override input-level keydown for arrow/enter navigation
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter') {
              e.preventDefault();
              handleKeydown(e);
            }
          }}
        />
        <kbd class="escape-hint">esc</kbd>
      </div>
      <div class="actions-list">
        {#each filtered as action, i}
          <button
            class="action-item"
            class:selected={i === selectedIndex}
            onclick={() => selectAction(action)}
            onmouseenter={() => (selectedIndex = i)}
            type="button"
          >
            <Icon name={action.icon} size={18} />
            <span class="action-label">{action.label}</span>
            <kbd class="action-shortcut">{action.shortcut}</kbd>
          </button>
        {/each}
        {#if filtered.length === 0}
          <div class="no-results">No matching commands</div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .command-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: 20vh;
    background: var(--scrim);
    animation: cmd-fade-in var(--duration-fast) var(--ease-out);
  }

  .command-palette {
    width: 560px;
    max-width: 90vw;
    max-height: 480px;
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    display: flex;
    flex-direction: column;
    font-family: var(--font-sans);
    animation: cmd-scale-in var(--duration-base) var(--ease-out);
  }

  @keyframes cmd-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @keyframes cmd-scale-in {
    from { opacity: 0; transform: translateY(-8px) scale(0.98); }
    to { opacity: 1; transform: none; }
  }

  @media (prefers-reduced-motion: reduce) {
    .command-overlay,
    .command-palette {
      animation: none;
    }
  }

  .search-bar {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-default);
  }

  .search-input {
    flex: 1;
    border: none;
    background: transparent;
    outline: none;
    font-size: var(--text-md);
    color: var(--text-primary);
    font-family: inherit;
  }

  .search-input::placeholder {
    color: var(--text-disabled);
  }

  .escape-hint {
    font-size: var(--text-xs);
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    background: var(--surface-sunken);
    color: var(--text-tertiary);
    font-family: inherit;
    font-weight: var(--weight-medium);
  }

  .actions-list {
    overflow-y: auto;
    padding: var(--space-2);
    flex: 1;
  }

  .action-item {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    padding: 10px 12px;
    border: none;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    cursor: pointer;
    font-family: inherit;
    text-align: left;
    transition: background var(--duration-fast) var(--ease-out);
  }

  .action-item:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }

  .action-item:hover,
  .action-item.selected {
    background: var(--surface-selected);
    color: var(--accent-fg-on-subtle);
  }

  .action-label {
    flex: 1;
    font-weight: var(--weight-medium);
  }

  .action-shortcut {
    font-size: var(--text-xs);
    padding: 2px 6px;
    border-radius: var(--radius-sm);
    background: var(--surface-sunken);
    color: var(--text-tertiary);
    font-family: var(--font-mono);
    font-weight: var(--weight-medium);
  }

  .no-results {
    padding: 40px 20px;
    text-align: center;
    color: var(--text-tertiary);
    font-size: var(--text-sm);
  }
</style>
