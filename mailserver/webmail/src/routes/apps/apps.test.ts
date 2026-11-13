import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { get } from 'svelte/store';
import AppsPage from './+page.svelte';
import { jmapSession } from '$lib/stores/session';
import { user } from '$lib/stores/auth';
import type { JmapSession } from '$lib/types/jmap';

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));

function sessionWith(apps: Partial<Record<string, boolean>>): JmapSession {
  return {
    apiUrl: '',
    downloadUrl: '',
    uploadUrl: '',
    eventSourceUrl: '',
    state: '',
    accounts: {},
    primaryAccounts: {},
    username: 'a@b.com',
    capabilities: {},
    branding: { name: 'SetJoin', logoUrl: '' },
    effectiveCapabilities: {
      // Every AppId defaults false here (an absent key is treated as enabled
      // by effectiveCaps' own default-allow filter — this fixture predates
      // approvals/drive/chat/meet, so those four silently rendered as
      // "enabled" in every test until they were listed explicitly).
      apps: {
        mail: false, calendar: false, contacts: false, tasks: false,
        approvals: false, drive: false, chat: false, meet: false,
        ...apps,
      },
      features: { assist: false, bundles: false },
    },
  } as JmapSession;
}

describe('apps launcher gating', () => {
  beforeEach(() => {
    jmapSession.set(null);
    user.set({ email: 'a@b.com', isAdmin: false } as never);
  });

  it('renders only the apps the effective-capabilities list enables', () => {
    jmapSession.set(sessionWith({ mail: true, calendar: true }));
    render(AppsPage);
    expect(screen.getByText('Mail')).toBeTruthy();
    expect(screen.getByText('Calendar')).toBeTruthy();
    expect(screen.queryByText('Contacts')).toBeNull();
    expect(screen.queryByText('Tasks')).toBeNull();
  });

  it('hides every app tile when no app is entitled (and not admin)', () => {
    jmapSession.set(sessionWith({}));
    render(AppsPage);
    expect(screen.queryByText('Mail')).toBeNull();
    expect(screen.queryByText('Calendar')).toBeNull();
    expect(screen.getByText('No apps available')).toBeTruthy();
  });

  it('renders the approvals/drive/chat/meet tiles when entitled (regression: the launcher used to hard-code a stale 4-app subset)', () => {
    jmapSession.set(sessionWith({ approvals: true, drive: true, chat: true, meet: true }));
    render(AppsPage);
    expect(screen.getByText('Approvals')).toBeTruthy();
    expect(screen.getByText('Drive')).toBeTruthy();
    expect(screen.getByText('Chat')).toBeTruthy();
    expect(screen.getByText('Meet')).toBeTruthy();
    expect(screen.queryByText('Mail')).toBeNull();
  });

  it('shows the Admin tile from isAdmin independent of app capabilities', () => {
    jmapSession.set(sessionWith({}));
    user.set({ email: 'a@b.com', isAdmin: true } as never);
    render(AppsPage);
    expect(screen.getByText('Admin')).toBeTruthy();
  });

  it('reads branding from the shared session store (no second fetch needed)', () => {
    const s = sessionWith({ mail: true });
    s.branding = { name: 'Acme Mail', logoUrl: '' };
    jmapSession.set(s);
    render(AppsPage);
    // brand name from the store, not a hardcoded default
    expect(get(jmapSession)?.branding?.name).toBe('Acme Mail');
    expect(screen.getByText('Acme Mail')).toBeTruthy();
  });
});
