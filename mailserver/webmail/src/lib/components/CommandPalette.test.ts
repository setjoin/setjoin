
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { fireEvent } from '@testing-library/svelte/svelte5';
import CommandPalette from './CommandPalette.svelte';
import * as tour from '$lib/onboarding/tour.svelte';
import { user } from '$lib/stores/auth';

const gotoMock = vi.fn();
vi.mock('$app/navigation', () => ({
  goto: (...args: unknown[]) => gotoMock(...args),
}));

describe('CommandPalette', () => {
  beforeEach(() => user.set(null));
  afterEach(() => user.set(null));
  it('renders hidden by default (open=false)', () => {
    render(CommandPalette, { open: false });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows dialog when open=true', () => {
    render(CommandPalette, { open: true });
    expect(screen.getByRole('dialog')).toBeTruthy();
  });

  it('filters actions by search query', async () => {
    render(CommandPalette, { open: true });

    const input = screen.getByPlaceholderText('Type a command…');
    // Simulate typing in the search field
    await fireEvent.input(input, { target: { value: 'Comp' } });

    // "Compose" should still be visible
    expect(screen.getByText('Compose')).toBeTruthy();
    // "Inbox" should be filtered out
    expect(screen.queryByText('Inbox')).toBeNull();
  });

	it('shows only explicitly enabled guest app commands and ignores caller-supplied member commands', () => {
    user.set({ email: 'pat@example.com', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		render(CommandPalette, {
			open: true,
			enabledApps: ['chat', 'meet'],
      actions: [{ label: 'Injected settings', icon: 'Settings', shortcut: '', category: 'settings', action: vi.fn() }],
    });
		expect(screen.getByText('Chat')).toBeInTheDocument();
		expect(screen.getByText('Meet')).toBeInTheDocument();
    expect(screen.queryByText('Compose')).not.toBeInTheDocument();
    expect(screen.queryByText('Inbox')).not.toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
    expect(screen.queryByText('Show welcome tour')).not.toBeInTheDocument();
    expect(screen.queryByText('Injected settings')).not.toBeInTheDocument();
  });

  it('closes on Escape key', async () => {
    const onClose = vi.fn();
    render(CommandPalette, { open: true, onclose: onClose });

    const dialog = screen.getByRole('dialog');
    await fireEvent.keyDown(dialog, { key: 'Escape' });

    expect(onClose).toHaveBeenCalled();
  });

  it('exposes modal a11y semantics (aria-modal + labelledby title)', () => {
    render(CommandPalette, { open: true });
    const dialog = screen.getByRole('dialog');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    const labelledBy = dialog.getAttribute('aria-labelledby');
    expect(labelledBy).toBeTruthy();
    const title = labelledBy ? document.getElementById(labelledBy) : null;
    expect(title?.textContent).toBe('Command palette');
  });

  it('navigates via goto (not window.location) for in-app routes', async () => {
    gotoMock.mockClear();
    const onClose = vi.fn();
    render(CommandPalette, { open: true, onclose: onClose });
    await fireEvent.click(screen.getByText('Inbox'));
    expect(gotoMock).toHaveBeenCalledWith('/inbox');
    expect(onClose).toHaveBeenCalled();
  });

  it('returns focus to the trigger when closed', async () => {
    const trigger = document.createElement('button');
    trigger.textContent = 'open palette';
    document.body.appendChild(trigger);
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    const { rerender } = render(CommandPalette, { open: true });
    // Closing the palette restores focus to the previously-focused trigger.
    await rerender({ open: false });
    expect(document.activeElement).toBe(trigger);

    trigger.remove();
  });

  it('traps Tab within the palette', async () => {
    render(CommandPalette, { open: true });
    const dialog = screen.getByRole('dialog');
    // The trap handler intercepts Tab; it must not throw and the dialog stays open.
    await fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(screen.getByRole('dialog')).toBeTruthy();
  });
});

describe('CommandPalette welcome-tour command', () => {
  it('runs requestTour(true) and navigates to /inbox', async () => {
    gotoMock.mockClear();
    tour.consumeRequest();
    render(CommandPalette, { open: true, onclose: () => {} });
    await fireEvent.click(screen.getByText('Show welcome tour'));
    expect(gotoMock).toHaveBeenCalledWith('/inbox');
    expect(tour.tourRequest.pending).toBe(true);
    expect(tour.tourRequest.force).toBe(true);
  });
});
