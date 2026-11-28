import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import { jmapSession } from '$lib/stores/session';

const nav = vi.hoisted(() => ({ goto: vi.fn() }));
vi.mock('$app/navigation', () => ({ goto: nav.goto }));
vi.mock('$app/state', () => ({ page: { url: new URL('https://setjoin.test/blocked?ref=ref-123') } }));

import Page from './+page.svelte';

describe('device-lockdown recovery workflows', () => {
	beforeEach(() => {
		nav.goto.mockReset();
		jmapSession.set(null);
	});

	afterEach(() => {
		delete (window as unknown as { setjoinNative?: unknown }).setjoinNative;
		vi.unstubAllGlobals();
	});

	it('guides a browser user to the native download and copies the reference', async () => {
		const open = vi.fn();
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal('open', open);
		vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
		render(Page);
		await fireEvent.click(screen.getByTestId('blocked-install-btn'));
		expect(open).toHaveBeenCalledWith('/downloads', '_blank');
		await fireEvent.click(screen.getByTestId('blocked-copy-ref'));
		expect(writeText).toHaveBeenCalledWith('ref-123');
		expect(screen.getByTestId('blocked-contact-link')).not.toHaveAttribute('href');
	});

	it('uses the configured help address, then the organization-domain fallback', () => {
		jmapSession.set({ helpEmail: 'help@corp.test', username: 'user@corp.test' } as never);
		const first = render(Page);
		expect(screen.getByTestId('blocked-contact-link')).toHaveAttribute('href', 'mailto:help@corp.test');
		first.unmount();
		jmapSession.set({ username: 'user@corp.test' } as never);
		render(Page);
		expect(screen.getByTestId('blocked-contact-link')).toHaveAttribute('href', 'mailto:admin@corp.test');
	});

	it('requests native approval, retains the waiting state when still blocked, and enters inbox when approved', async () => {
		(window as unknown as { setjoinNative: unknown }).setjoinNative = { capabilities: [] };
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: true })
			.mockResolvedValueOnce({ ok: false })
			.mockResolvedValueOnce({ ok: true });
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		await fireEvent.click(screen.getByTestId('blocked-request-btn'));
		await waitFor(() => expect(screen.getByTestId('blocked-requested-badge')).toBeInTheDocument());
		expect(screen.getByTestId('blocked-ack')).toBeInTheDocument();
		expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'include' }));
		await fireEvent.click(screen.getByTestId('blocked-check-again'));
		await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
		expect(nav.goto).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByTestId('blocked-check-again'));
		await waitFor(() => expect(nav.goto).toHaveBeenCalledWith('/inbox', { replaceState: true }));
	});

	it('surfaces both HTTP and network enrollment failures and permits retry', async () => {
		(window as unknown as { setjoinNative: unknown }).setjoinNative = { capabilities: [] };
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: false })
			.mockRejectedValueOnce(new Error('offline'))
			.mockResolvedValueOnce({ ok: true });
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		await fireEvent.click(screen.getByTestId('blocked-request-btn'));
		await waitFor(() => expect(screen.getByTestId('blocked-error')).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('blocked-request-btn'));
		await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
		expect(screen.getByTestId('blocked-error')).toBeInTheDocument();
		await fireEvent.click(screen.getByTestId('blocked-request-btn'));
		await waitFor(() => expect(screen.getByTestId('blocked-requested-badge')).toBeInTheDocument());
	});

	it('keeps the requested state stable across a check-again network error', async () => {
		(window as unknown as { setjoinNative: unknown }).setjoinNative = { capabilities: [] };
		vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({ ok: true }).mockRejectedValueOnce(new Error('offline')));
		render(Page);
		await fireEvent.click(screen.getByTestId('blocked-request-btn'));
		await waitFor(() => expect(screen.getByTestId('blocked-check-again')).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('blocked-check-again'));
		await waitFor(() => expect(screen.getByTestId('blocked-requested-badge')).toBeInTheDocument());
		expect(nav.goto).not.toHaveBeenCalled();
	});

	it('ignores clipboard failures on both policy and device reference copies', async () => {
		vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } });
		const device = render(Page);
		await expect(fireEvent.click(screen.getByTestId('blocked-copy-ref'))).resolves.toBe(true);
		device.unmount();
		render(Page, { props: { block: {
			decision: 'block', mode: 'hard', reason: 'Policy', correlation_id: 'corr', remediation: '',
		} } as never });
		await expect(fireEvent.click(screen.getByLabelText(/copy/i))).resolves.toBe(true);
	});
});
