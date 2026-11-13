import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import TermsAcceptance from './TermsAcceptance.svelte';

const tou = (over = {}) => ({ id: 1, name: 'AUP', version: 2, body_md: '# Hi', require_scroll: true, ...over });

describe('TermsAcceptance', () => {
  it('keeps Accept disabled until scrolled to bottom when require_scroll', async () => {
    const { getByRole, getByTestId } = render(TermsAcceptance, { props: { pending: [tou()] } });
    const accept = getByRole('button', { name: /accept/i }) as HTMLButtonElement;
    expect(accept.disabled).toBe(true);
    const body = getByTestId('tou-body');
    Object.defineProperty(body, 'scrollHeight', { value: 200, configurable: true });
    Object.defineProperty(body, 'clientHeight', { value: 100, configurable: true });
    Object.defineProperty(body, 'scrollTop', { value: 100, configurable: true });
    await fireEvent.scroll(body);
    expect(accept.disabled).toBe(false);
  });

  it('latches accept-enabled for a non-scrollable (short) document', async () => {
    const { getByRole, getByTestId } = render(TermsAcceptance, { props: { pending: [tou()] } });
    const body = getByTestId('tou-body');
    Object.defineProperty(body, 'scrollHeight', { value: 80, configurable: true });
    Object.defineProperty(body, 'clientHeight', { value: 100, configurable: true });
    await fireEvent.scroll(body); // first measure latches because not actually scrollable
    expect((getByRole('button', { name: /accept/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('does NOT dismiss on Escape (legal gate)', async () => {
    const onAllAccepted = vi.fn();
    const { queryByTestId } = render(TermsAcceptance, { props: { pending: [tou({ require_scroll: false })], onAllAccepted } });
    await fireEvent.keyDown(document, { key: 'Escape' });
    expect(queryByTestId('tou-body')).not.toBeNull(); // still mounted
    expect(onAllAccepted).not.toHaveBeenCalled();
  });

  it('posts tou_id + version on accept and advances the 1-of-N queue', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal('fetch', fetchMock);
    const onAllAccepted = vi.fn();
    const { getByRole, getByText } = render(TermsAcceptance, {
      props: { pending: [tou({ id: 1, require_scroll: false }), tou({ id: 9, name: 'Privacy', require_scroll: false })], onAllAccepted }
    });
    expect(getByText(/1 of 2/i)).toBeTruthy();
    await fireEvent.click(getByRole('button', { name: /accept/i }));
    expect(fetchMock).toHaveBeenCalledWith('/terms/accept', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ tou_id: 1, version: 2 })
    }));
    expect(getByText(/2 of 2/i)).toBeTruthy();
    await fireEvent.click(getByRole('button', { name: /accept/i }));
    expect(onAllAccepted).toHaveBeenCalled();
  });

  it('shows an inline error with Reload on a stale 409', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 409 }));
    const { getByRole, findByRole } = render(TermsAcceptance, { props: { pending: [tou({ require_scroll: false })] } });
    await fireEvent.click(getByRole('button', { name: /accept/i }));
    const alert = await findByRole('alert');
    expect(alert.textContent?.toLowerCase()).toContain('updated');
    expect(getByRole('button', { name: /reload/i })).toBeTruthy();
  });

  it('decline opens a confirm and signs out', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
    const { getByRole } = render(TermsAcceptance, { props: { pending: [tou({ require_scroll: false })] } });
    await fireEvent.click(getByRole('button', { name: /decline/i }));
    await fireEvent.click(getByRole('button', { name: /sign out/i }));
    expect(fetchMock).toHaveBeenCalledWith('/auth/logout', expect.objectContaining({ method: 'POST' }));
  });

  it('exposes a polite live region and announces the final acceptance', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 204 }));
    const { container, getByRole } = render(TermsAcceptance, { props: { pending: [tou({ require_scroll: false })], onAllAccepted: () => {} } });
    const live = container.querySelector('[aria-live="polite"]');
    expect(live).not.toBeNull(); // mandatory async-outcome announcer
    await fireEvent.click(getByRole('button', { name: /accept/i }));
    expect(live?.textContent?.toLowerCase()).toContain('accept'); // "All terms accepted…"
  });

  it('End key jumps to the bottom and latches accept-enabled (SR/keyboard escape hatch)', async () => {
    const { getByRole, getByTestId } = render(TermsAcceptance, { props: { pending: [tou()] } });
    const body = getByTestId('tou-body');
    Object.defineProperty(body, 'scrollHeight', { value: 400, configurable: true });
    Object.defineProperty(body, 'clientHeight', { value: 100, configurable: true });
    Object.defineProperty(body, 'scrollTop', { value: 300, configurable: true });
    await fireEvent.keyDown(body, { key: 'End' });
    await fireEvent.scroll(body);
    expect((getByRole('button', { name: /accept/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('truncates a 47-char document name with a full-value title (no overflow)', () => {
    const longName = 'Acceptable Use & Data Handling Policy v3 (EU)x'; // 47 chars
    const { getByText } = render(TermsAcceptance, { props: { pending: [tou({ name: longName, require_scroll: false })] } });
    const title = getByText(longName);
    expect(title.getAttribute('title')).toBe(longName); // full value preserved for hover/AT
  });
});

// Note: the reduced-motion contract (progress fill + accept-fade `transition: none`
// under `prefers-reduced-motion: reduce`) is asserted once for all CA-3b webmail
// surfaces by the shared `reduced-motion.test.ts` (Design Task A test block) which
// scans each component's <style> for a guarded `@media (prefers-reduced-motion: reduce)`
// block — added there so it covers TermsAcceptance, RiskRemediation, blocked,
// CertStatusCard and the two admin pages in one machine guard.
