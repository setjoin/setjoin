import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import Blocked from './+page.svelte';

const payload = (over = {}) => ({
	decision: 'block', mode: 'hard', reason: 'Device not compliant',
	correlation_id: 'corr-abc123', remediation: '', ...over
});

describe('blocked screen (CA-3b policy block)', () => {
	it('hard-block shows the reason + Contact IT, no retry, and states sign-in succeeded', () => {
		const { getByText, queryByRole } = render(Blocked, { props: { block: payload() } });
		expect(getByText(/access blocked by policy/i)).toBeTruthy();
		expect(getByText(/device not compliant/i)).toBeTruthy();
		expect(getByText(/sign-?in succeeded/i)).toBeTruthy();
		expect(queryByRole('button', { name: /retry/i })).toBeNull();
	});

	it('report-only renders an informational continue banner, not a wall', () => {
		const { getByRole, getByText } = render(Blocked, { props: { block: payload({ mode: 'report_only' }) } });
		expect(getByText(/would.*block/i)).toBeTruthy();
		expect(getByRole('button', { name: /continue/i })).toBeTruthy();
	});

	it('step-up offers Verify now', () => {
		const { getByRole } = render(Blocked, { props: { block: payload({ mode: 'step_up' }) } });
		expect(getByRole('button', { name: /verify/i })).toBeTruthy();
	});

	it('copies the correlation id', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal('navigator', { clipboard: { writeText } });
		const { getByLabelText } = render(Blocked, { props: { block: payload() } });
		await fireEvent.click(getByLabelText(/copy/i));
		expect(writeText).toHaveBeenCalledWith('corr-abc123');
	});

	it('never renders raw JSON of the payload', () => {
		const { container } = render(Blocked, { props: { block: payload() } });
		expect(container.textContent).not.toContain('"decision"');
	});

	it('focuses the H1 on mount and exposes role=main', () => {
		const { getByRole } = render(Blocked, { props: { block: payload() } });
		expect(getByRole('main')).toBeTruthy();
		const h1 = getByRole('heading', { level: 1 });
		expect(h1.getAttribute('tabindex')).toBe('-1');
	});

	it('hides the correlation chip when no correlation_id is present', () => {
		const { queryByLabelText } = render(Blocked, { props: { block: payload({ correlation_id: '' }) } });
		expect(queryByLabelText(/copy/i)).toBeNull();
	});

	it('announces the copy via an aria-live region', async () => {
		vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
		const { getByLabelText, container } = render(Blocked, { props: { block: payload() } });
		await fireEvent.click(getByLabelText(/copy/i));
		const live = container.querySelector('[aria-live="polite"]');
		expect(live?.textContent?.toLowerCase()).toContain('copied');
	});

	it('falls back to hard-block treatment for an unknown mode', () => {
		const { getByText } = render(Blocked, { props: { block: payload({ mode: 'totally-new-mode' }) } });
		expect(getByText(/access blocked by policy/i)).toBeTruthy();
		expect(getByText(/sign-?in succeeded/i)).toBeTruthy();
	});

	it('Contact IT renders as an anchor (not a noop button) on the hard-block terminal screen', () => {
		const { getByText } = render(Blocked, { props: { block: payload() } });
		const el = getByText(/contact it/i);
		// Must be an <a> — the only action on a terminal screen must not be a dead onclick
		expect(el.closest('a')).not.toBeNull();
		expect(el.closest('button')).toBeNull();
	});
});
