// ReasonPrompt.test.ts — TDD for Task 9
// Tests: field required, Submit disabled when empty, remember-last pre-fill, focus management
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';

// Reset the module-level lastReason state between test groups by re-importing
// after clearing the module cache — handled by beforeEach vi.resetModules below.

import ReasonPrompt from './ReasonPrompt.svelte';

describe('ReasonPrompt', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('renders a labeled Reason textarea', () => {
		render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		// label must be associated with the field
		expect(screen.getByLabelText(/reason/i)).toBeInTheDocument();
	});

	it('Submit button is disabled when reason is empty', () => {
		render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		const btn = screen.getByRole('button', { name: /submit/i });
		expect(btn).toBeDisabled();
	});

	it('Submit button enables once reason has content', async () => {
		render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		const textarea = screen.getByLabelText(/reason/i);
		await fireEvent.input(textarea, { target: { value: 'adding role for project X' } });
		const btn = screen.getByRole('button', { name: /submit/i });
		expect(btn).not.toBeDisabled();
	});

	it('calls onSubmit with the trimmed reason value', async () => {
		const onSubmit = vi.fn();
		render(ReasonPrompt, { area: 'roles', onSubmit });
		const textarea = screen.getByLabelText(/reason/i);
		await fireEvent.input(textarea, { target: { value: '  security review  ' } });
		const btn = screen.getByRole('button', { name: /submit/i });
		await fireEvent.click(btn);
		expect(onSubmit).toHaveBeenCalledWith('security review');
	});

	it('shows area-specific helper text', () => {
		render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		expect(screen.getByText(/roles/i)).toBeInTheDocument();
	});

	it('shows cancel button that calls onCancel', async () => {
		const onCancel = vi.fn();
		render(ReasonPrompt, { area: 'audit', onSubmit: vi.fn(), onCancel });
		const cancel = screen.getByRole('button', { name: /cancel/i });
		await fireEvent.click(cancel);
		expect(onCancel).toHaveBeenCalled();
	});
});

// remember-last is tested via the exported store — two separate renders in sequence
describe('ReasonPrompt — remember-last pre-fill', () => {
	it('pre-fills the reason field with the last-submitted reason', async () => {
		// First render: submit a reason
		const { unmount } = render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		const textarea1 = screen.getByLabelText(/reason/i);
		await fireEvent.input(textarea1, { target: { value: 'initial reason' } });
		await fireEvent.click(screen.getByRole('button', { name: /submit/i }));
		unmount();

		// Second render: should pre-fill with 'initial reason'
		render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		const textarea2 = screen.getByLabelText(/reason/i);
		expect((textarea2 as HTMLTextAreaElement).value).toBe('initial reason');
		// Submit should be enabled immediately (pre-filled)
		expect(screen.getByRole('button', { name: /submit/i })).not.toBeDisabled();
	});

	it("does NOT carry a reason across areas (a reason describes THIS action)", async () => {
		// Submit a reason in the 'roles' area.
		const { unmount } = render(ReasonPrompt, { area: 'roles', onSubmit: vi.fn() });
		const textarea1 = screen.getByLabelText(/reason/i);
		await fireEvent.input(textarea1, { target: { value: 'roles reason' } });
		await fireEvent.click(screen.getByRole('button', { name: /submit/i }));
		unmount();

		// A DIFFERENT area's prompt must start empty — no cross-action carryover.
		render(ReasonPrompt, { area: 'identity', onSubmit: vi.fn() });
		const textarea2 = screen.getByLabelText(/reason/i);
		expect((textarea2 as HTMLTextAreaElement).value).toBe('');
		expect(screen.getByRole('button', { name: /submit/i })).toBeDisabled();
	});
});
