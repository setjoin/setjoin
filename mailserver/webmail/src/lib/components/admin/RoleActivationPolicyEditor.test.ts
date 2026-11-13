import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({ policy: vi.fn(), defaults: vi.fn(), save: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminGetActivationPolicy: api.policy,
	adminGetJitDefaults: api.defaults,
	adminPutActivationPolicy: api.save,
}));
import Editor from './RoleActivationPolicyEditor.svelte';

describe('RoleActivationPolicyEditor', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.policy.mockResolvedValue({ maxDurationMinutes: 120, requireJustification: false });
		api.defaults.mockResolvedValue({ defaultMaxDurationMinutes: 480, defaultRequireJustification: true });
		api.save.mockResolvedValue({});
	});

	it('loads inherited policy context and persists explicit limits', async () => {
		render(Editor, { roleId: 17 });
		await waitFor(() => expect(screen.getByRole('combobox')).toHaveValue('120'));
		expect(screen.getByText(/8 h, justification required/)).toBeInTheDocument();
		await fireEvent.change(screen.getByRole('combobox'), { target: { value: '60' } });
		await fireEvent.click(screen.getByRole('switch'));
		await fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
		await waitFor(() => expect(api.save).toHaveBeenCalledWith(17, { maxDurationMinutes: 60, requireJustification: true }));
	});

	it('shows load and save failures without hiding the editor', async () => {
		api.policy.mockRejectedValueOnce(new Error('policy unavailable'));
		render(Editor, { roleId: 18 });
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('policy unavailable'));
		expect(screen.getByRole('button', { name: 'Save policy' })).toBeInTheDocument();
		api.save.mockRejectedValueOnce(new Error('policy conflict'));
		await fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('policy conflict'));
	});
});
