import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import { cleanup, screen } from '@testing-library/svelte';
import { resetStores } from '$lib/test-utils';
import PrincipalPicker from './PrincipalPicker.svelte';

// Mock adminFetch so no real network calls happen.
vi.mock('$lib/admin/client', () => ({
	adminFetch: vi.fn(),
}));

import { adminFetch } from '$lib/admin/client';
const mockAdminFetch = adminFetch as ReturnType<typeof vi.fn>;

const USER_PRINCIPALS = [
	{ id: 1, email: 'alice@corp.test', display_name: 'Alice Smith' },
	{ id: 2, email: 'bob@corp.test', display_name: 'Bob Jones' },
];

const GROUP_PRINCIPALS = [
	{ id: 10, name: 'IT Security' },
	{ id: 11, name: 'Admins' },
];

function makeResponse(data: unknown, ok = true, status = 200) {
	return { ok, status, json: async () => data, text: async () => '' } as Response;
}

describe('PrincipalPicker', () => {
	beforeEach(() => {
		resetStores?.();
		vi.clearAllMocks();
		mockAdminFetch.mockReset();
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it('renders chips from resolve-principals on mount (user kind)', async () => {
		mockAdminFetch.mockResolvedValueOnce(
			makeResponse({ users: USER_PRINCIPALS, groups: [] })
		);
		const onChange = vi.fn();
		const { findAllByTestId } = render(PrincipalPicker, {
			props: { kind: 'user', value: [1, 2], onChange },
		});
		const chips = await findAllByTestId('pp-chip');
		expect(chips).toHaveLength(2);
		expect(chips[0].title).toBe('Alice Smith');
		expect(chips[1].title).toBe('Bob Jones');
	});

	it('renders chips for groups', async () => {
		mockAdminFetch.mockResolvedValueOnce(
			makeResponse({ users: [], groups: GROUP_PRINCIPALS })
		);
		const { findAllByTestId } = render(PrincipalPicker, {
			props: { kind: 'group', value: [10, 11], onChange: vi.fn() },
		});
		const chips = await findAllByTestId('pp-chip');
		expect(chips).toHaveLength(2);
		expect(chips[0].title).toBe('IT Security');
	});

	it('renders a danger chip + error message for unresolvable id', async () => {
		// Only id=1 resolves; id=99 is not in the response
		mockAdminFetch.mockResolvedValueOnce(
			makeResponse({ users: [USER_PRINCIPALS[0]], groups: [] })
		);
		const { findAllByTestId, findByTestId } = render(PrincipalPicker, {
			props: { kind: 'user', value: [1, 99], onChange: vi.fn() },
		});
		const valid = await findAllByTestId('pp-chip');
		const invalid = await findAllByTestId('pp-chip-invalid');
		expect(valid).toHaveLength(1);
		expect(invalid).toHaveLength(1);
		// The invalid message should be visible
		const msg = await findByTestId('pp-invalid-msg');
		expect(msg.textContent).toBeTruthy();
	});

	it('shows ERROR banner + retry on resolve failure', async () => {
		mockAdminFetch
			.mockRejectedValueOnce(new Error('network'))
			.mockResolvedValueOnce(makeResponse({ users: [USER_PRINCIPALS[0]], groups: [] }));
		const { findByTestId, findByText } = render(PrincipalPicker, {
			props: { kind: 'user', value: [1], onChange: vi.fn() },
		});
		const err = await findByTestId('pp-resolve-error');
		expect(err).toBeTruthy();
		// retry button present
		const retryBtn = await findByText('Retry');
		expect(retryBtn).toBeTruthy();
		await fireEvent.click(retryBtn);
		expect((await screen.findAllByTitle('Alice Smith')).length).toBeGreaterThan(0);
		expect(screen.queryByTestId('pp-resolve-error')).toBeNull();
	});

	it('searches users, caps partial results, and adds a result with the mouse', async () => {
		const results = Array.from({ length: 21 }, (_, index) => ({
			id: index + 1,
			email: `person${index + 1}@corp.test`,
			display_name: index === 0 ? '' : `Person ${index + 1}`,
		}));
		mockAdminFetch.mockResolvedValueOnce(makeResponse(results));
		const onChange = vi.fn();
		render(PrincipalPicker, { props: { kind: 'user', value: [], onChange } });
		const input = screen.getByRole('textbox', { name: /excluded users/i });
		await fireEvent.input(input, { target: { value: 'person & one' } });
		await new Promise((resolve) => setTimeout(resolve, 240));

		expect(mockAdminFetch).toHaveBeenCalledWith('/admin/users?q=person%20%26%20one&limit=21');
		expect(await screen.findAllByRole('option')).toHaveLength(20);
		expect(document.querySelector('.pp__list-partial')).toBeTruthy();
		const first = screen.getAllByRole('option')[0];
		await fireEvent.mouseDown(first);
		expect(onChange).toHaveBeenCalledWith([1]);
		expect(input).toHaveValue('');
	});

	it('supports group search and keyboard selection including wraparound', async () => {
		mockAdminFetch.mockResolvedValueOnce(makeResponse([
			{ id: 10, name: '' },
			{ id: 11, name: 'Admins' },
		]));
		const onChange = vi.fn();
		render(PrincipalPicker, { props: { kind: 'group', value: [], onChange } });
		const input = screen.getByRole('textbox', { name: /excluded groups/i });
		await fireEvent.input(input, { target: { value: 'admin' } });
		await new Promise((resolve) => setTimeout(resolve, 240));
		await screen.findByRole('option', { name: 'Admins' });

		await fireEvent.keyDown(input, { key: 'ArrowUp' });
		expect(input).toHaveAttribute('aria-activedescendant', expect.stringMatching(/opt-1$/));
		await fireEvent.keyDown(input, { key: 'ArrowDown' });
		expect(input).toHaveAttribute('aria-activedescendant', expect.stringMatching(/opt-0$/));
		await fireEvent.keyDown(input, { key: 'Enter' });
		expect(onChange).toHaveBeenCalledWith([10]);
	});

	it('removes the last chip with Backspace and closes results with Escape', async () => {
		mockAdminFetch
			.mockResolvedValueOnce(makeResponse({ users: [USER_PRINCIPALS[0]], groups: [] }))
			.mockResolvedValueOnce(makeResponse(USER_PRINCIPALS));
		const onChange = vi.fn();
		render(PrincipalPicker, { props: { kind: 'user', value: [1], onChange } });
		const input = await screen.findByRole('textbox', { name: /excluded users/i });
		await fireEvent.keyDown(input, { key: 'Backspace' });
		expect(onChange).toHaveBeenCalledWith([]);

		await fireEvent.input(input, { target: { value: 'ali' } });
		await new Promise((resolve) => setTimeout(resolve, 240));
		expect(await screen.findByRole('listbox')).toBeTruthy();
		await fireEvent.keyDown(input, { key: 'Escape' });
		expect(screen.queryByRole('listbox')).toBeNull();
	});

	it('clears results for blank input and reopens cached results on focus', async () => {
		mockAdminFetch.mockResolvedValueOnce(makeResponse(USER_PRINCIPALS));
		render(PrincipalPicker, { props: { kind: 'user', value: [], onChange: vi.fn() } });
		const input = screen.getByRole('textbox', { name: /excluded users/i });
		await fireEvent.input(input, { target: { value: 'alice' } });
		await new Promise((resolve) => setTimeout(resolve, 240));
		await screen.findByRole('listbox');
		await fireEvent.blur(input);
		await new Promise((resolve) => setTimeout(resolve, 170));
		expect(screen.queryByRole('listbox')).toBeNull();
		await fireEvent.focus(input);
		expect(await screen.findByRole('listbox')).toBeTruthy();
		await fireEvent.input(input, { target: { value: '   ' } });
		expect(screen.queryByRole('listbox')).toBeNull();
	});

	it('keeps a failed search visible as an accessible error', async () => {
		mockAdminFetch.mockResolvedValueOnce(makeResponse([], false, 503));
		render(PrincipalPicker, { props: { kind: 'user', value: [], onChange: vi.fn() } });
		await fireEvent.input(screen.getByRole('textbox'), { target: { value: 'alice' } });
		await new Promise((resolve) => setTimeout(resolve, 240));
		expect(await screen.findByRole('alert')).toHaveTextContent(/failed|error|load/i);
	});

	it('does not add an already-selected search result', async () => {
		mockAdminFetch
			.mockResolvedValueOnce(makeResponse({ users: [USER_PRINCIPALS[0]], groups: [] }))
			.mockResolvedValueOnce(makeResponse([USER_PRINCIPALS[0]]));
		const onChange = vi.fn();
		render(PrincipalPicker, { props: { kind: 'user', value: [1], onChange } });
		const input = await screen.findByRole('textbox');
		await fireEvent.input(input, { target: { value: 'alice' } });
		await new Promise((resolve) => setTimeout(resolve, 240));
		await fireEvent.mouseDown((await screen.findAllByRole('option'))[0]);
		expect(onChange).not.toHaveBeenCalled();
	});

	it('calls onChange when a chip is removed', async () => {
		mockAdminFetch.mockResolvedValueOnce(
			makeResponse({ users: [USER_PRINCIPALS[0]], groups: [] })
		);
		const onChange = vi.fn();
		const { findByRole } = render(PrincipalPicker, {
			props: { kind: 'user', value: [1], onChange },
		});
		const removeBtn = await findByRole('button', { name: /remove alice smith/i });
		await fireEvent.click(removeBtn);
		expect(onChange).toHaveBeenCalledWith([]);
	});

	it('shows empty state placeholder when value is empty', async () => {
		const { getByPlaceholderText } = render(PrincipalPicker, {
			props: { kind: 'user', value: [], onChange: vi.fn() },
		});
		// placeholder should mention "No exclusions"
		const input = getByPlaceholderText(/no exclusions/i);
		expect(input).toBeTruthy();
	});

	it('renders reduced-motion: no animation class on chips (CSS-only — just checks render)', async () => {
		// The animation is CSS-only; this test verifies the component renders without error
		// under a mocked matchMedia prefers-reduced-motion query.
		const original = window.matchMedia;
		Object.defineProperty(window, 'matchMedia', {
			writable: true,
			value: vi.fn().mockImplementation((query: string) => ({
				matches: query === '(prefers-reduced-motion: reduce)',
				media: query,
				onchange: null,
				addListener: vi.fn(),
				removeListener: vi.fn(),
				addEventListener: vi.fn(),
				removeEventListener: vi.fn(),
				dispatchEvent: vi.fn(),
			})),
		});
		const { container } = render(PrincipalPicker, {
			props: { kind: 'user', value: [], onChange: vi.fn() },
		});
		expect(container.querySelector('.pp')).toBeTruthy();
		Object.defineProperty(window, 'matchMedia', { writable: true, value: original });
	});
});
