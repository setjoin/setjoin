// RecordingConsentGate.test.ts — Meet B2 Task 10, D5: the join interstitial.
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import RecordingConsentGate from './RecordingConsentGate.svelte';

const childrenSnippet = createRawSnippet(() => ({
	render: () => `<div>child-content-marker</div>`,
}));

describe('RecordingConsentGate', () => {
	it('when active, renders the interstitial body with exactly two affordances — Join and Don\'t join', () => {
		render(RecordingConsentGate, {
			recordingActive: true,
			onConsent: vi.fn(),
			onDecline: vi.fn(),
			children: childrenSnippet,
		});
		expect(
			screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
		).toBeTruthy();
		expect(screen.getAllByRole('button')).toHaveLength(2);
		expect(screen.getByText('Join')).toBeTruthy();
		expect(screen.getByText("Don't join")).toBeTruthy();
		expect(screen.queryByText('child-content-marker')).toBeNull();
	});

	it('calling the Join affordance calls onConsent; Don\'t join calls onDecline', async () => {
		const onConsent = vi.fn();
		const onDecline = vi.fn();
		render(RecordingConsentGate, { recordingActive: true, onConsent, onDecline, children: childrenSnippet });
		await fireEvent.click(screen.getByText('Join'));
		expect(onConsent).toHaveBeenCalled();
		await fireEvent.click(screen.getByText("Don't join"));
		expect(onDecline).toHaveBeenCalled();
	});

	it('when not active, renders its children untouched and no interstitial affordances', () => {
		render(RecordingConsentGate, {
			recordingActive: false,
			onConsent: vi.fn(),
			onDecline: vi.fn(),
			children: childrenSnippet,
		});
		expect(screen.getByText('child-content-marker')).toBeTruthy();
		expect(screen.queryByText('Join')).toBeNull();
		expect(screen.queryByText("Don't join")).toBeNull();
	});

	it('when the gate FLIPS active, focus moves to the interstitial heading', async () => {
		const { rerender } = render(RecordingConsentGate, {
			recordingActive: false,
			onConsent: vi.fn(),
			onDecline: vi.fn(),
			children: childrenSnippet,
		});
		expect(screen.queryByText('This meeting is being recorded')).toBeNull();

		await rerender({ recordingActive: true, onConsent: vi.fn(), onDecline: vi.fn(), children: childrenSnippet });
		await vi.waitFor(() => {
			expect(document.activeElement?.textContent?.trim()).toBe('This meeting is being recorded');
		});
	});
});
