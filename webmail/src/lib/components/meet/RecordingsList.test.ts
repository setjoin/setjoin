// RecordingsList.test.ts — Meet B2 Task 10: the state-chip set covers the
// FULL machine (requested/active/stopping share one in-progress chip, D-4).
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import RecordingsList from './RecordingsList.svelte';
import type { MeetingRecording } from '$lib/meet/api';

function rec(over: Partial<MeetingRecording>): MeetingRecording {
	return {
		recordingId: 1,
		state: 'ready',
		startedAt: '2026-07-15T10:00:00Z',
		stoppedAt: '2026-07-15T10:30:00Z',
		durationMs: 1_800_000,
		sizeBytes: 12345,
		versionId: 99,
		fileNodeId: 7,
		error: null,
		...over,
	};
}

describe('RecordingsList', () => {
	it.each(['requested', 'active', 'stopping'] as const)(
		'a %s row renders the in-progress chip (one chip covers all three)',
		(state) => {
			render(RecordingsList, { recordings: [rec({ state })] });
			expect(screen.getByText('Recording in progress')).toBeTruthy();
		},
	);

	it('a pending_ingest row renders the processing chip', () => {
		render(RecordingsList, { recordings: [rec({ state: 'pending_ingest' })] });
		expect(screen.getByText('Processing recording…')).toBeTruthy();
	});

	it('a ready row renders a <video> whose src is contentUrl(versionId)', () => {
		render(RecordingsList, { recordings: [rec({ state: 'ready', versionId: 99 })] });
		expect(screen.getByText('Ready')).toBeTruthy();
		const video = document.querySelector('video');
		expect(video).toBeTruthy();
		expect(video?.getAttribute('src')).toBe('/api/drive/versions/99/content');
	});

	it('a failed row renders the failed chip and a localized error for a known reason, raw string in title=', () => {
		render(RecordingsList, { recordings: [rec({ state: 'failed', error: 'egress_busy' })] });
		expect(screen.getByText('Recording failed')).toBeTruthy();
		const err = screen.getByText('Recording capacity is in use; try again shortly');
		expect(err.getAttribute('title')).toBe('egress_busy');
	});

	it.each([
		['stopping with no egress binding (wedge-4 sweep)', 'The recording could not be finalized (lost connection to the recorder).'],
		['ingest failed after 5 attempts: some transport error', 'Recording processing failed after repeated attempts.'],
	])('maps the known reason %s to its localized copy', (raw, localized) => {
		render(RecordingsList, { recordings: [rec({ state: 'failed', error: raw })] });
		const err = screen.getByText(localized);
		expect(err.getAttribute('title')).toBe(raw);
	});

	it('an unrecognized error reason falls back to the raw string', () => {
		render(RecordingsList, { recordings: [rec({ state: 'failed', error: 'some future reason' })] });
		expect(screen.getByText('some future reason')).toBeTruthy();
	});

	it('an empty list renders the empty state', () => {
		render(RecordingsList, { recordings: [] });
		expect(screen.getByText('No recordings')).toBeTruthy();
	});
});
