// SemanticReplayPanel.test.ts — MEET plan M4: the replay panel's honest
// states (interaction states row: "Semantic replay — manifest/index load |
// empty timeline explains no replayable facts | integrity/missing-object
// error names unavailable segment | deterministic playback | gaps shown on
// timeline") plus local-only provenance and the export bounds/exclusions.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/svelte/svelte5';
import SemanticReplayPanel from './SemanticReplayPanel.svelte';
import type { SemanticPackageRead } from '$lib/meet/semanticReplay';

function pkg(overrides: Partial<SemanticPackageRead> = {}): SemanticPackageRead {
	return {
		recordingId: 3,
		meetingId: 7,
		captureMode: 'server_audio',
		recState: 'stopped',
		packageState: 'ACTIVE',
		localOnly: false,
		policyMode: 'server_only',
		manifestDigest: 'a'.repeat(64),
		timelineSha256: 'b'.repeat(64),
		timelineRecords: 4,
		startedAt: null,
		stoppedAt: null,
		segments: [
			{
				seq: 1,
				state: 'verified',
				ack: 'acknowledged',
				contentSha256: 'a'.repeat(64),
				byteSize: 100,
				mimeType: 'audio/webm',
				codec: 'opus',
				container: 'webm',
				startMs: 0,
				endMs: 1000,
				wallStartUnixMs: 1,
				wallEndUnixMs: 2,
				interruptReason: null,
			},
			{
				seq: 2,
				state: 'interrupted',
				ack: 'lost',
				contentSha256: null,
				byteSize: null,
				mimeType: 'audio/webm',
				codec: 'opus',
				container: 'webm',
				startMs: 1000,
				endMs: 2000,
				wallStartUnixMs: 3,
				wallEndUnixMs: 4,
				interruptReason: 'producer crashed mid-segment',
			},
			{
				seq: 3,
				state: 'verified',
				ack: 'acknowledged',
				contentSha256: 'a'.repeat(64),
				byteSize: 100,
				mimeType: 'audio/webm',
				codec: 'opus',
				container: 'webm',
				startMs: 2000,
				endMs: 3000,
				wallStartUnixMs: 5,
				wallEndUnixMs: 6,
				interruptReason: null,
			},
		],
		children: [],
		exports: [],
		...overrides,
	};
}

afterEach(() => cleanup());

describe('SemanticReplayPanel', () => {
	it('loading shows a status skeleton, not fabricated content', () => {
		render(SemanticReplayPanel, { props: { pkg: null, loading: true } });
		expect(screen.getByRole('status')).toBeTruthy();
	});

	it('a named error renders as an alert', () => {
		render(SemanticReplayPanel, { props: { pkg: null, error: 'Recording integrity check failed' } });
		expect(screen.getByRole('alert').textContent).toContain('integrity check failed');
	});

	it('an empty timeline explains that no replayable facts exist', () => {
		const empty = pkg({ segments: [] });
		render(SemanticReplayPanel, { props: { pkg: empty } });
		expect(screen.getByRole('status').textContent).toContain('No replayable facts');
	});

	it('gaps appear on the timeline next to media runs (deterministic playback)', () => {
		render(SemanticReplayPanel, { props: { pkg: pkg() } });
		const buttons = screen.getAllByRole('button');
		const text = buttons.map((b) => b.textContent ?? '').join('\n');
		expect(text).toContain('0.0s–1.0s');
		expect(text).toContain('Unavailable interval 1.0s–2.0s');
		expect(text).toContain('2.0s–3.0s');
	});

	it('unavailable segments are NAMED with their reason', () => {
		const { container } = render(SemanticReplayPanel, { props: { pkg: pkg() } });
		const list = container.querySelector('.semantic-replay__unavailable');
		expect(list).toBeTruthy();
		expect(list?.textContent).toContain('Segment 2: producer crashed mid-segment');
		expect(list?.textContent).toContain('1.0s–2.0s');
	});

	it('seeking into a gap announces bounds and offers continue only when it exists', async () => {
		const { container } = render(SemanticReplayPanel, { props: { pkg: pkg() } });
		const gapButton = container.querySelector('.semantic-replay__gap') as HTMLButtonElement;
		fireEvent.click(gapButton);
		expect(screen.getByText(/Unavailable 1.0s–2.0s/)).toBeTruthy();
		expect(screen.getByText(/Continue at 2.0s/)).toBeTruthy();
	});

	it('a trailing gap offers no continue affordance', () => {
		const trailing = pkg({
			segments: [pkg().segments[0], { ...pkg().segments[1], state: 'failed', interruptReason: 'revoke' }],
		});
		const { container } = render(SemanticReplayPanel, { props: { pkg: trailing } });
		const gapButton = container.querySelector('.semantic-replay__gap') as HTMLButtonElement;
		fireEvent.click(gapButton);
		expect(screen.getByText(/Unavailable 1.0s–2.0s/)).toBeTruthy();
		expect(screen.queryByText(/Continue at/)).toBeNull();
	});

	it('local-only provenance is visibly labelled', () => {
		const { container } = render(SemanticReplayPanel, {
			props: { pkg: pkg({ localOnly: true, captureMode: 'local_registered' }) },
		});
		const notes = Array.from(container.querySelectorAll('[role="note"]')).map((n) => n.textContent ?? '');
		expect(notes.some((t) => /not centrally retained/i.test(t))).toBe(true);
	});

	it('a fenced package shows its boundary state instead of playing', () => {
		render(SemanticReplayPanel, {
			props: { pkg: pkg({ packageState: 'HELD_PARTIAL', segments: [] }) },
		});
		expect(screen.getByText('HELD_PARTIAL')).toBeTruthy();
		expect(screen.getByRole('status').textContent).toContain('No replayable facts');
	});

	it('replay-feed riders render: version links, annotation refs, and the fact rail', () => {
		const fed = pkg({
			presentationLinks: [
				{
					presentationId: 1,
					status: 'ENDED',
					driveNodeId: 11,
					driveVersionId: 22,
					manifestDigest: 'c'.repeat(64),
					manifestGeneration: 2,
					startedAt: null,
					endedAt: null,
					annotationSnapshotRef: 'annotations/p1-s5.json',
				},
			],
			annotations: [
				{
					presentationId: 1,
					checkpointSeq: 5,
					presenterGeneration: 1,
					snapshotPath: 'annotations/p1-s5.json',
					sha256: 'd'.repeat(64),
					byteSize: 128,
					createdAt: '2026-09-18T00:00:20Z',
				},
			],
			facts: [
				{ presentationId: 1, checkpointSeq: 5, kind: 'annotation.committed', payload: null, atMs: 20000, mediaMs: 500 },
			],
		});
		render(SemanticReplayPanel, { props: { pkg: fed } });
		expect(screen.getByText('Presented versions')).toBeTruthy();
		expect(screen.getByText('Version 2')).toBeTruthy();
		expect(screen.getByText('Retained annotations')).toBeTruthy();
		expect(screen.getByText('Recorded events')).toBeTruthy();
	});

	it('bound captions and unaligned facts render truthfully', () => {
		const fed = pkg({
			captions: [{ language: 'en', state: 'retained', path: 'captions/en.vtt' }],
			facts: [
				{ presentationId: 1, checkpointSeq: 2, kind: 'end', payload: null, atMs: 40000, mediaMs: -1 },
			],
		});
		render(SemanticReplayPanel, { props: { pkg: fed } });
		expect(screen.getByText('Captions')).toBeTruthy();
		expect(screen.getByText('en')).toBeTruthy();
		expect(screen.getByText('Recorded events')).toBeTruthy();
		// A fact without media alignment renders in the rail, never on the axis.
		expect(screen.getByText('no media alignment')).toBeTruthy();
	});

	it('caption absence is silent (an empty list projects no section)', () => {
		const fed = pkg({ captions: [] });
		render(SemanticReplayPanel, { props: { pkg: fed } });
		expect(screen.queryByText('Captions')).toBeNull();
	});

	it('export confirms exact bounds and exclusions', () => {
		const { container } = render(SemanticReplayPanel, { props: { pkg: pkg() } });
		const exportText = container.querySelector('.semantic-replay__export')?.textContent ?? '';
		expect(exportText).toContain('Export covers:');
		expect(exportText).toContain('0.0s–1.0s, 2.0s–3.0s');
		expect(exportText).toContain('excludes:');
		expect(exportText).toContain('1.0s–2.0s');
	});

	it('export is disabled when no verified audio exists', () => {
		const noAudio = pkg({ segments: [{ ...pkg().segments[1] }] });
		render(SemanticReplayPanel, { props: { pkg: noAudio } });
		expect(screen.getByText(/Export is unavailable/)).toBeTruthy();
	});
});
