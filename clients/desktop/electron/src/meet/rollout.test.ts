import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import {
	DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE,
	MEET_LOCAL_RECORDING_FLAG,
	MEET_LOCAL_RECORDING_ROLLOUT_MODES,
	assertCaptureAdmitted,
	captureAdmitted,
	probesAdmitted,
} from './rollout';

/** The client-side flag name must stay pinned to the server toggle registry
 *  (server-rust/crates/domains/platform/testdata/toggle/registry-v275.json). */
const toggleRegistry = JSON.parse(
	readFileSync(
		new URL('../../../../../server-rust/crates/domains/platform/testdata/toggle/registry-v275.json', import.meta.url),
		'utf8',
	),
) as { definitions: Array<{ key: string }> };

describe('meet local recording rollout gate', () => {
	it('pins the flag name to the server toggle registry', () => {
		expect(MEET_LOCAL_RECORDING_FLAG).toBe('feature.meet_local_recording');
		expect(toggleRegistry.definitions.some((d) => d.key === MEET_LOCAL_RECORDING_FLAG)).toBe(true);
	});

	it('ships the shared off/observe/execute vocabulary with production default off', () => {
		expect(MEET_LOCAL_RECORDING_ROLLOUT_MODES).toEqual(['off', 'observe', 'execute']);
		expect(DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE).toBe('off');
	});

	it('admits read-only probes in observe and execute, never off', () => {
		expect(probesAdmitted('off')).toBe(false);
		expect(probesAdmitted('observe')).toBe(true);
		expect(probesAdmitted('execute')).toBe(true);
	});

	it('admits the capture path only in execute', () => {
		expect(captureAdmitted('off')).toBe(false);
		expect(captureAdmitted('observe')).toBe(false);
		expect(captureAdmitted('execute')).toBe(true);
	});

	it('refuses capture-path entry points by throwing the named rollout refusal', () => {
		expect(() => assertCaptureAdmitted('off', 'consent.grant')).toThrowError(
			/feature\.meet_local_recording is not admitted in rollout mode 'off'/,
		);
		expect(() => assertCaptureAdmitted('observe', 'heartbeat.start')).toThrowError(
			/rollout mode 'observe'/,
		);
		expect(() => assertCaptureAdmitted('execute', 'capture.start')).not.toThrow();
	});
});
