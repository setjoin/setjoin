/**
 * E4-I r5 Astra correction (finding 6) regression: the receipt PRODUCER
 * (`writeCaseResult`) and the receipt VALIDATOR
 * (`scripts/check-connectivity-aware-sync-cases.mjs`) must agree. The
 * validator resolves retained artifacts and fixtures from the REPOSITORY root
 * and requires the run-scoped artifact template plus the exact
 * repo-root-relative fixture identity; the harness now emits exactly that
 * shape, and this suite proves an honestly generated receipt validates
 * UNCHANGED by running the real checker over it.
 *
 * TEST-BUILD-ONLY: the harness module under test refuses non-test imports.
 */

import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
	E4I_CASE_IDS,
	caseFixturePath,
	defaultRunId,
	e4iArtifactPath,
	repositoryRootDir,
	writeCaseResult,
	type CaseVerdict,
} from './backgroundWorkHarness';

const repositoryRoot = repositoryRootDir();
const manifestPath = path.join(repositoryRoot, 'docs', 'verification', 'connectivity-aware-sync-cases.json');
const checkerPath = path.join(repositoryRoot, 'scripts', 'check-connectivity-aware-sync-cases.mjs');

/** The validator's run-identity grammar (keep in sync with the checker). */
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

interface ManifestCase {
	id: string;
	fixture: string;
	retainedArtifacts: string[];
	seed?: string;
	lane: string;
}

function readManifest(): { cases: ManifestCase[]; evidenceRegistry: Array<{ caseId: string; resultId: string; lane: string }> } {
	return JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
		cases: ManifestCase[];
		evidenceRegistry: Array<{ caseId: string; resultId: string; lane: string }>;
	};
}

describe('E4-I receipt producer/validator agreement (r5 finding 6)', () => {
	it('the harness artifact template and fixture identity match the manifest exactly', () => {
		const manifest = readManifest();
		for (const caseId of E4I_CASE_IDS) {
			const entry = manifest.cases.find((candidate) => candidate.id === caseId);
			expect(entry, `manifest must carry ${caseId}`).toBeTruthy();
			// The run-scoped artifact TEMPLATE is the manifest's own.
			expect(e4iArtifactPath(caseId)).toBe(entry!.retainedArtifacts[0]);
			// The receipt's fixture identity is the manifest's
			// repo-root-relative fixture path, character for character.
			expect(caseFixturePath(caseId)).toBe(entry!.fixture);
			expect(caseFixturePath(caseId)).toMatch(/^mailserver\/webmail\//);
		}
	});

	it('the default run identity is a real, validator-acceptable, non-overwriting run id', () => {
		const first = defaultRunId();
		expect(RUN_ID_RE.test(first)).toBe(true);
		// A timestamped id, never a shared constant: two runs can never land on
		// the same evidence path the way a bare 'local' default would.
		expect(first).not.toBe('local');
		expect(first).toMatch(/^local-\d{4}-\d{2}-\d{2}T/);
		expect(first.startsWith(`local-${new Date().toISOString().slice(0, 10)}`)).toBe(true);
	});

	it('a receipt produced by writeCaseResult validates unchanged under the real checker', () => {
		const manifest = readManifest();
		const caseId = E4I_CASE_IDS[0];
		const entry = manifest.cases.find((candidate) => candidate.id === caseId)!;
		const binding = manifest.evidenceRegistry.find((candidate) => candidate.caseId === caseId)!;
		const runId = 'harness-agreement-regression';

		// The producer writes the receipt EXACTLY as a lane run would.
		const receiptFile = writeCaseResult({ caseId, ok: true, observations: {} } as CaseVerdict, runId);
		// ...at the run-scoped REPOSITORY-root path the validator resolves.
		expect(receiptFile).toBe(path.join(
			repositoryRoot,
			'test-results',
			'connectivity-aware-sync',
			runId,
			'e4i',
			'trigger-step-bounds.json',
		));
		expect(fs.existsSync(receiptFile)).toBe(true);

		// The lane results document cites the run-substituted artifact path.
		const resultsDocument = {
			schemaVersion: 1,
			runId,
			utcTime: new Date().toISOString(),
			results: [{
				caseId,
				status: 'passed',
				resultId: binding.resultId,
				lane: binding.lane,
				retainedArtifacts: entry.retainedArtifacts.map((artifact) => artifact.replace('<run-id>', runId)),
			}],
		};
		const resultsFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'e4i-agreement-')), 'results.json');
		fs.writeFileSync(resultsFile, JSON.stringify(resultsDocument, null, 2));

		try {
			const result = spawnSync(
				process.execPath,
				[checkerPath, manifestPath, resultsFile, '--case', caseId],
				{ encoding: 'utf8' },
			);
			const output = `${result.stdout}${result.stderr}`;
			expect(result.status, output).toBe(0);
			expect(output).toContain('PASS');
		} finally {
			fs.rmSync(path.dirname(resultsFile), { recursive: true, force: true });
		}
	});
});

afterAll(() => {
	// The suite owns exactly the run-scoped evidence it created under the
	// repository root; nothing else in test-results is touched.
	fs.rmSync(path.join(repositoryRoot, 'test-results', 'connectivity-aware-sync', 'harness-agreement-regression'), {
		recursive: true,
		force: true,
	});
});
