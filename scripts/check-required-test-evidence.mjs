#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';

const [manifestPath, baselinePath] = process.argv.slice(2);
if (!manifestPath || !baselinePath) {
	console.error('usage: check-required-test-evidence.mjs MANIFEST BASELINE');
	process.exit(2);
}

try {
	const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
	const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
	if (baseline.schemaVersion !== 1 || !Array.isArray(baseline.requirements) || !Array.isArray(baseline.evidence)) {
		throw new Error('invalid required-evidence baseline schema');
	}
	const requirements = [];
	const evidence = [];
	for (const contract of manifest.contracts ?? []) {
		for (const requirement of contract.requirements ?? []) {
			requirements.push(requirement.id);
			for (const item of requirement.evidence ?? []) evidence.push(item.id);
		}
	}
	for (const [label, ids] of [['requirement', requirements], ['evidence', evidence]]) {
		const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
		if (duplicates.length) throw new Error(`duplicate ${label} id(s): ${[...new Set(duplicates)].join(', ')}`);
	}
	const missingRequirements = baseline.requirements.filter((id) => !requirements.includes(id));
	const missingEvidence = baseline.evidence.filter((id) => !evidence.includes(id));
	if (missingRequirements.length || missingEvidence.length) {
		throw new Error([
			missingRequirements.length ? `missing required requirement id(s): ${missingRequirements.join(', ')}` : '',
			missingEvidence.length ? `missing required evidence id(s): ${missingEvidence.join(', ')}` : '',
		].filter(Boolean).join('; '));
	}
	console.log(`required-test-evidence: PASS (${baseline.requirements.length} requirement id(s), ${baseline.evidence.length} evidence id(s))`);
} catch (error) {
	console.error(`required-test-evidence: FAIL — ${error.message}`);
	process.exit(1);
}
