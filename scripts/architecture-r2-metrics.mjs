#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { cpus, platform, totalmem } from 'node:os';

const SCHEMA_VERSION = 1;
const DURATION_LIMIT_MS = 300_000;
const DIAGNOSTIC_LIMIT_MS = 30_000;

function fail(problem, cause, value, fix, rerun) {
	process.stderr.write(
		`E_ARCH_R2_METRICS problem=${problem} cause=${cause} value=${JSON.stringify(value)} fix=${JSON.stringify(fix)} rerun=${JSON.stringify(rerun)}\n`
	);
	process.exitCode = 1;
}

function run(command, args = []) {
	try {
		return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
	} catch {
		return 'missing';
	}
}

function sha256(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

function canonical(value) {
	if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
	if (value && typeof value === 'object') {
		return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
	}
	return JSON.stringify(value);
}

function atomicJSON(path, value) {
	mkdirSync(dirname(path), { recursive: true });
	const temporary = `${path}.tmp-${process.pid}`;
	writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
	renameSync(temporary, path);
}

function safeReadJSON(path) {
	try {
		return JSON.parse(readFileSync(path, 'utf8'));
	} catch (error) {
		throw new Error(`${path}: ${error instanceof Error ? error.message : String(error)}`);
	}
}

function memoryTier(bytes) {
	const gib = bytes / 1024 ** 3;
	if (gib < 4) return '<4GiB';
	if (gib < 8) return '4-8GiB';
	if (gib < 16) return '8-16GiB';
	if (gib < 32) return '16-32GiB';
	if (gib < 64) return '32-64GiB';
	if (gib < 128) return '64-128GiB';
	return '>=128GiB';
}

function lockDigest(root) {
	const listed = run('git', ['-C', root, 'ls-files', '*go.sum', '*package-lock.json', '*Cargo.lock', 'go.work.sum']);
	if (listed === 'missing' || !listed) return sha256('no-lockfiles');
	const hash = createHash('sha256');
	for (const path of listed.split('\n').filter(Boolean).sort()) {
		const absolute = join(root, path);
		if (!existsSync(absolute)) continue;
		hash.update(path);
		hash.update('\0');
		hash.update(readFileSync(absolute));
		hash.update('\0');
	}
	return hash.digest('hex');
}

function filesystemClass(root) {
	if (platform() === 'darwin') {
		const df = run('df', ['-P', root]).split('\n').filter(Boolean);
		const mount = df.at(-1)?.trim().split(/\s+/).at(-1) || '/';
		const info = run('diskutil', ['info', mount]);
		const match = info.match(/^\s*File System Personality:\s*(.+)$/m);
		return match?.[1]?.trim().toLowerCase() || 'darwin-unknown';
	}
	return run('stat', ['-f', '-c', '%T', root]);
}

function virtualizationClass() {
	if (existsSync('/.dockerenv')) return 'container';
	const detected = run('systemd-detect-virt');
	if (detected !== 'missing' && detected !== 'none') return detected;
	return platform() === 'darwin' ? 'darwin-native-or-vm' : 'native-or-unknown';
}

function fingerprint(root, output) {
	const cpuList = cpus();
	const inputs = {
		os: platform(),
		architecture: process.arch,
		shell: basename(process.env.SHELL || 'unknown'),
		bash: run('bash', ['--version']).split('\n')[0],
		go: run('go', ['version']),
		node: process.version,
		npm: run('npm', ['--version']),
		rust: run('rustc', ['--version']),
		postgresClient: run('psql', ['--version']),
		dependencyLockDigest: lockDigest(root),
		cpuModel: cpuList[0]?.model?.trim() || 'unknown',
		physicalCores: platform() === 'darwin' ? run('sysctl', ['-n', 'hw.physicalcpu']) : run('lscpu', ['-p=core']).split('\n').filter((line) => line && !line.startsWith('#')).filter((line, index, all) => all.indexOf(line) === index).length,
		logicalCores: cpuList.length,
		memoryTier: memoryTier(totalmem()),
		virtualization: virtualizationClass(),
		filesystem: filesystemClass(root),
		ciImage: [process.env.ImageOS, process.env.ImageVersion, process.env.RUNNER_OS, process.env.RUNNER_ARCH].filter(Boolean).join(':') || 'local'
	};
	const populationKey = sha256(canonical(inputs));
	atomicJSON(output, { schemaVersion: SCHEMA_VERSION, populationKey, inputs });
}

function recordSample(args) {
	const [output, logPath, commit, classification, populationKey, ordinal, startedAt, duration, diagnostic, status] = args;
	const logBytes = readFileSync(logPath);
	atomicJSON(output, {
		schemaVersion: SCHEMA_VERSION,
		commit,
		classification,
		populationKey,
		ordinal: Number(ordinal),
		startedAt,
		durationMs: Number(duration),
		diagnosticLatencyMs: Number(diagnostic),
		status,
		artifacts: [{ path: basename(logPath), sha256: sha256(logBytes) }]
	});
}

function nearestRank(values, quantile) {
	if (values.length === 0) return { index: 0, value: null };
	const index = Math.ceil(quantile * values.length);
	return { index, value: values[index - 1] };
}

function aggregate(runDir, expectedSamples, warmupCount, classification) {
	const fingerprintPath = join(runDir, 'fingerprint.json');
	const fingerprintData = safeReadJSON(fingerprintPath);
	const sampleDir = join(runDir, 'samples');
	const files = existsSync(sampleDir)
		? readdirSync(sampleDir).filter((name) => /^\d{3}\.json$/.test(name)).sort()
		: [];
	const samples = files.map((name) => ({ name, path: join(sampleDir, name), data: safeReadJSON(join(sampleDir, name)) }));
	const sampleArtifacts = samples.map(({ name, path }) => ({
		path: `samples/${name}`,
		sha256: sha256(readFileSync(path))
	}));
	const commits = new Set(samples.map(({ data }) => data.commit));
	const populationKeys = new Set(samples.map(({ data }) => data.populationKey));
	const classifications = new Set(samples.map(({ data }) => data.classification));
	const ordinals = samples.map(({ data }) => data.ordinal);
	const successful = samples.filter(({ data }) => data.status === 'pass');
	const durations = successful.map(({ data }) => data.durationMs).sort((a, b) => a - b);
	const diagnostics = successful.map(({ data }) => data.diagnosticLatencyMs).sort((a, b) => a - b);
	const p50 = nearestRank(durations, 0.5);
	const p95 = nearestRank(durations, 0.95);
	const diagnosticP95 = nearestRank(diagnostics, 0.95);
	const coherentPopulation =
		samples.length === expectedSamples &&
		commits.size === 1 &&
		populationKeys.size === 1 &&
		populationKeys.has(fingerprintData.populationKey) &&
		classifications.size === 1 &&
		classifications.has(classification) &&
		ordinals.every((value, index) => value === index + 1);
	const completePopulation = coherentPopulation && successful.length === expectedSamples;

	let verdict = 'insufficient_samples';
	let qualification = 'none';
	if (classification === 'cold') {
		qualification = 'cold_informational';
		verdict = completePopulation ? 'informational' : 'insufficient_samples';
	} else if (coherentPopulation && !completePopulation) {
		verdict = 'failed';
	} else if (completePopulation && expectedSamples === 20 && warmupCount === 2) {
		qualification = 'scheduled_p95';
		verdict = p95.value <= DURATION_LIMIT_MS && Math.max(...diagnostics) <= DIAGNOSTIC_LIMIT_MS ? 'pass' : 'failed';
	} else if (completePopulation && expectedSamples === 5 && warmupCount === 1) {
		qualification = 'pr_surrogate';
		verdict = Math.max(...durations) <= DURATION_LIMIT_MS && Math.max(...diagnostics) <= DIAGNOSTIC_LIMIT_MS ? 'pass' : 'failed';
	}

	const result = {
		schemaVersion: SCHEMA_VERSION,
		commit: commits.size === 1 ? [...commits][0] : null,
		classification,
		populationKey: fingerprintData.populationKey,
		populationInputs: fingerprintData.inputs,
		warmupCount,
		expectedSamples,
		recordedSamples: samples.length,
		successfulSamples: successful.length,
		qualification,
		formula: {
			name: 'nearest-rank',
			p50Index: p50.index,
			p95Index: p95.index,
			p95Expression: `ceil(0.95*${durations.length})`
		},
		metrics: {
			p50DurationMs: p50.value,
			p95DurationMs: p95.value,
			maxDurationMs: durations.length ? Math.max(...durations) : null,
			p95DiagnosticLatencyMs: diagnosticP95.value,
			maxDiagnosticLatencyMs: diagnostics.length ? Math.max(...diagnostics) : null
		},
		thresholds: {
			durationMs: DURATION_LIMIT_MS,
			diagnosticLatencyMs: DIAGNOSTIC_LIMIT_MS
		},
		samples: sampleArtifacts,
		verdict
	};
	atomicJSON(join(runDir, 'aggregate.json'), result);
	return result;
}

function assertRelativeArtifact(base, candidate) {
	const resolved = resolve(base, candidate);
	if (resolved !== base && !resolved.startsWith(`${base}${sep}`)) throw new Error(`artifact escapes run directory: ${candidate}`);
	return resolved;
}

function validate(aggregatePath) {
	const aggregateData = safeReadJSON(aggregatePath);
	const runDir = dirname(aggregatePath);
	if (aggregateData.schemaVersion !== SCHEMA_VERSION) throw new Error('unsupported aggregate schema');
	if (!['pass', 'failed', 'insufficient_samples', 'informational'].includes(aggregateData.verdict)) throw new Error('invalid verdict');
	if (!Array.isArray(aggregateData.samples) || aggregateData.samples.length !== aggregateData.recordedSamples) throw new Error('sample count mismatch');
	if (sha256(canonical(aggregateData.populationInputs)) !== aggregateData.populationKey) throw new Error('population fingerprint mismatch');
	const samples = [];
	for (const artifact of aggregateData.samples) {
		const path = assertRelativeArtifact(runDir, artifact.path);
		if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`missing sample artifact: ${artifact.path}`);
		if (sha256(readFileSync(path)) !== artifact.sha256) throw new Error(`sample hash mismatch: ${artifact.path}`);
		const sample = safeReadJSON(path);
		samples.push(sample);
		if (sample.commit !== aggregateData.commit || sample.populationKey !== aggregateData.populationKey || sample.classification !== aggregateData.classification) {
			throw new Error(`mixed population sample: ${artifact.path}`);
		}
		if (!Number.isFinite(sample.durationMs) || sample.durationMs < 0 || !Number.isFinite(sample.diagnosticLatencyMs) || sample.diagnosticLatencyMs < 0) {
			throw new Error(`invalid sample metric: ${artifact.path}`);
		}
		for (const nested of sample.artifacts ?? []) {
			const nestedPath = assertRelativeArtifact(dirname(path), nested.path);
			if (!existsSync(nestedPath) || sha256(readFileSync(nestedPath)) !== nested.sha256) throw new Error(`sample log hash mismatch: ${artifact.path}/${nested.path}`);
		}
	}
	if (!samples.every((sample, index) => sample.ordinal === index + 1)) throw new Error('sample ordinal mismatch');
	const successful = samples.filter((sample) => sample.status === 'pass');
	const durations = successful.map((sample) => sample.durationMs).sort((a, b) => a - b);
	const diagnostics = successful.map((sample) => sample.diagnosticLatencyMs).sort((a, b) => a - b);
	const p50 = nearestRank(durations, 0.5);
	const p95 = nearestRank(durations, 0.95);
	const diagnosticP95 = nearestRank(diagnostics, 0.95);
	const expectedMetrics = {
		p50DurationMs: p50.value,
		p95DurationMs: p95.value,
		maxDurationMs: durations.length ? Math.max(...durations) : null,
		p95DiagnosticLatencyMs: diagnosticP95.value,
		maxDiagnosticLatencyMs: diagnostics.length ? Math.max(...diagnostics) : null
	};
	if (canonical(aggregateData.metrics) !== canonical(expectedMetrics)) throw new Error('aggregate metric mismatch');
	if (aggregateData.successfulSamples !== successful.length) throw new Error('successful sample count mismatch');
	if (aggregateData.formula.p50Index !== p50.index || aggregateData.formula.p95Index !== p95.index || aggregateData.formula.p95Expression !== `ceil(0.95*${durations.length})`) {
		throw new Error('nearest-rank formula mismatch');
	}
	if (aggregateData.thresholds.durationMs !== DURATION_LIMIT_MS || aggregateData.thresholds.diagnosticLatencyMs !== DIAGNOSTIC_LIMIT_MS) throw new Error('threshold drift');
	let expectedVerdict = 'insufficient_samples';
	let expectedQualification = 'none';
	const complete = samples.length === aggregateData.expectedSamples && successful.length === aggregateData.expectedSamples;
	if (aggregateData.classification === 'cold') {
		expectedQualification = 'cold_informational';
		expectedVerdict = complete ? 'informational' : 'insufficient_samples';
	} else if (samples.length === aggregateData.expectedSamples && !complete) {
		expectedVerdict = 'failed';
	} else if (complete && aggregateData.expectedSamples === 20 && aggregateData.warmupCount === 2) {
		expectedQualification = 'scheduled_p95';
		expectedVerdict = p95.value <= DURATION_LIMIT_MS && Math.max(...diagnostics) <= DIAGNOSTIC_LIMIT_MS ? 'pass' : 'failed';
	} else if (complete && aggregateData.expectedSamples === 5 && aggregateData.warmupCount === 1) {
		expectedQualification = 'pr_surrogate';
		expectedVerdict = Math.max(...durations) <= DURATION_LIMIT_MS && Math.max(...diagnostics) <= DIAGNOSTIC_LIMIT_MS ? 'pass' : 'failed';
	}
	if (aggregateData.verdict !== expectedVerdict || aggregateData.qualification !== expectedQualification) throw new Error('aggregate verdict mismatch');
	if (aggregateData.qualification === 'scheduled_p95') {
		if (aggregateData.expectedSamples !== 20 || aggregateData.warmupCount !== 2 || aggregateData.formula.p95Index !== 19) throw new Error('invalid scheduled p95 contract');
	} else if (aggregateData.qualification === 'pr_surrogate') {
		if (aggregateData.expectedSamples !== 5 || aggregateData.warmupCount !== 1) throw new Error('invalid PR surrogate contract');
	}
	process.stdout.write(`architecture-r2 metrics: ${aggregateData.verdict} (${aggregateData.qualification}; ${aggregateData.recordedSamples} samples; p95=${aggregateData.metrics.p95DurationMs}ms)\n`);
	return aggregateData.verdict === 'pass' || aggregateData.verdict === 'informational';
}

function usage() {
	process.stdout.write('usage: architecture-r2-metrics.mjs fingerprint|record-sample|aggregate|validate|diagnostic ...\n');
}

const [command, ...args] = process.argv.slice(2);
try {
	switch (command) {
		case 'fingerprint':
			if (args.length !== 2) throw new Error('fingerprint requires ROOT OUTPUT');
			fingerprint(resolve(args[0]), resolve(args[1]));
			break;
		case 'record-sample':
			if (args.length !== 10) throw new Error('record-sample requires 10 arguments');
			recordSample(args);
			break;
		case 'aggregate': {
			if (args.length !== 4) throw new Error('aggregate requires RUN_DIR SAMPLES WARMUPS CLASS');
			const result = aggregate(resolve(args[0]), Number(args[1]), Number(args[2]), args[3]);
			process.stdout.write(`${result.verdict}\n`);
			break;
		}
		case 'validate':
			if (args.length !== 1) throw new Error('validate requires AGGREGATE');
			if (!validate(resolve(args[0]))) process.exitCode = 1;
			break;
		case 'diagnostic':
			fail('planted_failure', 'benchmark_diagnostic_probe', 'intentional', 'run the normal benchmark to record a passing diagnostic latency', 'bash scripts/verify-architecture-r2.sh benchmark --class warm --samples 5 --warmup 1');
			break;
		case '--help':
			usage();
			break;
		default:
			usage();
			process.exitCode = 2;
	}
} catch (error) {
	fail(
		'invalid_evidence',
		error instanceof Error ? error.message : String(error),
		args.join(' '),
		'regenerate the benchmark evidence from an unchanged checkout',
		'bash scripts/verify-architecture-r2.sh benchmark --class warm --samples 5 --warmup 1'
	);
}
