#!/usr/bin/env node
// vendor-blur-assets.mjs — Meet B1 Task 16b: self-hosts the background-blur
// WASM + segmentation-model assets as same-origin static files, mirroring
// mailserver/deploy/scripts/lib-livekit.sh's checksum-verified download
// pattern (never a CDN URL — the plan's own must, spec §3.2 + the 信创
// self-hosted-infra posture). Wired into package.json's predev/prebuild;
// re-run safe (skips once the checksum already matches; a present-but-
// mismatched retained model is removed BEFORE any download attempt, so the
// deployed set is always pinned-clean or absent). Never fails the build on
// a network/asset problem — it warns and leaves the blur toggle to degrade
// to hidden (graceful absence, not a broken switch).
//
// Two legs:
//   1. The mediapipe WASM fileset — copied straight out of
//      @mediapipe/tasks-vision's own node_modules install (a transitive dep
//      of @livekit/track-processors; npm's own integrity check already
//      covers this file, so no separate checksum is needed here — it's
//      just a local copy).
//   2. The ~244KB selfie-segmenter .tflite model — NOT shipped in the npm
//      package, fetched once from Google's model-zoo URL and pinned by
//      SHA-256 below (independently verified at authoring time,
//      2026-07-12). Never trust a runtime checksum fetched from the same
//      host serving the file — this one is hard-coded, same posture as
//      LIVEKIT_SHA256_AMD64/ARM64 in lib-livekit.sh.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, readdirSync, rmSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..'); // mailserver/webmail
const wasmSrc = join(root, 'node_modules/@mediapipe/tasks-vision/wasm');
const outDir = join(root, 'static/meet/mediapipe');
const wasmOutDir = join(outDir, 'wasm');

const MODEL_URL =
	'https://storage.googleapis.com/mediapipe-models/image_segmenter/selfie_segmenter/float16/latest/selfie_segmenter.tflite';
const MODEL_SHA256 = '191ac9529ae506ee0beefa6b2c945a172dab9d07d1e802a290a4e4038226658b';
const modelOut = join(outDir, 'selfie_segmenter.tflite');

function sha256(buf) {
	return createHash('sha256').update(buf).digest('hex');
}

// Reconcile state BEFORE any network attempt: a retained model whose checksum
// does not match the pin must never remain deployable. The old shape checked
// the pin, fell through to the download on mismatch, and — when that download
// then failed offline — left the stale/tampered file in static/ with exit 0
// (fail-open). Now the deployed set is either pinned-clean or absent, and
// blur.ts already degrades to hidden on absence (the documented contract).
function ensurePinnedModelOrAbsent() {
	if (!existsSync(modelOut)) {
		return;
	}
	if (sha256(readFileSync(modelOut)) === MODEL_SHA256) {
		return;
	}
	rmSync(modelOut);
	console.warn(
		`[vendor-blur-assets] retained segmenter model did NOT match the pinned sha256 — removed ${modelOut}; the blur toggle degrades to hidden until a verified download succeeds.`,
	);
}

function vendorWasm() {
	if (!existsSync(wasmSrc)) {
		console.warn(
			`[vendor-blur-assets] @mediapipe/tasks-vision not installed (${wasmSrc} missing) — skipping WASM vendor; the blur toggle degrades to hidden.`,
		);
		return;
	}
	mkdirSync(wasmOutDir, { recursive: true });
	for (const file of readdirSync(wasmSrc)) {
		copyFileSync(join(wasmSrc, file), join(wasmOutDir, file));
	}
	console.log(`[vendor-blur-assets] copied ${wasmSrc} -> ${wasmOutDir}`);
}

async function vendorModel() {
	ensurePinnedModelOrAbsent();
	if (existsSync(modelOut) && sha256(readFileSync(modelOut)) === MODEL_SHA256) {
		console.log('[vendor-blur-assets] segmenter model already present + checksum OK — skipping download.');
		return;
	}
	mkdirSync(outDir, { recursive: true });
	console.log('[vendor-blur-assets] downloading the selfie-segmenter model…');
	let res;
	try {
		res = await fetch(MODEL_URL);
	} catch (err) {
		console.warn(
			`[vendor-blur-assets] model download failed (${err instanceof Error ? err.message : String(err)}) — blur toggle degrades to hidden. Re-run once network access is available, or place the file manually at ${modelOut} (sha256 ${MODEL_SHA256}).`,
		);
		return;
	}
	if (!res.ok) {
		console.warn(
			`[vendor-blur-assets] model download failed (HTTP ${res.status}) — blur toggle degrades to hidden.`,
		);
		return;
	}
	const buf = Buffer.from(await res.arrayBuffer());
	const got = sha256(buf);
	if (got !== MODEL_SHA256) {
		console.error(
			`[vendor-blur-assets] checksum mismatch: expected ${MODEL_SHA256}, got ${got} — refusing to write a tampered/corrupt model.`,
		);
		process.exitCode = 1;
		return;
	}
	// Atomic publish: a torn writeFileSync must never leave a half-written
	// model at the deployed path (the pin check above would delete it on the
	// next run, but the current run would have deployed it unchecked).
	const tmp = `${modelOut}.tmp`;
	writeFileSync(tmp, buf);
	renameSync(tmp, modelOut);
	console.log(`[vendor-blur-assets] wrote ${modelOut} (sha256 verified).`);
}

vendorWasm();
await vendorModel();
