#!/usr/bin/env node

import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const corpusPath = path.join(root, 'clients/mam/conformance/v1/lifecycle.json');
const harmonyAdapterPath = path.join(root, 'clients/harmonyos/entry/src/main/ets/native/Mam.ets');
const harmonyLifecyclePath = path.join(root, 'clients/harmonyos/entry/src/main/ets/native/MamLifecycle.ets');
const harmonyCompositionPath = path.join(root, 'clients/harmonyos/entry/src/main/ets/pages/MainPage.ets');
const harmonyAbilityPath = path.join(root, 'clients/harmonyos/entry/src/main/ets/entryability/EntryAbility.ets');
const harmonyOwnerPath = path.join(root, 'clients/harmonyos/entry/src/main/ets/native/MamLifecycleOwner.ets');
const electronLifecyclePath = path.join(root, 'clients/desktop/electron/src/mamLifecycle.ts');
const electronOwnerPath = path.join(root, 'clients/desktop/electron/src/mamLifecycleOwner.ts');
const electronCompositionPath = path.join(root, 'clients/desktop/electron/src/main.ts');
const rustLifecyclePath = path.join(root, 'clients/desktop/src-tauri/src/mam_lifecycle.rs');
const rustOwnerPath = path.join(root, 'clients/desktop/src-tauri/src/mam_lifecycle_owner.rs');
const rustCompositionPath = path.join(root, 'clients/desktop/src-tauri/src/lib.rs');

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function normalizePolicy(version, map) {
  const maxOfflineDays = Number.parseInt(map.max_offline_days ?? '', 10);
  return {
    policy_version: version,
    copy_paste: map.copy_paste ?? '',
    screen_capture: map.screen_capture ?? '',
    encryption: map.encryption ?? '',
    watermark: map.watermark === 'true',
    notification_profile: map.notification_profile ?? '',
    max_offline_days: Number.isNaN(maxOfflineDays) ? 0 : maxOfflineDays,
  };
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateCorpus(corpus) {
  invariant(corpus.contract === 'setjoin.mam.lifecycle', 'unexpected MAM corpus contract id');
  invariant(corpus.version === 1, 'unsupported MAM corpus version');
  invariant(sameJson(corpus.rollout_modes, ['off', 'observe', 'execute']), 'MAM rollout mode contract drift');
  invariant(corpus.default_rollout_mode === 'off', 'MAM production rollout must default OFF');
  invariant(corpus.periodic_interval_ms === 15 * 60 * 1000, 'MAM periodic interval drift');
  invariant(corpus.signing_vectors?.length >= 2, 'MAM corpus needs at least two signing vectors');

  for (const vector of corpus.signing_vectors) {
    invariant(vector.secret.startsWith('test-only-'), `${vector.name}: fixture secret must be visibly test-only`);
    invariant(vector.challenge === `${vector.device_id}:${vector.timestamp}`, `${vector.name}: canonical challenge drift`);
    const got = createHmac('sha256', vector.secret).update(vector.challenge).digest('hex');
    invariant(got === vector.hmac_sha256_hex, `${vector.name}: HMAC golden drift`);
  }

  const request = corpus.request_vectors?.find((v) => v.name === 'signed-checkin-with-cached-version');
  invariant(request, 'missing signed check-in request vector');
  invariant(request.expected_body.device_id === request.device_id, 'request device_id must stay numeric');
  invariant(request.expected_body.policy_version === request.known_policy_version, 'request must echo cached policy version');
  invariant(request.expected_headers['If-None-Match'] === String(request.known_policy_version), 'request ETag drift');
  invariant(request.expected_headers['X-Device-Timestamp'] === request.timestamp, 'request timestamp drift');
  invariant(
    request.expected_headers['X-Device-HMAC'] ===
      createHmac('sha256', request.secret).update(`${request.device_id}:${request.timestamp}`).digest('hex'),
    'request HMAC drift',
  );

  const policyResponses = corpus.response_vectors?.filter((v) => v.expected.normalized_policy) ?? [];
  invariant(policyResponses.length >= 2, 'MAM corpus must cover changed and default policy normalization');
  for (const response of policyResponses) {
    invariant(response.status === 200, `${response.name}: policy response status drift`);
    invariant(
      sameJson(normalizePolicy(response.body.policy_version, response.body.policy), response.expected.normalized_policy),
      `${response.name}: policy normalization drift`,
    );
    invariant(
      sameJson(response.expected.effect_intents, ['cache_device', 'cache_policy', 'enforce_policy']),
      `${response.name}: policy effect order drift`,
    );
  }

  const notModified = corpus.response_vectors?.find((v) => v.name === 'not-modified-keeps-cache');
  invariant(notModified?.status === 304, 'missing 304 response vector');
  invariant(notModified.expected.policy_version === notModified.known_policy_version, '304 must retain cached version');
  invariant(notModified.expected.effect_intents.length === 0, '304 must not emit effects');

  const wipe = corpus.response_vectors?.find((v) => v.name === 'wipe-precedes-policy');
  invariant(wipe?.body?.wipe_requested === true, 'missing remote-wipe response vector');
  invariant(
    sameJson(wipe.expected.effect_intents, ['latch_wipe', 'clear_web_storage']),
    'remote wipe must latch before clearing web storage',
  );
  invariant(wipe.expected.forbidden_effect_intents.includes('cache_policy'), 'wipe vector must forbid policy caching');
}

function requirePattern(source, pattern, message) {
  invariant(pattern.test(source), message);
}

function validateHarmonySource(lifecycle, adapter, composition) {
  requirePattern(adapter, /Number\.parseInt\(deviceId, 10\)/, 'Harmony request must encode numeric device_id');
  requirePattern(adapter, /knownPolicyVersion\(NativeBinding\.mamGetPolicy\(\)\)/, 'Harmony must read cached policy version');
  requirePattern(lifecycle, /'If-None-Match': knownVersion\.toString\(\)/, 'Harmony must send cached ETag');
  requirePattern(
    lifecycle,
    /body: \{ device_id: deviceId, policy_version: knownVersion \}/,
    'Harmony check-in body must send device_id and policy_version',
  );
  requirePattern(lifecycle, /if \(status === 304\)/, 'Harmony pure reducer must preserve cache on 304');
  requirePattern(lifecycle, /policyFromMap\(version, body\.policy \?\? \{\}\)/, 'Harmony must normalize the flat server policy map');
  requirePattern(adapter, /buildCheckinRequest\(/, 'Harmony adapter must call the pure request builder');
  requirePattern(adapter, /reduceCheckinResponse\(/, 'Harmony adapter must call the pure response reducer');
  requirePattern(adapter, /for \(const effect of transition\.effects\)/, 'Harmony adapter must execute ordered effect intents');

  const wipeBranch = lifecycle.indexOf('if (body.wipe_requested === true)');
  const latchIntent = lifecycle.indexOf("{ type: 'latch_wipe' }", wipeBranch);
  const clearIntent = lifecycle.indexOf("{ type: 'clear_web_storage' }", wipeBranch);
  const policyIntent = lifecycle.indexOf("{ type: 'cache_policy'", wipeBranch);
  invariant(wipeBranch >= 0 && latchIntent > wipeBranch && clearIntent > latchIntent, 'Harmony wipe must latch before web clear');
  invariant(policyIntent < 0 || policyIntent > clearIntent, 'Harmony wipe branch must precede policy effects');

  requirePattern(composition, /new Mam\(this\.serverUrl, async/, 'Harmony composition must supply the ArkWeb clear effect');
  requirePattern(composition, /this\.controller\.runJavaScript/, 'Harmony wipe clear must use the owning WebviewController');
}

function validateThreeLanguageModules(electron, rust, harmony) {
  for (const [language, source] of [['TypeScript', electron], ['Rust', rust], ['ArkTS', harmony]]) {
    requirePattern(source, /build_?CheckinRequest|build_checkin_request/, `${language} pure request builder missing`);
    requirePattern(source, /reduce_?CheckinResponse|reduce_checkin_response/, `${language} pure response reducer missing`);
  }
}

function validateLifecycleOwners(sources) {
  requirePattern(sources.electronOwner, /DEFAULT_MAM_ROLLOUT_MODE[^=]*= 'off'/, 'Electron MAM owner must default OFF');
  requirePattern(sources.electronOwner, /class MamLifecycleOwner/, 'Electron exactly-one owner missing');
  requirePattern(sources.electronComposition, /mamLifecycleOwner = new MamLifecycleOwner/, 'Electron composition caller missing');
  requirePattern(sources.electronComposition, /mamLifecycleOwner\.start\(\)/, 'Electron start caller missing');
  requirePattern(sources.electronComposition, /mamLifecycleOwner\?\.resume\(\)/, 'Electron resume caller missing');
  requirePattern(sources.electronComposition, /mamLifecycleOwner\?\.stop\(\)/, 'Electron stop caller missing');

  requirePattern(sources.rustOwner, /DEFAULT_MAM_ROLLOUT_MODE[^=]*= MamRolloutMode::Off/, 'Tauri MAM owner must default OFF');
  requirePattern(sources.rustComposition, /MamLifecycleOwner::new\(/, 'Tauri composition caller missing');
  requirePattern(sources.rustComposition, /RunEvent::Ready => owner\.start\(\)/, 'Tauri start caller missing');
  requirePattern(sources.rustComposition, /WindowEvent::Resumed,[\s\S]*?=> owner\.resume\(\)/, 'Tauri mobile resume caller missing');
  requirePattern(sources.rustComposition, /RunEvent::Exit => owner\.stop\(\)/, 'Tauri stop caller missing');

  requirePattern(sources.harmonyOwner, /DEFAULT_MAM_ROLLOUT_MODE[^=]*= 'off'/, 'Harmony MAM owner must default OFF');
  requirePattern(sources.harmonyComposition, /MamLifecycleComposition\.install\(/, 'Harmony MainPage owner install missing');
  requirePattern(sources.harmonyAbility, /onForeground\(\): void \{\s*MamLifecycleComposition\.foreground\(\)/, 'Harmony foreground opportunity missing');
  requirePattern(sources.harmonyAbility, /onBackground\(\): void \{\s*MamLifecycleComposition\.background\(\)/, 'Harmony background pause missing');
  requirePattern(sources.harmonyAbility, /onDestroy\(\): void \{\s*MamLifecycleComposition\.stop\(\)/, 'Harmony stop caller missing');
  invariant(!sources.harmonyAdapter.includes('startPeriodicCheckin'), 'Harmony adapter must not retain a second scheduler');
}

function check(corpusText, sources) {
  validateCorpus(JSON.parse(corpusText));
  validateThreeLanguageModules(sources.electron, sources.rust, sources.harmonyLifecycle);
  validateHarmonySource(sources.harmonyLifecycle, sources.harmonyAdapter, sources.harmonyComposition);
  validateLifecycleOwners(sources);
}

function selfTest(corpusText, sources) {
  let caughtCorpus = false;
  try {
    check(corpusText.replace('"version": 1', '"version": 2'), sources);
  } catch {
    caughtCorpus = true;
  }
  invariant(caughtCorpus, 'self-test failed to catch corpus version drift');

  let caughtHarmony = false;
  try {
    check(corpusText, {
      ...sources,
      harmonyLifecycle: sources.harmonyLifecycle.replace("'If-None-Match': knownVersion.toString(),", ''),
    });
  } catch {
    caughtHarmony = true;
  }
  invariant(caughtHarmony, 'self-test failed to catch Harmony request drift');

  let caughtOwner = false;
  try {
    check(corpusText, {
      ...sources,
      harmonyAbility: sources.harmonyAbility.replace('MamLifecycleComposition.foreground();', ''),
    });
  } catch {
    caughtOwner = true;
  }
  invariant(caughtOwner, 'self-test failed to catch Harmony foreground-owner drift');
}

const corpusText = readFileSync(corpusPath, 'utf8');
const sources = {
  electron: readFileSync(electronLifecyclePath, 'utf8'),
  electronOwner: readFileSync(electronOwnerPath, 'utf8'),
  electronComposition: readFileSync(electronCompositionPath, 'utf8'),
  rust: readFileSync(rustLifecyclePath, 'utf8'),
  rustOwner: readFileSync(rustOwnerPath, 'utf8'),
  rustComposition: readFileSync(rustCompositionPath, 'utf8'),
  harmonyLifecycle: readFileSync(harmonyLifecyclePath, 'utf8'),
  harmonyAdapter: readFileSync(harmonyAdapterPath, 'utf8'),
  harmonyComposition: readFileSync(harmonyCompositionPath, 'utf8'),
  harmonyAbility: readFileSync(harmonyAbilityPath, 'utf8'),
  harmonyOwner: readFileSync(harmonyOwnerPath, 'utf8'),
};
const mode = process.argv[2] ?? '--check';

try {
  if (mode === '--self-test') {
    selfTest(corpusText, sources);
    console.log('MAM lifecycle conformance self-test: PASS');
  } else if (mode === '--check') {
    check(corpusText, sources);
    console.log('MAM lifecycle conformance: PASS (corpus v1 + TS/Rust/ArkTS pure modules)');
  } else {
    console.error('usage: mam-lifecycle-conformance.mjs [--check|--self-test]');
    process.exitCode = 2;
  }
} catch (error) {
  console.error(`MAM lifecycle conformance: FAIL: ${error.message}`);
  process.exitCode = 1;
}
