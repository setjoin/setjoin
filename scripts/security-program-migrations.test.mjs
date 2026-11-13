import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { SecurityProgramError, canonicalJson, parseStrictJson } from './lib/security-program-json.mjs';
import {
  PROJECTION_V1_SCHEMA,
  PROJECTION_V2_SCHEMA,
  assertProjectionMigrationFence,
  migrateProjection,
  publishProjectionMigration,
} from './lib/security-program-migrations.mjs';
import { publishVerifiedGeneration, readVerifiedLatest } from './lib/security-program-publication.mjs';

const scratch = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-migration-')));
const generationsDirectory = path.join(scratch, 'generations');
const pointerPath = path.join(scratch, 'latest.json');
const source = { schema: PROJECTION_V1_SCHEMA, claimed: true, state: 'HOLD' };
const now = new Date('2026-09-04T00:00:00.000Z');

function expectCode(code, operation) {
  assert.throws(operation, (error) => error instanceof SecurityProgramError && error.code === code);
}

function removeFixtureTree(filename) {
  if (!fs.existsSync(filename)) return;
  const metadata = fs.lstatSync(filename);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    fs.chmodSync(filename, 0o700);
    for (const name of fs.readdirSync(filename)) removeFixtureTree(path.join(filename, name));
  } else if (!metadata.isSymbolicLink()) fs.chmodSync(filename, 0o600);
  fs.rmSync(filename, { recursive: true, force: true });
}

try {
  const migrated = migrateProjection(source);
  assert.deepEqual(migrated, {
    schema: PROJECTION_V2_SCHEMA, claimed: true, verified: false, state: 'HOLD',
  });
  assert.deepEqual(migrateProjection(migrated), migrated, 'current projection replay must be idempotent');
  expectCode('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', () => migrateProjection({
    schema: 'setjoin.security-program.projection/v3', claimed: true, verified: true, state: 'PASS',
  }));
  expectCode('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', () => migrateProjection(source, 'v3'));
  for (const activeAttemptState of ['ACTIVE', 'DETACHED', 'ORPHANED_START', 'COMPLETION_UNKNOWN']) {
    expectCode('E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE', () => assertProjectionMigrationFence(activeAttemptState));
  }
  assert.doesNotThrow(() => assertProjectionMigrationFence('FRESH'));

  const root = publishVerifiedGeneration({
    generationsDirectory,
    pointerPath,
    generationId: 'migration-root-v1',
    files: { 'projection.json': canonicalJson(source) },
    now,
  });
  const rootIdentity = { generationId: root.generationId, generationHash: root.generationHash };
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => publishProjectionMigration({
    source, generationsDirectory, pointerPath, generationId: 'caller-authored-v2',
    expectedPrevious: rootIdentity, now,
  }));
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => publishProjectionMigration({
    generationsDirectory: path.join(scratch, 'unlinked-generations'),
    pointerPath: path.join(scratch, 'unlinked-latest.json'),
    generationId: 'unlinked-migration-v2', now,
  }));
  for (const activeAttemptState of ['ACTIVE', 'DETACHED', 'ORPHANED_START', 'COMPLETION_UNKNOWN']) {
    expectCode('E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE', () => publishProjectionMigration({
      activeAttemptState,
      generationsDirectory,
      pointerPath,
      generationId: `migration-blocked-${activeAttemptState.toLowerCase().replaceAll('_', '-')}`,
      expectedPrevious: rootIdentity,
      now,
    }));
  }

  let interrupted = false;
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => publishProjectionMigration({
    generationsDirectory,
    pointerPath,
    generationId: 'migration-recovered-v2',
    expectedPrevious: rootIdentity,
    now: new Date('2026-09-04T00:01:00.000Z'),
    faultInjector(checkpoint) {
      if (checkpoint === 'before-pointer-rename' && !interrupted) {
        interrupted = true;
        throw new SecurityProgramError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'migration interruption fixture');
      }
    },
  }));
  const recovered = publishProjectionMigration({
    generationsDirectory,
    pointerPath,
    generationId: 'migration-recovered-v2',
    expectedPrevious: rootIdentity,
    now: new Date('2026-09-04T00:01:00.000Z'),
  });
  assert.equal(recovered.predecessorGenerationId, root.generationId);
  const projection = parseStrictJson(fs.readFileSync(
    path.join(generationsDirectory, recovered.generationId, 'projection.json'), 'utf8',
  ));
  assert.deepEqual(projection, migrated);

  const rootReceipt = parseStrictJson(fs.readFileSync(
    path.join(generationsDirectory, root.generationId, 'generation-receipt.json'), 'utf8',
  ));
  fs.chmodSync(pointerPath, 0o600);
  fs.writeFileSync(pointerPath, `${JSON.stringify({
    schema: 'setjoin.security-program.latest-pointer/v1',
    generationId: rootReceipt.generationId,
    generationHash: rootReceipt.generationHash,
    predecessorGenerationId: rootReceipt.predecessorGenerationId,
    predecessorGenerationHash: rootReceipt.predecessorGenerationHash,
    createdAt: rootReceipt.createdAt,
  })}\n`, { mode: 0o400 });
  fs.chmodSync(pointerPath, 0o400);
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => readVerifiedLatest({ generationsDirectory, pointerPath }));

  console.log('security-program migrations: PASS (v1-to-v2, future reject, active-attempt fence, interruption replay, rollback pointer reject, scanner=0 network=0)');
} finally {
  removeFixtureTree(scratch);
}
