import {
  SecurityProgramError,
  assertClosedSchema,
  canonicalJson,
  parseStrictJson,
} from './security-program-json.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { publishVerifiedGeneration, readVerifiedLatest } from './security-program-publication.mjs';

export const PROJECTION_V1_SCHEMA = 'setjoin.security-program.projection/v1';
export const PROJECTION_V2_SCHEMA = 'setjoin.security-program.projection/v2';

function fail(code, message) {
  throw new SecurityProgramError(code, message);
}

export function migrateProjection(value, targetVersion = 'v2') {
  if (targetVersion !== 'v2') fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'unsupported projection migration target');
  if (value?.schema === PROJECTION_V2_SCHEMA) {
    assertClosedSchema(value, {
      schema: PROJECTION_V2_SCHEMA,
      required: ['claimed', 'verified', 'state'],
      name: 'security projection v2',
    });
    if (typeof value.claimed !== 'boolean' || typeof value.verified !== 'boolean'
        || typeof value.state !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(value.state)) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security projection v2 is malformed');
    }
    return Object.freeze({ ...value });
  }
  if (value?.schema !== PROJECTION_V1_SCHEMA) {
    fail('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'unsupported projection source schema');
  }
  assertClosedSchema(value, {
    schema: PROJECTION_V1_SCHEMA,
    required: ['claimed', 'state'],
    name: 'security projection v1',
  });
  if (typeof value.claimed !== 'boolean' || typeof value.state !== 'string'
      || !/^[A-Z][A-Z0-9_]*$/.test(value.state)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security projection v1 is malformed');
  }
  return Object.freeze({
    schema: PROJECTION_V2_SCHEMA,
    claimed: value.claimed,
    verified: false,
    state: value.state,
  });
}

export function assertProjectionMigrationFence(activeAttemptState = null) {
  if (['ACTIVE', 'DETACHED', 'ORPHANED_START', 'COMPLETION_UNKNOWN'].includes(activeAttemptState)) {
    fail('E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE', 'projection migration is fenced by an unfinished attempt');
  }
}

export function publishProjectionMigration({
  activeAttemptState = null,
  generationsDirectory,
  pointerPath,
  generationId,
  expectedPrevious,
  now,
  faultInjector,
  ...unsupported
}) {
  if (Object.keys(unsupported).length !== 0) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration contains unsupported caller authority');
  }
  assertProjectionMigrationFence(activeAttemptState);
  if (!expectedPrevious || typeof expectedPrevious.generationId !== 'string'
      || typeof expectedPrevious.generationHash !== 'string') {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration requires an exact predecessor identity');
  }
  const before = readVerifiedLatest({ generationsDirectory, pointerPath });
  if (before.generationId !== expectedPrevious.generationId
      || before.generationHash !== expectedPrevious.generationHash) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration predecessor is not the verified current generation');
  }
  const sourcePath = path.join(generationsDirectory, before.generationId, 'projection.json');
  const metadata = fs.lstatSync(sourcePath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o400) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration source is not sealed predecessor evidence');
  }
  const sourceText = fs.readFileSync(sourcePath, 'utf8');
  const source = parseStrictJson(sourceText);
  if (sourceText !== canonicalJson(source)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration source is not canonical predecessor evidence');
  }
  const after = readVerifiedLatest({ generationsDirectory, pointerPath });
  if (after.generationId !== before.generationId || after.generationHash !== before.generationHash) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'projection migration predecessor changed during source inspection');
  }
  const migrated = migrateProjection(source);
  return publishVerifiedGeneration({
    generationsDirectory,
    pointerPath,
    generationId,
    expectedPrevious,
    now,
    faultInjector,
    files: { 'projection.json': canonicalJson(migrated) },
  });
}
