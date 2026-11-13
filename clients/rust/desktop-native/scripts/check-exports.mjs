import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const binding = require('../index.js');

const expected = [
	'dbExec',
	'dbExecSchemaInit',
	'dbIsOpen',
	'dbMigrateStore',
	'dbOpen',
	'dbQuery',
	'dbTransactionBatch',
	'dbWipe',
	'driveDeleteChunks',
	'driveFetchChunk',
	'driveHasChunk',
	'driveImportFile',
	'drivePushChunk',
	'driveServeGrant',
	'driveSetConfinement',
	'driveServeRevoke',
	'driveServeStart',
	'driveServeStop',
	'mamClearWiped',
	'mamGetPolicy',
	'mamIsWiped',
	'mamMarkWiped',
	'mamStoreDeviceId',
	'mamStorePolicy',
	'pushDevicePublicKey',
	'recoveryBlobReadChunk',
	'recoveryBlobReadClose',
	'recoveryBlobReadOpen',
	'recoveryBlobRef',
	'recoveryBlobUnref',
	'recoveryBlobWriteAbort',
	'recoveryBlobWriteBegin',
	'recoveryBlobWriteChunk',
	'recoveryBlobWriteCommit',
	'secureStoreGet',
	'secureStoreRemove',
	'secureStoreSet',
	'vaultGenerateTotp',
	'vaultIsUnlocked',
	'vaultListTotp',
	'vaultUnlock',
].sort();

const actual = Object.keys(binding).sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
	throw new Error(`desktop-native export drift\nexpected: ${expected.join(',')}\nactual:   ${actual.join(',')}`);
}
if (binding.vaultIsUnlocked() !== false) {
	throw new Error('fresh desktop-native binding must start with the vault locked');
}

console.log(`desktop-native exports OK: ${actual.length} exact functions; fresh vault locked`);
