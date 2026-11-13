//! Vault (guard-core) handlers. Ported 1:1 from Tauri `bridge.rs`:
//! vault_unlock / vault_is_unlocked / vault_list_totp / vault_generate_totp.
//! The vault db path is resolved to `<userData>/guard.db` and provisioned inside
//! the native module (as Tauri did in `vault_db_path`).

import * as path from 'node:path';
import type { NativeBinding } from '../native';
import type { HandlerMap } from './db';

export function makeVaultHandlers(native: NativeBinding, userDataDir: string): HandlerMap {
	const vaultPath = path.join(userDataDir, 'guard.db');
	return {
		// Returns a boolean (Tauri's vault_unlock resolved to bool, never rejected
		// on a wrong passphrase). The native binding already returns bool.
		vault_unlock: (passphrase: unknown) => native.vaultUnlock(vaultPath, String(passphrase)),
		vault_is_unlocked: () => native.vaultIsUnlocked(),
		vault_list_totp: () => native.vaultListTotp(),
		vault_generate_totp: (id: unknown) => native.vaultGenerateTotp(String(id)),
	} as HandlerMap;
}
