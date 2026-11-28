import { describe, it, expect } from 'vitest';
import { driveErrorMessage } from './errors';
import { DriveError } from './api';
import { t } from '$lib/i18n';

function err(code: string, detail: string | undefined = 'server detail text'): DriveError {
	// detail is typed as required `string` on DriveErrorShape/DriveError — the
	// real server always sends one (problemOnError defaults it) — but the
	// `?? t(fallbackKey)` branch in driveErrorMessage only exists for the
	// theoretical case where it's missing, so the "no detail" test below casts
	// through `unknown` to construct that otherwise-unreachable shape.
	return new DriveError({ status: 400, code, detail: detail as unknown as string });
}

describe('driveErrorMessage', () => {
	it('localizes a BZ code that has a drive.errors.* key', () => {
		expect(driveErrorMessage(err('BZ145'))).toBe(t('drive.errors.BZ145'));
		expect(driveErrorMessage(err('BZ145'))).not.toBe('drive.errors.BZ145');
	});

	it('falls back to e.detail for a BZ-shaped code with no key', () => {
		expect(driveErrorMessage(err('BZ999', 'unmapped detail'))).toBe('unmapped detail');
	});

	it('falls back to the fallback translation when detail is missing and the code has no key', () => {
		// JS default params trigger on an explicit `undefined` too, so err()'s
		// default would mask this case — construct directly instead.
		const noDetail = new DriveError({ status: 400, code: 'BZ999' } as unknown as ConstructorParameters<typeof DriveError>[0]);
		expect(driveErrorMessage(noDetail)).toBe(t('common.error'));
	});

	it('falls back to the fallback translation for a plain Error', () => {
		expect(driveErrorMessage(new Error('boom'))).toBe(t('common.error'));
	});
});
