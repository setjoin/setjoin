// Shared driveErrorMessage — one blind BZ-code→i18n mapping used by every
// Drive surface (was 11 near-duplicate local copies with 3 divergent
// behaviors: no localization / a narrow per-site allow-list / the
// BZ139-BZ148 allow-list — see retired-docs:superpowers/sdd/task-9-report.md for the
// prior-attempt divergence analysis and the controller's full-convergence
// decision). `en.ts` defines drive.errors.BZ139-BZ150; any code with a key
// localizes here, everything else falls back to the server's raw `detail`
// (or the fallback translation if there's no detail either).
import { t } from '$lib/i18n';
import { DriveError } from '$lib/drive/api';

export function driveErrorMessage(e: unknown, fallbackKey = 'common.error'): string {
	if (e instanceof DriveError && /^BZ\d{3}$/.test(e.code)) {
		const key = 'drive.errors.' + e.code;
		const msg = t(key);
		return msg !== key ? msg : (e.detail ?? t(fallbackKey));
	}
	return t(fallbackKey);
}
