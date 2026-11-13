import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// ── Route raw-fetch ratchet (WP5, decision 5A; fingerprint binding 2026-09-30
// round 2) ──────────────────────────────────────────────────────────────────
//
// Routes must load/save through the typed seams ($lib/http.ts, admin/client.ts,
// jmap/client.ts, $lib/composables/settings-resource.svelte.ts) instead of
// hand-rolling fetch + res.ok + login-redirect chains. The 2026-09-30 census
// froze 20 route files / 71 raw fetch calls. The WP5 slice + its completion
// round migrated all four named routes to zero raw fetches
// (settings/signatures, settings/privacy, quarantine, settings/security).
//
// The baseline below binds every REMAINING grandfathered exception to the
// EXACT CALL FINGERPRINTS observed in the source — not per-file counts. A
// fingerprint is `callee + METHOD + first-argument source text` (whitespace
// collapsed), so:
//
//   - a NEW raw fetch anywhere in src/routes/** fails (unknown fingerprint);
//   - REPLACING an old grandfathered call with a new one fails even though the
//     per-file count stays equal — the new call's fingerprint is unknown and
//     the removed call's fingerprint is reported stale;
//   - removing a call without shrinking this baseline fails the entry as STALE
//     (the reduction path stays: delete the entry when a file goes clean, and
//     drop its fingerprints as calls migrate);
//   - every entry carries a reason; a missing/empty reason throws at config
//     load (unreasoned exceptions are rejected);
//   - test files (*.test.ts / *.spec.ts) are exempt — fetch mocks stay allowed;
//   - never silence this rule with in-file disables: shrink the baseline.
const ROUTE_RAW_FETCH_BASELINE = {
	'settings/migration/+page.svelte': {
		calls: [
			"fetch POST '/auth/me/migration/test-imap'",
			"fetch POST '/auth/me/migration'",
			"fetch POST `/auth/me/migration/upload?job_id=${jobId}`",
			"fetch GET '/auth/me/migration'",
			"fetch POST '/auth/me/migration/cancel'",
			"fetch POST '/auth/me/migration/pause'",
			"fetch POST '/auth/me/migration/resume'",
		],
		reason: 'IMAP migration wizard actions (test/connect/start/cancel/pause/resume/upload) — multipart and status-polling flows; follow-up migration.',
	},
	'admin/(mail)/migration/+page.svelte': {
		calls: [
			"fetch GET '/api/admin/migration/jobs'",
			"fetch POST '/api/admin/migration/test-connection'",
			"fetch POST '/api/admin/migration/start'",
			"fetch POST `/api/admin/migration/jobs/${id}/cancel`",
			"fetch POST `/api/admin/migration/jobs/${id}/retry`",
			"fetch POST `/api/admin/migration/jobs/${id}/cancel`",
		],
		reason: 'Admin migration job actions (list/test/start/cancel/retry) — admin client consolidation lands with the admin Fetch seam follow-up.',
	},
	'inbox/+page.svelte': {
		calls: [
			"fetch GET '/api/quarantine/count'",
			"fetch GET '/api/user/notification-preferences'",
			"fetch POST '/auth/me/read-receipt'",
			"fetch POST `/api/messages/${bundle.latestEmailId}/unsubscribe`",
			"fetch POST '/jmap'",
		],
		reason: 'Quarantine badge, read-receipt send, unsubscribe action, bundle action and /jmap probe — message-flow actions; follow-up migration.',
	},
	'settings/+page.svelte': {
		calls: [
			"fetch GET '/api/user/offline/caps'",
			"fetch POST '/api/user/profile'",
			"fetch PUT '/api/settings/view'",
		],
		reason: 'Offline caps probe + profile/view saves — settings storage pattern, first in the follow-up order.',
	},
	'admin/(identity)/terms-of-use/+page.svelte': {
		calls: [
			"fetch GET '/api/admin/terms-of-use'",
			"fetch GET url",
			"fetch DELETE `/api/admin/terms-of-use/${deleteTarget.id}`",
		],
		reason: 'ToU draft save/publish/delete admin actions — admin client consolidation follow-up.',
	},
	'+page.svelte': {
		calls: [
			"fetch GET `/api/discover?domain=${encodeURIComponent(domain)}`",
			"fetch GET '/jmap/session'",
			"fetch GET '/api/cert-hint'",
		],
		reason: 'Pre-login discover/cert-hint/jmap-session probes on the root (login) page — pre-auth flows keep their hand-rolled shape like stores/auth.ts; follow-up decision owed.',
	},
	'settings/notifications/+page.svelte': {
		calls: [
			"fetch GET '/api/user/notification-preferences'",
			"fetch PUT '/api/user/notification-preferences'",
		],
		reason: 'Notification-preferences load/save — same settings pattern as privacy; follow-up migration.',
	},
	'settings/automatic-replies/+page.svelte': {
		calls: [
			"fetch GET '/api/user/automatic-replies'",
			"fetch PUT '/api/user/automatic-replies'",
		],
		reason: 'Automatic-replies load/save — settings-resource pattern; follow-up migration.',
	},
	'settings/approval-delegation/+page.svelte': {
		calls: [
			"fetch GET '/api/user/approval-delegation'",
			"fetch PUT '/api/user/approval-delegation'",
		],
		reason: 'Approval-delegation load/save — settings-resource pattern; follow-up migration.',
	},
	'blocked/+page.svelte': {
		calls: [
			"fetch POST '/api/device/self-enroll'",
			"fetch GET '/.well-known/jmap'",
		],
		reason: 'Pre-auth device self-enroll POST and /.well-known/jmap read on the blocked-device page — pre-auth flows; follow-up decision owed.',
	},
	'admin/(access)/user-risk/+page.svelte': {
		calls: [
			"fetch GET '/api/admin/user-risk'",
			"fetch POST `/api/admin/user-risk/${id}/reset`",
		],
		reason: 'User-risk list + reset admin actions — admin client consolidation follow-up.',
	},
	'setup/+page.svelte': {
		calls: [
			"fetch GET '/setup/status'",
		],
		reason: 'Pre-auth /setup/status probe during first-run setup — pre-auth flow; follow-up decision owed.',
	},
	'settings/storage/+page.svelte': {
		calls: [
			"fetch GET '/api/user/offline/caps'",
		],
		reason: 'Offline caps read — settings storage pattern, first in the follow-up order.',
	},
	'settings/about/+page.svelte': {
		calls: [
			"fetch GET '/health'",
		],
		reason: '/health probe on the about page — settings-resource pattern; follow-up migration.',
	},
	'recover/+page.svelte': {
		calls: [
			"fetch GET '/jmap/session'",
		],
		reason: 'Pre-auth /jmap/session read on the recovery page — pre-auth flow; follow-up decision owed.',
	},
	'admin/+page.svelte': {
		calls: [
			"fetch GET '/api/admin/monitor/live?sections=volume,threats,system'",
		],
		reason: 'Admin monitor live stream (readable stream response) — streaming body is outside typedFetch; follow-up decision owed.',
	},
};

// Baseline validation: stale or unreasoned entries are rejected outright.
// Exported so the ratchet selftests pin the same rejection.
export function assertRouteRawFetchBaselineWellFormed(baseline) {
	for (const [file, entry] of Object.entries(baseline)) {
		if (
			!entry ||
			!Array.isArray(entry.calls) ||
			entry.calls.length < 1 ||
			!entry.calls.every((fp) => typeof fp === 'string' && fp.trim().length > 0) ||
			typeof entry.reason !== 'string' ||
			entry.reason.trim().length < 8
		) {
			throw new Error(
				`route-raw-fetch baseline entry '${file}' must carry a non-empty calls fingerprint array and a non-empty reason`
			);
		}
	}
}

assertRouteRawFetchBaselineWellFormed(ROUTE_RAW_FETCH_BASELINE);

function isRawFetchCallee(callee) {
	if (callee.type === 'Identifier') return callee.name === 'fetch';
	if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
		if (callee.property.name !== 'fetch') return false;
		return callee.object.type === 'Identifier' && (callee.object.name === 'window' || callee.object.name === 'globalThis');
	}
	return false;
}

// The call fingerprint: `<callee> <METHOD> <first-argument source>` with
// whitespace collapsed. Reformatting the call keeps the fingerprint; changing
// the callee (bare vs window./globalThis.), the method, or the URL/target
// expression changes it. Exported for the ratchet selftests.
export function rawFetchCallFingerprint(context, node) {
	const collapse = (text) => text.replace(/\s+/g, ' ').trim();
	const callee = collapse(context.sourceCode.getText(node.callee));
	const arg0 =
		node.arguments.length > 0 ? collapse(context.sourceCode.getText(node.arguments[0])) : '<no-arguments>';
	let method = 'GET';
	const init = node.arguments[1];
	if (init && init.type === 'ObjectExpression') {
		for (const prop of init.properties) {
			if (
				prop.type === 'Property' &&
				!prop.computed &&
				((prop.key.type === 'Identifier' && prop.key.name === 'method') ||
					(prop.key.type === 'Literal' && prop.key.value === 'method')) &&
				prop.value.type === 'Literal' &&
				typeof prop.value.value === 'string'
			) {
				method = String(prop.value.value).toUpperCase();
			}
		}
	}
	return `${callee} ${method} ${arg0}`;
}

function countBy(fingerprints) {
	const counts = new Map();
	for (const fp of fingerprints) counts.set(fp, (counts.get(fp) ?? 0) + 1);
	return counts;
}

// Named export: the ratchet's selftest drives this rule through RuleTester.
export const routeRawFetchRule = {
	meta: {
		type: 'problem',
		docs: {
			description:
				'Route-only raw-fetch ratchet: raw fetch, window.fetch and globalThis.fetch calls under src/routes/** are bound to EXACT frozen call fingerprints per file (WP5 decision 5A) — new calls, and replacements of grandfathered calls at an unchanged count, both fail. Route through $lib/http.ts or $lib/composables/settings-resource.svelte.ts instead.',
		},
		schema: [
			{
				type: 'object',
				properties: {
					baseline: {
						type: 'object',
						additionalProperties: {
							type: 'object',
							properties: {
								calls: { type: 'array', items: { type: 'string', minLength: 1 }, minItems: 1 },
								reason: { type: 'string' },
							},
							required: ['calls', 'reason'],
							additionalProperties: false,
						},
					},
				},
				additionalProperties: false,
			},
		],
		messages: {
			noBaseline:
				'Raw fetch() in a route has no baseline entry — route it through the $lib/http seam or the settings-resource composable (src/lib/composables/README.md). New raw route fetches fail this ratchet.',
			unknownCall:
				'Raw fetch() call [{{fingerprint}}] is not one of this route\'s frozen baseline fingerprints — replacing an old call with a new one fails the ratchet even at an unchanged count. Route it through the $lib/http seam / settings-resource composable. Frozen calls: {{calls}}. Baseline reason: {{reason}}',
			staleBaseline:
				'Baseline fingerprint(s) [{{missing}}] no longer exist in this route — the entry is STALE. Shrink the baseline (and the census in src/lib/composables/README.md) in the same change. Baseline reason: {{reason}}',
		},
	},
	create(context) {
		const filename = String(context.filename ?? '').replace(/\\/g, '/');
		const routeIdx = filename.indexOf('src/routes/');
		if (routeIdx === -1) return {};
		// Fetch mocks in route tests stay allowed.
		if (/\.(test|spec)\.[cm]?[jt]s$/.test(filename)) return {};
		const options = context.options[0] ?? {};
		const baseline = options.baseline ?? ROUTE_RAW_FETCH_BASELINE;
		const routePath = filename.slice(routeIdx + 'src/routes/'.length);
		const calls = [];
		return {
			CallExpression(node) {
				if (isRawFetchCallee(node.callee)) calls.push(node);
			},
			'Program:exit'() {
				const entry = baseline[routePath];
				if (!entry) {
					for (const node of calls) context.report({ node, messageId: 'noBaseline' });
					return;
				}
				// Multiset comparison: per-fingerprint counts must match exactly.
				// Occurrence i (0-based) of a fingerprint is covered iff the
				// baseline lists more than i copies of it — so a NEW call, a
				// REPLACEMENT at an unchanged count, and a DUPLICATE of a
				// grandfathered call all report unknownCall, while a removed
				// call leaves an unconsumed baseline fingerprint (stale below).
				const expected = countBy(entry.calls);
				const seen = new Map();
				for (const node of calls) {
					const fp = rawFetchCallFingerprint(context, node);
					const occurrence = seen.get(fp) ?? 0;
					seen.set(fp, occurrence + 1);
					if (occurrence >= (expected.get(fp) ?? 0)) {
						context.report({
							node,
							messageId: 'unknownCall',
							data: { fingerprint: fp, calls: entry.calls.join(' | '), reason: entry.reason },
						});
					}
				}
				const missing = [];
				for (const [fp, count] of expected) {
					const present = seen.get(fp) ?? 0;
					for (let i = present; i < count; i += 1) missing.push(fp);
				}
				if (missing.length > 0) {
					context.report({
						node: calls[0] ?? context.sourceCode.ast,
						messageId: 'staleBaseline',
						data: { missing: missing.join(' | '), reason: entry.reason },
					});
				}
			},
		};
	},
};

// Named exports for the ratchet's selftests (src/routes/route-raw-fetch.rule.test.ts).
export const routeRawFetchBaseline = ROUTE_RAW_FETCH_BASELINE;
export const routeRawFetchPlugin = { rules: { 'no-new-raw-fetch': routeRawFetchRule } };

export default tseslint.config(
	{
		ignores: [
			'.svelte-kit/**',
			'build/**',
			'coverage/**',
			'node_modules/**',
			'playwright-report/**',
			'static/**',
			'test-results/**'
		]
	},
	js.configs.recommended,
	...tseslint.configs.recommended,
	...svelte.configs['flat/recommended'],
	{
		files: ['**/*.{js,mjs,mts,ts}'],
		languageOptions: {
			globals: {
				...globals.browser,
				...globals.node
			}
		},
		rules: {
			// TypeScript resolves names more accurately than ESLint's JS-only rule.
			'no-undef': 'off',
			'no-redeclare': 'off',
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-unused-expressions': 'off',
			'@typescript-eslint/no-unused-vars': 'off'
		}
	},
	{
		files: ['**/*.svelte.{js,ts}'],
		languageOptions: {
			parser: tseslint.parser
		},
		rules: {
			'no-useless-assignment': 'off',
			'svelte/no-navigation-without-resolve': 'off',
			'svelte/prefer-svelte-reactivity': 'off'
		}
	},
	{
		files: ['**/*.svelte'],
		languageOptions: {
			globals: globals.browser,
			parserOptions: {
				parser: tseslint.parser
			}
		},
		rules: {
			'no-undef': 'off',
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-unused-expressions': 'off',
			'@typescript-eslint/no-unused-vars': 'off',
			'no-useless-assignment': 'off',
			// These migration-oriented Svelte rules are tracked separately from the
			// correctness gate; enabling them would require broad UI rewrites.
			'svelte/no-navigation-without-resolve': 'off',
			'svelte/no-unused-svelte-ignore': 'off',
			'svelte/no-useless-children-snippet': 'off',
			'svelte/prefer-svelte-reactivity': 'off',
			'svelte/prefer-writable-derived': 'off',
			'svelte/require-each-key': 'off',
			'svelte/valid-prop-names-in-kit-pages': 'off'
		}
	},
	{
		files: ['e2e/**/*.ts'],
		rules: {
			'no-empty-pattern': 'off'
		}
	},
	{
		files: ['**/*.test.ts'],
		rules: {
			'@typescript-eslint/no-this-alias': 'off',
			'no-useless-assignment': 'off'
		}
	},
	{
		files: [
			'src/lib/offline/recovery.ts',
			'src/lib/search/searchIntent.ts',
			'src/lib/validation.ts'
		],
		rules: {
			'no-control-regex': 'off'
		}
	},
	{
		// Route-only raw-fetch ratchet (WP5 decision 5A): see the baseline block
		// above. Test files stay exempt (fetch mocks are allowed) — enforced both
		// here and inside the rule so the selftests pin the same behavior.
		files: ['src/routes/**/*.{svelte,js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
		ignores: ['src/routes/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts}'],
		plugins: { 'route-raw-fetch': routeRawFetchPlugin },
		rules: {
			'route-raw-fetch/no-new-raw-fetch': 'error'
		}
	}
);
