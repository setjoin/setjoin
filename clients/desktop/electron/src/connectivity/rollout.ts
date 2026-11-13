//! Flag discipline for the connectivity-aware-sync harness surface
//! (`src/connectivity/` — the E6 desktop lane).
//!
//! How the connectivity flag reaches this client: the toggle lives server-side
//! (`shared/toggle/toggle.go` FeatureConnectivityAwareSync, default OFF) and
//! the E4-I coordinator itself lives in the webmail TypeScript layer
//! (`mailserver/webmail/src/lib/offline/coordinator.ts`), behind that same
//! default-OFF key. The Electron MAIN process has no toggle plumbing of its
//! own; the established client-side rollout seam is the MAM
//! `off|observe|execute` composition contract (`mamLifecycleOwner.ts`, reused
//! verbatim by `meet/rollout.ts`), which `main.ts` wires with the explicit
//! production default `off` so the landed composition path performs nothing
//! until a separate trusted rollout.
//!
//! This module pins that same vocabulary for the E6 saturation-status surface.
//! The shipped default stays `off`: nothing here widens it, and the ONLY way a
//! running instance admits the surface is the harness-only env seam below —
//! unset in every production launch, so the substrate is INERT there. The env
//! seam exists so the E6 paired-run harness can launch the candidate member of
//! one identical build with `execute` while the comparator member runs `off`
//! (the harness's `E6_FLAG`/`E6_POLICY_MODE` contract), without a second build
//! and without touching the shipped default.

/** The V264-style toggle this surface hangs behind — mirrors
 *  `shared/toggle/toggle.go` FeatureConnectivityAwareSync (default OFF). */
export const CONNECTIVITY_AWARE_SYNC_FLAG = "feature.connectivity_aware_sync";

/** Shared `off|observe|execute` rollout vocabulary (the MAM contract genre). */
export type ConnectivitySyncRolloutMode = "off" | "observe" | "execute";

export const CONNECTIVITY_SYNC_ROLLOUT_MODES: readonly ConnectivitySyncRolloutMode[] = [
	"off",
	"observe",
	"execute",
];

/** The shipped production default: the E6 saturation-status surface is inert
 *  and nothing listens. Only a separate trusted rollout decision (or the
 *  harness-only env seam below, for a harness-launched candidate instance)
 *  may widen it. */
export const DEFAULT_CONNECTIVITY_SYNC_ROLLOUT_MODE: ConnectivitySyncRolloutMode = "off";

/** Harness-only seam: forces the rollout mode of ONE harness-launched client
 *  instance (`off|observe|execute`). Unset in production; an invalid value is
 *  a composition REFUSAL, never a silent fallback. */
export const CONNECTIVITY_SYNC_MODE_ENV = "SETJOIN_E6_CONNECTIVITY_SYNC_MODE";

/** Harness-only seam: isolates ONE harness-launched client instance's
 *  user-data dir so two pair members of the same build can run side by side
 *  without colliding on stores (the `ELECTRON_DEV_SERVER_URL` env-seam genre).
 *  Presence of this variable also marks the instance as harness-managed —
 *  the only condition under which the E6 readiness line is printed. */
export const CONNECTIVITY_SYNC_USER_DATA_ENV = "SETJOIN_E6_USER_DATA_DIR";

/** True when the value is exactly one of the rollout vocabulary entries. */
export function isConnectivitySyncRolloutMode(
	value: unknown,
): value is ConnectivitySyncRolloutMode {
	return (
		typeof value === "string" &&
		(CONNECTIVITY_SYNC_ROLLOUT_MODES as readonly string[]).includes(value)
	);
}

/**
 * Resolve the rollout mode for a launching instance. Unset/empty falls back to
 * the shipped default `off`; a set-but-invalid value REFUSES (throws) rather
 * than silently degrading — a harness pair member that boots with the wrong
 * flag posture would invalidate the comparison, so this fails closed at
 * composition time where the launcher's readiness wait surfaces it.
 */
export function resolveConnectivitySyncRolloutMode(
	raw: string | undefined,
): ConnectivitySyncRolloutMode {
	if (raw === undefined || raw === "") return DEFAULT_CONNECTIVITY_SYNC_ROLLOUT_MODE;
	if (!isConnectivitySyncRolloutMode(raw)) {
		throw new Error(
			`${CONNECTIVITY_SYNC_MODE_ENV}=${JSON.stringify(raw)} is not a rollout mode ` +
				`(${CONNECTIVITY_SYNC_ROLLOUT_MODES.join("|")}); refusing to compose a misflagged instance`,
		);
	}
	return raw;
}

/** True when the mode admits READ-ONLY status surfaces (the saturation
 *  status endpoint is a read-only probe). `off` admits nothing. */
export function statusAdmitted(mode: ConnectivitySyncRolloutMode): boolean {
	return mode !== "off";
}

/** The field name the bridge carries the harness rollout mode under
 *  (`window.setjoinNative.connectivity.rolloutMode`). Pinned on BOTH sides of
 *  the build boundary — the webmail reads it in
 *  `mailserver/webmail/src/lib/offline/boot.ts`. */
export const CONNECTIVITY_BRIDGE_ROLLOUT_FIELD = "rolloutMode";

/**
 * The bridge-carried harness rollout mode: the ONLY path the E6 pair's
 * per-member flag delta reaches the webmail layer (the member's session
 * document cannot carry the device-gated `offline_effective_policy` block —
 * the fixture's password-login session has no device claim). `off` — every
 * production launch, the env seam unset — exposes NOTHING: the returned null
 * keeps the production bridge byte-identical to its pre-seam shape.
 */
export function connectivityBridgeModeFor(
	env: NodeJS.ProcessEnv,
): { rolloutMode: ConnectivitySyncRolloutMode } | null {
	const mode = resolveConnectivitySyncRolloutMode(env[CONNECTIVITY_SYNC_MODE_ENV]);
	if (!statusAdmitted(mode)) return null;
	return { rolloutMode: mode };
}
