import { writable, derived } from 'svelte/store';
import { httpRequest } from '$lib/http';
import { explicitlyEnabledApps } from '$lib/types/jmap';
import type { AppId, EffectiveCapabilities, JmapSession } from '$lib/types/jmap';
import { APP_ORDER, APP_PATHS } from '$lib/nav/navConfig';

// Strict-OFF compatibility fallback: the documented B8 window posture where a
// session that predates effectiveCapabilities entirely still shows every app.
// Strict-ON must not reach this shape — see effectiveCaps' `!payload` branch.
const FALLBACK_CAPS: EffectiveCapabilities = {
	enabledApps: [...APP_ORDER],
	assist: false,
	bundling: false,
	deviceLockdown: false,
	externalLabels: false,
	guestAccounts: false,
	guestInvite: false,
	mailSearchBuilder: false,
	senderControlCenter: false,
	sharedMailWork: false,
	sharedMailComments: false,
	sharedMailDrafts: false,
	sharedMailNotifications: false,
	sharedMailAnalytics: false,
	sharedMailIntegrations: false,
	allowMeetCreate: false,
	allowMeetHost: false,
	allowDownload: false,
};

export const jmapSession = writable<JmapSession | null>(null);

// TYPES-002 (SJ-FAIL-OPEN-CAPABILITY-DEFAULT) — B8 rollout gate for the
// enabled-apps derivation posture. OFF (the default) preserves the documented
// B8 compatibility window: an absent `apps` key means enabled (default-allow).
// When the B8 rollout flips this ON, enabledApps derives through the strict
// counterpart `explicitlyEnabledApps` (kept next to the payload type so the
// two postures cannot drift): an app is enabled ONLY on an explicit server
// `true` — absent ⇒ disabled (fail-closed).
//
// The gate is BOUND TO ITS WIRE SOURCE: `GET /.well-known/jmap` advertises the
// strict posture in the session document's vendor capability block
// (`urn:setjoin:params:jmap:mail` → `appsStrictEntitlements: true`, delivered
// from system_config:apps_caps_strict by jmap.Session) — the same
// no-extra-roundtrip toggle delivery the tasks `sharedLists` flag uses.
// loadSessionStore applies the advertised posture to this store; absent/false
// signal ⇒ OFF. setAppsCapsStrict remains the single control point (used by
// the wire binding and by tests simulating each posture).
export const appsCapsStrict = writable<boolean>(false);

/** Single control point for the B8 rollout flip: true ⇒ fail-closed strict
 *  entitlements, false ⇒ the default-allow compatibility window. */
export function setAppsCapsStrict(strict: boolean): void {
	appsCapsStrict.set(strict);
}

/** Extract the strict-posture rollout signal from a decoded session document.
 *  True ONLY on an explicit vendor-block `appsStrictEntitlements: true`; the
 *  wire is an unvalidated cast, so any other shape — absent vendor block,
 *  absent/false field, non-object payload — is OFF (never throw). */
export function strictEntitlementsAdvertised(session: unknown): boolean {
	const capabilities = (session as { capabilities?: Record<string, unknown> } | null | undefined)?.capabilities;
	const vendor = capabilities?.['urn:setjoin:params:jmap:mail'] as { appsStrictEntitlements?: unknown } | null | undefined;
	return vendor?.appsStrictEntitlements === true;
}

// True once loadSessionStore has finished (success OR failure). The admin layout
// gates its "no live consoles → bounce to my-roles" redirect on this so a fresh
// load / refresh of a deep admin link doesn't bounce before capabilities resolve
// (checkAuth fires loadSessionStore fire-and-forget, so authInitializing flips
// false first). Stays false only while the very first load is in flight.
export const sessionResolved = writable<boolean>(false);

export const effectiveCaps = derived([jmapSession, appsCapsStrict], ([$s, $strict]): EffectiveCapabilities => {
	const payload = $s?.effectiveCapabilities;
	if (!payload) {
		// Legacy-server compatibility (a session with NO effectiveCapabilities key
		// at all) keeps the all-apps FALLBACK_CAPS — but ONLY while the strict
		// posture is OFF (TYPES-002 r2 Finding 1: the compatibility fallback must
		// not precede the strict branch). Strict-ON: a session that asserts no
		// capability payload asserts no entitlements, so nothing is enabled
		// (fail-closed; firstEnabledApp then lands on the unguarded /apps).
		return $strict ? { ...FALLBACK_CAPS, enabledApps: [] } : FALLBACK_CAPS;
	}
	return {
		enabledApps: $strict
			? // Fail-closed (B8 rollout flipped): explicit `true` only. A present
			  // payload with no `apps` map at all enables nothing (the wire is an
			  // unvalidated cast — never throw from the derived store).
			  payload.apps
				? explicitlyEnabledApps(payload)
				: ([] as AppId[])
			: APP_ORDER.filter((app) => payload.apps?.[app] !== false), // absent ⇒ enabled (default-allow, B8 window)
		assist: payload.features?.assist ?? false,
		bundling: payload.features?.bundles ?? false,
		deviceLockdown: payload.features?.device_lockdown ?? false,
		externalLabels: payload.features?.external_labels === true,
		guestAccounts: payload.features?.guest_accounts === true,
		guestInvite: payload.features?.guest_accounts === true && payload.features?.guest_invite === true,
		mailSearchBuilder: payload.features?.mail_search_builder === true,
		senderControlCenter: payload.features?.sender_control_center === true,
		sharedMailWork: payload.features?.shared_mail_work === true,
		sharedMailComments: payload.features?.shared_mail_comments === true,
		sharedMailDrafts: payload.features?.shared_mail_drafts === true,
		sharedMailNotifications: payload.features?.shared_mail_notifications === true,
		sharedMailAnalytics: payload.features?.shared_mail_analytics === true,
		sharedMailIntegrations: payload.features?.shared_mail_integrations === true,
		allowMeetCreate: payload.guest?.allowMeetCreate === true,
		allowMeetHost: payload.guest?.allowMeetHost === true,
		allowDownload: payload.guest?.allowDownload === true,
	};
});

export const isGuestSession = derived(jmapSession, ($s): boolean => $s?.isGuest === true);

export const firstEnabledApp = derived(effectiveCaps, ($c): string => {
	const first = $c.enabledApps[0];
	// Fallback to the unguarded launcher, NOT '/inbox': with zero enabled apps the
	// '/inbox' fallback is itself a guarded-app route, so the layout's route guard
	// would goto('/inbox') → still disabled → re-fire → infinite redirect loop.
	return first ? APP_PATHS[first] : '/apps';
});

export const sodMode = derived(jmapSession, ($s): boolean => $s?.dengbao?.sodMode ?? false);

export async function loadSessionStore(): Promise<void> {
	try {
		// loginRedirect:null so a 401 throws (caught below) instead of redirecting —
		// this is a fire-and-forget capability load; on any failure the FALLBACK_CAPS
		// remain active and the store is left untouched (no throw escapes).
		//
		// The session resource is /.well-known/jmap (the JMAP standard discovery doc,
		// same one jmap/client.ts loadSession uses) — it carries `effectiveCapabilities`
		// + the admin `capabilities` block. There is no /jmap/session route, so the old
		// path silently fell back to the SPA index.html and left every derived
		// capability (apps/assist/bundles/deviceLockdown, admin consoles) stuck on
		// FALLBACK_CAPS — i.e. server-side capability gating never took effect.
		const res = await httpRequest('/.well-known/jmap', { loginRedirect: null });
		const session: unknown = await res.json();
		jmapSession.set(session as JmapSession);
		// Apply the advertised TYPES-002 rollout posture from the same document:
		// an absent/false signal (legacy server, rollout not admitted) keeps the
		// gate OFF. On a load failure the posture is left untouched on purpose —
		// resetting OFF after a previously-advertised strict session would widen
		// the derivation back to default-allow, so an unknown state never
		// widens access.
		setAppsCapsStrict(strictEntitlementsAdvertised(session));
	} catch {
		// non-ok / network error — fallback caps remain active
	} finally {
		// Capabilities are now resolved (loaded or known-failed) — release the
		// admin-layout redirect gate either way (never strand on a caps failure).
		sessionResolved.set(true);
	}
}
