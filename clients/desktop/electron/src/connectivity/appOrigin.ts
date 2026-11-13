//! E6 harness app-origin + member-session seams (the `SETJOIN_E6_*` env-seam
//! genre owned by `rollout.ts`).
//!
//! WHY THIS EXISTS (the 2026-09-21 white-screen defect): the pair launcher
//! originally let both instances load the BUNDLED webmail build
//! (`loadFile(webmailIndexPath())`) with a fresh user-data dir and no server —
//! the SPA booted with no API origin and rendered nothing. Worse, the E6
//! experiment's measured substrate — the E4-I coordinator — lives in the
//! GATEWAY-SERVED webmail (per-user, behind a logged-in session), so the
//! launched instances never ran it at all. This module is the fix's surface:
//! a harness-only, loopback-validated APP ORIGIN the window loads via
//! `loadURL` (through the SAME `appOrigins` allowlist + session-lockdown path
//! the composition root already owns), plus the member-session bootstrap that
//! gives the instance the SAME HttpOnly `access_token` cookie the authserver
//! sets on a real browser login (name/value captured by the fixture from the
//! login response itself — the value IS the minted bearer token, asserted by
//! the fixture's drift guard), plus the page-level readiness probe and the
//! session watchdog that keeps the logged-in session alive across the
//! reset-pair session wipes and 1 h token TTLs of a 2.5-3.5 h run.
//!
//! SEAM CHOICE (why not `ELECTRON_DEV_SERVER_URL`): the existing env loads a
//! vite DEV server (HMR semantics, unvalidated URL). The E6 window must load
//! the gateway-served PRODUCTION webmail build on a loopback origin —
//! overloading dev semantics would blur the one thing the harness must prove
//! (which build/origin the measured window rendered). The explicit seam feeds
//! the SAME app-origin mechanism (`appOrigins` + `loadURL`); only the source
//! of the origin differs, it is validated loopback-http-only, and it is INERT
//! (like every `SETJOIN_E6_*` seam) whenever unset — production never sets it.

/** Harness-only seam: the loopback http origin of the GATEWAY-SERVED webmail
 *  the instance must render (`http://127.0.0.1:<port>` — never a dev server,
 *  never a non-loopback host). Unset in every production launch; a
 *  set-but-invalid value is a composition REFUSAL, never a silent fallback. */
export const CONNECTIVITY_SYNC_APP_ORIGIN_ENV = "SETJOIN_E6_APP_ORIGIN";

/** Harness-only seam: the member session to bootstrap BEFORE the first load,
 *  in exact `name=value` Set-Cookie shape as captured from the fixture's
 *  login response. The name must be the authserver's SPA session cookie
 *  (fail-closed — anything else is a refusal). Requires
 *  CONNECTIVITY_SYNC_APP_ORIGIN_ENV (a session cookie names an origin). */
export const CONNECTIVITY_SYNC_SESSION_COOKIE_ENV = "SETJOIN_E6_SESSION_COOKIE";

/** Harness-only seams: the member credentials the session watchdog uses to
 *  re-mint the session AFTER the first load when the gateway revokes it
 *  (reset-pair deletes sessions between pairs; access tokens expire on a 1 h
 *  TTL against a 2.5-3.5 h run). Both must be present together; both come
 *  from the fixture env of the disposable e6.test members only. */
export const CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV = "SETJOIN_E6_MEMBER_EMAIL";
export const CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV = "SETJOIN_E6_MEMBER_PASSWORD";

/** The HttpOnly session cookie the authserver sets on `POST /auth/login` and
 *  the SPA rides for its online session (`credentials: 'include'`); the
 *  gateway's auth chain accepts it. Same name the meet transport reads in
 *  `main.ts`. */
export const E6_WEBMAIL_SESSION_COOKIE_NAME = "access_token";

/** The SPA's authenticated app-shell element (the root layout renders
 *  `<div class="sj-shell">` ONLY when the auth probe resolved
 *  authenticated). Presence of this marker is the readiness proof that the
 *  window actually rendered the logged-in webmail — not a white page, not
 *  the login form. */
export const APP_SHELL_RENDER_MARKER = ".sj-shell";

/** The login-page container (`<main class="sj-unauthenticated-content">`).
 *  Its presence during the readiness probe is the named white-screen-class
 *  failure: the SPA rendered, but WITHOUT the member session. */
export const LOGIN_PAGE_MARKER = ".sj-unauthenticated-content";

/** The protected route the window loads: a public route (`/`) never starts
 *  the SPA's auth probe and would render the login form even with a valid
 *  session cookie; `/inbox` starts the probe and renders the shell for a
 *  signed-in member. */
export const E6_APP_ENTRY_PATH = "/inbox";

export interface E6SessionCookie {
	name: string;
	value: string;
}

/**
 * Validate a harness app-origin value into an ADMITTABLE origin: an absolute
 * `http:` URL on a loopback host (127.0.0.1 / localhost / *.localhost — the
 * same loopback family `parseTrustedServerOrigin` admits for cleartext, and
 * the shape the fixture's `E6_TARGET_URL` always has), no userinfo, no path/
 * query/hash. Returns the normalized origin, or null for unset/empty; THROWS
 * a named refusal for a set-but-invalid value — a harness pair member that
 * boots against the wrong origin would invalidate the run, so this fails
 * closed at composition time.
 */
export function resolveE6HarnessAppOrigin(raw: unknown): string | null {
	if (raw === undefined || raw === "") return null;
	if (typeof raw !== "string") {
		throw new Error(`${CONNECTIVITY_SYNC_APP_ORIGIN_ENV} must be a loopback http origin string`);
	}
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error(
			`${CONNECTIVITY_SYNC_APP_ORIGIN_ENV}=${JSON.stringify(raw)} is not an absolute URL; ` +
				`refusing to compose an instance against an unloadable app origin`,
		);
	}
	const loopbackHttp =
		parsed.protocol === "http:" &&
		parsed.username === "" &&
		parsed.password === "" &&
		parsed.search === "" &&
		parsed.hash === "" &&
		(parsed.pathname === "/" || parsed.pathname === "") &&
		parsed.hostname !== "" &&
		(parsed.hostname === "127.0.0.1" ||
			parsed.hostname === "localhost" ||
			parsed.hostname.endsWith(".localhost"));
	if (!loopbackHttp) {
		throw new Error(
			`${CONNECTIVITY_SYNC_APP_ORIGIN_ENV}=${JSON.stringify(raw)} is not a loopback http origin ` +
				`(http://127.0.0.1|localhost[:port] with no path); refusing to compose an instance ` +
				`against a non-loopback or non-http app origin`,
		);
	}
	return parsed.origin;
}

/**
 * Parse the fixture-captured session cookie in `name=value` shape. The name
 * MUST be the SPA session cookie (anything else is a refusal — the harness
 * never plants arbitrary cookies), the value non-empty and free of control
 * characters (cookie-value safety). Null for unset/empty; THROWS a named
 * refusal otherwise.
 */
export function resolveE6HarnessSessionCookie(raw: unknown): E6SessionCookie | null {
	if (raw === undefined || raw === "") return null;
	if (typeof raw !== "string") {
		throw new Error(`${CONNECTIVITY_SYNC_SESSION_COOKIE_ENV} must be a "name=value" string`);
	}
	const eq = raw.indexOf("=");
	const name = eq < 0 ? "" : raw.slice(0, eq);
	const value = eq < 0 ? "" : raw.slice(eq + 1);
	if (name !== E6_WEBMAIL_SESSION_COOKIE_NAME || value === "") {
		throw new Error(
			`${CONNECTIVITY_SYNC_SESSION_COOKIE_ENV} must be "${E6_WEBMAIL_SESSION_COOKIE_NAME}=<token>" ` +
				`as captured from the fixture login response; got a different or malformed cookie — ` +
				`refusing to bootstrap the window session`,
		);
	}
	// biome-ignore lint/suspicious/noControlCharactersInRegex: deliberate control-char REFUSAL (cookie-value safety), the same genre as main.ts's mirrorSpaceFolder
	if (/[\x00-\x1f\x7f]/.test(value)) {
		throw new Error(
			`${CONNECTIVITY_SYNC_SESSION_COOKIE_ENV} value carries control characters; refusing to plant it`,
		);
	}
	return { name, value };
}

/**
 * Resolve the watchdog credentials. Both envs must be set together (a
 * password without an email — or the reverse — is a composition refusal,
 * never a half-configured watchdog); unset both = no watchdog (the documented
 * posture when only a short-lived window is wanted).
 */
export function resolveE6HarnessMemberCredentials(
	email: unknown,
	password: unknown,
): { email: string; password: string } | null {
	if ((email === undefined || email === "") && (password === undefined || password === "")) {
		return null;
	}
	if (
		typeof email !== "string" ||
		email === "" ||
		typeof password !== "string" ||
		password === ""
	) {
		throw new Error(
			`${CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV} and ${CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV} must be ` +
				`set together (or both unset); refusing a half-configured session watchdog`,
		);
	}
	return { email, password };
}

/** The structured result of one in-page readiness/auth probe. `auth` is the
 *  SESSION state, `rendered` whether the authenticated app shell is on the
 *  page, `email` the /auth/me identity (the member the window is really
 *  signed in as). */
export interface RenderProbe {
	auth: "authenticated" | "anonymous" | "unavailable";
	rendered: boolean;
	loginPage: boolean;
	email: string | null;
}

/**
 * The script executed in the renderer via `webContents.executeJavaScript`:
 * one async pass that fetches the SPA's own `/auth/me` (same-origin, cookie
 * credential) and reads the DOM markers. Kept a STRING (not a function) so it
 * ships verbatim and never closes over main-process state. The companion
 * `parseRenderProbe` validates whatever comes back — a tampered/unexpected
 * renderer answer is treated as unavailable, never as readiness.
 */
export const RENDER_PROBE_SCRIPT = `(async () => {
	try {
		const res = await fetch('/auth/me', { credentials: 'include' });
		const email = res.ok ? await res.json().then((d) => (typeof d?.email === 'string' ? d.email : null)).catch(() => null) : null;
		return {
			auth: res.ok ? 'authenticated' : (res.status === 401 ? 'anonymous' : 'unavailable'),
			rendered: !!document.querySelector('${APP_SHELL_RENDER_MARKER}'),
			loginPage: !!document.querySelector('${LOGIN_PAGE_MARKER}'),
			email,
		};
	} catch {
		return { auth: 'unavailable', rendered: !!document.querySelector('${APP_SHELL_RENDER_MARKER}'), loginPage: !!document.querySelector('${LOGIN_PAGE_MARKER}'), email: null };
	}
})()`;

/** Validate one probe answer; null for anything unexpected. */
export function parseRenderProbe(value: unknown): RenderProbe | null {
	if (value === null || typeof value !== "object") return null;
	const probe = value as Record<string, unknown>;
	if (!["authenticated", "anonymous", "unavailable"].includes(probe.auth as string)) return null;
	if (typeof probe.rendered !== "boolean" || typeof probe.loginPage !== "boolean") return null;
	if (probe.email !== null && typeof probe.email !== "string") return null;
	return {
		auth: probe.auth as RenderProbe["auth"],
		rendered: probe.rendered,
		loginPage: probe.loginPage,
		email: probe.email,
	};
}

/**
 * The readiness decision for one probe answer. Ready ONLY when the session is
 * authenticated AND the shell marker rendered AND the identity is a non-empty
 * email. `loginPage` (SPA rendered but session-less) and exhausted retries
 * fail CLOSED with named reasons — the launcher turns these into its
 * named white/no-render errors.
 */
export function readinessFromProbe(probe: RenderProbe): { ready: boolean; reason: string | null } {
	if (
		probe.auth === "authenticated" &&
		probe.rendered &&
		probe.email !== null &&
		probe.email !== ""
	) {
		return { ready: true, reason: null };
	}
	if (probe.loginPage && !probe.rendered) {
		return { ready: false, reason: "login-page" };
	}
	if (probe.auth === "anonymous") {
		return { ready: false, reason: "session-anonymous" };
	}
	if (probe.auth === "unavailable") {
		return { ready: false, reason: "gateway-unavailable" };
	}
	return { ready: false, reason: "not-rendered" };
}

/** Cookie details Electron's `session.cookies.set` accepts for the loopback
 *  origin. HttpOnly + SameSite=Strict mirror exactly what the authserver
 *  sets; the value is re-planted by the watchdog when the gateway revokes
 *  it, so the container TTL (24 h) deliberately outlives the 1 h token TTL. */
export function electronCookieDetails(
	origin: string,
	cookie: E6SessionCookie,
): {
	url: string;
	name: string;
	value: string;
	httpOnly: boolean;
	secure: false;
	sameSite: "strict";
	expirationDate: number;
} {
	return {
		url: origin,
		name: cookie.name,
		value: cookie.value,
		httpOnly: true,
		secure: false, // the seam is http-loopback-only by construction
		sameSite: "strict",
		expirationDate: Date.now() / 1000 + 24 * 3600,
	};
}
