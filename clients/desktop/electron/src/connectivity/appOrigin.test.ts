import { describe, expect, it } from "vitest";

import {
	APP_SHELL_RENDER_MARKER,
	CONNECTIVITY_SYNC_APP_ORIGIN_ENV,
	CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV,
	CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV,
	CONNECTIVITY_SYNC_SESSION_COOKIE_ENV,
	E6_APP_ENTRY_PATH,
	E6_WEBMAIL_SESSION_COOKIE_NAME,
	LOGIN_PAGE_MARKER,
	RENDER_PROBE_SCRIPT,
	electronCookieDetails,
	parseRenderProbe,
	readinessFromProbe,
	resolveE6HarnessAppOrigin,
	resolveE6HarnessMemberCredentials,
	resolveE6HarnessSessionCookie,
} from "./appOrigin";

describe("E6 harness env seam names", () => {
	it("names the harness-only seams once, in the SETJOIN_E6_* family", () => {
		expect(CONNECTIVITY_SYNC_APP_ORIGIN_ENV).toBe("SETJOIN_E6_APP_ORIGIN");
		expect(CONNECTIVITY_SYNC_SESSION_COOKIE_ENV).toBe("SETJOIN_E6_SESSION_COOKIE");
		expect(CONNECTIVITY_SYNC_MEMBER_EMAIL_ENV).toBe("SETJOIN_E6_MEMBER_EMAIL");
		expect(CONNECTIVITY_SYNC_MEMBER_PASSWORD_ENV).toBe("SETJOIN_E6_MEMBER_PASSWORD");
	});

	it("pins the webmail session contract constants", () => {
		// The authserver's Set-Cookie name (auth.go setAccessCookie) and the
		// same name main.ts's meet transport reads.
		expect(E6_WEBMAIL_SESSION_COOKIE_NAME).toBe("access_token");
		// The root layout's authenticated shell marker + login-page container.
		expect(APP_SHELL_RENDER_MARKER).toBe(".sj-shell");
		expect(LOGIN_PAGE_MARKER).toBe(".sj-unauthenticated-content");
		// A protected route (public routes never start the SPA's auth probe).
		expect(E6_APP_ENTRY_PATH).toBe("/inbox");
	});
});

describe("resolveE6HarnessAppOrigin", () => {
	it("is null when the seam is unset or empty (inert in production)", () => {
		expect(resolveE6HarnessAppOrigin(undefined)).toBeNull();
		expect(resolveE6HarnessAppOrigin("")).toBeNull();
	});

	it.each([
		"http://127.0.0.1:34567",
		"http://localhost:8080",
		"http://gateway.localhost:9999",
		"http://127.0.0.1",
	])("admits the loopback http origin %s", (origin) => {
		expect(resolveE6HarnessAppOrigin(origin)).toBe(new URL(origin).origin);
	});

	it.each([
		"https://127.0.0.1:34567", // the harness gateway is loopback cleartext only
		"http://10.0.0.1:34567", // non-loopback
		"http://gateway.e6.example/", // non-loopback hostname
		"http://127.0.0.1:34567/inbox", // path
		"http://127.0.0.1:34567/?x=1", // query
		"http://user:pass@127.0.0.1:34567", // userinfo
		"ftp://127.0.0.1:34567", // scheme
		"127.0.0.1:34567", // not an absolute URL (parsed as a relative-ish scheme)
		"not a url",
		"http://[::1]:34567", // the launcher's validator refuses bracketed IPv6 too
	])("refuses %p instead of silently degrading", (value) => {
		expect(() => resolveE6HarnessAppOrigin(value)).toThrow(/SETJOIN_E6_APP_ORIGIN/);
	});
});

describe("resolveE6HarnessSessionCookie", () => {
	it("is null when the seam is unset or empty", () => {
		expect(resolveE6HarnessSessionCookie(undefined)).toBeNull();
		expect(resolveE6HarnessSessionCookie("")).toBeNull();
	});

	it("parses the fixture's name=value Set-Cookie shape", () => {
		expect(resolveE6HarnessSessionCookie("access_token=jwt.value.here")).toEqual({
			name: "access_token",
			value: "jwt.value.here",
		});
	});

	it("refuses any cookie other than the SPA session cookie", () => {
		expect(() => resolveE6HarnessSessionCookie("sid=abc")).toThrow(/access_token=/);
		expect(() => resolveE6HarnessSessionCookie("not-a-cookie")).toThrow(/access_token=/);
		expect(() => resolveE6HarnessSessionCookie("access_token=")).toThrow(/access_token=/);
	});

	it("refuses control characters in the cookie value", () => {
		expect(() => resolveE6HarnessSessionCookie("access_token=abc\r\nSet-Cookie: evil=1")).toThrow(
			/control characters/,
		);
	});
});

describe("resolveE6HarnessMemberCredentials", () => {
	it("is null when both seams are unset (no watchdog)", () => {
		expect(resolveE6HarnessMemberCredentials(undefined, undefined)).toBeNull();
		expect(resolveE6HarnessMemberCredentials("", "")).toBeNull();
	});

	it("resolves both together", () => {
		expect(resolveE6HarnessMemberCredentials("e6-b@e6.test", "pw")).toEqual({
			email: "e6-b@e6.test",
			password: "pw",
		});
	});

	it("refuses a half-configured watchdog", () => {
		expect(() => resolveE6HarnessMemberCredentials("e6-b@e6.test", undefined)).toThrow(
			/set together/,
		);
		expect(() => resolveE6HarnessMemberCredentials(undefined, "pw")).toThrow(/set together/);
	});
});

describe("the in-page render/auth probe", () => {
	it("embeds the DOM markers and the cookie-credential /auth/me fetch", () => {
		expect(RENDER_PROBE_SCRIPT).toContain("fetch('/auth/me', { credentials: 'include' })");
		expect(RENDER_PROBE_SCRIPT).toContain(APP_SHELL_RENDER_MARKER);
		expect(RENDER_PROBE_SCRIPT).toContain(LOGIN_PAGE_MARKER);
	});

	it("parses a well-formed probe answer", () => {
		expect(
			parseRenderProbe({
				auth: "authenticated",
				rendered: true,
				loginPage: false,
				email: "e6-b@e6.test",
			}),
		).toEqual({ auth: "authenticated", rendered: true, loginPage: false, email: "e6-b@e6.test" });
	});

	it.each([
		null,
		undefined,
		42,
		{},
		{ auth: "root", rendered: true, loginPage: false, email: null },
		{ auth: "authenticated", rendered: "yes", loginPage: false, email: null },
		{ auth: "authenticated", rendered: true, loginPage: 0, email: null },
		{ auth: "authenticated", rendered: true, loginPage: false, email: 17 },
	])("treats a foreign renderer answer (%p) as unparsable", (value) => {
		expect(parseRenderProbe(value)).toBeNull();
	});

	it("readiness requires authenticated + rendered + identity", () => {
		expect(
			readinessFromProbe({
				auth: "authenticated",
				rendered: true,
				loginPage: false,
				email: "e6-b@e6.test",
			}),
		).toEqual({ ready: true, reason: null });
		expect(
			readinessFromProbe({
				auth: "authenticated",
				rendered: false,
				loginPage: false,
				email: "e6-b@e6.test",
			}),
		).toEqual({ ready: false, reason: "not-rendered" });
		expect(
			readinessFromProbe({ auth: "authenticated", rendered: true, loginPage: false, email: null }),
		).toEqual({ ready: false, reason: "not-rendered" });
	});

	it("names the session-less login page and anonymous classes fail-closed", () => {
		expect(
			readinessFromProbe({ auth: "anonymous", rendered: false, loginPage: true, email: null }),
		).toEqual({ ready: false, reason: "login-page" });
		expect(
			readinessFromProbe({ auth: "anonymous", rendered: false, loginPage: false, email: null }),
		).toEqual({ ready: false, reason: "session-anonymous" });
		expect(
			readinessFromProbe({ auth: "unavailable", rendered: false, loginPage: false, email: null }),
		).toEqual({ ready: false, reason: "gateway-unavailable" });
	});
});

describe("electronCookieDetails", () => {
	it("mirrors the authserver's HttpOnly SameSite=Strict cookie over loopback http", () => {
		const details = electronCookieDetails("http://127.0.0.1:34567", {
			name: "access_token",
			value: "jwt",
		});
		expect(details).toMatchObject({
			url: "http://127.0.0.1:34567",
			name: "access_token",
			value: "jwt",
			httpOnly: true,
			secure: false,
			sameSite: "strict",
		});
		// The container TTL deliberately outlives the 1 h token TTL — the
		// watchdog refreshes the VALUE, the cookie must not vanish under it.
		expect(details.expirationDate).toBeGreaterThan(Date.now() / 1000 + 12 * 3600);
	});
});
