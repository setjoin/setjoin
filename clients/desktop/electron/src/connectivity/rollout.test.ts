import { describe, expect, expectTypeOf, it } from "vitest";

import {
	CONNECTIVITY_AWARE_SYNC_FLAG,
	CONNECTIVITY_SYNC_MODE_ENV,
	CONNECTIVITY_SYNC_ROLLOUT_MODES,
	CONNECTIVITY_SYNC_USER_DATA_ENV,
	DEFAULT_CONNECTIVITY_SYNC_ROLLOUT_MODE,
	connectivityBridgeModeFor,
	isConnectivitySyncRolloutMode,
	resolveConnectivitySyncRolloutMode,
	statusAdmitted,
} from "./rollout";

describe("connectivity rollout discipline", () => {
	it("pins the server-side flag name exactly", () => {
		expect(CONNECTIVITY_AWARE_SYNC_FLAG).toBe("feature.connectivity_aware_sync");
	});

	it("keeps the shipped production default OFF", () => {
		expect(DEFAULT_CONNECTIVITY_SYNC_ROLLOUT_MODE).toBe("off");
	});

	it("carries the MAM-contract off|observe|execute vocabulary", () => {
		expect([...CONNECTIVITY_SYNC_ROLLOUT_MODES]).toEqual(["off", "observe", "execute"]);
		expectTypeOf(DEFAULT_CONNECTIVITY_SYNC_ROLLOUT_MODE).toMatchTypeOf<
			(typeof CONNECTIVITY_SYNC_ROLLOUT_MODES)[number]
		>();
	});

	it("names the harness-only seams once", () => {
		expect(CONNECTIVITY_SYNC_MODE_ENV).toBe("SETJOIN_E6_CONNECTIVITY_SYNC_MODE");
		expect(CONNECTIVITY_SYNC_USER_DATA_ENV).toBe("SETJOIN_E6_USER_DATA_DIR");
	});

	it.each(["off", "observe", "execute"] as const)("admits %s as a mode", (mode) => {
		expect(isConnectivitySyncRolloutMode(mode)).toBe(true);
	});

	it.each([undefined, null, "", "OFF", "Execute", "enabled", "on", 1])(
		"refuses %p as a mode",
		(value) => {
			expect(isConnectivitySyncRolloutMode(value)).toBe(false);
		},
	);

	it("falls back to the shipped default when the seam is unset", () => {
		expect(resolveConnectivitySyncRolloutMode(undefined)).toBe("off");
		expect(resolveConnectivitySyncRolloutMode("")).toBe("off");
	});

	it.each(["off", "observe", "execute"] as const)("resolves %s verbatim", (mode) => {
		expect(resolveConnectivitySyncRolloutMode(mode)).toBe(mode);
	});

	it("refuses a set-but-invalid mode instead of silently degrading", () => {
		expect(() => resolveConnectivitySyncRolloutMode("on")).toThrow(
			/SETJOIN_E6_CONNECTIVITY_SYNC_MODE.*not a rollout mode/,
		);
	});

	it("gates the read-only status surface strictly above off", () => {
		expect(statusAdmitted("off")).toBe(false);
		expect(statusAdmitted("observe")).toBe(true);
		expect(statusAdmitted("execute")).toBe(true);
	});
});

describe("connectivity bridge seam (the harness mode reaching the webmail)", () => {
	it("exposes NOTHING under the shipped default (the production bridge gains no field)", () => {
		expect(connectivityBridgeModeFor({})).toBeNull();
		expect(connectivityBridgeModeFor({ [CONNECTIVITY_SYNC_MODE_ENV]: "" })).toBeNull();
		expect(connectivityBridgeModeFor({ [CONNECTIVITY_SYNC_MODE_ENV]: "off" })).toBeNull();
	});

	it("carries the harness mode for the observe and execute pair members", () => {
		expect(connectivityBridgeModeFor({ [CONNECTIVITY_SYNC_MODE_ENV]: "execute" })).toEqual({
			rolloutMode: "execute",
		});
		expect(connectivityBridgeModeFor({ [CONNECTIVITY_SYNC_MODE_ENV]: "observe" })).toEqual({
			rolloutMode: "observe",
		});
	});

	it("refuses a set-but-invalid mode (never a silent fallback)", () => {
		expect(() => connectivityBridgeModeFor({ [CONNECTIVITY_SYNC_MODE_ENV]: "on" })).toThrow(
			/is not a rollout mode/,
		);
	});
});
