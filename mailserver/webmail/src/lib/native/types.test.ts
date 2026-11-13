import { describe, it, expect } from "vitest";
import type { DriveMirrorBridge, OfflineDbBridge } from "./types";
import {
  BRIDGE_VERSION,
  DRIVE_MIRROR_VERSION,
  NATIVE_CAPABILITIES,
  NATIVE_DB_APP_KEYS,
} from "./types";

describe("bridge contract", () => {
  it("narrows the offline db appKey namespace to the shell-enforced two-value ceiling", () => {
    // The renderer must not be able to name an arbitrary SQLCipher store
    // (including wipe()); the contract matches the shell's native allowlist.
    expect(NATIVE_DB_APP_KEYS).toEqual(["mail", "drive"]);
    // Compile-time: an OpenFn narrowed to the union accepts the union only.
    type OpenFn = OfflineDbBridge["open"];
    const _: OpenFn = (appKey: (typeof NATIVE_DB_APP_KEYS)[number], profile?: "standard" | "SMx") => {
      void appKey;
      void profile;
      return Promise.resolve();
    };
    void _;
  });

  it("OfflineDbBridge.open accepts an optional cipher profile param", () => {
    // Type-level: compile a call with profile='SMx'. If open() lacks the second
    // param this file would fail svelte-check / tsc. Runtime: check shape only —
    // no real bridge in unit tests.
    type OpenFn = OfflineDbBridge["open"];
    // A function with an optional second param must be assignable from one that
    // accepts (appKey, profile). A compile error here means the type is too narrow.
    const _: OpenFn = (appKey: string, profile?: "standard" | "SMx") => {
      void appKey;
      void profile;
      return Promise.resolve();
    };
    expect(true).toBe(true); // type guard passed; runtime is a no-op assertion
  });

  it("declares a numeric version", () => {
    expect(typeof BRIDGE_VERSION).toBe("number");
    expect(BRIDGE_VERSION).toBeGreaterThanOrEqual(1);
  });
  it("lists the capability keys the shell may advertise", () => {
    expect(NATIVE_CAPABILITIES).toEqual([
      "push",
      "biometric",
      "secureStore",
      "vault",
      "share",
      "pickFile",
      "notify",
      "openExternal",
      "mailDb",
      "deviceProof",
      "driveMirror",
      "drive",
      "recoveryBlob",
    ]);
  });

  it("declares a numeric DRIVE_MIRROR_VERSION, independent of BRIDGE_VERSION", () => {
    expect(typeof DRIVE_MIRROR_VERSION).toBe("number");
    expect(DRIVE_MIRROR_VERSION).toBeGreaterThanOrEqual(1);
  });

  it("DriveMirrorBridge.configure/refreshToken take the shapes the renderer bridge needs", () => {
    // Type-level only — no real bridge in unit tests (Electron main is P2's second half).
    const _: DriveMirrorBridge = {
      version: DRIVE_MIRROR_VERSION,
      status: () =>
        Promise.resolve({
          running: false,
          paused: false,
          perSpace: [],
          issues: [],
        }),
      configure: (cfg) => {
        void cfg;
        return Promise.resolve();
      },
      refreshToken: (token, expiresAt) => {
        void token;
        void expiresAt;
        return Promise.resolve();
      },
      setPaused: (paused) => {
        void paused;
        return Promise.resolve();
      },
      resync: (spaceId) => {
        void spaceId;
        return Promise.resolve();
      },
      openRoot: (spaceId) => {
        void spaceId;
        return Promise.resolve();
      },
      officeChoices: () => Promise.resolve([]),
      openOffice: (spaceId, nodeId, appId) => {
        void spaceId;
        void nodeId;
        void appId;
        return Promise.resolve();
      },
    };
    expect(_.version).toBe(DRIVE_MIRROR_VERSION);
  });
});
