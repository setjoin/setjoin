import { describe, it, expect, vi, type Mock } from "vitest";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

// C6 (2026-07-11 codebase review): main.ts re-registered every IPC handler on
// every createWindow() call. macOS re-runs createWindow() from the 'activate'
// handler whenever the app is reactivated with zero windows open (a normal mac
// flow: window-all-closed does not quit on darwin). ipc.ts's real
// registerHandler throws on a duplicate channel — so a second activation used
// to crash the reactivation path. This test drives that exact flow against the
// real (unmocked) ipc.ts and asserts it no longer throws.
//
// Everything electron-touching is mocked (electron itself, the native binding,
// every handler-factory module, session lockdown, and the Drive mirror
// service) so the composition root in main.ts can run outside a real Electron
// process; ipc.ts is deliberately left real since it is what the bug lives in.

const appListeners: Record<string, Array<(...args: unknown[]) => void>> = {};
const mamOwner = vi.hoisted(() => ({
  start: vi.fn(),
  pause: vi.fn(),
  resume: vi.fn(),
  stop: vi.fn(),
}));
// Astra desktop-drive-bridge-unconfined r2 item 1: the composition root calls
// the trusted-policy seam on the REAL binding surface — the mock carries the
// (now required) driveSetConfinement member so the wiring can be asserted.
const nativeBindingMock = vi.hoisted(() => ({
  driveSetConfinement: vi.fn(),
}));

vi.mock("electron", () => {
  class BrowserWindowMock {
    webContents = {};
    loadFile = vi.fn();
    loadURL = vi.fn();
    static getAllWindows = vi.fn(() => [] as unknown[]);
  }
  return {
    app: {
      isPackaged: false,
      whenReady: () => Promise.resolve(),
      on: vi.fn((event: string, cb: (...args: unknown[]) => void) => {
        (appListeners[event] ??= []).push(cb);
      }),
      getPath: () => "/tmp/setjoin-electron-test",
      getLocale: () => "en",
      quit: vi.fn(),
    },
    BrowserWindow: BrowserWindowMock,
    Menu: { buildFromTemplate: () => ({}) },
    Notification: class {
      show(): void {}
    },
    Tray: class {
      setToolTip(): void {}
      setContextMenu(): void {}
    },
    dialog: {
      showOpenDialog: vi.fn(async () => ({ canceled: true, filePaths: [] })),
    },
    nativeImage: { createEmpty: () => ({}) },
    session: {
      defaultSession: {
        clearStorageData: vi.fn(async () => {}),
        clearCache: vi.fn(async () => {}),
      },
    },
    shell: { openPath: vi.fn(), openExternal: vi.fn(async () => {}) },
    ipcMain: { handle: vi.fn() },
  };
});

vi.mock("./native", () => ({ loadNativeBinding: () => nativeBindingMock }));
vi.mock("./handlers/vault", () => ({
  makeVaultHandlers: () => ({ "vault:unlock": () => {} }),
}));
vi.mock("./handlers/securestore", () => ({
  makeSecureStoreHandlers: () => ({ "secure-store:get": () => {} }),
}));
vi.mock("./handlers/db", () => ({
  makeDbHandlers: () => ({ "db:open": () => {} }),
}));
vi.mock("./handlers/drive", () => ({
  makeDriveHandlers: () => ({ "drive:import": () => {} }),
}));
vi.mock("./handlers/recoveryBlob", () => ({
  makeRecoveryBlobHandlers: () => ({ "recovery-blob:begin": () => {} }),
}));
vi.mock("./handlers/os", () => ({
  makeOsHandlers: () => ({ "os:notify": () => {} }),
}));
vi.mock("./mam", () => ({
  makeMamHandlers: () => ({ "mam:checkin": () => {} }),
}));
vi.mock("./mamLifecycleOwner", () => ({
  DEFAULT_MAM_ROLLOUT_MODE: "off",
  MamLifecycleOwner: class {
    start = mamOwner.start;
    pause = mamOwner.pause;
    resume = mamOwner.resume;
    stop = mamOwner.stop;
  },
}));
vi.mock("./security/session-lockdown", () => ({
  applySessionLockdown: () => {},
}));
vi.mock("./drive/service", () => ({
  MirrorService: class {
    isRunning(): boolean {
      return false;
    }
    stop(): Promise<void> {
      return Promise.resolve();
    }
    setPaused(): void {}
  },
  TRAY_STRINGS: {
    en: {
      paused: "",
      error: "",
      syncing: "",
      idle: "",
      open: "",
      resume: "",
      pause: "",
      quit: "",
    },
  },
  makeDriveMirrorHandlers: () => ({ "drive-mirror:status": () => {} }),
  normalizeLocale: () => "en",
}));

/** Flush the microtask queue so `app.whenReady().then(...)` has run. */
async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("main.ts IPC registration on macOS reactivation (C6)", () => {
  it("registers handlers once and does not throw when activate re-fires with zero windows", async () => {
    vi.resetModules();
    for (const key of Object.keys(appListeners)) delete appListeners[key];

    await import("./main");
    await flushMicrotasks();

    const { app, BrowserWindow } = await import("electron");
    const activateCb = (appListeners.activate ?? [])[0];
    expect(activateCb).toBeTypeOf("function");
    expect(app.on).toHaveBeenCalled();

    // Simulate the real macOS flow: user closes every window, then clicks
    // the dock icon — activate fires with getAllWindows() === [].
    (BrowserWindow.getAllWindows as unknown as Mock).mockReturnValue([]);

    // Pre-fix this threw "duplicate IPC channel registration: vault:unlock"
    // on the very first reactivation; assert it survives two.
    expect(() => activateCb()).not.toThrow();
    expect(() => activateCb()).not.toThrow();
    expect(mamOwner.start).toHaveBeenCalledTimes(1);

    (appListeners["browser-window-blur"] ?? [])[0]?.();
    (appListeners["browser-window-focus"] ?? [])[0]?.();
    expect(mamOwner.pause).toHaveBeenCalledTimes(1);
    expect(mamOwner.resume).toHaveBeenCalledTimes(1);

    (appListeners["before-quit"] ?? [])[0]?.();
    expect(mamOwner.stop).toHaveBeenCalledTimes(1);
  });
});

// Astra desktop-drive-bridge-unconfined r2 item 1: production composition of
// the drive confinement binding. The r1 wiring called the seam through an
// optional projection (`confinementCapable.driveSetConfinement?.(...)`),
// which can never supply a missing native export — a packaged app would run
// every chunk transfer against the native fail-closed floor. Both tests below
// pin the REQUIRED wiring: the call is direct on the binding, and the real
// composition root actually invokes it at mirror construction.
describe("main.ts drive confinement composition (Astra r2 item 1)", () => {
  it("installs the trusted policy natively through the required driveSetConfinement seam", async () => {
    vi.resetModules();
    for (const key of Object.keys(appListeners)) delete appListeners[key];
    nativeBindingMock.driveSetConfinement.mockClear();

    await import("./main");
    await flushMicrotasks();

    // Mirror construction widens the shell policy and forwards it to the
    // offline-core floor natively (import roots only — the server origin is
    // admitted later, post-validation, via drive_mirror_configure).
    expect(nativeBindingMock.driveSetConfinement).toHaveBeenCalledTimes(1);
    expect(nativeBindingMock.driveSetConfinement).toHaveBeenCalledWith(
      ["/tmp/setjoin-electron-test/setjoin Drive"],
      [],
    );
  });

  it("wires the seam non-optionally (no `?.` projection on the required member)", () => {
    const source = fs.readFileSync(
      fileURLToPath(new URL("./main.ts", import.meta.url)),
      "utf8",
    );
    expect(source).toMatch(/native\.driveSetConfinement\(/);
    expect(source).not.toMatch(/driveSetConfinement\s*\?\./);
    expect(source).not.toContain("confinementCapable");
  });
});
