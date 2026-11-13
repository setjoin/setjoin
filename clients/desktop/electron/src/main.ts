//! Electron main process — composition root. Creates the hardened BrowserWindow,
//! loads the webmail SPA, loads the native binding, wires every IPC handler
//! through the single origin-gated `registerHandler` wrapper, and applies session
//! lockdown. Mostly not unit-tested (it is the wiring); the pieces it composes
//! are. The one exception is `main.test.ts`, which pins the macOS-reactivation
//! IPC-registration-once invariant (C6, 2026-07-11 codebase review) since that
//! bug lived in the wiring itself, not in any composed piece.

import {
	app,
	BrowserWindow,
	Menu,
	Notification,
	Tray,
	dialog,
	nativeImage,
	session,
	shell,
} from "electron";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import type { DriveMirrorStatus } from "../../../../mailserver/webmail/src/lib/native/types.js";
import { SqlMirrorIndex } from "../../../../mailserver/webmail/src/lib/drive/sync/schema.js";
import { configureAllowedOrigins, registerHandlers } from "./ipc";
import { loadNativeBinding } from "./native";
import type { NativeBinding } from "./native";
import { makeVaultHandlers } from "./handlers/vault";
import { makeSecureStoreHandlers } from "./handlers/securestore";
import { appKeyDbFile, makeDbHandlers } from "./handlers/db";
import type { HandlerMap } from "./handlers/db";
import { makeDriveHandlers } from "./handlers/drive";
import type { DriveConfinement, DriveTokenOwner } from "./handlers/drive";
import { makeRecoveryBlobHandlers } from "./handlers/recoveryBlob";
import { makeOsHandlers } from "./handlers/os";
import { makeMamHandlers } from "./mam";
import { DEFAULT_MAM_ROLLOUT_MODE, MamLifecycleOwner } from "./mamLifecycleOwner";
import { applySessionLockdown } from "./security/session-lockdown";
import {
	MirrorService,
	TRAY_STRINGS,
	makeDriveMirrorHandlers,
	normalizeLocale,
	type TrayLocale,
} from "./drive/service";
import { createLocalOfficeLauncher } from "./office/local";
import { DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE } from "./meet/rollout";
import { makeFetchMeetTransport, makeMeetLocalCaptureHandlers } from "./meet/localCapture";
import { CONNECTIVITY_SYNC_USER_DATA_ENV } from "./connectivity/rollout";
import {
	CONNECTIVITY_SYNC_APP_ORIGIN_ENV,
	CONNECTIVITY_SYNC_SESSION_COOKIE_ENV,
	E6_APP_ENTRY_PATH,
	type E6SessionCookie,
	electronCookieDetails,
	resolveE6HarnessAppOrigin,
	resolveE6HarnessSessionCookie,
} from "./connectivity/appOrigin";
import {
	composeConnectivityE6HarnessSurface,
	QUEUE_STATE_PROBE_SCRIPT,
} from "./connectivity/saturation";

// ── Connectivity E6 harness-only seam (module scope: must land before the
// first userData read). Unset in every production launch, so production keeps
// the default user-data dir; the E6 pair launcher sets it per instance so two
// members of ONE build can run side by side without colliding on stores. ──
if (process.env[CONNECTIVITY_SYNC_USER_DATA_ENV]) {
	app.setPath("userData", process.env[CONNECTIVITY_SYNC_USER_DATA_ENV] as string);
}

// ── Connectivity E6 harness-only app-origin seam (module scope, the same
// refuse-early genre as the userData seam above). Unset in every production
// launch → the window keeps loading the bundled webmail build. Under the E6
// pair launcher it names the GATEWAY-SERVED webmail origin, and the window
// loads THAT (loadURL through the same appOrigins allowlist + session
// lockdown below) with the fixture-captured member session cookie planted
// before the first navigation — the 2026-09-21 white-screen fix: the bundled
// build with a fresh user-data dir and no server rendered nothing, and the
// E4-I coordinator under measurement lives in the gateway-served webmail
// behind a logged-in session. A set-but-invalid value REFUSES startup. ──
const e6HarnessAppOrigin = resolveE6HarnessAppOrigin(process.env[CONNECTIVITY_SYNC_APP_ORIGIN_ENV]);

// ── Drive P2 tray (module-scope: shared across window-all-closed/before-quit,
// and rebuilt in place rather than per-window since sync keeps running with
// every window closed — arch D5/D6) ─────────────────────────────────────────
let mirrorService: MirrorService | undefined;
let tray: Tray | undefined;
let trayLocale: TrayLocale = "en";
let mirrorBaseDir = "";

// ── Drive P3 trusted wiring (deep-scan package desktop-drive-bridge-──────────
// unconfined, Astra items 3/4 + r2 items 1/4: "Preserve the empty fail-closed
// fallback, but complete the trusted wiring"). The composition root owns:
//   - the byte-plane CONFINEMENT (trusted mirror membership + configured
//     server origin), consulted per IPC call via the provider below — the
//     server origin is ADMITTED only after the underlying drive_mirror_configure
//     handler accepted the configuration AND the endpoint passed trusted
//     validation (r2 item 4): renderer input never widens the policy directly;
//   - the chunk-transfer BEARER (token-owner pattern, C3/C14/C15): the token
//     the renderer mints arrives via drive_mirror_refresh_token and is kept
//     alive by MirrorService's native-token renewals, teed through the
//     MirrorService fetchFn below. The bearer's LIFETIME is bound to the
//     admitted origin (r2 item 4): the owner only vouches for a token minted
//     for the currently-admitted origin, so a re-configuration never sends the
//     previous origin's bearer to the new one. Renderer-supplied bearers are
//     ignored by the handlers; with no matching owner token they fail closed.
let driveTokenValue: string | null = null;
/** The origin `driveTokenValue` was minted for — empty when no bound token is
 * held. getBearer() vouches only for a same-origin pair (fail-closed). */
let driveTokenOrigin = "";
let driveServerOrigin = "";
let driveConfinement: DriveConfinement = { importRoots: [], approvedOrigins: [] };
let driveIndex: SqlMirrorIndex | null = null;

const driveTokenOwner: DriveTokenOwner = {
	getBearer: async () =>
		driveTokenValue !== null && driveTokenOrigin !== "" && driveTokenOrigin === driveServerOrigin
			? driveTokenValue
			: null,
};

/** Mirror space-folder name — mirrors drive/service.ts's private
 * sanitizeFolderName (out of this delta's write scope; do not diverge). */
function mirrorSpaceFolder(name: string): string {
	// Stripping control characters out of on-disk folder names is the point
	// (same regex as service.ts, where the rule is disabled config-side).
	// biome-ignore lint/suspicious/noControlCharactersInRegex: deliberate control-char stripping
	const cleaned = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").trim();
	return cleaned || "space";
}

/** Lazily open the same drive metadata store MirrorService uses and wrap it
 * in the shared mirror index (dc_*), so the membership checker consults the
 * authoritative disk index. Locked/failed opens deny (fail-closed). */
function driveMetadataIndex(native: NativeBinding, userDataDir: string): SqlMirrorIndex | null {
	if (driveIndex) return driveIndex;
	try {
		native.dbOpen(path.join(userDataDir, appKeyDbFile("drive")), "drive", "standard");
		// Mirrors service.ts's nativeDbLike glue (private there; one tiny adapter).
		driveIndex = new SqlMirrorIndex({
			exec: async (sql, params = []) => native.dbExec("drive", sql, JSON.stringify(params)),
			query: async (sql, params = []) =>
				JSON.parse(native.dbQuery("drive", sql, JSON.stringify(params))) as never,
		});
		return driveIndex;
	} catch {
		return null; // vault locked or store unavailable → nothing is registered
	}
}

/** Trusted mirror-INDEX membership (Astra item 1): true only when the file
 * resolves inside some actively-mirrored space's root at a registered
 * dc_mirror rel_path. Realpath on both sides keeps legal ancestor symlinks
 * working and rejects escapes; any store/index/status failure denies. */
async function isTrustedMirrorFile(
	native: NativeBinding,
	userDataDir: string,
	srcPath: string,
): Promise<boolean> {
	let real: string;
	try {
		real = fs.realpathSync(srcPath);
	} catch {
		return false;
	}
	const index = driveMetadataIndex(native, userDataDir);
	if (!index || !mirrorService) return false;
	let perSpace: DriveMirrorStatus["perSpace"];
	try {
		perSpace = (await mirrorService.status()).perSpace;
	} catch {
		return false;
	}
	for (const space of perSpace) {
		// Only spaces the mirror actively serves can vouch for a file.
		if (
			space.state === "vault-locked" ||
			space.state === "auth-expired" ||
			space.state === "policy-blocked"
		) {
			continue;
		}
		const root = path.join(mirrorBaseDir, mirrorSpaceFolder(space.name));
		let rootReal: string;
		try {
			rootReal = fs.realpathSync(root);
		} catch {
			continue; // space not on disk (yet) → approves nothing
		}
		const rel = path.relative(rootReal, real);
		if (rel === "" || rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
			continue;
		}
		try {
			if (await index.findByPathCI(space.spaceId, rel.split(path.sep).join("/"))) {
				return true;
			}
		} catch {
			return false; // store vanished mid-check → deny
		}
	}
	return false;
}

/** Install the current trusted confinement on the byte-plane handlers. Called
 * at mirror construction and again whenever a server origin is admitted
 * (drive_mirror_configure, post-validation). */
function widenDriveConfinement(native: NativeBinding, userDataDir: string): void {
	driveConfinement = {
		importRoots: mirrorBaseDir ? [mirrorBaseDir] : [],
		approvedOrigins: driveServerOrigin ? [driveServerOrigin] : [],
		isTrustedMirrorFile: (srcPath) => isTrustedMirrorFile(native, userDataDir, srcPath),
	};
	// Defense-in-depth forwarding to the offline-core floor (drive.rs): install
	// the same trusted policy natively so both native bindings inherit it.
	// Astra r2 item 1: `driveSetConfinement` is a REQUIRED member of the
	// binding contract (native_impl.rs exports it in both napi twins) — the
	// call is direct, never an optional projection, so a packaged app cannot
	// silently run against the native fail-closed floor while the shell policy
	// looks wide.
	try {
		native.driveSetConfinement(driveConfinement.importRoots.slice(), [
			...driveConfinement.approvedOrigins,
		]);
	} catch (err) {
		console.error("drive: native confinement install failed", err);
	}
}

/** Validate a configured server endpoint into an ADMITTABLE origin (Astra r2
 * item 4). The endpoint is admitted only in origin form: an absolute http(s)
 * URL with no userinfo, no path/query/hash, and — mirroring the native
 * transport floor — cleartext http only for loopback hosts. Returns the
 * normalized origin, or null when the shape is not admissible (the previous
 * admitted origin then stays in force; nothing is widened). */
function parseTrustedServerOrigin(input: unknown): string | null {
	if (typeof input !== "string" || input === "") return null;
	let parsed: URL;
	try {
		parsed = new URL(input);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
	if (parsed.username !== "" || parsed.password !== "") return null;
	if (parsed.pathname !== "/" && parsed.pathname !== "") return null;
	if (parsed.search !== "" || parsed.hash !== "") return null;
	if (parsed.hostname === "") return null;
	if (
		parsed.protocol === "http:" &&
		!["127.0.0.1", "::1", "localhost"].includes(parsed.hostname) &&
		!parsed.hostname.endsWith(".localhost")
	) {
		return null; // cleartext http is loopback-only (the bearer must not leak)
	}
	return parsed.origin;
}

/** Publish a configured server endpoint into the trusted policy — but ONLY
 * after validation (Astra r2 item 4): the renderer never widens the policy
 * directly. Admitting a DIFFERENT origin retires the previous bearer (its
 * lifetime was bound to the old origin); a rejected shape leaves both the
 * policy and the token binding untouched. */
function admitConfiguredDriveOrigin(
	native: NativeBinding,
	userDataDir: string,
	cfg: unknown,
): void {
	const parsed = cfg as { serverOrigin?: unknown } | null;
	const admitted = parseTrustedServerOrigin(parsed?.serverOrigin);
	if (admitted === null) return;
	if (admitted !== driveServerOrigin) {
		// Token lifetime is bound to the admitted origin: do not retain the
		// previous origin's bearer for the new one.
		driveTokenValue = null;
		driveTokenOrigin = "";
		driveServerOrigin = admitted;
		widenDriveConfinement(native, userDataDir);
	}
}

// IPC handlers are process-wide singletons — ipc.ts's registeredChannels set
// throws on re-registration (by design, to catch copy-paste collisions).
// createWindow() re-runs from the 'activate' handler whenever macOS
// reactivates the app with zero windows open, so handler registration must run
// once at init, not per window (C6, 2026-07-11 codebase review). currentWindow
// tracks the live window for handlers (pickFilePath's dialog parent) that need
// "whichever window is open now" — the window live when handlers were first
// registered may since have closed.
let ipcHandlersRegistered = false;
let currentWindow: BrowserWindow | undefined;
let mamLifecycleOwner: MamLifecycleOwner | undefined;
// E6 harness surface is composed once (the ipcHandlersRegistered genre): the
// FIRST window's renderer is the one the ready line reports to the launcher.
let e6SurfaceComposed = false;
// The composed surface's disposer (stops the E6 session watchdog timer) —
// no-op until a harness-managed instance composes the surface.
let disposeE6Surface: () => void = () => {};

function renderTrayMenu(status: DriveMirrorStatus): void {
	if (!tray) return;
	const strings = TRAY_STRINGS[trayLocale];
	const label = status.paused
		? strings.paused
		: status.perSpace.some((s) => s.state === "error")
			? strings.error
			: status.perSpace.some((s) => s.state === "syncing")
				? strings.syncing
				: strings.idle;
	tray.setToolTip(label);
	tray.setContextMenu(
		Menu.buildFromTemplate([
			{ label, enabled: false },
			{ type: "separator" },
			// ponytail: one generic "open" action for the mirror base folder, not
			// per-space — the tray strings table has a single `open` label (spec's
			// table, not this file's invention); per-space folder access lives in
			// the webmail Drive app's SelectiveSyncSheet instead.
			{ label: strings.open, click: () => void shell.openPath(mirrorBaseDir) },
			{
				label: status.paused ? strings.resume : strings.pause,
				click: () => void mirrorService?.setPaused(!status.paused),
			},
			{ type: "separator" },
			{ label: strings.quit, click: () => app.quit() },
		]),
	);
}

/** Absolute path to the built webmail entry (adapter-static output). */
function webmailIndexPath(): string {
	// Packaged: the webmail build is shipped as an electron-builder extraResource
	// at `<resources>/webmail/`. Dev: dist/main.js → up 4 to repo root → webmail.
	if (app.isPackaged) {
		return path.join(process.resourcesPath, "webmail", "index.html");
	}
	return path.resolve(__dirname, "../../../../mailserver/webmail/build/index.html");
}

/** Base dir of the napi native module (packaged: an extraResource; dev: undefined = repo tree). */
function nativeModuleDir(): string | undefined {
	return app.isPackaged ? path.join(process.resourcesPath, "desktop-native") : undefined;
}

function createWindow(): void {
	const devServerUrl = process.env.ELECTRON_DEV_SERVER_URL;
	const indexPath = webmailIndexPath();

	// The exact app-origin allowlist shared by the IPC gate and session
	// lockdown. Precedence: dev server (unchanged dev semantics) → the E6
	// harness gateway origin (the white-screen fix: gateway-served webmail,
	// member session bootstrapped below) → the bundled webmail build.
	const appOrigins = devServerUrl
		? [new URL(devServerUrl).origin]
		: e6HarnessAppOrigin !== null
			? [e6HarnessAppOrigin]
			: [pathToFileURL(indexPath).href];
	configureAllowedOrigins(appOrigins);

	const win = new BrowserWindow({
		width: 1280,
		height: 860,
		webPreferences: {
			contextIsolation: true,
			sandbox: true,
			nodeIntegration: false,
			preload: path.join(__dirname, "preload.js"),
		},
	});
	currentWindow = win;

	// ── Connectivity E6 harness surface (the M5 localCapture genre: see the
	// module header for the honesty posture). Inert unless the instance was
	// launched with the harness user-data seam; under the shipped default
	// rollout mode `off` it starts no server and only the readiness line is
	// printed, and only for harness-managed instances. `setSessionCookie` is
	// the only electron touch the composition needs: the readiness probe and
	// the session watchdog live in the connectivity module, but cookie
	// planting must reach `session.defaultSession`. ──
	if (!e6SurfaceComposed) {
		e6SurfaceComposed = true;
		disposeE6Surface = composeConnectivityE6HarnessSurface(win, {
			setSessionCookie: (origin: string, cookie: E6SessionCookie) =>
				session.defaultSession.cookies.set(electronCookieDetails(origin, cookie)),
			// Real queue-depth truth for the saturation endpoint: read the composed
			// webmail's `__setjoinConnectivityQueueState` through the same window
			// bridge as the render probe (bounded; every failure falls back to the
			// policy-mode declaration — see saturation.ts's honesty posture).
			readEngineQueueState: () => win.webContents.executeJavaScript(QUEUE_STATE_PROBE_SCRIPT),
		});
	}

	// ── Native binding + handlers (all through the origin-gated wrapper) ──
	const native = loadNativeBinding(nativeModuleDir());
	const userDataDir = app.getPath("userData");

	// Register once (see ipcHandlersRegistered doc above) — not on every
	// createWindow() call, since macOS 'activate' can re-run this with zero
	// windows open.
	if (!ipcHandlersRegistered) {
		ipcHandlersRegistered = true;
		registerHandlers(makeVaultHandlers(native, userDataDir));
		registerHandlers(makeSecureStoreHandlers(native));
		registerHandlers(makeDbHandlers(native, userDataDir));
		registerHandlers(makeRecoveryBlobHandlers(native));
		// Trusted wiring (Astra item 3): the confinement provider is consulted per
		// call — production is NOT permanently empty; it widens when the mirror
		// service is constructed below and when drive_mirror_configure arrives.
		// Bearer ownership stays here: the token owner is main's, never the
		// renderer's.
		registerHandlers(makeDriveHandlers(native, () => driveConfinement, driveTokenOwner));
		registerHandlers(
			makeOsHandlers({
				showNotification: (title, body) => new Notification({ title, body }).show(),
				pickFilePath: async () => {
					if (!currentWindow) return null;
					const r = await dialog.showOpenDialog(currentWindow, {
						properties: ["openFile"],
					});
					return r.canceled || r.filePaths.length === 0 ? null : r.filePaths[0];
				},
				openExternalUrl: (url) => shell.openExternal(url),
			}),
		);
		const mamHandlers = makeMamHandlers(native, {
			clearStorage: async () => {
				await session.defaultSession.clearStorageData();
				await session.defaultSession.clearCache();
			},
		});
		registerHandlers(mamHandlers);
		// Connectivity E4's process-wide composition seam. Production remains
		// explicitly OFF; a later trusted rollout narrows onto this same owner.
		mamLifecycleOwner = new MamLifecycleOwner(
			DEFAULT_MAM_ROLLOUT_MODE,
			async () => {
				await mamHandlers.mam_checkin();
			},
			(error) => console.error("mam lifecycle check-in failed", error),
		);
		mamLifecycleOwner.start();
		// MEET M5 slice 2's process-wide composition seam (the MAM genre):
		// makeElectronPreflightDeps + the secure-store consent binding + the
		// main→server wire, composed here and registered through the same
		// origin-gated choke point. The substrate is INERT under the shipped
		// default rollout mode `off` (no probes, no store reads, no transport
		// calls); only a separate trusted rollout to `execute` — through this
		// same owner, never a second wiring — activates the wire, and its
		// transport stays fail-closed until BOTH an admitted server origin and
		// a session credential are provable (the driveServerOrigin pattern:
		// main owns the credential, the renderer only passes frames).
		registerHandlers(
			makeMeetLocalCaptureHandlers({
				native,
				mode: DEFAULT_MEET_LOCAL_RECORDING_ROLLOUT_MODE,
				transport: makeFetchMeetTransport({
					getOrigin: () => driveServerOrigin,
					getAccessToken: async () => {
						const cookies = await session.defaultSession.cookies.get({
							name: "access_token",
						});
						return (
							cookies.find(
								(c) =>
									(driveServerOrigin !== "" && `https://${c.domain}` === driveServerOrigin) ||
									`http://${c.domain}` === driveServerOrigin,
							)?.value ?? null
						);
					},
				}),
			}),
		);
	}

	// ── Drive P2: FolderMirror (constructed once — createWindow can re-run via
	// the 'activate' handler on macOS, but sync must not restart per window) ──
	if (!mirrorService) {
		mirrorBaseDir = path.join(app.getPath("home"), "setjoin Drive");
		trayLocale = normalizeLocale(app.getLocale());
		mirrorService = new MirrorService({
			native,
			userDataDir,
			// Raw, un-authenticated fetch — main has no server-origin cookie
			// (C3/C14/C15: the renderer mints a bearer token via
			// POST /api/drive/native-token and hands it over through
			// driveMirror.refreshToken; MirrorService slides it forward itself).
			// The tee below keeps MAIN as the bearer owner (Astra item 3): every
			// successful native-token renewal updates main's owned token so the
			// chunk-transfer handlers always hold the same live credential as sync.
			// The captured token is bound to the ADMITTED origin (r2 item 4) — the
			// guard already pins the tee to `${driveServerOrigin}/...`, and the
			// recorded origin is what getBearer() vouches against.
			fetchFn: async (input, init) => {
				const res = await fetch(input, init);
				try {
					if (
						driveServerOrigin !== "" &&
						res.ok &&
						input === `${driveServerOrigin}/api/drive/native-token`
					) {
						const body = (await res.clone().json()) as { token?: unknown };
						if (typeof body.token === "string" && body.token) {
							driveTokenValue = body.token;
							driveTokenOrigin = driveServerOrigin;
						}
					}
				} catch {
					// the tee is best-effort — never break the underlying sync request
				}
				return res;
			},
			mirrorBase: mirrorBaseDir,
			deviceLabel: os.hostname(),
			locale: app.getLocale(),
			openPath: (p) => void shell.openPath(p),
			localOffice: createLocalOfficeLauncher(),
			onStateChange: (s) => renderTrayMenu(s),
		});
		// Complete the bounded composition-root integration (Astra item 3 + r2
		// item 4): the handlers gain trusted mirror membership + the ADMITTED
		// server origin, and the mirror bridge is wrapped so MAIN captures the
		// server origin and the renderer-minted bearer — never directly from
		// renderer input: the endpoint is published only AFTER the underlying
		// configure handler accepted the configuration and the origin passed
		// trusted validation, and the bearer's lifetime is bound to the admitted
		// origin.
		widenDriveConfinement(native, userDataDir);
		const mirrorHandlers = makeDriveMirrorHandlers(mirrorService);
		const mirrorHandlersWithOwner: HandlerMap = {
			...mirrorHandlers,
			drive_mirror_configure: async (cfg: unknown) => {
				// Underlying service FIRST: a configure the mirror layer rejects must
				// never widen the policy (sync throws and promise rejections both skip
				// admission); only an accepted configuration is validated + admitted.
				const result = await mirrorHandlers.drive_mirror_configure(cfg);
				admitConfiguredDriveOrigin(native, userDataDir, cfg);
				return result;
			},
			drive_mirror_refresh_token: (token: unknown, expiresAt: unknown) => {
				// Main takes ownership of the bearer the moment it crosses the IPC
				// boundary; the renderer's copy is one hand-off, never the source.
				// The captured token is bound to the CURRENTLY ADMITTED origin (r2
				// item 4): a token handed over before any origin is admitted — or
				// after a re-admission it was not minted for — can never credential a
				// chunk transfer.
				if (typeof token === "string" && token !== "" && driveServerOrigin !== "") {
					driveTokenValue = token;
					driveTokenOrigin = driveServerOrigin;
				}
				return mirrorHandlers.drive_mirror_refresh_token(token, expiresAt);
			},
		};
		registerHandlers(mirrorHandlersWithOwner);
		tray = new Tray(nativeImage.createEmpty());
		renderTrayMenu({ running: false, paused: false, perSpace: [], issues: [] });
	}

	// ── Session lockdown (ADR-013 invariant 4) ──
	applySessionLockdown(session.defaultSession, win.webContents, appOrigins);

	if (devServerUrl) {
		void win.loadURL(devServerUrl);
	} else if (e6HarnessAppOrigin !== null) {
		// E6 harness load: plant the fixture-captured member session cookie
		// BEFORE the first navigation (the SPA probes /auth/me with cookie
		// credentials during boot — the same HttpOnly cookie a real browser
		// login receives), then load the gateway-served webmail at the
		// protected entry route (a public route never starts the SPA's auth
		// probe). The readiness probe in the composed E6 surface holds the
		// ready line until the authenticated shell actually rendered.
		const cookie =
			resolveE6HarnessSessionCookie(process.env[CONNECTIVITY_SYNC_SESSION_COOKIE_ENV]) ??
			failE6SessionCookieMissing();
		void (async () => {
			await session.defaultSession.cookies.set(electronCookieDetails(e6HarnessAppOrigin, cookie));
			await win.loadURL(`${e6HarnessAppOrigin}${E6_APP_ENTRY_PATH}`);
		})().catch((error) => {
			console.error("connectivity e6 session bootstrap/load failed", error);
			process.exit(1);
		});
	} else {
		void win.loadFile(indexPath);
	}
}

/** Named refusal for the compose-time invariant that the app-origin seam
 *  always ships with a session cookie (the launcher enforces it; this is the
 *  client-side backstop). Unreachable when the launcher is honest. */
function failE6SessionCookieMissing(): never {
	throw new Error(
		`${CONNECTIVITY_SYNC_SESSION_COOKIE_ENV} is required with ${CONNECTIVITY_SYNC_APP_ORIGIN_ENV}; ` +
			`refusing to load the gateway-served webmail with no member session`,
	);
}

app.whenReady().then(() => {
	createWindow();
	app.on("activate", () => {
		if (BrowserWindow.getAllWindows().length === 0) createWindow();
	});
});

app.on("browser-window-blur", () => mamLifecycleOwner?.pause());
app.on("browser-window-focus", () => mamLifecycleOwner?.resume());

app.on("window-all-closed", () => {
	// Keep syncing with every window closed (arch D5/D6, the tray is the
	// affordance) — quit only when there's no mirror running to keep alive for.
	if (process.platform !== "darwin" && !mirrorService?.isRunning()) app.quit();
});

app.on("before-quit", () => {
	mamLifecycleOwner?.stop();
	void mirrorService?.stop();
	disposeE6Surface();
});
