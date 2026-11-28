// Settings-resource composable: the route-side state machine around the typed
// HTTP seam ($lib/http).
//
// Division of ownership (WP5, decision 5A — do not blur):
//
//   - $lib/http.ts owns transport policy: the AbortController timeout, caller
//     signal merging, the 401/403 auth handling (login redirect), non-ok →
//     typed Error, and JSON parsing. This composable NEVER re-implements any
//     of it — it passes this call's abort signal into the seam and surfaces
//     whatever typed, display-safe error the seam raises.
//   - This module owns ROUTE STATE only: per-instance pending/error/data,
//     caller cancellation, supersede protection (a newer call wins; a stale
//     completion can neither overwrite newer state nor leave `pending` stuck)
//     and teardown on unmount.
//
// State is per instance — created inside the component setup, never shared
// across routes. Nothing here is module-global.
//
// Caller contract:
//   const res = createSettingsResource<Sig[]>({ load: { url: '/api/…' } });
//   const data = await res.load();            // null on failure/cancellation
//   const r = await res.save({ url, method: 'PUT', body });  // {ok} result
//   onMount(() => () => res.cleanup());       // abort in-flight on unmount
//
// See README.md in this directory for lifecycle details and the remaining
// raw-fetch census.

import { httpRequest, typedFetch, type HttpOptions } from '$lib/http';
import { parseError } from '$lib/errors';

/** HTTP methods a settings call may use (the seam supports more; routes need these). */
export type SettingsMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/** Description of one settings HTTP call, executed through the $lib/http seam. */
export interface SettingsRequest {
	/** Request target (root-relative, e.g. `/api/settings/signatures`). */
	url: string;
	/** HTTP method. Defaults to GET. */
	method?: SettingsMethod;
	/** JSON-serializable payload; encoded with the JSON content-type when present. */
	body?: unknown;
	/** Extra headers merged under the JSON content-type. */
	headers?: Record<string, string>;
	/**
	 * Success-body handling for saves. `'none'` (the default) treats any 2xx as
	 * a no-content success (204-friendly); `'json'` decodes the body as the
	 * declared result type. Loads always decode JSON.
	 */
	parse?: 'json' | 'none';
	/**
	 * Seam-level display-safe error message builder (http.ts `onError`). Use it
	 * to surface an authored body message; the composable never echoes raw
	 * server bodies itself.
	 */
	onError?: (res: Response) => string | Promise<string>;
	/** Seam timeout override (ms); the seam's default applies otherwise. */
	timeoutMs?: number;
	/**
	 * Optional external cancellation (e.g. an authed-bootstrap unmount signal).
	 * Merged by the seam with this call's own controller; aborting it cancels
	 * the call WITHOUT recording an error.
	 */
	signal?: AbortSignal | null;
}

export interface SettingsResourceConfig<TData> {
	/** The resource's canonical load call (GET unless explicitly overridden). */
	load: SettingsRequest;
	/** Seed value exposed as `data` before the first successful load. */
	initialData?: TData | null;
}

/** Typed load/save result: `ok: false` covers failure AND cancellation. */
export type SettingsSaveResult<TResult> = { ok: true; data: TResult } | { ok: false };

export interface SettingsResource<TData> {
	/** A load is in flight. */
	get pending(): boolean;
	/** A save is in flight. */
	get saving(): boolean;
	/** Display-safe load error (`''` when none). Cleared when a new load starts. */
	get error(): string;
	/** Display-safe save error (`''` when none). Cleared when a new save starts. */
	get saveError(): string;
	/** Last successfully loaded value, or the `initialData` seed. */
	get data(): TData | null;
	/**
	 * Run the configured load. A newer call supersedes an older one (which is
	 * aborted and resolves `null` without touching state). Resolves `null` on
	 * failure/cancellation — read {@link error} for the display-safe message.
	 */
	load(overrides?: Partial<Omit<SettingsRequest, 'parse'>>): Promise<TData | null>;
	/**
	 * Run one save call through the seam. Never throws: the seam's typed error
	 * lands in {@link saveError}. Supersedes an in-flight save the same way
	 * {@link load} does.
	 */
	save<TResult = void>(request: SettingsRequest): Promise<SettingsSaveResult<TResult>>;
	/** Abort all in-flight work and settle state. Call on unmount. */
	cleanup(): void;
}

/**
 * Create one settings resource. The returned object is component-local
 * reactive state (`$state` runes); instantiate it in component setup and
 * `cleanup()` it on unmount.
 */
export function createSettingsResource<TData>(
	config: SettingsResourceConfig<TData>
): SettingsResource<TData> {
	let data = $state<TData | null>(config.initialData ?? null);
	let pending = $state(false);
	let saving = $state(false);
	let error = $state('');
	let saveError = $state('');

	// Per-lane controllers: the NEWEST call in a lane owns the lane's state.
	let loadController: AbortController | null = null;
	let saveController: AbortController | null = null;

	function toHttpOptions(request: SettingsRequest, signal: AbortSignal): HttpOptions {
		const headers: Record<string, string> = {
			...(request.body !== undefined ? { 'content-type': 'application/json' } : {}),
			...request.headers,
		};
		// Merge this call's own controller with any external cancellation (the
		// seam merges the result with its timeout controller).
		const effective = request.signal ? AbortSignal.any([signal, request.signal]) : signal;
		return {
			method: request.method ?? 'GET',
			headers: Object.keys(headers).length > 0 ? headers : undefined,
			body: request.body !== undefined ? JSON.stringify(request.body) : undefined,
			signal: effective,
			onError: request.onError,
			timeoutMs: request.timeoutMs,
		};
	}

	/**
	 * True when the thrown error is a CANCELLATION of this call — either this
	 * lane's own controller (supersede) or the call's external signal (unmount)
	 * aborted it. An AbortError with both signals live-and-well is the seam's
	 * own timeout bound, which is a real failure and must surface as one.
	 */
	function isCancellation(err: unknown, controller: AbortController, external: AbortSignal | null | undefined): boolean {
		if (!(err instanceof DOMException) || err.name !== 'AbortError') return false;
		return controller.signal.aborted || external?.aborted === true;
	}

	/** Display-safe normalization: the seam already authored every message it raises. */
	function displayMessage(err: unknown): string {
		return parseError(err).message;
	}

	async function load(overrides?: Partial<Omit<SettingsRequest, 'parse'>>): Promise<TData | null> {
		// Supersede: abort the previous load. Its continuation observes a stale
		// lane below and settles without touching state (or pending).
		loadController?.abort();
		const controller = new AbortController();
		loadController = controller;
		pending = true;
		error = '';
		const request: SettingsRequest = { ...config.load, ...overrides };
		try {
			const result = await typedFetch<TData>(request.url, toHttpOptions(request, controller.signal));
			if (loadController !== controller) return null; // superseded — newer call owns state
			data = result;
			return result;
		} catch (err) {
			if (loadController !== controller) return null; // superseded
			if (isCancellation(err, controller, request.signal)) return null; // cancelled — not a failure
			error = displayMessage(err);
			return null;
		} finally {
			// Only the lane's current call may settle `pending`; a superseded or
			// cleaned-up call leaves it to its successor (or to cleanup()).
			if (loadController === controller) {
				loadController = null;
				pending = false;
			}
		}
	}

	async function save<TResult>(request: SettingsRequest): Promise<SettingsSaveResult<TResult>> {
		saveController?.abort();
		const controller = new AbortController();
		saveController = controller;
		saving = true;
		saveError = '';
		try {
			const res = await httpRequest(request.url, toHttpOptions(request, controller.signal));
			if (saveController !== controller) return { ok: false }; // superseded
			if (request.parse === 'json') {
				const decoded = (await res.json()) as TResult;
				return { ok: true, data: decoded };
			}
			return { ok: true, data: undefined as TResult };
		} catch (err) {
			if (saveController !== controller) return { ok: false }; // superseded
			if (isCancellation(err, controller, request.signal)) return { ok: false }; // cancelled
			saveError = displayMessage(err);
			return { ok: false };
		} finally {
			if (saveController === controller) {
				saveController = null;
				saving = false;
			}
		}
	}

	function cleanup(): void {
		loadController?.abort();
		loadController = null;
		saveController?.abort();
		saveController = null;
		pending = false;
		saving = false;
	}

	return {
		get pending() {
			return pending;
		},
		get saving() {
			return saving;
		},
		get error() {
			return error;
		},
		get saveError() {
			return saveError;
		},
		get data() {
			return data;
		},
		load,
		save,
		cleanup,
	};
}
