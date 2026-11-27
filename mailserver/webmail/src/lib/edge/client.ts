// Schema-first openapi-fetch client routed through Setjoin's existing DPoP
// httpRequest transport seam ($lib/http.ts).
//
// Preserves in one place:
// - DPoP proof header attachment (`DPoP` with `ath`) and per-tab 401
//   `dpop_admission` recovery + single replay;
// - timeout and caller AbortSignal merging;
// - 401 login redirect and 403 ToU/risk remediation (unless opted into
//   allowStatuses), plus caller onError/forbiddenMessage parity on plain 403s;
// - FormData multipart uploads without clobbering Content-Type boundary;
// - openapi-fetch onRequest middleware header mutations;
// - parseAs: 'json' | 'text' | 'blob' | 'stream' raw Response bodies;
// - typed RFC 9457 ProblemDetails extraction via EdgeProblemError.

import createClient, { type Client, type ClientOptions } from 'openapi-fetch';
import { httpRequest, type HttpOptions } from '$lib/http';
import type { components, paths } from './schema';

export type { paths, components, operations } from './schema';
export type EdgeProblemDetails = components['schemas']['Common.ProblemDetails'];

/**
 * Default non-2xx statuses passed through to openapi-fetch so callers receive
 * typed `{ data, error, response }` while preserving httpRequest's 401 DPoP
 * recovery + login redirect and 403 remediation hooks.
 */
export const EDGE_DEFAULT_ALLOW_STATUSES: readonly number[] = [
	400, 404, 405, 409, 410, 412, 413, 415, 422, 429, 500, 502, 503, 504
];

export interface EdgeClientOptions {
	/** Optional base URL prefix (defaults to root-relative `''`). */
	baseUrl?: string;
	/** Default request headers merged into every request. */
	headers?: ClientOptions['headers'];
	/** Passed through to {@link httpRequest}. */
	timeoutMs?: HttpOptions['timeoutMs'];
	/** Passed through to {@link httpRequest}. */
	cache?: HttpOptions['cache'];
	/** Passed through to {@link httpRequest}. */
	loginRedirect?: HttpOptions['loginRedirect'];
	/** Passed through to {@link httpRequest}. */
	unauthorizedMessage?: HttpOptions['unauthorizedMessage'];
	/** Passed through to {@link httpRequest}. */
	forbiddenMessage?: HttpOptions['forbiddenMessage'];
	/**
	 * Passed through to {@link httpRequest} for non-allowStatuses errors (such
	 * as plain non-remediation 403 responses).
	 */
	onError?: HttpOptions['onError'];
	/**
	 * HTTP non-2xx statuses returned to openapi-fetch as `{ error, response }`
	 * instead of throwing inside {@link httpRequest}.
	 * Defaults to {@link EDGE_DEFAULT_ALLOW_STATUSES}.
	 */
	allowStatuses?: number[];
}

/**
 * Typed RFC 9457 `application/problem+json` error extracted from an
 * openapi-fetch `{ error, response }` result.
 */
export class EdgeProblemError extends Error {
	readonly status: number;
	readonly type: string;
	readonly title: string;
	readonly detail: string;
	readonly code?: string;
	readonly instance?: string;
	readonly problem: EdgeProblemDetails;

	constructor(problem: EdgeProblemDetails, fallbackMessage?: string) {
		const message =
			problem.detail ||
			problem.title ||
			fallbackMessage ||
			`Request failed (${problem.status})`;
		super(message);
		this.name = 'EdgeProblemError';
		this.status = problem.status;
		this.type = problem.type ?? 'about:blank';
		this.title = problem.title ?? '';
		this.detail = problem.detail ?? message;
		this.code = problem.code;
		this.instance = problem.instance;
		this.problem = problem;
	}
}

export function isProblemDetails(value: unknown): value is EdgeProblemDetails {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Record<string, unknown>;
	return (
		typeof candidate.status === 'number' ||
		typeof candidate.detail === 'string' ||
		typeof candidate.title === 'string' ||
		typeof candidate.type === 'string' ||
		typeof candidate.code === 'string'
	);
}

/**
 * Normalize an openapi-fetch `error` payload + `Response` into a typed
 * {@link EdgeProblemError} carrying RFC 9457 fields.
 */
export function toEdgeProblemError(
	error: unknown,
	response: Response,
	fallbackMessage?: string
): EdgeProblemError {
	if (isProblemDetails(error)) {
		const candidate = error as Partial<EdgeProblemDetails>;
		return new EdgeProblemError(
			{
				type: typeof candidate.type === 'string' ? candidate.type : 'about:blank',
				title: typeof candidate.title === 'string' ? candidate.title : undefined,
				status: typeof candidate.status === 'number' ? candidate.status : response.status,
				detail: typeof candidate.detail === 'string' ? candidate.detail : undefined,
				code: typeof candidate.code === 'string' ? candidate.code : undefined,
				instance: typeof candidate.instance === 'string' ? candidate.instance : undefined,
				remediation: typeof candidate.remediation === 'string' ? candidate.remediation : undefined,
				remediation_tou_id:
					typeof candidate.remediation_tou_id === 'number'
						? candidate.remediation_tou_id
						: undefined,
				retryable: typeof candidate.retryable === 'boolean' ? candidate.retryable : undefined,
				holderId: typeof candidate.holderId === 'number' ? candidate.holderId : undefined
			},
			fallbackMessage
		);
	}
	return new EdgeProblemError(
		{
			type: 'about:blank',
			status: response.status,
			detail: fallbackMessage ?? `Request failed (${response.status})`
		},
		fallbackMessage
	);
}

/**
 * Custom Request subclass used by openapi-fetch so root-relative URLs and
 * replayable bodies (including FormData for multipart uploads) survive intact
 * into {@link httpRequest} and its 401 `dpop_admission` replay loop.
 */
class EdgeRequest extends Request {
	readonly edgeRawUrl: string;
	readonly edgeRawBody: BodyInit | null | undefined;
	readonly edgeMethod: string;
	readonly edgeSignal: AbortSignal | null | undefined;
	readonly edgeCredentials: RequestCredentials | undefined;
	readonly edgeKeepalive: boolean | undefined;

	constructor(input: RequestInfo | URL, init?: RequestInit) {
		const rawUrl =
			typeof input === 'string'
				? input
				: input instanceof URL
					? input.toString()
					: input.url;
		const syntheticOrigin =
			typeof location !== 'undefined' && location.origin && location.origin !== 'null'
				? location.origin
				: 'http://localhost';
		const requestInput =
			typeof input === 'string' && input.startsWith('/')
				? `${syntheticOrigin}${input}`
				: input;
		const isFormData = typeof FormData !== 'undefined' && init?.body instanceof FormData;
		const isBinaryBody =
			(typeof ArrayBuffer !== 'undefined' &&
				(init?.body instanceof ArrayBuffer || ArrayBuffer.isView(init?.body))) ||
			(typeof Blob !== 'undefined' && init?.body instanceof Blob);
		super(requestInput, isFormData || isBinaryBody ? { ...init, body: undefined } : init);
		this.edgeRawUrl = rawUrl;
		this.edgeRawBody = init?.body;
		this.edgeMethod = (init?.method ?? 'GET').toUpperCase();
		this.edgeSignal = init?.signal;
		this.edgeCredentials = init?.credentials;
		this.edgeKeepalive = init?.keepalive;
	}
}

function toRootRelativePath(rawUrl: string): string {
	if (rawUrl.startsWith('/')) return rawUrl;
	try {
		const parsed = new URL(rawUrl);
		return `${parsed.pathname}${parsed.search}`;
	} catch {
		return rawUrl;
	}
}

const CANONICAL_HEADER_NAMES: Record<string, string> = {
	accept: 'Accept',
	'content-type': 'Content-Type',
	'idempotency-key': 'Idempotency-Key',
	range: 'Range',
	'x-audit-reason': 'X-Audit-Reason',
	'x-captcha-answer': 'X-Captcha-Answer',
	'x-captcha-token': 'X-Captcha-Token',
	'x-mfa-reauth': 'X-MFA-Reauth'
};

function normalizeHeadersForBody(
	rawHeaders: HeadersInit | undefined,
	body: BodyInit | null | undefined
): Record<string, string> | undefined {
	if (!rawHeaders) return undefined;
	const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
	const headers = new Headers(rawHeaders);
	if (isFormData) {
		// Never clobber browser-generated multipart/form-data boundary header.
		headers.delete('content-type');
	}
	const out: Record<string, string> = {};
	let hasAny = false;
	headers.forEach((value, key) => {
		const canonical = CANONICAL_HEADER_NAMES[key.toLowerCase()] ?? key;
		out[canonical] = value;
		hasAny = true;
	});
	return hasAny ? out : undefined;
}

/**
 * Ensures minimal fetch mocks in unit tests (e.g. `{ ok: true, status: 200, json }`)
 * satisfy openapi-fetch's `response.headers.get()` and `response.text()` calls
 * without touching real Response instances (including streams and blobs).
 */
function ensureOpenApiFetchResponse(res: Response): Response {
	const candidate = res as unknown as {
		headers?: Headers;
		text?: () => Promise<string>;
		json?: () => Promise<unknown>;
	};
	if (candidate.headers && typeof candidate.text === 'function') {
		return res;
	}
	return new Proxy(res, {
		get(target, prop, receiver) {
			if (prop === 'headers' && !candidate.headers) {
				return new Headers({ 'content-type': 'application/json' });
			}
			if (prop === 'text') {
				return async () => {
					if (typeof candidate.text === 'function') {
						const raw = await candidate.text();
						if (raw.length > 0) return raw;
					}
					if (typeof candidate.json === 'function') {
						try {
							const val = await candidate.json();
							return val === undefined ? '' : JSON.stringify(val);
						} catch {
							return '';
						}
					}
					return '';
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		}
	});
}

/**
 * Build a `fetch`-compatible adapter backed by {@link httpRequest} (DPoP proof
 * signing, 401 `dpop_admission` recovery replay, timeout, AbortSignal merging).
 */
export function createDpopEdgeFetch(options: EdgeClientOptions = {}): typeof fetch {
	const allowStatuses = options.allowStatuses ?? [...EDGE_DEFAULT_ALLOW_STATUSES];

	return async function dpopEdgeFetch(
		input: RequestInfo | URL,
		init?: RequestInit
	): Promise<Response> {
		let path: string;
		let method: string;
		let headers: HeadersInit | undefined;
		let body: BodyInit | null | undefined;
		let signal: AbortSignal | null | undefined;
		let credentials: RequestCredentials | undefined;
		let keepalive: boolean | undefined;

		if (input instanceof EdgeRequest) {
			path = toRootRelativePath(input.edgeRawUrl);
			method = input.edgeMethod;
			body = input.edgeRawBody;
			// Prefer `input.headers` so openapi-fetch `onRequest` middleware header
			// mutations are preserved rather than overwritten by initial raw headers.
			headers = normalizeHeadersForBody(init?.headers ?? input.headers, body);
			signal = init?.signal ?? input.edgeSignal;
			credentials = init?.credentials ?? input.edgeCredentials;
			keepalive = init?.keepalive ?? input.edgeKeepalive;
		} else if (input instanceof Request) {
			path = toRootRelativePath(input.url);
			method = (init?.method ?? input.method ?? 'GET').toUpperCase();
			body = init?.body ?? (input.body ?? undefined);
			headers = normalizeHeadersForBody(init?.headers ?? input.headers, body);
			signal = init?.signal ?? input.signal;
			credentials = init?.credentials ?? input.credentials;
			keepalive = init?.keepalive ?? input.keepalive;
		} else {
			path = toRootRelativePath(typeof input === 'string' ? input : input.toString());
			method = (init?.method ?? 'GET').toUpperCase();
			body = init?.body;
			headers = normalizeHeadersForBody(init?.headers, body);
			signal = init?.signal;
			credentials = init?.credentials;
			keepalive = init?.keepalive;
		}

		const httpOpts: HttpOptions = {
			method,
			signal,
			timeoutMs: options.timeoutMs,
			cache: options.cache,
			loginRedirect: options.loginRedirect,
			unauthorizedMessage: options.unauthorizedMessage,
			forbiddenMessage: options.forbiddenMessage,
			onError: options.onError,
			allowStatuses
		};
		if (headers !== undefined) {
			httpOpts.headers = headers;
		}
		if (body !== undefined && body !== null) {
			httpOpts.body = body;
		}
		if (credentials !== undefined) {
			httpOpts.credentials = credentials;
		}
		if (keepalive !== undefined) {
			httpOpts.keepalive = keepalive;
		}

		const res = await httpRequest(path, httpOpts);
		return ensureOpenApiFetchResponse(res);
	};
}

/**
 * Create a typed `openapi-fetch` client wired to Setjoin's OpenAPI 3.1 edge
 * contract and routed through {@link httpRequest} (DPoP + recovery + timeout).
 */
export function createEdgeClient(options: EdgeClientOptions = {}): Client<paths> {
	return createClient<paths>({
		baseUrl: options.baseUrl ?? '',
		headers: options.headers,
		Request: EdgeRequest as unknown as typeof Request,
		fetch: createDpopEdgeFetch(options)
	});
}

/** Shared default typed edge client with standard browser auth redirects. */
export const edgeClient: Client<paths> = createEdgeClient();
