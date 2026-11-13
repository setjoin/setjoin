/// <reference types="@sveltejs/kit" />
/// <reference lib="webworker" />
import { build, files, version } from '$service-worker';
import { chooseStrategy } from '$lib/native/sw-strategy';
import {
	SHELL_MANIFEST_PATH,
	SHELL_PROTOCOL_VERSION,
	SHELL_STATE_CACHE,
	SHELL_STATE_KEY,
	candidateExpired,
	emptyShellGenerationState,
	reduceShellGenerationState,
	retainedCacheNames,
	retainedMemberBuilds,
	shellCacheName,
	validateCriticalShellManifest,
	type ShellGenerationState,
} from '$lib/native/sw-generation';
import { pushText, type PushLocale } from '$lib/i18n/push.generated';
import {
	runNotificationCommand,
	type NotificationClientsPort,
} from '$lib/push/notificationCommand';

const sw = self as unknown as ServiceWorkerGlobalScope;
const PUBLIC_ASSETS = new Set([...build, ...files].map((path) => (path.startsWith('/') ? path : `/${path}`)));
const CANDIDATE_CACHE = shellCacheName(version);
const CANDIDATE_ACK_TIMEOUT_MS = 15_000;
let pushLocale: PushLocale = 'en';
let candidateTimer: ReturnType<typeof setTimeout> | null = null;

async function readGenerationState(): Promise<ShellGenerationState> {
	const cache = await caches.open(SHELL_STATE_CACHE);
	const response = await cache.match(SHELL_STATE_KEY);
	if (!response) return emptyShellGenerationState();
	try {
		const value = await response.json() as ShellGenerationState;
		if (value?.protocolVersion !== SHELL_PROTOCOL_VERSION || !value.generations || typeof value.generations !== 'object') {
			return emptyShellGenerationState();
		}
		return value;
	} catch {
		return emptyShellGenerationState();
	}
}

async function writeGenerationState(state: ShellGenerationState): Promise<void> {
	const cache = await caches.open(SHELL_STATE_CACHE);
	await cache.put(SHELL_STATE_KEY, new Response(JSON.stringify(state), {
		headers: { 'Content-Type': 'application/json' },
	}));
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function installCandidate(): Promise<void> {
	await caches.delete(CANDIDATE_CACHE);
	try {
		const manifestResponse = await fetch(SHELL_MANIFEST_PATH, { cache: 'no-store', credentials: 'same-origin' });
		if (!manifestResponse.ok || manifestResponse.redirected || new URL(manifestResponse.url).origin !== location.origin) {
			throw new Error('critical shell manifest response is invalid');
		}
		const manifest = validateCriticalShellManifest(await manifestResponse.json(), version, location.origin);
		if (!manifest) throw new Error('critical shell manifest validation failed');
		const cache = await caches.open(CANDIDATE_CACHE);
		for (const member of manifest.members) {
			const request = new Request(member.path, { cache: 'reload', credentials: 'same-origin' });
			const response = await fetch(request);
			if (!response.ok || response.redirected || response.type === 'opaque' || new URL(response.url).origin !== location.origin) {
				throw new Error(`critical shell response is invalid: ${member.path}`);
			}
			const bytes = await response.clone().arrayBuffer();
			if (bytes.byteLength !== member.identityBytes || await sha256Hex(bytes) !== member.sha256) {
				throw new Error(`critical shell integrity mismatch: ${member.path}`);
			}
			await cache.put(member.path, response);
		}
		const state = reduceShellGenerationState(await readGenerationState(), {
			type: 'installed',
			buildId: version,
			members: manifest.members.map((member) => member.path),
		});
		await writeGenerationState(state);
	} catch (error) {
		await caches.delete(CANDIDATE_CACHE);
		throw error;
	}
}

async function cleanupShellCaches(state: ShellGenerationState): Promise<void> {
	const keep = retainedCacheNames(state);
	const names = await caches.keys();
	await Promise.all(names
		.filter((name) => name.startsWith('setjoin-shell-v1-') && !keep.has(name))
		.map((name) => caches.delete(name)));
}

async function notifyWindows(message: unknown): Promise<void> {
	const clients = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true });
	for (const client of clients) client.postMessage(message);
}

async function failCandidate(state: ShellGenerationState): Promise<ShellGenerationState> {
	const failed = reduceShellGenerationState(state, { type: 'failed', buildId: version });
	await writeGenerationState(failed);
	await caches.delete(CANDIDATE_CACHE);
	await cleanupShellCaches(failed);
	await notifyWindows({
		type: 'SETJOIN_CANDIDATE_FAILED',
		protocolVersion: SHELL_PROTOCOL_VERSION,
		buildId: version,
		previousBuildId: failed.currentBuildId,
	});
	if (failed.currentBuildId) {
		const clients = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true });
		for (const client of clients) {
			if ('navigate' in client) await (client as WindowClient).navigate(client.url);
		}
	}
	return failed;
}

async function expireCandidateIfNeeded(state: ShellGenerationState): Promise<ShellGenerationState> {
	if (state.candidateBuildId !== version || !candidateExpired(state, Date.now(), CANDIDATE_ACK_TIMEOUT_MS)) {
		return state;
	}
	if (candidateTimer) clearTimeout(candidateTimer);
	candidateTimer = null;
	return failCandidate(state);
}

function scheduleCandidateTimeout(state: ShellGenerationState): void {
	if (candidateTimer) clearTimeout(candidateTimer);
	candidateTimer = null;
	if (state.candidateBuildId !== version) return;
	const activatedAt = state.candidateActivatedAtMs;
	const remaining = typeof activatedAt === 'number' && Number.isFinite(activatedAt)
		? Math.max(0, activatedAt + CANDIDATE_ACK_TIMEOUT_MS - Date.now())
		: 0;
	candidateTimer = setTimeout(() => { void failUnacknowledgedCandidate(); }, remaining);
}

async function failUnacknowledgedCandidate(): Promise<void> {
	const before = await readGenerationState();
	const state = await expireCandidateIfNeeded(before);
	if (state.candidateBuildId === version) {
		// setTimeout may fire a few milliseconds early. Persisted wall-clock
		// evidence remains authoritative and the next check is rescheduled.
		scheduleCandidateTimeout(state);
	}
}

sw.addEventListener('message', (event) => {
	const data = event.data as { type?: string; locale?: string; protocolVersion?: number; buildId?: string } | null;
	if (data?.type === 'SETJOIN_PUSH_LOCALE' && (data.locale === 'en' || data.locale === 'de' || data.locale === 'zh')) {
		pushLocale = data.locale;
		return;
	}
	if (
		data?.type === 'SETJOIN_ACTIVATE_CANDIDATE' &&
		data.protocolVersion === SHELL_PROTOCOL_VERSION &&
		data.buildId === version
	) {
		event.waitUntil(sw.skipWaiting());
		return;
	}
	if (
		data?.type === 'SETJOIN_SHELL_MOUNTED' &&
		data.protocolVersion === SHELL_PROTOCOL_VERSION &&
		data.buildId === version
	) {
		event.waitUntil((async () => {
			const current = await readGenerationState();
			const checked = await expireCandidateIfNeeded(current);
			if (checked.candidateBuildId !== version) return;
			const state = reduceShellGenerationState(checked, { type: 'mounted', buildId: version });
			await writeGenerationState(state);
			await cleanupShellCaches(state);
			if (candidateTimer) clearTimeout(candidateTimer);
			candidateTimer = null;
		})());
	}
});

sw.addEventListener('install', (e) => {
	// A candidate is complete or absent: any failed member/hash/quota operation
	// deletes the whole cache. Activation waits for the page's safe-boundary
	// request instead of interrupting an active compose, upload, or meeting.
	e.waitUntil(installCandidate());
});

sw.addEventListener('activate', (e) => {
	e.waitUntil((async () => {
		await sw.clients.claim();
		let state = await readGenerationState();
		// The acknowledgement clock starts only after activation. A candidate may
		// wait safely behind an active compose/upload/meeting for an unbounded
		// period without being mistaken for a failed mounted shell.
		if (state.candidateBuildId === version && !Number.isFinite(state.candidateActivatedAtMs)) {
			state = reduceShellGenerationState(state, {
				type: 'activated', buildId: version, activatedAtMs: Date.now(),
			});
			await writeGenerationState(state);
		}
		state = await expireCandidateIfNeeded(state);
		await cleanupShellCaches(state);
		scheduleCandidateTimeout(state);
	})());
});

/**
 * Returns true when the SW should fall back to the cached app-shell document
 * for a navigation request (native-shell offline route load).
 *
 * Exported for unit testing; wired into the fetch listener below.
 */
export function shouldServeShell(request: Request): boolean {
	if (request.mode !== 'navigate') return false;
	const url = new URL(request.url);
	// Preserve the /jmap mail-caching ban + never shadow auth/blob/attachment endpoints.
	// ponytail: regex covers current banned prefixes; extend the set here if new data APIs are added.
	if (/^\/(jmap|auth|api|blobs|mail-attachment)(\/|$)/.test(url.pathname)) return false;
	return true;
}

sw.addEventListener('fetch', (e) => {
	const url = new URL(e.request.url);
	if (url.origin !== location.origin) return; // let cross-origin pass through untouched

	// Navigation fallback is generation-specific. Never search all CacheStorage:
	// that could mix an old HTML shell with a new executable graph.
	if (shouldServeShell(e.request)) {
		e.respondWith((async () => {
			const state = await expireCandidateIfNeeded(await readGenerationState());
			if (state.failedBuildId !== version) {
				try { return await fetch(e.request); } catch { /* exact retained fallback below */ }
			}
			for (const buildId of [state.candidateBuildId, state.currentBuildId, state.previousBuildId]) {
				if (!buildId) continue;
				const cache = await caches.open(shellCacheName(buildId));
				const hit = await cache.match(e.request) ?? await cache.match('/index.html');
				if (hit) return hit;
			}
			throw new Error('validated shell generation is unavailable');
		})());
		return;
	}
	if (e.request.method !== 'GET') return;
	e.respondWith((async () => {
		const state = await expireCandidateIfNeeded(await readGenerationState());
		const retainedPaths = Object.values(state.generations).flatMap((generation) => generation.members);
		const allowlist = new Set([...PUBLIC_ASSETS, ...retainedPaths]);
		const strategy = chooseStrategy(url, e.request.method, allowlist);
		if (strategy !== 'cache-first') return fetch(e.request);

		for (const buildId of retainedMemberBuilds(state, url.pathname)) {
			const hit = await (await caches.open(shellCacheName(buildId))).match(e.request);
			if (hit) return hit;
		}

		const response = await fetch(e.request);
		const writeBuildId = state.candidateBuildId === version || state.currentBuildId === version ? version : null;
		if (writeBuildId && PUBLIC_ASSETS.has(url.pathname) && response.ok && response.type !== 'opaque') {
			await (await caches.open(shellCacheName(writeBuildId))).put(e.request, response.clone());
		}
		return response;
	})());
});

// ── Web Push (QoL #9) ──────────────────────────────────────────────────────
// Server payload shape for a new-mail push. Other push `type`s (e.g. the
// existing MFA `mfa_challenge`/`security_alert` webpush payloads sent by
// authserver's NumberMatchPushProvider — see authn/push.go) are a distinct
// concern handled by the browser's native Notification API on that flow, not
// this SW; this handler only renders the mail shape and ignores the rest.
interface MailPushPayload {
	type?: string;
	// Real producer shape (pushjobs/worker.go buildPayload@worker.go:301-308):
	// sender is an object ({name,email}), and the subject line is its own field
	// — there is no flat title/body on the wire. title/body are kept as an
	// optional back-compat input (nothing sends them today) so an untyped
	// legacy/test payload still renders something.
	sender?: { name?: string; email?: string };
	subject?: string;
	title?: string;
	body?: string;
	messageId?: string;
	threadId?: string;
}

// lib.dom's NotificationOptions omits `actions` (it's a lib.webworker-only
// field the two ambient lib declarations don't merge in this project's
// tsconfig) — extend locally rather than fight the lib resolution.
type MailNotificationOptions = NotificationOptions & {
	actions?: { action: string; title: string }[];
};

/** Pure: turn a push payload into showNotification args. Exported for unit tests. */
export function buildMailNotification(data: MailPushPayload): { title: string; options: MailNotificationOptions } | null {
	// Bug fix (A3.5 Task 4): pushjobs/worker.go's buildPayload (worker.go:302) —
	// the ONLY real producer of a mail webpush payload — emits `type:"mail"`.
	// This guard used to require `type:'new_mail'`, a value nothing in the repo
	// ever sent, so the live mail webpush path never rendered a notification.
	if (data.type && data.type !== 'mail') return null; // not ours — leave it alone
	const dedupeTag = data.messageId ?? data.threadId ?? 'mail';
	// Blocker fix (A3.5 Task 4 review): buildPayload sends sender.name/subject,
	// never a flat title/body — map the real wire fields first.
	return {
		title: data.sender?.name || data.title || 'New message',
		options: {
			body: data.subject || data.body || '',
			tag: dedupeTag, // same id replaces the prior notification instead of stacking
			data: { messageId: data.messageId, threadId: data.threadId },
			actions: [
				{ action: 'archive', title: 'Archive' },
				{ action: 'reply', title: 'Reply' },
			],
		},
	};
}

// ── Chat push (A3.5 Task 4) ─────────────────────────────────────────────────
// Payload shape from pushjobs' chat drain leg (planChatFanout, worker/chat.go).
// Payload-privacy posture (A3.5 Global Constraint): NO message body ever
// travels in this payload — the client fetches content on tap, never renders
// message text from a push.
interface ChatPushPayload {
	type?: string;
	channelId?: number;
	messageId?: number;
	seq?: number;
	sender?: string; // author displayName
	channelName?: string; // channel name; "" for a plain DM (chat_channels.name is NULL); comma-joined for group_dm
	mention?: boolean; // this recipient's own mention/broadcast qualifier
	dedupeTag?: string; // "chat-{channelId}" — per-channel tag-replace
}

/** Pure: turn a chat push payload into showNotification args. Exported for unit tests. */
export function buildChatNotification(data: ChatPushPayload): { title: string; options: MailNotificationOptions } | null {
	if (data.type !== 'chat') return null; // not ours — leave it alone
	const sender = data.sender ?? '';
	const title = data.mention ? `${pushText(pushLocale, 'chat.push.mentionPrefix')}${sender}` : sender;
	// channelName is "" for a plain DM (server never resolves chat_channels.name,
	// which is NULL there) — the client renders the localized "Direct message"
	// copy itself, per the plan.
	const body = data.channelName || pushText(pushLocale, 'chat.list.unknownDm');
	return {
		title,
		options: {
			body,
			tag: data.dedupeTag ?? `chat-${data.channelId ?? ''}`, // per-channel replace, not per-message
			data: { type: 'chat', channelId: data.channelId, seq: data.seq },
		},
	};
}

sw.addEventListener('push', (e) => {
	let data: MailPushPayload & ChatPushPayload;
	try {
		data = e.data?.json() ?? {};
	} catch {
		data = {};
	}
	// Real type dispatch: chat and mail are the only two producers today, each
	// gets its own pure builder; an unrecognized/absent type falls to the mail
	// builder's own back-compat default (untyped payload == mail, historical).
	const notification = data.type === 'chat' ? buildChatNotification(data) : buildMailNotification(data);
	if (!notification) return;
	e.waitUntil(sw.registration.showNotification(notification.title, notification.options));
});

/** Pure: decide what a notificationclick should do. Exported for unit tests. */
export function routeNotificationClick(
	action: string,
	data: { messageId?: string; threadId?: string },
): { kind: 'archive'; messageId: string } | { kind: 'focus'; url: string } {
	if (action === 'archive' && data.messageId) {
		return { kind: 'archive', messageId: data.messageId };
	}
	// 'reply', a bare click, or an archive click missing an id: focus/open the
	// deep link (the reply/compose affordance lives in the reading pane itself).
	const linkId = data.threadId ?? data.messageId ?? '';
	return { kind: 'focus', url: `/inbox?t=${encodeURIComponent(linkId)}` };
}

/**
 * Pure: the chat click-through deep link. Carries `seq` (not messageId) —
 * ChatApp's `openChannelAt` (the jump-to-message substrate every click-through
 * uses) is seq-keyed, exactly why the payload carries `seq` in the first
 * place. Exported for unit tests.
 */
export function chatNotificationUrl(data: { channelId?: number; seq?: number }): string {
	return `/chat?channel=${data.channelId ?? ''}&seq=${data.seq ?? ''}`;
}

const notificationClientsPort: NotificationClientsPort = {
	async matchAll() {
		return await sw.clients.matchAll({ type: 'window', includeUncontrolled: true }) as WindowClient[];
	},
	async openWindow(url) {
		return await sw.clients.openWindow(url) as WindowClient | null;
	},
};

const notificationFetch = (input: RequestInfo | URL, init?: RequestInit) =>
	fetch(input, { ...init, credentials: 'include' });

type NotificationClickData = { type?: string; messageId?: string; threadId?: string; channelId?: number; seq?: number };
type NotificationClickCommandRunner = (command: Parameters<typeof runNotificationCommand>[0]) => Promise<unknown>;

export function handleNotificationClick(
	event: Pick<NotificationEvent, 'action' | 'notification' | 'waitUntil'>,
	runCommand: NotificationClickCommandRunner,
): void {
	const notification = event.notification;
	const data = (notification.data ?? {}) as NotificationClickData;
	notification.close();

	let command: Parameters<typeof runNotificationCommand>[0];
	if (data.type === 'chat') {
		command = { kind: 'focus', targetUrl: chatNotificationUrl(data) };
	} else {
		const route = routeNotificationClick(event.action, data);
		command = route.kind === 'archive'
			? { kind: 'archive', messageId: route.messageId, targetUrl: `/inbox?t=${encodeURIComponent(route.messageId)}` }
			: { kind: 'focus', targetUrl: route.url };
	}
	event.waitUntil(runCommand(command));
}

sw.addEventListener('notificationclick', (e) => {
	handleNotificationClick(e, (command) => runNotificationCommand(
		command,
		notificationFetch,
		notificationClientsPort,
		sw.location.origin,
	));
});
