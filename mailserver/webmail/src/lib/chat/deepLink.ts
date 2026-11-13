// A3.5 Task 4 — chat push deep-link wiring. A chat push notification's
// click-through lands at `/chat?channel=<id>&seq=<seq>`
// (service-worker.ts's chatNotificationUrl); these two pure helpers do the
// route-level parsing so the actual $page/goto wiring in +page.svelte stays
// thin, untested glue — same split as service-worker.ts's
// shouldServeShell/buildMailNotification/routeNotificationClick.

/**
 * Parse a chat deep-link URL's `?channel=&seq=` params. Returns null when
 * either is absent or non-numeric — no partial jump (openChannelAt needs
 * both a channelId and a seq).
 */
export function parseChatDeepLink(url: URL): { channelId: number; seq: number } | null {
	const channelParam = url.searchParams.get('channel');
	const seqParam = url.searchParams.get('seq');
	if (!channelParam || !seqParam) return null;
	const channelId = Number(channelParam);
	const seq = Number(seqParam);
	if (!Number.isFinite(channelId) || !Number.isFinite(seq)) return null;
	return { channelId, seq };
}

/**
 * The URL with the deep-link params stripped, so a refresh/back never
 * replays the jump (mirrors inbox/+page.svelte's consumeFolderParam/
 * restoreDeepLink cleanup convention).
 */
export function stripChatDeepLinkParams(url: URL): string {
	const stripped = new URL(url);
	stripped.searchParams.delete('channel');
	stripped.searchParams.delete('seq');
	return stripped.pathname + stripped.search;
}
