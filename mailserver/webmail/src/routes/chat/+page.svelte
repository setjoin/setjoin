<svelte:options runes={true} />
<script lang="ts">
	// The capability guard lives in the root layout's appForPath route guard
	// (src/routes/+layout.svelte) — the same mechanism mail/calendar/contacts/
	// tasks/drive use — so a disabled 'chat' app bounces to $firstEnabledApp
	// before this page ever mounts.
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import ChatApp from '$lib/components/chat/ChatApp.svelte';
	import { parseChatDeepLink, stripChatDeepLinkParams } from '$lib/chat/deepLink';

	// Deep-link wiring (A3.5 Task 4): a chat push notification's click-through
	// lands here as `/chat?channel=<id>&seq=<seq>` (service-worker.ts's
	// chatNotificationUrl). Parse once, hand the target to ChatApp's own
	// jump-to-message substrate (openChannelAt, Task 10), then strip the
	// params so a refresh/back doesn't replay the jump — same cleanup
	// convention as inbox/+page.svelte's consumeFolderParam/restoreDeepLink.
	let deepLinkChannel = $state<number | null>(null);
	let deepLinkSeq = $state<number | null>(null);

	$effect(() => {
		try {
			const target = parseChatDeepLink($page.url);
			if (!target) return;
			deepLinkChannel = target.channelId;
			deepLinkSeq = target.seq;
			void goto(stripChatDeepLinkParams($page.url), { replaceState: true, keepFocus: true, noScroll: true });
		} catch {
			/* $page/navigation may not be available in test */
		}
	});
</script>
<ChatApp {deepLinkChannel} {deepLinkSeq} />
