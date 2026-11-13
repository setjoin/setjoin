<svelte:options runes={true} />

<script lang="ts">
	// WhiteboardPanel — Meet B3 Task 9 (spec §4.4, DN5, F15, design D2/D6/D9).
	// A MAIN-STAGE surface (design D6, wired by MeetApp.svelte) — NOT a side
	// panel, since a 320px canvas is useless. Client-only: no toggle (DN6),
	// no server surface. ALL React/Excalidraw lives behind the lazy
	// `$lib/meet/whiteboard` module, dynamically imported ONLY once this
	// component itself mounts — the ~1MB gz Excalidraw+React cost must never
	// land in the main bundle (DN5), so this file never statically imports
	// it (verified by this component's own test, source-guard style).
	//
	// D9: Excalidraw's internal chrome (incl. the "Export to chat" button
	// whiteboard.ts renders INSIDE it via renderTopRightUI) is accepted
	// as-is — the ONE sanctioned exception to this app's token-only styling
	// contract. Everything OUTSIDE the canvas (this panel's own header/
	// loading state) stays token-styled like every other Meet surface.
	import { onDestroy, onMount } from 'svelte';
	import type { MeetRoom } from '$lib/meet/room.svelte';
	import type { WhiteboardHandle, WhiteboardTheme } from '$lib/meet/whiteboard';
	import { chatStore } from '$lib/chat/store.svelte';
	import { IconButton, Spinner, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		room,
		theme,
		chatChannelId,
		onClose,
	}: {
		room: MeetRoom;
		theme: WhiteboardTheme;
		/** null: no bridged chat channel for this meeting (feature.chat off,
		 *  or attachments disabled) — the export-to-chat button never renders
		 *  (whiteboard.ts hides it entirely when onExport is undefined). */
		chatChannelId: number | null;
		onClose: () => void;
	} = $props();

	let canvasEl = $state<HTMLDivElement | undefined>();
	let handle: WhiteboardHandle | null = null;
	let loading = $state(true);
	let mountFailed = $state(false);

	/** "Export PNG to chat" (spec §4.4): the PNG rides the EXISTING A2 chat
	 *  attachment upload rail (chunked hash/upload + chat_message_send) — the
	 *  same rail Composer's file-picker uses — so it inherits Drive
	 *  governance/retention for free, no bespoke upload path. `send('', ...)`
	 *  mirrors Composer's own attachment-only-message shape (design C2). */
	async function exportToChat(blob: Blob): Promise<void> {
		if (chatChannelId == null) return;
		const channelId = chatChannelId;
		if (chatStore.activeChannelId !== channelId) await chatStore.openChannel(channelId);
		const file = new File([blob], `whiteboard-${Date.now()}.png`, { type: 'image/png' });
		await Promise.allSettled(chatStore.addAttachments(channelId, null, [file]));
		await chatStore.send('', null);
	}

	onMount(() => {
		let cancelled = false;
		void (async () => {
			try {
				// Lazy by construction: this is the ONLY import of this module
				// anywhere in the app, and it is dynamic — see the test guard.
				const { mountWhiteboard, wireRoomSync } = await import('$lib/meet/whiteboard');
				if (cancelled || !canvasEl) return;
				handle = mountWhiteboard(canvasEl, {
					theme,
					onChange: (elements) => room.sendWhiteboard(elements),
					onExport: chatChannelId != null ? (blob) => void exportToChat(blob) : undefined,
					onFull: () => showToast(t('meet.wb.full')),
				});
				wireRoomSync(room, handle);
			} catch {
				if (!cancelled) mountFailed = true;
			} finally {
				if (!cancelled) loading = false;
			}
		})();
		return () => {
			cancelled = true;
		};
	});

	onDestroy(() => {
		handle?.unmount();
		handle = null;
		// B3 retro fix (design #9): unregister the room's wb listeners — they
		// were wired to THIS panel's handle by wireRoomSync (whiteboard.ts);
		// leaving them registered would let an incoming wb/wb_req frame call
		// into a now-unmounted Excalidraw handle the next time one arrives,
		// right up until (if ever) a future WhiteboardPanel re-mounts and
		// overwrites them.
		room.onWhiteboard(null);
		room.onWhiteboardRequest(null);
	});

	// D9: kept in sync with the app theme. No reactive theme store exists
	// app-wide (theme lives on document.documentElement.dataset.theme,
	// applied imperatively by $lib/theme/apply.ts on toggle) — a
	// MutationObserver is the lazy way to notice a LIVE toggle while the
	// panel is open without inventing a new global store for one consumer.
	$effect(() => {
		if (typeof document === 'undefined' || typeof MutationObserver === 'undefined') return;
		const observer = new MutationObserver(() => {
			const next: WhiteboardTheme = document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
			handle?.setTheme(next);
		});
		observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
		return () => observer.disconnect();
	});
</script>

<div class="wb-panel">
	<div class="wb-panel__header">
		<h3 class="wb-panel__title">{t('meet.wb.open')}</h3>
		<span class="wb-panel__hint">{t('meet.wb.ephemeral')}</span>
		<IconButton label={t('common.close')} onclick={onClose}>
			<Icon name="X" size={16} />
		</IconButton>
	</div>
	<div class="wb-panel__canvas-wrap">
		<div class="wb-panel__canvas" bind:this={canvasEl}></div>
		{#if loading}
			<div class="wb-panel__loading">
				<Spinner />
				<span>{t('meet.wb.loading')}</span>
			</div>
		{:else if mountFailed}
			<div class="wb-panel__loading">{t('common.error')}</div>
		{/if}
	</div>
</div>

<style>
	.wb-panel {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-height: 0;
		background: var(--surface-base);
	}
	.wb-panel__header {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		flex: none;
	}
	.wb-panel__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.wb-panel__hint {
		flex: 1;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.wb-panel__canvas-wrap {
		position: relative;
		flex: 1;
		min-height: 0;
	}
	.wb-panel__canvas {
		position: absolute;
		inset: 0;
	}
	.wb-panel__loading {
		position: absolute;
		inset: 0;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		background: var(--surface-base);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
</style>
