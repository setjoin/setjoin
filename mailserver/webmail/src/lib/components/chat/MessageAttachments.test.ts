// MessageAttachments.test.ts — the voice/image/file attachment genres (Chat
// A2 Task 8's image/file surface, A3 QoL Task 15's voice player), split out
// of MessageRow.test.ts (whole-pipeline review arch #9). Voice is bundled
// with image/file here (not its own file) because all three share the
// SAME node-meta -> content-blob resolution pipeline this component owns —
// see MessageAttachments.svelte's own header comment. MessageRow.test.ts
// keeps one thin smoke test proving the row still mounts this component;
// every other attachment behavior lives here.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import MessageAttachments from './MessageAttachments.svelte';
import type { StoreMessage } from '$lib/chat/store.svelte';
import type { ChatAttachment, ChatMessage } from '$lib/chat/api';
import { jmapSession } from '$lib/stores/session';
import { user } from '$lib/stores/auth';

const typedFetch = vi.fn();
vi.mock('$lib/http', async () => {
	const actual = await vi.importActual<typeof import('$lib/http')>('$lib/http');
	return { ...actual, typedFetch: (...a: unknown[]) => typedFetch(...a) };
});

const fetchVersionContent = vi.fn();
const fetchVersionPreview = vi.fn();
vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		fetchVersionContent: (...a: unknown[]) => fetchVersionContent(...a),
		fetchVersionPreview: (...a: unknown[]) => fetchVersionPreview(...a),
	};
});

function attachment(over: Partial<ChatAttachment> = {}): ChatAttachment {
	return { id: 1, fileNodeId: 5, filename: 'pic.png', contentType: 'image/png', sizeBytes: 2048, ...over };
}

function msg(over: Partial<StoreMessage> = {}): StoreMessage {
	return {
		messageId: 1,
		channelId: 1,
		seq: 1,
		authorId: 99,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: 'hello',
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-11T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
		status: 'sent',
		...over,
	} as StoreMessage;
}

const createObjectURL = vi.fn(() => 'blob:mock-url');
const revokeObjectURL = vi.fn();

beforeEach(() => {
	typedFetch.mockReset();
	fetchVersionContent.mockReset();
	fetchVersionPreview.mockReset();
	jmapSession.set(null);
	user.set(null);
	createObjectURL.mockClear();
	revokeObjectURL.mockClear();
	URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
	URL.revokeObjectURL = revokeObjectURL;
});

afterEach(() => {
	vi.clearAllMocks();
});

describe('MessageAttachments — Chat A2 Task 8 attachments', () => {
	it('no attachments -> no attachment markup at all', () => {
		const { container } = render(MessageAttachments, { message: msg({ attachments: [] }) });
		expect(container.querySelector('.mrow__attachments')).toBeNull();
	});

	it('an image attachment resolves node-meta then fetches content as a blob and renders a thumbnail', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionContent.mockResolvedValue({ blob: async () => new Blob(['x'], { type: 'image/png' }) });
		const { container } = render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(typedFetch).toHaveBeenCalledWith('/api/drive/nodes?ids=5'));
		await waitFor(() => expect(screen.getByAltText('pic.png')).toBeTruthy());
		expect((screen.getByAltText('pic.png') as HTMLImageElement).src).toBe('blob:mock-url');
		expect(container.querySelector('.mrow__thumb')).toBeTruthy();
	});

	it('a view-only guest never fetches raw image bytes and sees the metadata-only posture', async () => {
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: {
				apps: { chat: true },
				features: { assist: false, bundles: false },
				guest: { allowDownload: false },
			},
		} as never);
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		const { container } = render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(screen.getByText('View-only: original file unavailable')).toBeTruthy());
		expect(fetchVersionContent).not.toHaveBeenCalled();
		expect(container.querySelector('img')).toBeNull();
	});

	it('a known auth guest remains view-only when JMAP capability loading failed', async () => {
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		const { container } = render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(screen.getByText('View-only: original file unavailable')).toBeTruthy());
		expect(fetchVersionContent).not.toHaveBeenCalled();
		expect(container.querySelector('img')).toBeNull();
	});

	it('a view-only guest opens an office rendition in the watermarked SecureViewer', async () => {
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: {
				apps: { chat: true },
				features: { assist: false, bundles: false },
				guest: { allowDownload: false },
			},
		} as never);
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionPreview.mockResolvedValue({ status: 200, blob: async () => new Blob(['pdf'], { type: 'application/pdf' }) });
		const { container } = render(MessageAttachments, {
			message: msg({ attachments: [attachment({ filename: 'brief.docx', contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' })] }),
		});
		await waitFor(() => expect(screen.getByLabelText('Preview attachment')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Preview attachment'));
		await waitFor(() => expect(fetchVersionPreview).toHaveBeenCalledWith(9, { allowStatuses: [404] }));
		expect(container.querySelector('.watermark')).toBeTruthy();
		expect(fetchVersionContent).not.toHaveBeenCalled();
		expect(screen.queryByLabelText('Download')).toBeNull();
	});

	it('row height (the fixed thumbnail box) is unchanged across the <img> load event — A1 scroll-anchor pin', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionContent.mockResolvedValue({ blob: async () => new Blob(['x'], { type: 'image/png' }) });
		const { container } = render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		const box = container.querySelector('.mrow__thumb') as HTMLElement;
		const heightBefore = getComputedStyle(box).height;
		const widthBefore = getComputedStyle(box).width;
		// Sanity must assert the exact fixed px values, not just non-empty: jsdom has no
		// layout engine, so an unset height/width still computes to a non-'' 'auto' — a
		// weaker "not.toBe('')" guard passes even with the dimensions deleted from the
		// component, making the whole pin vacuous (mutation-verified).
		expect(heightBefore).toBe('120px');
		expect(widthBefore).toBe('160px');
		await waitFor(() => expect(container.querySelector('.mrow__thumb-img')).toBeTruthy());
		const img = container.querySelector('.mrow__thumb-img') as HTMLImageElement;
		await fireEvent.load(img);
		expect(getComputedStyle(box).height).toBe(heightBefore);
		expect(getComputedStyle(box).width).toBe(widthBefore);
	});

	it('a non-image attachment renders a file chip (name + size) with download + Open in Drive once resolved', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		render(MessageAttachments, {
			message: msg({ attachments: [attachment({ filename: 'report.pdf', contentType: 'application/pdf', sizeBytes: 3072 })] }),
		});
		expect(screen.getByText('report.pdf')).toBeTruthy();
		expect(screen.getByText('3.0 KB')).toBeTruthy();
		await waitFor(() => expect(screen.getByLabelText('Open in Drive')).toBeTruthy());
		const link = screen.getByLabelText('Open in Drive') as HTMLAnchorElement;
		expect(link.href).toContain('/api/drive/versions/9/content');
		expect(fetchVersionContent).not.toHaveBeenCalled(); // non-image never fetches a blob
	});

	it('node-meta lookup returning nothing (deleted/invisible node) renders a tombstone chip', async () => {
		typedFetch.mockResolvedValue([]);
		render(MessageAttachments, { message: msg({ attachments: [attachment({ filename: 'gone.png' })] }) });
		await waitFor(() => expect(screen.getByText('Attachment unavailable')).toBeTruthy());
		expect(screen.queryByAltText('gone.png')).toBeNull();
	});

	it('an <img> onerror flips the thumbnail to a tombstone', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionContent.mockResolvedValue({ blob: async () => new Blob(['x'], { type: 'image/png' }) });
		render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(screen.getByAltText('pic.png')).toBeTruthy());
		await fireEvent.error(screen.getByAltText('pic.png'));
		expect(screen.getByText('Attachment unavailable')).toBeTruthy();
	});

	it('an optimistic placeholder attachment (fileNodeId 0, still sending) is skipped — no network call, no tombstone', () => {
		const { container } = render(MessageAttachments, {
			message: msg({ status: 'sending', attachments: [attachment({ fileNodeId: 0 })] }),
		});
		expect(typedFetch).not.toHaveBeenCalled();
		expect(container.querySelector('.mrow__attachments')).toBeNull();
	});

	it('clicking a resolved thumbnail opens an M1 Dialog lightbox', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionContent.mockResolvedValue({ blob: async () => new Blob(['x'], { type: 'image/png' }) });
		render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(screen.getByAltText('pic.png')).toBeTruthy());
		await fireEvent.click(screen.getByAltText('pic.png').closest('button')!);
		expect(screen.getByRole('dialog')).toBeTruthy();
	});

	it('multiple images render in a flex-wrap row; non-image files stack in a separate list below', () => {
		render(MessageAttachments, {
			message: msg({
				attachments: [
					attachment({ id: 1, fileNodeId: 5, filename: 'a.png', contentType: 'image/png' }),
					attachment({ id: 2, fileNodeId: 6, filename: 'b.png', contentType: 'image/png' }),
					attachment({ id: 3, fileNodeId: 7, filename: 'c.pdf', contentType: 'application/pdf' }),
				],
			}),
		});
		const images = document.querySelectorAll('.mrow__images li');
		const files = document.querySelectorAll('.mrow__files li');
		expect(images.length).toBe(2);
		expect(files.length).toBe(1);
	});

	it('the attachment lists carry role=list for a11y', () => {
		render(MessageAttachments, { message: msg({ attachments: [attachment()] }) });
		expect(document.querySelector('.mrow__images')?.getAttribute('role')).toBe('list');
	});
});

describe('MessageAttachments — A3 QoL Task 15: voice messages', () => {
	function voiceMsg(over: Partial<ChatMessage> = {}): StoreMessage {
		return msg({
			messageId: 20,
			msgType: 'voice',
			body: '',
			payload: { durationMs: 4200 },
			attachments: [{ id: 1, fileNodeId: 5, filename: 'clip.webm', contentType: 'audio/webm', sizeBytes: 900 }],
			...over,
		}) as StoreMessage;
	}

	it('a ready voice attachment renders a native <audio> player, not the generic file-chip UI', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		const { container } = render(MessageAttachments, { message: voiceMsg() });
		await waitFor(() => expect(screen.getByTestId('voice-player')).toBeTruthy());
		const audio = screen.getByTestId('voice-player') as HTMLAudioElement;
		expect(audio.src).toContain('/api/drive/versions/9/content');
		expect(container.querySelector('.mrow__files')).toBeNull();
		expect(container.querySelector('.mrow__images')).toBeNull();
	});

	it('an unresolved/deleted voice attachment shows the unavailable tombstone, never a broken player', async () => {
		typedFetch.mockResolvedValue([]);
		render(MessageAttachments, { message: voiceMsg() });
		await waitFor(() => expect(screen.getByText('Attachment unavailable')).toBeTruthy());
		expect(screen.queryByTestId('voice-player')).toBeNull();
	});
});
