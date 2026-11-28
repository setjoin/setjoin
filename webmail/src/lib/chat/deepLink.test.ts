import { describe, it, expect } from 'vitest';
import { parseChatDeepLink, stripChatDeepLinkParams } from './deepLink';

describe('parseChatDeepLink', () => {
	it('parses valid channel/seq params', () => {
		expect(parseChatDeepLink(new URL('https://app/chat?channel=7&seq=42'))).toEqual({ channelId: 7, seq: 42 });
	});

	it('returns null when channel is missing', () => {
		expect(parseChatDeepLink(new URL('https://app/chat?seq=42'))).toBeNull();
	});

	it('returns null when seq is missing', () => {
		expect(parseChatDeepLink(new URL('https://app/chat?channel=7'))).toBeNull();
	});

	it('returns null for non-numeric params (no partial/garbage jump)', () => {
		expect(parseChatDeepLink(new URL('https://app/chat?channel=abc&seq=xyz'))).toBeNull();
	});

	it('returns null when neither param is present', () => {
		expect(parseChatDeepLink(new URL('https://app/chat'))).toBeNull();
	});
});

describe('stripChatDeepLinkParams', () => {
	it('removes channel/seq but keeps other params + path', () => {
		expect(stripChatDeepLinkParams(new URL('https://app/chat?channel=7&seq=42&foo=bar'))).toBe('/chat?foo=bar');
	});

	it('is a no-op (bare path) when neither param is present', () => {
		expect(stripChatDeepLinkParams(new URL('https://app/chat'))).toBe('/chat');
	});
});
