import { onMount } from 'svelte';

type ShortcutHandler = () => void;
type ShortcutOptions = { ctrl?: boolean; meta?: boolean; shift?: boolean };

interface ShortcutEntry {
	key: string;
	handler: ShortcutHandler;
	options: ShortcutOptions;
}

let shortcuts: ShortcutEntry[] = [];
let listenerAdded = false;

function handleKeydown(e: KeyboardEvent) {
	// Never intercept when user is typing in an input, textarea, or contenteditable
	const active = document.activeElement as HTMLElement | null;
	const tag = active?.tagName;
	const isContentEditable = active?.isContentEditable ?? false;
	if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || isContentEditable) {
		return;
	}

	for (const s of shortcuts) {
		const keyMatch = e.key.toLowerCase() === s.key.toLowerCase();
		const ctrlMatch = s.options.ctrl ? (e.ctrlKey || e.metaKey) : true;
		const metaMatch = s.options.meta ? e.metaKey : true;
		const shiftMatch = s.options.shift ? e.shiftKey : true;

		if (keyMatch && ctrlMatch && metaMatch && shiftMatch) {
			e.preventDefault();
			s.handler();
			return;
		}
	}
}

export function registerShortcut(
	key: string,
	handler: ShortcutHandler,
	options: ShortcutOptions = {}
): () => void {
	const entry: ShortcutEntry = { key: key.toLowerCase(), handler, options };
	shortcuts.push(entry);

	if (!listenerAdded) {
		document.addEventListener('keydown', handleKeydown);
		listenerAdded = true;
	}

	// Return cleanup function
	return () => {
		shortcuts = shortcuts.filter((s) => s !== entry);
		if (shortcuts.length === 0 && listenerAdded) {
			document.removeEventListener('keydown', handleKeydown);
			listenerAdded = false;
		}
	};
}

// Pre-defined Gmail-style shortcut map
export const EMAIL_SHORTCUTS = {
	compose: 'c',
	reply: 'r',
	replyAll: 'a',
	forward: 'f',
	archive: 'e',
	delete: '#',
	star: 's',
	snooze: 'z',
	markRead: 'i',
	markUnread: 'u',
	nextMessage: 'j',
	prevMessage: 'k',
	search: '/',
	commandPalette: { key: 'k', ctrl: true },
	undo: 'z',
} as const;
