// Shared focus trap: focus the node on mount, trap Tab/Shift+Tab within it,
// call onEscape on Escape, restore focus to the previously-focused element on destroy.
interface FocusTrapParams {
	onEscape?: () => void;
}

const FOCUSABLE =
	'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface ActiveTrap {
	node: HTMLElement;
}

const activeTraps: ActiveTrap[] = [];

export function focusTrap(node: HTMLElement, params: FocusTrapParams = {}) {
	let opts = params;
	const previouslyFocused = document.activeElement as HTMLElement | null;
	const trap = { node };
	activeTraps.push(trap);
	node.focus();

	function onKeydown(e: KeyboardEvent) {
		if (activeTraps[activeTraps.length - 1] !== trap) return;
		if (e.key === 'Escape') {
			e.preventDefault();
			opts.onEscape?.();
			return;
		}
		if (e.key !== 'Tab') return;
		const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
		if (items.length === 0) {
			e.preventDefault();
			node.focus();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		const inside = active !== null && node.contains(active);
		if (e.shiftKey && (!inside || active === first || active === node)) {
			e.preventDefault();
			last.focus();
		} else if (!e.shiftKey && (!inside || active === last || active === node)) {
			e.preventDefault();
			first.focus();
		}
	}

	function onFocusin(e: FocusEvent) {
		if (activeTraps[activeTraps.length - 1] !== trap || node.contains(e.target as Node)) return;
		node.focus();
	}

	document.addEventListener('keydown', onKeydown);
	document.addEventListener('focusin', onFocusin);
	return {
		update(p: FocusTrapParams) { opts = p; },
		destroy() {
			document.removeEventListener('keydown', onKeydown);
			document.removeEventListener('focusin', onFocusin);
			const wasTopmost = activeTraps[activeTraps.length - 1] === trap;
			const index = activeTraps.lastIndexOf(trap);
			if (index !== -1) activeTraps.splice(index, 1);
			if (!wasTopmost) return;

			const next = activeTraps[activeTraps.length - 1];
			if (next && (!previouslyFocused?.isConnected || !next.node.contains(previouslyFocused))) {
				next.node.focus();
			} else if (previouslyFocused?.isConnected) {
				previouslyFocused.focus();
			}
		},
	};
}
