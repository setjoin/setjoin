// Pure calendar formatting helpers — kept out of the .svelte component so the
// CSS-injection guard (safeColor) and the timezone day-key (localDayKey) are
// unit-testable without a DOM.

// cal.color is unconstrained `text` and, for a SHARED calendar, set by another
// user (attacker-controlled). It is interpolated into inline
// style="background:{...}" — Svelte escapes the attribute quote but not the CSS
// grammar inside it, so a value like
// 'red;position:fixed;inset:0;width:100vw;height:100vh' would inject arbitrary
// declarations (overlay/clickjacking) and url() would leak the viewer's IP.
// Only #hex passes; anything else falls back to the design-system token.
const HEX_COLOR = /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

export function safeColor(c: string | undefined | null): string {
	return c && HEX_COLOR.test(c.trim()) ? c.trim() : 'var(--app-calendar)';
}

// The event's LOCAL calendar day. start_at is TIMESTAMPTZ rendered with offset;
// a UTC date slice (substring(0,10) / toISOString()) is off-by-one for a
// negative-UTC-offset user (an evening event renders under the next UTC day).
// Month/week views already group by local `new Date(ev.start)`, so keying the
// day view locally keeps all three views in agreement.
export function localDayKey(d: Date): string {
	const y = d.getFullYear();
	const m = String(d.getMonth() + 1).padStart(2, '0');
	const day = String(d.getDate()).padStart(2, '0');
	return `${y}-${m}-${day}`;
}
