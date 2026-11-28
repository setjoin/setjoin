// Client inactivity timer. Resets on user activity; fires onIdle after the
// configured minutes. The server-side session_activity TTL is the tamper-proof
// backstop (D4 "both") — this is the instant-UX half.
export function startIdleTimer(minutes: number, onIdle: () => void): () => void {
	let timer: ReturnType<typeof setTimeout>;
	const reset = () => {
		clearTimeout(timer);
		timer = setTimeout(onIdle, minutes * 60 * 1000);
	};
	const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
	events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
	reset();
	return () => {
		clearTimeout(timer);
		events.forEach((e) => window.removeEventListener(e, reset));
	};
}
