import { SHELL_MANIFEST_PATH, SHELL_PROTOCOL_VERSION } from './sw-generation';

export interface ServiceWorkerGenerationCoordinator {
	setSafeToActivate(safe: boolean): void;
	dispose(): void;
}

interface CandidateEnvelope {
	protocolVersion?: unknown;
	buildId?: unknown;
}

function focusedWorkIsUnsafe(): boolean {
	const active = document.activeElement as HTMLElement | null;
	if (!active) return false;
	return active.matches('input, textarea, select, [contenteditable="true"], [aria-busy="true"]');
}

async function candidateBuildId(): Promise<string | null> {
	try {
		const response = await fetch(SHELL_MANIFEST_PATH, { cache: 'no-store', credentials: 'same-origin' });
		if (!response.ok || response.redirected || new URL(response.url).origin !== location.origin) return null;
		const value = await response.json() as CandidateEnvelope;
		return value.protocolVersion === SHELL_PROTOCOL_VERSION && typeof value.buildId === 'string' && value.buildId.length > 0
			? value.buildId
			: null;
	} catch {
		return null;
	}
}

/**
 * Coordinates the prompt-free safe boundary for an already installed worker.
 * The worker remains waiting while a compose/form/upload/Meet boundary is live;
 * after activation the new document must mount and acknowledge its exact build.
 */
export function installServiceWorkerGenerationCoordinator(
	currentBuildId: string,
	initiallySafe = true,
): ServiceWorkerGenerationCoordinator {
	if (!('serviceWorker' in navigator)) return { setSafeToActivate() {}, dispose() {} };
	let safe = initiallySafe;
	let disposed = false;
	let activatingBuildId: string | null = null;
	let registration: ServiceWorkerRegistration | null = null;

	const acknowledgeMounted = () => {
		navigator.serviceWorker.controller?.postMessage({
			type: 'SETJOIN_SHELL_MOUNTED',
			protocolVersion: SHELL_PROTOCOL_VERSION,
			buildId: currentBuildId,
		});
	};

	const maybeActivate = async () => {
		if (disposed || !safe || document.visibilityState !== 'visible' || focusedWorkIsUnsafe()) return;
		registration ??= (await navigator.serviceWorker.getRegistration()) ?? null;
		const waiting = registration?.waiting;
		if (!waiting) return;
		const buildId = await candidateBuildId();
		if (!buildId || disposed || !safe || focusedWorkIsUnsafe()) return;
		activatingBuildId = buildId;
		waiting.postMessage({
			type: 'SETJOIN_ACTIVATE_CANDIDATE',
			protocolVersion: SHELL_PROTOCOL_VERSION,
			buildId,
		});
	};

	const onStateChange = () => { void maybeActivate(); };
	const onUpdateFound = () => registration?.installing?.addEventListener('statechange', onStateChange);
	const onControllerChange = () => {
		if (!activatingBuildId) return;
		const key = `setjoin-sw-reload-v1:${activatingBuildId}`;
		if (sessionStorage.getItem(key) === '1') return;
		sessionStorage.setItem(key, '1');
		location.reload();
	};
	const onPotentialSafeBoundary = () => { void maybeActivate(); };

	void navigator.serviceWorker.ready.then((ready) => {
		if (disposed) return;
		registration = ready;
		registration.addEventListener('updatefound', onUpdateFound);
		// Two frames mean the Svelte tree has committed, painted, and reached the
		// useful-shell acknowledgement point for this exact executable build.
		requestAnimationFrame(() => requestAnimationFrame(acknowledgeMounted));
		void maybeActivate();
	});
	navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
	document.addEventListener('visibilitychange', onPotentialSafeBoundary);
	document.addEventListener('focusout', onPotentialSafeBoundary);

	return {
		setSafeToActivate(next) {
			safe = next;
			if (safe) void maybeActivate();
		},
		dispose() {
			disposed = true;
			registration?.removeEventListener('updatefound', onUpdateFound);
			registration?.installing?.removeEventListener('statechange', onStateChange);
			navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
			document.removeEventListener('visibilitychange', onPotentialSafeBoundary);
			document.removeEventListener('focusout', onPotentialSafeBoundary);
		},
	};
}
