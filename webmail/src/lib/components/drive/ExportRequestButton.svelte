<svelte:options runes={true} />

<script lang="ts">
	// P5 Task 11 — export/print request flow for secure/gxp versions (spec
	// §7, §9.2). regular/secure-with-allow grants immediately; gxp always
	// routes through the approval engine. CRITICAL (AUTOPLAN correction #5):
	// the single-use download URL is BURNING on GET — it is navigated with
	// window.location.assign(), NEVER rendered as an <a href>, since a
	// prefetcher/hover-preload on an anchor would consume the grant before
	// the user's own click.
	import * as api from '$lib/drive/api';
	import { DriveError, type ExportAction } from '$lib/drive/api';
	import { typedFetch } from '$lib/http';
	import { Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		versionId,
		action,
		classification,
	}: {
		versionId: number;
		action: ExportAction;
		classification: 'regular' | 'secure' | 'gxp';
	} = $props();

	type Phase = 'idle' | 'requesting' | 'pending' | 'approved' | 'denied' | 'expired' | 'blocked' | 'error';
	let phase = $state<Phase>('idle');
	let errorMessage = $state('');
	let requestId = $state<number | null>(null);
	let storedToken = $state<string | null>(null);

	const STORAGE_KEY = 'drive.exportTokens';

	interface StoredToken {
		requestId: number;
		token: string;
		versionId: number;
		action: ExportAction;
	}

	// ponytail: client-side token retention in sessionStorage — a server-side
	// re-issue verb is the upgrade if lost-token complaints show (plan Global
	// Constraints; §7's "token only on granted" is unimplementable since the
	// approval path mints its grant at DECIDE time from a hash it cannot
	// invert, so the plaintext must be handed to the requester at request
	// time or never at all). Session-scoped on purpose: the plaintext must
	// survive a page RELOAD (same tab) but NOT outlive the browser session —
	// the export token is a bearer capability and must not persist across
	// sessions with no logout cleanup.
	function readStore(): StoredToken[] {
		try {
			const raw = sessionStorage.getItem(STORAGE_KEY);
			return raw ? (JSON.parse(raw) as StoredToken[]) : [];
		} catch {
			return [];
		}
	}

	function writeStore(entries: StoredToken[]) {
		try {
			sessionStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
		} catch {
			/* sessionStorage unavailable (private mode / quota) — the request still
			 * succeeded server-side; the user just can't resume it after a reload. */
		}
	}

	function persist(entry: StoredToken) {
		writeStore([...readStore().filter((e) => e.requestId !== entry.requestId), entry]);
	}

	function clearPersisted(id: number) {
		writeStore(readStore().filter((e) => e.requestId !== id));
	}

	function errMsg(e: unknown): string {
		if (e instanceof DriveError) {
			if (e.code === 'BZ145') return '';
			if (e.code === 'BZ146') return t('drive.errors.BZ146');
			return e.detail;
		}
		return t('drive.export.failed');
	}

	async function submit() {
		phase = 'requesting';
		errorMessage = '';
		try {
			const res = await api.requestExport(versionId, action);
			if (res.status === 'granted') {
				window.location.assign(api.exportDownloadUrl(res.token));
				phase = 'idle';
				return;
			}
			// pending — persist so a page reload can resume polling instead of
			// silently losing the only copy of the plaintext token.
			requestId = res.requestId ?? null;
			storedToken = res.token;
			if (requestId !== null) {
				persist({ requestId, token: res.token, versionId, action });
			}
			phase = 'pending';
		} catch (e) {
			if (e instanceof DriveError && e.code === 'BZ145') {
				phase = 'blocked';
				return;
			}
			errorMessage = errMsg(e);
			phase = 'error';
		}
	}

	interface ApprovalRequestLite {
		id: number;
		status: string;
	}
	interface ApprovalsResponseLite {
		myRequests: ApprovalRequestLite[];
	}

	async function pollStatus() {
		if (requestId === null) return;
		try {
			const data = await typedFetch<ApprovalsResponseLite>('/api/me/approvals');
			const mine = data.myRequests.find((r) => r.id === requestId);
			if (!mine) return;
			if (mine.status === 'applied') {
				phase = 'approved';
			} else if (mine.status === 'denied') {
				phase = 'denied';
				clearPersisted(requestId);
			} else if (mine.status === 'expired' || mine.status === 'cancelled') {
				phase = 'expired';
				clearPersisted(requestId);
			}
			// 'pending' — keep waiting, next poll tick.
		} catch {
			/* transient poll failure — the next interval tick retries. */
		}
	}

	function downloadNow() {
		if (!storedToken || requestId === null) return;
		window.location.assign(api.exportDownloadUrl(storedToken));
		clearPersisted(requestId);
		phase = 'idle';
		storedToken = null;
		requestId = null;
	}

	// Resume a pending request that survived a page reload — restore from
	// localStorage and start polling immediately instead of forgetting it.
	$effect(() => {
		const existing = readStore().find((e) => e.versionId === versionId && e.action === action);
		if (existing) {
			requestId = existing.requestId;
			storedToken = existing.token;
			phase = 'pending';
			void pollStatus();
		}
	});

	const POLL_MS = 20_000;
	$effect(() => {
		if (phase !== 'pending') return;
		const id = setInterval(() => void pollStatus(), POLL_MS);
		return () => clearInterval(id);
	});

	let label = $derived(action === 'download' ? t('drive.export.request') : t('drive.export.requestPrint'));
	// Defensive no-op: regular spaces use the plain content-download link
	// (VersionDrawer) and never mount this button — this guard just keeps the
	// component honest if a future caller wires it up unconditionally.
	let isDriveClassificationGated = $derived(classification !== 'regular');
</script>

{#if isDriveClassificationGated}
<span class="erb" aria-live="polite">
	{#if phase === 'idle' || phase === 'requesting'}
		<Button variant="ghost" size="sm" disabled={phase === 'requesting'} onclick={submit}>{label}</Button>
	{:else if phase === 'pending'}
		<span class="erb__status">{t('drive.export.pending')}</span>
	{:else if phase === 'approved'}
		<Button variant="secondary" size="sm" onclick={downloadNow}>{t('drive.export.download')}</Button>
		<span class="erb__hint">{t('drive.export.singleUse')}</span>
	{:else if phase === 'denied'}
		<span class="erb__status erb__status--error">{t('drive.export.denied')}</span>
	{:else if phase === 'expired'}
		<span class="erb__status erb__status--error">{t('drive.export.expired')}</span>
	{:else if phase === 'blocked'}
		<span class="erb__status">{t('drive.export.blockedWormPending')}</span>
	{:else if phase === 'error'}
		<span class="erb__status erb__status--error">{errorMessage}</span>
	{/if}
</span>
{/if}

<style>
	.erb {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.erb__status {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.erb__status--error {
		color: var(--danger-fg);
	}
	.erb__hint {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
