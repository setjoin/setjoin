<svelte:options runes={true} />
<script lang="ts">
	import { messageTrace } from '$lib/api/delivery';
	import type { Trace } from '$lib/types/delivery';
	import Spinner from '$lib/components/ui/Spinner.svelte';
	import Tabs from '$lib/components/ui/Tabs.svelte';
	import type { TabItem } from '$lib/components/ui/Tabs.svelte';
	import IconButton from '$lib/components/ui/IconButton.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import type { ComponentProps } from 'svelte';
	import InboundTimeline from './InboundTimeline.svelte';
	import OutboundTimeline from './OutboundTimeline.svelte';
	import AuthResults from './AuthResults.svelte';
	import HeaderExplorer from './HeaderExplorer.svelte';
	import RawSource from './RawSource.svelte';
	import { httpRequest } from '$lib/http';

	let {
		emailId,
		rawUrl,
		open,
		onResend,
		onClose,
	}: {
		emailId: string;
		rawUrl: string;
		open: boolean;
		/** Resend after NDR — fresh compose seeded from the original message. Shown only when a recipient bounced. */
		onResend?: () => void;
		onClose: () => void;
	} = $props();

	// ── Trace state ──────────────────────────────────────────────────────────
	let loading = $state(false);
	let error = $state<string | null>(null);
	let trace = $state<Trace | null>(null);

	async function loadTrace() {
		loading = true;
		error = null;
		trace = null;
		try {
			trace = await messageTrace(emailId);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (!open) return;
		loadTrace();
	});

	// ── Raw fetch (lazy, shared across Headers / Raw / Auth-from-raw) ─────────
	let rawLoading = $state(false);
	let rawError = $state<string | null>(null);
	let rawText = $state<string | null>(null);

	async function ensureRaw() {
		if (rawText !== null || rawLoading) return;
		rawLoading = true;
		rawError = null;
		try {
			const res = await httpRequest(rawUrl, { method: 'GET' });
			rawText = await res.text();
		} catch (e) {
			rawError = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			rawLoading = false;
		}
	}

	// ── Tabs ──────────────────────────────────────────────────────────────────
	let activeTab = $state<'flow' | 'auth' | 'headers' | 'raw'>('flow');

	const tabItems = $derived<TabItem[]>([
		{
			id: 'flow',
			label: 'Flow',
			count: trace?.direction === 'outbound' ? (trace?.recipients?.length ?? undefined) : (trace?.hopCount ?? undefined),
		},
		{ id: 'auth', label: 'Auth' },
		{ id: 'headers', label: 'Headers' },
		{ id: 'raw', label: 'Raw' },
	]);

	function handleTabChange(id: string) {
		activeTab = id as typeof activeTab;
		if (id === 'headers' || id === 'raw') {
			ensureRaw();
		}
	}

	// ── Digest strip helpers ──────────────────────────────────────────────────
	function fmtTransit(ms: number | null | undefined): string {
		if (ms == null) return 'unknown';
		if (ms < 1000) return `${ms} ms`;
		if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
		const mins = Math.round(ms / 60000);
		return `${mins} min`;
	}

	// ── Outbound verdict digest (D-D4) ────────────────────────────────────────
	const isOutbound = $derived(trace?.direction === 'outbound');

	const outboundVerdict = $derived.by(() => {
		const recips = trace?.recipients ?? [];
		const total = recips.length;
		const delivered = recips.filter((r) => r.status === 'delivered').length;
		const bounced = recips.filter((r) => r.status === 'bounced').length;
		const retrying = recips.filter((r) => r.status === 'deferred').length;
		// Lead icon = the worst outcome: any bounce → danger; else any deferred → warning; else success.
		const leadIcon: { name: ComponentProps<typeof Icon>['name']; cls: string } =
			bounced > 0
				? { name: 'XCircle', cls: 'dp__digest-icon--bad' }
				: retrying > 0
					? { name: 'AlertTriangle', cls: 'dp__digest-icon--warn' }
					: { name: 'CheckCheck', cls: 'dp__digest-icon--ok' };
		const allDelivered = total > 0 && delivered === total && bounced === 0 && retrying === 0;
		let lead: string;
		if (allDelivered) {
			lead = total === 1 ? `Delivered to ${recips[0].email}` : `Delivered to all ${total} recipients`;
		} else {
			lead = `${delivered} of ${total} delivered`;
		}
		return { total, delivered, bounced, retrying, leadIcon, allDelivered, lead };
	});

	// D-D9 retention-skew: queue alive (overallStatus present) but per-recipient detail pruned.
	const retentionSkew = $derived(
		isOutbound && (trace?.recipients?.length ?? 0) === 0 && (trace?.overallStatus ?? '') !== '',
	);

	// ── Focus management ─────────────────────────────────────────────────────
	let panelEl = $state<HTMLDivElement | undefined>(undefined);

	const FOCUSABLE =
		'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

	function trapFocus(e: KeyboardEvent) {
		if (!panelEl) return;
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose();
			return;
		}
		if (e.key !== 'Tab') return;
		const items = Array.from(panelEl.querySelectorAll<HTMLElement>(FOCUSABLE));
		if (items.length === 0) { e.preventDefault(); panelEl.focus(); return; }
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		const inside = active !== null && panelEl.contains(active);
		if (e.shiftKey) {
			if (!inside || active === first || active === panelEl) { e.preventDefault(); last.focus(); }
		} else {
			if (!inside || active === last || active === panelEl) { e.preventDefault(); first.focus(); }
		}
	}

	$effect(() => {
		if (!open) return;
		const prev = document.activeElement as HTMLElement | null;
		// Move focus in after a microtask to allow DOM to settle
		const raf = requestAnimationFrame(() => {
			panelEl?.focus();
		});
		document.addEventListener('keydown', trapFocus);
		return () => {
			cancelAnimationFrame(raf);
			document.removeEventListener('keydown', trapFocus);
			prev?.focus();
		};
	});

	const uid = $props.id();
	const tabpanelId = $derived(`${uid}-tabpanel`);
</script>

{#if open}
	<div class="dp-backdrop" role="presentation" onmousedown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
		<div
			class="dp"
			role="dialog"
			aria-label="Delivery details"
			aria-modal="true"
			tabindex="-1"
			bind:this={panelEl}
		>
			<!-- Header row -->
			<div class="dp__head">
				<span class="dp__title">Delivery details</span>
				<IconButton label="Close" onclick={onClose}>
					<Icon name="X" size={16} />
				</IconButton>
			</div>

			<!-- Digest strip -->
			{#if trace && isOutbound && ((trace.recipients?.length ?? 0) > 0 || retentionSkew)}
				<!-- Outbound verdict-as-hero digest (D-D4) + retention-skew (D-D9) -->
				<div class="dp__digest dp__digest--verdict">
					<span class="dp__verdict">
						<Icon name={outboundVerdict.leadIcon.name} size={18} class="dp__digest-icon {outboundVerdict.leadIcon.cls}" />
						<span class="dp__verdict-text">{outboundVerdict.lead}</span>
					</span>
					{#if outboundVerdict.bounced > 0}
						<span class="dp__pill dp__pill--bad"><span class="dp__pill-dot"></span>{outboundVerdict.bounced} bounced</span>
					{/if}
					{#if outboundVerdict.retrying > 0}
						<span class="dp__pill dp__pill--warn"><span class="dp__pill-dot"></span>{outboundVerdict.retrying} retrying</span>
					{/if}
					<span class="dp__digest-spacer"></span>
					{#if onResend && outboundVerdict.bounced > 0}
						<!-- Resend after NDR: a brand-new compose seeded from this message (not
						     an un-bounce of the immutable queue row). Only offered when a bounce
						     is the reason there's something to resend. -->
						<Button variant="secondary" size="sm" onclick={onResend}>
							{#snippet icon()}<Icon name="Send" size={14} />{/snippet}
							{t('triage.resend')}
						</Button>
					{/if}
					<IconButton label="Refresh delivery status" size="sm" onclick={loadTrace}>
						<Icon name="RefreshCw" size={14} />
					</IconButton>
				</div>
			{:else if trace && !isOutbound && (trace.hops?.length ?? 0) > 0}
				<!-- Inbound hops digest (unchanged) -->
				<div class="dp__digest">
					<div class="dp__digest-item">
						<Icon name="Clock" size={14} class="dp__digest-icon dp__digest-icon--neutral" />
						<span class="dp__digest-val">{fmtTransit(trace.totalTransitMs)}</span>
						<span class="dp__digest-label">transit</span>
					</div>
					<div class="dp__digest-item">
						<Icon name="ArrowLeftRight" size={14} class="dp__digest-icon dp__digest-icon--neutral" />
						<span class="dp__digest-val">{trace.hopCount ?? trace.hops?.length ?? 0}</span>
						<span class="dp__digest-label">hops</span>
					</div>
					{#if trace.slowestHopIndex != null}
						<div class="dp__digest-item">
							<Icon name="AlertTriangle" size={14} class="dp__digest-icon dp__digest-icon--warn" />
							<span class="dp__digest-label">bottleneck at hop {trace.slowestHopIndex + 1}</span>
						</div>
					{/if}
				</div>
			{/if}

			<!-- Tabs strip -->
			<Tabs items={tabItems} active={activeTab} onChange={handleTabChange} />

			<!-- Tab body -->
			<div class="dp__body" role="tabpanel" id={tabpanelId} aria-label={tabItems.find((t) => t.id === activeTab)?.label ?? activeTab}>
				{#if activeTab === 'flow'}
					{#if isOutbound}
						<!-- Outbound: 0 recipients is NOT an error (retention skew) — gate the error on `error` only -->
						{#if loading}
							<div class="dp__center">
								<Spinner label="Checking delivery…" />
								<span class="dp__loading-label">Checking delivery…</span>
							</div>
						{:else if error}
							<div class="dp__center dp__center--error">
								<p class="dp__error-msg">Couldn't load delivery status</p>
								<button type="button" class="dp__retry" onclick={loadTrace}>Retry</button>
							</div>
						{:else if retentionSkew}
							<p class="dp__skew-msg">
								Per-recipient detail is no longer available (delivery history is kept for the
								configured retention window). Overall status is from the send queue.
							</p>
						{:else if trace}
							<OutboundTimeline recipients={trace.recipients ?? []} overallStatus={trace.overallStatus} />
						{/if}
					{:else if loading}
						<div class="dp__center">
							<Spinner label="Tracing delivery path…" />
							<span class="dp__loading-label">Tracing delivery path…</span>
						</div>
					{:else if error || (trace && (trace.hops?.length ?? 0) === 0)}
						<div class="dp__center dp__center--error">
							<p class="dp__error-msg">Couldn't load delivery path</p>
							<button type="button" class="dp__retry" onclick={loadTrace}>Retry</button>
						</div>
					{:else if trace}
						<InboundTimeline hops={trace.hops ?? []} slowestHopIndex={trace.slowestHopIndex ?? null} />
					{/if}
				{:else if activeTab === 'auth'}
					<AuthResults auth={trace?.auth} />
				{:else if activeTab === 'headers'}
					{#if rawLoading}
						<div class="dp__center">
							<Spinner label="Loading headers…" />
						</div>
					{:else if rawError}
						<p class="dp__error-msg">Couldn't load headers: {rawError}</p>
					{:else if rawText !== null}
						<HeaderExplorer {rawText} />
					{:else}
						<div class="dp__center">
							<Spinner label="Loading headers…" />
						</div>
					{/if}
				{:else if activeTab === 'raw'}
					{#if rawLoading}
						<div class="dp__center">
							<Spinner label="Loading raw message…" />
						</div>
					{:else if rawError}
						<p class="dp__error-msg">Couldn't load raw message: {rawError}</p>
					{:else if rawText !== null}
						<RawSource {rawText} />
					{:else}
						<div class="dp__center">
							<Spinner label="Loading raw message…" />
						</div>
					{/if}
				{/if}
			</div>
		</div>
	</div>
{/if}

<style>
	.dp-backdrop {
		position: fixed;
		inset: 0;
		background: var(--scrim);
		z-index: 1000;
		display: flex;
		align-items: flex-start;
		justify-content: center;
		padding: 9vh var(--space-4) var(--space-4); /* viewport-relative top offset */
	}

	.dp {
		background: var(--surface-card);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
		width: 100%;
		max-width: 640px;
		font-family: var(--font-sans);
		display: flex;
		flex-direction: column;
		max-height: 80vh;
		overflow: hidden;
		outline: none;
	}

	/* Header */
	.dp__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-3) var(--space-5) 0;
		flex: none;
	}

	.dp__title {
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
	}

	/* Digest strip */
	.dp__digest {
		display: flex;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-2) var(--space-5);
		border-bottom: 1px solid var(--border-subtle);
		flex: none;
	}

	.dp__digest--verdict {
		flex-wrap: wrap;
		gap: var(--space-3);
	}

	.dp__digest-item {
		display: flex;
		align-items: center;
		gap: var(--space-1);
	}

	/* Outbound verdict-as-hero */
	.dp__verdict {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.dp__verdict-text {
		font-size: var(--text-md);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.dp__digest-spacer {
		flex: 1;
	}

	.dp__pill {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		padding: 2px var(--space-2); /* 2px vertical — pill is intentionally compact */
		border-radius: var(--radius-full);
	}

	.dp__pill-dot {
		width: 7px; /* 7px status dot — structural constant */
		height: 7px;
		border-radius: 50%;
		flex: none;
	}

	.dp__pill--bad {
		background: var(--danger-bg);
		color: var(--danger-fg);
	}
	.dp__pill--bad .dp__pill-dot {
		background: var(--danger-solid);
	}

	.dp__pill--warn {
		background: var(--warning-bg);
		color: var(--warning-fg);
	}
	.dp__pill--warn .dp__pill-dot {
		background: var(--warning-solid);
	}

	.dp__skew-msg {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: var(--space-2) 0 0;
		line-height: var(--leading-normal);
	}

	.dp__digest-val {
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.dp__digest-label {
		font-size: var(--text-caption);
		color: var(--text-secondary);
	}

	/* Tab body */
	.dp__body {
		flex: 1;
		overflow-y: auto;
		padding: var(--space-3) var(--space-5);
		min-height: 0;
	}

	/* Loading / error center */
	.dp__center {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-8) 0;
	}

	.dp__center--error {
		color: var(--text-secondary);
	}

	.dp__loading-label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.dp__error-msg {
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: 0;
		text-align: center;
	}

	.dp__retry {
		all: unset;
		cursor: pointer;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-accent);
		text-decoration: underline;
		text-underline-offset: 2px;
		border-radius: var(--radius-sm);
	}

	.dp__retry:focus-visible {
		box-shadow: var(--focus-ring);
	}

	.dp__retry:hover {
		color: var(--accent-hover);
	}

	/* Icon colour helpers (applied via global class on Icon) */
	:global(.dp__digest-icon--neutral) {
		color: var(--text-secondary);
	}

	:global(.dp__digest-icon--warn) {
		color: var(--warning-solid);
	}

	:global(.dp__digest-icon--ok) {
		color: var(--success-solid);
	}

	:global(.dp__digest-icon--bad) {
		color: var(--danger-solid);
	}
</style>
