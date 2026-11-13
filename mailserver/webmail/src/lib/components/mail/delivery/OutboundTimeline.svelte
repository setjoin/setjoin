<svelte:options runes={true} />
<script lang="ts">
	import type { ComponentProps } from 'svelte';
	import type { Recipient, Attempt } from '$lib/types/delivery';
	import Icon from '$lib/components/Icon.svelte';
	import { formatRelativeTime } from '$lib/i18n';

	type IconName = ComponentProps<typeof Icon>['name'];

	// `overallStatus` is part of the trace contract (the panel digest renders it); the
	// per-recipient timeline itself doesn't display it, so we accept-and-ignore it here.
	let { recipients, overallStatus: _overallStatus = undefined }: { recipients: Recipient[]; overallStatus?: string } = $props();

	// D-D5: auto-expand the first `bounced` recipient on mount (its "why" is the payload).
	const firstBouncedIdx = $derived(recipients.findIndex((r) => r.status === 'bounced'));
	let openIdx = $state<number | null>(null);
	let initialized = $state(false);
	$effect(() => {
		// Run once on mount: seed openIdx from the first bounce (or stay collapsed).
		if (!initialized) {
			initialized = true;
			openIdx = firstBouncedIdx >= 0 ? firstBouncedIdx : null;
		}
	});

	// ── D-D3 chip taxonomy: icon + WORD + colour. The WORD is the colour-blind guarantee. ──
	type ChipMeta = { cls: string; icon: IconName; label: string };
	const CHIP: Record<Recipient['status'], ChipMeta> = {
		delivered: { cls: 'chip--ok', icon: 'CheckCheck', label: 'Delivered' },
		bounced: { cls: 'chip--bad', icon: 'XCircle', label: 'Bounced' },
		deferred: { cls: 'chip--warn', icon: 'Clock', label: 'Retrying' },
		queued: { cls: 'chip--info', icon: 'Clock', label: 'Queued' },
	};

	// ── Relative time via the app's i18n util (never a raw timestamp). ──
	// Returns a human "{rel}" fragment for an ISO string relative to now (past or future).
	function relParts(iso: string | null): { rel: string; future: boolean } | null {
		if (!iso) return null;
		const t = Date.parse(iso);
		if (Number.isNaN(t)) return null;
		const diffMs = t - Date.now(); // >0 future, <0 past
		const future = diffMs > 0;
		const absSec = Math.round(Math.abs(diffMs) / 1000);
		let value: number;
		let unit: Intl.RelativeTimeFormatUnit;
		if (absSec < 60) {
			value = absSec;
			unit = 'second';
		} else if (absSec < 3600) {
			value = Math.round(absSec / 60);
			unit = 'minute';
		} else if (absSec < 86400) {
			value = Math.round(absSec / 3600);
			unit = 'hour';
		} else {
			value = Math.round(absSec / 86400);
			unit = 'day';
		}
		// Intl.RelativeTimeFormat: negative => past ("2 minutes ago"), positive => future ("in 8 minutes").
		const rel = formatRelativeTime(future ? value : -value, unit);
		return { rel, future };
	}

	// "delivered {rel} ago" — strip the locale's directional wrapper to a bare "{rel} ago".
	function agoFragment(iso: string | null): string {
		const p = relParts(iso);
		return p ? p.rel : 'recently';
	}

	function codeText(code: number | null, text: string | null): string {
		const parts: string[] = [];
		if (code != null) parts.push(String(code));
		if (text) parts.push(text);
		return parts.join(' ');
	}

	function attemptNumber(r: Recipient): number {
		return r.attempts.length > 0 ? r.attempts[r.attempts.length - 1].n : r.attempts.length;
	}

	// Deferred timing fragment (D-D8): future → "next attempt in ~{rel}"; past → "retrying now";
	// null → "retrying". Always suffix "(attempt {n})".
	function deferredWhen(r: Recipient): string {
		const p = relParts(r.nextAttemptAt);
		const attemptNo = attemptNumber(r);
		if (p && p.future) return `next attempt in ~${p.rel.replace(/^in\s+/i, '')} (attempt ${attemptNo})`;
		if (p && !p.future) return `retrying now (attempt ${attemptNo})`;
		return `retrying (attempt ${attemptNo})`;
	}

	// Inline sub-line for the statuses with no mx/code (queued) — D-D3 templates.
	function subText(r: Recipient): string {
		switch (r.status) {
			case 'queued':
				return 'waiting to send — not yet attempted';
			default:
				return '';
		}
	}

	// ── Truthful aria-label, built by OMITTING null clauses (D-D8). ──
	function ariaLabel(r: Recipient, i: number, n: number): string {
		const parts: string[] = [`Recipient ${i + 1} of ${n}`, r.email];
		switch (r.status) {
			case 'delivered':
				parts.push('delivered');
				if (r.mxHost) parts.push(`to ${r.mxHost}`);
				if (r.lastSmtpCode != null) parts.push(`SMTP ${r.lastSmtpCode}`);
				break;
			case 'bounced':
				parts.push('bounced');
				if (r.mxHost) parts.push(`rejected by ${r.mxHost}`);
				if (r.lastSmtpCode != null) parts.push(`SMTP ${r.lastSmtpCode}`);
				if (r.lastSmtpText) parts.push(r.lastSmtpText);
				break;
			case 'deferred': {
				parts.push('deferred', 'retrying');
				const p = relParts(r.nextAttemptAt);
				if (p && p.future) parts.push(`next attempt ${p.rel}`);
				parts.push(`attempt ${attemptNumber(r)}`);
				if (r.lastSmtpCode != null) parts.push(`SMTP ${r.lastSmtpCode}`);
				break;
			}
			case 'queued':
				parts.push('queued', 'not yet attempted');
				break;
		}
		return parts.join(', ');
	}

	// ── Per-attempt expanded value: "{rel} · {mx} · {TLS?} · {code} {text}" (D-D6). ──
	function attemptValue(a: Attempt): { when: string; mx: string | null; tls: boolean; codeText: string } {
		return {
			when: a.at ? agoFragment(a.at) : 'time unknown',
			mx: a.mxHost,
			tls: a.tls,
			codeText: codeText(a.smtpCode, a.smtpText),
		};
	}

	function toggle(i: number) {
		openIdx = openIdx === i ? null : i;
	}

	const n = $derived(recipients.length);
</script>

<ol class="rcpts" role="list">
	{#each recipients as r, i (r.email)}
		{@const chip = CHIP[r.status]}
		<li class="rcpt" class:rcpt--open={openIdx === i}>
			<button
				type="button"
				class="rcpt__btn"
				aria-expanded={openIdx === i}
				aria-label={ariaLabel(r, i, n)}
				onclick={() => toggle(i)}
			>
				<span class="chip {chip.cls}">
					<Icon name={chip.icon} size={14} class="chip__ic" />
					<span class="chip__word">{chip.label}</span>
				</span>
				<span class="rcpt__main">
					<span class="rcpt__email">{r.email}</span>
					<span class="rcpt__sub">
						{#if r.status === 'delivered'}
							<!-- D-D11: no {code} inline on the happy path -->
							{#if r.mxHost}to <span class="mx">{r.mxHost}</span> · delivered {agoFragment(r.deliveredAt)}{:else}delivered {agoFragment(r.deliveredAt)}{/if}
						{:else if r.status === 'bounced'}
							{#if r.mxHost}rejected by <span class="mx">{r.mxHost}</span>{:else}rejected{/if}
							{#if codeText(r.lastSmtpCode, r.lastSmtpText)} · <span class="rcpt__code">{codeText(r.lastSmtpCode, r.lastSmtpText)}</span>{/if}
						{:else if r.status === 'deferred'}
							{deferredWhen(r)}
							{#if codeText(r.lastSmtpCode, r.lastSmtpText)} · <span class="rcpt__code">{codeText(r.lastSmtpCode, r.lastSmtpText)}</span>{/if}
						{:else}
							{subText(r)}
						{/if}
					</span>
				</span>
				<span class="chev" aria-hidden="true">›</span>
			</button>
			{#if openIdx === i}
				<div class="rcpt__detail">
					{#if r.attempts.length === 0}
						<p class="att__empty">No delivery attempts have been made yet.</p>
					{:else}
						<div class="att">
							{#each r.attempts as a, ai (a.n)}
								{@const v = attemptValue(a)}
								{#if ai > 0}<span class="att__sep" aria-hidden="true"></span>{/if}
								<span class="att__n">attempt {a.n}</span>
								<span class="att__v">
									{v.when}{#if v.mx} · <span class="mono">{v.mx}</span>{/if}{#if v.tls} · TLS{/if}{#if v.codeText} · <span class="mono">{v.codeText}</span>{/if}
								</span>
							{/each}
						</div>
					{/if}
				</div>
			{/if}
		</li>
	{/each}
</ol>

<style>
	.rcpts {
		list-style: none;
		margin: 0;
		padding: 0;
	}

	.rcpt {
		border-bottom: 1px solid var(--border-subtle);
	}

	.rcpt__btn {
		all: unset;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-2);
		width: 100%;
		box-sizing: border-box;
	}

	.rcpt__btn:hover {
		background: var(--surface-hover);
		border-radius: var(--radius-sm);
	}

	.rcpt__btn:focus-visible {
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-sm);
	}

	/* Fixed-width chip column (104px structural constant) so emails left-align.
	   The chip WORD never truncates — it is the colour-blind guarantee. */
	.chip {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		flex: none;
		width: 104px; /* structural constant — fixed chip column, no token */
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
	}

	.chip :global(.chip__ic) {
		flex: none;
	}

	.chip__word {
		white-space: nowrap; /* never truncate the word */
	}

	.chip--ok {
		color: var(--success-fg);
	}
	.chip--warn {
		color: var(--warning-fg);
	}
	.chip--bad {
		color: var(--danger-fg);
	}
	.chip--info {
		color: var(--info-fg);
	}

	.rcpt__main {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px; /* tight 2px stack — structural, no token */
	}

	.rcpt__email {
		font-size: var(--text-sm);
		color: var(--text-primary);
		font-weight: var(--weight-medium);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.rcpt__sub {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.rcpt__sub .mx {
		font-family: var(--font-mono);
		color: var(--text-primary);
	}

	.rcpt__code {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	.chev {
		color: var(--text-caption);
		font-size: var(--text-xs);
		flex: none;
		transition: transform var(--duration-fast) var(--ease-out);
	}

	.rcpt--open .chev {
		transform: rotate(90deg);
	}

	/* Expanded attempt history */
	.rcpt__detail {
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		margin: 0 var(--space-2) var(--space-3);
		padding: var(--space-3);
	}

	.att {
		display: grid;
		grid-template-columns: 64px 1fr; /* "attempt {n}" / value — 64px structural constant */
		gap: var(--space-2) var(--space-3);
		font-size: var(--text-xs);
	}

	.att__n {
		font-family: var(--font-mono);
		color: var(--text-secondary);
	}

	.att__v {
		color: var(--text-primary);
		overflow-wrap: anywhere;
	}

	.att__v .mono {
		font-family: var(--font-mono);
	}

	.att__sep {
		grid-column: 1 / -1;
		border-top: 1px dashed var(--border-default);
		margin: 2px 0; /* hairline gap — structural */
	}

	.att__empty {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
</style>
