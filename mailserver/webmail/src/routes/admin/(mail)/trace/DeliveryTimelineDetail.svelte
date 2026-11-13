<svelte:options runes={true} />

<script lang="ts">
	import { Badge } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import OutboundTimeline from '$lib/components/mail/delivery/OutboundTimeline.svelte';
	import type { TraceTimeline, TraceEvent } from '$lib/admin/client';

	let { timeline }: { timeline: TraceTimeline } = $props();

	function fmtDate(iso: string): string {
		return new Date(iso).toLocaleString();
	}

	type EventVariant = 'success' | 'info' | 'danger' | 'warning' | 'neutral';

	function eventVariant(ev: string): EventVariant {
		switch (ev) {
			case 'delivered': return 'success';
			case 'received': return 'info';
			case 'bounced': return 'danger';
			case 'deferred': return 'warning';
			case 'queued': return 'warning';
			default: return 'neutral';
		}
	}

	type IconName =
		| 'MailCheck'
		| 'Inbox'
		| 'MailMinus'
		| 'Clock'
		| 'ShieldAlert'
		| 'Archive'
		| 'ShieldBan'
		| 'Route'
		| 'Mail';

	function eventIcon(ev: string): IconName {
		switch (ev) {
			case 'delivered': return 'MailCheck';
			case 'received': return 'Inbox';
			case 'bounced': return 'MailMinus';
			case 'deferred': return 'Clock';
			case 'queued': return 'Clock';
			case 'spam_filtered': return 'ShieldAlert';
			case 'quarantined': return 'ShieldBan';
			case 'archived': return 'Archive';
			case 'rule_applied': return 'Route';
			default: return 'Mail';
		}
	}

	type DotColor = string;

	function eventDotColor(ev: string): DotColor {
		switch (ev) {
			case 'delivered': return 'var(--success-solid)';
			case 'received': return 'var(--info-solid)';
			case 'bounced': return 'var(--danger-solid)';
			case 'deferred':
			case 'queued': return 'var(--warning-solid)';
			default: return 'var(--text-tertiary)';
		}
	}

	function queueStatusVariant(status: string): EventVariant {
		switch (status) {
			case 'delivered': return 'success';
			case 'bounced': return 'danger';
			case 'deferred': return 'warning';
			default: return 'neutral';
		}
	}
</script>

<div class="dtd">
	{#if timeline.events.length === 0}
		<p class="dtd-empty">No delivery events recorded for this message.</p>
	{:else}
		<ol class="dtd-timeline" aria-label="Delivery timeline">
			{#each timeline.events as ev (ev.occurredAt + ev.event)}
				<li class="dtd-event">
					<span class="dtd-dot" style="background: {eventDotColor(ev.event)}" aria-hidden="true">
						<Icon name={eventIcon(ev.event)} size={12} />
					</span>
					<div class="dtd-event-body">
						<div class="dtd-event-head">
							<Badge variant={eventVariant(ev.event)} label={ev.event} />
							<span class="dtd-ts">{fmtDate(ev.occurredAt)}</span>
						</div>
						{#if ev.rcptAddr || ev.remoteHost}
							<div class="dtd-event-meta">
								{#if ev.rcptAddr}<span class="dtd-mono">{ev.rcptAddr}</span>{/if}
								{#if ev.remoteHost}<span class="dtd-mono dtd-host">{ev.remoteHost}</span>{/if}
							</div>
						{/if}
					</div>
				</li>
			{/each}
		</ol>
	{/if}

	{#if timeline.queue}
		{@const q = timeline.queue}
		<div class="dtd-queue">
			<p class="dtd-queue-label">Live queue</p>
			<div class="dtd-queue-row">
				<Badge variant={queueStatusVariant(q.status)} dot label={q.status} />
				<span class="dtd-queue-attempts">{q.attemptCount} attempt{q.attemptCount === 1 ? '' : 's'}</span>
			</div>
			{#if q.nextAttemptAt}
				<p class="dtd-queue-next">Next attempt: <span class="dtd-mono">{fmtDate(q.nextAttemptAt)}</span></p>
			{/if}
			{#if q.lastError}
				<p class="dtd-queue-err">{q.lastError}</p>
			{/if}
		</div>
	{/if}

	{#if timeline.recipients && timeline.recipients.length > 0}
		<div class="dtd-recipients">
			<p class="dtd-section-label">Per-recipient delivery</p>
			<OutboundTimeline recipients={timeline.recipients} overallStatus={timeline.overallStatus} />
		</div>
	{:else if timeline.detailExpired}
		<p class="dtd-caveat">Per-recipient delivery detail is no longer available (delivery history is kept for the configured retention window). Overall status is from the send queue.</p>
	{:else if timeline.multiRecipient}
		<p class="dtd-caveat">Per-recipient delivery detail isn't available for this message.</p>
	{/if}

	<div class="dtd-caveats">
		<p class="dtd-caveat">Events older than ~30 days are pruned and may not appear.</p>
		<p class="dtd-caveat">Bounce reason is best-effort text, not a remote SMTP response code.</p>
	</div>
</div>

<style>
	.dtd {
		padding: 12px 16px 8px;
	}

	/* Empty */
	.dtd-empty {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 8px;
	}

	/* Timeline */
	.dtd-timeline {
		list-style: none;
		margin: 0 0 12px;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.dtd-event {
		display: flex;
		gap: 10px;
		align-items: flex-start;
	}

	.dtd-dot {
		flex: none;
		width: 22px;
		height: 22px;
		border-radius: var(--radius-full);
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-inverse);
		margin-top: 1px;
	}

	.dtd-event-body {
		flex: 1;
		min-width: 0;
	}

	.dtd-event-head {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}

	.dtd-ts {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	.dtd-event-meta {
		display: flex;
		gap: 10px;
		margin-top: 3px;
		flex-wrap: wrap;
	}

	.dtd-mono {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.dtd-host::before {
		content: 'via ';
		font-family: var(--font-sans);
		color: var(--text-tertiary);
	}

	/* Queue block */
	.dtd-queue {
		border-top: 1px solid var(--border-subtle);
		padding-top: 10px;
		margin-bottom: 10px;
	}

	.dtd-queue-label {
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		margin: 0 0 6px;
	}

	.dtd-queue-row {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 4px;
	}

	.dtd-queue-attempts {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	.dtd-queue-next {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 2px 0;
	}

	.dtd-queue-err {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 2px 0;
		font-family: var(--font-mono);
	}

	/* Per-recipient delivery (Phase 2b) */
	.dtd-recipients {
		border-top: 1px solid var(--border-subtle);
		padding-top: 10px;
		margin-bottom: 10px;
	}

	.dtd-section-label {
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		margin: 0 0 6px;
	}

	/* Caveats */
	.dtd-caveats {
		border-top: 1px solid var(--border-subtle);
		padding-top: 8px;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.dtd-caveat {
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
		margin: 0;
	}
</style>
