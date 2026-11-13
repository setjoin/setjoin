<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import Icon from './Icon.svelte';
	import { IconButton } from '$lib/components/ui';
	import { emailNudges, emailNudgeDismiss } from '$lib/jmap/client';
	import { t } from '$lib/i18n';
	import type { EmailNudge } from '$lib/types/jmap';

	/**
	 * Stale-thread / no-reply nudge banner (#13). Self-fetches the computed nudge
	 * list on mount (empty when feature.stale_nudges is OFF — the gateway gates
	 * it, so this renders nothing). Each finding offers a kind-specific reply/
	 * follow-up action plus a persistent dismiss (view_prefs->'nudgeDismissed').
	 */
	interface Props {
		/** Open the reply/follow-up compose for a nudge (parent supplies context). */
		onreply?: (nudge: EmailNudge) => void;
	}
	let { onreply }: Props = $props();

	let nudges = $state<EmailNudge[]>([]);

	onMount(async () => {
		try {
			nudges = await emailNudges();
		} catch {
			// Nudges are optional chrome; a load failure must not block the inbox.
			nudges = [];
		}
	});

	async function dismiss(nudge: EmailNudge) {
		nudges = nudges.filter((n) => n.threadId !== nudge.threadId);
		try {
			await emailNudgeDismiss(nudge.threadId);
		} catch {
			// Best-effort: the local removal already hid it for this session.
		}
	}
</script>

{#if nudges.length}
	<div class="nudge-banner">
		<div class="nudge-banner__head">
			<Icon name="BellRing" size={14} strokeWidth={1.75} />
			<span class="nudge-banner__title">{t('nudges.title')}</span>
		</div>
		{#each nudges as nudge (nudge.threadId)}
			<div class="nudge-row">
				<div class="nudge-row__info">
					<span class="nudge-row__subject">{nudge.subject || '(no subject)'}</span>
					<span class="nudge-row__meta">
						{nudge.kind === 'no_reply_sent'
							? t('nudges.no_reply_sent', { who: nudge.counterpart })
							: t('nudges.stale_unanswered', { who: nudge.counterpart })}
					</span>
				</div>
				<button class="nudge-row__action" onclick={() => onreply?.(nudge)}>
					<Icon name="Reply" size={13} strokeWidth={1.75} />
					{nudge.kind === 'no_reply_sent' ? t('nudges.follow_up') : t('nudges.reply')}
				</button>
				<IconButton label={t('nudges.dismiss')} size="sm" onclick={() => dismiss(nudge)}>
					<Icon name="X" size={14} strokeWidth={1.75} />
				</IconButton>
			</div>
		{/each}
	</div>
{/if}

<style>
	.nudge-banner {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		overflow: hidden;
		margin: 8px 0;
	}

	.nudge-banner__head {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 16px;
		color: var(--text-secondary);
		border-bottom: 1px solid var(--border-subtle);
	}

	.nudge-banner__title {
		font-size: var(--text-xs);
		font-weight: 600;
	}

	.nudge-row {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 16px;
		border-bottom: 1px solid var(--border-subtle);
	}

	.nudge-row:last-child {
		border-bottom: none;
	}

	.nudge-row:hover {
		background: var(--surface-sunken);
	}

	.nudge-row__info {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	.nudge-row__subject {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.nudge-row__meta {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.nudge-row__action {
		display: flex;
		align-items: center;
		gap: 4px;
		flex: none;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		color: var(--text-secondary);
		font: inherit;
		font-size: var(--text-xs);
		font-weight: 500;
		cursor: pointer;
		white-space: nowrap;
	}

	.nudge-row__action:hover {
		background: var(--accent-subtle);
		border-color: var(--accent);
		color: var(--accent-fg-on-subtle);
	}

	.nudge-row__action:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
