<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Button, IconButton } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { RemindersStore } from '$lib/stores/reminders.svelte';
	import { getWebmailSyncCoordinator } from '$lib/sync/webmail/runtime.svelte';
	import { createJmapRefreshAdapter, REMINDERS_DEBOUNCE_MS } from '$lib/sync/webmail/adapters/jmapOnline';
	import type { Reminder } from '$lib/jmap/client';

	const store = new RemindersStore();
	let offRemindersSync: (() => void) | null = null;

	onMount(() => {
		store.load();
		// Wave 2.8 (#555): route Reminder wakeups + reconnect catch-up through
		// SyncCoordinator with 500ms debounce.
		offRemindersSync = getWebmailSyncCoordinator('member').register(
			createJmapRefreshAdapter({
				consumerId: 'pim:reminders',
				mailboxScopeId: 'primary',
				dataTypes: ['Email', 'Task', 'Calendar'],
				debounceMs: REMINDERS_DEBOUNCE_MS,
				refresh: () => store.load(),
			}),
		);
	});

	onDestroy(() => {
		offRemindersSync?.();
		offRemindersSync = null;
	});

	function iconFor(sourceType: Reminder['sourceType']): 'CalendarClock' | 'SquareCheck' | 'Flag' | 'BellRing' {
		switch (sourceType) {
			case 'event': return 'CalendarClock';
			case 'task': return 'SquareCheck';
			case 'flag': return 'Flag';
			default: return 'BellRing';
		}
	}
</script>

{#if store.list.length > 0}
	<section class="reminders-window" aria-label={t('reminders.title')}>
		<header class="rw-header">
			<h2 class="rw-title">{t('reminders.title')}</h2>
			<Button variant="ghost" size="sm" onclick={() => store.dismissAll()}>{t('reminders.dismissAll')}</Button>
		</header>
		<ul class="rw-list">
			{#each store.list as r (r.id)}
				<li class="rw-item">
					<div class="rw-icon"><Icon name={iconFor(r.sourceType)} size={16} /></div>
					<div class="rw-body">
						<!-- TEXT only — reminder title/body are user/shared-calendar-controlled; never {@html}. -->
						<div class="rw-item-title">{r.title}</div>
						{#if r.body}<div class="rw-item-desc">{r.body}</div>{/if}
						<div class="rw-actions">
							<Button variant="ghost" size="sm" onclick={() => store.snooze(r.id, '5m')}>{t('reminders.snooze.5m')}</Button>
							<Button variant="ghost" size="sm" onclick={() => store.snooze(r.id, '1h')}>{t('reminders.snooze.1h')}</Button>
							<Button variant="ghost" size="sm" onclick={() => store.snooze(r.id, 'tomorrow')}>{t('reminders.snooze.tomorrow')}</Button>
						</div>
					</div>
					<IconButton label={t('reminders.dismiss')} variant="ghost" size="sm" onclick={() => store.dismiss(r.id)}>
						<Icon name="X" size={14} />
					</IconButton>
				</li>
			{/each}
		</ul>
	</section>
{/if}

<style>
	.reminders-window {
		position: fixed;
		right: var(--space-4);
		bottom: var(--space-4);
		width: min(360px, calc(100vw - 2 * var(--space-4)));
		max-height: 60vh;
		overflow-y: auto;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-md);
		z-index: 800;
	}
	.rw-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-default);
	}
	.rw-title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.rw-list {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.rw-item {
		display: flex;
		align-items: flex-start;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.rw-icon {
		color: var(--accent);
		margin-top: 2px;
	}
	.rw-body {
		flex: 1;
		min-width: 0;
	}
	.rw-item-title {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.rw-item-desc {
		font-size: var(--text-xs);
		color: var(--text-caption);
		white-space: pre-wrap;
	}
	.rw-actions {
		display: flex;
		gap: var(--space-1);
		margin-top: 4px;
	}
</style>
