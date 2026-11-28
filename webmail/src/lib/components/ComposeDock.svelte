<svelte:options runes={true} />

<script lang="ts">
	// ComposeDock (QoL #18) — the minimized-compose dock. Renders ONE bar per
	// minimized ComposeSession (subject/recipient, truncated) as a real <button>
	// with roving tabindex (one bar in the tab order; Arrow keys move focus). An
	// autosave failure on a minimized draft shows an error badge on its bar. Clicking
	// a bar restores it (swap-maximizes); the X closes it. Rendered once in +layout —
	// the compose panels themselves live in the primary pane, CSS-hidden when minimized.
	import { tick } from 'svelte';
	import { composeStore } from '$lib/stores/compose';
	import type { ComposeSession } from '$lib/stores/compose';
	import { t } from '$lib/i18n';
	import Icon from './Icon.svelte';
	import IconButton from './ui/IconButton.svelte';

	let minimized = $derived($composeStore.sessions.filter((s) => s.minimized));
	// Roving-tabindex cursor: exactly one bar has tabindex 0. Clamped as bars come
	// and go so it never points past the end.
	let active = $state(0);
	$effect(() => {
		if (active >= minimized.length) active = Math.max(0, minimized.length - 1);
	});

	function label(s: ComposeSession): string {
		return s.subject?.trim() || s.recipient?.trim() || t('compose.title');
	}

	function focusBar(i: number) {
		void tick().then(() => document.getElementById(`compose-dock-bar-${minimized[i]?.id}`)?.focus());
	}

	function onKey(e: KeyboardEvent, i: number) {
		if (minimized.length === 0) return;
		if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
			e.preventDefault();
			active = (i + 1) % minimized.length;
			focusBar(active);
		} else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
			e.preventDefault();
			active = (i - 1 + minimized.length) % minimized.length;
			focusBar(active);
		}
	}
</script>

{#if minimized.length > 0}
	<div class="compose-dock" role="toolbar" aria-label={t('compose.dock_label')} data-testid="compose-dock">
		{#each minimized as s, i (s.id)}
			<div class="compose-dock__bar" class:compose-dock__bar--error={s.saveError}>
				<button
					id={`compose-dock-bar-${s.id}`}
					class="compose-dock__restore"
					data-testid="compose-pill"
					tabindex={i === active ? 0 : -1}
					title={label(s)}
					onfocus={() => (active = i)}
					onkeydown={(e) => onKey(e, i)}
					onclick={() => composeStore.restore(s.id)}
				>
					<Icon name="Pencil" size={14} style="color: var(--accent)" />
					<span class="compose-dock__title">{label(s)}</span>
					{#if s.saveError}
						<span class="compose-dock__badge" aria-label={t('compose.draftSaveErrorBadge')} title={t('compose.draftSaveErrorBadge')}>
							<Icon name="AlertTriangle" size={12} />
						</span>
					{/if}
				</button>
				<IconButton label={t('compose.close')} variant="ghost" size="sm" onclick={() => composeStore.close(s.id)}>
					<Icon name="X" size={14} />
				</IconButton>
			</div>
		{/each}
	</div>
{/if}

<style>
	.compose-dock { position: fixed; bottom: 16px; right: 24px; z-index: 200; display: flex; align-items: flex-end; gap: 8px; }
	.compose-dock__bar { display: flex; align-items: center; gap: 2px; max-width: 260px; padding: 2px 4px 2px 12px; background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-lg); box-shadow: var(--shadow-md); }
	.compose-dock__bar--error { border-color: var(--danger-solid); }
	.compose-dock__restore { display: flex; align-items: center; gap: 8px; min-width: 0; flex: 1; border: none; background: none; cursor: pointer; font-size: var(--text-sm); font-weight: 500; font-family: var(--font-sans); color: var(--text-primary); padding: 6px 2px; border-radius: var(--radius-sm); }
	.compose-dock__restore:focus-visible { box-shadow: var(--focus-ring); outline: none; }
	.compose-dock__title { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.compose-dock__badge { display: inline-flex; align-items: center; color: var(--danger-solid); flex: none; }
</style>
