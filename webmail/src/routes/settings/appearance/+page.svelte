<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import { goto } from '$app/navigation';
	import { Button, Card, showToast, Toast } from '$lib/components/ui';
	import { requestTour } from '$lib/onboarding/tour.svelte';
	import { applyTheme as applyThemeShared, applyDensity as applyDensityShared } from '$lib/theme/apply';

	type ThemeMode = 'system' | 'dark' | 'light';
	type Density = 'comfortable' | 'compact';

	let mode: ThemeMode = $state('system');
	let density: Density = $state('comfortable');

	$effect(() => {
		if (typeof window !== 'undefined') {
			const stored = localStorage.getItem('sj-theme') as ThemeMode | null;
			if (stored === 'dark' || stored === 'light' || stored === 'system') {
				mode = stored;
			}
			const storedDensity = localStorage.getItem('density') as Density | null;
			if (storedDensity === 'comfortable' || storedDensity === 'compact') {
				density = storedDensity;
			}
		}
	});

	function applyMode(newMode: ThemeMode) {
		mode = newMode;
		applyThemeShared(newMode);
		showToast(t('settings.saved'));
	}

	function applyDensity(newDensity: Density) {
		density = newDensity;
		applyDensityShared(newDensity);
		showToast(t('settings.saved'));
	}

	async function replayTour() {
		await goto('/inbox');
		requestTour(true);
	}
</script>

<div class="sj-appearance-page">
	<h1 class="sj-page-title">{t('settings.title')}</h1>

	<Card title={t('settings.appearance_card')}>
		<h2 class="sj-section-label">{t('settings.theme')}</h2>
		<p class="sj-section-desc">Choose how SetJoin looks.</p>

		<div class="sj-theme-grid">
			<button
				class="sj-theme-btn"
				class:active={mode === 'system'}
				aria-pressed={mode === 'system'}
				data-value="system"
				onclick={() => applyMode('system')}
			>
				<div class="sj-theme-preview system-preview">
					<div class="preview-half-dark"></div>
					<div class="preview-half-light"></div>
				</div>
				<span class="sj-theme-label">{t('settings.theme_system')}</span>
			</button>

			<button
				class="sj-theme-btn"
				class:active={mode === 'dark'}
				aria-pressed={mode === 'dark'}
				data-value="dark"
				onclick={() => applyMode('dark')}
			>
				<div class="sj-theme-preview dark-preview"></div>
				<span class="sj-theme-label">{t('settings.theme_dark')}</span>
			</button>

			<button
				class="sj-theme-btn"
				class:active={mode === 'light'}
				aria-pressed={mode === 'light'}
				data-value="light"
				onclick={() => applyMode('light')}
			>
				<div class="sj-theme-preview light-preview"></div>
				<span class="sj-theme-label">{t('settings.theme_light')}</span>
			</button>
		</div>

		<h2 class="sj-section-label sj-section-label--spaced">Density</h2>
		<p class="sj-section-desc">Control the spacing and information density of list views.</p>

		<div class="sj-theme-grid density-grid">
			<button
				class="sj-theme-btn"
				class:active={density === 'comfortable'}
				aria-pressed={density === 'comfortable'}
				data-value="comfortable"
				onclick={() => applyDensity('comfortable')}
			>
				<div class="sj-density-preview">
					<div class="density-bar c1"></div>
					<div class="density-bar c2"></div>
					<div class="density-bar c3"></div>
				</div>
				<span class="sj-theme-label">Comfortable</span>
			</button>

			<button
				class="sj-theme-btn"
				class:active={density === 'compact'}
				aria-pressed={density === 'compact'}
				data-value="compact"
				onclick={() => applyDensity('compact')}
			>
				<div class="sj-density-preview">
					<div class="density-bar dense1"></div>
					<div class="density-bar dense2"></div>
					<div class="density-bar dense3"></div>
					<div class="density-bar dense4"></div>
					<div class="density-bar dense5"></div>
				</div>
				<span class="sj-theme-label">Compact</span>
			</button>
		</div>
	</Card>

	<Card title={t('onboarding.replay_card_title')}>
		<p class="sj-section-desc">{t('onboarding.replay_desc')}</p>
		<Button onclick={replayTour}>{t('onboarding.replay')}</Button>
	</Card>
</div>

<Toast />

<style>
	.sj-appearance-page {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
	}

	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		margin: 0 0 16px;
		color: var(--text-primary);
	}

	.sj-section-label {
		font-size: var(--text-md);
		font-weight: 600;
		color: var(--text-primary);
		margin: 0 0 var(--space-1);
	}
	.sj-section-label--spaced {
		margin-top: var(--space-5);
	}

	.sj-section-desc {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 12px;
	}

	.sj-theme-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 12px;
	}

	.density-grid {
		grid-template-columns: repeat(2, 1fr);
	}

	@media (max-width: 600px) {
		.sj-theme-grid {
			grid-template-columns: 1fr;
		}
	}

	.sj-theme-btn {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 8px;
		padding: 12px;
		border-radius: var(--radius-sm);
		border: 2px solid var(--border-default);
		background: var(--surface-card);
		cursor: pointer;
		font-family: inherit;
		color: var(--text-primary);
		transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
	}

	.sj-theme-btn:hover {
		background: var(--surface-hover);
	}

	.sj-theme-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-theme-btn.active {
		border-color: var(--border-accent);
		background: var(--surface-selected);
		box-shadow: 0 0 0 2px var(--accent);
	}

	.sj-theme-preview {
		width: 80px;
		height: 50px;
		border-radius: var(--radius-sm);
		overflow: hidden;
		border: 1px solid var(--border-default);
	}

	.system-preview { display: flex; }
	.preview-half-dark { flex: 1; background: var(--preview-dark-bg); }
	.preview-half-light { flex: 1; background: var(--preview-light-bg); }
	.dark-preview { background: var(--preview-dark-bg); }
	.light-preview { background: var(--preview-light-bg); }

	.sj-density-preview {
		width: 80px;
		display: flex;
		flex-direction: column;
		gap: 3px;
		padding: 6px;
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
	}

	.density-bar {
		width: 100%;
		height: 4px;
		background: var(--border-default);
		border-radius: 2px;
	}
	.density-bar.c1 { height: 6px; background: var(--text-secondary); }
	.density-bar.dense1 { height: 3px; background: var(--text-secondary); }

	.sj-theme-label {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}
</style>
