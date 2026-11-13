<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Textarea, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { createSettingsResource } from '$lib/composables/settings-resource.svelte';
	import { authedBootstrap } from '$lib/composables/authed-bootstrap.svelte';

	type Role = 'new' | 'reply' | 'both' | 'none';
	type Sig = {
		id: number; alias_email: string; signature_html: string;
		signature_text: string; default_for: Role;
	};

	// Load + saves run through the shared settings-resource composable, which
	// wraps the $lib/http seam (timeout/abort/401 redirect/typed errors) with
	// per-instance pending/error state, supersede protection and unmount abort.
	const sigsRes = createSettingsResource<Sig[]>({
		load: { url: '/api/settings/signatures-list', method: 'GET' },
	});
	const sigs = $derived(sigsRes.data ?? []);
	let editing = $state<Sig | null>(null);
	let loading = $state(true);

	async function load(signal?: AbortSignal) {
		loading = true;
		await sigsRes.load({ signal });
		loading = false;
		if (sigsRes.error) showToast(t('settings.signatures.loadError'));
	}
	// WP5: authenticated mount bootstrap — the protected list load runs only
	// after a proven session; an unproven page settles its loading state and
	// unmount aborts in-flight work (cleanup below).
	authedBootstrap(
		(signal) => load(signal),
		{ onUnproven: () => { loading = false; } }
	);
	onMount(() => () => sigsRes.cleanup());

	function startNew() {
		editing = { id: 0, alias_email: '', signature_html: '', signature_text: '', default_for: 'none' };
	}
	function startEdit(s: Sig) {
		editing = { ...s };
	}

	async function save() {
		if (!editing) return;
		const body = {
			alias_email: editing.alias_email,
			signature_text: editing.signature_text,
			signature_html: editing.signature_html || `<p>${editing.signature_text}</p>`,
			is_default: editing.default_for !== 'none' ? 'true' : 'false',
			default_for: editing.default_for,
		};
		const result = await sigsRes.save({
			url: '/api/settings/signatures', method: 'PUT', body,
		});
		if (result.ok) {
			editing = null;
			await load();
			showToast(t('settings.signatures.saved'));
		} else {
			showToast(t('settings.signatures.saveError'));
		}
	}

	async function remove(s: Sig) {
		const result = await sigsRes.save({
			url: `/api/settings/signatures/${s.id}`, method: 'DELETE',
		});
		if (result.ok) {
			await load();
		} else {
			showToast(t('settings.signatures.deleteError'));
		}
	}

	// Toggle one role for a signature. Clicking the role you already hold clears it;
	// holding the other role promotes to 'both'; otherwise sets the clicked role.
	async function setDefault(s: Sig, role: 'new' | 'reply') {
		const other: 'new' | 'reply' = role === 'new' ? 'reply' : 'new';
		const next: Role =
			s.default_for === role ? 'none'
			: s.default_for === other || s.default_for === 'both' ? 'both'
			: role;
		const result = await sigsRes.save({
			url: '/api/settings/signatures', method: 'PUT',
			body: {
				alias_email: s.alias_email, signature_text: s.signature_text,
				signature_html: s.signature_html, is_default: 'true', default_for: next,
			},
		});
		if (result.ok) await load();
		else showToast(t('settings.signatures.saveError'));
	}

	function holdsRole(s: Sig, role: 'new' | 'reply'): boolean {
		return s.default_for === role || s.default_for === 'both';
	}
</script>

<div class="sj-sig-page">
	<Card title={t('settings.signatures.title')}>
		{#snippet actions()}
			<Button size="sm" variant="primary" data-testid="sig-new-btn" onclick={startNew}>
				<Icon name="Plus" size={14} />{t('settings.signatures.new')}
			</Button>
		{/snippet}
		{#snippet children()}
			{#if !loading}
				{#if sigs.length === 0}
					<p class="sj-sig-empty">{t('settings.signatures.empty')}</p>
				{:else}
					<ul class="sj-sig-list">
						{#each sigs as s (s.id)}
							<li class="sj-sig-row">
								<span class="sj-sig-alias">{s.alias_email}</span>
								<span class="sj-sig-preview">{s.signature_text}</span>
								<label class="sj-sig-flag">
									<input type="checkbox" data-testid={`sig-default-new-${s.id}`}
										checked={holdsRole(s, 'new')}
										onclick={() => setDefault(s, 'new')} />
									{t('settings.signatures.defaultNew')}
								</label>
								<label class="sj-sig-flag">
									<input type="checkbox" data-testid={`sig-default-reply-${s.id}`}
										checked={holdsRole(s, 'reply')}
										onclick={() => setDefault(s, 'reply')} />
									{t('settings.signatures.defaultReply')}
								</label>
								<Button size="sm" variant="ghost" onclick={() => startEdit(s)}>{t('common.edit')}</Button>
								<Button size="sm" variant="ghost" data-testid={`sig-delete-${s.id}`} onclick={() => remove(s)}>
									<Icon name="Trash2" size={14} />
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
			{/if}

			{#if editing}
				<div class="sj-sig-editor">
					<Input label={t('settings.signatures.alias')} bind:value={editing.alias_email} />
					<Textarea label={t('settings.signatures.body')} rows={4} bind:value={editing.signature_text} />
					<div class="sj-sig-editor-actions">
						<Button size="sm" variant="ghost" onclick={() => (editing = null)}>{t('common.cancel')}</Button>
						<Button size="sm" variant="primary" data-testid="sig-save-btn" onclick={save}>{t('common.save')}</Button>
					</div>
				</div>
			{/if}
		{/snippet}
	</Card>
</div>

<style>
	.sj-sig-page { max-width: 720px; margin: 0 auto; padding: 24px clamp(12px, 3vw, 24px); }
	.sj-sig-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
	.sj-sig-row { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); }
	.sj-sig-alias { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-primary); }
	.sj-sig-preview { flex: 1; min-width: 0; font-size: var(--text-sm); color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.sj-sig-flag { display: inline-flex; align-items: center; gap: 4px; font-size: var(--text-xs); color: var(--text-tertiary); }
	.sj-sig-empty { font-size: var(--text-sm); color: var(--text-secondary); margin: 0; }
	.sj-sig-editor { margin-top: 16px; display: flex; flex-direction: column; gap: 12px; border-top: 1px solid var(--border-subtle); padding-top: 16px; }
	.sj-sig-editor-actions { display: flex; gap: 8px; justify-content: flex-end; }
</style>
