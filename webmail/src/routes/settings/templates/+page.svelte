<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Textarea, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { emailTemplateList, emailTemplateSet, emailTemplateDelete } from '$lib/jmap/emailTemplates';
	import type { EmailTemplate } from '$lib/types/jmap';

	let templates = $state<EmailTemplate[]>([]);
	let loading = $state(true);
	let editing = $state<EmailTemplate | null>(null);
	let saving = $state(false);
	let formError = $state('');

	async function load() {
		loading = true;
		try {
			templates = await emailTemplateList();
		} catch {
			showToast(t('templates.save_failed'));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	function startNew() {
		formError = '';
		editing = { id: '', name: '', subject: '', bodyHtml: '' };
	}
	function startEdit(tpl: EmailTemplate) {
		formError = '';
		editing = { ...tpl };
	}
	function cancel() {
		editing = null;
		formError = '';
	}

	async function save() {
		if (!editing) return;
		formError = '';
		const name = editing.name.trim();
		if (!name) {
			formError = t('templates.name_required');
			return;
		}
		saving = true;
		try {
			// body_html is stored verbatim; the compose editor sanitizes on insert.
			await emailTemplateSet(name, editing.subject, editing.bodyHtml);
			editing = null;
			await load();
			showToast(t('templates.title'));
		} catch (e) {
			formError = e instanceof Error ? e.message : t('templates.save_failed');
		} finally {
			saving = false;
		}
	}

	async function remove(tpl: EmailTemplate) {
		try {
			await emailTemplateDelete(tpl.id);
			await load();
		} catch {
			showToast(t('templates.save_failed'));
		}
	}
</script>

<div class="sj-tpl-page">
	<Card title={t('templates.title')}>
		{#snippet actions()}
			<Button size="sm" variant="primary" data-testid="tpl-new-btn" onclick={startNew}>
				<Icon name="Plus" size={14} />{t('templates.new')}
			</Button>
		{/snippet}
		{#snippet children()}
			<p class="sj-tpl-subtitle">{t('templates.subtitle')}</p>

			{#if !loading}
				{#if templates.length === 0}
					<p class="sj-tpl-empty">{t('templates.empty')}</p>
				{:else}
					<ul class="sj-tpl-list">
						{#each templates as tpl (tpl.id)}
							<li class="sj-tpl-row">
								<Icon name="FileText" size={16} strokeWidth={1.75} />
								<span class="sj-tpl-name">{tpl.name}</span>
								<span class="sj-tpl-summary">{tpl.subject}</span>
								<Button size="sm" variant="ghost" onclick={() => startEdit(tpl)}>{t('templates.edit')}</Button>
								<Button size="sm" variant="ghost" data-testid={`tpl-delete-${tpl.id}`} onclick={() => remove(tpl)}>
									<Icon name="Trash2" size={14} />
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
			{/if}

			{#if editing}
				<div class="sj-tpl-editor">
					<Input label={t('templates.name')} placeholder={t('templates.name_placeholder')} bind:value={editing.name} />
					<Input label={t('templates.subject')} placeholder={t('templates.subject_placeholder')} bind:value={editing.subject} />
					<Textarea label={t('templates.body')} rows={6} placeholder={t('templates.body_placeholder')} bind:value={editing.bodyHtml} />

					{#if formError}
						<p class="sj-tpl-error" role="alert">{formError}</p>
					{/if}

					<div class="sj-tpl-editor-actions">
						<Button size="sm" variant="ghost" onclick={cancel}>{t('templates.cancel')}</Button>
						<Button size="sm" variant="primary" data-testid="tpl-save-btn" disabled={saving} onclick={save}>
							{t('templates.save')}
						</Button>
					</div>
				</div>
			{/if}
		{/snippet}
	</Card>
</div>

<style>
	.sj-tpl-page { max-width: 720px; margin: 0 auto; padding: 24px clamp(12px, 3vw, 24px); }
	.sj-tpl-subtitle { font-size: var(--text-sm); color: var(--text-secondary); margin: 0 0 16px; }
	.sj-tpl-empty { font-size: var(--text-sm); color: var(--text-secondary); margin: 0; }
	.sj-tpl-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
	.sj-tpl-row { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); }
	.sj-tpl-name { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
	.sj-tpl-summary { flex: 1; min-width: 0; font-size: var(--text-xs); color: var(--text-caption); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.sj-tpl-editor { margin-top: 16px; display: flex; flex-direction: column; gap: 12px; border-top: 1px solid var(--border-subtle); padding-top: 16px; }
	.sj-tpl-error { font-size: var(--text-sm); color: var(--danger-solid); margin: 0; }
	.sj-tpl-editor-actions { display: flex; gap: 8px; justify-content: flex-end; }
</style>
