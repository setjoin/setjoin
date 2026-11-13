<svelte:options runes={true} />

<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { beforeNavigate } from '$app/navigation';
	import { t, locale } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import { user, adminPermissions, hasPermission } from '$lib/stores/auth';
	import { jmapSession } from '$lib/stores/session';
	import { Card, Button, Badge, Tooltip, Dialog, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import {
		WelcomeForm,
		LOCALES,
		WELCOME_TOKEN_NAMES,
		WELCOME_TOKENS,
		TOKEN_HELP_KEY,
		localeStatus,
		lintPlaceholders,
		type LocaleId,
		type LocaleStatus,
		type LintFinding
	} from './welcomeForm.svelte';

	// Keep t() reactive across language switches.
	$locale;

	const form = new WelcomeForm();

	// ── Local UI state the view owns (DOM glue, dialogs, live region) ──
	let lastFocusedField = $state<'subject' | 'body_text' | null>(null);
	let subjectEl = $state<HTMLInputElement | null>(null);
	let bodyEl = $state<HTMLTextAreaElement | null>(null);
	let chipMsg = $state(''); // polite live-region announcement for chip insertion
	let showDiscard = $state(false);
	let showDisable = $state(false);

	// ── Session-derived personalization context (best-effort) ──
	const adminEmail = $derived($user?.email ?? '');
	const orgName = $derived($jmapSession?.branding?.name ?? '');
	const webmailURL = $derived(typeof window !== 'undefined' ? window.location.origin : '');
	const isMac = $derived(
		typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform ?? '')
	);

	// ── Derived state for the view ──
	const cfg = $derived(form.cfg);
	const active = $derived(form.activeLocale);
	const current = $derived(form.current);

	function langLabel(loc: LocaleId): string {
		return t(`admin.welcome_email.lang_${loc}`);
	}

	// C1: per-tab status (drives dots + aria-labels + badge).
	function statusFor(loc: LocaleId): LocaleStatus {
		const required = loc === 'en';
		return localeStatus(cfg.locales[loc], required);
	}

	function isDirtyLocale(loc: LocaleId): boolean {
		const a = cfg.locales[loc];
		const b = form.saved.locales[loc];
		if (!a || !b) return false;
		return a.subject !== b.subject || a.body_text !== b.body_text || a.body_html !== b.body_html;
	}

	function tabAria(loc: LocaleId): string {
		const lang = langLabel(loc);
		const s = statusFor(loc);
		if (s === 'complete') return t('admin.welcome_email.tab_aria_complete', { lang });
		if (s === 'empty_required') return t('admin.welcome_email.tab_aria_empty_required', { lang });
		return t('admin.welcome_email.tab_aria_fallback', { lang, default: langLabel(cfg.default_locale as LocaleId) });
	}

	// C2: live fallback explainer. The backend uses an optional locale only when
	// it has a subject, so the note fires whenever the active non-en locale has
	// no subject (including a body-only locale that would silently fall back).
	const showFallbackNote = $derived(active !== 'en' && current.subject.trim() === '');

	// C9: edit-time placeholder lint across the active locale's editable fields.
	const lintFindings = $derived<LintFinding[]>([
		...lintPlaceholders(current.subject),
		...lintPlaceholders(current.body_text),
		...lintPlaceholders(current.body_html)
	]);
	const lintUnknown = $derived(lintFindings.find((f) => f.kind === 'unknown'));
	const lintUnbalanced = $derived(lintFindings.some((f) => f.kind === 'unbalanced'));

	onMount(() => {
		form.load();
	});

	// D1/C7: guard route changes when there are unsaved edits.
	beforeNavigate(({ cancel }) => {
		if (form.isDirty && !confirm(t('admin.welcome_email.unsaved_warning'))) {
			cancel();
		}
	});

	// ── Tabs: roving tabindex + arrow navigation (D2) ──
	function focusTab(loc: LocaleId) {
		const el = document.getElementById(`we-tab-${loc}`);
		el?.focus();
	}

	function onTabKeydown(e: KeyboardEvent, idx: number) {
		let nextIdx = idx;
		if (e.key === 'ArrowRight') nextIdx = (idx + 1) % LOCALES.length;
		else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + LOCALES.length) % LOCALES.length;
		else if (e.key === 'Home') nextIdx = 0;
		else if (e.key === 'End') nextIdx = LOCALES.length - 1;
		else return;
		e.preventDefault();
		const loc = LOCALES[nextIdx];
		form.activeLocale = loc;
		focusTab(loc);
	}

	// ── Field editing ──
	function onSubjectInput(e: Event) {
		form.setField('subject', (e.currentTarget as HTMLInputElement).value);
	}
	function onBodyInput(e: Event) {
		form.setField('body_text', (e.currentTarget as HTMLTextAreaElement).value);
	}
	function onHtmlInput(e: Event) {
		form.setField('body_html', (e.currentTarget as HTMLTextAreaElement).value);
	}

	// ── C3: caret-aware, keyboard-operable chip insertion ──
	function targetEl(): HTMLInputElement | HTMLTextAreaElement | null {
		if (lastFocusedField === 'subject') return subjectEl;
		return bodyEl; // default: body caret-at-end behavior
	}

	async function insertToken(token: string, tokenName: string) {
		const field: 'subject' | 'body_text' = lastFocusedField === 'subject' ? 'subject' : 'body_text';
		const el = targetEl();
		const len = (field === 'subject' ? current.subject : current.body_text).length;
		const start = el?.selectionStart ?? len;
		const end = el?.selectionEnd ?? len;
		const caret = form.insertPlaceholder(field, token, start, end);
		chipMsg = t('admin.welcome_email.chip_inserted', { token });
		await tick();
		const after = field === 'subject' ? subjectEl : bodyEl;
		if (after) {
			after.focus();
			after.setSelectionRange(caret, caret);
		}
	}

	// ── C3: roving tabindex on the chip toolbar ──
	let chipIdx = $state(0);
	function onChipKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowRight') {
			e.preventDefault();
			chipIdx = (chipIdx + 1) % WELCOME_TOKENS.length;
			(document.getElementById(`we-chip-${chipIdx}`) as HTMLButtonElement | null)?.focus();
		} else if (e.key === 'ArrowLeft') {
			e.preventDefault();
			chipIdx = (chipIdx - 1 + WELCOME_TOKENS.length) % WELCOME_TOKENS.length;
			(document.getElementById(`we-chip-${chipIdx}`) as HTMLButtonElement | null)?.focus();
		} else if (e.key === 'Home') {
			e.preventDefault();
			chipIdx = 0;
			(document.getElementById('we-chip-0') as HTMLButtonElement | null)?.focus();
		} else if (e.key === 'End') {
			e.preventDefault();
			chipIdx = WELCOME_TOKENS.length - 1;
			(document.getElementById(`we-chip-${chipIdx}`) as HTMLButtonElement | null)?.focus();
		}
	}

	function tokenTooltip(name: string): string {
		const key = TOKEN_HELP_KEY[name as keyof typeof TOKEN_HELP_KEY];
		let help = t(key);
		// C4: interpolate the real org name / webmail URL where available.
		if (name === 'OrgName' && orgName) help = `${help} (${orgName})`;
		if (name === 'WebmailURL' && webmailURL) help = `${help} (${webmailURL})`;
		return help;
	}

	// ── Save / test / discard ──
	async function save() {
		if (!form.validate()) {
			form.activeLocale = 'en';
			await tick();
			(form.subjectError ? subjectEl : bodyEl)?.focus();
			return;
		}
		try {
			const ok = await form.save();
			if (ok) showToast(t('admin.welcome_email.saved'));
		} catch (e) {
			showToast(parseError(e).message);
		}
	}

	async function sendTest() {
		try {
			await form.sendTest();
			showToast(
				t('admin.welcome_email.test_sent', { lang: langLabel(active), email: adminEmail })
			);
		} catch (e) {
			showToast(parseError(e).message);
		}
	}

	function confirmDiscard() {
		form.discard();
		showDiscard = false;
		showToast(t('admin.welcome_email.discarded'));
	}

	// ── C8: confirm before the ON→OFF org-wide blackout ──
	function onToggleEnabled(e: Event) {
		const next = (e.currentTarget as HTMLInputElement).checked;
		if (cfg.enabled && !next) {
			// Revert the checkbox; only commit after confirm.
			(e.currentTarget as HTMLInputElement).checked = true;
			showDisable = true;
			return;
		}
		form.setEnabled(next);
	}
	function confirmDisable() {
		form.setEnabled(false);
		showDisable = false;
	}

	// ── C6: Cmd/Ctrl+S to save ──
	function onWindowKeydown(e: KeyboardEvent) {
		if ((e.metaKey || e.ctrlKey) && (e.key === 's' || e.key === 'S')) {
			if (showDiscard || showDisable) return;
			e.preventDefault();
			if (form.isDirty && !form.saving) void save();
			else if (!form.validate()) {
				form.activeLocale = 'en';
				void tick().then(() => (form.subjectError ? subjectEl : bodyEl)?.focus());
			}
		}
	}

	function statusDotClass(loc: LocaleId): string {
		return `we-dot we-dot--${statusFor(loc)}`;
	}
</script>

<svelte:window onkeydown={onWindowKeydown} />

<!-- C3: one polite live region for chip-insertion announcements -->
<div class="sr-only" role="status" aria-live="polite">{chipMsg}</div>

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.welcome_email.title')}</h1>
			<p>{t('admin.welcome_email.description')}</p>
		</div>
	</header>

	{#if form.loading}
		<Card><p class="we-loading">{t('admin.welcome_email.loading')}</p></Card>
	{:else if form.loadError}
		<Card><p class="we-alert-danger" role="alert">{form.loadError}</p></Card>
	{:else}
		<!-- Card 1: enablement + default language -->
		<Card>
			<label class="we-toggle-row">
				<input type="checkbox" checked={cfg.enabled} onchange={onToggleEnabled} />
				<span>{t('admin.welcome_email.enabled')}</span>
			</label>

			<!-- C10: consequence-first bulk warning -->
			<div class="we-warning" role="note">
				<Icon name="AlertTriangle" size={16} />
				<span>{t('admin.welcome_email.bulk_warning')}</span>
			</div>

			<label class="we-field" for="we-default-locale">
				<span class="we-label">{t('admin.welcome_email.default_locale')}</span>
				<select
					id="we-default-locale"
					value={cfg.default_locale}
					onchange={(e) => form.setDefaultLocale((e.currentTarget as HTMLSelectElement).value)}
				>
					{#each LOCALES as loc (loc)}
						<option value={loc}>{langLabel(loc)}</option>
					{/each}
				</select>
				<span class="we-hint">{t('admin.welcome_email.default_help')}</span>
			</label>
		</Card>

		<!-- Card 2: per-locale content editor -->
		<Card>
			<!-- C10: single honest outcome-stating status line -->
			<p class="we-status" role="status">
				{#if cfg.enabled}
					{t('admin.welcome_email.status_on', { default: langLabel(cfg.default_locale as LocaleId) })}
				{:else}
					{t('admin.welcome_email.status_off')}
				{/if}
			</p>

			<!-- D2 + C1: ARIA tabs with status dots, default badge, stateful labels -->
			<div class="we-tabs" role="tablist" aria-label={t('admin.welcome_email.title')}>
				{#each LOCALES as loc, i (loc)}
					<button
						id={`we-tab-${loc}`}
						role="tab"
						type="button"
						class="we-tab"
						class:active={active === loc}
						aria-selected={active === loc}
						aria-controls={`we-panel-${loc}`}
						aria-label={tabAria(loc)}
						tabindex={active === loc ? 0 : -1}
						onclick={() => (form.activeLocale = loc)}
						onkeydown={(e) => onTabKeydown(e, i)}
					>
						<span class={statusDotClass(loc)} aria-hidden="true"></span>
						{#if isDirtyLocale(loc)}<span class="we-dot we-dot--dirty" aria-hidden="true"></span>{/if}
						<span class="we-tab-label">{langLabel(loc)}</span>
						{#if cfg.default_locale === loc}
							<Badge variant="info" label={t('admin.welcome_email.tab_default')} />
						{/if}
					</button>
				{/each}
			</div>

			<div
				role="tabpanel"
				id={`we-panel-${active}`}
				aria-labelledby={`we-tab-${active}`}
				class="we-panel"
			>
				<!-- D3: toggle-off stays editable; status banner only -->
				{#if !cfg.enabled}
					<p class="we-status-off" role="status">{t('admin.welcome_email.status_off')}</p>
				{/if}

				<!-- C2: empty-locale fallback explainer (vanishes the instant they type) -->
				{#if showFallbackNote}
					<p class="we-fallback" role="note">
						<Icon name="Info" size={14} />
						<span>
							{t('admin.welcome_email.fallback_note', {
								lang: langLabel(active),
								default: langLabel(cfg.default_locale as LocaleId)
							})}
						</span>
					</p>
				{/if}

				<!-- Subject (C5 field-associated error) -->
				<div class="we-field">
					<label class="we-label" for={`we-subject-${active}`}>{t('admin.welcome_email.subject')}</label>
					<input
						id={`we-subject-${active}`}
						type="text"
						bind:this={subjectEl}
						value={current.subject}
						oninput={onSubjectInput}
						onfocus={() => (lastFocusedField = 'subject')}
						aria-invalid={active === 'en' && form.subjectError ? 'true' : undefined}
						aria-describedby={active === 'en' && form.subjectError ? 'we-subject-err' : undefined}
					/>
					{#if active === 'en' && form.subjectError}
						<p id="we-subject-err" class="we-err" role="alert">{t(form.subjectError)}</p>
					{/if}
				</div>

				<!-- Body text (C5 field-associated error) -->
				<div class="we-field">
					<label class="we-label" for={`we-body-${active}`}>{t('admin.welcome_email.body_text')}</label>
					<textarea
						id={`we-body-${active}`}
						rows="10"
						bind:this={bodyEl}
						value={current.body_text}
						oninput={onBodyInput}
						onfocus={() => (lastFocusedField = 'body_text')}
						aria-invalid={active === 'en' && form.bodyError ? 'true' : undefined}
						aria-describedby={active === 'en' && form.bodyError ? 'we-body-err' : undefined}
					></textarea>
					{#if active === 'en' && form.bodyError}
						<p id="we-body-err" class="we-err" role="alert">{t(form.bodyError)}</p>
					{/if}
				</div>

				<!-- HTML body (D4: raw textarea + sanitization note) -->
				<div class="we-field">
					<label class="we-label" for={`we-html-${active}`}>{t('admin.welcome_email.body_html')}</label>
					<textarea
						id={`we-html-${active}`}
						rows="6"
						value={current.body_html}
						oninput={onHtmlInput}
						onfocus={() => (lastFocusedField = 'body_text')}
					></textarea>
					<p class="we-hint">{t('admin.welcome_email.html_hint')}</p>
				</div>

				<!-- C9: non-blocking placeholder lint -->
				{#if lintUnknown}
					<p class="we-lint" role="status">
						<Icon name="AlertTriangle" size={14} />
						<span>
							{t('admin.welcome_email.lint_unknown', {
								name: `{${lintUnknown.name}}`,
								suggestion: `{${lintUnknown.suggestion}}`
							})}
						</span>
					</p>
				{:else if lintUnbalanced}
					<p class="we-lint" role="status">
						<Icon name="AlertTriangle" size={14} />
						<span>{t('admin.welcome_email.lint_unbalanced')}</span>
					</p>
				{/if}

				<!-- C3 + C4: self-documenting chip toolbar -->
				<div class="we-chips" role="toolbar" aria-label={t('admin.welcome_email.chip_toolbar')}>
					<span class="we-chips-label">{t('admin.welcome_email.placeholders')}</span>
					{#each WELCOME_TOKEN_NAMES as name, i (name)}
						<Tooltip text={tokenTooltip(name)}>
							<button
								id={`we-chip-${i}`}
								type="button"
								class="we-chip"
								tabindex={i === chipIdx ? 0 : -1}
								aria-label={`${WELCOME_TOKENS[i]} — ${tokenTooltip(name)}`}
								onmousedown={(e) => e.preventDefault()}
								onclick={() => insertToken(WELCOME_TOKENS[i], name)}
								onkeydown={onChipKeydown}
							>
								{WELCOME_TOKENS[i]}
							</button>
						</Tooltip>
					{/each}
					<span class="we-hint">{t('admin.welcome_email.placeholders_hint')}</span>
				</div>
			</div>

			<!-- C11: sticky, in-reach, honest action bar -->
			<div class="we-actions">
				<div class="we-actions-left">
					{#if form.isDirty}
						<span class="we-unsaved">{t('admin.welcome_email.unsaved')}</span>
					{:else}
						<span class="we-saved"><Icon name="MailCheck" size={14} /> {t('admin.welcome_email.all_saved')}</span>
					{/if}
				</div>
				<div class="we-actions-right">
					<Button variant="ghost" size="sm" disabled={!form.isDirty} onclick={() => (showDiscard = true)}>
						{t('admin.welcome_email.discard')}
					</Button>
					<Button
						variant="secondary"
						size="sm"
						disabled={form.testing || !hasPermission($adminPermissions, 'system.config')}
						onclick={sendTest}
						title={t('admin.welcome_email.test_hint', { lang: langLabel(active), email: adminEmail })}
					>
						{#snippet icon()}<Icon name="Send" size={16} />{/snippet}
						{form.testing
							? t('admin.welcome_email.sending')
							: t('admin.welcome_email.test_send')}
					</Button>
					<Button
						variant="primary"
						size="sm"
						disabled={!form.isDirty || form.saving || !hasPermission($adminPermissions, 'system.config')}
						onclick={save}
						title={isMac ? '⌘S' : 'Ctrl+S'}
						aria-keyshortcuts="Meta+S Control+S"
						aria-busy={form.saving}
					>
						{form.saving ? t('admin.welcome_email.saving') : t('admin.welcome_email.save')}
					</Button>
					<kbd class="we-kbd">{isMac ? '⌘S' : 'Ctrl+S'}</kbd>
				</div>
			</div>
		</Card>
	{/if}
</div>

<!-- C7: discard confirmation -->
{#if showDiscard}
	<Dialog open={showDiscard} title={t('admin.welcome_email.discard_title')} onClose={() => (showDiscard = false)}>
		{#snippet children()}
			<p>{t('admin.welcome_email.discard_body')}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={confirmDiscard}>{t('admin.welcome_email.discard')}</Button>
			<Button variant="ghost" onclick={() => (showDiscard = false)}>{t('admin.welcome_email.disable_cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<!-- C8: disable (ON→OFF) confirmation -->
{#if showDisable}
	<Dialog open={showDisable} title={t('admin.welcome_email.disable_title')} onClose={() => (showDisable = false)}>
		{#snippet children()}
			<p>{t('admin.welcome_email.disable_body')}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="danger" onclick={confirmDisable}>{t('admin.welcome_email.disable_confirm')}</Button>
			<Button variant="ghost" onclick={() => (showDisable = false)}>{t('admin.welcome_email.disable_cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-page { max-width: 900px; }
	.sj-page-head { margin-bottom: 16px; }
	.sj-page-head h1 {
		margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: var(--weight-semibold); letter-spacing: var(--tracking-display); color: var(--text-primary);
	}
	.sj-page-head p { margin: 4px 0 0; font-size: var(--text-sm); color: var(--text-secondary); }

	.sr-only {
		position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
		overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0;
	}

	.we-loading { margin: 0; color: var(--text-secondary); font-size: var(--text-sm); }
	.we-alert-danger { margin: 0; color: var(--danger-fg); font-size: var(--text-sm); }

	.we-toggle-row { display: flex; align-items: center; gap: 8px; color: var(--text-primary); }

	.we-warning {
		display: flex; align-items: flex-start; gap: 8px; margin: 12px 0 0;
		padding: 10px 12px; border-radius: var(--radius-md);
		background: var(--danger-bg); border: 1px solid var(--danger-solid);
		color: var(--danger-fg); font-size: var(--text-sm); line-height: var(--leading-normal);
	}

	.we-field { display: flex; flex-direction: column; gap: 6px; margin-top: 16px; color: var(--text-primary); }
	.we-label { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
	.we-hint { font-size: var(--text-sm); color: var(--text-caption); }

	.we-field input,
	.we-field textarea,
	.we-field select,
	.we-field :global(select) {
		width: 100%; padding: 8px 10px;
		background: var(--surface-card); color: var(--text-primary);
		border: 1px solid var(--border-default); border-radius: var(--radius-sm);
		font-family: inherit; font-size: var(--text-sm);
	}
	.we-field textarea { resize: vertical; min-height: 96px; }
	.we-field input[aria-invalid='true'],
	.we-field textarea[aria-invalid='true'] { border-color: var(--danger-solid); }
	.we-field :is(input, textarea, select):focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.we-err { margin: 2px 0 0; font-size: var(--text-sm); color: var(--danger-fg); }

	.we-status {
		margin: 0 0 12px; font-size: var(--text-sm); color: var(--text-secondary);
		line-height: var(--leading-normal);
	}
	.we-status-off {
		margin: 0 0 12px; padding: 8px 12px; border-radius: var(--radius-md);
		background: var(--warning-bg); color: var(--warning-fg); font-size: var(--text-sm);
	}

	.we-fallback,
	.we-lint {
		display: flex; align-items: flex-start; gap: 6px; margin: 0 0 12px;
		font-size: var(--text-sm); line-height: var(--leading-normal);
	}
	.we-fallback {
		padding: 8px 12px; border-radius: var(--radius-md);
		background: var(--surface-sunken); border: 1px solid var(--border-subtle);
		color: var(--text-secondary);
	}
	.we-lint { color: var(--warning-fg); margin-top: 8px; }

	/* Tabs */
	.we-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 8px; }
	.we-tab {
		display: inline-flex; align-items: center; gap: 6px;
		padding: 8px 14px; background: none; border: none; cursor: pointer;
		color: var(--text-secondary); border-bottom: 2px solid transparent;
		font-size: var(--text-sm); font-family: inherit;
	}
	.we-tab.active { color: var(--text-primary); border-bottom-color: var(--accent); }
	.we-tab:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.we-tab-label { line-height: 1; }

	.we-dot { width: 6px; height: 6px; border-radius: 50%; flex: 0 0 auto; }
	.we-dot--complete { background: var(--success-solid); }
	.we-dot--empty_required { background: var(--danger-solid); }
	.we-dot--fallback { background: transparent; border: 1px solid var(--text-tertiary); }
	.we-dot--dirty { background: var(--warning-solid); }

	.we-panel { padding-top: 4px; }

	/* Chips */
	.we-chips { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 16px; }
	.we-chips-label { font-size: var(--text-sm); color: var(--text-secondary); }
	.we-chip {
		padding: 4px 8px; font-family: var(--font-mono); font-size: var(--text-xs);
		background: var(--surface-sunken); color: var(--text-primary);
		border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); cursor: pointer;
	}
	.we-chip:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* C11: sticky action bar */
	.we-actions {
		position: sticky; bottom: 0; z-index: 1;
		display: flex; align-items: center; justify-content: space-between; gap: 8px;
		margin: 20px -16px -16px; padding: 12px 16px;
		background: var(--surface-card); border-top: 1px solid var(--border-subtle);
	}
	.we-actions-left { display: flex; align-items: center; }
	.we-actions-right { display: flex; align-items: center; gap: 8px; }
	.we-unsaved { font-size: var(--text-sm); color: var(--warning-fg); }
	.we-saved {
		display: inline-flex; align-items: center; gap: 4px;
		font-size: var(--text-sm); color: var(--text-secondary);
	}
	.we-kbd {
		font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-caption);
		padding: 1px 4px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);
	}

	/* D2: responsive */
	@media (max-width: 640px) {
		.we-actions {
			flex-direction: column; align-items: stretch;
		}
		.we-actions-right { flex-wrap: wrap; }
		.we-actions-right :global(.sj-btn) { flex: 1 1 auto; }
	}

	@media (pointer: coarse) {
		.we-chip { min-height: 40px; }
	}
</style>
