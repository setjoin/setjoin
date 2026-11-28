<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Button, Badge } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { user } from '$lib/stores/auth';
	import { logger } from '$lib/logger';
	import { getGlobalSourceConfig, type GlobalIMAPConfig, type GlobalEWSConfig } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let step = $state<'config' | 'upload' | 'running' | 'complete'>('config');
	let error = $state('');
	let migrationError = $state('');
	let loading = $state(false);

	let sourceType = $state<'imap' | 'ews' | 'm365'>('imap');

	// IMAP config
	let imapHost = $state('');
	let imapPort = $state('993');
	let customPort = $state('');
	let imapMode = $state('tls');
	let imapUser = $state('');
	let imapPass = $state('');
	let testResult = $state<string | null>(null);

	// EWS config
	let ewsUrl = $state('');
	let ewsUser = $state('');
	let ewsPass = $state('');

	// M365 status
	let m365Configured = $state<boolean | null>(null);

	// Load global defaults when source type changes
	$effect(() => {
		const type = sourceType;
		loadGlobalDefaults(type);
	});

	async function loadGlobalDefaults(type: string) {
		m365Configured = null;
		try {
			const config = await getGlobalSourceConfig(type);
			if (!config) {
				if (type === 'm365') m365Configured = false;
				return;
			}
			if (type === 'imap') {
				const c = config as GlobalIMAPConfig;
				if (c.host && !imapHost) imapHost = c.host;
				if (c.port) imapPort = String(c.port);
				if (c.tls_mode && imapMode === 'tls') imapMode = c.tls_mode;
			} else if (type === 'ews') {
				const c = config as GlobalEWSConfig;
				if (c.serverURL && !ewsUrl) ewsUrl = c.serverURL;
				if (c.username && !ewsUser) ewsUser = c.username;
				if (c.password && !ewsPass) ewsPass = c.password;
			} else if (type === 'm365') {
				m365Configured = true;
			}
		} catch {
			// Admin config is optional; silently ignore
		}
	}

	// ICS/VCF upload
	let conflictStrategy = $state('skip');

	// Progress
	let jobId = $state(0);
	let progress = $state<Record<string, unknown>>({});
	let errorLog = $state<string[]>([]);
	let jobStatus = $state('');

	// Completion
	let imported = $state(0);
	let skipped = $state(0);

	onMount(() => {
		pollStatus();
	});

	let pollTimer: ReturnType<typeof setInterval>;

	async function testConnection() {
		testResult = null;
		loading = true;
		try {
			const res = await fetch('/auth/me/migration/test-imap', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					host: imapHost,
					port: imapPort === 'other' ? parseInt(customPort) : parseInt(imapPort),
					tls_mode: imapMode,
					credentials: { username: imapUser, password: imapPass }
				})
			});
			const data = await res.json();
			testResult = data.success ? t('settings.migration.test_success') : `Failed: ${data.error}`;
		} catch (err) {
			testResult = `Error: ${parseError(err).message}`;
		} finally {
			loading = false;
		}
	}

	async function startMigration() {
		loading = true;
		error = '';
		try {
			// 1. Create the migration job
			let body: Record<string, unknown>;
			if (sourceType === 'imap') {
				body = {
					source_type: 'imap',
					conflict_strategy: conflictStrategy,
					imap_config: {
						host: imapHost,
						port: imapPort === 'other' ? parseInt(customPort) : parseInt(imapPort),
						tls_mode: imapMode,
						credentials: { username: imapUser, password: imapPass }
					}
				};
			} else {
				body = {
					source_type: 'ews',
					conflict_strategy: conflictStrategy,
					ews_config: {
						server_url: ewsUrl,
						credentials: { username: ewsUser, password: ewsPass }
					}
				};
			}
			const res = await fetch('/auth/me/migration', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify(body)
			});
			if (!res.ok) throw new Error(await res.text());
			const data = await res.json();
			jobId = data.id;

			// 2. Upload ICS/VCF files if provided
			const icsFile = (document.getElementById('ics-file') as HTMLInputElement)?.files?.[0];
			const vcfFile = (document.getElementById('vcf-file') as HTMLInputElement)?.files?.[0];
			if (icsFile || vcfFile) {
				const formData = new FormData();
				if (icsFile) formData.append('ics', icsFile);
				if (vcfFile) formData.append('vcf', vcfFile);
				await fetch(`/auth/me/migration/upload?job_id=${jobId}`, {
					method: 'POST',
					credentials: 'include',
					body: formData
				});
			}

			step = 'running';
			pollTimer = setInterval(pollStatus, 2000);
		} catch (err) {
			error = `Failed to start migration: ${err}`;
		} finally {
			loading = false;
		}
	}

	async function pollStatus() {
		try {
			const res = await fetch('/auth/me/migration', { credentials: 'include' });
			const data = await res.json();
			if (data.status === 'none') return;

			jobStatus = data.status;
			progress = typeof data.progress === 'object' ? data.progress : {};
			errorLog = Array.isArray(data.error_log) ? data.error_log : [];

			if (data.status === 'completed' || data.status === 'cancelled' || data.status === 'failed') {
				clearInterval(pollTimer);
				if (data.status === 'completed') {
					step = 'complete';
					imported = (progress as any)?.ics?.imported ?? 0;
					skipped = (progress as any)?.ics?.skipped ?? 0;
				}
				if (data.status === 'failed') {
					error = errorLog.join('; ');
				}
			}
		} catch (err) {
			migrationError = parseError(err).message;
			logger.error('poll migration status', err);
		}
	}

	async function cancelMigration() {
		loading = true;
		migrationError = '';
		try {
			await fetch('/auth/me/migration/cancel', { method: 'POST', credentials: 'include' });
			clearInterval(pollTimer);
			step = 'config';
			error = t('settings.migration.cancelled');
		} catch (err) {
			migrationError = parseError(err).message;
			logger.error('cancel migration', err);
		} finally {
			loading = false;
		}
	}

	async function pauseMigration() {
		loading = true;
		migrationError = '';
		try {
			await fetch('/auth/me/migration/pause', { method: 'POST', credentials: 'include' });
			jobStatus = 'paused';
		} catch (err) {
			migrationError = parseError(err).message;
			logger.error('pause migration', err);
		} finally {
			loading = false;
		}
	}

	async function resumeMigration() {
		loading = true;
		migrationError = '';
		try {
			await fetch('/auth/me/migration/resume', { method: 'POST', credentials: 'include' });
			jobStatus = 'fetching';
			pollStatus();
		} catch (err) {
			migrationError = parseError(err).message;
			logger.error('resume migration', err);
		} finally {
			loading = false;
		}
	}

	function nextStep() {
		if (step === 'config') step = 'upload';
		else if (step === 'upload') startMigration();
	}

	// Derive test-result badge variant
	function testBadgeVariant(result: string): 'success' | 'danger' {
		return result === t('settings.migration.test_success') ? 'success' : 'danger';
	}
</script>

<div class="migration-page">
	<h1>{t('settings.migration.title')}</h1>
	<p class="migration-subtitle">{t('settings.migration.subtitle')}</p>

	{#if error}
		<div class="error-banner" role="alert">{error}</div>
	{/if}
	{#if migrationError}
		<div class="error-banner" role="alert">{migrationError}</div>
	{/if}

	{#if step === 'config'}
		<section class="migration-step">
			<h2>{t('settings.migration.step1.title')}</h2>
			<div class="source-picker">
				<button
					class="source-chip"
					class:active={sourceType === 'imap'}
					onclick={() => { sourceType = 'imap'; testResult = null; }}
				>
					<Icon name="Mail" size={20} strokeWidth={1.75} />
					<span class="source-chip-label">{t('settings.migration.source.imap')}</span>
				</button>
				<button
					class="source-chip"
					class:active={sourceType === 'ews'}
					onclick={() => { sourceType = 'ews'; testResult = null; }}
				>
					<Icon name="ArrowLeftRight" size={20} strokeWidth={1.75} />
					<span class="source-chip-label">{t('settings.migration.source.ews')}</span>
				</button>
				<button
					class="source-chip"
					class:active={sourceType === 'm365'}
					onclick={() => { sourceType = 'm365'; testResult = null; }}
				>
					<Icon name="Cloud" size={20} strokeWidth={1.75} />
					<span class="source-chip-label">{t('settings.migration.source.m365')}</span>
				</button>
			</div>

			{#if sourceType === 'm365'}
				<div class="m365-notice">
					{#if m365Configured === null}
						<p>{t('settings.migration.m365.checking')}</p>
					{:else if m365Configured}
						<p>{t('settings.migration.m365.configured')}</p>
					{:else}
						<p>{t('settings.migration.m365.not_configured')}</p>
					{/if}
				</div>
			{:else if sourceType === 'ews'}
				<h2>{t('settings.migration.step2.ews.title')}</h2>
				<div class="form-group">
					<label for="ews-url">{t('settings.migration.field.ews_url')}</label>
					<input class="sj-input-native" type="url" id="ews-url" bind:value={ewsUrl}
						placeholder="https://exchange.company.com/EWS/Exchange.asmx" />
				</div>
				<div class="form-group">
					<label for="ews-user">{t('settings.migration.field.ews_user')}</label>
					<input class="sj-input-native" type="text" id="ews-user" bind:value={ewsUser} placeholder="DOMAIN\\user" />
				</div>
				<div class="form-group">
					<label for="ews-pass">{t('settings.migration.field.ews_pass')}</label>
					<input class="sj-input-native" type="password" id="ews-pass" bind:value={ewsPass}
						placeholder={t('settings.migration.field.ews_pass')} />
				</div>
				<Button variant="primary" onclick={nextStep} disabled={!ewsUrl || !ewsUser || !ewsPass}>
					{t('settings.migration.next_upload')}
				</Button>
			{:else}
				<h2>{t('settings.migration.step2.imap.title')}</h2>
				<div class="form-group">
					<label for="imap-host">{t('settings.migration.field.server')}</label>
					<input class="sj-input-native" id="imap-host" type="text" bind:value={imapHost} placeholder="imap.example.com" />
				</div>
				<div class="form-group">
					<label for="imap-port">{t('settings.migration.field.port')}</label>
					<select class="sj-select-native" id="imap-port" bind:value={imapPort}>
						<option value="993">993 (TLS)</option>
						<option value="143">143 (STARTTLS)</option>
						<option value="other">{t('settings.migration.port.other')}</option>
					</select>
					{#if imapPort === 'other'}
						<label for="custom-port" class="form-label-inline">{t('settings.migration.custom_port')}</label>
						<input class="sj-input-native" id="custom-port" type="number" min="1" max="65535"
							bind:value={customPort} placeholder="e.g. 587" />
					{/if}
				</div>
				<div class="form-group">
					<label for="imap-mode">{t('settings.migration.field.security')}</label>
					<select class="sj-select-native" id="imap-mode" bind:value={imapMode}>
						<option value="tls">{t('settings.migration.security.tls')}</option>
						<option value="starttls">{t('settings.migration.security.starttls')}</option>
						<option value="none">{t('settings.migration.security.none')}</option>
					</select>
				</div>
				<div class="form-group">
					<label for="imap-user">{t('settings.migration.field.username')}</label>
					<input class="sj-input-native" id="imap-user" type="text" bind:value={imapUser} placeholder="you@old-provider.com" />
				</div>
				<div class="form-group">
					<label for="imap-pass">{t('settings.migration.field.password')}</label>
					<input class="sj-input-native" id="imap-pass" type="password" bind:value={imapPass} placeholder={t('settings.migration.field.password')} />
				</div>
				<Button variant="secondary" onclick={testConnection} disabled={loading || !imapHost || !imapUser || !imapPass}>
					{loading ? t('settings.migration.testing') : t('settings.migration.test_connection')}
				</Button>
				{#if testResult}
					<div class="test-result-row">
						<Badge variant={testBadgeVariant(testResult)} label={testResult} />
					</div>
				{/if}
				<Button variant="primary" onclick={nextStep} disabled={!testResult || testResult !== t('settings.migration.test_success')}>
					{t('settings.migration.next_upload')}
				</Button>
			{/if}
		</section>

	{:else if step === 'upload'}
		<section class="migration-step">
			<h2>{t('settings.migration.step_upload.title')}</h2>
			<div class="form-group">
				<label for="ics-file">{t('settings.migration.field.ics')}</label>
				<input id="ics-file" type="file" accept=".ics" />
			</div>
			<div class="form-group">
				<label for="vcf-file">{t('settings.migration.field.vcf')}</label>
				<input id="vcf-file" type="file" accept=".vcf" />
			</div>
			<div class="form-group">
				<label for="conflict-strategy">{t('settings.migration.field.conflict')}</label>
				<select class="sj-select-native" id="conflict-strategy" bind:value={conflictStrategy}>
					<option value="skip">{t('settings.migration.conflict.skip')}</option>
					<option value="overwrite">{t('settings.migration.conflict.overwrite')}</option>
					<option value="rename">{t('settings.migration.conflict.rename')}</option>
				</select>
			</div>
			<div class="action-row">
				<Button variant="primary" onclick={startMigration} disabled={loading}>
					{loading ? t('settings.migration.starting') : t('settings.migration.start')}
				</Button>
				<Button variant="secondary" onclick={() => { step = 'config'; }}>{t('settings.migration.back')}</Button>
			</div>
		</section>

	{:else if step === 'running'}
		<section class="migration-step">
			<h2>{t('settings.migration.running.title')}</h2>
			<div class="progress-container">
				<div class="progress-track">
					<div class="progress-fill" style="width: {jobStatus === 'completed' ? 100 : 50}%"></div>
				</div>
			</div>
			<p class="status-line">{t('settings.migration.status_label', { status: jobStatus })}</p>
			{#if Object.keys(progress).length > 0}
				<div class="phase-stats">
					{#each Object.entries(progress) as [phase, stats]}
						<div class="phase-stat">
							<strong>{phase}</strong>:
							{#if stats && typeof stats === 'object'}
								{` imported: ${(stats as any).imported ?? 0}, skipped: ${(stats as any).skipped ?? 0}`}
							{/if}
						</div>
					{/each}
				</div>
			{/if}
			{#if errorLog.length > 0}
				<div class="error-log" role="log">
					<h3>{t('settings.migration.errors_title')}</h3>
					<ul>
						{#each errorLog as err}
							<li>{err}</li>
						{/each}
					</ul>
				</div>
			{/if}
			<p class="notice">{t('settings.migration.notice')}</p>
			<div class="action-row">
				{#if jobStatus === 'paused'}
					<Button variant="primary" onclick={resumeMigration} disabled={loading}>{t('settings.migration.resume')}</Button>
				{:else}
					<Button variant="secondary" onclick={pauseMigration} disabled={loading}>{t('settings.migration.pause')}</Button>
				{/if}
				<Button variant="danger" onclick={cancelMigration} disabled={loading}>{t('settings.migration.cancel')}</Button>
			</div>
		</section>

	{:else if step === 'complete'}
		<section class="migration-step">
			<h2>{t('settings.migration.complete.title')}</h2>
			<div class="completion-card">
				<p>{t('settings.migration.imported', { count: String(imported) })}</p>
				<p>{t('settings.migration.skipped', { count: String(skipped) })}</p>
			</div>
			<Button variant="primary" onclick={() => { window.location.href = '/inbox'; }}>
				{t('settings.migration.go_inbox')}
			</Button>
		</section>
	{/if}
</div>

<style>
	.migration-page {
		max-width: 600px;
		margin: 2rem auto;
		padding: 1rem;
	}

	h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0 0 var(--space-1);
	}

	.migration-subtitle {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 var(--space-4);
	}

	h2 {
		font-family: var(--font-sans);
		font-size: var(--text-lg);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: var(--space-4) 0 var(--space-2);
	}

	.migration-step {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-1);
	}

	.form-group label {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}

	.form-label-inline {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		margin-top: var(--space-2);
	}

	/* Native input/select — minimal styling to match M1 Input visually */
	.sj-input-native,
	.sj-select-native {
		width: 100%;
		padding: 0 var(--space-2);
		height: 32px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		box-sizing: border-box;
	}

	.sj-input-native:focus,
	.sj-select-native:focus {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.action-row {
		display: flex;
		gap: var(--space-2);
		flex-wrap: wrap;
		margin-top: var(--space-2);
	}

	/* Error banner */
	.error-banner {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-solid);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		margin-bottom: var(--space-3);
	}

	/* Test result */
	.test-result-row {
		margin-top: var(--space-1);
	}

	/* Source picker */
	.source-picker {
		display: flex;
		gap: var(--space-2);
		margin: var(--space-3) 0;
		flex-wrap: wrap;
	}

	.source-chip {
		flex: 1;
		min-width: 100px;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-1);
		padding: var(--space-3) var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		transition: border-color var(--duration-fast) var(--ease-out),
		            background var(--duration-fast) var(--ease-out);
	}

	.source-chip:hover {
		border-color: var(--accent);
		color: var(--text-primary);
	}

	.source-chip:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.source-chip.active {
		border-color: var(--accent);
		background: var(--surface-selected);
		color: var(--text-primary);
	}

	.source-chip-label {
		font-weight: var(--weight-medium);
	}

	/* M365 notice */
	.m365-notice {
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-3);
		margin: var(--space-2) 0;
	}

	.m365-notice p {
		margin: 0;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}

	/* Progress bar */
	.progress-container {
		margin: var(--space-2) 0;
	}

	.progress-track {
		height: 8px;
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-full);
		overflow: hidden;
	}

	.progress-fill {
		height: 100%;
		background: var(--accent);
		border-radius: var(--radius-full);
		transition: width 0.5s var(--ease-out);
	}

	.status-line {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
	}

	.phase-stats {
		margin: var(--space-1) 0;
	}

	.phase-stat {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding: var(--space-1) 0;
	}

	/* Error log */
	.error-log {
		margin-top: var(--space-2);
		background: var(--warning-bg);
		border: 1px solid var(--warning-solid);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}

	.error-log h3 {
		margin: 0 0 var(--space-1);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--warning-fg);
	}

	.error-log ul {
		margin: 0;
		padding-left: 1.25rem;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.notice {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: var(--space-2) 0 0;
	}

	/* Completion */
	.completion-card {
		background: var(--success-bg);
		border: 1px solid var(--success-solid);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		margin: var(--space-2) 0;
	}

	.completion-card p {
		margin: 0 0 var(--space-1);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--success-fg);
	}

	.completion-card p:last-child {
		margin-bottom: 0;
	}
</style>
