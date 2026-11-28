<svelte:options runes={true} />

<script lang="ts">
	import { Card, Button, Input, Select, Spinner } from '$lib/components/ui';
	import { adminFetch } from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';

	let status = $state<any>({ challenge: '', domains: '', email: '', dns_provider: '', cache_dir: '', enabled: false });
	let saved = $state(false);
	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');

	const CHALLENGE_OPTIONS = [
		{ value: '', label: 'None (static cert only)' },
		{ value: 'tls-alpn-01', label: 'TLS-ALPN-01 (port 443)' },
		{ value: 'http-01', label: 'HTTP-01 (port 80)' },
		{ value: 'dns-01', label: 'DNS-01 (air-gap compatible)' },
	];

	const DNS_PROVIDER_OPTIONS = [
		{ value: '', label: 'Select provider...' },
		{ value: 'cloudflare', label: 'Cloudflare' },
		{ value: 'route53', label: 'AWS Route 53' },
		{ value: 'rfc2136', label: 'RFC 2136 (generic)' },
	];

	async function loadStatus() {
		loading = true;
		error = '';
		try {
			const res = await adminFetch('/admin/tls/status');
			const data = await res.json();
			status = {
				...data,
				challenge: data.challenge === 'none' ? '' : (data.challenge ?? ''),
				domains: Array.isArray(data.domains) ? data.domains.join(', ') : (data.domains ?? ''),
				email: data.email ?? '',
				dns_provider: data.dns_provider ?? '',
				cache_dir: data.cache_dir ?? '',
			};
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function save() {
		error = '';
		saved = false;
		saving = true;
		try {
			await adminFetch('/admin/tls/config', {
				method: 'PUT',
				body: JSON.stringify({
					'tls_autocert_challenge': status.challenge || '',
					'tls_autocert_domains': status.domains || '',
					'tls_autocert_email': status.email || '',
					'tls_dns_provider': status.dns_provider || '',
					'tls_autocert_cache_dir': status.cache_dir || '',
				}),
			});
			saved = true;
			setTimeout(() => (saved = false), 3000);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	$effect(() => { loadStatus(); });
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>TLS certificate management</h1>
		<p class="page-desc">ACME automatic certificates and renewal for your mail hostnames.</p>
	</div>
</header>

<Card title="Certificate settings">
	{#snippet children()}
		{#if loading}
			<div class="tls-loading">
				<Spinner size={20} />
				<span>Loading TLS status…</span>
			</div>
		{:else}
			<div class="tls-form">
				<Select
					label="ACME challenge type"
					options={CHALLENGE_OPTIONS}
					bind:value={status.challenge}
				/>

				<Input
					label="Domains"
					type="text"
					placeholder="mail.corp.com, imap.corp.com"
					bind:value={status.domains}
				/>

				<Input
					label="Notification email"
					type="email"
					bind:value={status.email}
				/>

				{#if status.challenge === 'dns-01'}
					<Select
						label="DNS provider"
						options={DNS_PROVIDER_OPTIONS}
						bind:value={status.dns_provider}
					/>
				{/if}

				{#if status.cert_info}
					<div class="tls-cert" class:tls-cert--warn={status.cert_info.days_left < 30}>
						<div>Certificate: {status.cert_info.subject}</div>
						<div>Issuer: {status.cert_info.issuer}</div>
						<div>Expires: {status.cert_info.not_after} ({status.cert_info.days_left} days)</div>
					</div>
				{/if}

				{#if error}
					<p class="tls-error" role="alert">{error}</p>
				{/if}

				{#if saved}
					<p class="tls-success">Saved. Restart gateway to apply.</p>
				{/if}

				<div class="tls-actions">
					<Button variant="primary" size="md" onclick={save} disabled={saving || !hasPermission($adminPermissions, 'security.write')}>
						{saving ? 'Saving…' : 'Save'}
					</Button>
				</div>
			</div>
		{/if}
	{/snippet}
</Card>

<style>
	.page-header {
		margin-bottom: 16px;
	}

	.page-header h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.page-desc {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: var(--leading-normal);
	}

	.tls-loading {
		display: flex;
		align-items: center;
		gap: 10px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		padding: 12px 0;
	}

	.tls-form {
		display: flex;
		flex-direction: column;
		gap: 14px;
		max-width: 480px;
	}

	.tls-cert {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--success-fg);
		background: var(--success-bg);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
		line-height: var(--leading-relaxed);
	}

	.tls-cert--warn {
		color: var(--warning-fg);
		background: var(--warning-bg);
	}

	.tls-error {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 8px 12px;
		margin: 0;
	}

	.tls-success {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--success-fg);
		background: var(--success-bg);
		border-radius: var(--radius-sm);
		padding: 8px 12px;
		margin: 0;
	}

	.tls-actions {
		display: flex;
		gap: 8px;
	}
</style>
