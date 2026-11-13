<svelte:options runes={true} />

<script lang="ts">
	import { adminDNSGenerate, adminDNSVerify, type DNSRecords, type DNSHealth, adminGetTLSPolicy, adminPutTLSPolicy, type TLSPolicy } from '$lib/admin/client';
	import { Card, Button, Badge, Input, Radio, EmptyState, Tag } from '$lib/components/ui';

	let domain = $state('');
	let records = $state<DNSRecords | null>(null);
	let health = $state<DNSHealth | null>(null);
	let loading = $state(false);
	let error = $state('');

	let tlsPolicy = $state<TLSPolicy | null>(null);
	let tlsPolicyLoaded = $state(false);
	let tlsPolicySaving = $state(false);
	let tlsPolicyError = $state('');
	let tlsPolicySaved = $state(false);
	let enforceInput = $state('');
	let skipInput = $state('');

	async function generate() {
		if (!domain.trim()) return;
		loading = true;
		error = '';
		try {
			records = await adminDNSGenerate(domain.trim());
		} catch (e) {
			error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	async function verify() {
		if (!domain.trim()) return;
		loading = true;
		error = '';
		try {
			health = await adminDNSVerify(domain.trim());
		} catch (e) {
			error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	async function loadTLSPolicy() {
		tlsPolicyError = '';
		try {
			tlsPolicy = await adminGetTLSPolicy();
			tlsPolicyLoaded = true;
		} catch (e) {
			tlsPolicyError = (e as Error).message;
		}
	}

	async function saveTLSPolicy() {
		if (!tlsPolicy) return;
		tlsPolicySaving = true;
		tlsPolicyError = '';
		tlsPolicySaved = false;
		try {
			await adminPutTLSPolicy(tlsPolicy);
			tlsPolicySaved = true;
			setTimeout(() => { tlsPolicySaved = false; }, 3000);
		} catch (e) {
			tlsPolicyError = (e as Error).message;
		} finally {
			tlsPolicySaving = false;
		}
	}

	function addEnforceDomain() {
		const d = enforceInput.trim();
		if (!d || !tlsPolicy) return;
		if (!tlsPolicy.enforce_domains.includes(d) && !tlsPolicy.skip_domains.includes(d)) {
			tlsPolicy = { ...tlsPolicy, enforce_domains: [...tlsPolicy.enforce_domains, d] };
		}
		enforceInput = '';
	}

	function removeEnforceDomain(d: string) {
		if (!tlsPolicy) return;
		tlsPolicy = { ...tlsPolicy, enforce_domains: tlsPolicy.enforce_domains.filter(v => v !== d) };
	}

	function addSkipDomain() {
		const d = skipInput.trim();
		if (!d || !tlsPolicy) return;
		if (!tlsPolicy.skip_domains.includes(d) && !tlsPolicy.enforce_domains.includes(d)) {
			tlsPolicy = { ...tlsPolicy, skip_domains: [...tlsPolicy.skip_domains, d] };
		}
		skipInput = '';
	}

	function removeSkipDomain(d: string) {
		if (!tlsPolicy) return;
		tlsPolicy = { ...tlsPolicy, skip_domains: tlsPolicy.skip_domains.filter(v => v !== d) };
	}

	function setGlobalMode(mode: string) {
		if (!tlsPolicy) return;
		tlsPolicy = { enforce_domains: tlsPolicy.enforce_domains, skip_domains: tlsPolicy.skip_domains, global_mode: mode };
	}

	$effect(() => {
		void loadTLSPolicy();
	});
</script>

<div class="sj-dns-page">
	<header class="sj-page-head">
		<h1>DNS Wizard</h1>
	</header>

	{#if error}
		<div class="sj-alert sj-alert--danger">{error}</div>
	{/if}

	<div class="sj-search-bar">
		<Input placeholder="example.com" value={domain} oninput={(e) => domain = (e.target as HTMLInputElement).value} />
		<Button variant="primary" size="sm" onclick={generate} disabled={loading}>{loading ? 'Generating...' : 'Generate Records'}</Button>
		<Button variant="secondary" size="sm" onclick={verify} disabled={loading}>{loading ? 'Verifying...' : 'Verify DNS'}</Button>
	</div>

	{#if !records && !health && !loading && !error}
		<EmptyState title="Enter a domain name and generate DNS records." />
	{/if}

	{#if records}
		{@const r = records}
		{@const recordCards = [
			{ title: 'A Record', content: r.recommendedA },
			{ title: 'MX Record', content: r.mx },
			{ title: 'SPF Record', content: r.spf },
			...r.dkim.map(d => ({ title: 'DKIM Record (' + d.selector + ')', content: d.record })),
			{ title: 'DMARC Record', content: r.dmarc },
			{ title: 'MTA-STS Record', content: r.mtasts || 'N/A' },
		]}
		{#each recordCards as rc}
			<Card>
				{#snippet children()}
					<code class="sj-dns-code">{rc.content}</code>
				{/snippet}
			</Card>
		{/each}

		<Card>
			{#snippet children()}
				<code class="sj-dns-code">{r.tlsa || 'N/A'}</code>
				<p class="sj-dns-note">
					<strong>DANE-EE (3 1 1):</strong> Pins the server TLS certificate SHA-256 hash.
					This record requires <strong>DNSSEC</strong> to be enabled on your domain.
					Generate the hash with:<br/>
					<code>openssl x509 -in /path/to/cert.pem -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':'</code>
				</p>
			{/snippet}
		</Card>

		<Card>
			{#snippet children()}
				<div class="sj-dns-guide">
					<ol>
						<li><strong>Enable DNSSEC</strong> at your domain registrar (Cloudflare: one click; Route53: enable DNSSEC signing; self-hosted: sign zone with <code>dnssec-signzone</code>)</li>
						<li><strong>Publish DS record</strong> in your parent zone -- your registrar provides this after enabling DNSSEC</li>
						<li><strong>Verify DNSSEC</strong>: <code>dig +dnssec {domain} SOA</code> -- look for <code>ad</code> flag (Authenticated Data)</li>
						<li><strong>Publish TLSA record</strong> above once DNSSEC is active on your domain</li>
						<li><strong>Verify DANE</strong>: <code>dig +dnssec _25._tcp.{r.mx.split(' ')[0] || 'mail.' + domain} TLSA</code></li>
					</ol>
				</div>
			{/snippet}
		</Card>

		{#if r.reverseDns}
			<Card>
				{#snippet children()}
					<code class="sj-dns-code">{r.reverseDns}</code>
				{/snippet}
			</Card>
		{/if}
	{/if}

	<!-- Outbound TLS Policy -->
	<Card title="Outbound TLS Policy">
		{#snippet children()}
			{#if tlsPolicyError}
				<div class="sj-alert sj-alert--danger">{tlsPolicyError}</div>
			{/if}

			{#if !tlsPolicy && !tlsPolicyLoaded}
				<p class="sj-hint">Loading...</p>
			{:else if tlsPolicy}
				<div class="sj-tls-section">
					<span class="sj-tls-label">Global Mode</span>
					<div class="sj-tls-options">
						<Radio name="tls-mode" value="opportunistic" checked={tlsPolicy.global_mode === 'opportunistic'} label="Opportunistic" onchange={() => setGlobalMode('opportunistic')} />
						<Radio name="tls-mode" value="enforce" checked={tlsPolicy.global_mode === 'enforce'} label="Enforce" onchange={() => setGlobalMode('enforce')} />
					</div>
				</div>

				<div class="sj-tls-section">
					<label for="enforce-input" class="sj-tls-label">Enforce Domains</label>
					<div class="sj-tls-add-row">
						<Input id="enforce-input" placeholder="domain.example" value={enforceInput} oninput={(e) => enforceInput = (e.target as HTMLInputElement).value} />
						<Button variant="ghost" size="sm" onclick={addEnforceDomain}>Add</Button>
					</div>
					{#if tlsPolicy.enforce_domains.length === 0}
						<p class="sj-hint">No enforce domains</p>
					{:else}
						<div class="sj-tls-tags">
							{#each tlsPolicy.enforce_domains as d}
								<Tag label={d} onremove={() => removeEnforceDomain(d)} />
							{/each}
						</div>
					{/if}
				</div>

				<div class="sj-tls-section">
					<label for="skip-input" class="sj-tls-label">Skip Domains</label>
					{#if tlsPolicy.skip_domains.length > 0}
						<div class="sj-alert sj-alert--warning">
							Mail to skip-listed domains is delivered in plaintext — STARTTLS is bypassed, so it can be read or altered in transit. Use only for domains whose TLS is genuinely broken.
						</div>
					{/if}
					<div class="sj-tls-add-row">
						<Input id="skip-input" placeholder="domain.example" value={skipInput} oninput={(e) => skipInput = (e.target as HTMLInputElement).value} />
						<Button variant="ghost" size="sm" onclick={addSkipDomain}>Add</Button>
					</div>
					{#if tlsPolicy.skip_domains.length === 0}
						<p class="sj-hint">No skip domains</p>
					{:else}
						<div class="sj-tls-tags">
							{#each tlsPolicy.skip_domains as d}
								<Tag label={d} onremove={() => removeSkipDomain(d)} />
							{/each}
						</div>
					{/if}
				</div>

				<div class="sj-tls-section">
					<span class="sj-tls-label">Auto-discovered</span>
					<Card>
						{#snippet children()}
							<p class="sj-hint">via MTA-STS enforce: (none)</p>
							<p class="sj-hint">via DANE: (none)</p>
						{/snippet}
					</Card>
				</div>

				<div class="sj-tls-save-row">
					<Button variant="primary" size="sm" onclick={saveTLSPolicy} disabled={tlsPolicySaving}>
						{tlsPolicySaving ? 'Saving...' : 'Save Policy'}
					</Button>
					{#if tlsPolicySaved}
						<Badge variant="success" label="Saved" />
					{/if}
				</div>
			{/if}
		{/snippet}
	</Card>

	{#if health}
		{@const h = health}
		<Card>
			{#snippet children()}
				<div class="sj-dns-health-head">
					<span class="sj-dns-health-title">DNS Health Check</span>
					{#if h.allPass}
						<Badge variant="success" label="All Pass" />
					{:else}
						<Badge variant="danger" label="Issues Found" />
					{/if}
				</div>
				<table class="sj-table">
					<thead><tr><th>Type</th><th>Name</th><th>Status</th><th>Value / Expected</th></tr></thead>
					<tbody>
						{#each h.checks as c}
							<tr>
								<td>{c.type}</td>
								<td>{c.name}</td>
								<td><Badge variant={c.status === 'pass' ? 'success' : c.status === 'warn' ? 'warning' : 'danger'} label={c.status} /></td>
								<td class="sj-mono sj-text-xs">{c.value || c.expected || '—'}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/snippet}
		</Card>
	{/if}
</div>

<style>
	.sj-dns-page {
		max-width: 980px;
	}

	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-bottom: 16px;
	}
	.sj-page-head h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: 600;
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}

	.sj-alert {
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		margin-bottom: 12px;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
	}
	.sj-alert--danger {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.sj-alert--warning {
		background: var(--warning-bg);
		color: var(--warning-fg);
		border: 1px solid var(--warning-fg);
	}

	.sj-search-bar {
		display: flex;
		gap: 8px;
		align-items: center;
		margin-bottom: 16px;
	}
	.sj-search-bar :global(.sj-input) {
		flex: 1;
	}

	.sj-dns-code {
		display: block;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		background: var(--surface-sunken);
		padding: 8px 12px;
		border-radius: var(--radius-sm);
		word-break: break-all;
		color: var(--text-primary);
	}

	.sj-dns-note {
		margin-top: 12px;
		font-size: var(--text-xs);
		color: var(--text-secondary);
		line-height: 1.6;
	}
	.sj-dns-note code {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		padding: 1px 4px;
		border-radius: 3px;
	}

	.sj-dns-guide {
		font-size: var(--text-sm);
		line-height: 1.6;
	}
	.sj-dns-guide ol {
		padding-left: 20px;
		margin: 0;
	}
	.sj-dns-guide code {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		padding: 1px 4px;
		border-radius: 3px;
	}

	.sj-tls-section {
		margin-bottom: 16px;
	}
	.sj-tls-label {
		font-weight: 600;
		display: block;
		margin-bottom: 4px;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sj-tls-options {
		display: flex;
		gap: 24px;
	}
	.sj-tls-add-row {
		display: flex;
		gap: 8px;
		margin-bottom: 8px;
	}
	.sj-tls-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
	}
	.sj-tls-save-row {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.sj-dns-health-head {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-bottom: 12px;
	}
	.sj-dns-health-title {
		font-weight: 600;
		font-size: var(--text-md);
	}

	.sj-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.sj-table th {
		text-align: left;
		padding: 8px 12px;
		font-size: var(--text-2xs);
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
		font-weight: 600;
		border-bottom: 1px solid var(--border-default);
	}
	.sj-table td {
		padding: 8px 12px;
		border-bottom: 1px solid var(--border-subtle);
	}

	.sj-mono {
		font-family: var(--font-mono);
	}
	.sj-text-xs {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.sj-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
</style>
