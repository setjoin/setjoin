<svelte:options runes={true} />

<script lang="ts">
	let status = $state<'checking' | 'waiting' | 'unavailable'>('checking');

	$effect(() => {
		let stopped = false;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const check = async () => {
			try {
				const response = await fetch('/setup/status');
				if (!response.ok) throw new Error('status unavailable');
				const data = (await response.json()) as { initialized?: boolean };
				if (data.initialized) {
					window.location.replace('/auth/login');
					return;
				}
				if (!stopped) status = 'waiting';
			} catch {
				if (!stopped) status = 'unavailable';
			}
			if (!stopped) timer = setTimeout(check, 2000);
		};
		void check();
		return () => {
			stopped = true;
			if (timer) clearTimeout(timer);
		};
	});
</script>

<svelte:head>
	<title>Setjoin setup</title>
</svelte:head>

<main class="setup-page">
	<section class="setup-card" aria-labelledby="setup-title">
		<header class="setup-brand">
			<h1 id="setup-title" class="setup-wordmark">Setjoin setup</h1>
			<p class="setup-subtitle">Local administrator action required</p>
			<p class="setup-description">This page only reports readiness. It never accepts administrator credentials or backup secrets.</p>
		</header>

		<div class="status" role="status" aria-live="polite">
			<span class:status-dot--warning={status !== 'unavailable'} class:status-dot--danger={status === 'unavailable'} class="status-dot"></span>
			{status === 'checking' ? 'Checking server state…' : status === 'waiting' ? 'Waiting for local setup to complete' : 'The server status endpoint is temporarily unavailable'}
		</div>

		<div class="setup-options">
			<article class="setup-option">
				<h2>New installation</h2>
				<p>Connect to the server using SSH and run the local command below. The password is entered through a hidden prompt and is not placed in browser history or command arguments.</p>
				<code>mailctl bootstrap-admin --email admin@example.com</code>
			</article>

			<article class="setup-option">
				<h2>Restore a backup</h2>
				<p>Run <code>mailctl restore</code> on the server. Recovery sources and secrets are handled by the local operator path; this browser page cannot start or configure a restore.</p>
			</article>
		</div>

		<p class="setup-note">This page checks again automatically and redirects to sign-in after initialization succeeds.</p>
	</section>
</main>

<style>
	.setup-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-4);
	}

	.setup-card {
		width: 100%;
		max-width: 520px;
		padding: var(--space-10);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
		color: var(--text-primary);
	}

	.setup-brand { text-align: center; margin-bottom: var(--space-5); }
	.setup-wordmark {
		font: var(--weight-bold) var(--text-3xl)/var(--leading-tight) var(--font-display);
		letter-spacing: -0.02em;
		margin: 0;
	}
	.setup-subtitle {
		margin: var(--space-2) 0 0;
		font: var(--weight-medium) var(--text-md)/var(--leading-normal) var(--font-sans);
		color: var(--text-secondary);
	}
	.setup-description,
	.setup-option p,
	.setup-note {
		font: var(--weight-regular) var(--text-sm)/var(--leading-normal) var(--font-sans);
		color: var(--text-caption);
	}
	.setup-description { margin: var(--space-1) 0 0; }
	.status {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		font: var(--weight-medium) var(--text-sm)/var(--leading-normal) var(--font-sans);
	}
	.status-dot { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; }
	.status-dot--warning { background: var(--warn); }
	.status-dot--danger { background: var(--danger-solid); }
	.setup-options { display: grid; gap: var(--space-3); margin-top: var(--space-4); }
	.setup-option { padding: var(--space-4); border: 1px solid var(--border-default); border-radius: var(--radius-md); }
	.setup-option h2 {
		margin: 0 0 var(--space-1);
		font: var(--weight-semibold) var(--text-lg)/var(--leading-normal) var(--font-sans);
	}
	.setup-option p { margin: 0; }
	.setup-option > code {
		display: block;
		margin-top: var(--space-3);
		padding: var(--space-2) var(--space-3);
		overflow-wrap: anywhere;
		background: var(--surface-sunken);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font: var(--weight-regular) var(--text-sm)/var(--leading-normal) var(--font-mono);
	}
	.setup-option p code { font-family: var(--font-mono); }
	.setup-note { margin: var(--space-4) 0 0; text-align: center; }
</style>
