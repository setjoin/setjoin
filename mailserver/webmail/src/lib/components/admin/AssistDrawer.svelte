<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import { assistComplete, asRich, type AssistMessage } from '$lib/admin/assist';
	import { Button, IconButton, Input, Spinner } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	let {
		open = false,
		onClose = () => {},
	}: {
		open?: boolean;
		onClose?: () => void;
	} = $props();

	interface ChatMessage {
		id: number;
		role: 'user' | 'assistant';
		content: string;
	}

	let messages = $state<ChatMessage[]>([]);
	let nextId = 0;
	let inputText = $state('');
	let busy = $state(false);
	let error = $state('');
	let transcriptEl = $state<HTMLDivElement | null>(null);
	let dialogEl = $state<HTMLDivElement | null>(null);

	const FOCUSABLE =
		'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

	function focusables(): HTMLElement[] {
		if (!dialogEl) return [];
		return Array.from(dialogEl.querySelectorAll<HTMLElement>(FOCUSABLE));
	}

	/** Dialog-level keydown: Escape closes, Tab/Shift+Tab trap focus within the drawer. */
	function onDialogKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			e.preventDefault();
			onClose();
			return;
		}
		if (e.key !== 'Tab' || !dialogEl) return;
		const items = focusables();
		if (items.length === 0) {
			e.preventDefault();
			dialogEl.focus();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		const inside = active !== null && dialogEl.contains(active);
		if (e.shiftKey) {
			if (!inside || active === first || active === dialogEl) {
				e.preventDefault();
				last.focus();
			}
		} else if (!inside || active === last || active === dialogEl) {
			e.preventDefault();
			first.focus();
		}
	}

	// Focus the drawer when it opens; restore focus to the trigger on close.
	$effect(() => {
		if (!open) return;
		const previouslyFocused = document.activeElement as HTMLElement | null;
		dialogEl?.focus();
		return () => {
			previouslyFocused?.focus();
		};
	});

	// Suggested questions per admin-kit §6.3
	const suggestedQuestions = $derived([
		{ key: 'admin.assist.q_alerts' },
		{ key: 'admin.assist.q_queue' },
		{ key: 'admin.assist.q_threats' },
	]);

	function scrollToBottom() {
		requestAnimationFrame(() => {
			if (transcriptEl) {
				transcriptEl.scrollTop = transcriptEl.scrollHeight;
			}
		});
	}

	/** Render user message — escape HTML then apply bold + code formatting. */
	function userContentHTML(text: string): string {
		const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
		return asRich(escaped);
	}

	/** Render assistant message — escape HTML, apply asRich, then handle newlines. */
	function assistContentHTML(text: string): string {
		const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
		const rich = asRich(escaped);
		return rich
			.split('\n')
			.map((line) => line || '&nbsp;')
			.join('<br>');
	}

	async function send() {
		const text = inputText.trim();
		if (!text || busy) return;
		const userMsg: ChatMessage = { id: nextId++, role: 'user', content: text };
		messages = [...messages, userMsg];
		inputText = '';
		error = '';
		busy = true;
		scrollToBottom();

		try {
			const apiMessages: AssistMessage[] = [
				{
					role: 'system',
					content:
						'You are Assist, the operations copilot inside the setjoin admin portal. ' +
						'Answer concisely and concretely. Style: plain prose and • bullets only — ' +
						'no markdown headings, no emoji, no tables. Answer in English.',
				},
			];
			for (const m of messages) {
				apiMessages.push({ role: m.role, content: m.content });
			}
			const resp = await assistComplete({ messages: apiMessages });
			messages = [...messages, { id: nextId++, role: 'assistant', content: resp.content }];
		} catch (e: unknown) {
			const msg = e instanceof Error ? e.message : t('admin.assist.error_generic');
			error = msg;
		} finally {
			busy = false;
			scrollToBottom();
		}
	}

	function askSuggested(q: { key: string }) {
		inputText = t(q.key);
		send();
	}

	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	}

	// Auto-scroll on new messages
	$effect(() => {
		void messages.length;
		scrollToBottom();
	});
</script>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="sj-assist"
		role="dialog"
		aria-modal="true"
		aria-label={t('admin.assist.title')}
		tabindex="-1"
		bind:this={dialogEl}
		onkeydown={onDialogKeydown}
	>
		<!-- Header -->
		<div class="sj-assist-header">
			<Icon name="Sparkles" size={16} strokeWidth={1.75} class="assist-sparkles" />
			<span class="assist-title">{t('admin.assist.title')}</span>
			<IconButton
				label={t('common.close')}
				variant="ghost"
				size="sm"
				onclick={onClose}
			>
				<Icon name="X" size={16} strokeWidth={1.75} />
			</IconButton>
		</div>

		<!-- Transcript -->
		<div class="sj-assist-transcript" bind:this={transcriptEl}>
			{#if messages.length === 0}
				<div class="assist-empty">
					<p class="assist-intro">
						{t('admin.assist.intro')}
					</p>
					{#each suggestedQuestions as q}
						<button
							class="assist-suggested"
							onclick={() => askSuggested(q)}
							disabled={busy}
						>
							{t(q.key)}
						</button>
					{/each}
				</div>
			{:else}
				{#each messages as msg (msg.id)}
					<div class="assist-message">
						<div class="assist-avatar" class:assist-avatar--user={msg.role === 'user'}>
							<Icon
								name={msg.role === 'user' ? 'Users' : 'Sparkles'}
								size={12}
								strokeWidth={1.75}
							/>
						</div>
						<div class="assist-body">
							<!-- Content is escaped before the small bold/code/newline allowlist. -->
							<!-- eslint-disable-next-line svelte/no-at-html-tags -->
							{@html msg.role === 'assistant'
								? assistContentHTML(msg.content)
								: userContentHTML(msg.content)}
						</div>
					</div>
				{/each}
				{#if busy}
					<div class="assist-message">
						<div class="assist-avatar">
							<Icon name="Sparkles" size={12} strokeWidth={1.75} />
						</div>
						<div class="assist-body">
							<Spinner size={16} />
						</div>
					</div>
				{/if}
				{#if error}
					<div class="assist-error">
						{error}
					</div>
				{/if}
			{/if}
		</div>

		<!-- Input form -->
		<form class="sj-assist-form" onsubmit={(e: Event) => { e.preventDefault(); send(); }}>
			<div style="flex:1; min-width:0;">
					<Input
						bind:value={inputText}
						placeholder={t('admin.assist.placeholder')}
						disabled={busy}
						onkeydown={onKeydown}
					/>
				</div>
			<Button
				size="md"
				disabled={!inputText.trim() || busy}
				onclick={send}
			>
				<Icon name="Send" size={16} strokeWidth={1.75} />
				{t('common.ask')}
			</Button>
		</form>
	</div>
{/if}

<style>
	.sj-assist {
		display: flex;
		flex-direction: column;
		background: var(--surface-card);
		overflow: hidden;
		border-left: 1px solid var(--border-default);
		width: 320px;
		flex: none;
		outline: none;
	}

	@media (max-width: 767px) {
		.sj-assist {
			position: fixed;
			inset: 0;
			z-index: 800;
			width: 100%;
			border-left: none;
		}
	}

	@media (min-width: 1280px) {
		.sj-assist {
			width: 360px;
		}
	}

	/* ── Header ── */
	.sj-assist-header {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 0 12px;
		height: 44px;
		flex: none;
		border-bottom: 1px solid var(--border-subtle);
	}

	:global(.assist-sparkles) {
		color: var(--accent);
		flex: none;
	}

	.assist-title {
		flex: 1;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}

	/* ── Transcript ── */
	.sj-assist-transcript {
		flex: 1;
		overflow-y: auto;
		padding: 14px;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	/* ── Empty state ── */
	.assist-empty {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding-top: 20px;
	}

	.assist-intro {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		line-height: 1.5;
		margin: 0 0 4px;
	}

	.assist-suggested {
		text-align: left;
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		font-size: var(--text-sm);
		font-family: var(--font-sans);
		color: var(--text-primary);
		cursor: pointer;
		transition: background var(--duration-fast) var(--ease-out);
	}

	.assist-suggested:hover {
		background: var(--surface-hover);
	}

	.assist-suggested:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.assist-suggested:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* ── Messages ── */
	.assist-message {
		display: flex;
		gap: 8px;
		align-items: flex-start;
	}

	.assist-avatar {
		width: 22px;
		height: 22px;
		border-radius: var(--radius-sm);
		background: var(--accent-subtle);
		color: var(--accent-fg-on-subtle);
		display: flex;
		align-items: center;
		justify-content: center;
		flex: none;
		margin-top: 1px;
	}

	.assist-avatar--user {
		background: var(--surface-sunken);
		color: var(--text-secondary);
	}

	.assist-body {
		flex: 1;
		font-size: var(--text-sm);
		line-height: 1.55;
		white-space: pre-wrap;
		overflow-wrap: break-word;
		color: var(--text-primary);
		min-width: 0;
	}

	:global(.assist-body strong) {
		font-weight: 600;
	}

	:global(.assist-body .sj-code-chip) {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		background: var(--surface-sunken);
		border: 1px solid var(--border-subtle);
		border-radius: 3px;
		padding: 0 4px;
	}

	.assist-error {
		font-size: var(--text-xs);
		color: var(--danger-fg);
		background: var(--danger-subtle);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		line-height: 1.45;
	}

	/* ── Input form ── */
	.sj-assist-form {
		flex: none;
		display: flex;
		gap: 6px;
		padding: 10px;
		border-top: 1px solid var(--border-subtle);
	}
</style>
