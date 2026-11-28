<script lang="ts">
	import { avatarHue, avatarInitials } from './avatarHash';

	interface Props {
		name?: string;
		src?: string;
		size?: 'sm' | 'md' | 'lg' | 'xl';
	}

	let { name = '', src = '', size = 'md' }: Props = $props();

	const SIZES = { sm: 24, md: 32, lg: 40, xl: 64 } as const;

	const px = $derived(SIZES[size]);
	// The src sink accepts ONLY same-origin root-relative paths — every current
	// producer builds /api/blobs/… URLs. Any other shape (absolute URL,
	// protocol-relative host, blob:/data:/javascript: scheme, bare id) falls
	// back to the initials avatar so a future caller cannot introduce a remote
	// or scheme-smuggled image source.
	const safeSrc = $derived(/^\/(?!\/)/.test(src) ? src : '');
	const bg = $derived(safeSrc ? 'var(--gray-200)' : avatarHue(name));
</script>

<span
	class="avatar"
	title={name}
	style="width: {px}px; height: {px}px; font-size: {Math.round(px * 0.38)}px; background: {bg};"
>
	{#if safeSrc}
		<img src={safeSrc} alt={name} />
	{:else}
		{avatarInitials(name)}
	{/if}
</span>

<style>
	.avatar {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		flex: none;
		border-radius: var(--radius-full);
		font-family: var(--font-sans);
		font-weight: var(--weight-semibold);
		color: var(--text-inverse);
		overflow: hidden;
		user-select: none;
	}
	.avatar img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
</style>
