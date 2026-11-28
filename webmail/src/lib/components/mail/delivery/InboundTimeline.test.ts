import { render, screen } from '@testing-library/svelte/svelte5';
import { describe, it, expect } from 'vitest';
import InboundTimeline from './InboundTimeline.svelte';

describe('InboundTimeline', () => {
	const hops = [
		{ index: 0, byHost: 'relay.example', timestamp: null, delayMs: null, tlsActive: false, isOurInfra: false, parseOk: true },
		{ index: 1, byHost: 'inbound.setjoin.local', timestamp: null, delayMs: 400, tlsActive: true, isOurInfra: true, parseOk: true }
	];
	it('renders an ordered list with one accessible disclosure per hop', () => {
		render(InboundTimeline, { hops, slowestHopIndex: 1 });
		expect(screen.getByRole('list')).toBeTruthy();
		expect(screen.getAllByRole('button').length).toBe(2);
	});
	it('renders the plain-language trust divider', () => {
		render(InboundTimeline, { hops, slowestHopIndex: 1 });
		expect(screen.getByText(/can be forged/i)).toBeTruthy();
	});

	it('clock skew hop renders hatch marker and skew label, not a bar', () => {
		const skewHops = [
			{ index: 0, byHost: 'sender.example', timestamp: null, delayMs: null, tlsActive: false, isOurInfra: false, parseOk: true },
			{ index: 1, byHost: 'relay.example', timestamp: null, delayMs: -4000, tlsActive: false, isOurInfra: false, parseOk: true }
		];
		const { container } = render(InboundTimeline, { hops: skewHops, slowestHopIndex: null });
		// Skew label must be present
		expect(screen.getByText(/clock skew/i)).toBeTruthy();
		// Hatch marker must be present
		expect(container.querySelector('[data-testid="skew-marker"]')).toBeTruthy();
		// No .bar element should exist for the skew hop (bar elements have a dynamic positive height)
		const bars = container.querySelectorAll('.bar');
		expect(bars.length).toBe(0);
	});

	it('slowest hop carries the bottleneck class', () => {
		const { container } = render(InboundTimeline, { hops, slowestHopIndex: 1 });
		const bottleneck = container.querySelector('.hop--bottleneck');
		expect(bottleneck).toBeTruthy();
		// The bottleneck hop button should contain the slowest host label
		const btn = bottleneck?.querySelector('.hop__btn');
		expect(btn?.textContent).toContain('inbound.setjoin.local');
	});

	it('disclosure button aria-label includes host and infra type', () => {
		render(InboundTimeline, { hops, slowestHopIndex: null });
		const buttons = screen.getAllByRole('button');
		// First hop (external)
		expect(buttons[0].getAttribute('aria-label')).toContain('relay.example');
		expect(buttons[0].getAttribute('aria-label')).toContain('external');
		// Second hop (our infrastructure)
		expect(buttons[1].getAttribute('aria-label')).toContain('inbound.setjoin.local');
		expect(buttons[1].getAttribute('aria-label')).toContain('our infrastructure');
	});
});
