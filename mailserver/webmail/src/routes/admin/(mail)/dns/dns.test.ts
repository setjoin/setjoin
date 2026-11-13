import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import DNSPage from './+page.svelte';

const api = vi.hoisted(() => ({
	adminDNSGenerate: vi.fn(),
	adminDNSVerify: vi.fn(),
	adminGetTLSPolicy: vi.fn(),
	adminPutTLSPolicy: vi.fn(),
}));

vi.mock('$lib/admin/client', () => api);

describe('DNS and outbound TLS policy page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.adminGetTLSPolicy.mockResolvedValue({
			enforce_domains: ['secure.example'],
			skip_domains: ['legacy.example'],
			global_mode: 'opportunistic',
		});
		api.adminPutTLSPolicy.mockResolvedValue(undefined);
		api.adminDNSGenerate.mockResolvedValue({
			recommendedA: 'mail.example.test A 192.0.2.10',
			mx: '10 mail.example.test',
			spf: 'v=spf1 mx -all',
			dkim: [{ selector: 'sj', record: 'sj._domainkey TXT key' }],
			dmarc: 'v=DMARC1; p=reject',
			mtasts: '_mta-sts TXT v=STSv1',
			tlsa: '_25._tcp TLSA 3 1 1 abc',
			reverseDns: '10.2.0.192.in-addr.arpa PTR mail.example.test',
		});
		api.adminDNSVerify.mockResolvedValue({
			allPass: false,
			checks: [
				{ type: 'MX', name: 'example.test', status: 'pass', value: 'mail.example.test' },
				{ type: 'DMARC', name: '_dmarc.example.test', status: 'warn', expected: 'p=reject' },
			],
		});
	});

	it('generates the full DNS/DANE guide and renders a mixed verification result', async () => {
		render(DNSPage);
		await waitFor(() => expect(api.adminGetTLSPolicy).toHaveBeenCalledOnce());
		const domain = screen.getByPlaceholderText('example.com');
		await fireEvent.input(domain, { target: { value: 'example.test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Generate Records' }));
		await waitFor(() => expect(api.adminDNSGenerate).toHaveBeenCalledWith('example.test'));
		expect(screen.getByText('v=spf1 mx -all')).toBeInTheDocument();
		expect(screen.getByText(/DANE-EE/)).toBeInTheDocument();
		expect(screen.getByText(/PTR mail\.example\.test/)).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Verify DNS' }));
		expect(await screen.findByText('DNS Health Check')).toBeInTheDocument();
		expect(screen.getByText('Issues Found')).toBeInTheDocument();
		expect(screen.getByText('p=reject')).toBeInTheDocument();
	});

	it('edits disjoint enforce/skip lists, changes mode, and saves the exact policy', async () => {
		render(DNSPage);
		await screen.findByText('secure.example');
		await fireEvent.click(screen.getByRole('radio', { name: 'Enforce' }));
		const enforce = document.querySelector('#enforce-input') as HTMLInputElement;
		await fireEvent.input(enforce, { target: { value: 'partner.example' } });
		const addButtons = screen.getAllByRole('button', { name: 'Add' });
		await fireEvent.click(addButtons[0]);
		const skip = document.querySelector('#skip-input') as HTMLInputElement;
		await fireEvent.input(skip, { target: { value: 'secure.example' } });
		await fireEvent.click(addButtons[1]);
		// A domain already in enforce must not be duplicated into the plaintext bypass list.
		expect(screen.getAllByText('secure.example')).toHaveLength(1);

		await fireEvent.click(screen.getByRole('button', { name: 'Save Policy' }));
		await waitFor(() => expect(api.adminPutTLSPolicy).toHaveBeenCalledWith({
			enforce_domains: ['secure.example', 'partner.example'],
			skip_domains: ['legacy.example'],
			global_mode: 'enforce',
		}));
		expect(screen.getByText('Saved')).toBeInTheDocument();
	});

	it('keeps both DNS and TLS failures visible', async () => {
		api.adminGetTLSPolicy.mockRejectedValueOnce(new Error('TLS policy unavailable'));
		api.adminDNSGenerate.mockRejectedValueOnce(new Error('DNS backend unavailable'));
		render(DNSPage);
		expect(await screen.findByText('TLS policy unavailable')).toBeInTheDocument();
		const domain = screen.getByPlaceholderText('example.com');
		await fireEvent.input(domain, { target: { value: 'example.test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Generate Records' }));
		expect(await screen.findByText('DNS backend unavailable')).toBeInTheDocument();
	});
});
