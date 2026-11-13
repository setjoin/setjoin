import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const api = vi.hoisted(() => ({
	status: vi.fn(),
	incidents: vi.fn(),
	artifacts: vi.fn(),
	open: vi.fn(),
	action: vi.fn(),
	accept: vi.fn(),
}));

vi.mock('$lib/admin/client', () => ({
	adminMailRecoveryStatus: api.status,
	adminMailRecoveryIncidents: api.incidents,
	adminMailRecoveryArtifacts: api.artifacts,
	adminMailRecoveryOpen: api.open,
	adminMailRecoveryIncidentAction: api.action,
	adminMailRecoveryAccept: api.accept,
}));

import Page from './+page.svelte';

const now = '2026-08-02T00:00:00Z';
const counts = { uploading: 0, quarantined: 1, accepted: 0, rejected: 0, deduplicated: 0 };

function recoveryStatus(withSignal = true) {
	return {
		installationId: 'installation-1',
		localTimelineGeneration: '8',
		lastWallClock: now,
		lastBootEpoch: 'boot-local',
		lastBootAt: now,
		restoreDeclaredAt: now,
		signals: withSignal ? [{
			mailboxId: '42', email: 'owner@example.test', tokenSha256: 'a'.repeat(64),
			timelineGeneration: '11', stateWatermark: '99', bootEpoch: 'boot-new',
			issuedAt: now, observedAt: now, signalClass: 'client_observed_newer_timeline',
		}] : [],
	};
}

describe('mail recovery admin console', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.status.mockResolvedValue(recoveryStatus());
		api.incidents.mockResolvedValue([]);
		api.artifacts.mockResolvedValue([]);
		api.open.mockResolvedValue({ id: 'incident-1' });
		api.action.mockResolvedValue(undefined);
		api.accept.mockResolvedValue(undefined);
	});

	it('requires selected signed evidence and opens only a bounded incident', async () => {
		render(Page);
		const open = await screen.findByRole('button', { name: 'Open recovery incident' });
		expect(open).toBeDisabled();
		await fireEvent.click(screen.getByRole('checkbox', { name: /owner@example\.test/ }));
		expect(open).toBeEnabled();
		await fireEvent.click(open);

		await waitFor(() => expect(api.open).toHaveBeenCalledTimes(1));
		expect(api.open).toHaveBeenCalledWith(expect.objectContaining({
			mailboxIds: ['42'],
			evidence: { '42': 'a'.repeat(64) },
			minimumTimeline: '11',
			maximumTimeline: '11',
			approvalRequired: true,
		}));
	});

	it('does not allow a clock anomaly alone to open intake', async () => {
		api.status.mockResolvedValue(recoveryStatus(false));
		render(Page);
		expect(await screen.findByText('No credible newer timeline')).toBeInTheDocument();
		expect(screen.getByText(/clock anomaly alone cannot open mail intake/i)).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Open recovery incident' })).not.toBeInTheDocument();
	});

	it('reviews quarantine provenance before an explicit acceptance', async () => {
		api.incidents.mockResolvedValue([{
			id: 'incident-1', status: 'open', minimumTimeline: '9', maximumTimeline: '12',
			reason: 'Verified rollback evidence', openedBy: '1', approvalRequired: false,
			approvedBy: '1', expiresAt: now, createdAt: now, mailboxCount: 1, counts,
		}]);
		api.artifacts.mockResolvedValue([{
			id: 'artifact-1', mailboxId: '42', uploadingUserId: '7', deviceId: 'device-1',
			artifactIdentity: 'b'.repeat(64), rawMimeSha256: 'c'.repeat(64), rawMimeSize: '512',
			signedTimeline: '11', signedBootEpoch: 'boot-new', headers: { subject: 'Recovered subject', from: 'sender@example.test' },
			malwareStatus: 'clean', status: 'quarantined', rejectionReason: null,
			forkConsented: false, createdAt: now, terminalAt: null,
		}]);

		render(Page);
		await fireEvent.click(await screen.findByRole('button', { name: 'Review artifacts' }));
		expect(await screen.findByText('Recovered subject')).toBeInTheDocument();
		expect(screen.getByText(/SHA-256/)).toHaveTextContent('c'.repeat(64));
		await fireEvent.click(screen.getByRole('button', { name: 'Accept as a recovered copy' }));
		await waitFor(() => expect(api.accept).toHaveBeenCalledWith(
			'artifact-1', 'accept', 'Reviewed recovery evidence and quarantine result',
		));
	});
});
