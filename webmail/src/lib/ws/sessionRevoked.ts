// Handles the gateway's CAE live-revocation push: clear the in-memory token and
// redirect to login. Returns true iff it acted on a SessionRevoked envelope.
export interface SessionRevokedDeps {
	clearToken: () => void;
	redirect: (path: string) => void;
}

export function handleSessionRevoked(
	envelope: { '@type'?: string },
	deps: SessionRevokedDeps
): boolean {
	if (envelope?.['@type'] !== 'SessionRevoked') return false;
	deps.clearToken();
	deps.redirect('/login');
	return true;
}
