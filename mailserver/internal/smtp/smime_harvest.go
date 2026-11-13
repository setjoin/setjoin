package smtp

import (
	"context"
	"strings"

	"setjoin.com/mailserver/internal/smime"
)

// harvestSignerCert stores the verified signer's S/MIME leaf cert for the RECEIVING
// user so future encrypted replies can target it (SP1 Phase 2). It is called from the
// inbound delivery path once the S/MIME verdict is computed.
//
// Policy: harvest ONLY a fully-valid verdict (trusted chain + From-binding). An
// untrusted / invalid / unsigned signer must never be harvestable — VerifyResult.LeafPEM
// is set only on StatusValid, and this hook also gates on Status == StatusValid + a
// non-empty LeafPEM/SignerEmail, so a harvested cert is always one we'd trust.
//
// Best-effort: ANY failure logs at Warn/Debug and returns — harvest must NEVER block or
// fail inbound delivery (a DB hiccup or a malformed cert costs us a stored cert, not a
// dropped message). This function returns nothing for that reason.
//
// Credential / RLS posture: the inbound MTA (InboundServer) runs on the workerPool
// (BYPASSRLS, native-RLS W4 — smtp.NewInboundServer(workerPool, …)), so c.srv.pool IS the
// cross-tenant worker credential. owner_user_id is resolved per-recipient here (from the
// receiving mailbox's user_id, never from a tenant GUC or req.*) — an intentional
// cross-tenant carve-out that mirrors the existing applyPerUserSpam owner lookup, and
// satisfies R2 (owner set from auth-derived data, not request fields). recipient_smime_certs
// is not a messages/message_tags table, so scripts/check-rls-coverage.sh does not gate this
// site and no allowlist entry is required.
//
// Filing address: a 'valid' verdict only guarantees that SOME SAN on the leaf matched the
// message From — it does NOT guarantee that From is the FIRST SAN (res.SignerEmail =
// certEmail(leaf), the first binding email). For a multi-SAN cert these differ, so storing
// res.SignerEmail would file the cert under an address the message never claimed (a real
// mis-filing vector under admin-imported private-CA roots). We therefore file under the
// validated From — fromAddr, the address CertMatchesEmail(leaf, fromAddr) matched in pass 2.
// The reducer lower-cases + trims it (lower(btrim(p_email))); we also TrimSpace here so a
// blank From is gated before the DB round-trip.
func (c *inConnState) harvestSignerCert(ctx context.Context, rcpt, fromAddr string, res *smime.VerifyResult) {
	if res == nil || res.Status != smime.StatusValid || res.LeafPEM == "" {
		return
	}
	harvestEmail := strings.ToLower(strings.TrimSpace(fromAddr))
	if harvestEmail == "" {
		// A valid verdict requires a From-bound SAN, so this should not happen; gate
		// defensively rather than file a cert under an empty address.
		c.srv.logger.Debug("smime harvest: empty From address, skipping", "rcpt", rcpt)
		return
	}

	mailboxID := c.resolveMailboxID(ctx, rcpt)
	if mailboxID == 0 {
		c.srv.logger.Debug("smime harvest: unresolved recipient, skipping", "rcpt", rcpt)
		return
	}

	var ownerUserID int64
	if err := c.srv.pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID,
	).Scan(&ownerUserID); err != nil {
		c.srv.logger.Warn("smime harvest: owner lookup failed (best-effort)", "error", err, "mailbox_id", mailboxID)
		return
	}
	if ownerUserID == 0 {
		// Shared/resource mailbox (user_id IS NULL → scanned as 0): no owning user to
		// harvest for. Skip — harvesting under a NULL/0 owner would violate the FK anyway.
		c.srv.logger.Debug("smime harvest: mailbox has no owning user, skipping", "mailbox_id", mailboxID)
		return
	}

	fp, _, notBefore, notAfter, err := smime.Fingerprint(res.LeafPEM)
	if err != nil {
		c.srv.logger.Warn("smime harvest: fingerprint failed (best-effort)", "error", err)
		return
	}

	var id int64
	if err := c.srv.pool.QueryRow(ctx,
		`SELECT smime_harvest_recipient_cert($1,$2,$3,$4,$5,$6)`,
		ownerUserID, harvestEmail, res.LeafPEM, fp, notBefore, notAfter,
	).Scan(&id); err != nil {
		c.srv.logger.Warn("smime harvest: upsert failed (best-effort)", "error", err, "owner", ownerUserID, "from", harvestEmail)
		return
	}
	c.srv.logger.Debug("smime harvest: stored signer cert", "owner", ownerUserID, "from", harvestEmail, "id", id)
}
