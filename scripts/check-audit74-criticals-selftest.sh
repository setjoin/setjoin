#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-audit74-criticals-selftest.sh — proves check-audit74-criticals.sh
# actually FIRES. Builds a synthetic scratch tree carrying a representative
# subset of the 10 fix signatures (one per source file the real guard checks,
# so every FILES[] path is exercised at least once), asserts:
#   (A) with every signature present, the guard PASSES.
#   (B) with ONE signature removed (C9, the passkey-takeover fix — picked
#       because it's the highest-severity of the 12 checks), the guard FAILS
#       and NAMES C9 specifically (not just "something failed").
#   (C) a completely missing file (simulating a wholesale file deletion/move)
#       is also caught and named.
# Then, separately:
#   (D) the guard run against the REAL tree (no AUDIT_ROOT override) is
#       currently green — proves the guard isn't just correct in the
#       synthetic case but also non-broken against live code right now.
# Never mutates the real tree.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-audit74-criticals.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p \
  "$WORK/mailserver/internal/acme" \
  "$WORK/mailserver/internal/blob" \
  "$WORK/mailserver/internal/carddav" \
  "$WORK/mailserver/internal/imap" \
  "$WORK/mailserver/internal/ldap" \
  "$WORK/mailserver/internal/scim" \
  "$WORK/mailserver/internal/storage" \
  "$WORK/mailserver/internal/webdav" \
  "$WORK/mailserver/internal/caldav" \
  "$WORK/authserver/internal/authn" \
  "$WORK/authserver/internal/handlers"

write_all_fixed() {
  cat >"$WORK/mailserver/internal/acme/dns01.go" <<'GO'
package acme
func obtain() {
	blob := append(res.PrivateKey, res.Certificate...)
	_ = blob
}
GO
  cat >"$WORK/mailserver/internal/blob/handler.go" <<'GO'
package blob
func (h *Handler) Put() {
	if !bytes.Equal(sum, want) {
		http.Error(w, "sha256 mismatch", http.StatusBadRequest)
		return
	}
	h.minio.CopyObject(ctx, dst, src)
}
GO
  cat >"$WORK/mailserver/internal/carddav/carddav.go" <<'GO'
package carddav
func scanContact(rows pgx.Rows, c *contactRow) error {
	return rows.Scan(&c.ID, &c.InstantMsgs, &c.Notes)
}
GO
  cat >"$WORK/mailserver/internal/imap/imap.go" <<'GO'
package imap
func (c *connState) handleAuthenticate(ctx context.Context, tag, args string) {
	f := strings.Fields(args)
	if len(f) == 0 {
		c.reply(tag, "BAD mechanism required")
		return
	}
}
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic in handleConn (recovered)", "panic", r)
		}
	}()
}
GO
  cat >"$WORK/mailserver/internal/ldap/search.go" <<'GO'
package ldap
func (s *Server) searchContacts() {
	q := `SELECT c.id FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id WHERE ab.is_shared = TRUE`
	_ = q
}
GO
  cat >"$WORK/mailserver/internal/scim/user.go" <<'GO'
package scim
func count() {
	s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM user_identity_links l
		JOIN users u ON u.id=l.user_id
		WHERE l.source_id=$%d AND l.state='active'
		AND 'provision'=ANY(l.purposes)
		AND NOT is_guest_account(u.id) AND %s`, sourceArg, where))
}
GO
  cat >"$WORK/mailserver/internal/storage/posix_worm_linux.go" <<'GO'
package storage
func getFlags() {
	unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags)))
}
GO
  cat >"$WORK/mailserver/internal/webdav/webdav.go" <<'GO'
package webdav
func ResolveProperties(value any, ok bool) {
	if !ok || isNilPropertyValue(value) {
		return
	}
}
GO
  cat >"$WORK/mailserver/internal/caldav/webdav.go" <<'GO'
package caldav
func buildPropstat() {
	resolution := webdav.ResolveProperties(
	_ = resolution
}
GO
  cat >"$WORK/authserver/internal/authn/webauthn.go" <<'GO'
package authn
func (p *PasskeyProvider) persistCredential(ctx context.Context, userID int64, cred *webauthn.Credential) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO passkey_credentials (id, user_id, public_key) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET public_key = $3
		WHERE passkey_credentials.user_id = EXCLUDED.user_id`)
	return err
}
GO
  cat >"$WORK/authserver/internal/handlers/push.go" <<'GO'
package handlers
func (h *mfaHandler) PushMFAVerify(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "in-band push answer is not accepted; approve the sign-in on your enrolled device"})
}
GO
  cat >"$WORK/authserver/internal/handlers/device.go" <<'GO'
package handlers
func approve(h *deviceHandler, r *http.Request, userID int64, req approveReq) error {
	return authn.VerifyPushApproval(publicKey, canonical, req.Signature)
}
GO
}

pass=0
fail=0
ok() {
  echo "  ok: $1"
  pass=$((pass + 1))
}
bad() {
  echo "  FAIL: $1"
  fail=$((fail + 1))
}

# (A) everything fixed → guard passes.
write_all_fixed
rc=0
out="$(AUDIT_ROOT="$WORK" bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(A) all-fixed synthetic tree passes the guard"; else bad "(A) guard FAILED against an all-fixed synthetic tree:"$'\n'"$out"; fi

# (B) revert C9 (remove the user_id scoping clause) → guard fails, names C9.
cat >"$WORK/authserver/internal/authn/webauthn.go" <<'GO'
package authn
func (p *PasskeyProvider) persistCredential(ctx context.Context, userID int64, cred *webauthn.Credential) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO passkey_credentials (id, user_id, public_key) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET public_key = $3`)
	return err
}
GO
rc=0
out="$(AUDIT_ROOT="$WORK" bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(B) reverted C9 fails the guard"; else bad "(B) guard PASSED with C9 reverted (false-negative!)"; fi
if printf '%s' "$out" | grep -q '^  REGRESSION: C9 '; then ok "(B) names C9 specifically"; else bad "(B) did not name C9 in the failure output"; fi
# restore C9 for the next case
write_all_fixed

# (C) weaken source ownership while retaining the join. This is the historical
# false-negative: the old C6 signature alone still passed.
perl -0pi -e "s/WHERE l\\.source_id=\\\$%d AND l\\.state='active'/WHERE true AND l.state='active'/" \
  "$WORK/mailserver/internal/scim/user.go"
rc=0
out="$(AUDIT_ROOT="$WORK" bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(C) removed SCIM source predicate fails the guard"; else bad "(C) guard PASSED without SCIM source ownership (false-negative!)"; fi
if printf '%s' "$out" | grep -q '^  REGRESSION: C6b '; then ok "(C) names C6b specifically"; else bad "(C) did not name C6b in the failure output"; fi
write_all_fixed

# (D) delete a whole file (simulating a rename/move that drops the fix along
# with it) → guard fails, names the missing-file case.
rm "$WORK/mailserver/internal/imap/imap.go"
rc=0
out="$(AUDIT_ROOT="$WORK" bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(D) a wholesale-missing file fails the guard"; else bad "(D) guard PASSED with imap.go missing entirely (false-negative!)"; fi
if printf '%s' "$out" | grep -q 'file missing entirely'; then ok "(D) names the missing-file case"; else bad "(D) did not report the missing-file case distinctly"; fi

# (E) the REAL tree (no AUDIT_ROOT override) is currently green.
rc=0
out_real="$(bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(E) the real tree currently passes the guard"; else bad "(E) the REAL tree fails the guard right now:"$'\n'"$out_real"; fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-audit74-criticals selftest FAILED ($fail/$((pass + fail)) checks failed)."
  exit 1
fi
echo "check-audit74-criticals selftest: all $pass checks passed (guard fires + is precise)."
