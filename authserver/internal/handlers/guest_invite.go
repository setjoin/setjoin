package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pwhash"
)

const (
	guestDisclosureVersion = "v1"
	guestInviteBodyLimit   = 1 << 20
	guestInviteError       = "invite link is invalid or has expired"
)

func guestDisclosureLanguage(header string) string {
	primary := strings.TrimSpace(header)
	if i := strings.IndexAny(primary, ",;"); i >= 0 {
		primary = strings.TrimSpace(primary[:i])
	}
	primary = strings.ToLower(primary)
	switch {
	case strings.HasPrefix(primary, "zh"):
		return "zh"
	case strings.HasPrefix(primary, "de"):
		return "de"
	default:
		return "en"
	}
}

func guestDisclosureCopy(lang, orgName string, channels []string, locality, addendum string) string {
	if locality == "" {
		switch lang {
		case "zh":
			locality = "在你所在组织的本地环境中"
		case "de":
			locality = "lokal am Standort Ihrer Organisation"
		default:
			locality = "on-premise at your organization's location"
		}
	}

	var disclosure string
	switch lang {
	case "zh":
		access := orgName + " 中的聊天频道"
		if len(channels) > 0 {
			access = orgName + " 中的以下聊天频道：" + strings.Join(channels, "、")
		}
		disclosure = fmt.Sprintf(
			"你将以外部来宾身份加入 %s，并可访问%s。你的消息、文件和活动将依照组织的数据保留政策保存。"+
				"授权管理员可以使用组织的合规工具访问、导出和审查你的内容。你的内容将%s归档。继续即表示你同意此归档和监控。",
			orgName, access, locality)
	case "de":
		access := "Chat-Kanäle in " + orgName
		if len(channels) > 0 {
			access = "die folgenden Chat-Kanäle in " + orgName + ": " + strings.Join(channels, ", ")
		}
		disclosure = fmt.Sprintf(
			"Sie werden als externer Gast in %s aufgenommen und erhalten Zugriff auf %s. "+
				"Ihre Nachrichten, Dateien und Aktivitäten werden gemäß den Aufbewahrungsrichtlinien der Organisation gespeichert. "+
				"Autorisierte Administratoren können Ihre Inhalte mit den Compliance-Werkzeugen der Organisation aufrufen, exportieren und prüfen. "+
				"Ihre Inhalte werden %s archiviert. Wenn Sie fortfahren, stimmen Sie dieser Archivierung und Überwachung zu.",
			orgName, access, locality)
	default:
		access := "chat channels in " + orgName
		if len(channels) > 0 {
			access = "the following chat channels in " + orgName + ": " + strings.Join(channels, ", ")
		}
		disclosure = fmt.Sprintf(
			"You are being onboarded as an external guest user in %s and will be able to access %s. "+
				"Your messages, files, and activity will be retained under the organization's data retention policies. "+
				"Authorized administrators may access, export, and review your content using the organization's compliance tooling. "+
				"Your content is archived %s. By proceeding you consent to this archival and monitoring.",
			orgName, access, locality)
	}
	if addendum != "" {
		disclosure += " " + addendum
	}
	return disclosure
}

func guestInviteTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func guestInviteTerminalReject(w http.ResponseWriter) {
	time.Sleep(enumConstantDelay)
	httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": guestInviteError})
}

type guestInviteRollbacker interface {
	Rollback(context.Context) error
}

func guestInviteRollbackAndReject(ctx context.Context, tx guestInviteRollbacker, w http.ResponseWriter) {
	_ = tx.Rollback(ctx)
	guestInviteTerminalReject(w)
}

// guestInviteBeforeDisclosureStampKey is a package-private deterministic
// concurrency-test seam. Production requests never carry this context value.
type guestInviteBeforeDisclosureStampKey struct{}

func guestInviteWriteOK(tag pgconn.CommandTag) bool { return tag.RowsAffected() == 1 }

// GuestInviteAcceptGet validates a single-use invite and records the disclosure
// version shown without consuming the token.
func (h *accountRecoveryHandler) GuestInviteAcceptGet(w http.ResponseWriter, r *http.Request) {
	if enumRateLimited(w, r) {
		return
	}
	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		guestInviteTerminalReject(w)
		return
	}

	tx, err := h.workerPool.Begin(r.Context())
	if err != nil {
		h.guestInviteInternalError(w, "begin GET transaction", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	var (
		inviteID          int64
		guestUserID       int64
		hostDomainID      int64
		invitedEmail      string
		status            string
		inviteExpiresAt   time.Time
		guestExpiresAt    *time.Time
		usedAt            *time.Time
		stampedVersion    *string
		federatedIdentity bool
	)
	err = tx.QueryRow(r.Context(),
		`SELECT gi.id, gi.guest_user_id, gi.host_domain_id, u.email,
		        ga.status, gi.expires_at, ga.expires_at, gi.used_at,
		        gi.disclosure_version,
		        (u.sync_source = 'sso'
		         OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
		         OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
		   FROM guest_invites gi
		   JOIN guest_accounts ga ON ga.user_id = gi.guest_user_id
		   JOIN users u ON u.id = gi.guest_user_id
		  WHERE gi.token_hash = $1`, guestInviteTokenHash(rawToken),
	).Scan(&inviteID, &guestUserID, &hostDomainID, &invitedEmail,
		&status, &inviteExpiresAt, &guestExpiresAt, &usedAt, &stampedVersion, &federatedIdentity)
	now := time.Now()
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (usedAt != nil ||
		!inviteExpiresAt.After(now) || (guestExpiresAt != nil && !guestExpiresAt.After(now)) ||
		status != "invited" || federatedIdentity)) {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}
	if err != nil {
		h.guestInviteInternalError(w, "read invite disclosure", err)
		return
	}
	version := guestDisclosureVersion
	if stampedVersion != nil {
		version = *stampedVersion
	}
	if hook, ok := r.Context().Value(guestInviteBeforeDisclosureStampKey{}).(func()); ok {
		hook()
	}
	tag, err := tx.Exec(r.Context(),
		`UPDATE guest_invites gi
		    SET disclosure_version = COALESCE(gi.disclosure_version, $1)
		   FROM guest_accounts ga
		  WHERE gi.id = $2
		    AND ga.user_id = gi.guest_user_id
		    AND gi.used_at IS NULL
		    AND gi.expires_at > now()
		    AND (ga.expires_at IS NULL OR ga.expires_at > now())
		    AND ga.status = 'invited'`, guestDisclosureVersion, inviteID)
	if err != nil {
		h.guestInviteInternalError(w, "stamp invite disclosure", err)
		return
	}
	if !guestInviteWriteOK(tag) {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}

	var orgName string
	if err := tx.QueryRow(r.Context(), `SELECT name FROM domains WHERE id = $1`, hostDomainID).Scan(&orgName); err != nil {
		h.guestInviteInternalError(w, "read invite organization", err)
		return
	}
	var locality string
	if err := tx.QueryRow(r.Context(),
		`SELECT COALESCE(
		   (SELECT NULLIF(value #>> '{}', '') FROM system_config WHERE key='installation.locality'), '')`,
	).Scan(&locality); err != nil {
		h.guestInviteInternalError(w, "read invite locality", err)
		return
	}
	var addendum string
	if err := tx.QueryRow(r.Context(),
		`SELECT COALESCE(
		   (SELECT NULLIF(value #>> '{}', '') FROM system_config WHERE key='guest.disclosure_addendum'), '')`,
	).Scan(&addendum); err != nil {
		h.guestInviteInternalError(w, "read invite disclosure addendum", err)
		return
	}
	rows, err := tx.Query(r.Context(),
		`SELECT c.name
		   FROM chat_channels c
		   JOIN chat_channel_members m ON m.channel_id = c.id
		  WHERE m.user_id = $1 AND c.name IS NOT NULL
		  ORDER BY c.name`, guestUserID)
	if err != nil {
		h.guestInviteInternalError(w, "read invite channels", err)
		return
	}
	channels := make([]string, 0)
	for rows.Next() {
		var channel string
		if err := rows.Scan(&channel); err != nil {
			rows.Close()
			h.guestInviteInternalError(w, "scan invite channel", err)
			return
		}
		channels = append(channels, channel)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		h.guestInviteInternalError(w, "iterate invite channels", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.guestInviteInternalError(w, "commit invite disclosure", err)
		return
	}

	language := guestDisclosureLanguage(r.Header.Get("Accept-Language"))
	disclosure := guestDisclosureCopy(language, orgName, channels, locality, addendum)
	w.Header().Set("Content-Language", language)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"org_name": orgName, "invited_email": invitedEmail, "channels": channels,
		"disclosure_text": disclosure, "disclosure_version": version,
		"expires_at": inviteExpiresAt.UTC().Format(time.RFC3339),
	})
}

// GuestInviteAcceptPost consumes an invite and activates the guest in one
// worker transaction. No successful write is observable without all siblings.
func (h *accountRecoveryHandler) GuestInviteAcceptPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, guestInviteBodyLimit)
	if enumRateLimited(w, r) {
		return
	}
	var req struct {
		Token              string `json:"token"`
		DisclosureAccepted bool   `json:"disclosure_accepted"`
		NewPassword        string `json:"new_password"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Token == "" {
		guestInviteTerminalReject(w)
		return
	}
	if !req.DisclosureAccepted {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "disclosure acceptance is required"})
		return
	}
	if req.NewPassword == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "new password is required"})
		return
	}

	tx, err := h.workerPool.Begin(r.Context())
	if err != nil {
		h.guestInviteInternalError(w, "begin invite acceptance", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	var (
		inviteID          int64
		guestUserID       int64
		invitedEmail      string
		status            string
		inviteExpiresAt   time.Time
		guestExpiresAt    *time.Time
		usedAt            *time.Time
		federatedIdentity bool
	)
	tokenHash := guestInviteTokenHash(req.Token)
	// Discover the stable ids without a lock, then take every writer's
	// canonical guest -> user -> invite lock order. The invite is re-read and
	// fully revalidated after all locks are held.
	err = tx.QueryRow(r.Context(),
		`SELECT gi.id, gi.guest_user_id
		   FROM guest_invites gi
		  WHERE gi.token_hash = $1`, tokenHash,
	).Scan(&inviteID, &guestUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}
	if err != nil {
		h.guestInviteInternalError(w, "discover invite", err)
		return
	}

	err = tx.QueryRow(r.Context(),
		`SELECT u.email, ga.status, ga.expires_at,
		        (u.sync_source = 'sso'
		         OR u.oidc_subject IS NOT NULL OR u.oidc_issuer IS NOT NULL
		         OR u.saml_name_id IS NOT NULL OR u.saml_idp_entity_id IS NOT NULL)
		   FROM guest_accounts ga
		   JOIN users u ON u.id = ga.user_id
		  WHERE ga.user_id = $1
		  FOR UPDATE OF ga, u`, guestUserID,
	).Scan(&invitedEmail, &status, &guestExpiresAt, &federatedIdentity)
	if errors.Is(err, pgx.ErrNoRows) {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}
	if err != nil {
		h.guestInviteInternalError(w, "lock guest invite identity", err)
		return
	}

	err = tx.QueryRow(r.Context(),
		`SELECT expires_at, used_at
		   FROM guest_invites
		  WHERE id = $1 AND token_hash = $2
		  FOR UPDATE`, inviteID, tokenHash,
	).Scan(&inviteExpiresAt, &usedAt)
	now := time.Now()
	if errors.Is(err, pgx.ErrNoRows) {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}
	if err != nil {
		h.guestInviteInternalError(w, "lock guest invite", err)
		return
	}
	if usedAt == nil && (!inviteExpiresAt.After(now) || (guestExpiresAt != nil && !guestExpiresAt.After(now))) {
		if _, err := tx.Exec(r.Context(),
			`UPDATE guest_invites
			    SET used_at=expires_at, terminal_reason='expired'
			  WHERE id=$1 AND used_at IS NULL`, inviteID); err != nil {
			h.guestInviteInternalError(w, "stamp expired guest invite", err)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.guestInviteInternalError(w, "commit expired guest invite", err)
			return
		}
		guestInviteTerminalReject(w)
		return
	}
	if usedAt != nil || status != "invited" || federatedIdentity {
		guestInviteRollbackAndReject(r.Context(), tx, w)
		return
	}
	if len([]byte(req.NewPassword)) > pwhash.PasswordMaxBytes {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password exceeds the %d-byte limit", pwhash.PasswordMaxBytes),
		})
		return
	}

	var passwordResult json.RawMessage
	if err := tx.QueryRow(r.Context(), `SELECT validate_password($1, false)`, req.NewPassword).Scan(&passwordResult); err != nil {
		h.guestInviteInternalError(w, "validate guest password", err)
		return
	}
	var validation struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(passwordResult, &validation); err != nil {
		h.guestInviteInternalError(w, "decode password validation", err)
		return
	}
	if !validation.Valid {
		message := validation.Error
		if message == "" {
			message = "password does not meet policy requirements"
		}
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": message})
		return
	}
	passwordHash, err := pwhash.HashPasswordWithProfile(req.NewPassword)
	if err != nil {
		h.guestInviteInternalError(w, "hash guest password", err)
		return
	}

	if tag, err := tx.Exec(r.Context(),
		`UPDATE guest_invites
		    SET used_at=now(), disclosure_accepted_at=now(),
		        disclosure_version=COALESCE(disclosure_version, $1),
		        terminal_reason='accepted'
		  WHERE id=$2 AND used_at IS NULL`, guestDisclosureVersion, inviteID); err != nil || !guestInviteWriteOK(tag) {
		h.guestInviteInternalError(w, "consume guest invite", err)
		return
	}
	if tag, err := tx.Exec(r.Context(),
		`UPDATE guest_accounts SET status='active', updated_at=now()
		  WHERE user_id=$1 AND status='invited'`, guestUserID); err != nil || !guestInviteWriteOK(tag) {
		h.guestInviteInternalError(w, "activate guest satellite", err)
		return
	}
	if tag, err := tx.Exec(r.Context(),
		`UPDATE users SET enabled=TRUE, password_hash=$2, must_change_password=FALSE, updated_at=now()
		  WHERE id=$1`, guestUserID, string(passwordHash)); err != nil || !guestInviteWriteOK(tag) {
		h.guestInviteInternalError(w, "activate guest identity", err)
		return
	}
	var ip any
	if clientIP := httputil.ClientIP(r); clientIP != "" {
		ip = clientIP
	}
	if _, err := tx.Exec(r.Context(),
		`SELECT audit_write($1::bigint, 'guest.invite_accept', 'guest_invite', $2::bigint, NULL,
		        jsonb_build_object('status','active','guestUserId',$1::bigint::text), $3::inet,
		        'guest invite accepted', 'core')`, guestUserID, inviteID, ip); err != nil {
		h.guestInviteInternalError(w, "audit guest invite acceptance", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.guestInviteInternalError(w, "commit guest invite acceptance", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Account activated. You may now sign in.", "invited_email": invitedEmail,
	})
}

func (h *accountRecoveryHandler) guestInviteInternalError(w http.ResponseWriter, operation string, err error) {
	if h.logger != nil {
		h.logger.Error("guest invite acceptance failed", "operation", operation, "error", err)
	}
	httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}
