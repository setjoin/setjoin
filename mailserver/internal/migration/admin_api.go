package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// AdminAPI serves the admin migration console's two action endpoints
// (POST /admin/migration/test-connection + POST /admin/migration/start).
// It lives in-package so it can reuse the connector constructors, the
// factory config machinery, and the orchestrator's derived encryption keys
// without exporting them. Job listing/control stays on user.MigrationHandler.
type AdminAPI struct {
	orch            *Orchestrator
	imapDialContext func(context.Context, string, string) (net.Conn, error) // test seam; nil in production
}

// NewAdminAPI creates the admin migration action handler.
func NewAdminAPI(orch *Orchestrator) *AdminAPI { return &AdminAPI{orch: orch} }

// testConnTimeout bounds a connection test — the server dials an
// admin-supplied host, so a black-holed address must not hang the request.
const testConnTimeout = 10 * time.Second

// TestConnection validates admin-supplied source-server details by dialing
// the source and returning the connector's error verbatim on failure.
//
// SSRF posture: migration sources are ADMIN-TRUSTED, internal-allowed hosts
// (on-prem Exchange/IMAP typically sit on private IPs behind the firewall) —
// the same deliberate divergence from the ssrf dialer guard documented on
// NewEWSConnector/validateEWSServerURL. The EWS URL gets the scheme-only
// check; the route is write-gated (mail.pipeline) in main.go.
func (a *AdminAPI) TestConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceType string `json:"source_type"`
		// imap
		Host string `json:"host"`
		Port int    `json:"port"`
		SSL  *bool  `json:"ssl"`
		// ews (username/password also honored for imap when provided)
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), testConnTimeout)
	defer cancel()

	var check func(context.Context) error
	switch req.SourceType {
	case "imap":
		if req.Host == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "host is required")
			return
		}
		conn := NewIMAPConnector(IMAPConfig{
			Host:    req.Host,
			Port:    defaultPort(req.Port),
			TLSMode: tlsModeFromSSL(req.SSL),
			Credentials: IMAPCredentials{
				Username: req.Username,
				Password: req.Password,
			},
		})
		conn.dialContext = a.imapDialContext
		if req.Username == "" {
			// The admin console sends no IMAP credentials (per-user creds
			// ride on each migration target) — reachability + TLS check only.
			check = func(ctx context.Context) error {
				cl, err := conn.dial(ctx)
				if err != nil {
					return err
				}
				_ = cl.Logout()
				return nil
			}
		} else {
			check = conn.TestConnection
		}
	case "ews":
		if req.URL == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "url is required")
			return
		}
		if err := validateEWSServerURL(req.URL, nil); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
			return
		}
		conn := NewEWSConnector(EWSConfig{ServerURL: req.URL, Username: req.Username, Password: req.Password})
		check = conn.TestConnection
	case "m365":
		// Test uses the stored global app credentials (the console has no
		// per-request M365 fields) — reuse the factory's global-config read.
		cfgAny, err := (m365Factory{a.orch}).merge(&MigrationJobConfig{})
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "M365 config not found — save client ID and secret first")
			return
		}
		conn, err := NewM365Connector(ctx, *cfgAny.(*MigrationM365Config))
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadGateway, fmt.Sprintf("connection failed: %v", err))
			return
		}
		check = conn.TestConnection
	default:
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "source_type must be one of imap, ews, m365")
		return
	}

	// ponytail: goroutine+select bounds every connector uniformly — the IMAP
	// dial takes no context; a stuck dial goroutine ends at the OS timeout.
	errCh := make(chan error, 1)
	go func() { errCh <- check(ctx) }()
	select {
	case err := <-errCh:
		if err != nil {
			a.orch.logger.Warn("admin migration test connection failed",
				"sourceType", req.SourceType, "error", err)
			httputil.WriteProblemStatus(w, http.StatusBadGateway, fmt.Sprintf("connection failed: %v", err))
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
	case <-ctx.Done():
		httputil.WriteProblemStatus(w, http.StatusGatewayTimeout, fmt.Sprintf("connection test timed out after %s", testConnTimeout))
	}
}

// Start creates one migration job per target (the admin console's bulk
// start) and starts each — the same INSERT + Orchestrator.StartJob seam as
// the self-service path in user.MigrationHandler.StartMigration.
func (a *AdminAPI) Start(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		SourceType string `json:"source_type"`
		AuthMode   string `json:"auth_mode"` // "impersonation" | "per_user"
		Targets    []struct {
			SourceEmail string `json:"source_email"`
			TargetEmail string `json:"target_email"`
			Password    string `json:"password"`
		} `json:"targets"`
		// imap
		IMAPHost string `json:"imap_host"`
		IMAPPort int    `json:"imap_port"`
		IMAPSSL  *bool  `json:"imap_ssl"`
		// ews
		EWSURL      string `json:"ews_url"`
		EWSUsername string `json:"ews_username"`
		EWSPassword string `json:"ews_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch req.SourceType {
	case "imap":
		if req.IMAPHost == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "imap_host is required")
			return
		}
	case "ews":
		if req.EWSURL == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "ews_url is required")
			return
		}
		if err := validateEWSServerURL(req.EWSURL, nil); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
			return
		}
	case "m365":
	default:
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "source_type must be one of imap, ews, m365")
		return
	}
	if len(req.Targets) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "targets[] is required (at least one source/target pair)")
		return
	}
	for _, tgt := range req.Targets {
		if tgt.SourceEmail == "" || tgt.TargetEmail == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "every target needs source_email and target_email")
			return
		}
	}

	ctx := r.Context()
	useGlobal := a.hasGlobalSourceConfig(ctx, req.SourceType)
	if req.SourceType == "m365" && !useGlobal {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "M365 global config not found — admin must configure it first")
		return
	}

	var jobIDs []int64
	var firstErr string
	for _, tgt := range req.Targets {
		// Explicit trusted-admin provenance: AdminAPI.Start is the only route
		// allowed to store SelfService=false, so its jobs inherit the shared
		// service-account credentials on resume. Post-marker jobs must never
		// carry a nil marker — that fails closed at the ewsFactory merge.
		jobCfg := MigrationJobConfig{SourceType: req.SourceType, UseGlobalAuth: useGlobal, SelfService: CredentialProvenance(false)}
		switch req.SourceType {
		case "imap":
			jobCfg.IMAP = &IMAPConfig{
				Host:    req.IMAPHost,
				Port:    defaultPort(req.IMAPPort),
				TLSMode: tlsModeFromSSL(req.IMAPSSL),
				Credentials: IMAPCredentials{
					Username: tgt.SourceEmail,
					Password: tgt.Password,
				},
			}
		case "ews":
			ews := MigrationEWSConfig{ServerURL: req.EWSURL, Username: req.EWSUsername, Password: req.EWSPassword}
			if req.AuthMode == "per_user" && tgt.Password != "" {
				// per-user auth: log in as the source user directly.
				ews.Username = tgt.SourceEmail
				ews.Password = tgt.Password
			} else {
				// impersonation: the service account acts as the source mailbox.
				ews.ImpersonateAs = tgt.SourceEmail
			}
			jobCfg.EWS = &ews
		case "m365":
			jobCfg.UseGlobalAuth = true
			jobCfg.M365 = &MigrationM365Config{SourceEmail: tgt.SourceEmail}
		}

		sourceConfigEnc, err := EncryptConfigAny(jobCfg, a.orch.encryptionKey)
		if err != nil {
			a.orch.logger.Error("encrypt migration config", "error", err)
			continue
		}

		var mailboxID int64
		err = a.orch.pool.QueryRow(ctx,
			`SELECT m.id FROM mailboxes m
			 JOIN users u ON m.user_id = u.id
			 WHERE u.email = $1 LIMIT 1`, tgt.TargetEmail).Scan(&mailboxID)
		if err != nil {
			a.orch.logger.Warn("admin migration: no mailbox for target email", "email", tgt.TargetEmail)
			if firstErr == "" {
				firstErr = "no mailbox found for " + tgt.TargetEmail
			}
			continue
		}

		var jobID int64
		err = a.orch.pool.QueryRow(ctx, `
			INSERT INTO migration_jobs (user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status)
			VALUES ($1, $2, $3, $4, 'skip', 'pending')
			RETURNING id`,
			claims.UserID, req.SourceType, sourceConfigEnc, mailboxID,
		).Scan(&jobID)
		if err != nil {
			a.orch.logger.Error("insert migration job", "error", err)
			if firstErr == "" {
				firstErr = "failed to create job for " + tgt.TargetEmail
			}
			continue
		}
		jobIDs = append(jobIDs, jobID)
	}

	if len(jobIDs) == 0 {
		msg := "failed to create any migration jobs"
		if firstErr != "" {
			msg += ": " + firstErr
		}
		httputil.WriteProblemStatus(w, http.StatusBadRequest, msg)
		return
	}

	for _, jobID := range jobIDs {
		if err := a.orch.StartJob(ctx, jobID); err != nil {
			a.orch.logger.Error("start migration job", "job_id", jobID, "error", err)
		}
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"ids":    jobIDs,
		"status": "pending",
	})
}

// hasGlobalSourceConfig mirrors user.MigrationHandler.hasGlobalSourceConfig:
// true if a global source config row exists for the given source type.
func (a *AdminAPI) hasGlobalSourceConfig(ctx context.Context, sourceType string) bool {
	keyMap := map[string]string{
		"imap": "imap.defaults",
		"ews":  "ews.global",
		"m365": "m365.app",
	}
	configKey, ok := keyMap[sourceType]
	if !ok {
		return false
	}
	var exists bool
	_ = a.orch.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM system_config WHERE key = $1)`, configKey,
	).Scan(&exists)
	return exists
}

func defaultPort(p int) int {
	if p == 0 {
		return 993
	}
	return p
}

// tlsModeFromSSL maps the console's ssl checkbox to the connector TLS mode
// (nil = unset = the secure default).
func tlsModeFromSSL(ssl *bool) string {
	if ssl != nil && !*ssl {
		return "none"
	}
	return "tls"
}
