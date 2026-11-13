package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
)

// basicAuthMethod implements HTTP Basic Authentication for DAV clients.
type basicAuthMethod struct {
	pool              *pgxpool.Pool
	threatInterceptor *threat.ThreatInterceptor
}

func (m *basicAuthMethod) Slug() string  { return "basic_auth" }
func (m *basicAuthMethod) Priority() int { return 30 }

func (m *basicAuthMethod) Authenticate(r *http.Request) (*Claims, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		return nil, errors.New("no basic auth")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return nil, errors.New("invalid basic auth encoding")
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid basic auth format")
	}
	email, password := parts[0], parts[1]

	var meta threat.ConnectionMeta
	if m.threatInterceptor != nil {
		meta = threat.ConnectionMeta{
			SourceIP:  httputil.ClientIP(r),
			Username:  email,
			Protocol:  threat.ProtocolHTTP,
			UserAgent: r.UserAgent(),
		}
		result, _, delay := m.threatInterceptor.Intercept(r.Context(), &meta)
		switch result {
		case threat.ActionReject, threat.ActionTarpitted:
			if delay > 0 {
				time.Sleep(delay)
			}
			return nil, ErrInvalidCredentials
		case threat.ActionRateLimited:
			return nil, ErrInvalidCredentials
		}
	}

	user, err := CheckPassword(r.Context(), m.pool, email, password)
	if err != nil {
		if m.threatInterceptor != nil {
			m.threatInterceptor.RecordResult(r.Context(), &meta, false, 0)
		}
		pwhash.LogAuthEvent(r.Context(), m.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "basic", Email: email,
			IPAddress: httputil.ClientIP(r),
		}, nil)
		return nil, err
	}
	if m.threatInterceptor != nil {
		m.threatInterceptor.RecordResult(r.Context(), &meta, true, user.ID)
	}
	pwhash.LogAuthEvent(r.Context(), m.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "basic", Email: email,
		IPAddress: httputil.ClientIP(r),
	}, nil)
	return &Claims{
		UserID:     user.ID,
		Email:      user.Email,
		IsAdmin:    user.IsAdmin,
		Type:       TypeAccess,
		AuthMethod: m.Slug(), // CA eval keys on this; empty would misclassify as jwt_bearer
	}, nil
}
