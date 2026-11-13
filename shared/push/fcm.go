package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// fcmScope is the OAuth2 scope required to send via the FCM HTTP v1 API.
const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// FCMDispatcher sends push notifications via Firebase Cloud Messaging v1 API.
// It mints and refreshes its own OAuth2 access token from the service-account
// JSON (the token source caches + auto-refreshes), so no external refresh loop
// is required — the previous "caller must refresh accessToken" design was never
// wired to a refresher.
type FCMDispatcher struct {
	projectID   string
	tokenSource oauth2.TokenSource
	httpClient  *http.Client
}

// NewFCMDispatcher creates an FCM dispatcher from a service-account JSON blob.
// It validates the SA and derives the project id from it when projectID is empty.
func NewFCMDispatcher(saJSON []byte) (*FCMDispatcher, error) {
	cfg, err := google.JWTConfigFromJSON(saJSON, fcmScope)
	if err != nil {
		return nil, fmt.Errorf("fcm service account: %w", err)
	}
	// project_id lives in the SA JSON; JWTConfig doesn't expose it, so read it.
	var sa struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("fcm service account json: %w", err)
	}
	if sa.ProjectID == "" {
		return nil, fmt.Errorf("fcm service account: missing project_id")
	}
	return &FCMDispatcher{
		projectID:   sa.ProjectID,
		tokenSource: cfg.TokenSource(context.Background()),
		httpClient:  &http.Client{},
	}, nil
}

// ProjectID reports the GCP project id derived from the service account (used by
// the doctor to display which project the SA targets).
func (d *FCMDispatcher) ProjectID() string { return d.projectID }

// OAuth mints (or returns a cached) access token — used by the doctor to prove the
// SA can actually authenticate, not merely parse.
func (d *FCMDispatcher) OAuth(ctx context.Context) error {
	_, err := d.tokenSource.Token()
	return err
}

// Send delivers a payload to an FCM device token.
func (d *FCMDispatcher) Send(ctx context.Context, fcmToken string, payload []byte) error {
	tok, err := d.tokenSource.Token()
	if err != nil {
		// Redact at the seam: token-source errors can carry request URLs.
		return redactProviderError(fmt.Errorf("fcm token: %w", err))
	}
	body := map[string]interface{}{
		"message": map[string]interface{}{
			"token": fcmToken,
			// decided 2026-07-07: rich payload on all providers — the client renders
			// sender/subject/actions from this data key.
			"data": map[string]string{
				"data": fmt.Sprintf("%x", payload),
			},
			"android": map[string]interface{}{
				"priority": "high",
			},
		},
	}
	b, _ := json.Marshal(body)
	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", d.projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Redact at the seam: *url.Error embeds the full request URL (project
		// id in the path; token stays in the body, never re-rendered here).
		return redactProviderError(fmt.Errorf("fcm send: %w", err))
	}
	defer resp.Body.Close()
	// FCM v1 returns 404 (NOT_FOUND) or 400 UNREGISTERED for a dead token: prune it.
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("fcm: HTTP %d: %w", resp.StatusCode, ErrUnregistered)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fcm: HTTP %d", resp.StatusCode)
	}
	return nil
}
