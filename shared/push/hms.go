package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HMSDispatcher sends push notifications via Huawei Mobile Services Push Kit v3.
type HMSDispatcher struct {
	appID      string
	appSecret  string
	httpClient *http.Client
}

// NewHMSDispatcher creates an HMS dispatcher.
func NewHMSDispatcher(appID, appSecret string) *HMSDispatcher {
	return &HMSDispatcher{
		appID:      appID,
		appSecret:  appSecret,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *HMSDispatcher) getAccessToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", d.appID)
	form.Set("client_secret", d.appSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth-login.cloud.huawei.com/oauth2/v3/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		// Fail closed at construction (mirrors fcm.go): discarding this error
		// would turn a malformed request into a deferred nil dereference.
		return "", fmt.Errorf("hms oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hms oauth: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("hms oauth decode: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("hms oauth: empty access_token (bad app id/secret)")
	}
	return result.AccessToken, nil
}

// OAuth proves the app id/secret can obtain an access token — used by the doctor.
func (d *HMSDispatcher) OAuth(ctx context.Context) error {
	_, err := d.getAccessToken(ctx)
	return err
}

// Send delivers a payload to an HMS device token.
func (d *HMSDispatcher) Send(ctx context.Context, hmsToken string, payload []byte) error {
	token, err := d.getAccessToken(ctx)
	if err != nil {
		return redactProviderError(err)
	}
	body := map[string]interface{}{
		"message": map[string]interface{}{
			"token": []string{hmsToken},
			// decided 2026-07-07: rich payload on all providers.
			"data": fmt.Sprintf("%x", payload),
			"android": map[string]interface{}{
				"urgency": "HIGH",
			},
		},
	}
	b, _ := json.Marshal(body)
	url := fmt.Sprintf("https://push-api.cloud.huawei.com/v3/%s/messages:send", d.appID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		// Mirror fcm.go:84-87: a construction failure (e.g. a malformed
		// HMS_APP_ID interpolated into the URL) must surface here as an
		// error, not as a deferred nil-pointer panic on req below.
		return fmt.Errorf("hms send request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		// Redact at the seam: *url.Error embeds the full request URL, whose
		// path carries the app id.
		return redactProviderError(fmt.Errorf("hms send: %w", err))
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hms: HTTP %d: %s", resp.StatusCode, rb)
	}
	// HMS returns 200 with a body code; 80300007/80100000 == invalid/expired token.
	// ponytail: only the two documented dead-token codes prune; other non-zero
	// codes retry. Add codes here if HMS surfaces more permanent-failure cases.
	var res struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rb, &res)
	if res.Code == "80300007" || res.Code == "80100000" {
		return fmt.Errorf("hms rejected %s: %w", res.Code, ErrUnregistered)
	}
	if res.Code != "" && res.Code != "80000000" {
		return fmt.Errorf("hms rejected: %s", res.Code)
	}
	return nil
}
