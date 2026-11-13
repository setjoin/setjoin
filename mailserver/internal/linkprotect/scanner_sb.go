package linkprotect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SafeBrowsingScanner checks URLs against the Google Safe Browsing API v5
// (threatMatches:find). Requires an API key.
type SafeBrowsingScanner struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewSafeBrowsingScanner creates a Safe Browsing scanner with the given API key.
func NewSafeBrowsingScanner(apiKey string) *SafeBrowsingScanner {
	return &SafeBrowsingScanner{
		apiKey:   apiKey,
		endpoint: "https://safebrowsing.googleapis.com",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the scanner identifier.
func (s *SafeBrowsingScanner) Name() string {
	return "safebrowsing"
}

type sbRequest struct {
	Client     sbClient     `json:"client"`
	ThreatInfo sbThreatInfo `json:"threatInfo"`
}

type sbClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type sbThreatInfo struct {
	ThreatTypes      []string  `json:"threatTypes"`
	PlatformTypes    []string  `json:"platformTypes"`
	ThreatEntryTypes []string  `json:"threatEntryTypes"`
	ThreatEntries    []sbEntry `json:"threatEntries"`
}

type sbEntry struct {
	URL string `json:"url"`
}

type sbResponse struct {
	Matches []sbMatch `json:"matches"`
}

type sbMatch struct {
	ThreatType      string  `json:"threatType"`
	PlatformType    string  `json:"platformType"`
	ThreatEntryType string  `json:"threatEntryType"`
	Threat          sbEntry `json:"threat"`
}

// Check queries the Safe Browsing API for the given URL.
func (s *SafeBrowsingScanner) Check(ctx context.Context, url string) (Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	reqBody := sbRequest{
		Client: sbClient{
			ClientID:      "mailserver",
			ClientVersion: "1.0.0",
		},
		ThreatInfo: sbThreatInfo{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries: []sbEntry{
				{URL: url},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return VerdictUnknown, fmt.Errorf("safebrowsing: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, //nolint:gosec // G704: destination is the fixed Google Safe Browsing endpoint (s.endpoint, set in constructor); the scanned URL is request-body data, not the request host
		http.MethodPost,
		s.endpoint+"/v5/threatMatches:find?key="+s.apiKey,
		bytes.NewReader(body),
	)
	if err != nil {
		return VerdictUnknown, fmt.Errorf("safebrowsing: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req) //nolint:gosec // G704: destination is the fixed Google Safe Browsing endpoint; the scanned URL is request-body data, not the request host
	if err != nil {
		return VerdictUnknown, fmt.Errorf("safebrowsing: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return VerdictUnknown, fmt.Errorf("safebrowsing: HTTP %d", resp.StatusCode)
	}

	var sbResp sbResponse
	if err := json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return VerdictUnknown, fmt.Errorf("safebrowsing: decode response: %w", err)
	}

	if len(sbResp.Matches) > 0 {
		return VerdictMalicious, nil
	}

	return VerdictSafe, nil
}
