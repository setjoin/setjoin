package office

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"setjoin.com/shared/ssrf"
)

const qualificationResponseLimit = 2 << 20

type QualificationTarget struct {
	ProviderID        string   `json:"providerId"`
	Generation        int64    `json:"generation"`
	ConfigSHA256      string   `json:"configSha256"`
	Profile           string   `json:"profile"`
	ProofDiscoveryURL string   `json:"proofDiscoveryUrl"`
	WOPIPublicBaseURL string   `json:"wopiPublicBaseUrl"`
	EditorURL         string   `json:"editorUrl"`
	PrivateAllowHosts []string `json:"privateAllowHosts"`
	PrivateAllowCIDRs []string `json:"privateAllowCidrs"`
	BuildID           *string  `json:"buildId"`
}

type QualificationResult struct {
	Checks               map[string]any `json:"checks"`
	DiscoveryFingerprint string         `json:"discoveryFingerprint"`
	Duration             time.Duration  `json:"-"`
}

type ProviderProber interface {
	Probe(context.Context, QualificationTarget) (QualificationResult, error)
}

type LiveProviderProber struct{}

func (LiveProviderProber) Probe(ctx context.Context, target QualificationTarget) (QualificationResult, error) {
	started := time.Now()
	policy, err := ssrf.CompilePrivatePolicy(target.PrivateAllowHosts, target.PrivateAllowCIDRs)
	if err != nil {
		return QualificationResult{}, fmt.Errorf("compile private target policy: %w", err)
	}
	for name, raw := range map[string]string{
		"proof discovery":  target.ProofDiscoveryURL,
		"editor":           target.EditorURL,
		"WOPI public base": target.WOPIPublicBaseURL,
	} {
		if err := ssrf.ValidateURLWithPrivatePolicy(raw, policy); err != nil {
			return QualificationResult{}, fmt.Errorf("%s URL: %w", name, err)
		}
	}
	discoveryOrigin, err := url.Parse(target.ProofDiscoveryURL)
	if err != nil {
		return QualificationResult{}, err
	}
	editorOrigin, err := url.Parse(target.EditorURL)
	if err != nil || !strings.EqualFold(discoveryOrigin.Host, editorOrigin.Host) {
		return QualificationResult{}, errors.New("editor and WOPI discovery must use the same HTTPS origin")
	}
	client := ssrf.SafeHTTPClientWithPrivatePolicy(12*time.Second, policy)
	return probeProvider(ctx, target, client, started)
}

func probeProvider(ctx context.Context, target QualificationTarget, client *http.Client, started time.Time) (QualificationResult, error) {
	body, err := fetchQualificationURL(ctx, client, http.MethodGet, target.ProofDiscoveryURL, http.StatusOK)
	if err != nil {
		return QualificationResult{}, fmt.Errorf("discovery: %w", err)
	}
	var doc discovery
	if err := xml.Unmarshal(body, &doc); err != nil {
		return QualificationResult{}, fmt.Errorf("discovery XML: %w", err)
	}
	if _, err := parsePublicKey(doc.ProofKey.Modulus, doc.ProofKey.Exponent); err != nil {
		return QualificationResult{}, fmt.Errorf("proof key: %w", err)
	}
	if _, err := fetchQualificationURL(ctx, client, http.MethodHead, target.EditorURL, 0); err != nil {
		return QualificationResult{}, fmt.Errorf("editor: %w", err)
	}
	digest := sha256.Sum256(body)
	return QualificationResult{
		Checks: map[string]any{
			"discovery": "pass", "proof": "pass", "editor": "pass",
			"wopiSave": "pending_receipt", "discoveryBytes": len(body),
		},
		DiscoveryFingerprint: hex.EncodeToString(digest[:]),
		Duration:             time.Since(started),
	}, nil
}

func fetchQualificationURL(ctx context.Context, client *http.Client, method, raw string, exactStatus int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml,text/xml,*/*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if exactStatus != 0 && res.StatusCode != exactStatus {
		return nil, fmt.Errorf("unexpected HTTP status %d", res.StatusCode)
	}
	if exactStatus == 0 && (res.StatusCode < 200 || res.StatusCode >= 500) {
		return nil, fmt.Errorf("unexpected HTTP status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, qualificationResponseLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > qualificationResponseLimit {
		return nil, errors.New("response exceeds 2 MiB")
	}
	return body, nil
}

func DecodeQualificationTarget(raw []byte) (QualificationTarget, error) {
	var target QualificationTarget
	if err := json.Unmarshal(raw, &target); err != nil {
		return QualificationTarget{}, fmt.Errorf("decode qualification target: %w", err)
	}
	if target.ProviderID == "" || target.Generation <= 0 || len(target.ConfigSHA256) != 64 {
		return QualificationTarget{}, errors.New("qualification target is incomplete")
	}
	return target, nil
}
