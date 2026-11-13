package acme

import (
	"encoding/json"
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// ProviderConfig holds the provider type and its JSON credentials blob.
type ProviderConfig struct {
	Provider string `json:"provider"` // "cloudflare", "route53", "rfc2136"
	Config   string `json:"config"`   // provider-specific JSON credentials
}

// NewDNSProvider creates a lego DNS provider from config.
// Supported providers: cloudflare, route53, rfc2136.
func NewDNSProvider(cfg ProviderConfig) (challenge.Provider, error) {
	switch cfg.Provider {
	case "cloudflare":
		return newCloudflareProvider(cfg.Config)
	case "route53":
		return newRoute53Provider(cfg.Config)
	case "rfc2136":
		return newRFC2136Provider(cfg.Config)
	default:
		return nil, fmt.Errorf("unknown DNS provider: %q (supported: cloudflare, route53, rfc2136)", cfg.Provider)
	}
}

func newCloudflareProvider(config string) (challenge.Provider, error) {
	type cfConfig struct {
		APIToken string `json:"CF_API_TOKEN"`
	}
	var c cfConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, fmt.Errorf("cloudflare config: %w", err)
	}
	if c.APIToken == "" {
		return nil, fmt.Errorf("cloudflare: CF_API_TOKEN is required")
	}
	return cloudflare.NewDNSProviderConfig(&cloudflare.Config{
		AuthToken: c.APIToken,
		TTL:       120,
	})
}

func newRoute53Provider(config string) (challenge.Provider, error) {
	type r53Config struct {
		AccessKeyID     string `json:"AWS_ACCESS_KEY_ID"`
		SecretAccessKey string `json:"AWS_SECRET_ACCESS_KEY"`
		Region          string `json:"AWS_REGION"`
	}
	var c r53Config
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, fmt.Errorf("route53 config: %w", err)
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	return route53.NewDNSProviderConfig(&route53.Config{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		Region:          c.Region,
	})
}

func newRFC2136Provider(config string) (challenge.Provider, error) {
	type rfcConfig struct {
		Nameserver string `json:"RFC2136_NAMESERVER"`
		TSIGKey    string `json:"RFC2136_TSIG_KEY"`
		TSIGSecret string `json:"RFC2136_TSIG_SECRET"`
		Algorithm  string `json:"RFC2136_TSIG_ALGORITHM"`
	}
	var c rfcConfig
	if err := json.Unmarshal([]byte(config), &c); err != nil {
		return nil, fmt.Errorf("rfc2136 config: %w", err)
	}
	if c.Algorithm == "" {
		c.Algorithm = "hmac-sha256."
	}
	return rfc2136.NewDNSProviderConfig(&rfc2136.Config{
		Nameserver:    c.Nameserver,
		TSIGKey:       c.TSIGKey,
		TSIGSecret:    c.TSIGSecret,
		TSIGAlgorithm: c.Algorithm,
	})
}
