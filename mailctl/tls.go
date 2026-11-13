package main

import (
	"flag"
	"fmt"
)

func runTLS(c *cmdCtx, action string, args []string) error {
	switch action {
	case "status":
		return tlsStatusCmd(c, args)
	case "set":
		return tlsSetCmd(c.client, args)
	default:
		return fmt.Errorf("tls: unknown action %q (use: status, set)", action)
	}
}

func tlsStatusCmd(c *cmdCtx, args []string) error {
	cl := c.client
	var result struct {
		Enabled     bool     `json:"enabled"`
		Challenge   string   `json:"challenge"`
		Domains     []string `json:"domains"`
		Email       string   `json:"email"`
		DNSProvider string   `json:"dns_provider"`
		CertInfo    *struct {
			Subject   string `json:"subject"`
			Issuer    string `json:"issuer"`
			NotBefore string `json:"not_before"`
			NotAfter  string `json:"not_after"`
			DaysLeft  int    `json:"days_left"`
		} `json:"cert_info,omitempty"`
		CacheDir string `json:"cache_dir"`
	}

	if err := cl.Do("GET", "/admin/tls/status", nil, &result); err != nil {
		return err
	}

	if c.json {
		return printOut(c, result)
	}

	fmt.Printf("TLS: %s\n", enabledStr(result.Enabled))
	fmt.Printf("Challenge: %s\n", result.Challenge)
	fmt.Printf("Domains: %v\n", result.Domains)
	fmt.Printf("Email: %s\n", result.Email)
	fmt.Printf("DNS Provider: %s\n", result.DNSProvider)
	fmt.Printf("Cache Dir: %s\n", result.CacheDir)
	if result.CertInfo != nil {
		fmt.Printf("\nCertificate:\n")
		fmt.Printf("  Subject:   %s\n", result.CertInfo.Subject)
		fmt.Printf("  Issuer:    %s\n", result.CertInfo.Issuer)
		fmt.Printf("  Not Before: %s\n", result.CertInfo.NotBefore)
		fmt.Printf("  Not After:  %s\n", result.CertInfo.NotAfter)
		fmt.Printf("  Days Left:  %d\n", result.CertInfo.DaysLeft)
	}
	return nil
}

func tlsSetCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("tls set", flag.ExitOnError)
	challenge := fs.String("challenge", "", "ACME challenge type (tls-alpn-01, http-01, dns-01)")
	domains := fs.String("domains", "", "Comma-separated domain list")
	email := fs.String("email", "", "ACME notification email")
	dnsProvider := fs.String("dns-provider", "", "DNS provider for dns-01 (cloudflare, route53, rfc2136)")
	fs.Parse(args)

	body := map[string]string{}
	if *challenge != "" {
		body["tls.autocert_challenge"] = *challenge
	}
	if *domains != "" {
		body["tls.autocert_domains"] = *domains
	}
	if *email != "" {
		body["tls.autocert_email"] = *email
	}
	if *dnsProvider != "" {
		body["tls.dns_provider"] = *dnsProvider
	}

	if err := cl.Do("PUT", "/admin/tls/config", body, nil); err != nil {
		return err
	}

	fmt.Println("TLS config saved. Restart gateway to apply.")
	return nil
}

func enabledStr(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
