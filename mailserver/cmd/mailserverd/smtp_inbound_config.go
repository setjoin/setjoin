package main

import (
	"log/slog"
	"strings"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/smtp"
	"setjoin.com/mailserver/internal/spam"
)

// smtpInboundCommonSetter is the composition-root seam shared by the STARTTLS
// and implicit-TLS inbound listeners. TLS policy and certificates remain owned
// by the individual listener sites in main.go.
type smtpInboundCommonSetter interface {
	SetBlobStore(*minio.Client, string)
	SetMaxConns(int32)
	SetClamAV(string)
	SetSandbox(*smtp.AttachmentAnalysisPipeline)
	SetLinkProtect([]byte, []string)
	SetLinkProtectKeys(linkprotect.TokenKeys)
	SetAntiPhish([]smtp.PhishDetector)
	SetSpamStore(spam.ModelSource)
}

func configureSMTPInboundCommon(
	server smtpInboundCommonSetter,
	cfg *config.Config,
	minioClient *minio.Client,
	antiPhishDetectors []smtp.PhishDetector,
	spamStore *spam.PGModelStore,
	logger *slog.Logger,
) {
	server.SetBlobStore(minioClient, cfg.S3Bucket)
	server.SetMaxConns(clampInt32(cfg.SMTPInboundMaxConns))

	if cfg.ClamAVAddr != "" {
		server.SetClamAV(cfg.ClamAVAddr)
		logger.Info("ClamAV scanning enabled", "addr", cfg.ClamAVAddr)
	}

	if cfg.SandboxEnabled && cfg.SandboxCAPEURL != "" {
		capeAnalyzer := smtp.NewCAPEAnalyzer(cfg.SandboxCAPEURL, cfg.SandboxCAPEKey, cfg.SandboxTimeout)
		failMode := smtp.FailOpen
		if cfg.SandboxFailMode == "closed" {
			failMode = smtp.FailClosed
		}
		pipeline := smtp.NewAttachmentAnalysisPipeline(
			[]smtp.SandboxAnalyzer{capeAnalyzer}, cfg.SandboxTimeout, failMode, logger,
		)
		server.SetSandbox(pipeline)
		logger.Info("sandbox attachment analysis enabled", "cape_url", cfg.SandboxCAPEURL, "timeout", cfg.SandboxTimeout, "fail_mode", cfg.SandboxFailMode)
	}

	if cfg.JWTSecret != "" {
		internalDomains := strings.Split(cfg.InternalDomains, ",")
		for i := range internalDomains {
			internalDomains[i] = strings.TrimSpace(internalDomains[i])
		}
		server.SetLinkProtect([]byte(cfg.JWTSecret), internalDomains)
		// MAILSERVERD-004: install the configured versioned key set so the
		// inbound rewriter mints tokens under the CURRENT key version — the
		// click handler and the outbound un-rewriter verify against the same
		// set, and a rotation never orphans tokens already delivered in mail.
		server.SetLinkProtectKeys(cfg.LinkProtectTokenKeys())
	}

	server.SetAntiPhish(antiPhishDetectors)
	// Normalize a nil concrete store to a nil interface: a typed-nil
	// *PGModelStore inside a non-nil interface would defeat InboundServer's
	// spamStore != nil delivery guard.
	var spamSource spam.ModelSource
	if spamStore != nil {
		spamSource = spamStore
	}
	server.SetSpamStore(spamSource)
}
