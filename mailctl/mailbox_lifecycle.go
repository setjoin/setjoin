package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const maxMailboxLifecycleResponse = 1 << 20

func runMailboxLifecycle(c *cmdCtx, action string, args []string) error {
	switch action {
	case "retained":
		if len(args) != 0 {
			return fmt.Errorf("usage: mailctl mailbox retained")
		}
		var result []map[string]any
		if err := c.client.DoBounded(http.MethodGet, "/admin/mailboxes/retained", nil, &result, maxMailboxLifecycleResponse); err != nil {
			return err
		}
		return printOut(c, result)
	case "preview":
		return mailboxLifecyclePreviewCmd(c, args)
	case "parity":
		if len(args) != 0 {
			return fmt.Errorf("usage: mailctl mailbox parity")
		}
		var result map[string]any
		if err := c.client.DoBounded(http.MethodGet, "/admin/mailboxes/lifecycle/parity", nil, &result, maxMailboxLifecycleResponse); err != nil {
			return err
		}
		return printOut(c, result)
	case "suspend", "resume", "detach-retain", "reconnect":
		return mailboxLifecycleTransitionCmd(c, action, args)
	case "purge-schedule":
		return mailboxPurgeScheduleCmd(c, args)
	case "purge-approve", "purge-deny":
		return mailboxPurgeApprovalCmd(c, action, args)
	case "purge-cancel", "purge-execute":
		return mailboxPurgeActionCmd(c, action, args)
	default:
		return fmt.Errorf("unknown mailbox action: %s", action)
	}
}

func mailboxPositiveID(raw, name string) (string, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return "", fmt.Errorf("%s must be a positive decimal identifier", name)
	}
	return strconv.FormatInt(id, 10), nil
}

func mailboxReason(reason string) error {
	if len(reason) < 8 || len(reason) > 1024 || strings.TrimSpace(reason) != reason || strings.ContainsAny(reason, "\r\n\x00") {
		return fmt.Errorf("--reason must contain 8-1024 safe characters without leading/trailing whitespace")
	}
	return nil
}

func mailboxLifecycleDo(c *Client, method, path, reason, key string, body, result any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal mailbox lifecycle request: %w", err)
	}
	headers := make(http.Header)
	if reason != "" {
		headers.Set("X-Audit-Reason", reason)
	}
	if key != "" {
		headers.Set("Idempotency-Key", key)
	}
	return c.DoRawWithHeadersBounded(method, path, "application/json", headers,
		bytes.NewReader(raw), result, maxMailboxLifecycleResponse)
}

func mailboxLifecyclePreviewCmd(c *cmdCtx, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mailctl mailbox preview <mailbox-id>")
	}
	id, err := mailboxPositiveID(args[0], "mailbox-id")
	if err != nil {
		return err
	}
	var result map[string]any
	if err := c.client.DoBounded(http.MethodGet, "/admin/mailboxes/"+id+"/lifecycle/preview", nil, &result, maxMailboxLifecycleResponse); err != nil {
		return err
	}
	return printOut(c, result)
}

func mailboxLifecycleTransitionCmd(c *cmdCtx, action string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl mailbox %s <mailbox-id> --generation N --reason TEXT", action)
	}
	mailboxID, err := mailboxPositiveID(args[0], "mailbox-id")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("mailbox "+action, flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	var generation, reason, targetUser, evidenceKind, linkID, linkGeneration, sourceDigest, delivery string
	fs.StringVar(&generation, "generation", "", "expected lifecycle generation")
	fs.StringVar(&reason, "reason", "", "audit reason")
	fs.StringVar(&targetUser, "target-user", "", "verified target user id")
	fs.StringVar(&evidenceKind, "evidence-kind", "", "local_user or identity_link")
	fs.StringVar(&linkID, "identity-link", "", "identity link id")
	fs.StringVar(&linkGeneration, "link-generation", "", "identity link generation")
	fs.StringVar(&sourceDigest, "source-key-digest", "", "source key SHA-256")
	fs.StringVar(&delivery, "delivery", "", "accepting or rejecting")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 {
		return fmt.Errorf("invalid mailbox %s flags", action)
	}
	if _, err := mailboxPositiveID(generation, "generation"); err != nil {
		return err
	}
	if err := mailboxReason(reason); err != nil {
		return err
	}
	serverAction := strings.ReplaceAll(action, "-", "_")
	body := map[string]string{
		"action": serverAction, "expectedGeneration": generation,
		"reason": reason, "idempotencyKey": uuid.NewString(),
	}
	if delivery != "" {
		if delivery != "accepting" && delivery != "rejecting" {
			return fmt.Errorf("--delivery must be accepting or rejecting")
		}
		body["delivery"] = delivery
	}
	if action == "reconnect" {
		if _, err := mailboxPositiveID(targetUser, "target-user"); err != nil {
			return err
		}
		if evidenceKind != "local_user" && evidenceKind != "identity_link" {
			return fmt.Errorf("--evidence-kind must be local_user or identity_link")
		}
		body["targetUserId"], body["evidenceKind"] = targetUser, evidenceKind
		if evidenceKind == "identity_link" {
			if _, err := mailboxPositiveID(linkID, "identity-link"); err != nil {
				return err
			}
			if _, err := mailboxPositiveID(linkGeneration, "link-generation"); err != nil {
				return err
			}
			if len(sourceDigest) != 64 {
				return fmt.Errorf("--source-key-digest must be a 64-character SHA-256 digest")
			}
			body["identityLinkId"], body["linkGeneration"], body["sourceKeyDigest"] = linkID, linkGeneration, strings.ToLower(sourceDigest)
		}
	}
	if (action == "suspend" || action == "detach-retain") && !confirm(c, action+" mailbox "+mailboxID) {
		return fmt.Errorf("cancelled")
	}
	var result map[string]any
	if err := mailboxLifecycleDo(c.client, http.MethodPost, "/admin/mailboxes/"+mailboxID+"/lifecycle",
		reason, body["idempotencyKey"], body, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

func mailboxPurgeScheduleCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl mailbox purge-schedule <mailbox-id> --generation N --preview-digest HEX --approver-user ID --reason TEXT")
	}
	mailboxID, err := mailboxPositiveID(args[0], "mailbox-id")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("mailbox purge-schedule", flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	var generation, digest, approver, reason string
	fs.StringVar(&generation, "generation", "", "expected lifecycle generation")
	fs.StringVar(&digest, "preview-digest", "", "preview SHA-256")
	fs.StringVar(&approver, "approver-user", "", "independent approver user id")
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 {
		return fmt.Errorf("invalid purge-schedule flags")
	}
	if _, err := mailboxPositiveID(generation, "generation"); err != nil {
		return err
	}
	if _, err := mailboxPositiveID(approver, "approver-user"); err != nil {
		return err
	}
	if len(digest) != 64 {
		return fmt.Errorf("--preview-digest must be a 64-character SHA-256 digest")
	}
	if err := mailboxReason(reason); err != nil {
		return err
	}
	if !confirm(c, "schedule permanent purge for mailbox "+mailboxID) {
		return fmt.Errorf("cancelled")
	}
	key := uuid.NewString()
	body := map[string]string{"expectedGeneration": generation, "previewDigest": strings.ToLower(digest),
		"approverUserId": approver, "reason": reason, "idempotencyKey": key}
	var result map[string]any
	if err := mailboxLifecycleDo(c.client, http.MethodPost, "/admin/mailboxes/"+mailboxID+"/purge", reason, key, body, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

func mailboxPurgeApprovalCmd(c *cmdCtx, action string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl mailbox %s <approval-id> [--comment TEXT]", action)
	}
	id, err := mailboxPositiveID(args[0], "approval-id")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("mailbox "+action, flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	var comment string
	fs.StringVar(&comment, "comment", "", "bounded approval comment")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 || len(comment) > 1024 {
		return fmt.Errorf("invalid purge approval flags")
	}
	if action == "purge-approve" && !confirm(c, "approve permanent mailbox purge request "+id) {
		return fmt.Errorf("cancelled")
	}
	decision := "approve"
	if action == "purge-deny" {
		decision = "deny"
	}
	var result map[string]any
	if err := mailboxLifecycleDo(c.client, http.MethodPost, "/admin/mailbox-purge-approvals/"+id,
		"", "", map[string]string{"decision": decision, "comment": comment}, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

func mailboxPurgeActionCmd(c *cmdCtx, action string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl mailbox %s <purge-id> --reason TEXT", action)
	}
	purgeID, err := uuid.Parse(args[0])
	if err != nil || purgeID == uuid.Nil {
		return fmt.Errorf("purge-id must be a UUID")
	}
	fs := flag.NewFlagSet("mailbox "+action, flag.ContinueOnError)
	fs.SetOutput(bytes.NewBuffer(nil))
	var reason string
	fs.StringVar(&reason, "reason", "", "audit reason")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 {
		return fmt.Errorf("invalid %s flags", action)
	}
	if err := mailboxReason(reason); err != nil {
		return err
	}
	if action == "purge-execute" && !confirm(c, "permanently purge mailbox request "+purgeID.String()) {
		return fmt.Errorf("cancelled")
	}
	key := uuid.NewString()
	body := map[string]string{"reason": reason, "idempotencyKey": key}
	verb := strings.TrimPrefix(action, "purge-")
	var result map[string]any
	if err := mailboxLifecycleDo(c.client, http.MethodPost, "/admin/mailbox-purges/"+purgeID.String()+"/"+verb,
		reason, key, body, &result); err != nil {
		return err
	}
	return printOut(c, result)
}
