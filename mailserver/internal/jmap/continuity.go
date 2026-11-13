package jmap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"setjoin.com/mailserver/internal/auth"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/toggle"
)

type continuityContext struct {
	InstallationID     string  `json:"installationId"`
	TimelineID         string  `json:"timelineId"`
	TimelineGeneration string  `json:"timelineGeneration"`
	StateWatermark     string  `json:"stateWatermark"`
	ServerTime         string  `json:"serverTime"`
	PreviousWallClock  *string `json:"previousWallClock"`
	RestoreDeclaredAt  *string `json:"restoreDeclaredAt"`
}

type continuityGetArgs struct {
	AccountID string `json:"accountId"`
}

type continuityPresentArgs struct {
	AccountID string `json:"accountId"`
	Token     string `json:"token"`
}

func (h *JMAPHandler) continuityEnabled() bool {
	return h != nil && h.continuity != nil && h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureUpgradeClientReceipts)
}

func (h *JMAPHandler) continuityGet(ctx context.Context, user *auth.Claims, raw json.RawMessage) (string, json.RawMessage) {
	if !h.continuityEnabled() {
		return marshalResponse("error", Error{Type: "forbidden", Description: "client continuity receipts are disabled"})
	}
	var args continuityGetArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return marshalResponse("error", Error{Type: "invalidArguments", Description: "invalid continuity request"})
	}
	mailboxID, methodErr := h.parseAccountID(ctx, args.AccountID, user.UserID)
	if methodErr != nil {
		return "error", methodErr
	}
	current, methodErr := h.continuityContext(ctx, mailboxID)
	if methodErr != nil {
		return "error", methodErr
	}
	token, err := h.continuity.Issue(current.InstallationID, args.AccountID, current.TimelineGeneration, current.StateWatermark)
	if err != nil {
		return marshalResponse("error", Error{Type: "serverFail", Description: "continuity token signing failed"})
	}
	return marshalResponse("Continuity/get", map[string]any{
		"accountId": args.AccountID, "token": token, "timelineGeneration": current.TimelineGeneration,
		"stateWatermark": current.StateWatermark, "bootEpoch": h.continuity.BootEpoch,
	})
}

func (h *JMAPHandler) continuityPresent(ctx context.Context, user *auth.Claims, raw json.RawMessage) (string, json.RawMessage) {
	if !h.continuityEnabled() {
		return marshalResponse("error", Error{Type: "forbidden", Description: "client continuity receipts are disabled"})
	}
	var args continuityPresentArgs
	if err := json.Unmarshal(raw, &args); err != nil || args.Token == "" {
		return marshalResponse("error", Error{Type: "invalidArguments", Description: "invalid continuity witness"})
	}
	mailboxID, methodErr := h.parseAccountID(ctx, args.AccountID, user.UserID)
	if methodErr != nil {
		return "error", methodErr
	}
	current, methodErr := h.continuityContext(ctx, mailboxID)
	if methodErr != nil {
		return "error", methodErr
	}
	claims, err := sharedcontinuity.VerifyToken(args.Token, h.continuity.Keys, sharedcontinuity.VerifyOptions{
		Now: time.Now().UTC(), MaxAge: 180 * 24 * time.Hour,
		InstallationID: current.InstallationID, AccountID: args.AccountID,
	})
	if err != nil {
		status := "invalid"
		if errors.Is(err, sharedcontinuity.ErrUnknownKey) || errors.Is(err, sharedcontinuity.ErrExpired) {
			status = "unverifiable"
		}
		return marshalResponse("Continuity/present", map[string]any{
			"accountId": args.AccountID, "verificationStatus": status,
			"signalClass": "none", "recoveryIntakeAllowed": false,
		})
	}
	generation, errGeneration := strconv.ParseInt(claims.TimelineGeneration, 10, 64)
	watermark, errWatermark := strconv.ParseInt(claims.StateWatermark, 10, 64)
	issuedAt, errTime := time.Parse(time.RFC3339, claims.IssuedAt)
	if errGeneration != nil || errWatermark != nil || errTime != nil {
		return marshalResponse("error", Error{Type: "invalidArguments", Description: "invalid continuity witness"})
	}
	digest := sha256.Sum256([]byte(args.Token))
	result, err := h.caller.CallScoped(ctx, mailboxID, "continuity_client_witness_record",
		hex.EncodeToString(digest[:]), claims.InstallationID, generation, watermark, issuedAt, claims.BootEpoch)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "Continuity/present")
	}
	var response map[string]any
	if err := json.Unmarshal(result, &response); err != nil {
		return marshalResponse("error", Error{Type: "serverFail", Description: "invalid continuity result"})
	}
	response["accountId"] = args.AccountID
	response["verificationStatus"] = "verified"
	// U5 never opens intake. U7 requires a separate administrator incident,
	// step-up, user consent, and the independently-OFF ingest toggle.
	response["recoveryIntakeAllowed"] = false
	return marshalResponse("Continuity/present", response)
}

func (h *JMAPHandler) continuityContext(ctx context.Context, mailboxID int64) (continuityContext, json.RawMessage) {
	var current continuityContext
	raw, err := h.caller.CallScoped(ctx, mailboxID, "continuity_context_issue", h.continuity.BootEpoch)
	if err != nil {
		return current, mapReducerErr(err, h.logger, "Continuity/get")
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		errJSON, _ := json.Marshal(Error{Type: "serverFail", Description: "invalid continuity context"})
		return current, errJSON
	}
	return current, nil
}

func marshalResponse(name string, value any) (string, json.RawMessage) {
	raw, _ := json.Marshal(value)
	return name, raw
}
