package mailrecovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	servercontinuity "setjoin.com/mailserver/internal/continuity"
	"setjoin.com/mailserver/internal/mimeutil"
	sharedcontinuity "setjoin.com/shared/continuity"
	"setjoin.com/shared/jwtutil"
)

const (
	maxChunkBytes     = 256 << 10
	maxRawMIMEBytes   = 50 << 20
	maxArtifactBytes  = int64(8 << 30)
	receiptMaximumAge = 180 * 24 * time.Hour
	maximumParsedBody = 64 << 10
)

type InventoryItem struct {
	ItemID string `json:"itemId"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Size   string `json:"size"`
}

type parsedMessage struct {
	MessageID   string          `json:"messageId"`
	Subject     string          `json:"subject"`
	FromAddr    string          `json:"fromAddr"`
	FromName    string          `json:"fromName"`
	ToAddrs     json.RawMessage `json:"toAddrs"`
	CCAddrs     json.RawMessage `json:"ccAddrs"`
	BCCAddrs    json.RawMessage `json:"bccAddrs"`
	InReplyTo   string          `json:"inReplyTo"`
	References  string          `json:"references"`
	BodyText    string          `json:"bodyText"`
	BodyHTML    string          `json:"bodyHtml"`
	ReceivedAt  string          `json:"receivedAt"`
	Eligibility string          `json:"eligibility"`
}

func verifyOffer(service *servercontinuity.Service, receipt sharedcontinuity.SignedReceipt, accountID string, now time.Time) error {
	if service == nil {
		return errors.New("continuity verification unavailable")
	}
	if err := sharedcontinuity.VerifyReceipt(receipt, service.Keys, sharedcontinuity.VerifyOptions{
		AccountID: accountID,
		Now:       now.UTC(),
		MaxAge:    receiptMaximumAge,
	}); err != nil {
		return err
	}
	return nil
}

func verifyArtifactIdentity(receipt sharedcontinuity.SignedReceipt, supplied string) error {
	expected, err := sharedcontinuity.ArtifactIdentity(receipt.Claims)
	if err != nil || supplied != expected {
		return errors.New("recovery artifact identity mismatch")
	}
	return nil
}

func signedEligibility(receipt sharedcontinuity.SignedReceipt, requested string) (string, error) {
	if requested != receipt.Claims.Eligibility {
		return "", errors.New("recovery eligibility does not match signed receipt")
	}
	return receipt.Claims.Eligibility, nil
}

func validateInventory(receipt sharedcontinuity.SignedReceipt, inventory []InventoryItem) (int64, error) {
	if len(inventory) != len(receipt.Claims.Blobs)+1 || len(inventory) > 4097 {
		return 0, errors.New("recovery inventory cardinality mismatch")
	}
	signed := make(map[string]sharedcontinuity.BlobDigest, len(receipt.Claims.Blobs))
	for _, blob := range receipt.Claims.Blobs {
		signed[blob.BlobID] = blob
	}
	seen := make(map[string]struct{}, len(inventory))
	var total int64
	raw := 0
	for _, item := range inventory {
		if item.ItemID == "" || len(item.ItemID) > 256 || strings.ContainsAny(item.ItemID, "/\x00\r\n") {
			return 0, errors.New("invalid recovery inventory item")
		}
		if _, duplicate := seen[item.ItemID]; duplicate {
			return 0, errors.New("duplicate recovery inventory item")
		}
		seen[item.ItemID] = struct{}{}
		size, err := strconv.ParseInt(item.Size, 10, 64)
		if err != nil || size <= 0 || size > maxArtifactBytes || strconv.FormatInt(size, 10) != item.Size {
			return 0, errors.New("invalid recovery inventory size")
		}
		if len(item.SHA256) != sha256.Size*2 {
			return 0, errors.New("invalid recovery inventory digest")
		}
		if _, err := hex.DecodeString(item.SHA256); err != nil {
			return 0, errors.New("invalid recovery inventory digest")
		}
		switch item.Role {
		case "raw":
			raw++
			if item.ItemID != "raw" || item.SHA256 != receipt.Claims.RawMIMESHA256 || item.Size != receipt.Claims.RawMIMESize || size > maxRawMIMEBytes {
				return 0, errors.New("raw MIME inventory differs from receipt")
			}
		case "attachment", "inline":
			blob, ok := signed[item.ItemID]
			if !ok || blob.SHA256 != item.SHA256 || blob.Size != item.Size {
				return 0, errors.New("blob inventory differs from receipt")
			}
			delete(signed, item.ItemID)
		default:
			return 0, errors.New("invalid recovery inventory role")
		}
		if total > maxArtifactBytes-size {
			return 0, errors.New("recovery artifact exceeds size limit")
		}
		total += size
	}
	if raw != 1 || len(signed) != 0 {
		return 0, errors.New("recovery inventory is incomplete")
	}
	return total, nil
}

func parseRecoveredMessage(raw []byte, eligibility string, now time.Time) (parsedMessage, error) {
	if len(raw) == 0 || len(raw) > maxRawMIMEBytes || (eligibility != "received" && eligibility != "sent-terminal") {
		return parsedMessage{}, errors.New("invalid recoverable message")
	}
	if _, err := mail.ReadMessage(strings.NewReader(string(raw))); err != nil {
		return parsedMessage{}, fmt.Errorf("malformed RFC 5322 message: %w", err)
	}
	rawText := string(raw)
	fromName, fromAddr := mimeutil.ParseFrom(mimeutil.ExtractHeader(rawText, "From"))
	if fromAddr == "" || len(fromAddr) > 320 {
		return parsedMessage{}, errors.New("message has no valid From address")
	}
	receivedAt := now.UTC()
	if value := mimeutil.ExtractHeader(rawText, "Date"); value != "" {
		if parsed, err := mail.ParseDate(value); err == nil && parsed.Before(now.Add(5*time.Minute)) && parsed.After(now.AddDate(-20, 0, 0)) {
			receivedAt = parsed.UTC()
		}
	}
	bodyText := mimeutil.ExtractBodyText(rawText)
	bodyHTML := mimeutil.ExtractBodyHTML(rawText)
	if len(bodyText) > maximumParsedBody {
		bodyText = bodyText[:maximumParsedBody]
	}
	if len(bodyHTML) > maximumParsedBody {
		bodyHTML = bodyHTML[:maximumParsedBody]
	}
	return parsedMessage{
		MessageID: mimeutil.ExtractHeader(rawText, "Message-ID"), Subject: mimeutil.ExtractHeader(rawText, "Subject"),
		FromAddr: fromAddr, FromName: fromName,
		ToAddrs:   mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawText, "To")),
		CCAddrs:   mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawText, "Cc")),
		BCCAddrs:  mimeutil.ParseAddressList(mimeutil.ExtractHeader(rawText, "Bcc")),
		InReplyTo: mimeutil.ExtractHeader(rawText, "In-Reply-To"), References: mimeutil.ExtractHeader(rawText, "References"),
		BodyText: bodyText, BodyHTML: bodyHTML, ReceivedAt: receivedAt.Format(time.RFC3339), Eligibility: eligibility,
	}, nil
}

func recoveryStepUpBinding(claims *jwtutil.Claims, incidentID uuid.UUID, now time.Time) ([sha256.Size]byte, bool) {
	var empty [sha256.Size]byte
	evidence, err := jwtutil.VerifyFreshAAL2(claims, now, jwtutil.CurrentFreshAAL2Policy())
	if err != nil {
		return empty, false
	}
	issuedAt := evidence.IssuedAt.UTC().Format(time.RFC3339Nano)
	return sha256.Sum256([]byte(fmt.Sprintf("setjoin-mail-recovery-step-up-v1\n%d\n%s\n%s\n%s", evidence.UserID, evidence.JTI, issuedAt, incidentID))), true
}
