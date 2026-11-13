package smtp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ContactGraphDetector checks for impersonation attacks by comparing the sender's
// display name against the recipient's contact graph. If the sender email is novel
// but the display name matches a known contact at a different address, it flags
// as impersonation (Warn only — never Reject, to avoid false positives).
type ContactGraphDetector struct {
	pool *pgxpool.Pool

	// negativeCache avoids re-querying repeat senders.
	// Key: "mailbox_id:sender_email", Value: last checked timestamp.
	negativeCache sync.Map
	negativeTTL   time.Duration
}

// NewContactGraphDetector creates a new contact-graph impersonation detector.
func NewContactGraphDetector(pool *pgxpool.Pool) *ContactGraphDetector {
	return &ContactGraphDetector{
		pool:        pool,
		negativeTTL: 10 * time.Minute,
	}
}

// Name returns the detector identifier.
func (d *ContactGraphDetector) Name() string {
	return "contact_graph"
}

// Check evaluates the message for contact-graph impersonation.
func (d *ContactGraphDetector) Check(ctx context.Context, msg *PhishInput) (*PhishResult, error) {
	fromName := msg.FromName
	if fromName == "" {
		return nil, nil
	}
	fromAddr := msg.FromAddr
	if fromAddr == "" {
		return nil, nil
	}

	for _, rcpt := range msg.Recipients {
		if rcpt.MailboxID == 0 {
			continue
		}

		cacheKey := fmt.Sprintf("%d:%s", rcpt.MailboxID, fromAddr)

		// Check negative cache
		if lastChecked, ok := d.negativeCache.Load(cacheKey); ok {
			if ts, ok := lastChecked.(time.Time); ok {
				if time.Since(ts) < d.negativeTTL {
					continue // known repeat sender, skip
				}
			}
		}

		// If no pool, skip DB queries (test mode)
		if d.pool == nil {
			continue
		}

		// Check if this sender has previously delivered to this recipient
		known, err := d.isKnownSender(ctx, rcpt.MailboxID, fromAddr)
		if err != nil {
			return nil, err
		}

		if known {
			d.negativeCache.Store(cacheKey, time.Now())
			continue
		}

		// Novel sender: check if display name matches a known contact
		matched, matchedAddr, err := d.findNameMatch(ctx, rcpt.MailboxID, fromName, fromAddr)
		if err != nil {
			return nil, err
		}

		if matched {
			return &PhishResult{
				Verdict:  PhishWarn,
				Detector: d.Name(),
				Evidence: []string{fmt.Sprintf("impersonation:%s:%s matches %s", fromName, fromAddr, matchedAddr)},
			}, nil
		}

		// Cache as non-match
		d.negativeCache.Store(cacheKey, time.Now())
	}

	return nil, nil
}

// isKnownSender checks whether this sender email has previously delivered to the mailbox.
func (d *ContactGraphDetector) isKnownSender(ctx context.Context, mailboxID int64, senderEmail string) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM antiphish_contact_graph
			WHERE mailbox_id = $1 AND sender_email = $2
		)`, mailboxID, senderEmail,
	).Scan(&exists)
	return exists, err
}

// findNameMatch checks whether a different sender address with the same display name
// has previously delivered to the mailbox.
func (d *ContactGraphDetector) findNameMatch(ctx context.Context, mailboxID int64, senderName, senderEmail string) (bool, string, error) {
	var matchedAddr string
	err := d.pool.QueryRow(ctx,
		`SELECT sender_email FROM antiphish_contact_graph
		 WHERE mailbox_id = $1 AND lower(sender_name) = lower($2) AND sender_email != $3
		 LIMIT 1`,
		mailboxID, senderName, senderEmail,
	).Scan(&matchedAddr)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, "", nil
		}
		return false, "", err
	}
	return true, matchedAddr, nil
}

// CacheSize returns the number of entries in the negative cache (useful for testing/monitoring).
func (d *ContactGraphDetector) CacheSize() int {
	count := 0
	d.negativeCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
