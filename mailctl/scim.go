package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// runScim is the modeDB entrypoint. It validates the action FIRST (so `scim
// bogus` returns its "unknown action" error without demanding a DSN —
// byte-identical with the pre-table dispatch), then the sub-handlers open the
// pool via c.openDB(), which applies scim's pooled-DB_DSN policy.
func runScim(c *cmdCtx, action string, args []string) error {
	switch action {
	case "create-token":
		return scimCreateToken(c, args)
	case "list-tokens":
		return scimListTokens(c, args)
	default:
		return fmt.Errorf("unknown scim action: %s. Try: create-token, list-tokens", action)
	}
}

func scimCreateToken(c *cmdCtx, args []string) error {
	opts, err := parseScimCreateTokenArgs(args)
	if err != nil {
		return err
	}

	// Connect to database (pooled DB_DSN; dispatch owns closing c.db).
	ctx := context.Background()
	pool, err := c.openDB()
	if err != nil {
		return err
	}

	// Generate random token (32 bytes = 64 hex chars)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("random generation failed: %w", err)
	}
	plaintext := hex.EncodeToString(tokenBytes)

	// bcrypt hash the token for storage
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt hashing failed: %w", err)
	}

	// Non-secret indexed lookup key (V238): lowercase hex SHA-256 of the raw
	// token, so gateway auth resolves one candidate row instead of bcrypt-
	// scanning every active token. It is not a verifier and not reversible
	// into the 256-bit random token.
	lookupSum := sha256.Sum256([]byte(plaintext))
	lookupHash := hex.EncodeToString(lookupSum[:])

	// Insert into scim_tokens
	var expiresAt any
	now := time.Now()
	if opts.expiry > 0 {
		expiresAt = now.Add(opts.expiry).UTC()
	} else {
		expiresAt = nil
	}

	var created []byte
	err = pool.QueryRow(ctx,
		`SELECT scim_token_create($1,$2,$3,$4,$5,'mailctl',$6)`,
		opts.sourceKey, opts.name, string(hash), expiresAt, opts.deletionPolicy, lookupHash,
	).Scan(&created)
	if err != nil {
		return fmt.Errorf("token creation failed: %w", err)
	}

	fmt.Printf("SCIM token created successfully.\n\n")
	fmt.Printf("  Name:            %s\n", opts.name)
	fmt.Printf("  Source:          %s\n", opts.sourceKey)
	fmt.Printf("  Deletion policy: %s\n", opts.deletionPolicy)
	if opts.expiry > 0 {
		fmt.Printf("  Expires:         %s\n", now.Add(opts.expiry).UTC().Format(time.RFC3339))
	} else {
		fmt.Printf("  Expires:         never\n")
	}
	fmt.Printf("\n  Token (save now — cannot be recovered):\n")
	fmt.Printf("  %s\n\n", plaintext)
	fmt.Printf("  Authorization header:\n")
	fmt.Printf("  Authorization: Bearer %s\n\n", plaintext)
	fmt.Printf("Copy this header into your IdP provisioning configuration:\n")
	fmt.Printf("  - Entra ID: Enterprise Applications → Provisioning → Admin Credentials\n")
	fmt.Printf("  - Okta: Applications → Provisioning → API Integration\n")

	return nil
}

type scimCreateTokenOptions struct {
	name           string
	sourceKey      string
	expiry         time.Duration
	deletionPolicy string
}

func parseScimCreateTokenArgs(args []string) (scimCreateTokenOptions, error) {
	fs := flag.NewFlagSet("scim create-token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "Token name (required)")
	sourceKey := fs.String("source", "", "Active SCIM identity source key (required)")
	expiry := fs.Duration("expiry", 0, "Token expiry duration (e.g. 8760h for 1 year). 0 = no expiry")
	deletionPolicy := fs.String("deletion-policy", "soft", "soft or hard")
	if err := fs.Parse(args); err != nil {
		return scimCreateTokenOptions{}, err
	}
	if fs.NArg() != 0 {
		return scimCreateTokenOptions{}, fmt.Errorf("unexpected positional arguments")
	}
	if *name == "" {
		return scimCreateTokenOptions{}, fmt.Errorf("--name is required")
	}
	if strings.TrimSpace(*name) != *name || len(*name) > 128 {
		return scimCreateTokenOptions{}, fmt.Errorf("--name must be trimmed and at most 128 bytes")
	}
	if *sourceKey == "" {
		return scimCreateTokenOptions{}, fmt.Errorf("--source is required")
	}
	if strings.TrimSpace(*sourceKey) != *sourceKey || len(*sourceKey) > 64 {
		return scimCreateTokenOptions{}, fmt.Errorf("--source must be a trimmed identity source key of at most 64 bytes")
	}
	if *expiry < 0 {
		return scimCreateTokenOptions{}, fmt.Errorf("--expiry must not be negative")
	}
	if *deletionPolicy != "soft" && *deletionPolicy != "hard" {
		return scimCreateTokenOptions{}, fmt.Errorf("--deletion-policy must be 'soft' or 'hard'")
	}
	return scimCreateTokenOptions{
		name: *name, sourceKey: *sourceKey, expiry: *expiry,
		deletionPolicy: *deletionPolicy,
	}, nil
}

func scimListTokens(c *cmdCtx, args []string) error {
	ctx := context.Background()
	pool, err := c.openDB()
	if err != nil {
		return err
	}
	// dispatch owns closing c.db.

	rows, err := pool.Query(ctx,
		`SELECT token_id,name,source_key,source_state,created_at,last_used_at,
		        expires_at,revoked_at,deletion_policy,token_hash_prefix
		   FROM scim_token_list()`)
	if err != nil {
		return fmt.Errorf("token query failed: %w", err)
	}
	defer rows.Close()

	fmt.Printf("%-4s %-24s %-24s %-20s %-20s %-20s %-12s %-6s %s\n",
		"ID", "NAME", "SOURCE", "CREATED", "LAST USED", "EXPIRES", "STATUS", "POLICY", "HASH")
	fmt.Println("──── ─────────────────────── ─────────────────────── ──────────────────── ──────────────────── ──────────────────── ──────────── ────── ────────")

	var count int
	for rows.Next() {
		var id int64
		var name, sourceKey, sourceState string
		var createdAt time.Time
		var lastUsedAt *time.Time
		var expiresAt *time.Time
		var revokedAt *time.Time
		var dp string
		var tokenHashPrefix string

		if err := rows.Scan(
			&id, &name, &sourceKey, &sourceState, &createdAt, &lastUsedAt,
			&expiresAt, &revokedAt, &dp, &tokenHashPrefix,
		); err != nil {
			continue
		}

		status := "active"
		if revokedAt != nil {
			status = "revoked"
		} else if expiresAt != nil && expiresAt.Before(time.Now()) {
			status = "expired"
		} else if sourceState != "active" {
			status = sourceState
		}

		lastUsed := "-"
		if lastUsedAt != nil {
			lastUsed = lastUsedAt.Format(time.RFC3339)
		}
		expires := "never"
		if expiresAt != nil {
			expires = expiresAt.Format(time.RFC3339)
		}

		maskedHash := tokenHashPrefix + "..."

		fmt.Printf("%-4d %-24s %-24s %-20s %-20s %-20s %-12s %-6s %s\n",
			id, truncate(name, 23), truncate(sourceKey, 23),
			createdAt.Format(time.RFC3339), lastUsed, expires, status, dp, maskedHash)
		count++
	}

	if count == 0 {
		fmt.Println("(no SCIM tokens configured)")
	} else {
		fmt.Printf("\n%d token(s)\n", count)
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
