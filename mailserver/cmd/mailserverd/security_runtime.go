package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/threat"
)

type revocationQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadActiveSessionRevocations(
	ctx context.Context,
	querier revocationQuerier,
	protocolSessions *threat.ProtocolSessionRegistry,
) ([]threat.RevocationRow, error) {
	rows, err := querier.Query(ctx,
		`SELECT user_id, scope, COALESCE(jti,''), COALESCE(family_id,''),
		        not_before, expires_at
		   FROM session_revocations
		  WHERE expires_at > now()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []threat.RevocationRow
	for rows.Next() {
		var row threat.RevocationRow
		if err := rows.Scan(
			&row.UserID, &row.Scope, &row.JTI, &row.FamilyID,
			&row.NotBefore, &row.ExpiresAt,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The same durable snapshot repairs missed protocol-session NOTIFYs.
	protocolSessions.Reconcile(out)
	return out, nil
}

func decodeSessionRevocation(payload string) (threat.RevocationRow, error) {
	var encoded struct {
		UserID    int64  `json:"user_id"`
		Scope     string `json:"scope"`
		NotBefore string `json:"not_before"`
		ExpiresAt string `json:"expires_at"`
		JTI       string `json:"jti"`
		FamilyID  string `json:"family_id"`
	}
	if err := json.Unmarshal([]byte(payload), &encoded); err != nil {
		return threat.RevocationRow{}, err
	}
	notBefore, err := time.Parse(time.RFC3339Nano, encoded.NotBefore)
	if err != nil {
		return threat.RevocationRow{}, errors.New("invalid not_before: " + err.Error())
	}
	var expiresAt time.Time
	if encoded.ExpiresAt != "" {
		expiresAt, err = time.Parse(time.RFC3339Nano, encoded.ExpiresAt)
		if err != nil {
			return threat.RevocationRow{}, errors.New("invalid expires_at: " + err.Error())
		}
	}
	return threat.RevocationRow{
		UserID:    encoded.UserID,
		Scope:     encoded.Scope,
		JTI:       encoded.JTI,
		FamilyID:  encoded.FamilyID,
		NotBefore: notBefore,
		ExpiresAt: expiresAt,
	}, nil
}
