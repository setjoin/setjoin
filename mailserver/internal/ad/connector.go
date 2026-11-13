package ad

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"setjoin.com/mailserver/internal/directorysync"
	"setjoin.com/mailserver/internal/ldaputil"
)

type usnCursor int64

func (c usnCursor) Encode() (json.RawMessage, error) {
	return json.Marshal(map[string]string{"usn": strconv.FormatInt(int64(c), 10)})
}

type normalizedConnector struct {
	client directoryClient
}

func (c normalizedConnector) Label() string                                   { return "AD" }
func (c normalizedConnector) Preflight() error                                { return nil }
func (c normalizedConnector) ValidateObject(directorysync.Object, bool) error { return nil }

func (c normalizedConnector) DecodeCursor(raw json.RawMessage) (directorysync.Cursor, error) {
	if len(raw) == 0 {
		return usnCursor(0), nil
	}
	var value struct {
		USN string `json:"usn"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value.USN == "" {
		return usnCursor(0), nil
	}
	parsed, err := strconv.ParseInt(value.USN, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("decode AD committed uSNChanged: %w", err)
	}
	return usnCursor(parsed), nil
}

// Fetch honors ctx (D-MAILSERVER-INTERNAL-AD-004): cancellation is observed
// before the dial/bind/search work, and SearchUsers checks ctx between pages
// so a canceled admin SyncNow or worker shutdown stops the LDAP half promptly
// instead of running to completion (pages x 30s dial timeout).
func (c normalizedConnector) Fetch(ctx context.Context, from directorysync.Cursor) ([]directorysync.Object, directorysync.Cursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("AD fetch canceled before connect: %w", err)
	}
	cursor, ok := from.(usnCursor)
	if !ok {
		return nil, nil, fmt.Errorf("AD cursor has type %T", from)
	}
	conn, err := c.client.connect()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("AD fetch canceled before bind: %w", err)
	}
	if err := c.client.Bind(conn); err != nil {
		return nil, nil, err
	}
	users, maxUSN, err := c.client.SearchUsers(ctx, conn, int64(cursor))
	if err != nil {
		return nil, nil, err
	}
	if maxUSN < int64(cursor) {
		maxUSN = int64(cursor)
	}
	objects := make([]directorysync.Object, 0, len(users))
	for _, user := range users {
		objects = append(objects, directorysync.Object{
			Subject:            user.ObjectGUID,
			RelationKey:        ldaputil.NormalizeDN(user.DN),
			ManagerRelationKey: ldaputil.NormalizeDN(user.ManagerDN),
			ManagerSubject:     user.ManagerSubject,
			Email:              user.Email,
			DisplayName:        user.DisplayName,
			FirstName:          user.FirstName,
			LastName:           user.LastName,
			JobTitle:           user.Title,
			Phone:              user.Phone,
			Department:         user.Department,
			UPN:                user.UPN,
			Disabled:           user.Disabled,
			CursorValue:        strconv.FormatInt(user.USNChanged, 10),
		})
	}
	return objects, usnCursor(maxUSN), nil
}
