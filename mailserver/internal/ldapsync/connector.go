package ldapsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"setjoin.com/mailserver/internal/directorysync"
	"setjoin.com/mailserver/internal/ldaputil"
)

type stampCursor string

func (c stampCursor) Encode() (json.RawMessage, error) {
	return json.Marshal(map[string]string{"modifyTimestamp": string(c)})
}

type normalizedConnector struct {
	client directoryClient
	filter string
}

func (c normalizedConnector) Label() string { return "LDAP" }
func (c normalizedConnector) Preflight() error {
	if c.client.SubjectAttribute() == "" {
		return errors.New("LDAP normalized sync requires a uniqueness-proven immutable subject attribute")
	}
	return nil
}
func (c normalizedConnector) ValidateObject(_ directorysync.Object, duplicate bool) error {
	if duplicate {
		return errors.New("LDAP immutable subject is not unique in page")
	}
	return nil
}

func (c normalizedConnector) DecodeCursor(raw json.RawMessage) (directorysync.Cursor, error) {
	if len(raw) == 0 {
		return stampCursor(""), nil
	}
	var value struct {
		ModifyTimestamp string `json:"modifyTimestamp"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return stampCursor(value.ModifyTimestamp), nil
}

func (c normalizedConnector) Fetch(_ context.Context, from directorysync.Cursor) ([]directorysync.Object, directorysync.Cursor, error) {
	cursor, ok := from.(stampCursor)
	if !ok {
		return nil, nil, fmt.Errorf("LDAP cursor has type %T", from)
	}
	conn, err := c.client.Connect()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := c.client.Bind(conn); err != nil {
		return nil, nil, err
	}
	users, err := c.client.SearchUsers(conn, buildSyncFilter(c.filter, string(cursor)), 500)
	if err != nil {
		return nil, nil, err
	}
	maxStamp := string(cursor)
	objects := make([]directorysync.Object, 0, len(users))
	for _, user := range users {
		if user.ModifyStamp > maxStamp {
			maxStamp = user.ModifyStamp
		}
		objects = append(objects, directorysync.Object{
			Subject:            user.ImmutableSubject,
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
			CursorValue:        user.ModifyStamp,
		})
	}
	return objects, stampCursor(maxStamp), nil
}
