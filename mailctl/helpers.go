package main

import "fmt"

// resolveUserID looks up a user's numeric id by email. There is no by-email GET
// that returns the id, so it lists users (GET /admin/users) and matches locally.
// Used by role grant/revoke and the quota verbs.
func resolveUserID(c *cmdCtx, email string) (int64, error) {
	if email == "" {
		return 0, fmt.Errorf("email is required")
	}
	var users []struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	}
	if err := c.client.Do("GET", "/admin/users", nil, &users); err != nil {
		return 0, err
	}
	for _, u := range users {
		if u.Email == email {
			return u.ID, nil
		}
	}
	return 0, fmt.Errorf("no user found with email %q", email)
}
