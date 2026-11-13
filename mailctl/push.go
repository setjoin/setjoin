package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	sharedpush "setjoin.com/shared/push"
)

// runPush implements `mailctl push doctor` and `mailctl push test --user <email>`.
//
//   - doctor: validates every configured provider from the environment (VAPID key
//     parses, APNs cert loads, FCM SA parses+OAuths, HMS OAuths). Fully local — no
//     DB. Prints configured / absent / INVALID per provider.
//   - test:   resolves the user's non-revoked push devices, decrypts their tokens
//     (DB_ENCRYPTION_KEY), and sends one test notification per device.
//
// Registered modeDB (preferDirect=false); doctor simply never opens the pool.
func runPush(c *cmdCtx, action string, args []string) error {
	switch action {
	case "doctor":
		return pushDoctor(c)
	case "test":
		return pushTest(c, args)
	default:
		return fmt.Errorf("unknown push action: %s (try: doctor, test)", action)
	}
}

func pushDoctor(c *cmdCtx) error {
	statuses := sharedpush.Doctor(context.Background(), sharedpush.LoadConfig())
	if c.json {
		rows := make([]map[string]interface{}, 0, len(statuses))
		for _, s := range statuses {
			rows = append(rows, map[string]interface{}{
				"provider": string(s.Kind), "state": string(s.State), "detail": s.Detail,
			})
		}
		return printOut(c, rows)
	}
	var anyInvalid bool
	for _, s := range statuses {
		mark := "  "
		switch s.State {
		case sharedpush.Configured:
			mark = "OK"
		case sharedpush.Invalid:
			mark = "!!"
			anyInvalid = true
		case sharedpush.Absent:
			mark = ".."
		}
		if s.Detail != "" {
			fmt.Printf("  [%s] %-8s %s — %s\n", mark, s.Kind, s.State, s.Detail)
		} else {
			fmt.Printf("  [%s] %-8s %s\n", mark, s.Kind, s.State)
		}
	}
	if anyInvalid {
		return fmt.Errorf("one or more push providers have INVALID config")
	}
	return nil
}

func pushTest(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("push test", flag.ContinueOnError)
	user := fs.String("user", "", "recipient email address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("usage: mailctl push test --user <email>")
	}

	encKey := os.Getenv("DB_ENCRYPTION_KEY")
	if encKey == "" {
		return fmt.Errorf("DB_ENCRYPTION_KEY is required to decrypt device tokens")
	}

	set, statuses := sharedpush.Build(sharedpush.LoadConfig())
	if !set.Any() {
		return fmt.Errorf("no push providers configured (run 'mailctl push doctor')")
	}
	_ = statuses

	pool, err := c.openDB()
	if err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// Set the encryption key so ResolveDevices' pgp_sym_decrypt
	// (current_setting('app.encryption_key')) can read it, matching the gateway.
	// The GUC is transaction-local (is_local=true) and every statement that
	// reads it runs inside the SAME explicit transaction: openDB hands out the
	// PgBouncer transaction-pooled DB_DSN, so a session-scoped set_config would
	// outlive this command on the pooled server connection and leak
	// DB_ENCRYPTION_KEY to the next borrower (D-MAILCTL-006).
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin push test transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.encryption_key', $1, true)`, encKey); err != nil {
		return fmt.Errorf("set encryption key: %w", err)
	}

	var userID int64
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE email = lower($1)`, *user).Scan(&userID); err != nil {
		return fmt.Errorf("resolve user %q: %w", *user, err)
	}

	devices, err := sharedpush.ResolveDevices(ctx, tx, userID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit push test transaction: %w", err)
	}
	committed = true
	if len(devices) == 0 {
		return fmt.Errorf("user %q has no registered push devices", *user)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"type": "test",
		"body": "SetJoin mailctl push test",
	})

	var sent, failed int
	for _, d := range devices {
		disp, ok := set.Get(d.Provider)
		if !ok {
			fmt.Printf("  SKIP device %d (%s): provider not configured here\n", d.ID, d.Provider)
			continue
		}
		if err := disp.Send(ctx, d.Token, payload); err != nil {
			fmt.Printf("  FAIL device %d (%s): %v\n", d.ID, d.Provider, err)
			failed++
			continue
		}
		fmt.Printf("  SENT device %d (%s)\n", d.ID, d.Provider)
		sent++
	}
	fmt.Printf("Done: %d sent, %d failed\n", sent, failed)
	if sent == 0 {
		return fmt.Errorf("no test push delivered")
	}
	return nil
}
