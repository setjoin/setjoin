package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"

	"golang.org/x/term"
	sharedconfig "setjoin.com/shared/config"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/validate"
)

type bootstrapAdminConfig struct {
	email         string
	passwordFile  string
	passwordStdin bool
}

type bootstrapAdminResult struct {
	AdminCreated bool   `json:"admin_created"`
	Reason       string `json:"reason"`
	Email        string `json:"email"`
	UserID       int64  `json:"user_id"`
}

var (
	bootstrapIsTerminal   = term.IsTerminal
	bootstrapReadPassword = term.ReadPassword
)

func parseBootstrapAdminFlags(args []string) (bootstrapAdminConfig, error) {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg bootstrapAdminConfig
	fs.StringVar(&cfg.email, "email", "", "first administrator email")
	fs.StringVar(&cfg.passwordFile, "password-file", "", "read password from a mode-0600 regular file")
	fs.BoolVar(&cfg.passwordStdin, "password-stdin", false, "read one password line from stdin")
	if err := fs.Parse(args); err != nil {
		return bootstrapAdminConfig{}, err
	}
	if fs.NArg() != 0 {
		return bootstrapAdminConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	cfg.email = strings.TrimSpace(strings.ToLower(cfg.email))
	parsed, err := mail.ParseAddress(cfg.email)
	if err != nil || parsed.Address != cfg.email || len(cfg.email) > 254 {
		return bootstrapAdminConfig{}, fmt.Errorf("--email must be one valid mailbox address")
	}
	// RFC 2142 gate: the first administrator must not claim a system identity
	// (postmaster, abuse, ...). Quoted-local or decorated inputs cannot bypass
	// this — the check evaluates the canonical address. This is the Go-side half
	// of the ensure_default_admin reserved-name wiring (the bootstrap path's
	// provisioning gate runs before the reducer is ever called).
	if validate.IsReservedEmailAddress(cfg.email) {
		return bootstrapAdminConfig{}, fmt.Errorf("--email must not use a reserved local-part (RFC 2142)")
	}
	if cfg.passwordFile != "" && cfg.passwordStdin {
		return bootstrapAdminConfig{}, fmt.Errorf("choose only one of --password-file or --password-stdin")
	}
	return cfg, nil
}

func readBootstrapPassword(cfg bootstrapAdminConfig, in *os.File, out io.Writer) ([]byte, error) {
	if cfg.passwordFile != "" {
		info, err := os.Lstat(cfg.passwordFile)
		if err != nil {
			return nil, fmt.Errorf("inspect password file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("password file must be a regular file with mode 0600 or stricter")
		}
		data, err := os.ReadFile(cfg.passwordFile)
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		return []byte(strings.TrimRight(string(data), "\r\n")), nil
	}
	if cfg.passwordStdin || !bootstrapIsTerminal(int(in.Fd())) {
		line, err := bufio.NewReader(io.LimitReader(in, validate.PasswordMaxBytes+2)).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read password from stdin: %w", err)
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fmt.Fprint(out, "Administrator password: ")
	first, err := bootstrapReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(out, "Confirm password: ")
	second, err := bootstrapReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, err
	}
	if string(first) != string(second) {
		return nil, fmt.Errorf("password confirmation does not match")
	}
	return first, nil
}

func runBootstrapAdmin(c *cmdCtx, action string, args []string) error {
	allArgs := append([]string(nil), args...)
	if action != "" {
		allArgs = append([]string{action}, allArgs...)
	}
	cfg, err := parseBootstrapAdminFlags(allArgs)
	if err != nil {
		return err
	}
	pool, err := c.openDB()
	if err != nil {
		return err
	}
	password, err := readBootstrapPassword(cfg, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	policy, err := pwhash.LoadPasswordPolicy(context.Background(), pool)
	if err != nil {
		return fmt.Errorf("load password policy: %w", err)
	}
	policy.DisallowEmail = cfg.email
	if err := validate.ValidatePassword(string(password), policy); err != nil {
		return err
	}
	sharedconfig.InitCryptoProfile(cryptokey.ParseCryptoProfile(os.Getenv("CRYPTO_PROFILE")))
	hash, err := pwhash.HashPasswordWithProfile(string(password))
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	var raw json.RawMessage
	if err := pool.QueryRow(context.Background(), `SELECT ensure_default_admin($1, $2)`, cfg.email, hash).Scan(&raw); err != nil {
		return fmt.Errorf("bootstrap administrator: %w", err)
	}
	var result bootstrapAdminResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode bootstrap result: %w", err)
	}
	if !result.AdminCreated {
		return fmt.Errorf("bootstrap refused: %s", result.Reason)
	}
	fmt.Printf("First administrator created: %s (user %d)\n", result.Email, result.UserID)
	return nil
}
