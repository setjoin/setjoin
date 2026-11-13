package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
)

// audit.go — compliance export + tamper-evidence check against the server's
// admin_audit_log (routes: GET /admin/audit/csv, GET /admin/audit/verify).
// A compliance cron runs `mailctl audit verify-chain` on a schedule; a
// forensic export runs `mailctl audit export --out <file>`.

func runAudit(c *cmdCtx, action string, args []string) error {
	switch action {
	case "export":
		return auditExportCmd(c, args)
	case "verify-chain":
		return auditVerifyChainCmd(c, args)
	default:
		return fmt.Errorf("unknown audit action: %s (try: export, verify-chain)", action)
	}
}

// auditExportCmd streams the server's CSV audit-log export (GET
// /admin/audit/csv) to stdout, or to --out <file> if given.
func auditExportCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	out := fs.String("out", "", "Write CSV to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var f *os.File
	err := c.client.rawStream("/admin/audit/csv",
		func() (io.Writer, error) {
			if *out == "" {
				return os.Stdout, nil
			}
			var cerr error
			f, cerr = os.Create(*out)
			if cerr != nil {
				return nil, fmt.Errorf("create %s: %w", *out, cerr)
			}
			return f, nil
		},
		func(err error) error { return fmt.Errorf("write: %w", err) },
	)
	if f != nil {
		f.Close()
	}
	if err != nil {
		return err
	}
	if *out != "" {
		fmt.Printf("Audit log exported to %s\n", *out)
	}
	return nil
}

// auditVerifyChainCmd calls GET /admin/audit/verify (verify_audit_chain SQL
// function) to check the SHA-256 checksum chain over admin_audit_log rows.
// Exits non-zero (via the returned error) if any row in range fails
// verification — the tamper-evidence signal a compliance cron watches for.
func auditVerifyChainCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("audit verify-chain", flag.ContinueOnError)
	from := fs.Int64("from", 0, "Start row ID (inclusive; 0 = from the beginning)")
	to := fs.Int64("to", 0, "End row ID (inclusive; 0 = to the end)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := "/admin/audit/verify"
	q := url.Values{}
	if *from != 0 {
		q.Set("from_id", fmt.Sprintf("%d", *from))
	}
	if *to != 0 {
		q.Set("to_id", fmt.Sprintf("%d", *to))
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var result struct {
		Chain []struct {
			ID         int64  `json:"id"`
			Valid      bool   `json:"valid"`
			OccurredAt string `json:"occurredAt"`
			Action     string `json:"action"`
		} `json:"chain"`
	}
	if err := c.client.Do("GET", path, nil, &result); err != nil {
		return err
	}

	var broken []int64
	for _, r := range result.Chain {
		if !r.Valid {
			broken = append(broken, r.ID)
		}
	}

	if c.json {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else if len(broken) == 0 {
		fmt.Printf("Audit chain OK: %d row(s) verified.\n", len(result.Chain))
	} else {
		fmt.Printf("Audit chain BROKEN: %d/%d row(s) failed verification (ids: %v)\n", len(broken), len(result.Chain), broken)
	}

	if len(broken) > 0 {
		return fmt.Errorf("audit chain integrity check failed: %d broken row(s)", len(broken))
	}
	return nil
}
