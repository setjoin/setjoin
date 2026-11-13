// Command gencontract renders the frozen ER3 transition grammar
// (docs/verification/deep-security-remediation-transitions.json) from the
// shared/securityprogram package — the single grammar authority both the Go
// namespace and the ER1 checker consume. Regenerate only together with the
// checker's pinned hash; the freeze test fails on any byte drift.
package main

import (
	"fmt"
	"io"
	"os"

	securityprogram "setjoin.com/shared/securityprogram"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

// run renders the frozen grammar to stdout, returning the process exit code:
// 0 on success, 1 when the grammar cannot be rendered or written. The
// streams are parameters so a test can drive every arm without exiting the
// test process.
func run(stdout, stderr io.Writer) int {
	out, err := securityprogram.ContractJSON()
	if err != nil {
		fmt.Fprintf(stderr, "gencontract: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "gencontract: %v\n", err)
		return 1
	}
	return 0
}
