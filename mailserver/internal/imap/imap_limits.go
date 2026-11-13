package imap

import (
	"bufio"
	"errors"
	"strings"
	"time"
)

const (
	// maxIMAPLineBytes caps a single command/continuation line. IMAP keeps bulk
	// data in literals (size-checked separately); command lines are small, so a
	// 64 KiB ceiling is generous while preventing a client from exhausting memory
	// by sending an endless line with no CRLF. RFC 9051 sets no line limit, but a
	// cap is standard practice (cf. Dovecot's imap_max_line_length).
	maxIMAPLineBytes = 64 * 1024

	// imapReadTimeout bounds how long the command loop blocks waiting for the next
	// line, defeating slowloris-style holds. RFC 9051 §5.4 sets the autologout
	// timer minimum at 30 minutes, which also accommodates a client in IDLE.
	imapReadTimeout = 30 * time.Minute
)

// errIMAPLineTooLong is returned by readLineLimited when a line exceeds the cap.
// It is a package-level sentinel so callers can compare with == (no errors import).
var errIMAPLineTooLong = errors.New("imap: command line exceeds limit")

// readLineLimited reads one '\n'-terminated line, returning errIMAPLineTooLong if
// it would grow past maxIMAPLineBytes. The returned string keeps the trailing
// newline (callers TrimSpace), matching bufio.Reader.ReadString semantics.
func readLineLimited(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		b, err := r.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
		if sb.Len() >= maxIMAPLineBytes {
			return "", errIMAPLineTooLong
		}
	}
}

// readCommandLine refreshes the per-command read deadline (slowloris guard) and
// reads one length-capped line (memory-exhaustion guard). Used by the command
// loops; IDLE clears the deadline so a long idle is not disconnected.
func (c *connState) readCommandLine() (string, error) {
	if c.conn != nil {
		_ = c.conn.SetReadDeadline(time.Now().Add(imapReadTimeout))
	}
	return readLineLimited(c.reader)
}

// clearReadDeadline removes any pending read deadline so a long-lived IDLE is not
// torn down by the command-loop timeout. The next readCommandLine re-arms it.
func (c *connState) clearReadDeadline() {
	if c.conn != nil {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
}
