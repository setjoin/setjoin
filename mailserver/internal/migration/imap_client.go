package migration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	imap "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"setjoin.com/shared/ssrf"
)

// SourceItemType classifies a single item pulled from a migration source.
type SourceItemType string

// SourceChange describes the source-side mutation represented by a source
// object. Connectors must not encode deletes or moves as an empty payload.
type SourceChange string

const (
	ItemMail     SourceItemType = "mail"
	ItemCalendar SourceItemType = "calendar"
	ItemContact  SourceItemType = "contact"
	SourceUpsert SourceChange   = "upsert"
	SourceMove   SourceChange   = "move"
	SourceDelete SourceChange   = "delete"
)

// SourceObject is the typed identity/version envelope shared by every
// connector. ObjectID is immutable within one source instance; Version changes
// whenever applying the same object again could change the target projection.
type SourceObject struct {
	Type              SourceItemType
	Change            SourceChange
	SourceObjectID    string
	SourceVersion     string
	SourceFolderID    string
	RawMIME           []byte
	RawICS            string
	RawVCF            string
	FolderPath        []string
	Tags              []string
	Flags             []string
	SourceUID         uint32
	SourceUIDValidity uint32
}

// SourceItem remains an alias for one compatibility release while connector
// fixtures move to the explicit SourceObject terminology.
type SourceItem = SourceObject

// Connector abstracts a migration data source that can be tested and iterated.
type Connector interface {
	TestConnection(ctx context.Context) error
	FetchItems(ctx context.Context, progress func(done, total int)) (<-chan SourceItem, <-chan error)
	FetchItemsCursor(ctx context.Context, cursor map[string]int) (<-chan SourceItem, <-chan error)
}

// DeltaLinker is an optional interface implemented by connectors that
// support incremental sync via delta links (e.g. M365 @odata.deltaLink).
type DeltaLinker interface {
	SetDeltaLinks(links map[string]string)
	GetDeltaLinks() map[string]string
}

// SourceIdentity binds one migration job to exactly one remote mailbox before
// any content is applied.
type SourceIdentity struct {
	SourceType       string
	MailboxKey       string
	SelectorDigest   string
	SourceGeneration int64
}

type SourceIdentityProvider interface {
	ResolveSourceIdentity(ctx context.Context) (SourceIdentity, error)
}

// IMAPConnector fetches mail from a remote IMAP server.
type IMAPConnector struct {
	config                  IMAPConfig
	dialContext             func(context.Context, string, string) (net.Conn, error) // tests only; production leaves nil
	tlsConfig               func(string) *tls.Config                                // tests only; production leaves nil
	checkpointUIDValidities map[string]uint32
	checkpointMu            sync.Mutex
	completedCheckpoints    map[string]IMAPSourceCheckpoint
	resumeCursor            map[string]int
}

// ── Post-handshake admission bounds (er5-s15, sealed anchor imap-migration-
// buffers-attacker-sized-rfc822-messages-without-a-byte-limit) ──
//
// The dial seam sets connect and TLS-handshake deadlines, but every
// post-handshake command round trip (greeting, LOGIN, LIST, SELECT, UID
// FETCH) previously ran WITHOUT any deadline: a hostile source server that
// completes the handshake and then answers nothing pins the migration
// goroutine and its socket indefinitely. runIMAPCommand bounds each round
// trip by imapCommandDeadline (the caller's earlier ctx deadline wins) and
// releases the deadline between commands, so consumer pacing between commands
// (batch emit → persist) is never penalized — only in-command server silence
// is bounded.

const (
	// maxMigrationMessageBytes caps one RFC822 message buffered from the
	// source, aligned with the migration upload bound (maxMigrationUploadBytes,
	// 64 MiB) in internal/user. A hostile or misbehaving source could
	// previously stream an arbitrarily large literal into io.ReadAll; the
	// connector now refuses over-cap messages with an error, failing the
	// folder fetch loudly instead of silently dropping mail.
	maxMigrationMessageBytes = 64 << 20
)

// imapCommandDeadline bounds one post-handshake IMAP command round trip.
// Var (not const) so the deadline tests can shorten it deterministically.
var imapCommandDeadline = 2 * time.Minute

// imapTeardownDeadline bounds the LOGOUT round trip on a healthy session's
// teardown. A session that already FAILED a command is torn down with
// Terminate (close now) instead — a LOGOUT against a hostile or dead server
// must never park the connector on a deadline-free connection.
var imapTeardownDeadline = 5 * time.Second

// runIMAPCommand runs fn (one command round trip against the source server)
// under a connection deadline: the sooner of imapCommandDeadline and the
// caller's remaining ctx deadline. The deadline is CLEARED on return so the
// idle gap between commands (consumer-paced batch persistence) is not held to
// the command budget.
func runIMAPCommand(ctx context.Context, conn net.Conn, fn func() error) error {
	return runIMAPCommandBounded(ctx, conn, imapCommandDeadline, fn)
}

// runIMAPCommandBounded is runIMAPCommand with an explicit deadline bound.
func runIMAPCommandBounded(ctx context.Context, conn net.Conn, bound time.Duration, fn func() error) error {
	if dl, ok := ctx.Deadline(); ok {
		if until := time.Until(dl); until < bound {
			bound = until
		}
	}
	if bound <= 0 {
		bound = time.Millisecond // already-expired ctx: fail the command now
	}
	_ = conn.SetDeadline(time.Now().Add(bound))
	err := fn()
	_ = conn.SetDeadline(time.Time{})
	return err
}

// teardownIMAPSession ends a connector session safely: a session whose last
// command FAILED (or never completed) gets Terminate — an unconditional
// transport close that also unblocks any goroutine parked on the deadline-free
// connection — while a healthy session gets a LOGOUT bounded by
// imapTeardownDeadline. ok is true only when the session's work completed.
func teardownIMAPSession(ctx context.Context, conn net.Conn, cl *client.Client, ok bool) {
	if !ok {
		_ = cl.Terminate()
		return
	}
	_ = runIMAPCommandBounded(ctx, conn, imapTeardownDeadline, func() error {
		return cl.Logout()
	})
	_ = cl.Terminate()
}

// IMAPSourceCheckpoint binds a high-water UID to the UIDVALIDITY generation
// observed by the same SELECT. A UID without its generation is never resumable.
type IMAPSourceCheckpoint struct {
	UID         uint32
	UIDValidity uint32
}

// NewIMAPConnector returns a connector for the given IMAP configuration.
func NewIMAPConnector(config IMAPConfig) *IMAPConnector {
	return &IMAPConnector{config: config}
}

func (c *IMAPConnector) RestoreSourceState(state SourceResumeState) error {
	c.resumeCursor = make(map[string]int, len(state.LegacyUIDs))
	for scope, uid := range state.LegacyUIDs {
		c.resumeCursor[scope] = uid
	}
	validities := make(map[string]uint32)
	for _, candidate := range state.Durable {
		if candidate.Kind != "imap_uid" {
			return rejectCheckpointKind(candidate, "imap_uid")
		}
		checkpoint, err := decodeIMAPCheckpoint(candidate.Value)
		if err != nil {
			return fmt.Errorf("restore IMAP checkpoint %q: %w", candidate.Scope, err)
		}
		c.resumeCursor[candidate.Scope] = int(checkpoint.UID)
		validities[candidate.Scope] = checkpoint.UIDValidity
	}
	c.SetCheckpointUIDValidities(validities)
	return nil
}

func (c *IMAPConnector) IterateSource(ctx context.Context) *SourceBatchStream {
	return newSourceBatchStream(ctx, func(ctx context.Context, emit sourceBatchEmitter) error {
		return c.iterateIMAPBatches(ctx, c.resumeCursor, emit)
	})
}

func imapBatchSnapshot(folder string, uid, uidValidity uint32) SourceCheckpointSnapshot {
	return SourceCheckpointSnapshot{
		Candidates: []SourceCheckpointCandidate{{
			Scope: folder, LegacyScope: folder, Kind: "imap_uid",
			Value: encodeIMAPCheckpoint(imapCheckpoint{UID: uid, UIDValidity: uidValidity}),
		}},
		LegacyPatch: map[string]any{"cursor_uids": map[string]int{folder: int(uid)}},
	}
}

func (c *IMAPConnector) SetCheckpointUIDValidities(validities map[string]uint32) {
	c.checkpointUIDValidities = make(map[string]uint32, len(validities))
	for folder, validity := range validities {
		c.checkpointUIDValidities[folder] = validity
	}
}

func (c *IMAPConnector) CompletedCheckpoints() map[string]IMAPSourceCheckpoint {
	c.checkpointMu.Lock()
	defer c.checkpointMu.Unlock()
	out := make(map[string]IMAPSourceCheckpoint, len(c.completedCheckpoints))
	for folder, checkpoint := range c.completedCheckpoints {
		out[folder] = checkpoint
	}
	return out
}

func (c *IMAPConnector) ResolveSourceIdentity(context.Context) (SourceIdentity, error) {
	selector := strings.ToLower(strings.TrimSpace(c.config.Host)) + "\x00" + strings.TrimSpace(c.config.Credentials.Username)
	if strings.Trim(selector, "\x00") == "" {
		return SourceIdentity{}, fmt.Errorf("IMAP source mailbox selector is required")
	}
	digest := hashSourcePayload([]byte("imap\x00" + selector))
	return SourceIdentity{SourceType: "imap", MailboxKey: "imap:" + digest, SelectorDigest: digest, SourceGeneration: 1}, nil
}

// TestConnection dials the IMAP server, logs in, and lists the root to verify
// that the connection and credentials are valid.  Does not persist anything.
func (c *IMAPConnector) TestConnection(ctx context.Context) error {
	cl, conn, err := c.dialConn(ctx)
	if err != nil {
		return err
	}
	stopInterrupt := interruptIMAPClientOnCancel(ctx, cl)
	defer stopInterrupt()
	ok := false
	defer func() { teardownIMAPSession(ctx, conn, cl, ok) }()
	if err := runIMAPCommand(ctx, conn, func() error {
		return cl.Login(c.config.Credentials.Username, c.config.Credentials.Password)
	}); err != nil {
		return fmt.Errorf("imap login: %w", err)
	}
	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- cl.List("", "*", mailboxes)
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("imap list: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	ok = true
	return nil
}

// FetchItems connects to the IMAP server, recursively lists all folders,
// and fetches every RFC822 message.  Items are sent on the returned channel.
func (c *IMAPConnector) FetchItems(ctx context.Context, progress func(done, total int)) (<-chan SourceItem, <-chan error) {
	return c.FetchItemsCursor(ctx, nil)
}

// FetchItemsCursor is like FetchItems but starts from a cursor map
// (folder name → last imported UID). Entries with UID ≤ cursor are skipped.
func (c *IMAPConnector) FetchItemsCursor(ctx context.Context, cursor map[string]int) (<-chan SourceItem, <-chan error) {
	items := make(chan SourceItem, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(items)
		defer close(errs)

		cl, conn, err := c.dialConn(ctx)
		if err != nil {
			errs <- err
			return
		}
		// The legacy channel API is consumer-paced, so in-command server
		// silence here is bounded by ctx cancellation + this interruptor
		// (Terminate on ctx.Done), not by a per-command deadline that could
		// abort a legitimately slow consumer mid-stream.
		stopInterrupt := interruptIMAPClientOnCancel(ctx, cl)
		defer stopInterrupt()
		ok := false
		defer func() { teardownIMAPSession(ctx, conn, cl, ok) }()

		if err := runIMAPCommand(ctx, conn, func() error {
			return cl.Login(c.config.Credentials.Username, c.config.Credentials.Password)
		}); err != nil {
			errs <- fmt.Errorf("imap login: %w", err)
			return
		}

		folders, err := c.listFolders(ctx, cl, conn)
		if err != nil {
			errs <- err
			return
		}

		for _, f := range folders {
			var lastUID uint32
			if last, ok := cursor[f.name]; ok && last > 0 && uint64(last) <= math.MaxUint32 {
				lastUID = uint32(last)
			}
			if err := c.fetchFolder(ctx, conn, cl, f, items, lastUID); err != nil {
				errs <- err
				return
			}
			select {
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			default:
			}
		}
		ok = true
	}()

	return items, errs
}

func (c *IMAPConnector) iterateIMAPBatches(ctx context.Context, cursor map[string]int, emit sourceBatchEmitter) error {
	cl, conn, err := c.dialConn(ctx)
	if err != nil {
		return err
	}
	stopInterrupt := interruptIMAPClientOnCancel(ctx, cl)
	defer stopInterrupt()
	ok := false
	defer func() { teardownIMAPSession(ctx, conn, cl, ok) }()
	if err := runIMAPCommand(ctx, conn, func() error {
		return cl.Login(c.config.Credentials.Username, c.config.Credentials.Password)
	}); err != nil {
		return fmt.Errorf("imap login: %w", err)
	}
	folders, err := c.listFolders(ctx, cl, conn)
	if err != nil {
		return err
	}
	for _, folder := range folders {
		lastUID := uint32(0)
		if last, ok := cursor[folder.name]; ok && last > 0 && uint64(last) <= math.MaxUint32 {
			lastUID = uint32(last)
		}
		if err := c.fetchFolderBatches(ctx, conn, cl, folder, lastUID, emit); err != nil {
			return err
		}
	}
	ok = true
	return nil
}

func interruptIMAPClientOnCancel(ctx context.Context, cl *client.Client) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			_ = cl.Terminate()
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// fetchFolderBatches closes bounded UID ranges in ascending order. Advancing
// across an empty range is safe: SELECT's UIDNEXT is a high-water snapshot and
// an expunged UID cannot later reappear in the same UIDVALIDITY generation.
// fetchFolderBatches closes bounded UID ranges in ascending order. Advancing
// across an empty range is safe: SELECT's UIDNEXT is a high-water snapshot and
// an expunged UID cannot later reappear in the same UIDVALIDITY generation.
// Every command round trip (SELECT, each bounded-range UID FETCH) runs under
// the per-command deadline; the batch drain inside a fetch is
// consumer-independent (bounded by sourceBatchSize), so the deadline bounds
// server silence without ever racing the downstream consumer, which is only
// engaged by emit AFTER the command completes.
func (c *IMAPConnector) fetchFolderBatches(ctx context.Context, conn net.Conn, cl *client.Client, folder folderInfo, lastUID uint32, emit sourceBatchEmitter) error {
	var status *imap.MailboxStatus
	if err := runIMAPCommand(ctx, conn, func() error {
		var err error
		status, err = cl.Select(folder.name, true)
		return err
	}); err != nil {
		return fmt.Errorf("imap select %q: %w", folder.name, err)
	}
	startUID := uint32(1)
	if lastUID > 0 && c.checkpointUIDValidities[folder.name] == status.UidValidity {
		startUID = lastUID + 1
	}
	if status.UidNext <= startUID {
		return nil
	}
	highWater := status.UidNext - 1
	for rangeStart := startUID; rangeStart <= highWater; {
		rangeEnd := rangeStart + sourceBatchSize - 1
		if rangeEnd < rangeStart || rangeEnd > highWater {
			rangeEnd = highWater
		}
		seqSet := new(imap.SeqSet)
		seqSet.AddRange(rangeStart, rangeEnd)
		messages := make(chan *imap.Message, sourceBatchSize)
		fetchDone := make(chan error, 1)
		batchItems := make([]SourceItem, 0, sourceBatchSize)
		// The whole UID FETCH exchange — issue, message drain, completion —
		// runs under one per-command deadline. The drain is
		// consumer-independent work inside the bounded fn; emit (which can
		// take consumer time) runs only after the deadline is released. An
		// over-cap message is recorded and the drain CONTINUES to channel
		// close, so the command always runs to its tagged completion and no
		// response goroutine is orphaned holding a grant on the deadline-free
		// connection.
		fetchErr := runIMAPCommand(ctx, conn, func() error {
			go func() {
				fetchDone <- cl.UidFetch(seqSet, []imap.FetchItem{imap.FetchRFC822, imap.FetchFlags}, messages)
			}()
			var firstErr error
			for msg := range messages {
				if firstErr != nil {
					continue // discard the rest; the over-cap verdict is final
				}
				if msg == nil || msg.Uid < rangeStart || msg.Uid > rangeEnd {
					continue
				}
				raw, err := rfc822Bytes(msg)
				if err != nil {
					firstErr = err
					continue
				}
				if raw == nil {
					continue
				}
				batchItems = append(batchItems, SourceItem{
					Type: ItemMail, Change: SourceUpsert,
					SourceObjectID: fmt.Sprintf("imap:%s:%d:%d", folder.name, status.UidValidity, msg.Uid),
					SourceVersion:  hashSourcePayload(raw), SourceFolderID: folder.name,
					RawMIME: raw, FolderPath: folder.path, Tags: folder.tags, Flags: msg.Flags,
					SourceUID: msg.Uid, SourceUIDValidity: status.UidValidity,
				})
			}
			if firstErr != nil {
				return firstErr
			}
			return <-fetchDone
		})
		if fetchErr != nil {
			return fetchErr
		}
		sort.Slice(batchItems, func(i, j int) bool { return batchItems[i].SourceUID < batchItems[j].SourceUID })
		if err := emit(SourceBatch{Items: batchItems, Candidate: imapBatchSnapshot(folder.name, rangeEnd, status.UidValidity)}); err != nil {
			return err
		}
		if rangeEnd == highWater {
			break
		}
		rangeStart = rangeEnd + 1
	}
	return nil
}

// ---------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------

type folderInfo struct {
	name string
	path []string
	tags []string
}

// dial dials the configured IMAP source under the SSRF private-address policy.
// The two-value form for callers (admin_api) that need only the client.
func (c *IMAPConnector) dial(ctx context.Context) (*client.Client, error) {
	cl, _, err := c.dialConn(ctx)
	return cl, err
}

// dialClientBounded runs makeClient (client.New) under a wall-clock bound.
// go-imap's greeting exchange runs BEFORE the caller can arm Client.Timeout,
// and its internal command waiters park on the response channel ignoring any
// conn deadline until the reader goroutine exits — so the bound must CLOSE
// the connection on overrun: the reader dies, the client's loggedOut channel
// closes, and the parked greet waiters return errClosed promptly.
func dialClientBounded(conn net.Conn, bound time.Duration, makeClient func() (*client.Client, error)) (*client.Client, error) {
	if bound <= 0 {
		bound = time.Millisecond
	}
	type outcome struct {
		cl  *client.Client
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		cl, err := makeClient()
		ch <- outcome{cl, err}
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case oc := <-ch:
		return oc.cl, oc.err
	case <-timer.C:
		_ = conn.Close() // break the greet read; parked waiters unblock
		oc := <-ch       // the close surfaces the failure promptly
		return oc.cl, oc.err
	}
}

// dialConn dials the configured IMAP source under the SSRF private-address
// policy and returns the client plus the RAW connection. Post-handshake
// bounding is two-layered: Client.Timeout (go-imap's own per-command deadline
// — its execute() CLEARS any externally-set conn deadline when Timeout==0, so
// a bare conn deadline would be defeated on every command) plus
// runIMAPCommand's explicit conn-deadline bound around each round trip. With
// Timeout armed, the response reader also treats imapCommandDeadline of
// complete server silence as a dead session: a hostile or stalled source
// fails the migration job (resumable from its checkpoint) instead of pinning
// the goroutine and socket forever.
func (c *IMAPConnector) dialConn(ctx context.Context) (*client.Client, net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	policy, err := ssrf.CompilePrivatePolicy(c.config.PrivateHosts, c.config.PrivateCIDRs)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid IMAP source policy: %w", err)
	}
	dialContext := c.dialContext
	if dialContext == nil {
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return ssrf.DialContextWithPrivatePolicy(ctx, network, address, policy)
		}
	}
	conn, err := dialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("IMAP destination is not allowed: %w", err)
	}
	bound := imapCommandDeadline
	if dl, ok := ctx.Deadline(); ok {
		if until := time.Until(dl); until < bound {
			bound = until
		}
	}
	tlsConfig := &tls.Config{ServerName: c.config.Host, MinVersion: tls.VersionTLS12}
	if c.tlsConfig != nil {
		tlsConfig = c.tlsConfig(c.config.Host)
	}
	armTimeout := func(cl *client.Client) *client.Client {
		cl.Timeout = imapCommandDeadline
		return cl
	}
	switch c.config.TLSMode {
	case "tls":
		tlsConn := tls.Client(conn, tlsConfig)
		if deadline, ok := ctx.Deadline(); ok {
			_ = tlsConn.SetDeadline(deadline)
		} else {
			_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("IMAP TLS handshake: %w", err)
		}
		// The greeting exchange runs under the handshake deadline window and
		// the dial watchdog; Client.Timeout takes over for every command
		// after this point.
		cl, err := dialClientBounded(conn, bound, func() (*client.Client, error) {
			return client.New(tlsConn)
		})
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		_ = tlsConn.SetDeadline(time.Time{})
		return armTimeout(cl), conn, nil
	case "starttls":
		cl, err := dialClientBounded(conn, bound, func() (*client.Client, error) {
			return client.New(conn)
		})
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		armTimeout(cl)
		if err := runIMAPCommand(ctx, conn, func() error {
			return cl.StartTLS(tlsConfig)
		}); err != nil {
			_ = cl.Terminate()
			return nil, nil, fmt.Errorf("STARTTLS failed: %w", err)
		}
		return cl, conn, nil
	case "none":
		cl, err := dialClientBounded(conn, bound, func() (*client.Client, error) {
			return client.New(conn)
		})
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		return armTimeout(cl), conn, nil
	default:
		_ = conn.Close()
		return nil, nil, fmt.Errorf("unsupported IMAP TLS mode %q", c.config.TLSMode)
	}
}

// listFolders lists every selectable folder. The LIST round trip — issue,
// channel drain, and completion — runs under the per-command deadline: a
// source that accepts LOGIN and then goes silent on the first command fails
// the folder walk instead of pinning it.
func (c *IMAPConnector) listFolders(ctx context.Context, cl *client.Client, conn net.Conn) ([]folderInfo, error) {
	mailboxes := make(chan *imap.MailboxInfo, 50)
	done := make(chan error, 1)

	var all []*imap.MailboxInfo
	err := runIMAPCommand(ctx, conn, func() error {
		go func() {
			done <- cl.List("", "*", mailboxes)
		}()
		// Drain inside the bounded fn so List can always deliver; a stall
		// anywhere in the exchange breaks on the conn deadline.
		for mbox := range mailboxes {
			all = append(all, mbox)
		}
		return <-done
	})
	if err != nil {
		return nil, fmt.Errorf("imap list: %w", err)
	}

	var folders []folderInfo
	for _, mbox := range all {
		if hasAttr(mbox.Attributes, "\\Noselect") {
			continue
		}
		folders = append(folders, folderInfo{
			name: mbox.Name,
			path: c.folderPath(mbox),
			tags: c.folderTags(mbox),
		})
	}
	return folders, nil
}

func (c *IMAPConnector) folderPath(mbox *imap.MailboxInfo) []string {
	delim := mbox.Delimiter
	if delim == "" {
		delim = "/"
	}
	parts := strings.Split(mbox.Name, delim)
	nonEmpty := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return nonEmpty
}

// folderTags maps IMAP special-use attributes and names to mailserver tags.
func (c *IMAPConnector) folderTags(mbox *imap.MailboxInfo) []string {
	attrs := mbox.Attributes
	for _, a := range attrs {
		switch strings.ToLower(a) {
		case "\\sent":
			return []string{"Sent"}
		case "\\drafts":
			return []string{"Drafts"}
		case "\\trash":
			return []string{"Trash"}
		case "\\junk", "\\spam":
			return []string{"Spam"}
		case "\\archive":
			return []string{"Archive"}
		}
	}
	lower := strings.ToLower(mbox.Name)
	switch {
	case lower == "inbox":
		return []string{"Inbox"}
	case lower == "sent" || strings.HasSuffix(lower, ".sent") || strings.HasSuffix(lower, "/sent"):
		return []string{"Sent"}
	case lower == "drafts" || strings.HasSuffix(lower, ".drafts") || strings.HasSuffix(lower, "/drafts"):
		return []string{"Drafts"}
	case lower == "trash" || lower == "deleted items" || strings.HasSuffix(lower, ".trash") || strings.HasSuffix(lower, "/trash"):
		return []string{"Trash"}
	case lower == "junk" || lower == "spam" || lower == "junk e-mail" || strings.HasSuffix(lower, ".junk") || strings.HasSuffix(lower, "/spam"):
		return []string{"Spam"}
	case lower == "archive" || strings.HasSuffix(lower, ".archive") || strings.HasSuffix(lower, "/archive"):
		return []string{"Archive"}
	}

	// 3. Multi-language folder name -> system tag
	if systemTag, ok := folderNameToSystemTag[mbox.Name]; ok {
		return []string{systemTag}
	}

	// 4. Custom folder - use leaf name as user tag
	delim := mbox.Delimiter
	if delim == "" {
		delim = "/"
	}
	parts := strings.Split(mbox.Name, delim)
	leaf := parts[len(parts)-1]
	if leaf == "" && len(parts) > 1 {
		leaf = parts[len(parts)-2]
	}
	if leaf != "" {
		return []string{leaf}
	}
	return nil
}

func (c *IMAPConnector) fetchFolder(ctx context.Context, conn net.Conn, cl *client.Client, f folderInfo, items chan<- SourceItem, lastUID uint32) error {
	var status *imap.MailboxStatus
	if err := runIMAPCommand(ctx, conn, func() error {
		var err error
		status, err = cl.Select(f.name, true)
		return err
	}); err != nil {
		return fmt.Errorf("imap select %q: %w", f.name, err)
	}
	startUID := uint32(1)
	if lastUID > 0 && c.checkpointUIDValidities[f.name] == status.UidValidity {
		startUID = lastUID + 1
	} else {
		lastUID = 0
	}

	if status.Messages == 0 || startUID > status.UidNext {
		c.recordCompletedCheckpoint(f.name, lastUID, status.UidValidity)
		return nil
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddRange(1, status.Messages)

	messages := make(chan *imap.Message, 50)
	fetchDone := make(chan error, 1)
	go func() {
		fetchDone <- cl.UidFetch(seqSet, []imap.FetchItem{imap.FetchRFC822, imap.FetchFlags}, messages)
	}()

	for msg := range messages {
		if msg == nil {
			continue
		}
		// Skip messages with UID ≤ cursor position
		if startUID > 1 && msg.Uid < startUID {
			continue
		}
		if msg.Uid > lastUID {
			lastUID = msg.Uid
		}
		raw, err := rfc822Bytes(msg)
		if err != nil {
			return err
		}
		if raw == nil {
			continue
		}
		select {
		case items <- SourceItem{
			Type:              ItemMail,
			Change:            SourceUpsert,
			SourceObjectID:    fmt.Sprintf("imap:%s:%d:%d", f.name, status.UidValidity, msg.Uid),
			SourceVersion:     hashSourcePayload(raw),
			SourceFolderID:    f.name,
			RawMIME:           raw,
			FolderPath:        f.path,
			Tags:              f.tags,
			Flags:             msg.Flags,
			SourceUID:         msg.Uid,
			SourceUIDValidity: status.UidValidity,
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := <-fetchDone; err != nil {
		return err
	}
	c.recordCompletedCheckpoint(f.name, lastUID, status.UidValidity)
	return nil
}

func (c *IMAPConnector) recordCompletedCheckpoint(folder string, uid, uidValidity uint32) {
	c.checkpointMu.Lock()
	defer c.checkpointMu.Unlock()
	if c.completedCheckpoints == nil {
		c.completedCheckpoints = make(map[string]IMAPSourceCheckpoint)
	}
	c.completedCheckpoints[folder] = IMAPSourceCheckpoint{UID: uid, UIDValidity: uidValidity}
}

func hashSourcePayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// rfc822Bytes extracts the full RFC822 message body from a go-imap Message.
// go-imap stores RFC822 bodies in the Body map with a parsed BodySectionName
// key (not in the Items map), and the literal value is a *bytes.Buffer.
//
// The read is BOUNDED at maxMigrationMessageBytes: a source declaring an
// oversized literal is refused with an error (failing the folder fetch
// loudly) instead of buffering attacker-sized bytes into memory. The
// LimitReader caps the buffered bytes at cap+1 before the verdict.
func rfc822Bytes(msg *imap.Message) ([]byte, error) {
	readBounded := func(r io.Reader) ([]byte, error) {
		data, err := io.ReadAll(io.LimitReader(r, maxMigrationMessageBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxMigrationMessageBytes {
			return nil, fmt.Errorf("RFC822 message exceeds the %d MiB migration cap", maxMigrationMessageBytes>>20)
		}
		return data, nil
	}
	if lit, ok := msg.Items[imap.FetchRFC822]; ok && lit != nil {
		if l, ok := lit.(imap.Literal); ok {
			return readBounded(l)
		}
	}
	// Fallback: go-imap parses RFC822 as BODY[] and stores in msg.Body
	for _, literal := range msg.Body {
		if literal != nil {
			return readBounded(literal)
		}
	}
	return nil, nil
}

func hasAttr(attrs []string, needle string) bool {
	for _, a := range attrs {
		if strings.EqualFold(a, needle) {
			return true
		}
	}
	return false
}
