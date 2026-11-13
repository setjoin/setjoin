package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// backupDBConfig is the resolved configuration for `mailctl backup-db`.
type backupDBConfig struct {
	dsn string
	// dbPassword is the password dsnForChildArgv separated from dsn. It reaches
	// pg_dump via PGPASSWORD in the child environment, never argv.
	dbPassword string
	s3         s3Config
	// dumpHMACKey is the dump-authentication key (0600 file discipline). Every
	// uploaded dump object is sealed under it; restore verifies the sidecar
	// fail-closed before pg_restore may run.
	dumpHMACKey []byte
}

// pgDumpArgs builds the exact argument list for a complete custom-format dump.
// dsn must already be credential-free (dsnForChildArgv): any password travels
// to pg_dump via PGPASSWORD in the child environment, never argv. Ownership and
// ACLs are deliberately retained: reducers and materialized views use
// setjoin_worker ownership as authority, while setjoin_app relies on grants.
// A full-restore target must provision the standard roles before replay.
func pgDumpArgs(dsn, outPath string) []string {
	return []string{
		"--format=custom",
		"--file=" + outPath,
		dsn,
	}
}

func pgRestoreListArgs(dumpPath string) []string { return []string{"--list", dumpPath} }

func validateCustomDump(dumpPath string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("pg_restore", pgRestoreListArgs(dumpPath)...) //nolint:gosec // fixed executable and generated temp path
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := stderr.String()
		if len(message) > 4096 {
			message = message[:4096]
		}
		return fmt.Errorf("pg_restore --list rejected the completed dump: %w: %s", err, message)
	}
	return nil
}

// refuseArgvSecretFlags rejects explicit command-line secret flags. The flags
// stay registered (with placeholder defaults) so misuse gets targeted guidance
// instead of "unknown flag"; environment sources keep working through
// post-parse resolution, and only argv values refuse.
func refuseArgvSecretFlags(fs *flag.FlagSet, names ...string) error {
	for _, name := range names {
		if flagWasSet(fs, name) {
			return fmt.Errorf("--%s must not be passed on the command line (process listings and shell history expose it); pass the matching --%s-file (0600) or set the environment default instead", name, name)
		}
	}
	return nil
}

// loosePasswordAssignment matches a case-insensitive "password" keyword
// assignment with or without whitespace around '='. It is the conservative
// net under the structural parsers: password-shaped text that neither parser
// can attribute to a real credential (a longer keyword, a quoted value, an
// unparseable URL) still counts as embedded, so detection and stripping fail
// closed instead of passing unverifiable conninfo to child argv.
var loosePasswordAssignment = regexp.MustCompile(`(?i)\bpassword[ \t\n\r\v\f]*=`)

// dsnEmbedsCredential reports whether a conninfo string carries an inline
// password, in either URL form (postgres://user:secret@host/db, including a
// ?password= query parameter) or keyword form (... password=secret ...,
// tokenized with real libpq keyword/value rules: whitespace around '=',
// single-quoted values, backslash escapes). Detection routes on the same
// predicate as splitting (splitDSNCredentials) and shares one tokenizer with
// it (scanKeywordConninfo), so detection and stripping agree by construction:
// a spaced pair such as "password = secret" is both detected and stripped,
// and the detector can no longer bless a DSN the stripper never saw.
// Credential-free DSNs (peer auth, .pgpass) stay allowed on the command line.
func dsnEmbedsCredential(dsn string) bool {
	if dsn == "" {
		return false
	}
	if strings.Contains(dsn, "://") {
		return urlConninfoEmbedsCredential(dsn)
	}
	return keywordConninfoEmbedsCredential(dsn)
}

// urlConninfoEmbedsCredential reports whether a URL-form conninfo carries a
// password in the places splitURLDSNCredentials strips: the userinfo or the
// ?password= query parameter (checked structurally, so percent-encoded
// parameter names are caught). Unparseable URLs fall back to the shared
// urlParseErrorEmbedsCredential net, and password-shaped text anywhere in the
// raw bytes still fails closed.
func urlConninfoEmbedsCredential(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil {
		return urlParseErrorEmbedsCredential(dsn)
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return true
		}
	}
	if _, hasQueryPassword := u.Query()["password"]; hasQueryPassword {
		return true
	}
	return loosePasswordAssignment.MatchString(dsn)
}

// urlParseErrorEmbedsCredential is the shared fail-closed fallback for
// URL-form conninfo net/url rejects: a "user:..." segment ahead of the first
// '@' may hide a password that can neither be verified nor stripped. Used by
// both dsnEmbedsCredential and splitURLDSNCredentials so the two cannot
// disagree about unparseable URLs.
func urlParseErrorEmbedsCredential(dsn string) bool {
	return urlUserinfoMayHidePassword(dsn) || loosePasswordAssignment.MatchString(dsn)
}

// keywordConninfoEmbedsCredential reports whether a keyword/value conninfo
// embeds a password under real libpq tokenization. It runs the same scanner
// splitKeywordDSNCredentials strips with, so a password visible to detection
// is exactly a password the stripper removes or refuses as unstrippable. A
// conninfo the tokenizer cannot fully parse, and password-shaped text the
// tokenizer cannot attribute (loosePasswordAssignment — e.g. a quoted value
// containing "password="), still count as embedded.
func keywordConninfoEmbedsCredential(dsn string) bool {
	_, found, _, err := scanKeywordConninfo(dsn)
	if err != nil || found {
		return true
	}
	return loosePasswordAssignment.MatchString(dsn)
}

// refuseArgvDSNCredentials rejects an operator --dsn that embeds a password.
// Even though dsnForChildArgv now strips credentials before pg_dump/pg_restore
// argv, an argv-carried DSN puts the password in THIS process's own command
// line — readable by any local user via process listing and shell history —
// so it is refused outright. The env precedence (resolveOperatorDSN) is the
// non-argv path; dsnForChildArgv strips env-sourced credentials before the
// child runs.
func refuseArgvDSNCredentials(fs *flag.FlagSet, dsn string) error {
	if flagWasSet(fs, "dsn") && dsnEmbedsCredential(dsn) {
		return fmt.Errorf("--dsn with embedded credentials must not be passed on the command line (process listings and shell history expose it); export DB_DIRECT_OWNER_DSN / DB_OWNER_DSN instead")
	}
	return nil
}

// dsnForChildArgv is the single gate between DSN resolution and child-process
// argv: it strips embedded credentials from a resolved operator DSN and returns
// the password separately for PGPASSWORD delivery. Credential-bearing input
// that cannot be reliably stripped is refused, and the stripped result is
// re-checked, so no DSN source — flag, environment, or upstream file resolution
// such as a 0600 .pgpass — can place a password in pg_dump/pg_restore argv.
func dsnForChildArgv(dsn string) (cleanDSN, dbPassword string, err error) {
	cleanDSN, dbPassword, err = splitDSNCredentials(dsn)
	if err != nil {
		return "", "", err
	}
	if dsnEmbedsCredential(cleanDSN) {
		return "", "", fmt.Errorf("resolved DSN still embeds credentials after stripping; refusing to place a password in pg_dump/pg_restore argv (deliver credentials via PGPASSWORD or a 0600 .pgpass instead)")
	}
	return cleanDSN, dbPassword, nil
}

// splitDSNCredentials separates a conninfo string into a credential-free DSN
// that is safe for child-process argv and the embedded password ("" when the
// DSN carries none). URL-form credentials (userinfo or a ?password= query
// parameter) and keyword-form password= pairs are both handled. Routing keys
// off the same "://" predicate dsnEmbedsCredential uses, so detection and
// stripping always examine a DSN with the same grammar. A DSN that embeds
// credentials but cannot be reliably stripped is refused rather than passed
// through.
func splitDSNCredentials(dsn string) (string, string, error) {
	if dsn == "" {
		return "", "", nil
	}
	if strings.Contains(dsn, "://") {
		return splitURLDSNCredentials(dsn)
	}
	return splitKeywordDSNCredentials(dsn)
}

// splitURLDSNCredentials strips the password from a URL-form conninfo,
// accepting it from either the userinfo or the ?password= query parameter.
// Credential-free URLs are returned byte-identical, so no re-encoding can
// drift a peer-auth or .pgpass DSN.
func splitURLDSNCredentials(dsn string) (string, string, error) {
	refuse := func() (string, string, error) {
		return "", "", fmt.Errorf("DSN embeds credentials in a form that cannot be safely stripped; pass a credential-free DSN and deliver the password via PGPASSWORD or a 0600 .pgpass instead")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		// url.Parse rejects some DSNs whose userinfo still hides a password
		// (e.g. invalid percent-escapes). Fail closed on that shape instead of
		// passing an unverifiable conninfo to child argv. The fallback is
		// shared with dsnEmbedsCredential so detection and stripping agree on
		// unparseable URLs.
		if urlParseErrorEmbedsCredential(dsn) {
			return refuse()
		}
		return dsn, "", nil
	}
	password := ""
	if u.User != nil {
		if pw, has := u.User.Password(); has {
			password = pw
		}
	}
	query := u.Query()
	hadQueryPassword := false
	if pws, ok := query["password"]; ok {
		hadQueryPassword = true
		query.Del("password")
		if len(pws) > 1 {
			return "", "", fmt.Errorf("DSN carries multiple ?password= parameters; pass a single credential source")
		}
		if pw := pws[0]; pw != "" {
			if password != "" && pw != password {
				return "", "", fmt.Errorf("DSN carries two different passwords (userinfo and query parameter); pass a single credential source")
			}
			password = pw
		}
	}
	if password == "" && !hadQueryPassword {
		return dsn, "", nil
	}
	clean := *u
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			clean.User = url.User(name)
		} else {
			clean.User = nil
		}
	}
	clean.RawQuery = query.Encode()
	return clean.String(), password, nil
}

// urlUserinfoMayHidePassword is the conservative fallback for DSNs url.Parse
// rejects: a "user:..." segment ahead of the first "@" is treated as a
// possible embedded password that can neither be verified nor stripped.
func urlUserinfoMayHidePassword(dsn string) bool {
	marker := strings.Index(dsn, "://")
	if marker < 0 {
		return false
	}
	rest := dsn[marker+len("://"):]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return false
	}
	return strings.IndexByte(rest[:at], ':') >= 0
}

// splitKeywordDSNCredentials strips password= pairs from a keyword/value
// conninfo ("host=h dbname=db password=pw", including libpq whitespace around
// '=' as in "password = secret") using the same tokenizer detection uses
// (scanKeywordConninfo). Every non-password token is copied through verbatim
// so the stripped DSN stays valid. A conninfo that looks like it embeds a
// password but yields none to the scanner is refused rather than passed
// through.
func splitKeywordDSNCredentials(dsn string) (string, string, error) {
	password, found, kept, err := scanKeywordConninfo(dsn)
	if err != nil {
		return "", "", fmt.Errorf("DSN embeds credentials in a form that cannot be safely stripped: %w", err)
	}
	if found {
		return strings.Join(kept, " "), password, nil
	}
	if keywordConninfoEmbedsCredential(dsn) {
		return "", "", fmt.Errorf("DSN embeds credentials in a form that cannot be safely stripped; pass a credential-free DSN and deliver the password via PGPASSWORD or a 0600 .pgpass instead")
	}
	return dsn, "", nil
}

// scanKeywordConninfo is the single libpq keyword/value tokenizer behind both
// keyword-form detection (keywordConninfoEmbedsCredential) and stripping
// (splitKeywordDSNCredentials), so the two agree by construction. It walks
// keyword=value tokens — whitespace around '=', single-quoted values with
// backslash escapes and doubled quotes, unquoted values running to the next
// whitespace with backslash escapes — and returns the decoded password (""
// when absent), whether a password keyword was found, and the verbatim token
// spans that survive stripping. A string with no '=' is libpq's
// bare-database-name form and cannot carry a keyword password; a malformed
// conninfo returns an error.
func scanKeywordConninfo(dsn string) (string, bool, []string, error) {
	if !strings.Contains(dsn, "=") {
		return "", false, nil, nil
	}
	var kept []string
	password := ""
	found := false
	i := 0
	for i < len(dsn) {
		for i < len(dsn) && isConninfoSpace(dsn[i]) {
			i++
		}
		if i >= len(dsn) {
			break
		}
		start := i
		for i < len(dsn) && dsn[i] != '=' && !isConninfoSpace(dsn[i]) {
			i++
		}
		keyword := dsn[start:i]
		for i < len(dsn) && isConninfoSpace(dsn[i]) {
			i++
		}
		if keyword == "" || i >= len(dsn) || dsn[i] != '=' {
			return "", false, nil, fmt.Errorf("malformed keyword/value conninfo (missing '=' after keyword)")
		}
		i++ // consume '='
		for i < len(dsn) && isConninfoSpace(dsn[i]) {
			i++
		}
		value, next, scanErr := scanConninfoValue(dsn, i)
		if scanErr != nil {
			return "", false, nil, scanErr
		}
		i = next
		if strings.EqualFold(keyword, "password") {
			password = value
			found = true
			continue
		}
		kept = append(kept, dsn[start:next])
	}
	return password, found, kept, nil
}

// scanConninfoValue reads one conninfo value starting at i: either a
// single-quoted string (backslash escapes and a doubled quote for a literal
// quote) or an unquoted run up to the next whitespace (with backslash
// escapes). It returns the decoded value and the index just past the token.
func scanConninfoValue(dsn string, i int) (string, int, error) {
	if i >= len(dsn) {
		return "", i, nil
	}
	if dsn[i] == '\'' {
		i++
		var b strings.Builder
		for i < len(dsn) {
			switch dsn[i] {
			case '\\':
				if i+1 >= len(dsn) {
					return "", i, fmt.Errorf("unterminated backslash escape")
				}
				b.WriteByte(dsn[i+1])
				i += 2
			case '\'':
				if i+1 < len(dsn) && dsn[i+1] == '\'' {
					b.WriteByte('\'')
					i += 2
					continue
				}
				return b.String(), i + 1, nil
			default:
				b.WriteByte(dsn[i])
				i++
			}
		}
		return "", i, fmt.Errorf("unterminated quoted value")
	}
	var b strings.Builder
	for i < len(dsn) {
		c := dsn[i]
		if c == '\\' {
			if i+1 >= len(dsn) {
				return "", i, fmt.Errorf("unterminated backslash escape")
			}
			b.WriteByte(dsn[i+1])
			i += 2
			continue
		}
		if isConninfoSpace(c) {
			break
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i, nil
}

// isConninfoSpace reports whether c separates conninfo tokens (libpq allows
// whitespace around keywords, '=' and values; the set matches C isspace() in
// the "C" locale, which is what libpq uses, so "password\v=" cannot slip past
// the tokenizer).
func isConninfoSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// pgChildEnv builds the environment for a libpq child process (pg_dump,
// pg_restore): the parent environment plus PGPASSWORD when a password was
// separated from the DSN. An empty password inherits the environment
// unchanged, so operators resolving credentials through a 0600 .pgpass or
// their own PGPASSWORD keep working.
func pgChildEnv(parent []string, password string) []string {
	if password == "" {
		return nil
	}
	// os/exec keeps the LAST occurrence of a duplicate key, so the appended
	// PGPASSWORD wins over anything inherited.
	return append(parent, "PGPASSWORD="+password)
}

// ── Dump authentication (occ_f2695a92cddad0cd92e90513 —
// legacy-db-dump-restored-without-authentication) ────────────────────────────
// `mailctl restore --type full` replays the downloaded db-dump.dump with
// pg_restore --clean --if-exists against the owner DSN: an attacker who can
// substitute that object in the backup bucket executes owner-privileged SQL
// on the next disaster-recovery restore. The dump is therefore bound at
// PUBLICATION: runBackupDB seals an HMAC-SHA256 envelope sidecar next to
// every dump object it uploads, and the restore path verifies the sidecar
// FAIL-CLOSED before exec — absent (the s13 lookup-error leg), malformed,
// schema/algorithm mismatched, bound to a different object, wrong-sized,
// digest-mismatched, or HMAC-mismatched bindings all refuse before pg_restore
// runs. Mechanism: the D5 signed-envelope genre (shared/recoveryset
// Seal/Verify) — HMAC-SHA256 over a canonical manifest with constant-time
// compare and a ≥32-byte key. The recoveryset 24h freshness axis is
// deliberately absent: a DR dump must stay restorable for its whole retention
// life. The key rides the existing mailctl operator credential discipline — a
// regular non-symlink 0600 file of ≥32 bytes (readPrivateKeyFile, the
// recovery-set HMAC key contract), never argv.

const (
	// dumpAuthSchema / dumpAuthAlgorithm pin the envelope and MAC forms.
	// Unknown values refuse (fail-closed versioning, the ER3 schema posture).
	dumpAuthSchema        = "setjoin.mailctl.dump-auth/v1"
	dumpAuthAlgorithm     = "hmac-sha256"
	dumpAuthSidecarSuffix = ".hmac"
)

// dumpAuthDigestRe is the canonical lowercase-hex SHA-256 shape every digest
// field must carry.
var dumpAuthDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// dumpAuthEnvelope is the sidecar published next to each dump object. Every
// field except hmacSha256 is inside the MAC: objectKey stops an archival
// copy's sidecar from standing in for the canonical dump, and
// sizeBytes+sha256 stop any substituted or tampered byte from verifying.
type dumpAuthEnvelope struct {
	Schema     string `json:"schema"`
	ObjectKey  string `json:"objectKey"`
	SizeBytes  int64  `json:"sizeBytes"`
	SHA256     string `json:"sha256"`
	Algorithm  string `json:"algorithm"`
	CreatedAt  string `json:"createdAt"`
	HMACSHA256 string `json:"hmacSha256"`
}

// dumpAuthSidecarKey is the object key of the sidecar published next to a
// dump object.
func dumpAuthSidecarKey(objectKey string) string {
	return objectKey + dumpAuthSidecarSuffix
}

// fileDigest streams a local file's lowercase-hex SHA-256 and its size (dumps
// run to multiple GB; never whole-file buffering).
func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path, like every other opener in this module
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("digest %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// dumpAuthMAC computes the envelope's HMAC-SHA256 over its canonical JSON with
// hmacSha256 cleared. json.Marshal of the fixed struct is deterministic
// (declaration order), so verification reproduces the exact sealed payload
// from the decoded fields. Marshal cannot fail for this shape (strings and an
// int64 only — no channels, funcs, or cycles), so the error is discarded.
func dumpAuthMAC(envelope dumpAuthEnvelope, key []byte) (string, error) {
	if len(key) < 32 {
		return "", errors.New("dump authentication HMAC key must be at least 32 bytes")
	}
	envelope.HMACSHA256 = ""
	payload, _ := json.Marshal(envelope) // infallible for this fixed shape
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// sealDumpAuthEnvelope authenticates the dump bytes at path for objectKey,
// returning the sidecar body to publish next to that object.
func sealDumpAuthEnvelope(dumpPath, objectKey string, key []byte, now time.Time) ([]byte, error) {
	digest, size, err := fileDigest(dumpPath)
	if err != nil {
		return nil, err
	}
	envelope := dumpAuthEnvelope{
		Schema:    dumpAuthSchema,
		ObjectKey: objectKey,
		SizeBytes: size,
		SHA256:    digest,
		Algorithm: dumpAuthAlgorithm,
		CreatedAt: now.UTC().Format(time.RFC3339),
	}
	mac, err := dumpAuthMAC(envelope, key)
	if err != nil {
		return nil, err
	}
	envelope.HMACSHA256 = mac
	out, _ := json.MarshalIndent(envelope, "", " ") // infallible for this fixed shape
	return append(out, '\n'), nil
}

// verifyDumpAuthEnvelope verifies a downloaded sidecar against the downloaded
// dump bytes, fail-closed: undecodable, trailing-data, schema/algorithm
// mismatched, foreign-object-bound, malformed, wrong-key, or tampered inputs
// refuse — never proceed.
func verifyDumpAuthEnvelope(dumpPath, objectKey string, key, sidecar []byte) error {
	var envelope dumpAuthEnvelope
	decoder := json.NewDecoder(bytes.NewReader(sidecar))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("dump authentication sidecar is not valid %s JSON: %w", dumpAuthSchema, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("dump authentication sidecar carries trailing data")
	}
	if envelope.Schema != dumpAuthSchema || envelope.Algorithm != dumpAuthAlgorithm {
		return fmt.Errorf("dump authentication sidecar schema/algorithm mismatch: %q/%q", envelope.Schema, envelope.Algorithm)
	}
	if envelope.ObjectKey != objectKey {
		return fmt.Errorf("dump authentication sidecar binds %q, not the requested %q", envelope.ObjectKey, objectKey)
	}
	if envelope.SizeBytes < 0 || !dumpAuthDigestRe.MatchString(envelope.SHA256) || !dumpAuthDigestRe.MatchString(envelope.HMACSHA256) {
		return fmt.Errorf("dump authentication sidecar envelope is malformed")
	}
	if _, err := time.Parse(time.RFC3339, envelope.CreatedAt); err != nil {
		return fmt.Errorf("dump authentication sidecar timestamp is not RFC 3339: %q", envelope.CreatedAt)
	}
	mac, err := dumpAuthMAC(envelope, key)
	if err != nil {
		return err
	}
	// The MAC field's shape was checked above, so the decode is infallible.
	want, _ := hex.DecodeString(envelope.HMACSHA256)
	got, _ := hex.DecodeString(mac)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("dump authentication HMAC mismatch: the sidecar was not sealed under the configured key (wrong key or tampered binding)")
	}
	digest, size, err := fileDigest(dumpPath)
	if err != nil {
		return err
	}
	if size != envelope.SizeBytes || digest != envelope.SHA256 {
		return fmt.Errorf("dump bytes do not match the authenticated publication binding (size/digest mismatch) — the dump was substituted or corrupted after publication")
	}
	return nil
}

// parseBackupDBFlags parses and validates the backup-db flags.
func parseBackupDBFlags(args []string) (backupDBConfig, error) {
	fs := flag.NewFlagSet("backup-db", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "PostgreSQL DSN (defaults to owner-first DB_*_DSN precedence)")
	provider := fs.String("provider", "", "S3 provider (e.g. minio, aws)")
	endpoint := fs.String("endpoint", "", "S3 endpoint (host or https://host)")
	region := fs.String("region", "", "S3 region")
	bucket := fs.String("bucket", "", "Backup bucket name")
	// Secret flags carry PLACEHOLDER defaults: a resolved secret is never
	// stored in the flag, so Go's default usage printer — invoked when an
	// unknown flag fails parsing, before post-parse resolution runs — cannot
	// echo it. The environment is resolved after Parse below. The flags stay
	// registered (pointers deliberately discarded) so an argv value gets
	// targeted refusal guidance rather than "unknown flag".
	fs.String("access-key", "", "S3 access key; refused on the command line (set BACKUP_ACCESS_KEY or pass --access-key-file)")
	fs.String("secret-key", "", "S3 secret key; refused on the command line (set BACKUP_SECRET_KEY or pass --secret-key-file)")
	accessKeyFile := fs.String("access-key-file", os.Getenv("BACKUP_ACCESS_KEY_FILE"), "0600 file containing the S3 access key")
	secretKeyFile := fs.String("secret-key-file", os.Getenv("BACKUP_SECRET_KEY_FILE"), "0600 file containing the S3 secret key")
	dumpHMACKeyFile := fs.String("dump-hmac-key-file", os.Getenv("BACKUP_DUMP_HMAC_KEY_FILE"), "0600 file containing the dump-authentication HMAC key (required: binds every uploaded dump so restore can verify it fail-closed before pg_restore runs)")
	if err := fs.Parse(args); err != nil {
		return backupDBConfig{}, err
	}
	if err := refuseArgvSecretFlags(fs, "access-key", "secret-key"); err != nil {
		return backupDBConfig{}, err
	}
	// Secrets resolve AFTER parsing (never as flag defaults): the argv forms
	// were refused above, so the surviving sources are the environment and the
	// 0600 files below — files win, mirroring the backup create/verify lane.
	accessKeyValue := os.Getenv("BACKUP_ACCESS_KEY")
	secretKeyValue := os.Getenv("BACKUP_SECRET_KEY")

	// Parent-argv hygiene first, then the child-argv gate: whatever survives
	// resolveOperatorDSN (flag or environment) is stripped to a credential-free
	// conninfo with the password returned for PGPASSWORD delivery.
	resolvedDSN := resolveOperatorDSN(*dsn)
	if err := refuseArgvDSNCredentials(fs, resolvedDSN); err != nil {
		return backupDBConfig{}, err
	}
	cleanDSN, dbPassword, err := dsnForChildArgv(resolvedDSN)
	if err != nil {
		return backupDBConfig{}, err
	}

	cfg := backupDBConfig{
		dsn:        cleanDSN,
		dbPassword: dbPassword,
		s3: s3Config{
			Provider:  *provider,
			Endpoint:  *endpoint,
			Region:    *region,
			Bucket:    *bucket,
			AccessKey: accessKeyValue,
			SecretKey: secretKeyValue,
		},
	}
	if cfg.s3.Bucket == "" || (cfg.s3.AccessKey == "" && *accessKeyFile == "") || (cfg.s3.SecretKey == "" && *secretKeyFile == "") {
		return backupDBConfig{}, fmt.Errorf("backup bucket and access/secret credentials (prefer 0600 files) are required")
	}
	// File-backed credentials win over the environment default, mirroring the
	// backup create/verify lane.
	if *accessKeyFile != "" {
		accessKeyValue, err := readPrivateCredentialFile(*accessKeyFile, "backup access key")
		if err != nil {
			return backupDBConfig{}, err
		}
		cfg.s3.AccessKey = accessKeyValue
	}
	if *secretKeyFile != "" {
		secretKeyValue, err := readPrivateCredentialFile(*secretKeyFile, "backup secret key")
		if err != nil {
			return backupDBConfig{}, err
		}
		cfg.s3.SecretKey = secretKeyValue
	}
	if cfg.dsn == "" {
		return backupDBConfig{}, fmt.Errorf("no DSN: pass --dsn or set DB_DIRECT_OWNER_DSN / DB_OWNER_DSN / DB_DIRECT_DSN / DB_DSN")
	}
	// Dump authentication is mandatory at PUBLICATION (occ_f2695a92cddad0cd92e90513):
	// a dump uploaded without its HMAC sidecar would be refused by the restore
	// path (fail-closed), so refuse here with the binding instruction instead.
	if *dumpHMACKeyFile == "" {
		return backupDBConfig{}, fmt.Errorf("dump authentication is mandatory at publication: pass --dump-hmac-key-file (or set BACKUP_DUMP_HMAC_KEY_FILE) so restore can verify the dump fail-closed before pg_restore runs")
	}
	dumpHMACKey, err := readPrivateKeyFile(*dumpHMACKeyFile, "dump authentication HMAC key")
	if err != nil {
		return backupDBConfig{}, err
	}
	cfg.dumpHMACKey = dumpHMACKey
	if err := cfg.s3.validate(); err != nil {
		return backupDBConfig{}, err
	}
	return cfg, nil
}

// runBackupDB handles `mailctl backup-db` (modeLocal). It runs pg_dump to a temp
// file and uploads the result to the backup bucket as db-dump.dump plus a
// timestamped copy. No gateway, no app DB pool — pg_dump talks to PostgreSQL
// directly and minio-go talks to S3 directly.
func runBackupDB(c *cmdCtx, action string, args []string) error {
	// backup-db takes no action verb; the whole arg list is flags. A help arg is
	// handled by the dispatch before we get here.
	allArgs := args
	if action != "" {
		allArgs = append([]string{action}, args...)
	}

	cfg, err := parseBackupDBFlags(allArgs)
	if err != nil {
		return err
	}

	for _, binary := range []string{"pg_dump", "pg_restore"} {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Errorf("%s binary not found in PATH: %w", binary, err)
		}
	}

	tmp, err := os.CreateTemp("", "mailctl-db-dump-*.dump")
	if err != nil {
		return fmt.Errorf("create temp dump file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp dump file: %w", err)
	}
	defer func() { _ = os.Remove(tmpPath) }()

	fmt.Fprintf(os.Stderr, "Running pg_dump (custom format)...\n")
	dumpArgs := pgDumpArgs(cfg.dsn, tmpPath)
	cmd := exec.Command("pg_dump", dumpArgs...) //nolint:gosec // args built from a pure builder
	cmd.Env = pgChildEnv(os.Environ(), cfg.dbPassword)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump failed: %w", err)
	}
	if err := validateCustomDump(tmpPath); err != nil {
		return err
	}

	info, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("stat dump: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("pg_dump produced an empty custom-format dump")
	}
	fmt.Fprintf(os.Stderr, "Dump complete (%d bytes). Uploading to s3://%s ...\n", info.Size(), cfg.s3.Bucket)

	ctx := context.Background()
	// Bind dump authentication at PUBLICATION (occ_f2695a92cddad0cd92e90513):
	// each uploaded dump object carries its own HMAC sidecar binding ITS
	// object key — the canonical and archival dumps are sealed separately
	// (objectKey is inside the MAC, so one sidecar can never stand in for the
	// other). Sidecars upload AFTER their dump: an interrupted publication
	// leaves a sidecar-less dump that the restore path refuses (fail-closed),
	// never an unauthenticated dump that restores.
	canonicalSidecar, err := sealDumpAuthEnvelope(tmpPath, dbDumpObjectKey, cfg.dumpHMACKey, time.Now())
	if err != nil {
		return err
	}
	// Canonical key the restore path reads.
	if err := uploadFile(ctx, cfg.s3, tmpPath, dbDumpObjectKey); err != nil {
		return err
	}
	if err := uploadSidecar(ctx, cfg.s3, canonicalSidecar, dbDumpObjectKey); err != nil {
		return err
	}
	// A timestamped archival copy.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	tsKey := fmt.Sprintf("db-dump-%s.dump", stamp)
	tsSidecar, err := sealDumpAuthEnvelope(tmpPath, tsKey, cfg.dumpHMACKey, time.Now())
	if err != nil {
		return err
	}
	if err := uploadFile(ctx, cfg.s3, tmpPath, tsKey); err != nil {
		return err
	}
	if err := uploadSidecar(ctx, cfg.s3, tsSidecar, tsKey); err != nil {
		return err
	}

	fmt.Printf("Backup uploaded: s3://%s/%s (+%s)\n", cfg.s3.Bucket, dbDumpObjectKey, dumpAuthSidecarKey(dbDumpObjectKey))
	fmt.Printf("Archival copy:   s3://%s/%s (+%s)\n", cfg.s3.Bucket, tsKey, dumpAuthSidecarKey(tsKey))
	return nil
}

// uploadSidecar writes an authentication envelope to a temp file and uploads
// it next to the dump object it binds.
func uploadSidecar(ctx context.Context, s3Cfg s3Config, sidecar []byte, objectKey string) (retErr error) {
	tmp, err := os.CreateTemp("", "mailctl-db-dump-*.hmac")
	if err != nil {
		return fmt.Errorf("create temp sidecar file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(sidecar); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp sidecar file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp sidecar file: %w", err)
	}
	return uploadFile(ctx, s3Cfg, tmpPath, dumpAuthSidecarKey(objectKey))
}
