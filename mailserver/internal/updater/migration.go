package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"setjoin.com/shared/release"
)

var (
	ErrMigrationRange    = errors.New("migration schema range differs")
	ErrMigrationUnsafe   = errors.New("migration SQL is unsafe")
	ErrMigrationEvidence = errors.New("migration evidence differs")
)

type MigrationEvidence struct {
	Version        int
	ReleaseID      string
	ManifestDigest string
	MigrationID    string
	SHA256         string
}

// MigrationConnection is deliberately narrower than pgx. Apply must execute
// SQL and evidence insertion in one database transaction.
type MigrationConnection interface {
	CurrentVersion(context.Context) (int, error)
	Evidence(context.Context, int) (*MigrationEvidence, error)
	Apply(context.Context, release.Migration, string, MigrationEvidence) error
}

type MigrationRunner struct {
	DB MigrationConnection
}

// ApplyRelease applies a signed expand-only chain one file per transaction.
// A lost commit response is reconciled by the exact checksum evidence.
func (runner MigrationRunner) ApplyRelease(ctx context.Context, releaseDir, manifestDigest string, manifest *release.Manifest, expectedFrom, expectedTo int) error {
	if runner.DB == nil || manifest == nil || !journalDigestExpr.MatchString(manifestDigest) {
		return fmt.Errorf("migration runner dependencies or manifest digest are invalid")
	}
	if expectedFrom != manifest.SchemaFrom || expectedTo != manifest.SchemaTo || expectedTo < expectedFrom {
		return fmt.Errorf("%w: command %d->%d manifest %d->%d", ErrMigrationRange, expectedFrom, expectedTo, manifest.SchemaFrom, manifest.SchemaTo)
	}
	current, err := runner.DB.CurrentVersion(ctx)
	if err != nil {
		return err
	}
	if current < expectedFrom || current > expectedTo {
		return fmt.Errorf("%w: database=%d expected=%d..%d", ErrMigrationRange, current, expectedFrom, expectedTo)
	}
	for _, migration := range manifest.Migrations {
		if current >= migration.ToSchema {
			if err := runner.verifyEvidence(ctx, migration, manifest, manifestDigest); err != nil {
				return err
			}
			continue
		}
		if current != migration.FromSchema {
			return fmt.Errorf("%w: database=%d next=%d->%d", ErrMigrationRange, current, migration.FromSchema, migration.ToSchema)
		}
		path := filepath.Join(releaseDir, "share", "migrations", migration.ID+".sql")
		raw, err := readMigrationFile(path, migration)
		if err != nil {
			return err
		}
		if err := validateTransactionalSQL(string(raw)); err != nil {
			return fmt.Errorf("migration %q: %w", migration.ID, err)
		}
		evidence := MigrationEvidence{Version: migration.ToSchema, ReleaseID: manifest.ReleaseID,
			ManifestDigest: manifestDigest, MigrationID: migration.ID, SHA256: migration.SHA256}
		applyErr := runner.DB.Apply(ctx, migration, string(raw), evidence)
		if applyErr != nil {
			// Commit acknowledgement may be lost. Only exact durable version plus
			// signed checksum evidence converts that uncertainty into success.
			observed, readErr := runner.DB.CurrentVersion(ctx)
			if readErr != nil || observed != migration.ToSchema {
				return applyErr
			}
			if verifyErr := runner.verifyEvidence(ctx, migration, manifest, manifestDigest); verifyErr != nil {
				return errors.Join(applyErr, verifyErr)
			}
		}
		current = migration.ToSchema
	}
	if current != expectedTo {
		return fmt.Errorf("%w: migration chain ended at %d, want %d", ErrMigrationRange, current, expectedTo)
	}
	return nil
}

func (runner MigrationRunner) verifyEvidence(ctx context.Context, migration release.Migration, manifest *release.Manifest, manifestDigest string) error {
	evidence, err := runner.DB.Evidence(ctx, migration.ToSchema)
	if err != nil {
		return err
	}
	if evidence == nil || evidence.Version != migration.ToSchema || evidence.ReleaseID != manifest.ReleaseID ||
		evidence.ManifestDigest != manifestDigest || evidence.MigrationID != migration.ID || evidence.SHA256 != migration.SHA256 {
		return fmt.Errorf("%w for schema %d", ErrMigrationEvidence, migration.ToSchema)
	}
	return nil
}

func readMigrationFile(path string, migration release.Migration) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > 16<<20 {
		return nil, fmt.Errorf("%w: migration %q is not a bounded private regular file", ErrMigrationUnsafe, migration.ID)
	}
	// path is built from the verified release root and signed migration ID, then
	// lstat-checked above as a bounded private regular file.
	//nolint:gosec // G304: no request-controlled filesystem path is read.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != migration.SHA256 {
		return nil, fmt.Errorf("%w: migration %q digest differs", ErrMigrationEvidence, migration.ID)
	}
	return raw, nil
}

// validateTransactionalSQL is a conservative lexer: transaction-control and
// PostgreSQL nontransactional concurrent DDL are rejected outside comments,
// strings, quoted identifiers, and dollar-quoted bodies.
func validateTransactionalSQL(sql string) error {
	words, err := sqlWords(sql)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMigrationUnsafe, err)
	}
	for index, word := range words {
		switch word {
		case "begin", "commit", "rollback", "savepoint", "vacuum", "cluster", "reindex":
			return fmt.Errorf("%w: statement %q is updater-owned or nontransactional", ErrMigrationUnsafe, word)
		case "concurrently":
			return fmt.Errorf("%w: concurrent DDL is not supported", ErrMigrationUnsafe)
		case "program":
			return fmt.Errorf("%w: server-side program execution is not supported", ErrMigrationUnsafe)
		case "alter":
			if index+1 < len(words) && words[index+1] == "system" {
				return fmt.Errorf("%w: ALTER SYSTEM is not supported", ErrMigrationUnsafe)
			}
			if index+1 < len(words) && words[index+1] == "type" {
				limit := min(len(words), index+7)
				for _, candidate := range words[index+2 : limit] {
					if candidate == "add" {
						return fmt.Errorf("%w: ALTER TYPE ADD is refused in v1", ErrMigrationUnsafe)
					}
				}
			}
		case "create", "drop":
			if index+1 < len(words) && (words[index+1] == "database" || words[index+1] == "tablespace" || words[index+1] == "subscription") {
				return fmt.Errorf("%w: %s %s is not supported", ErrMigrationUnsafe, word, words[index+1])
			}
		case "call":
			return fmt.Errorf("%w: CALL is not supported in v1 migrations", ErrMigrationUnsafe)
		}
	}
	return nil
}

func sqlWords(input string) ([]string, error) {
	var words []string
	for index := 0; index < len(input); {
		switch {
		case unicode.IsSpace(rune(input[index])):
			index++
		case strings.HasPrefix(input[index:], "--"):
			if next := strings.IndexByte(input[index+2:], '\n'); next >= 0 {
				index += next + 3
			} else {
				index = len(input)
			}
		case strings.HasPrefix(input[index:], "/*"):
			end := strings.Index(input[index+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated block comment")
			}
			index += end + 4
		case input[index] == '\'' || input[index] == '"':
			quote := input[index]
			index++
			closed := false
			for index < len(input) {
				if input[index] == quote {
					if index+1 < len(input) && input[index+1] == quote {
						index += 2
						continue
					}
					index++
					closed = true
					break
				}
				index++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted value")
			}
		case input[index] == '$':
			end := strings.IndexByte(input[index+1:], '$')
			if end < 0 {
				index++
				continue
			}
			tagEnd := index + end + 2
			tag := input[index:tagEnd]
			if strings.IndexFunc(tag[1:len(tag)-1], func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') }) >= 0 {
				index++
				continue
			}
			closeAt := strings.Index(input[tagEnd:], tag)
			if closeAt < 0 {
				return nil, fmt.Errorf("unterminated dollar quote")
			}
			index = tagEnd + closeAt + len(tag)
		case unicode.IsLetter(rune(input[index])) || input[index] == '_':
			start := index
			for index < len(input) && (unicode.IsLetter(rune(input[index])) || unicode.IsDigit(rune(input[index])) || input[index] == '_') {
				index++
			}
			words = append(words, strings.ToLower(input[start:index]))
		default:
			index++
		}
	}
	return words, nil
}
