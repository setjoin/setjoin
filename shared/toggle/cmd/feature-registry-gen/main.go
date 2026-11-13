// Command feature-registry-gen freezes and verifies the feature-toggle
// registry projection consumed by PostgreSQL. Historical migration input is
// immutable: normal development writes require the next migration version.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/toggle"
)

const initialVersion = "V183"

// featureKeyPattern constrains registry keys to plain (dot-separated) lower-
// case identifiers: no quotes, backslashes, whitespace, or unicode. Validated
// before any SQL emission so the literal escaper below only ever sees values
// it can render safely (GEN-SQL-LITERAL-ESCAPE fail-fast gate).
const featureKeyPattern = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`

var featureKeyRE = regexp.MustCompile(featureKeyPattern)

type providerProjection struct {
	Provider   pwhash.AuthProvider `json:"provider"`
	FeatureKey string              `json:"featureKey"`
}

type snapshot struct {
	Version        string               `json:"version"`
	RegistryDigest string               `json:"registryDigest"`
	Definitions    []toggle.Definition  `json:"definitions"`
	AuthProviders  []providerProjection `json:"authProviders"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fail(err.Error())
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("feature-registry-gen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "verify generated outputs")
	write := flags.Bool("write", false, "write the next versioned projection")
	bootstrap := flags.Bool("bootstrap-v183", false, "one-time creation of the frozen V183 artifacts")
	printSQL := flags.Bool("print-sql", false, "print the current classifier projection")
	migration := flags.String("migration", "", "migration version, for example V184")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || boolCount(*check, *write, *bootstrap, *printSQL) != 1 {
		return errors.New("usage: feature-registry-gen (--check | --write --migration V184 | --bootstrap-v183 | --print-sql)")
	}

	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	if *check {
		if *migration != "" {
			return errors.New("--check and --migration are mutually exclusive")
		}
		if err := checkOutputs(root); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "feature_registry_projection_ok")
		return err
	}
	if *printSQL {
		if *migration != "" {
			return errors.New("--print-sql does not accept --migration")
		}
		sql, err := currentSQL()
		if err != nil {
			return err
		}
		_, err = stdout.Write(sql)
		return err
	}
	if *bootstrap {
		if *migration != "" {
			return errors.New("--bootstrap-v183 does not accept --migration")
		}
		return writeFrozen(root)
	}
	if *migration == "" || *migration == initialVersion {
		return errors.New("--write requires the next unused migration (for example --migration V184); V183 is immutable")
	}
	return writeNext(root, *migration)
}

func boolCount(values ...bool) int {
	n := 0
	for _, value := range values {
		if value {
			n++
		}
	}
	return n
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root containing go.work not found")
		}
		dir = parent
	}
}

func currentSnapshot(version string) (snapshot, error) {
	providers := pwhash.AuthProviders()
	projection := make([]providerProjection, 0, len(providers))
	for _, provider := range providers {
		key, ok := pwhash.AuthLogFeatureKey(provider)
		if !ok {
			return snapshot{}, fmt.Errorf("provider %q has no feature key", provider)
		}
		projection = append(projection, providerProjection{Provider: provider, FeatureKey: key})
	}
	return snapshot{
		Version:        version,
		RegistryDigest: toggle.RegistryDigest(),
		Definitions:    toggle.Definitions(),
		AuthProviders:  projection,
	}, nil
}

func marshalSnapshot(version string) ([]byte, error) {
	s, err := currentSnapshot(version)
	if err != nil {
		return nil, err
	}
	payload, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

// sqlSingleQuotedLiteral renders s as a PostgreSQL single-quoted string
// literal under standard_conforming_strings=on semantics: the only sequence
// requiring escape is a single quote, which is doubled. Replaces the old
// strconv.Quote + global double-quote replacement, which emitted Go escape
// sequences (\\t, \\x2A, …) verbatim into the SQL literal for any key
// containing them — silently corrupting the classifier projection instead of
// failing. Keys are grammar-validated first (featureKeyPattern), so the
// doubling here is belt-and-braces for the emission path.
func sqlSingleQuotedLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func currentSQL() ([]byte, error) {
	definitions := toggle.Definitions()
	var out strings.Builder
	out.WriteString("-- Code generated by feature-registry-gen; DO NOT EDIT.\n")
	out.WriteString("-- registry-digest: " + toggle.RegistryDigest() + "\n")
	out.WriteString("CREATE OR REPLACE FUNCTION public.feature_registry_classify(p_key text)\n")
	out.WriteString("RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$\n")
	out.WriteString("  SELECT CASE WHEN p_key = ANY (ARRAY[\n")
	for i, definition := range definitions {
		key := string(definition.Key)
		if !featureKeyRE.MatchString(key) {
			return nil, fmt.Errorf("E_FEATURE_KEY_INVALID: registry key %q does not match %s — fix the key in shared/toggle, never the projection", key, featureKeyPattern)
		}
		out.WriteString("    ")
		out.WriteString(sqlSingleQuotedLiteral(key))
		if i+1 != len(definitions) {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("  ]::text[]) THEN 'known' ELSE 'unknown' END\n")
	out.WriteString("$$;\n")
	return []byte(out.String()), nil
}

func paths(root, version string) (snapshotPath, sqlPath string) {
	lower := strings.ToLower(version)
	return filepath.Join(root, "shared", "toggle", "testdata", "registry-"+lower+".json"),
		filepath.Join(root, "mailserver", "sql", "generated", "feature_toggle_registry_current.sql")
}

func writeFrozen(root string) error {
	snapshotPath, sqlPath := paths(root, initialVersion)
	checksumPath := snapshotPath + ".sha256"
	for _, path := range []string{snapshotPath, sqlPath, checksumPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite frozen artifact %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	migrationPath := filepath.Join(root, "mailserver", "sql", "dbschema", "V183__feature_toggle_registry_authority.sql")
	migrationBody, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("read migration before freeze: %w", err)
	}
	payload, err := marshalSnapshot(initialVersion)
	if err != nil {
		return err
	}
	projection, err := currentSQL()
	if err != nil {
		return err
	}
	if err := os.WriteFile(snapshotPath, payload, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(sqlPath, projection, 0o644); err != nil {
		return err
	}
	checksum := checksumDocument(
		checksumEntry(migrationPath, migrationBody),
		checksumEntry(snapshotPath, payload),
	)
	if err := os.WriteFile(checksumPath, checksum, 0o644); err != nil {
		return err
	}
	fmt.Printf("froze %s registry digest %s\n", initialVersion, toggle.RegistryDigest())
	return nil
}

func checkOutputs(root string) error {
	versions, err := registryVersions(root)
	if err != nil {
		return err
	}
	if len(versions) == 0 || versions[0] != initialVersion {
		return errors.New("frozen V183 registry snapshot is missing")
	}
	for _, version := range versions {
		snapshotPath, _ := paths(root, version)
		migrationPath := registryMigrationPath(root, version)
		if err := verifyChecksums(migrationPath, snapshotPath, snapshotPath+".sha256"); err != nil {
			return fmt.Errorf("immutable %s checksum: %w", version, err)
		}
	}
	currentVersion := versions[len(versions)-1]
	snapshotPath, sqlPath := paths(root, currentVersion)
	wantSnapshot, err := marshalSnapshot(currentVersion)
	if err != nil {
		return err
	}
	currentProjection, err := currentSQL()
	if err != nil {
		return err
	}
	if err := sameFile(snapshotPath, wantSnapshot); err != nil {
		return driftError(err, snapshotPath)
	}
	if err := sameFile(sqlPath, currentProjection); err != nil {
		return driftError(err, sqlPath)
	}
	migrationPath := registryMigrationPath(root, currentVersion)
	migrationBody, err := os.ReadFile(migrationPath)
	if err != nil {
		return err
	}
	if !bytes.Contains(migrationBody, []byte(toggle.RegistryDigest())) {
		return driftError(errors.New("installed migration digest differs from compiled digest"), migrationPath)
	}
	for _, definition := range toggle.Definitions() {
		if !bytes.Contains(migrationBody, []byte("'"+string(definition.Key)+"'")) {
			return driftError(fmt.Errorf("key %q absent from installed classifier", definition.Key), migrationPath)
		}
	}
	return nil
}

func sameFile(path string, want []byte) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("content is stale")
	}
	return nil
}

func writeNext(root, version string) error {
	if len(version) != 4 || version[0] != 'V' {
		return fmt.Errorf("migration must match VNNN: %q", version)
	}
	if _, err := strconv.Atoi(version[1:]); err != nil {
		return fmt.Errorf("migration must match VNNN: %q", version)
	}
	wantVersion, err := nextMigrationVersion(root)
	if err != nil {
		return err
	}
	if version != wantVersion {
		return fmt.Errorf("migration must be the next unused schema version %s, got %s", wantVersion, version)
	}
	snapshotPath, _ := paths(root, version)
	migrationPath := filepath.Join(root, "mailserver", "sql", "dbschema", version+"__feature_toggle_registry_projection.sql")
	checksumPath := snapshotPath + ".sha256"
	for _, path := range []string{snapshotPath, migrationPath, checksumPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	payload, err := marshalSnapshot(version)
	if err != nil {
		return err
	}
	projectionBody, err := currentSQL()
	if err != nil {
		return err
	}
	if err := os.WriteFile(snapshotPath, payload, 0o644); err != nil {
		return err
	}
	projection := append([]byte{}, projectionBody...)
	projection = append(projection, migrationFooter(version)...)
	if err := os.WriteFile(migrationPath, projection, 0o644); err != nil {
		return err
	}
	checksum := checksumDocument(
		checksumEntry(migrationPath, projection),
		checksumEntry(snapshotPath, payload),
	)
	if err := os.WriteFile(checksumPath, checksum, 0o644); err != nil {
		return err
	}
	_, currentPath := paths(root, initialVersion)
	if err := os.WriteFile(currentPath, projectionBody, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s; review %s and rerun --check\n", version, migrationPath)
	return nil
}

func migrationFooter(version string) []byte {
	const footer = `
UPDATE public.feature_toggle_registry_state SET registry_digest='{{REGISTRY_DIGEST}}', updated_at=now() WHERE singleton;
INSERT INTO public.schema_migrations (version, applied_at) VALUES ({{SCHEMA_VERSION}}, now()) ON CONFLICT (version) DO NOTHING;
`
	return []byte(strings.NewReplacer(
		"{{REGISTRY_DIGEST}}", toggle.RegistryDigest(),
		"{{SCHEMA_VERSION}}", version[1:],
	).Replace(footer))
}

type checksumLine struct {
	name string
	hash string
}

func checksumEntry(path string, body []byte) checksumLine {
	sum := sha256.Sum256(body)
	return checksumLine{name: filepath.Base(path), hash: hex.EncodeToString(sum[:])}
}

func checksumDocument(entries ...checksumLine) []byte {
	var result strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&result, "%s  %s\n", entry.hash, entry.name)
	}
	return []byte(result.String())
}

func verifyChecksums(migrationPath, snapshotPath, checksumPath string) error {
	checksum, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, path := range []string{migrationPath, snapshotPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entry := checksumEntry(path, body)
		want[entry.name] = entry.hash
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(checksum)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[1]] {
			return errors.New("checksum document must contain unique hash and filename pairs")
		}
		seen[fields[1]] = true
		if expected, ok := want[fields[1]]; !ok || fields[0] != expected {
			return fmt.Errorf("bytes changed for %s", fields[1])
		}
	}
	if len(seen) != len(want) {
		return errors.New("checksum document does not cover migration and snapshot")
	}
	return nil
}

func registryVersions(root string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(root, "shared", "toggle", "testdata", "registry-v[0-9][0-9][0-9].json"))
	if err != nil {
		return nil, err
	}
	versions := make([]string, 0, len(matches))
	for _, match := range matches {
		name := filepath.Base(match)
		versions = append(versions, strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(name, "registry-"), ".json")))
	}
	sort.Strings(versions)
	return versions, nil
}

func registryMigrationPath(root, version string) string {
	name := version + "__feature_toggle_registry_projection.sql"
	if version == initialVersion {
		name = version + "__feature_toggle_registry_authority.sql"
	}
	return filepath.Join(root, "mailserver", "sql", "dbschema", name)
}

func nextMigrationVersion(root string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(root, "mailserver", "sql", "dbschema", "V[0-9][0-9][0-9]__*.sql"))
	if err != nil {
		return "", err
	}
	maximum := 0
	for _, match := range matches {
		version, err := strconv.Atoi(filepath.Base(match)[1:4])
		if err != nil {
			return "", fmt.Errorf("invalid migration filename %s", match)
		}
		if version > maximum {
			maximum = version
		}
	}
	if maximum == 0 || maximum >= 999 {
		return "", fmt.Errorf("cannot derive next migration after V%03d", maximum)
	}
	return fmt.Sprintf("V%03d", maximum+1), nil
}

func driftError(err error, path string) error {
	keys := toggle.Keys()
	providers := pwhash.AuthProviders()
	sort.Strings(keys)
	return fmt.Errorf("E_FEATURE_REGISTRY_DRIFT: %v; authority=shared/toggle/toggle.go providers=shared/pwhash/auth_log.go output=%s compiled_digest=%s keys=%d providers=%d; next: derive the next migration version and run go run ./shared/toggle/cmd/feature-registry-gen --write --migration VNNN", err, path, toggle.RegistryDigest(), len(keys), len(providers))
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
