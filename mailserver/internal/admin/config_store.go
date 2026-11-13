package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigValue is a single system_config value plus its encryption marker. The
// `Encrypted` bool is written to the authoritative `encrypted` column (not just
// inferred from the `_enc` key suffix), so the config-backup export/import
// contract round-trips the secret marker for every writer that routes through
// the store.
type ConfigValue struct {
	Value     json.RawMessage
	Encrypted bool
}

// StoredConfig is a row read back from system_config via the store.
type StoredConfig struct {
	Key       string
	Value     json.RawMessage
	Encrypted bool
}

// ConfigHook is a side effect fired after a system_config key under a registered
// prefix is written. It receives the pre-write value (old, zero if the key was
// absent) and the just-written value (new). Hooks run synchronously inside the
// store after the write commits; a hook must not block (e.g. trigger a sync via
// a goroutine).
type ConfigHook func(ctx context.Context, key string, old, new ConfigValue)

// SideEffectRegistry maps a system_config key prefix to the hooks that fire when
// a key under that prefix is written through the ConfigStore. Every hook whose
// prefix matches the written key fires (registration order). The zero value is a
// usable empty registry.
type SideEffectRegistry struct {
	hooks []prefixHook
}

type prefixHook struct {
	prefix string
	hook   ConfigHook
}

// Register adds a hook fired for every written key with the given prefix.
func (r *SideEffectRegistry) Register(prefix string, hook ConfigHook) {
	if r == nil || hook == nil {
		return
	}
	r.hooks = append(r.hooks, prefixHook{prefix: prefix, hook: hook})
}

// fire invokes every registered hook whose prefix matches the key.
func (r *SideEffectRegistry) fire(ctx context.Context, key string, old, new ConfigValue) {
	if r == nil {
		return
	}
	for _, h := range r.hooks {
		if strings.HasPrefix(key, h.prefix) {
			h.hook(ctx, key, old, new)
		}
	}
}

// ConfigStore centralizes system_config reads/writes for the admin handlers
// (AD/LDAP/TLS sync config and any other prefix-scoped config surface). It is
// the single writer that persists the authoritative `encrypted` column and the
// single seam that fires side-effect hooks (e.g. trigger a directory SyncNow on
// an ldap_sync_* / ad_sync_* change). It replaces the scattered
// batchUpsertSystemConfig that omitted the encrypted column.
type ConfigStore struct {
	pool     *pgxpool.Pool
	registry *SideEffectRegistry
	secrets  configSecretCodec
}

type configSecretCodec interface {
	Encrypt(sourceKey string, plaintext json.RawMessage) (json.RawMessage, error)
	Decrypt(sourceKey string, envelope json.RawMessage) (json.RawMessage, error)
}

// NewConfigStore creates a config store over pool. registry and secrets may be
// nil. A store without a secret codec may read/write non-secret values but
// fails closed when asked to persist or decrypt secret material.
func NewConfigStore(pool *pgxpool.Pool, registry *SideEffectRegistry, secrets ...*ConfigSecretCodec) *ConfigStore {
	var codec configSecretCodec
	if len(secrets) > 0 && secrets[0] != nil {
		codec = secrets[0]
	}
	return &ConfigStore{pool: pool, registry: registry, secrets: codec}
}

// GetByPrefix returns every system_config row whose key starts with prefix.
func (s *ConfigStore) GetByPrefix(ctx context.Context, prefix string) ([]StoredConfig, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, value, encrypted FROM system_config WHERE key LIKE $1 ORDER BY key`,
		prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredConfig
	for rows.Next() {
		var sc StoredConfig
		var v []byte
		if err := rows.Scan(&sc.Key, &v, &sc.Encrypted); err != nil {
			return nil, err
		}
		sc.Value = append(json.RawMessage(nil), v...)
		out = append(out, sc)
	}
	return out, rows.Err()
}

// GetDecryptedByPrefix returns runtime-ready config. Secret rows are decrypted
// only through the configured codec; legacy plaintext, malformed envelopes,
// missing versions, wrong keys, and AAD mismatches all fail closed.
func (s *ConfigStore) GetDecryptedByPrefix(ctx context.Context, prefix string) ([]StoredConfig, error) {
	rows, err := s.GetByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if !rows[i].Encrypted && !isSecretConfigKey(rows[i].Key) {
			continue
		}
		if s.secrets == nil {
			return nil, fmt.Errorf("decrypt config secret %q: codec is not configured", rows[i].Key)
		}
		if !isConfigSecretEnvelope(rows[i].Value) {
			return nil, fmt.Errorf("decrypt config secret %q: legacy plaintext requires startup migration", rows[i].Key)
		}
		plaintext, err := s.secrets.Decrypt(rows[i].Key, rows[i].Value)
		if err != nil {
			return nil, err
		}
		rows[i].Value = plaintext
	}
	return rows, nil
}

// GetKey returns the value for a single key. ok is false (no error) when the key
// is absent.
func (s *ConfigStore) GetKey(ctx context.Context, key string) (ConfigValue, bool, error) {
	var v []byte
	var enc bool
	err := s.pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = $1`, key).Scan(&v, &enc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConfigValue{}, false, nil
		}
		return ConfigValue{}, false, err
	}
	return ConfigValue{Value: append(json.RawMessage(nil), v...), Encrypted: enc}, true, nil
}

// SetKey writes a single key, persisting the authoritative `encrypted` column,
// then fires any matching side-effect hook with the pre/post values.
func (s *ConfigStore) SetKey(ctx context.Context, key string, val ConfigValue, desc string) error {
	return s.BatchSet(ctx, desc, map[string]ConfigValue{key: val})
}

// BatchSet upserts a set of keys in one batch, persisting the authoritative
// `encrypted` column for each, then fires matching side-effect hooks (pre-write
// old value → just-written new value) for every key. The pre-write values are
// read first so a hook can compare old vs new.
func (s *ConfigStore) BatchSet(ctx context.Context, desc string, kv map[string]ConfigValue) error {
	if len(kv) == 0 {
		return nil
	}

	prepared := make(map[string]ConfigValue, len(kv))
	for key, val := range kv {
		if val.Encrypted || isSecretConfigKey(key) {
			val.Encrypted = true
			if isRedactedConfigSentinel(val.Value) {
				if _, ok, err := s.GetKey(ctx, key); err != nil {
					return err
				} else if !ok {
					return fmt.Errorf("cannot preserve absent config secret %q", key)
				}
				continue
			}
			if s.secrets == nil {
				return fmt.Errorf("encrypt config secret %q: codec is not configured", key)
			}
			encrypted, err := s.secrets.Encrypt(key, val.Value)
			if err != nil {
				return err
			}
			val.Value = encrypted
		}
		prepared[key] = val
	}
	if len(prepared) == 0 {
		return nil
	}

	// Snapshot pre-write values for the hooks (best-effort: an absent key yields
	// the zero ConfigValue). Only needed when hooks are registered.
	old := map[string]ConfigValue{}
	if s.registry != nil && len(s.registry.hooks) > 0 {
		for k := range prepared {
			if cur, ok, err := s.GetKey(ctx, k); err == nil && ok {
				old[k] = cur
			}
		}
	}

	batch := &pgx.Batch{}
	for k, v := range prepared {
		batch.Queue(
			`INSERT INTO system_config (key, value, encrypted, description, updated_at)
			 VALUES ($1, $2, $3, $4, now())
			 ON CONFLICT (key) DO UPDATE
			   SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted, updated_at = now()`,
			k, v.Value, v.Encrypted, desc)
	}
	br := s.pool.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}

	if s.registry != nil {
		for k, v := range prepared {
			s.registry.fire(ctx, k, old[k], v)
		}
	}
	return nil
}

// EnsureSecretEncryption validates every existing secret envelope and upgrades
// legacy plaintext rows under the supplied prefixes in one transaction. It is a
// startup gate: callers must not construct directory workers until it succeeds.
func (s *ConfigStore) EnsureSecretEncryption(ctx context.Context, prefixes ...string) (int, error) {
	if s.secrets == nil {
		return 0, errors.New("config secret codec is not configured")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rows, err := tx.Query(ctx,
		`SELECT key, value, encrypted
		   FROM system_config
		  WHERE encrypted OR right(key, 4) = '_enc'
		  ORDER BY key
		  FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	var candidates []StoredConfig
	for rows.Next() {
		var row StoredConfig
		var value []byte
		if err := rows.Scan(&row.Key, &value, &row.Encrypted); err != nil {
			rows.Close()
			return 0, err
		}
		if hasAnyConfigPrefix(row.Key, prefixes) {
			row.Value = append(json.RawMessage(nil), value...)
			candidates = append(candidates, row)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	var validationErrs []error
	for _, row := range candidates {
		if !isConfigSecretEnvelope(row.Value) {
			continue
		}
		if _, err := s.secrets.Decrypt(row.Key, row.Value); err != nil {
			validationErrs = append(validationErrs, fmt.Errorf("%s: %w", row.Key, err))
		}
	}
	if len(validationErrs) > 0 {
		return 0, fmt.Errorf(
			"validate %d encrypted config secret(s): %w; verify the configured active/retiring keys and restore identity.deployment_id with the ciphertext",
			len(validationErrs),
			errors.Join(validationErrs...),
		)
	}

	upgraded := 0
	for _, row := range candidates {
		if isConfigSecretEnvelope(row.Value) {
			if !row.Encrypted {
				if _, err := tx.Exec(ctx,
					`UPDATE system_config SET encrypted = true, updated_at = now() WHERE key = $1`,
					row.Key,
				); err != nil {
					return 0, err
				}
			}
			continue
		}
		encrypted, err := s.secrets.Encrypt(row.Key, row.Value)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE system_config
			    SET value = $2, encrypted = true, updated_at = now()
			  WHERE key = $1`,
			row.Key, encrypted,
		); err != nil {
			return 0, err
		}
		upgraded++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return upgraded, nil
}

func hasAnyConfigPrefix(key string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// EnsureNamedSecretEncryption upgrades legacy plaintext rows for the named
// secret config keys (namedSecretConfigKeys — e.g. assist.api_key, which
// carries no `_enc` suffix so EnsureSecretEncryption's suffix/prefix candidate
// set never selected it). Envelopes are authenticated and their encrypted
// flag repaired; legacy plaintext is encrypted in place — the same upgrade
// contract EnsureSecretEncryption applies to the connector prefixes. It is a
// startup gate: a failing key aborts the whole upgrade so the server never
// runs with a half-migrated secret.
func (s *ConfigStore) EnsureNamedSecretEncryption(ctx context.Context) (int, error) {
	if s.secrets == nil {
		return 0, errors.New("config secret codec is not configured")
	}
	named := namedSecretConfigKeys()
	keys := make([]string, 0, len(named))
	for key := range named {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	rows, err := tx.Query(ctx,
		`SELECT key, value, encrypted
		   FROM system_config
		  WHERE key = ANY($1)
		  ORDER BY key
		  FOR UPDATE`, keys)
	if err != nil {
		return 0, err
	}
	var candidates []StoredConfig
	for rows.Next() {
		var row StoredConfig
		var value []byte
		if err := rows.Scan(&row.Key, &value, &row.Encrypted); err != nil {
			rows.Close()
			return 0, err
		}
		row.Value = append(json.RawMessage(nil), value...)
		candidates = append(candidates, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	// Authenticate every existing envelope BEFORE touching anything.
	var validationErrs []error
	for _, row := range candidates {
		if !isConfigSecretEnvelope(row.Value) {
			continue
		}
		if _, err := s.secrets.Decrypt(row.Key, row.Value); err != nil {
			validationErrs = append(validationErrs, fmt.Errorf("%s: %w", row.Key, err))
		}
	}
	if len(validationErrs) > 0 {
		return 0, fmt.Errorf(
			"validate %d encrypted config secret(s): %w; verify the configured active/retiring keys and restore identity.deployment_id with the ciphertext",
			len(validationErrs),
			errors.Join(validationErrs...),
		)
	}

	upgraded := 0
	for _, row := range candidates {
		if isConfigSecretEnvelope(row.Value) {
			if !row.Encrypted {
				if _, err := tx.Exec(ctx,
					`UPDATE system_config SET encrypted = true, updated_at = now() WHERE key = $1`,
					row.Key,
				); err != nil {
					return 0, err
				}
			}
			continue
		}
		encrypted, err := s.secrets.Encrypt(row.Key, row.Value)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE system_config
			    SET value = $2, encrypted = true, updated_at = now()
			  WHERE key = $1`,
			row.Key, encrypted,
		); err != nil {
			return 0, err
		}
		upgraded++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return upgraded, nil
}

// configValuesFromRaw converts a decoded JSON object (the on-wire shape the
// AD/LDAP SetConfig handlers receive) into a ConfigValue map, marking secret
// keys (the `_enc` convention) as encrypted so the authoritative `encrypted`
// column is written. A marshal failure on any value aborts the whole batch.
func configValuesFromRaw(raw map[string]interface{}) (map[string]ConfigValue, error) {
	out := make(map[string]ConfigValue, len(raw))
	for k, v := range raw {
		jsonVal, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = ConfigValue{Value: jsonVal, Encrypted: isSecretConfigKey(k)}
	}
	return out, nil
}

func validatePrefixedStringConfig(raw map[string]interface{}, prefix string) error {
	if len(raw) > 64 {
		return errors.New("too many config keys")
	}
	for key, value := range raw {
		if !strings.HasPrefix(key, prefix) || len(key) > 128 || strings.ContainsRune(key, '\x00') {
			return fmt.Errorf("config key %q is outside the %s namespace", key, prefix)
		}
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("config value %q must be a string", key)
		}
		if len(text) > 64<<10 || strings.ContainsRune(text, '\x00') {
			return fmt.Errorf("config value %q is invalid", key)
		}
	}
	return nil
}
