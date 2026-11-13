package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/ad"
	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/shared/toggle"
)

const identitySourceRuntimePollInterval = 30 * time.Second

type identitySourceRuntimeEntry struct {
	spec   identitysource.Spec
	key    string
	config admin.IdentitySourceRuntimeConfig
}

type identitySourceRuntimeSnapshot struct {
	entries       []identitySourceRuntimeEntry
	invalid       []error
	authoritative bool
	masterEnabled bool
}

type identitySourceRuntimeCatalog interface {
	LoadActive(context.Context) (identitySourceRuntimeSnapshot, error)
}

type databaseIdentitySourceRuntimeCatalog struct {
	pool  *pgxpool.Pool
	codec *admin.ConfigSecretCodec
}

func (c databaseIdentitySourceRuntimeCatalog) LoadActive(
	ctx context.Context,
) (identitySourceRuntimeSnapshot, error) {
	rows, err := c.pool.Query(ctx, `
		WITH gate AS (
			SELECT COALESCE((
				SELECT enabled FROM feature_toggles
				 WHERE key='feature.identity_model_v2'
			),FALSE) AS enabled
		)
		SELECT gate.enabled,s.id,s.source_key,s.kind,s.generation,s.config_envelope
		  FROM gate
		  LEFT JOIN identity_sources s
		    ON gate.enabled
		   AND s.state='active'
		   AND s.kind IN ('ad','ldap')
		 ORDER BY s.id`)
	if err != nil {
		return identitySourceRuntimeSnapshot{}, fmt.Errorf("query active identity sources: %w", err)
	}
	defer rows.Close()

	snapshot := identitySourceRuntimeSnapshot{authoritative: true}
	for rows.Next() {
		var (
			enabled    bool
			id         *int64
			key        *string
			kind       *string
			generation *int64
			envelope   []byte
		)
		if err := rows.Scan(&enabled, &id, &key, &kind, &generation, &envelope); err != nil {
			return identitySourceRuntimeSnapshot{},
				fmt.Errorf("scan active identity source: %w", err)
		}
		snapshot.masterEnabled = enabled
		if id == nil {
			continue
		}
		config, err := admin.DecodeIdentitySourceRuntime(c.codec, *key, *kind, envelope)
		if err != nil {
			snapshot.invalid = append(snapshot.invalid,
				fmt.Errorf("active identity source %q is not runnable: %w", *key, err))
			continue
		}
		snapshot.entries = append(snapshot.entries, identitySourceRuntimeEntry{
			spec:   identitysource.Spec{SourceID: *id, Generation: *generation},
			key:    *key,
			config: config,
		})
	}
	if err := rows.Err(); err != nil {
		return identitySourceRuntimeSnapshot{},
			fmt.Errorf("iterate active identity sources: %w", err)
	}
	return snapshot, nil
}

type identitySourceWorkerBuilder struct {
	pool            *pgxpool.Pool
	store           *identitysource.Store
	logger          *slog.Logger
	adIntervalMin   int
	ldapIntervalMin int
}

type identitySourceRuntimeWorkerBuilder interface {
	Build(identitySourceRuntimeEntry) (identitysource.Runnable, error)
}

func (b identitySourceWorkerBuilder) Build(
	entry identitySourceRuntimeEntry,
) (identitysource.Runnable, error) {
	cfg := entry.config
	switch cfg.Kind {
	case "ad":
		client, err := ad.NewConfiguredClient(ad.ClientConfig{
			Host:             cfg.Host,
			Port:             cfg.Port,
			Transport:        cfg.Transport,
			BaseDN:           cfg.BaseDN,
			BindDN:           cfg.BindDN,
			Password:         cfg.BindPassword(),
			SubjectAttribute: cfg.SubjectAttribute,
			UserFilter:       cfg.UserFilter,
		}, b.logger)
		if err != nil {
			return nil, err
		}
		worker := ad.NewSyncWorker(client, b.pool, b.logger, b.adIntervalMin)
		worker.SetIdentitySource(b.store, entry.key)
		return worker, nil
	case "ldap":
		client, err := ldapsync.NewClientWithTransport(
			cfg.Host,
			cfg.Port,
			cfg.Transport,
			cfg.BindDN,
			cfg.BindPassword(),
			cfg.BaseDN,
		)
		if err != nil {
			return nil, err
		}
		if err := client.SetSubjectAttribute(cfg.SubjectAttribute); err != nil {
			return nil, err
		}
		worker := ldapsync.NewSyncWorker(client, b.pool, b.logger, b.ldapIntervalMin)
		if err := worker.SetFilter(cfg.UserFilter); err != nil {
			return nil, err
		}
		worker.SetIdentitySource(b.store, entry.key)
		return worker, nil
	default:
		return nil, fmt.Errorf("unsupported identity source kind %q", cfg.Kind)
	}
}

// identitySourceRuntimeManager owns the process-local worker generations. The
// database lease still selects the one discovery process across all gateway
// processes. Notifications provide immediate reconciliation and polling closes
// the lost-NOTIFY window after a listener reconnect.
type identitySourceRuntimeManager struct {
	catalog    identitySourceRuntimeCatalog
	supervisor *identitysource.Supervisor
	builder    identitySourceRuntimeWorkerBuilder
	logger     *slog.Logger
	pollEvery  time.Duration
	trigger    chan struct{}
	enabled    func() bool

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func newIdentitySourceRuntimeManager(
	catalog identitySourceRuntimeCatalog,
	builder identitySourceRuntimeWorkerBuilder,
	logger *slog.Logger,
	enabled func() bool,
) *identitySourceRuntimeManager {
	if enabled == nil {
		enabled = func() bool { return false }
	}
	return &identitySourceRuntimeManager{
		catalog:    catalog,
		supervisor: identitysource.NewSupervisor(),
		builder:    builder,
		logger:     logger,
		pollEvery:  identitySourceRuntimePollInterval,
		trigger:    make(chan struct{}, 1),
		enabled:    enabled,
	}
}

func (m *identitySourceRuntimeManager) Start(parent context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return errors.New("identity source runtime manager is already started")
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.done = make(chan struct{})
	m.mu.Unlock()

	if err := m.reconcile(ctx); err != nil {
		cancel()
		m.supervisor.Stop()
		m.mu.Lock()
		m.cancel = nil
		close(m.done)
		m.mu.Unlock()
		return fmt.Errorf("initial identity source reconciliation: %w", err)
	}
	go m.run(ctx)
	return nil
}

func (m *identitySourceRuntimeManager) run(ctx context.Context) {
	defer func() {
		m.mu.Lock()
		if m.done != nil {
			close(m.done)
		}
		m.mu.Unlock()
	}()
	ticker := time.NewTicker(m.pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.trigger:
		case <-ticker.C:
		}
		if err := m.reconcile(ctx); err != nil && ctx.Err() == nil {
			m.logger.Error("identity source runtime reconciliation failed", "error", err)
		}
	}
}

func (m *identitySourceRuntimeManager) reconcile(ctx context.Context) error {
	snapshot, loadErr := m.catalog.LoadActive(ctx)
	if !snapshot.authoritative {
		stopErr := m.supervisor.Reconcile(ctx, nil, func(identitysource.Spec) (identitysource.Runnable, error) {
			return nil, errors.New("identity source worker cannot start without an authoritative catalog")
		})
		return errors.Join(loadErr, stopErr)
	}
	if !snapshot.masterEnabled || !m.enabled() {
		stopErr := m.supervisor.Reconcile(ctx, nil, func(identitysource.Spec) (identitysource.Runnable, error) {
			return nil, errors.New("identity source worker cannot start while the master feature is disabled")
		})
		return errors.Join(loadErr, stopErr)
	}
	for _, invalid := range snapshot.invalid {
		m.logger.Error("identity source runtime source isolated", "error", invalid)
	}
	entries := make(map[int64]identitySourceRuntimeEntry, len(snapshot.entries))
	specs := make([]identitysource.Spec, 0, len(snapshot.entries))
	for _, entry := range snapshot.entries {
		entries[entry.spec.SourceID] = entry
		specs = append(specs, entry.spec)
	}
	reconcileErr := m.supervisor.Reconcile(
		ctx,
		specs,
		func(spec identitysource.Spec) (identitysource.Runnable, error) {
			entry, ok := entries[spec.SourceID]
			if !ok || entry.spec.Generation != spec.Generation {
				return nil, errors.New("identity source runtime snapshot changed")
			}
			return m.builder.Build(entry)
		},
	)
	return errors.Join(loadErr, reconcileErr)
}

func (m *identitySourceRuntimeManager) Notify(payload string) {
	var notification struct {
		Key string `json:"key"`
	}
	if json.Unmarshal([]byte(payload), &notification) != nil {
		return
	}
	if notification.Key != toggle.FeatureIdentityModelV2 &&
		!validIdentitySourceNotificationKey(notification.Key) {
		return
	}
	m.Trigger()
}

// Trigger requests one coalesced authoritative reconciliation. Notification
// decoding/filtering belongs to the gateway toggle observer; polling remains
// the durable lost-notification floor.
func (m *identitySourceRuntimeManager) Trigger() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func (m *identitySourceRuntimeManager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
	m.supervisor.Stop()
}
