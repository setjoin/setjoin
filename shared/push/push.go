// Package push is the shared push-notification dispatch stack: the transport seam
// (Dispatcher) plus the four provider implementations (Web Push / APNs / FCM /
// HMS), their config, a doctor that validates each configured provider, and the
// device-resolution helper that turns a user id into decrypted device tokens.
//
// It was extracted from authserver/internal/authn so BOTH the authserver (push
// MFA + security alerts) and the mailserver push worker (mail notifications) call
// one implementation. authserver keeps its ECIES/MFA payload building; this
// package owns only the transports.
//
// # Environment variables
//
// LoadConfig reads (all optional — an unset provider is simply absent):
//
//	VAPID_PRIVATE_KEY        Web Push VAPID private key (base64url)
//	VAPID_SUBJECT            Web Push subject URI (mailto:/https:), default mailto:admin@localhost
//	APNS_CERT_PATH           path to the APNs PKCS#12 (.p12) certificate (cert-based auth, M4)
//	APNS_CERT_PASSWORD       password for the .p12 certificate
//	APNS_BUNDLE_ID           APNs topic / app bundle id
//	APNS_PRODUCTION          "true" ⇒ production APNs gateway, else sandbox
//	FCM_SERVICE_ACCOUNT_FILE path to the Firebase service-account JSON (mints its own OAuth2 token)
//	HMS_APP_ID               Huawei Push Kit app id
//	HMS_APP_SECRET           Huawei Push Kit app secret
package push

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/envutil"
)

// Dispatcher is the single transport seam every push backend satisfies: deliver
// opaque payload bytes to a device token. Kept single-method deliberately — the
// payload carries everything (ECIES challenge or rich mail JSON); rendering is the
// client's job.
type Dispatcher interface {
	Send(ctx context.Context, token string, payload []byte) error
}

// ProviderKind is the push backend discriminator; values match the
// push_devices.push_provider column (the per-row dispatch key).
type ProviderKind string

const (
	Webpush ProviderKind = "webpush"
	APNs    ProviderKind = "apns"
	FCM     ProviderKind = "fcm"
	HMS     ProviderKind = "hms"
)

// ErrUnregistered is returned (wrapped) by a Dispatcher when the provider reports
// the device token is permanently dead (404/410/Unregistered/BadDeviceToken). The
// caller prunes the device (sets revoked_at) instead of retrying.
var ErrUnregistered = errors.New("push: device token no longer registered")

// Config is the raw push configuration; zero-valued fields mean "provider absent".
type Config struct {
	VAPIDPrivateKey string
	VAPIDSubject    string

	// WebPushHTTPClient is a TEST-ONLY injection seam for loopback E2E
	// harnesses: the production dispatcher defaults to the dial-time SSRF
	// client (loopback/private/special-use endpoints are refused), and a
	// webpush E2E test's "push service" is a local httptest server. Nil (the
	// default, and every production wire) keeps the guarded client. Never
	// feed operator input into this field.
	WebPushHTTPClient *http.Client

	APNsCertPath     string
	APNsCertPassword string
	APNsBundleID     string
	APNsProduction   bool

	FCMServiceAccountFile string

	HMSAppID     string
	HMSAppSecret string
}

// LoadConfig reads the push configuration from the environment (see package doc).
func LoadConfig() Config {
	return Config{
		VAPIDPrivateKey:       os.Getenv("VAPID_PRIVATE_KEY"),
		VAPIDSubject:          envutil.Getenv("VAPID_SUBJECT", "mailto:admin@localhost"),
		APNsCertPath:          os.Getenv("APNS_CERT_PATH"),
		APNsCertPassword:      os.Getenv("APNS_CERT_PASSWORD"),
		APNsBundleID:          os.Getenv("APNS_BUNDLE_ID"),
		APNsProduction:        envutil.ParseBool(os.Getenv("APNS_PRODUCTION")),
		FCMServiceAccountFile: os.Getenv("FCM_SERVICE_ACCOUNT_FILE"),
		HMSAppID:              os.Getenv("HMS_APP_ID"),
		HMSAppSecret:          os.Getenv("HMS_APP_SECRET"),
	}
}

// State classifies a provider after Build/Doctor.
type State string

const (
	// Absent: no config for this provider.
	Absent State = "absent"
	// Configured: config present and the dispatcher built cleanly.
	Configured State = "configured"
	// Invalid: config present but construction/validation failed (a loud error —
	// an operator meant to enable it and it is broken).
	Invalid State = "invalid"
)

// ProviderStatus is one row of Build/Doctor output.
type ProviderStatus struct {
	Kind   ProviderKind
	State  State
	Detail string // error text when Invalid, informational otherwise
}

// Set is the built collection of dispatchers keyed by provider kind.
type Set struct {
	dispatchers map[ProviderKind]Dispatcher
}

// Get returns the dispatcher for kind (nil, false if not configured).
func (s *Set) Get(kind ProviderKind) (Dispatcher, bool) {
	d, ok := s.dispatchers[kind]
	return d, ok
}

// Any reports whether at least one provider is configured.
func (s *Set) Any() bool { return len(s.dispatchers) > 0 }

// Build constructs every configured dispatcher and returns the set plus a status
// per provider. A present-but-broken provider is reported Invalid (never silently
// skipped) but does not fail Build — the caller logs it loudly and continues with
// the providers that did build.
func Build(cfg Config) (*Set, []ProviderStatus) {
	set := &Set{dispatchers: make(map[ProviderKind]Dispatcher)}
	var statuses []ProviderStatus

	// Web Push
	if cfg.VAPIDPrivateKey != "" {
		if err := validateVAPIDPrivateKey(cfg.VAPIDPrivateKey); err != nil {
			// Loud-Invalid doctrine: a present-but-broken key is reported
			// Invalid (never silently Configured, never silently skipped) —
			// the operator meant to enable Web Push and it is broken. The
			// old behavior only surfaced the failure at the first send,
			// which read as "configured" everywhere until then.
			statuses = append(statuses, ProviderStatus{Webpush, Invalid, err.Error()})
		} else {
			set.dispatchers[Webpush] = NewWebPushDispatcherWithClient(cfg.VAPIDPrivateKey, cfg.VAPIDSubject, cfg.WebPushHTTPClient)
			statuses = append(statuses, ProviderStatus{Webpush, Configured, "VAPID subject " + cfg.VAPIDSubject})
		}
	} else {
		statuses = append(statuses, ProviderStatus{Webpush, Absent, ""})
	}

	// APNs (cert-based)
	if cfg.APNsCertPath != "" {
		d, err := NewAPNsDispatcher(cfg.APNsCertPath, cfg.APNsCertPassword, cfg.APNsBundleID, cfg.APNsProduction)
		if err != nil {
			statuses = append(statuses, ProviderStatus{APNs, Invalid, err.Error()})
		} else {
			set.dispatchers[APNs] = d
			statuses = append(statuses, ProviderStatus{APNs, Configured, "bundle " + cfg.APNsBundleID})
		}
	} else {
		statuses = append(statuses, ProviderStatus{APNs, Absent, ""})
	}

	// FCM (service-account JSON)
	if cfg.FCMServiceAccountFile != "" {
		saJSON, err := os.ReadFile(cfg.FCMServiceAccountFile)
		if err != nil {
			statuses = append(statuses, ProviderStatus{FCM, Invalid, "read SA file: " + err.Error()})
		} else if d, err := NewFCMDispatcher(saJSON); err != nil {
			statuses = append(statuses, ProviderStatus{FCM, Invalid, err.Error()})
		} else {
			set.dispatchers[FCM] = d
			statuses = append(statuses, ProviderStatus{FCM, Configured, "project " + d.ProjectID()})
		}
	} else {
		statuses = append(statuses, ProviderStatus{FCM, Absent, ""})
	}

	// HMS
	if cfg.HMSAppID != "" {
		set.dispatchers[HMS] = NewHMSDispatcher(cfg.HMSAppID, cfg.HMSAppSecret)
		statuses = append(statuses, ProviderStatus{HMS, Configured, "app " + cfg.HMSAppID})
	} else {
		statuses = append(statuses, ProviderStatus{HMS, Absent, ""})
	}

	return set, statuses
}

// Doctor validates each configured provider more deeply than Build: for FCM/HMS it
// actually mints an OAuth token (network), proving the credentials authenticate,
// not merely parse. Web Push and APNs are validated at Build time (key/cert parse).
func Doctor(ctx context.Context, cfg Config) []ProviderStatus {
	set, statuses := Build(cfg)
	for i := range statuses {
		if statuses[i].State != Configured {
			continue
		}
		switch statuses[i].Kind {
		case FCM:
			if d, ok := set.dispatchers[FCM].(*FCMDispatcher); ok {
				if err := d.OAuth(ctx); err != nil {
					statuses[i] = ProviderStatus{FCM, Invalid, "OAuth failed: " + err.Error()}
				}
			}
		case HMS:
			if d, ok := set.dispatchers[HMS].(*HMSDispatcher); ok {
				if err := d.OAuth(ctx); err != nil {
					statuses[i] = ProviderStatus{HMS, Invalid, "OAuth failed: " + err.Error()}
				}
			}
		}
	}
	return statuses
}

// Device is a resolved, decrypted push registration.
type Device struct {
	ID       int64
	Provider ProviderKind
	Token    string
}

// Querier is the minimal pgx surface ResolveDevices needs (satisfied by a pool,
// conn, or tx). The connection MUST have app.encryption_key set (the worker pool
// and authserver pool both inject it) so pgp_sym_decrypt can read push_token_enc.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// validateVAPIDPrivateKey checks the VAPID private key is the form
// webpush-go consumes at send time: base64url of the 32-byte P-256 private
// scalar. Anything else would only fail at the first send; Build surfaces it
// as the loud Invalid state instead.
func validateVAPIDPrivateKey(key string) error {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("VAPID_PRIVATE_KEY is not valid base64url: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("VAPID_PRIVATE_KEY must decode to the 32-byte P-256 private scalar; got %d bytes", len(raw))
	}
	return nil
}

// ResolveDevices returns a user's non-revoked push devices with their
// decrypted tokens. Decryption happens in SQL — per token, through the
// push_decrypt_token helper (V263), whose PL/pgSQL EXCEPTION block isolates
// exactly the undecryptable-token failure (SQLSTATE 39000, pgcrypto "Wrong
// key or corrupt data") as a NULL; everything else propagates: real query
// errors, a missing OR EMPTY app.encryption_key GUC (42704 — configuration
// error, validated OUTSIDE the helper's protected block because pgcrypto
// raises the same 39000 for an empty key as for a bad token) and
// cancellation all fail the resolve loudly. The helper is exception-isolated
// in SQL because only there can the failure be kept from marking the pgx
// result set broken AND from poisoning a transaction caller's transaction
// (client-side per-row scan errors can be skipped, but a server-raised error
// aborts the surrounding transaction and there is no safe per-call savepoint
// through the Querier seam — a pool and a tx would need different, and for
// pools unsound, savepoint choreography).
//
// A single undecryptable token never sinks the whole send (the skip remains
// intentionally fail-closed: nothing is misdirected), but the skip is no
// longer SILENT: the count of unreadable rows is logged loudly, because a
// systemic decrypt failure (wrong/missing key at the pooler) must be
// distinguishable from "user has no devices" — that gap is a
// revocation-delivery observability hole. The aggregate log names only the
// skipped-row count — never a token or the key.
func ResolveDevices(ctx context.Context, q Querier, userID int64) ([]Device, error) {
	rows, err := q.Query(ctx, `
		SELECT id, push_provider, push_decrypt_token(push_token_enc)
		  FROM push_devices
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve push devices: %w", err)
	}
	defer rows.Close()

	var out []Device
	var undecryptable int
	for rows.Next() {
		var d Device
		var provider string
		var token *string
		if err := rows.Scan(&d.ID, &provider, &token); err != nil {
			// A single unreadable row must not sink the whole send (defensive:
			// the helper turns the decrypt failure itself into a NULL, so a
			// scan error here means an unexpected driver-level problem on one
			// row — skipped and counted, never misdirected).
			undecryptable++
			continue
		}
		if token == nil {
			// push_decrypt_token returned NULL: the row's ciphertext is
			// undecryptable under app.encryption_key (SQLSTATE 39000,
			// isolated in-sql by the V263 helper) — skipped, counted.
			undecryptable++
			continue
		}
		if *token == "" {
			continue
		}
		d.Token = *token
		d.Provider = ProviderKind(provider)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if undecryptable > 0 {
		// Aggregate-and-surface: one loud line per dispatch, not per row.
		slog.Error("push: push_devices rows could not be decrypted; tokens skipped",
			"user_id", userID, "skipped_rows", undecryptable,
			"consequence", "those devices will not receive this dispatch; check app.encryption_key at the connection pooler")
	}
	return out, nil
}
