package smtp

import (
	"bufio"
	"context"
	"net"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"setjoin.com/shared/toggle"
)

// The pooled-session policy gate (med-shard2-001 / SMTP-V005): the MX pool is
// keyed by host, so policy-differing recipient domains sharing an MX host must
// never hand an enforce-listed delivery a pooled PLAINTEXT session, and reused
// deliveries must report the session's REAL TLS state (never a hard-coded
// tls:false success).

func newPoolTestWorker(t *testing.T) *OutboundWorker {
	t.Helper()
	return &OutboundWorker{
		logger:         testLogger(),
		toggles:        emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
		commandTimeout: time.Second,
		dataTimeout:    time.Second,
	}
}

// freshSMTPConn scripts an accepting plaintext SMTP session whose greeting is
// still unread — the shape a FRESH dial presents to dialAndEHLO.
func freshSMTPConn(t *testing.T) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close() })
	fullSMTPServer(t, serverConn, "250 2.1.5 recipient ok", "250 2.0.0 queued")
	return clientConn
}

// pooledPlaintextSession returns a plaintext session shaped like a REAL pooled
// one: mid-conversation, its greeting already consumed, so the reuse path's
// RSET is the next expected exchange. If the worker (wrongly) reuses it, the
// scripted server accepts the message — exactly what the negative tests assert
// must NOT happen for policy-gated deliveries.
func pooledPlaintextSession(t *testing.T) net.Conn {
	t.Helper()
	clientConn := freshSMTPConn(t)
	greeting, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, "220") {
		t.Fatalf("scripted greeting = %q, err %v", greeting, err)
	}
	return clientConn
}

func drainPooledConn(t *testing.T, w *OutboundWorker, host string) {
	t.Helper()
	if pc := w.connPool.get(host); pc != nil {
		pc.tp.Close()
		pc.conn.Close()
	}
}

func TestDeliverToMX_PlaintextPooledSessionRefusedWhenTLSRequired(t *testing.T) {
	w := newPoolTestWorker(t)
	pooledClient := pooledPlaintextSession(t)
	// tls=false: a pooled PLAINTEXT session for this MX host.
	w.connPool.put(&pooledConn{
		tp: textproto.NewConn(pooledClient), conn: pooledClient,
		host: "mx.example.test", tls: false, used: time.Now(),
	})

	var dials atomic.Int32
	w.dialMX = func(string) (net.Conn, error) {
		dials.Add(1)
		return freshSMTPConn(t), nil
	}

	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, true, false)
	// If the pooled plaintext session had been reused, the scripted server
	// would have accepted the message (err == nil) over cleartext.
	if got.err == nil {
		t.Fatal("enforce-listed delivery used the pooled PLAINTEXT session")
	}
	if !strings.Contains(got.err.Error(), "TLS required") {
		t.Fatalf("delivery error = %v, want fail-closed TLS policy refusal", got.err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dial count = %d, want exactly one fresh (policy-compliant) dial", dials.Load())
	}
	drainPooledConn(t, w, "mx.example.test")
}

func TestDeliverToMX_PlaintextPooledSessionReusedWithoutPolicy(t *testing.T) {
	w := newPoolTestWorker(t)
	pooledClient := pooledPlaintextSession(t)
	w.connPool.put(&pooledConn{
		tp: textproto.NewConn(pooledClient), conn: pooledClient,
		host: "mx.example.test", tls: false, used: time.Now(),
	})
	w.dialMX = func(string) (net.Conn, error) {
		t.Error("no-policy delivery must reuse the pooled plaintext session, not dial")
		return nil, context.Canceled
	}

	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if got.err != nil {
		t.Fatalf("pooled plaintext reuse failed: %v", got.err)
	}
	if got.tls {
		t.Errorf("reused plaintext session reported tls=true")
	}
	drainPooledConn(t, w, "mx.example.test")
}

func TestDeliverToMX_TLSPooledSessionSatisfiesRequireTLSAndReportsTrue(t *testing.T) {
	w := newPoolTestWorker(t)
	pooledClient := pooledPlaintextSession(t)
	w.connPool.put(&pooledConn{
		tp: textproto.NewConn(pooledClient), conn: pooledClient,
		host: "mx.example.test", tls: true, used: time.Now(),
	})
	w.dialMX = func(string) (net.Conn, error) {
		t.Error("requireTLS delivery must reuse the pooled TLS session, not dial")
		return nil, context.Canceled
	}

	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, true, false)
	if got.err != nil {
		t.Fatalf("pooled TLS reuse failed: %v", got.err)
	}
	if !got.tls {
		t.Fatal("reused TLS session reported tls=false — a tls:false success mask")
	}
	drainPooledConn(t, w, "mx.example.test")
}

// TestDeliverRecipients_SharedMXEnforceDomainNeverCleartext is the integration
// cell of the matrix: two policy-differing recipient domains share ONE MX host.
// The free domain pools a plaintext session; the enforce-listed domain must not
// deliver over it and must not report a tls:false success.
func TestDeliverRecipients_SharedMXEnforceDomainNeverCleartext(t *testing.T) {
	w := newPoolTestWorker(t)
	w.tlsPolicy = &tlsPolicyState{enforceDomains: []string{"enforce.test"}}
	w.lookupMXFn = func(string) ([]*net.MX, error) {
		return []*net.MX{{Host: "shared-mx.test", Pref: 10}}, nil
	}
	var dials atomic.Int32
	w.dialMX = func(string) (net.Conn, error) {
		dials.Add(1)
		return freshSMTPConn(t), nil
	}

	item := queueItem{
		messageID:  "<shared-mx-pool@test>",
		fromAddr:   "sender@from.test",
		recipients: []string{"a@free.test", "b@enforce.test"},
	}
	results, lastErr := w.deliverRecipients(context.Background(), item, cannedRaw)
	if len(results) != 2 {
		t.Fatalf("results = %+v, want one per recipient", results)
	}

	free := results[0]
	if free.rcpt != "a@free.test" || free.outcome != outcomeAccepted {
		t.Fatalf("free-domain result = %+v, want accepted (legitimate non-DANE/opportunistic delivery preserved)", free)
	}
	if free.tls {
		t.Errorf("free-domain delivery reported tls=true over a plaintext session")
	}

	enforce := results[1]
	if enforce.outcome == outcomeAccepted {
		t.Fatal("enforce-listed recipient was delivered over the shared plaintext session")
	}
	if enforce.tls {
		t.Errorf("enforce-listed recipient reported tls=true over a plaintext session")
	}
	// outcome for a code-0 policy refusal is "error" → the queue row defers
	// with retry via markFailed (never a silent plaintext success).
	if enforce.outcome != outcomeError {
		t.Fatalf("enforce outcome = %q, want %q (defer-with-retry path)", enforce.outcome, outcomeError)
	}
	if dials.Load() != 2 {
		t.Fatalf("dial count = %d, want 2 (free domain dial + enforce domain's refused-pool fresh dial)", dials.Load())
	}
	if !strings.Contains(lastErr, "TLS required") {
		t.Fatalf("lastErr = %q, want the TLS policy refusal", lastErr)
	}
	drainPooledConn(t, w, "shared-mx.test")
}

func TestApplyDANEVerdict_Matrix(t *testing.T) {
	w := &OutboundWorker{logger: testLogger()}
	tests := []struct {
		name       string
		result     DANEResult
		wantErrSub string // empty = proceed (nil error)
	}{
		{"secure → deliver", DANESecure, ""},
		{"secure-unusable (no usable records) → proceed with active TLS", DANESecureUnusable, ""},
		{"absence → opportunistic, never defers or rejects", DANEInsecure, ""},
		{"authenticated records + mismatch → reject even CA-valid", DANECertMismatch, "does not match"},
		{"lookup failure → defer with retry", DANELookupFailed, "unreachable"},
		{"unknown verdict → fail closed", DANEResult(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := w.applyDANEVerdict(tc.result, "mx.example.test")
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("applyDANEVerdict(%v) = %v, want proceed", tc.result, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("applyDANEVerdict(%v) = nil, want error containing %q", tc.result, tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSub)
			}
		})
	}
}

// daneToggles returns flags with the DANE rails ON (and the network-touching
// MTA-STS/TLS-RPT features off) for the deliverToMX DANE matrix below.
func daneToggles() *toggle.FeatureFlags {
	return toggle.NewStatic(map[string]bool{
		"feature.mta_sts": false,
		"feature.tls_rpt": false,
		"feature.dnssec":  true,
		"feature.dane":    true,
	})
}

// TestDeliverToMX_DANEPolicyMatrix pins the pre-MAIL/DATA DANE decisions
// (med-shard2-001 review item 1): the complete outcome (DANEPrecheckMX) is
// evaluated BEFORE any pooled reuse or fresh delivery, so
//   - a failed TLSA lookup defers BEFORE DIALING (never plaintext, skipTLS or
//     a pooled session cannot bypass it),
//   - authenticated records force TLS for the attempt (STARTTLS stripping is
//     refused fail-closed; a pooled plaintext or never-DANE-validated session
//     is dropped — policy is re-evaluated NOW, not inherited from when the
//     session was pooled), and
//   - absence preserves legitimate plaintext/opportunistic delivery.
//
// The former dialAndEHLO-level IsDANEAvailable downgrade check was removed
// with this change: its collapsed lookup-failure→false result was exactly the
// reviewed bug, and the refusal now lives in deliverToMX where the full
// outcome (and the pool/skip interactions) are in scope.
func TestDeliverToMX_DANEPolicyMatrix(t *testing.T) {
	assoc := []byte("cafe")

	// Pooled-session shapes: (session tls, session dane-validated-at-establishment).
	// poolNone is the zero value so cells without a pooled session seed none.
	const (
		poolNone      = ""
		poolPlaintext = "plaintext"
		poolTLSNoDane = "tls-not-dane-validated"
		poolTLSDane   = "tls-dane-validated"
	)
	poolShape := func(pool string) (tls, dane bool) {
		switch pool {
		case poolPlaintext:
			return false, false
		case poolTLSNoDane:
			return true, false
		case poolTLSDane:
			return true, true
		}
		return false, false
	}

	tests := []struct {
		name       string
		resp       *dns.Msg
		pool       string
		requireTLS bool
		skipTLS    bool
		wantDials  int32
		wantErrSub string // empty = delivery must SUCCEED
		wantTLS    bool
	}{
		// FAILURE: lookup failures defer before dialing.
		{
			name:       "TLSA lookup failure defers before dialing — never plaintext",
			resp:       dnsResponse(false, dns.RcodeServerFailure),
			wantDials:  0,
			wantErrSub: "unreachable",
		},
		{
			name:       "TLSA lookup failure defers even when admin policy skips TLS",
			resp:       dnsResponse(false, dns.RcodeServerFailure),
			skipTLS:    true,
			wantDials:  0,
			wantErrSub: "unreachable",
		},
		{
			name:       "TLSA lookup failure defers even with a pooled DANE-validated TLS session",
			resp:       dnsResponse(false, dns.RcodeServerFailure),
			pool:       poolTLSDane,
			wantDials:  0,
			wantErrSub: "unreachable",
		},
		// STRIPPING: records published but STARTTLS not advertised.
		{
			name:       "STARTTLS stripped on a DANE host → refused fail-closed",
			resp:       dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			wantDials:  1,
			wantErrSub: "TLS required",
		},
		{
			name:       "STARTTLS stripped + admin skipTLS → still refused (skip cannot bypass DANE)",
			resp:       dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			skipTLS:    true,
			wantDials:  1,
			wantErrSub: "TLS required",
		},
		// POLICY CHANGE: the DANE decision is made NOW, not when the session was pooled.
		{
			name:       "pooled plaintext session dropped once records appear → refused, not reused",
			resp:       dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			pool:       poolPlaintext,
			wantDials:  1,
			wantErrSub: "TLS required",
		},
		{
			name:       "pooled never-DANE-validated TLS session dropped once records appear → refused, not reused",
			resp:       dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			pool:       poolTLSNoDane,
			wantDials:  1,
			wantErrSub: "TLS required",
		},
		// SKIP interaction, absence: legitimate non-DANE delivery preserved.
		{
			name:      "no TLSA records + no STARTTLS + skipTLS → legitimate plaintext preserved",
			resp:      dnsResponse(false, dns.RcodeSuccess),
			skipTLS:   true,
			wantDials: 1,
			wantTLS:   false,
		},
		{
			name:      "no TLSA records + no STARTTLS → legitimate plaintext preserved",
			resp:      dnsResponse(false, dns.RcodeSuccess),
			wantDials: 1,
			wantTLS:   false,
		},
		// Pooled DANE-validated TLS session satisfies the DANE requirement —
		// even under admin skipTLS (the session was DANE-authenticated).
		{
			name:      "pooled DANE-validated TLS session reused despite records + skipTLS",
			resp:      dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			pool:      poolTLSDane,
			skipTLS:   true,
			wantDials: 0,
			wantTLS:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newPoolTestWorker(t)
			w.toggles = daneToggles()
			fakeExchangeTLSA(t, tc.resp, nil)

			if tc.pool != poolNone {
				sessionTLS, sessionDane := poolShape(tc.pool)
				pooledClient := pooledPlaintextSession(t)
				w.connPool.put(&pooledConn{
					tp: textproto.NewConn(pooledClient), conn: pooledClient,
					host: "mx.example.test", tls: sessionTLS, dane: sessionDane, used: time.Now(),
				})
			}

			var dials atomic.Int32
			w.dialMX = func(string) (net.Conn, error) {
				dials.Add(1)
				// Fresh dial: a scripted server that (like the pool-scripted
				// one) accepts the whole envelope WITHOUT advertising
				// STARTTLS — if a DANE-required delivery reached MAIL/DATA
				// over this connection, the test's success/error expectation
				// would expose it.
				return freshSMTPConn(t), nil
			}

			got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, tc.requireTLS, tc.skipTLS)
			if tc.wantErrSub == "" {
				if got.err != nil {
					t.Fatalf("delivery failed: %v", got.err)
				}
			} else {
				if got.err == nil {
					t.Fatal("delivery succeeded where the DANE outcome must fail it closed")
				}
				if !strings.Contains(got.err.Error(), tc.wantErrSub) {
					t.Fatalf("error %q does not contain %q", got.err.Error(), tc.wantErrSub)
				}
			}
			if got.tls != tc.wantTLS {
				t.Errorf("result tls = %v, want %v", got.tls, tc.wantTLS)
			}
			if dials.Load() != tc.wantDials {
				t.Errorf("dial count = %d, want %d", dials.Load(), tc.wantDials)
			}
			drainPooledConn(t, w, "mx.example.test")
		})
	}
}
