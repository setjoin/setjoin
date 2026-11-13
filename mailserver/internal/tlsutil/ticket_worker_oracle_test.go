package tlsutil

// Records one actual Go ticket-manager tick for Rust's worker parity oracle.
import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
)

type ticketOracle struct {
	StartupUnchanged   bool `json:"startup_unchanged"`
	CurrentChanged     bool `json:"current_changed"`
	CurrentBytes       int  `json:"current_bytes"`
	PreviousWasCurrent bool `json:"previous_was_current"`
	EncryptedLabel     bool `json:"encrypted_label"`
}

func TestTicketWorkerOracleOneTick(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	var prior []byte
	var encrypted bool
	var description *string
	var updated time.Time
	err := pool.QueryRow(ctx, `SELECT value, encrypted, description, updated_at FROM system_config WHERE key='tls_session_ticket_keys'`).Scan(&prior, &encrypted, &description, &updated)
	hadPrior := err == nil
	if err != nil && err != pgx.ErrNoRows {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		if hadPrior {
			_, err = pool.Exec(context.Background(), `UPDATE system_config SET value=$1, encrypted=$2, description=$3, updated_at=$4 WHERE key='tls_session_ticket_keys'`, prior, encrypted, description, updated)
		} else {
			_, err = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='tls_session_ticket_keys'`)
		}
		if err != nil {
			t.Error(err)
		}
	})
	seed := storedTicketKeys{Current: base64.StdEncoding.EncodeToString([]byte("33333333333333333333333333333333")), Previous: base64.StdEncoding.EncodeToString([]byte("11111111111111111111111111111111"))}
	raw, _ := json.Marshal(seed)
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted,description,updated_at) VALUES('tls_session_ticket_keys',$1,true,'ticket oracle',now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=EXCLUDED.encrypted,description=EXCLUDED.description,updated_at=EXCLUDED.updated_at`, raw); err != nil {
		t.Fatal(err)
	}
	manager := NewSessionTicketKeyManager(&tls.Config{}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)), 500*time.Millisecond)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); manager.Start(runCtx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(100 * time.Millisecond)
	var before []byte
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key='tls_session_ticket_keys'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	var startup storedTicketKeys
	if err := json.Unmarshal(before, &startup); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var after storedTicketKeys
	var label bool
	for {
		var row []byte
		if err := pool.QueryRow(ctx, `SELECT value,encrypted FROM system_config WHERE key='tls_session_ticket_keys'`).Scan(&row, &label); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(row, &after); err != nil {
			t.Fatal(err)
		}
		if after.Current != seed.Current {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not rotate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	current, err := base64.StdEncoding.DecodeString(after.Current)
	if err != nil {
		t.Fatal(err)
	}
	got := ticketOracle{startup == seed, after.Current != seed.Current, len(current), after.Previous == seed.Current, label}
	if path := os.Getenv("GOFREE_RECORD_TICKET_WORKER"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(got); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.Open("../../../server-rust/bins/gateway/tests/golden/go-ticket-rotation.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var want ticketOracle
	if err := json.NewDecoder(file).Decode(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
