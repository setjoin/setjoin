package mailrecovery

// The recorder exercises one frozen Go cleanup tick against committed rows and
// a fake quarantine store. GOFREE_RECORD_WORKER writes a new golden only.
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/shared/testsupport"
)

type cleanupRequest struct {
	Method         string `json:"method"`
	URI            string `json:"uri"`
	Body           string `json:"body"`
	SHA256         string `json:"sha256"`
	Scope          string `json:"scope"`
	SignedHeaders  string `json:"signed_headers"`
	SignatureValid bool   `json:"signature_valid"`
}

type cleanupOracle struct {
	SessionStatus   string           `json:"session_status"`
	ItemStatus      string           `json:"item_status"`
	RemainingChunks int              `json:"remaining_chunks"`
	RemovedObject   bool             `json:"removed_object"`
	Requests        []cleanupRequest `json:"requests,omitempty"`
}

func TestWorkerOracleRecoveryCleanupOneTick(t *testing.T) { recoveryCleanupOracle(t, false) }
func TestWorkerOracleRecoveryCleanupHTTP(t *testing.T)    { recoveryCleanupOracle(t, true) }

func recoveryCleanupOracle(t *testing.T, realHTTP bool) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	incident, session := uuid.New(), uuid.New()
	var mailbox, user int64
	t.Cleanup(func() {
		cleanup := context.Background()
		tx, err := pool.Begin(cleanup)
		if err != nil {
			t.Errorf("begin cleanup: %v", err)
			return
		}
		defer func() { _ = tx.Rollback(cleanup) }()
		for _, step := range []struct {
			sql string
			arg any
		}{
			{`DELETE FROM mail_recovery_upload_sessions WHERE id=$1`, session},
			{`DELETE FROM mail_recovery_incidents WHERE id=$1`, incident},
			{`DELETE FROM mailboxes WHERE id=$1`, mailbox},
			{`DELETE FROM users WHERE id=$1`, user},
		} {
			if _, err := tx.Exec(cleanup, step.sql, step.arg); err != nil {
				t.Errorf("clean recovery fixture: %v", err)
				return
			}
		}
		if err := tx.Commit(cleanup); err != nil {
			t.Errorf("commit cleanup: %v", err)
		}
	})
	if err := pool.QueryRow(ctx, `SELECT mk_account('blobs1-worker')`).Scan(&mailbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailbox).Scan(&user); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("recovery-quarantine/%s/%s/%064x/0-%064x", incident, session, 0, 1)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO mail_recovery_incidents (id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES ($1,gen_random_uuid(),1,1,'test cleanup',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())`, []any{incident, user}},
		{`INSERT INTO mail_recovery_upload_sessions (id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) VALUES ($1,$2,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{}',now(),now()-interval '1 minute',gen_random_uuid())`, []any{session, incident, mailbox, user}},
		{`INSERT INTO mail_recovery_upload_items (session_id,item_id,role,sha256,declared_size) VALUES ($1,'raw','raw',decode(repeat('aa',32),'hex'),1)`, []any{session}},
		{`INSERT INTO mail_recovery_upload_chunks (session_id,item_id,start_offset,size_bytes,sha256,object_key) VALUES ($1,'raw',0,1,decode(repeat('bb',32),'hex'),$2)`, []any{session, key}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	store := &recordingStore{}
	var transport objectStore = store
	var requests []cleanupRequest
	var requestMu sync.Mutex
	var removed bool
	if realHTTP {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			record, err := observeCleanupRequest(r, body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			if r.Method == http.MethodDelete {
				if r.URL.Path != "/mailblobs/"+key {
					t.Errorf("unexpected deletion: %s", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				record.URI = "/mailblobs/<quarantine-key>"
				requestMu.Lock()
				removed = true
				requestMu.Unlock()
			}
			requestMu.Lock()
			requests = append(requests, record)
			requestMu.Unlock()
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, "<LocationConstraint>eu-central-1</LocationConstraint>")
			} else {
				w.WriteHeader(204)
			}
		}))
		defer server.Close()
		client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("test-access", "test-secret", "")})
		if err != nil {
			t.Fatal(err)
		}
		transport = minioStore{client: client, bucket: "mailblobs"}
	}
	handler := &Handler{db: pool, store: transport, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler.cleanupTerminalChunks(ctx)
	var got cleanupOracle
	if err := pool.QueryRow(ctx, `SELECT s.status,i.status,(SELECT count(*) FROM mail_recovery_upload_chunks WHERE session_id=s.id) FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1 AND i.item_id='raw'`, session).Scan(&got.SessionStatus, &got.ItemStatus, &got.RemainingChunks); err != nil {
		t.Fatal(err)
	}
	got.RemovedObject = reflect.DeepEqual(store.removedKeys, []string{key})
	if realHTTP {
		requestMu.Lock()
		got.RemovedObject = removed
		got.Requests = append([]cleanupRequest(nil), requests...)
		requestMu.Unlock()
	}

	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if recordWorkerOracle(t, data) {
		return
	}
	fixture := "../../../server-rust/bins/gateway/tests/golden/go-recovery-cleanup.json"
	if realHTTP {
		fixture = "../../../server-rust/bins/gateway/tests/golden/go-recovery-cleanup-http.json"
	}
	expected, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var want cleanupOracle
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worker oracle mismatch: got %+v, want %+v", got, want)
	}
}

// Verify SigV4 independently at the fake S3 HTTP boundary before normalizing
// its volatile date/signature. An invalid signature can never enter a golden.
func observeCleanupRequest(r *http.Request, body []byte) (cleanupRequest, error) {
	fail := func() (cleanupRequest, error) { return cleanupRequest{}, fmt.Errorf("invalid cleanup SigV4 request") }
	const algorithm = "AWS4-HMAC-SHA256"
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algorithm+" ") {
		return fail()
	}
	fields := map[string]string{}
	for _, field := range strings.Split(strings.TrimPrefix(auth, algorithm+" "), ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			return fail()
		}
		fields[name] = value
	}
	credential := strings.Split(fields["Credential"], "/")
	date := r.Header.Get("X-Amz-Date")
	if _, err := time.Parse("20060102T150405Z", date); err != nil {
		return fail()
	}
	if len(credential) != 5 || credential[0] != "test-access" || credential[1] != date[:8] || credential[3] != "s3" || credential[4] != "aws4_request" {
		return fail()
	}
	headers := ""
	for _, name := range strings.Split(fields["SignedHeaders"], ";") {
		value := strings.Join(r.Header.Values(name), ",")
		if name == "host" {
			value = r.Host
		}
		headers += name + ":" + strings.Join(strings.Fields(value), " ") + "\n"
	}
	digest := sha256.Sum256(body)
	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload != hex.EncodeToString(digest[:]) {
		return fail()
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.Query().Encode() + "\n" + headers + "\n" + fields["SignedHeaders"] + "\n" + payload
	canonicalHash := sha256.Sum256([]byte(canonical))
	scope := strings.Join(credential[1:], "/")
	input := algorithm + "\n" + date + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	mac := func(key []byte, value string) []byte {
		hash := hmac.New(sha256.New, key)
		_, _ = hash.Write([]byte(value))
		return hash.Sum(nil)
	}
	key := mac([]byte("AWS4test-secret"), credential[1])
	key = mac(key, credential[2])
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	expected := hex.EncodeToString(mac(key, input))
	if !hmac.Equal([]byte(expected), []byte(fields["Signature"])) {
		return fail()
	}
	return cleanupRequest{r.Method, r.URL.RequestURI(), string(body), payload, credential[0] + "/<date>/" + strings.Join(credential[2:], "/"), fields["SignedHeaders"], true}, nil
}

// recordWorkerOracle never overwrites an immutable recording.
func recordWorkerOracle(t *testing.T, data []byte) bool {
	t.Helper()
	path := os.Getenv("GOFREE_RECORD_WORKER")
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		complete := false
		defer func() {
			if err := f.Close(); err != nil {
				complete = false
				t.Error(err)
			}
			if !complete {
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}
		}()
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		complete = true
		return true
	}
	return false
}

type anonymousCleanupRequest struct {
	Method        string `json:"method"`
	URI           string `json:"uri"`
	Body          string `json:"body"`
	Authorization bool   `json:"authorization"`
	Date          bool   `json:"date"`
	SHA256        bool   `json:"sha256"`
}

// The transport used by the frozen worker accepts missing or partial static
// credentials as anonymous. Capture real MinIO HTTP instead of inferring it.
func TestWorkerOracleRecoveryAnonymousHTTP(t *testing.T) {
	var mu sync.Mutex
	var got []anonymousCleanupRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, anonymousCleanupRequest{r.Method, r.URL.RequestURI(), string(body), r.Header.Get("Authorization") != "", r.Header.Get("X-Amz-Date") != "", r.Header.Get("X-Amz-Content-Sha256") != ""})
		mu.Unlock()
		if r.URL.RawQuery == "location=" {
			_, _ = io.WriteString(w, "<LocationConstraint>eu-central-1</LocationConstraint>")
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, pair := range [][2]string{{"", ""}, {"test-access", ""}, {"", "test-secret"}} {
		client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4(pair[0], pair[1], ""), Secure: false})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.RemoveObject(ctx, "mailblobs", "recovery-quarantine/a/b", minio.RemoveObjectOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 6 {
		t.Fatalf("expected location and delete per client, got %+v", got)
	}
	for _, request := range got {
		if request.Authorization || request.Date || request.SHA256 {
			t.Fatalf("anonymous request was signed: %+v", request)
		}
	}
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if recordWorkerOracle(t, data) {
		return
	}
	expected, err := os.ReadFile("../../../server-rust/bins/gateway/tests/golden/go-recovery-anonymous-http.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []anonymousCleanupRequest
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("anonymous transport mismatch: got %+v, want %+v", got, want)
	}
}
