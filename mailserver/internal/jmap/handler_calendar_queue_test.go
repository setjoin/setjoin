package jmap

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/shared/pgxutil"
)

type successfulObjectPutTransport struct{}

func (successfulObjectPutTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_, _ = io.Copy(io.Discard, request.Body)
	_ = request.Body.Close()
	header := make(http.Header)
	header.Set("ETag", `"calendar-queue-test"`)
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}, nil
}

func calendarQueueTestHandler(t *testing.T) *JMAPHandler {
	t.Helper()
	pool := testPoolDB(t)
	client, err := minio.New("s3.test", &minio.Options{
		Creds:     credentials.NewStaticV4("test-access", "test-secret", ""),
		Secure:    false,
		Region:    "us-east-1",
		Transport: successfulObjectPutTransport{},
	})
	if err != nil {
		t.Fatalf("new object client: %v", err)
	}
	return NewJMAPHandler(
		pool,
		pgxutil.WorkerPool{Pool: pool},
		"localhost",
		client,
		"calendar-test",
		10_000_000,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func TestCalendarIMIPQueuesUseNativeTextArrays(t *testing.T) {
	h := calendarQueueTestHandler(t)
	ctx := context.Background()
	const inviteUID = "coverage-invite-native-array"
	const counterUID = "coverage-counter-native-array"
	_, _ = h.pool.Exec(ctx, `DELETE FROM outbound_queue WHERE message_id = ANY($1)`, []string{inviteUID, counterUID})
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DELETE FROM outbound_queue WHERE message_id = ANY($1)`, []string{inviteUID, counterUID})
	})

	invite := []byte(`{
		"uid":"coverage-invite-native-array","title":"Coverage Invite",
		"start":"2026-08-01T10:00:00Z","end":"2026-08-01T11:00:00Z",
		"timezone":"UTC","status":"confirmed","sequence":1,
		"organizerEmail":"organizer@test.local","organizerName":"Organizer",
		"attendees":[
			{"email":"organizer@test.local","role":"organizer","status":"accepted"},
			{"email":"first@test.local","role":"required","status":"needs-action"},
			{"email":"second@test.local","role":"optional","status":"needs-action"}
		]}`)
	h.serializeAndEnqueueInvite(ctx, invite)

	var inviteFrom string
	var inviteRecipients []string
	if err := h.pool.QueryRow(ctx,
		`SELECT from_addr, rcpt_addrs FROM outbound_queue WHERE message_id = $1`, inviteUID,
	).Scan(&inviteFrom, &inviteRecipients); err != nil {
		t.Fatalf("read queued invite: %v", err)
	}
	if inviteFrom != "organizer@test.local" || strings.Join(inviteRecipients, ",") != "first@test.local,second@test.local" {
		t.Fatalf("queued invite = from %q recipients %v", inviteFrom, inviteRecipients)
	}

	counter := []byte(`{
		"uid":"coverage-counter-native-array","title":"Coverage Counter",
		"start":"2026-08-01T12:00:00Z","end":"2026-08-01T12:30:00Z",
		"timezone":"UTC","sequence":2,
		"organizerEmail":"organizer@test.local","organizerName":"Organizer",
		"attendeeEmail":"attendee@test.local","attendeeName":"Attendee"
	}`)
	h.serializeAndEnqueueCounter(ctx, counter)

	var counterFrom string
	var counterRecipients []string
	if err := h.pool.QueryRow(ctx,
		`SELECT from_addr, rcpt_addrs FROM outbound_queue WHERE message_id = $1`, counterUID,
	).Scan(&counterFrom, &counterRecipients); err != nil {
		t.Fatalf("read queued counter: %v", err)
	}
	if counterFrom != "attendee@test.local" || strings.Join(counterRecipients, ",") != "organizer@test.local" {
		t.Fatalf("queued counter = from %q recipients %v", counterFrom, counterRecipients)
	}
}
