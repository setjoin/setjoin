package mailwork

import (
	"context"
	"errors"
	"strings"
	"testing"

	wh "setjoin.com/shared/webhook"
)

type captureWebhook struct{ event wh.CloudEvent }

func (c *captureWebhook) EnqueueDurable(_ context.Context, event wh.CloudEvent) error {
	c.event = event
	return nil
}

func TestBoundedError(t *testing.T) {
	if got := boundedError(nil); got != "" {
		t.Fatalf("nil error = %q", got)
	}
	got := boundedError(errors.New(strings.Repeat("x", 3000)))
	if len(got) != 2048 {
		t.Fatalf("bounded error length = %d", len(got))
	}
}

func TestValidConsumerIncludesOnlyImplementedDispatchers(t *testing.T) {
	for _, consumer := range []string{"push", "digest", "metric", "webhook", "task", "chat", "drive"} {
		if !validConsumer(consumer) {
			t.Fatalf("consumer %q rejected", consumer)
		}
	}
	for _, consumer := range []string{"", "email", "shell", "TASK"} {
		if validConsumer(consumer) {
			t.Fatalf("unimplemented consumer %q accepted", consumer)
		}
	}
}

func TestDispatchWebhookUsesApprovedTypeAndSafeProjection(t *testing.T) {
	capture := &captureWebhook{}
	w := &Worker{webhooks: capture}
	err := w.dispatchWebhook(context.Background(), claim{EventID: "event-1", Consumer: "webhook", Payload: map[string]any{
		"mailboxId": "42", "threadId": "thread-1", "eventType": "completed", "generation": "3",
		"subject": "must not leave", "comment": "private",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if capture.event.Type != wh.EventMailWorkCompleted || capture.event.ID != "event-1" {
		t.Fatalf("unexpected event: %#v", capture.event)
	}
	data, ok := capture.event.Data.(map[string]any)
	if !ok {
		t.Fatalf("data type = %T", capture.event.Data)
	}
	if _, present := data["subject"]; present {
		t.Fatal("subject leaked")
	}
	if _, present := data["comment"]; present {
		t.Fatal("comment leaked")
	}
	if len(data) != 5 {
		t.Fatalf("safe field count = %d", len(data))
	}
}

func TestDispatchWebhookRejectsUnapprovedEvent(t *testing.T) {
	w := &Worker{webhooks: &captureWebhook{}}
	if err := w.dispatchWebhook(context.Background(), claim{EventID: "event-2", Payload: map[string]any{"eventType": "commented"}}); err == nil {
		t.Fatal("unapproved event accepted")
	}
}
