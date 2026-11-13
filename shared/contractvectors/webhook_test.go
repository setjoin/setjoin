package contractvectors

import (
	"os"
	"testing"
	"time"

	"setjoin.com/shared/webhook"
)

func TestRecordWebhook(t *testing.T) {
	// Sign takes its timestamp from time.Now. The Go runtime faketime tag
	// fixes it without changing the frozen implementation or replaying its MAC.
	if os.Getenv("GOFREE_VECTOR_DIR") != "" && time.Now().Unix() != 1257894000 {
		t.Fatal("record webhook with go test -tags=faketime")
	}
	type input struct {
		Body   string `json:"body"`
		Secret string `json:"secret"`
		Unix   int64  `json:"unix"`
	}
	tests := []struct {
		name string
		in   input
	}{
		{"normal", input{Body: `{"event":"mail.received"}`, Secret: "0123456789abcdef0123456789abcdef", Unix: 1257894000}},
		{"empty_body", input{Body: "", Secret: "0123456789abcdef0123456789abcdef", Unix: 1257894000}},
		{"unicode_body", input{Body: "测试\n", Secret: "0123456789abcdef0123456789abcdef", Unix: 1257894000}},
		{"short_secret", input{Body: "x", Secret: "short", Unix: 1257894000}},
	}
	cases := make([]map[string]any, 0, len(tests))
	for _, tc := range tests {
		signature, err := webhook.Sign([]byte(tc.in.Body), tc.in.Secret)
		out := map[string]any{"signature": signature, "error": ""}
		if err != nil {
			out["error"] = err.Error()
		}
		cases = append(cases, map[string]any{"name": tc.name, "input": tc.in, "output": out})
	}
	writeVectors(t, "webhook", cases)
}
