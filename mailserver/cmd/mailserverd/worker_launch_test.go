package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestLaunchWorkerLogsExactlyOnceAndPreservesContext(t *testing.T) {
	var logs synchronizedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan context.Context, 1)
	returned := make(chan struct{})

	launchWorker(ctx, logger, "fixture", func(got context.Context) {
		started <- got
		<-got.Done()
		close(returned)
	})

	select {
	case got := <-started:
		if got != ctx {
			t.Fatal("launchWorker replaced the caller context")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not reach worker")
	}

	deadline := time.Now().Add(time.Second)
	for strings.Count(logs.String(), `"worker":"fixture"`) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := strings.Count(logs.String(), `"msg":"background worker started"`); got != 1 {
		t.Fatalf("start log count = %d, want 1; logs=%s", got, logs.String())
	}
	if got := strings.Count(logs.String(), `"msg":"background worker returned"`); got != 1 {
		t.Fatalf("return log count = %d, want 1; logs=%s", got, logs.String())
	}
}

func TestLaunchWorkerEvaluatesRunBeforeStartingGoroutine(t *testing.T) {
	constructed := false
	makeRun := func() func(context.Context) {
		constructed = true
		return func(context.Context) {}
	}
	launchWorker(context.Background(), slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "fixture", makeRun())
	if !constructed {
		t.Fatal("run method value was not evaluated synchronously")
	}
}

func TestLaunchWorkerDoesNotRecoverPanic(t *testing.T) {
	if os.Getenv("SETJOIN_WORKER_PANIC_FIXTURE") == "1" {
		launchWorker(context.Background(), slog.Default(), "panic-fixture", func(context.Context) {
			panic("worker panic sentinel")
		})
		time.Sleep(5 * time.Second)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLaunchWorkerDoesNotRecoverPanic$")
	cmd.Env = append(os.Environ(), "SETJOIN_WORKER_PANIC_FIXTURE=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("worker panic was recovered; output=%s", out)
	}
	if !bytes.Contains(out, []byte("worker panic sentinel")) {
		t.Fatalf("subprocess failed without the worker panic; output=%s", out)
	}
}

func TestLaunchWorkerHonorsWorkersOff(t *testing.T) {
	t.Setenv("GO_WORKERS_OFF", "cron, mail-work, user-risk, cert-monitor, tls-ticket-keys ")
	started := make(chan string, 6)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	for _, name := range []string{"cron", "mail-work", "user-risk", "cert-monitor", "tls-ticket-keys", "booking-expiry"} {
		name := name
		launchWorker(context.Background(), logger, name, func(context.Context) { started <- name })
	}
	select {
	case name := <-started:
		if name != "booking-expiry" {
			t.Fatalf("disabled worker %q started", name)
		}
	case <-time.After(time.Second):
		t.Fatal("enabled worker did not start")
	}
	select {
	case name := <-started:
		t.Fatalf("disabled worker %q started", name)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStartWorkerPreservesSynchronousStartup(t *testing.T) {
	for _, tc := range []struct {
		off  string
		want bool
	}{{"", true}, {" , unknown,webhook-retry-extra", true}, {" webhook-retry , webhook-retry ", false}} {
		t.Run(tc.off, func(t *testing.T) {
			t.Setenv("GO_WORKERS_OFF", tc.off)
			ctx := context.WithValue(context.Background(), struct{}{}, "startup")
			started := false
			startWorker(ctx, "webhook-retry", func(got context.Context) {
				if got != ctx {
					t.Fatal("startup context replaced")
				}
				started = true
			})
			if started != tc.want {
				t.Fatalf("started=%v, want %v before returning", started, tc.want)
			}
		})
	}
}
