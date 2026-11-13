package smtp

// MAILSERVERD-004 (owner decision D3), Astra impl-d3 HOLD round 2: the live
// MAIL delivery paths must carry the CONFIGURED link-protect key set, not a
// single pinned secret. These tests exercise exactly the two live seams:
//
//   - inbound delivery rewrite: RewriteMessageBodyN is the delegate
//     inbound.go's delivery pipeline calls with the server's configured key
//     set — tokens minted AFTER a rotation must carry the CURRENT key version
//     (the pre-fix path minted v1 tokens that matched neither key once the
//     handler was wired for {new/v2, old/v1});
//   - outbound egress un-rewrite: OutboundWorker.unwrapForwardLinks is the
//     deliverOne head outbound.go calls for forwarded copies — redirects
//     delivered under either generation must un-rewrite during the overlap
//     window, current-generation ones keep un-rewriting after the drain, and
//     old-generation ones stay inert (in place) once it is drained.

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/shared/pgxutil"
)

// Rotation fixtures, deliberately distinct from each other so every assertion
// proves secret AND version independence.
var (
	lprOldSecret = []byte("smtp-rotation-retiring-secret-32byte!")
	lprNewSecret = []byte("smtp-rotation-current-secret-32bytes!")
)

func lprTransition() linkprotect.TokenKeys {
	return linkprotect.TokenKeys{Secret: lprNewSecret, Version: 2, PreviousSecret: lprOldSecret}
}

func lprDrained() linkprotect.TokenKeys {
	return linkprotect.TokenKeys{Secret: lprNewSecret, Version: 2}
}

func lprPlainMessage(body string) []byte {
	return []byte("From: sender@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"Subject: smtp rotation\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + body)
}

func lprNewWorker(keys linkprotect.TokenKeys) *OutboundWorker {
	w := NewOutboundWorker(pgxutil.WorkerPool{}, slog.New(slog.NewTextHandler(io.Discard, nil)), "bucket", nil, nil)
	w.SetLinkProtectKeys(keys)
	return w
}

// TestOutboundWorker_UnwrapForwardLinks_RotationArms drives the live egress
// un-rewrite seam (deliverOne's forward-unwrap head) through the rotation
// arms. Messages are rewritten by the LIVE inbound seam (RewriteMessageBodyN),
// exactly the shape stored bodies carry.
func TestOutboundWorker_UnwrapForwardLinks_RotationArms(t *testing.T) {
	rewrite := func(t *testing.T, keys linkprotect.TokenKeys, url string) string {
		t.Helper()
		out, n, err := RewriteMessageBodyN(lprPlainMessage("see "+url+" now"), keys, nil, "msg-fw", 7)
		if err != nil || n != 1 {
			t.Fatalf("live inbound rewrite: n=%d err=%v", n, err)
		}
		return string(out)
	}

	// Pre-rotation delivery (v1 token) and post-rotation delivery (v2 token).
	oldMsg := rewrite(t, linkprotect.TokenKeys{Secret: lprOldSecret}, "https://example.com/old-key")
	newMsg := rewrite(t, lprTransition(), "https://example.com/new-key")

	item := queueItem{messageID: "<fw@test>"}

	t.Run("transition-window-unrewrites-both-generations", func(t *testing.T) {
		w := lprNewWorker(lprTransition())
		for name, msg := range map[string]string{"old": oldMsg, "new": newMsg} {
			out, n := w.unwrapForwardLinks(item, msg)
			if n != 1 || strings.Contains(out, "/link-protect?token=") {
				t.Fatalf("%s-generation redirect must un-rewrite during the window (n=%d):\n%s", name, n, out)
			}
		}
		if out, _ := w.unwrapForwardLinks(item, oldMsg); !strings.Contains(out, "https://example.com/old-key") {
			t.Fatalf("transition unwrap must restore the original URL:\n%s", out)
		}
	})

	t.Run("drained-unrewrites-only-current-generation", func(t *testing.T) {
		w := lprNewWorker(lprDrained())
		out, n := w.unwrapForwardLinks(item, newMsg)
		if n != 1 || !strings.Contains(out, "https://example.com/new-key") {
			t.Fatalf("current-generation redirect must keep un-rewriting after the drain (n=%d):\n%s", n, out)
		}
		out, n = w.unwrapForwardLinks(item, oldMsg)
		if n != 0 || out != oldMsg {
			t.Fatalf("old-generation redirect must stay inert after the drain (n=%d)", n)
		}
	})

	t.Run("pre-rotation-worker-unrewrites-only-v1", func(t *testing.T) {
		// The version-1 default (SetLinkProtectSecret shorthand): pre-rotation
		// behavior is byte-identical, and rotated tokens are left alone.
		w := lprNewWorker(linkprotect.TokenKeys{Secret: lprOldSecret})
		out, n := w.unwrapForwardLinks(item, oldMsg)
		if n != 1 || strings.Contains(out, "/link-protect?token=") {
			t.Fatalf("v1 redirect must still un-rewrite pre-rotation (n=%d)", n)
		}
		out, n = w.unwrapForwardLinks(item, newMsg)
		if n != 0 || out != newMsg {
			t.Fatalf("v2 token must not verify under the v1-only worker (n=%d)", n)
		}
	})

	t.Run("no-keys-wired-leaves-message-unchanged", func(t *testing.T) {
		w := lprNewWorker(linkprotect.TokenKeys{})
		out, n := w.unwrapForwardLinks(item, oldMsg)
		if n != 0 || out != oldMsg {
			t.Fatalf("unwired worker must leave the message unchanged (n=%d)", n)
		}
	})
}

// TestInboundRewriteDelegate_MintsCurrentVersionDuringRotation pins the live
// inbound seam's sign behavior: a token minted by RewriteMessageBodyN under
// the rotated key set verifies by the CURRENT key alone (surviving the drain)
// and does NOT verify under the version-1 derivation of the new secret — the
// exact neither-key failure the unwired threading produced.
func TestInboundRewriteDelegate_MintsCurrentVersionDuringRotation(t *testing.T) {
	rewritten, n, err := RewriteMessageBodyN(lprPlainMessage("see https://example.com/minted-after-rotation now"), lprTransition(), nil, "msg-in", 7)
	if err != nil || n != 1 {
		t.Fatalf("live inbound rewrite: n=%d err=%v", n, err)
	}

	// Pull the token out of the delivered body the way the click handler sees it.
	const marker = "/link-protect?token="
	idx := strings.Index(string(rewritten), marker)
	if idx < 0 {
		t.Fatalf("rewritten body carries no redirect:\n%s", rewritten)
	}
	token := string(rewritten[idx+len(marker):])
	if end := strings.IndexAny(token, " \r\n"); end >= 0 {
		token = token[:end]
	}

	if _, err := linkprotect.VerifyTokenN(token, lprDrained()); err != nil {
		t.Fatalf("delivered token must verify after the window drains: %v", err)
	}
	if _, err := linkprotect.VerifyTokenN(token, linkprotect.TokenKeys{Secret: lprNewSecret}); err == nil {
		t.Fatal("delivered token must NOT verify as a version-1 token of the new secret")
	}
}
