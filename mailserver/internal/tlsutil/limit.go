package tlsutil

import (
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/net/netutil"
)

// ErrLimitExceeded is returned by ConnTracker.TryAcquire when the per-user
// connection limit is reached.
var ErrLimitExceeded = errors.New("per-user connection limit exceeded")

// LimitListener returns a Listener that accepts at most n simultaneous
// connections from the provided Listener. Connections beyond the limit
// queue until a slot is released. Closing the returned listener unblocks
// any pending Accept.
func LimitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		return l
	}
	return netutil.LimitListener(l, n)
}

// ConnTracker limits concurrent connections per authenticated user.
// Zero maxConns means unlimited. Safe for concurrent use.
type ConnTracker struct {
	maxConns atomic.Int32 // 0 = unlimited
	users    sync.Map     // map[int64]*int32
}

// SetMaxConns sets the per-user connection limit. 0 = unlimited.
func (ct *ConnTracker) SetMaxConns(n int) {
	// Clamp into int32 before storing: a config value that overflows int32
	// must not wrap and flip sign (a huge positive could become negative,
	// which TryAcquire reads as "unlimited"). Negative stays negative
	// (unlimited); above the int32 ceiling saturates to the max limit.
	switch {
	case n < 0:
		ct.maxConns.Store(-1)
	case n > math.MaxInt32:
		ct.maxConns.Store(math.MaxInt32)
	default:
		ct.maxConns.Store(int32(n)) //nolint:gosec // G115: bounded to [0, MaxInt32] by the clamp above
	}
}

// TryAcquire attempts to acquire a connection slot for the given user.
// Returns (release, nil) on success, or (nil, error) if the limit is exceeded.
// The caller must call release when the connection closes.
func (ct *ConnTracker) TryAcquire(userID int64) (func(), error) {
	limit := ct.maxConns.Load()
	if limit <= 0 {
		return func() {}, nil
	}
	val, _ := ct.users.LoadOrStore(userID, new(int32))
	count := atomic.AddInt32(val.(*int32), 1)
	if count > limit {
		atomic.AddInt32(val.(*int32), -1)
		return nil, ErrLimitExceeded
	}
	release := func() { atomic.AddInt32(val.(*int32), -1) }
	return release, nil
}
