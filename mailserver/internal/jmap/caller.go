package jmap

import (
	"setjoin.com/mailserver/internal/reducercall"
)

// reducerCaller is the JMAP gateway's seam for invoking a reducer. The deep
// implementation (Call / CallScoped → buildReducerSQL → pool.QueryRow + Scan)
// now lives in the shared internal/reducercall package so CalDAV/CardDAV can
// route through the same seam; this is an alias kept for the 57 in-package call
// sites + tests. See reducercall.Caller for the full contract.
type reducerCaller = reducercall.Caller
