package admin

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// threatQuerier is the query-layer interface used by ThreatHandler.
// The production implementation wraps *pgxpool.Pool; tests can inject a stub.
type threatQuerier interface {
	// QueryCount returns the total row count for the given SQL + args.
	QueryCount(ctx context.Context, sql string, args ...any) (int, error)
	// QueryRows executes the data query and returns rows that can be iterated.
	QueryRows(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// poolThreatQuerier is the production threatQuerier that delegates to pgxpool.
type poolThreatQuerier struct {
	pool *pgxpool.Pool
}

func (p *poolThreatQuerier) QueryCount(ctx context.Context, sql string, args ...any) (int, error) {
	var n int
	if err := p.pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (p *poolThreatQuerier) QueryRows(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return p.pool.Query(ctx, sql, args...)
}

// ThreatHandler serves the generic threat-flow read API for the admin console.
// It covers four read-only views over threat tables shared with the authserver:
// auth_attempts, auth_lockouts, threat_feed_blocks, rate_limit_counters.
type ThreatHandler struct {
	querier threatQuerier
	// lockoutsQuerier is the WORKER credential for the lockouts view. That
	// view reads ONLY through the worker-owned SECURITY DEFINER accessor
	// lockout_list (V259 deny-all FORCE RLS on auth_lockouts: the table has
	// zero policies and only setjoin_worker holds EXECUTE on the accessor),
	// so it needs the BYPASSRLS credential, not the request pool. nil falls
	// back to querier (unit tests; and the W1b INERT alias until
	// DB_WORKER_DSN is set).
	lockoutsQuerier threatQuerier
	logger          *slog.Logger
}

// NewThreatHandler constructs a ThreatHandler. pool backs the three
// table-backed views; worker (DB_WORKER_DSN, may be nil → aliases pool)
// backs the accessor-backed lockouts view.
func NewThreatHandler(pool *pgxpool.Pool, worker *pgxpool.Pool, logger *slog.Logger) *ThreatHandler {
	var q, wq threatQuerier
	if pool != nil {
		q = &poolThreatQuerier{pool: pool}
	}
	if worker != nil {
		wq = &poolThreatQuerier{pool: worker}
	}
	return &ThreatHandler{querier: q, lockoutsQuerier: wq, logger: logger}
}

// threatQueryParams holds the validated, sanitised query parameters for a
// single view request.
type threatQueryParams struct {
	limit  int
	offset int
	since  string // optional ISO-8601 interval, e.g. "24h" or "7 days"
	q      string // optional text filter (applied per-view)
	sort   string // allow-listed column name (empty = default)
	dir    string // ASC or DESC (validated)
}

// viewDef describes a single threat view: the SQL table, selectable columns,
// allow-listed sort columns, and the default ORDER BY expression.
type viewDef struct {
	table      string
	selectSQL  string // comma-separated column list for SELECT
	scanRow    func(row interface{ Scan(...any) error }) (map[string]any, error)
	sortCols   []string                                                     // allow-listed sort column names
	defaultOrd string                                                       // ORDER BY expression used when sort is absent or invalid
	filterFn   func(params threatQueryParams, args *[]any, idx *int) string // extra WHERE clauses
	csvHeaders []string                                                     // CSV column headers in SELECT order
	csvRow     func(row map[string]any) []string                            // converts a scanned row to CSV fields
	// usesAccessor routes the view through a worker-owned SECURITY DEFINER
	// accessor instead of the generic table SQL (the lockouts view reads
	// lockout_list — auth_lockouts is deny-all FORCE RLS under V259). The
	// accessor owns the ORDER BY and the page bounds: sortCols names the
	// columns it allow-lists and the validated column + direction ride to it
	// as bind parameters (resolveAccessorSort); defaultOrd/filterFn stay
	// inert because the q-filter and the default order live inside the
	// accessor too.
	usesAccessor bool
}

// viewRegistry maps url-path view name → viewDef.
var viewRegistry = map[string]viewDef{
	"attempts": {
		table: "auth_attempts",
		selectSQL: `host(source_ip::inet), target_username, protocol, outcome,
					COALESCE(failure_reason,''), COALESCE(geo_country,''), occurred_at`,
		sortCols:   []string{"occurred_at", "source_ip", "outcome"},
		defaultOrd: "occurred_at DESC",
		csvHeaders: []string{"source_ip", "target_username", "protocol", "outcome", "failure_reason", "geo_country", "occurred_at"},
		csvRow: func(row map[string]any) []string {
			return []string{
				fmt.Sprint(row["sourceIp"]),
				fmt.Sprint(row["targetUsername"]),
				fmt.Sprint(row["protocol"]),
				fmt.Sprint(row["outcome"]),
				fmt.Sprint(row["failureReason"]),
				fmt.Sprint(row["geoCountry"]),
				fmt.Sprint(row["occurredAt"]),
			}
		},
		filterFn: func(p threatQueryParams, args *[]any, idx *int) string {
			var clauses []string
			if p.since != "" {
				clauses = append(clauses, fmt.Sprintf("occurred_at >= now() - $%d::interval", *idx))
				*args = append(*args, p.since)
				(*idx)++
			}
			if p.q != "" {
				clauses = append(clauses, fmt.Sprintf(
					"(target_username ILIKE '%%' || $%d || '%%' OR source_ip::text ILIKE '%%' || $%d || '%%')",
					*idx, *idx))
				*args = append(*args, p.q)
				(*idx)++
			}
			return strings.Join(clauses, " AND ")
		},
		scanRow: func(row interface{ Scan(...any) error }) (map[string]any, error) {
			var sourceIP, username, protocol, outcome, failureReason, geoCountry string
			var occurredAt any
			if err := row.Scan(&sourceIP, &username, &protocol, &outcome, &failureReason, &geoCountry, &occurredAt); err != nil {
				return nil, err
			}
			return map[string]any{
				"sourceIp":       sourceIP,
				"targetUsername": username,
				"protocol":       protocol,
				"outcome":        outcome,
				"failureReason":  failureReason,
				"geoCountry":     geoCountry,
				"occurredAt":     occurredAt,
			}, nil
		},
	},
	"lockouts": {
		// V259 deny-all FORCE RLS: this view never addresses auth_lockouts
		// directly — runAccessorQuery reads the worker-owned SECURITY DEFINER
		// lockout_list accessor (same column set, ILIKE q-filter, allow-listed
		// sort applied before the page bounds) on the worker credential.
		// sortCols is the accessor's allow-list: the validated column + dir
		// ride to it as $4/$5 bind parameters (Astra impl-r2 P2: the fixed
		// locked_until DESC order silently dropped this view's supported
		// sorting).
		table:        "auth_lockouts",
		selectSQL:    "lockout_key, failed_count, locked_until, escalation_level, updated_at",
		sortCols:     []string{"locked_until", "failed_count", "updated_at"},
		defaultOrd:   "locked_until DESC",
		usesAccessor: true,
		csvHeaders:   []string{"lockout_key", "failed_count", "locked_until", "escalation_level", "updated_at"},
		csvRow: func(row map[string]any) []string {
			return []string{
				fmt.Sprint(row["lockoutKey"]),
				fmt.Sprint(row["failedCount"]),
				fmt.Sprint(row["lockedUntil"]),
				fmt.Sprint(row["escalationLevel"]),
				fmt.Sprint(row["updatedAt"]),
			}
		},
		filterFn: nil, // the ILIKE q-filter lives inside lockout_list now
		scanRow: func(row interface{ Scan(...any) error }) (map[string]any, error) {
			var lockoutKey string
			var failedCount, escalation int
			var lockedUntil, updatedAt any
			if err := row.Scan(&lockoutKey, &failedCount, &lockedUntil, &escalation, &updatedAt); err != nil {
				return nil, err
			}
			return map[string]any{
				"lockoutKey":      lockoutKey,
				"failedCount":     failedCount,
				"lockedUntil":     lockedUntil,
				"escalationLevel": escalation,
				"updatedAt":       updatedAt,
			}, nil
		},
	},
	"feed-blocks": {
		table:      "threat_feed_blocks",
		selectSQL:  "cidr::text AS cidr, source, added_at",
		sortCols:   []string{"added_at", "source"},
		defaultOrd: "added_at DESC",
		csvHeaders: []string{"cidr", "source", "added_at"},
		csvRow: func(row map[string]any) []string {
			return []string{
				fmt.Sprint(row["cidr"]),
				fmt.Sprint(row["source"]),
				fmt.Sprint(row["addedAt"]),
			}
		},
		filterFn: func(p threatQueryParams, args *[]any, idx *int) string {
			if p.q != "" {
				clause := fmt.Sprintf("(cidr::text ILIKE '%%' || $%d || '%%' OR source ILIKE '%%' || $%d || '%%')", *idx, *idx)
				*args = append(*args, p.q)
				(*idx)++
				return clause
			}
			return ""
		},
		scanRow: func(row interface{ Scan(...any) error }) (map[string]any, error) {
			var cidr, source string
			var addedAt any
			if err := row.Scan(&cidr, &source, &addedAt); err != nil {
				return nil, err
			}
			return map[string]any{
				"cidr":    cidr,
				"source":  source,
				"addedAt": addedAt,
			}, nil
		},
	},
	"rate-counters": {
		table:      "rate_limit_counters",
		selectSQL:  "key, count, window_start, blocked_until",
		sortCols:   []string{"count", "window_start", "blocked_until"},
		defaultOrd: "count DESC",
		csvHeaders: []string{"key", "count", "window_start", "blocked_until"},
		csvRow: func(row map[string]any) []string {
			return []string{
				fmt.Sprint(row["key"]),
				fmt.Sprint(row["count"]),
				fmt.Sprint(row["windowStart"]),
				fmt.Sprint(row["blockedUntil"]),
			}
		},
		filterFn: func(p threatQueryParams, args *[]any, idx *int) string {
			if p.q != "" {
				clause := fmt.Sprintf("key ILIKE '%%' || $%d || '%%'", *idx)
				*args = append(*args, p.q)
				(*idx)++
				return clause
			}
			return ""
		},
		scanRow: func(row interface{ Scan(...any) error }) (map[string]any, error) {
			var key string
			var count int
			var windowStart, blockedUntil any
			if err := row.Scan(&key, &count, &windowStart, &blockedUntil); err != nil {
				return nil, err
			}
			return map[string]any{
				"key":          key,
				"count":        count,
				"windowStart":  windowStart,
				"blockedUntil": blockedUntil,
			}, nil
		},
	},
}

// parseThreatParams validates and sanitises pagination + filter query params.
// Over-max limits clamp down to maxLimit (not the shared reset-to-default
// helper — this endpoint's contract is clamp-to-max).
func parseThreatParams(r *http.Request) threatQueryParams {
	const defaultLimit = 100
	const maxLimit = 500

	q := r.URL.Query()
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset, err := strconv.Atoi(q.Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	return threatQueryParams{
		limit:  limit,
		offset: offset,
		since:  q.Get("since"),
		q:      q.Get("q"),
		sort:   q.Get("sort"),
		dir:    q.Get("dir"),
	}
}

// resolveOrder returns a safe ORDER BY clause from the view definition.
// It allow-lists the sort column and direction — never string-concatenates
// user input directly (OWASP A03: Injection prevention).
func resolveOrder(def viewDef, params threatQueryParams) string {
	col := ""
	for _, allowed := range def.sortCols {
		if strings.EqualFold(params.sort, allowed) {
			col = allowed
			break
		}
	}
	if col == "" {
		return def.defaultOrd
	}
	dir := "ASC"
	if strings.EqualFold(params.dir, "DESC") {
		dir = "DESC"
	}
	return col + " " + dir
}

// resolveAccessorSort validates the requested sort column against the view's
// allow-list and returns the canonical column name and direction for the
// accessor-backed views. The pair is bound to the accessor as parameters —
// no user-controlled string ever reaches SQL text — and the accessor applies
// its own allow-list and default order to them (defense in depth). An absent
// or unknown sort returns "", "" so the accessor falls back to its documented
// default order (locked_until DESC for lockout_list).
func resolveAccessorSort(def viewDef, params threatQueryParams) (string, string) {
	col := ""
	for _, allowed := range def.sortCols {
		if strings.EqualFold(params.sort, allowed) {
			col = allowed
			break
		}
	}
	if col == "" {
		return "", ""
	}
	dir := "asc"
	if strings.EqualFold(params.dir, "desc") {
		dir = "desc"
	}
	return col, dir
}

// View implements GET /admin/threat/{view}.
// It dispatches to the registered view definition, builds a parameterised
// query, and returns {rows, total, limit, offset} (JSON) or text/csv when
// the format=csv query parameter is set.
func (h *ThreatHandler) View(w http.ResponseWriter, r *http.Request) {
	viewName := r.PathValue("view")
	def, ok := viewRegistry[viewName]
	if !ok {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem(
			"Unknown threat view: "+viewName+
				". Valid views: attempts, lockouts, feed-blocks, rate-counters."))
		return
	}

	params := parseThreatParams(r)

	// Nil querier: return an empty result set (unit-test / dev-mode safe).
	if h.querier == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"rows":   []any{},
			"total":  0,
			"limit":  params.limit,
			"offset": params.offset,
		})
		return
	}

	// CSV export path: when format=csv, stream CSV instead of JSON.
	if r.URL.Query().Get("format") == "csv" {
		h.viewCSV(w, r, viewName, def, params)
		return
	}

	rows, total, err := h.runQuery(r, def, params)
	if err != nil {
		h.logError("threat view query failed", viewName, err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"rows":   rows,
		"total":  total,
		"limit":  params.limit,
		"offset": params.offset,
	})
}

// viewCSV streams the threat view results as a CSV download.
func (h *ThreatHandler) viewCSV(w http.ResponseWriter, r *http.Request, viewName string, def viewDef, params threatQueryParams) {
	rows, _, err := h.runQuery(r, def, params)
	if err != nil {
		h.logError("threat csv query failed", viewName, err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	filename := fmt.Sprintf("threat-%s-%s.csv", viewName, time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Write CSV header row.
	if def.csvHeaders != nil {
		cw.Write(def.csvHeaders)
	}

	// Write data rows. Formula-injection guard: attack-derived cells
	// (source_ip, target_username, failure_reason, lockout_key, feed cidr and
	// source, rate-counter key) are neutralized at the writer seam
	// (admin_csv.go, migration.EscapeCSVCell) before serialization.
	for _, row := range rows {
		if def.csvRow != nil {
			cw.Write(escapeCSVCells(def.csvRow(row)))
		}
	}
}

// runQuery executes the COUNT(*) and paginated data query for a single view.
func (h *ThreatHandler) runQuery(r *http.Request, def viewDef, params threatQueryParams) ([]map[string]any, int, error) {
	ctx := r.Context()

	// Accessor-backed view (lockouts): read ONLY through the worker-owned
	// SECURITY DEFINER lockout_list accessor on the worker credential — the
	// underlying auth_lockouts table is deny-all FORCE RLS (V259) and must
	// never be addressed directly from the request pool.
	if def.usesAccessor {
		return h.runAccessorQuery(ctx, def, params)
	}

	// Build WHERE clause using the view's filter function.
	args := []any{}
	idx := 1
	whereClause := ""
	if def.filterFn != nil {
		whereClause = def.filterFn(params, &args, &idx)
	}
	where := "WHERE 1=1"
	if whereClause != "" {
		where += " AND " + whereClause
	}

	// COUNT query.
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", def.table, where)
	total, err := h.querier.QueryCount(ctx, countSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}

	// Data query.
	orderBy := resolveOrder(def, params)
	dataSQL := fmt.Sprintf(
		"SELECT %s FROM %s %s ORDER BY %s LIMIT $%d OFFSET $%d",
		def.selectSQL, def.table, where, orderBy, idx, idx+1,
	)
	args = append(args, params.limit, params.offset)

	pgRows, err := h.querier.QueryRows(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("data query: %w", err)
	}
	defer pgRows.Close()

	out := make([]map[string]any, 0)
	for pgRows.Next() {
		m, err := def.scanRow(pgRows)
		if err != nil {
			h.logError("scan row", def.table, err)
			continue
		}
		out = append(out, m)
	}
	if pgRows.Err() != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", pgRows.Err())
	}
	return out, total, nil
}

// runAccessorQuery serves an accessor-backed view: the count and the page
// both go through worker-owned SECURITY DEFINER accessors (lockout_count and
// lockout_list), executed on the worker credential (lockoutsQuerier, falling
// back to querier). The ILIKE q-filter lives inside the accessors, so the
// count must pass through one too — lockout_count has NO page bound, so
// total is the honest full filtered count even beyond lockout_list's 500-row
// page ceiling (Astra impl-r2 P2: counting a max page reported at most 500
// and pagination could never reach row 501). Sorting is validated against the
// view allow-list here and applied inside lockout_list BEFORE its page
// bounds (Astra impl-r2 P2: the fixed locked_until DESC silently dropped the
// view's supported sort). Order and page bounds remain accessor-owned.
func (h *ThreatHandler) runAccessorQuery(ctx context.Context, def viewDef, params threatQueryParams) ([]map[string]any, int, error) {
	q := h.lockoutsQuerier
	if q == nil {
		q = h.querier
	}

	// FULL filtered count — lockout_count applies the same ILIKE q-filter as
	// lockout_list with no LIMIT/OFFSET, so total is uncapped.
	total, err := q.QueryCount(ctx,
		`SELECT lockout_count($1::text)`,
		params.q)
	if err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}

	// Validated sort: bind parameters only — the accessor's CASE allow-list
	// maps the column/direction pair onto its ORDER BY (unknown sorts fall
	// back to locked_until DESC inside the accessor).
	sortCol, sortDir := resolveAccessorSort(def, params)

	// def.selectSQL is the compile-time-literal column list declared in
	// viewRegistry (same field the generic table path interpolates below);
	// every value rides $N bind parameters.
	dataSQL := "SELECT " + def.selectSQL +
		" FROM lockout_list($1::text, $2::int, $3::int, $4::text, $5::text)"
	pgRows, err := q.QueryRows(ctx, dataSQL, params.q, params.limit, params.offset, sortCol, sortDir)
	if err != nil {
		return nil, 0, fmt.Errorf("data query: %w", err)
	}
	defer pgRows.Close()

	out := make([]map[string]any, 0)
	for pgRows.Next() {
		m, err := def.scanRow(pgRows)
		if err != nil {
			h.logError("scan row", def.table, err)
			continue
		}
		out = append(out, m)
	}
	if pgRows.Err() != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", pgRows.Err())
	}
	return out, total, nil
}

// logError logs an error, silently ignoring a nil logger.
func (h *ThreatHandler) logError(msg, view string, err error) {
	if h.logger != nil {
		h.logger.Error(msg, "view", view, "error", err)
	}
}
