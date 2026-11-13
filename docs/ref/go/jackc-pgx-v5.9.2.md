package pgxpool // import "github.com/jackc/pgx/v5/pgxpool"

Package pgxpool is a concurrency-safe connection pool for pgx.

pgxpool implements a nearly identical interface to pgx connections.

# Creating a Pool

The primary way of creating a pool is with pgxpool.New:

    pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))

The database connection string can be in URL or keyword/value format. PostgreSQL
settings, pgx settings, and pool settings can be specified here. In addition,
a config struct can be created by ParseConfig.

    config, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
    if err != nil {
        // ...
    }
    config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
        // do something with every new connection
    }

    pool, err := pgxpool.NewWithConfig(context.Background(), config)

A pool returns without waiting for any connections to be established. Acquire
a connection immediately after creating the pool to check if a connection can
successfully be established.

TYPES

type AcquireTracer interface {
	// TraceAcquireStart is called at the beginning of Acquire.
	// The returned context is used for the rest of the call and will be passed to the TraceAcquireEnd.
	TraceAcquireStart(ctx context.Context, pool *Pool, data TraceAcquireStartData) context.Context
	// TraceAcquireEnd is called when a connection has been acquired.
	TraceAcquireEnd(ctx context.Context, pool *Pool, data TraceAcquireEndData)
}
    AcquireTracer traces Acquire.

type Config struct {
	ConnConfig *pgx.ConnConfig

	// BeforeConnect is called before a new connection is made. It is passed a copy of the underlying [pgx.ConnConfig] and
	// will not impact any existing open connections.
	BeforeConnect func(context.Context, *pgx.ConnConfig) error

	// AfterConnect is called after a connection is established, but before it is added to the pool.
	AfterConnect func(context.Context, *pgx.Conn) error

	// BeforeAcquire is called before a connection is acquired from the pool. It must return true to allow the
	// acquisition or false to indicate that the connection should be destroyed and a different connection should be
	// acquired.
	//
	// Deprecated: Use PrepareConn instead. If both PrepareConn and BeforeAcquire are set, PrepareConn will take
	// precedence, ignoring BeforeAcquire.
	BeforeAcquire func(context.Context, *pgx.Conn) bool

	// PrepareConn is called before a connection is acquired from the pool. If this function returns true, the connection
	// is considered valid, otherwise the connection is destroyed. If the function returns a non-nil error, the instigating
	// query will fail with the returned error.
	//
	// Specifically, this means that:
	//
	//	- If it returns true and a nil error, the query proceeds as normal.
	//	- If it returns true and an error, the connection will be returned to the pool, and the instigating query will fail with the returned error.
	//	- If it returns false, and an error, the connection will be destroyed, and the query will fail with the returned error.
	//	- If it returns false and a nil error, the connection will be destroyed, and the instigating query will be retried on a new connection.
	PrepareConn func(context.Context, *pgx.Conn) (bool, error)

	// AfterRelease is called after a connection is released, but before it is returned to the pool. It must return true to
	// return the connection to the pool or false to destroy the connection.
	AfterRelease func(*pgx.Conn) bool

	// BeforeClose is called right before a connection is closed and removed from the pool.
	BeforeClose func(*pgx.Conn)

	// ShouldPing is called after a connection is acquired from the pool. If it returns true, the connection is pinged to check for liveness.
	// If this func is not set, the default behavior is to ping connections that have been idle for at least 1 second.
	ShouldPing func(context.Context, ShouldPingParams) bool

	// MaxConnLifetime is the duration since creation after which a connection will be automatically closed.
	MaxConnLifetime time.Duration

	// MaxConnLifetimeJitter is the duration after MaxConnLifetime to randomly decide to close a connection.
	// This helps prevent all connections from being closed at the exact same time, starving the pool.
	MaxConnLifetimeJitter time.Duration

	// MaxConnIdleTime is the duration after which an idle connection will be automatically closed by the health check.
	MaxConnIdleTime time.Duration

	// PingTimeout is the maximum amount of time to wait for a connection to pong before considering it as unhealthy and
	// destroying it. If zero, the default is no timeout.
	PingTimeout time.Duration

	// MaxConns is the maximum size of the pool. The default is the greater of 4 or runtime.NumCPU().
	MaxConns int32

	// MinConns is the minimum size of the pool. After connection closes, the pool might dip below MinConns. A low
	// number of MinConns might mean the pool is empty after MaxConnLifetime until the health check has a chance
	// to create new connections.
	MinConns int32

	// MinIdleConns is the minimum number of idle connections in the pool. You can increase this to ensure that
	// there are always idle connections available. This can help reduce tail latencies during request processing,
	// as you can avoid the latency of establishing a new connection while handling requests. It is superior
	// to MinConns for this purpose.
	// Similar to MinConns, the pool might temporarily dip below MinIdleConns after connection closes.
	MinIdleConns int32

	// HealthCheckPeriod is the duration between checks of the health of idle connections.
	HealthCheckPeriod time.Duration

	// Has unexported fields.
}
    Config is the configuration struct for creating a pool. It must be created
    by ParseConfig and then it can be modified.

func ParseConfig(connString string) (*Config, error)
    ParseConfig builds a Config from connString. It parses connString with
    the same behavior as pgx.ParseConfig with the addition of the following
    variables:

      - pool_max_conns: integer greater than 0 (default 4)
      - pool_min_conns: integer 0 or greater (default 0)
      - pool_max_conn_lifetime: duration string (default 1 hour)
      - pool_max_conn_idle_time: duration string (default 30 minutes)
      - pool_health_check_period: duration string (default 1 minute)
      - pool_max_conn_lifetime_jitter: duration string (default 0)

    See Config for definitions of these arguments.

        # Example Keyword/Value
        user=jack password=secret host=pg.example.com port=5432 dbname=mydb sslmode=verify-ca pool_max_conns=10 pool_max_conn_lifetime=1h30m

        # Example URL
        postgres://jack:secret@pg.example.com:5432/mydb?sslmode=verify-ca&pool_max_conns=10&pool_max_conn_lifetime=1h30m

func (c *Config) ConnString() string
    ConnString returns the connection string as parsed by pgxpool.ParseConfig
    into pgxpool.Config.

func (c *Config) Copy() *Config
    Copy returns a deep copy of the config that is safe to use and modify.
    The only exception is the tls.Config: according to the tls.Config docs it
    must not be modified after creation.

type Conn struct {
	// Has unexported fields.
}
    Conn is an acquired *pgx.Conn from a Pool.

func (c *Conn) Begin(ctx context.Context) (pgx.Tx, error)
    Begin starts a transaction block from the *Conn without explicitly setting
    a transaction mode (see BeginTx with TxOptions if transaction mode is
    required).

func (c *Conn) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
    BeginTx starts a transaction block from the *Conn with txOptions determining
    the transaction mode.

func (c *Conn) Conn() *pgx.Conn

func (c *Conn) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)

func (c *Conn) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)

func (c *Conn) Hijack() *pgx.Conn
    Hijack assumes ownership of the connection from the pool. Caller is
    responsible for closing the connection. Hijack will panic if called on an
    already released or hijacked connection.

func (c *Conn) Ping(ctx context.Context) error

func (c *Conn) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)

func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row

func (c *Conn) Release()
    Release returns c to the pool it was acquired from. Once Release has been
    called, other methods must not be called. However, it is safe to call
    Release multiple times. Subsequent calls after the first will be ignored.

func (c *Conn) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults

type Pool struct {
	// Has unexported fields.
}
    Pool allows for connection reuse.

func New(ctx context.Context, connString string) (*Pool, error)
    New creates a new Pool. See ParseConfig for information on connString
    format.

func NewWithConfig(ctx context.Context, config *Config) (*Pool, error)
    NewWithConfig creates a new Pool. config must have been created by
    ParseConfig.

func (p *Pool) Acquire(ctx context.Context) (c *Conn, err error)
    Acquire returns a connection (Conn) from the Pool.

func (p *Pool) AcquireAllIdle(ctx context.Context) []*Conn
    AcquireAllIdle atomically acquires all currently idle connections. Its
    intended use is for health check and keep-alive functionality. It does not
    update pool statistics.

func (p *Pool) AcquireFunc(ctx context.Context, f func(*Conn) error) error
    AcquireFunc acquires a Conn and calls f with that Conn. ctx will only affect
    the Pool.Acquire. It has no effect on the call of f. The return value is
    either an error acquiring the Conn or the return value of f. The Conn is
    automatically released after the call of f.

func (p *Pool) Begin(ctx context.Context) (pgx.Tx, error)
    Begin acquires a connection from the Pool and starts a transaction.
    Unlike database/sql, the context only affects the begin command. i.e. there
    is no auto-rollback on context cancellation. Begin initiates a transaction
    block without explicitly setting a transaction mode for the block (see
    Pool.BeginTx with pgx.TxOptions if transaction mode is required). *Tx is
    returned, which implements the pgx.Tx interface. Tx.Commit or Tx.Rollback
    must be called on the returned transaction to finalize the transaction
    block.

func (p *Pool) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
    BeginTx acquires a connection from the Pool and starts a transaction with
    pgx.TxOptions determining the transaction mode. Unlike database/sql,
    the context only affects the begin command. i.e. there is no auto-rollback
    on context cancellation. *Tx is returned, which implements the pgx.Tx
    interface. Tx.Commit or Tx.Rollback must be called on the returned
    transaction to finalize the transaction block.

func (p *Pool) Close()
    Close closes all connections in the pool and rejects future Pool.Acquire
    calls. Blocks until all connections are returned to pool and closed.

func (p *Pool) Config() *Config
    Config returns a copy of config that was used to initialize this Pool.

func (p *Pool) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)

func (p *Pool) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
    Exec acquires a connection from the Pool and executes the given SQL. SQL
    can be either a prepared statement name or an SQL string. Arguments should
    be referenced positionally from the SQL string as $1, $2, etc. The acquired
    connection is returned to the pool when the Pool.Exec function returns.

func (p *Pool) Ping(ctx context.Context) error
    Ping acquires a connection from the Pool and executes an empty sql statement
    against it. If the sql returns without error, the database Pool.Ping is
    considered successful, otherwise, the error is returned.

func (p *Pool) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
    Query acquires a connection and executes a query that returns pgx.Rows.
    Arguments should be referenced positionally from the SQL string as $1, $2,
    etc. See pgx.Rows documentation to close the returned pgx.Rows and return
    the acquired connection to the Pool.

    If there is an error, the returned pgx.Rows will be returned in an error
    state. If preferred, ignore the error returned from Pool.Query and handle
    errors using the returned pgx.Rows.

    For extra control over how the query is executed, the types
    pgx.QueryExecMode, pgx.QueryResultFormats, and pgx.QueryResultFormatsByOID
    may be used as the first args to control exactly how the query is executed.
    This is rarely needed. See the documentation for those types for details.

func (p *Pool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
    QueryRow acquires a connection and executes a query that is expected to
    return at most one row (pgx.Row). Errors are deferred until pgx.Row's Scan
    method is called. If the query selects no rows, pgx.Row's Scan will return
    pgx.ErrNoRows. Otherwise, pgx.Row's Scan scans the first selected row and
    discards the rest. The acquired connection is returned to the Pool when
    pgx.Row's Scan method is called.

    Arguments should be referenced positionally from the SQL string as $1, $2,
    etc.

    For extra control over how the query is executed, the types
    pgx.QueryExecMode, pgx.QueryResultFormats, and pgx.QueryResultFormatsByOID
    may be used as the first args to control exactly how the query is executed.
    This is rarely needed. See the documentation for those types for details.

func (p *Pool) Reset()
    Reset closes all connections, but leaves the pool open. It is intended for
    use when an error is detected that would disrupt all connections (such as a
    network interruption or a server state change).

    It is safe to reset a pool while connections are checked out. Those
    connections will be closed when they are returned to the pool.

func (p *Pool) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults

func (p *Pool) Stat() *Stat
    Stat returns a pgxpool.Stat struct with a snapshot of Pool statistics.

type ReleaseTracer interface {
	// TraceRelease is called at the beginning of Release.
	TraceRelease(pool *Pool, data TraceReleaseData)
}
    ReleaseTracer traces Release.

type ShouldPingParams struct {
	Conn         *pgx.Conn
	IdleDuration time.Duration
}
    ShouldPingParams are the parameters passed to ShouldPing.

type Stat struct {
	// Has unexported fields.
}
    Stat is a snapshot of Pool statistics.

func (s *Stat) AcquireCount() int64
    AcquireCount returns the cumulative count of successful acquires from the
    pool.

func (s *Stat) AcquireDuration() time.Duration
    AcquireDuration returns the total duration of all successful acquires from
    the pool.

func (s *Stat) AcquiredConns() int32
    AcquiredConns returns the number of currently acquired connections in the
    pool.

func (s *Stat) CanceledAcquireCount() int64
    CanceledAcquireCount returns the cumulative count of acquires from the pool
    that were canceled by a context.

func (s *Stat) ConstructingConns() int32
    ConstructingConns returns the number of conns with construction in progress
    in the pool.

func (s *Stat) EmptyAcquireCount() int64
    EmptyAcquireCount returns the cumulative count of successful acquires from
    the pool that waited for a resource to be released or constructed because
    the pool was empty.

func (s *Stat) EmptyAcquireWaitTime() time.Duration
    EmptyAcquireWaitTime returns the cumulative time waited for successful
    acquires from the pool for a resource to be released or constructed because
    the pool was empty.

func (s *Stat) IdleConns() int32
    IdleConns returns the number of currently idle conns in the pool.

func (s *Stat) MaxConns() int32
    MaxConns returns the maximum size of the pool.

func (s *Stat) MaxIdleDestroyCount() int64
    MaxIdleDestroyCount returns the cumulative count of connections destroyed
    because they exceeded MaxConnIdleTime.

func (s *Stat) MaxLifetimeDestroyCount() int64
    MaxLifetimeDestroyCount returns the cumulative count of connections
    destroyed because they exceeded MaxConnLifetime.

func (s *Stat) NewConnsCount() int64
    NewConnsCount returns the cumulative count of new connections opened.

func (s *Stat) TotalConns() int32
    TotalConns returns the total number of resources currently in the pool.
    The value is the sum of ConstructingConns, AcquiredConns, and IdleConns.

type TraceAcquireEndData struct {
	Conn *pgx.Conn
	Err  error
}

type TraceAcquireStartData struct{}

type TraceReleaseData struct {
	Conn *pgx.Conn
}

type Tx struct {
	// Has unexported fields.
}
    Tx represents a database transaction acquired from a Pool.

func (tx *Tx) Begin(ctx context.Context) (pgx.Tx, error)
    Begin starts a pseudo nested transaction implemented with a savepoint.

func (tx *Tx) Commit(ctx context.Context) error
    Commit commits the transaction and returns the associated connection back to
    the Pool. Commit will return an error where errors.Is(ErrTxClosed) is true
    if the Tx is already closed, but is otherwise safe to call multiple times.
    If the commit fails with a rollback status (e.g. the transaction was already
    in a broken state) then ErrTxCommitRollback will be returned.

func (tx *Tx) Conn() *pgx.Conn

func (tx *Tx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)

func (tx *Tx) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)

func (tx *Tx) LargeObjects() pgx.LargeObjects

func (tx *Tx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error)
    Prepare creates a prepared statement with name and sql. If the name is
    empty, an anonymous prepared statement will be used. sql can contain
    placeholders for bound parameters. These placeholders are referenced
    positionally as $1, $2, etc.

    Prepare is idempotent; i.e. it is safe to call Prepare multiple times with
    the same name and sql arguments. This allows a code path to Prepare and
    Query/Exec without needing to first check whether the statement has already
    been prepared.

func (tx *Tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)

func (tx *Tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row

func (tx *Tx) Rollback(ctx context.Context) error
    Rollback rolls back the transaction and returns the associated
    connection back to the Pool. Rollback will return where an error where
    errors.Is(ErrTxClosed) is true if the Tx is already closed, but is otherwise
    safe to call multiple times. Hence, defer tx.Rollback() is safe even if
    tx.Commit() will be called first in a non-error condition.

func (tx *Tx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults

package pgx // import "github.com/jackc/pgx/v5"

Package pgx is a PostgreSQL database driver.

pgx provides a native PostgreSQL driver and can act as a database/sql/driver.
The native PostgreSQL interface is similar to the database/sql interface
while providing better speed and access to PostgreSQL specific features. Use
github.com/jackc/pgx/v5/stdlib to use pgx as a database/sql compatible driver.
See that package's documentation for details.

# Establishing a Connection

The primary way of establishing a connection is with pgx.Connect:

    conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))

The database connection string can be in URL or key/value format. Both
PostgreSQL settings and pgx settings can be specified here. In addition,
a config struct can be created by ParseConfig and modified before establishing
the connection with ConnectConfig to configure settings such as tracing that
cannot be configured with a connection string.

# Connection Pool

*pgx.Conn represents a single connection to the database and is not concurrency
safe. Use package github.com/jackc/pgx/v5/pgxpool for a concurrency safe
connection pool.

# Query Interface

pgx implements Conn.Query in the familiar database/sql style. However,
pgx provides generic functions such as CollectRows and ForEachRow that are a
simpler and safer way of processing rows than manually calling defer Rows.Close,
Rows.Next, Rows.Scan, and Rows.Err.

CollectRows can be used collect all returned rows into a slice.

    rows, _ := conn.Query(context.Background(), "select generate_series(1,$1)", 5)
    numbers, err := pgx.CollectRows(rows, pgx.RowTo[int32])
    if err != nil {
      return err
    }
    // numbers => [1 2 3 4 5]

ForEachRow can be used to execute a callback function for every row. This is
often easier than iterating over rows directly.

    var sum, n int32
    rows, _ := conn.Query(context.Background(), "select generate_series(1,$1)", 10)
    _, err := pgx.ForEachRow(rows, []any{&n}, func() error {
      sum += n
      return nil
    })
    if err != nil {
      return err
    }

pgx also implements Conn.QueryRow in the same style as database/sql.

    var name string
    var weight int64
    err := conn.QueryRow(context.Background(), "select name, weight from widgets where id=$1", 42).Scan(&name, &weight)
    if err != nil {
        return err
    }

Use Conn.Exec to execute a query that does not return a result set.

    commandTag, err := conn.Exec(context.Background(), "delete from widgets where id=$1", 42)
    if err != nil {
        return err
    }
    if commandTag.RowsAffected() != 1 {
        return errors.New("No row found to delete")
    }

# PostgreSQL Data Types

pgx uses the pgtype package to converting Go values to and from PostgreSQL
values. It supports many PostgreSQL types directly and is customizable and
extendable. User defined data types such as enums, domains, and composite types
may require type registration. See that package's documentation for details.

# Transactions

Transactions are started by calling Conn.Begin.

    tx, err := conn.Begin(context.Background())
    if err != nil {
        return err
    }
    // Rollback is safe to call even if the tx is already closed, so if
    // the tx commits successfully, this is a no-op
    defer tx.Rollback(context.Background())

    _, err = tx.Exec(context.Background(), "insert into foo(id) values (1)")
    if err != nil {
        return err
    }

    err = tx.Commit(context.Background())
    if err != nil {
        return err
    }

The Tx returned from Conn.Begin also implements the Tx.Begin method. This can be
used to implement pseudo nested transactions. These are internally implemented
with savepoints.

Use Conn.BeginTx to control the transaction mode. Conn.BeginTx also can be used
to ensure a new transaction is created instead of a pseudo nested transaction.

BeginFunc and BeginTxFunc are functions that begin a transaction, execute a
function, and commit or rollback the transaction depending on the return value
of the function. These can be simpler and less error prone to use.

    err = pgx.BeginFunc(context.Background(), conn, func(tx pgx.Tx) error {
        _, err := tx.Exec(context.Background(), "insert into foo(id) values (1)")
        return err
    })
    if err != nil {
        return err
    }

# Prepared Statements

Prepared statements can be manually created with the Conn.Prepare method.
However, this is rarely necessary because pgx includes an automatic statement
cache by default. Queries run through the normal Conn.Query, Conn.QueryRow,
and Conn.Exec functions are automatically prepared on first execution and the
prepared statement is reused on subsequent executions. See ParseConfig for
information on how to customize or disable the statement cache.

# Copy Protocol

Use Conn.CopyFrom to efficiently insert multiple rows at a time using the
PostgreSQL copy protocol. Conn.CopyFrom accepts a CopyFromSource interface. If
the data is already in a [][]any use CopyFromRows to wrap it in a CopyFromSource
interface. Or implement CopyFromSource to avoid buffering the entire data set in
memory.

    rows := [][]any{
        {"John", "Smith", int32(36)},
        {"Jane", "Doe", int32(29)},
    }

    copyCount, err := conn.CopyFrom(
        context.Background(),
        pgx.Identifier{"people"},
        []string{"first_name", "last_name", "age"},
        pgx.CopyFromRows(rows),
    )

When you already have a typed array using CopyFromSlice can be more convenient.

    rows := []User{
        {"John", "Smith", 36},
        {"Jane", "Doe", 29},
    }

    copyCount, err := conn.CopyFrom(
        context.Background(),
        pgx.Identifier{"people"},
        []string{"first_name", "last_name", "age"},
        pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
            return []any{rows[i].FirstName, rows[i].LastName, rows[i].Age}, nil
        }),
    )

CopyFrom can be faster than an insert with as few as 5 rows.

# Listen and Notify

pgx can listen to the PostgreSQL notification system with the
Conn.WaitForNotification method. It blocks until a notification is received or
the context is canceled.

    _, err := conn.Exec(context.Background(), "listen channelname")
    if err != nil {
        return err
    }

    notification, err := conn.WaitForNotification(context.Background())
    if err != nil {
        return err
    }
    // do something with notification

# Tracing and Logging

pgx supports tracing by setting ConnConfig.Tracer. To combine several tracers
you can use the github.com/jackc/pgx/v5/multitracer.Tracer.

In addition, the github.com/jackc/pgx/v5/tracelog package provides the
github.com/jackc/pgx/v5/tracelog.TraceLog type which lets a traditional logger
act as a QueryTracer.

For debug tracing of the actual PostgreSQL wire protocol messages see
github.com/jackc/pgx/v5/pgproto3.

# Lower Level PostgreSQL Functionality

github.com/jackc/pgx/v5/pgconn contains a lower level PostgreSQL driver
roughly at the level of libpq. Conn is implemented on top of pgconn.PgConn.
The Conn.PgConn method can be used to access this lower layer.

# PgBouncer

By default pgx automatically uses prepared statements. Prepared statements
are incompatible with PgBouncer. This can be disabled by setting a different
QueryExecMode in ConnConfig.DefaultQueryExecMode.

CONSTANTS

const (
	TextFormatCode   = 0
	BinaryFormatCode = 1
)
    PostgreSQL format codes


VARIABLES

var (
	// ErrNoRows occurs when rows are expected but none are returned.
	ErrNoRows = newProxyErr(sql.ErrNoRows, "no rows in result set")
	// ErrTooManyRows occurs when more rows than expected are returned.
	ErrTooManyRows = errors.New("too many rows in result set")
)
var ErrTxClosed = errors.New("tx is closed")
var ErrTxCommitRollback = errors.New("commit unexpectedly resulted in rollback")
    ErrTxCommitRollback occurs when an error has occurred in a transaction and
    Commit() is called. PostgreSQL accepts COMMIT on aborted transactions,
    but it is treated as ROLLBACK.


FUNCTIONS

func AppendRows[T any, S ~[]T](slice S, rows Rows, fn RowToFunc[T]) (S, error)
    AppendRows iterates through rows, calling fn for each row, and appending the
    results into a slice of T.

    This function closes the rows automatically on return.

func BeginFunc(
	ctx context.Context,
	db interface {
		Begin(ctx context.Context) (Tx, error)
	},
	fn func(Tx) error,
) (err error)
    BeginFunc calls Begin on db and then calls fn. If fn does not return
    an error then it calls Tx.Commit on db. If fn returns an error it calls
    Tx.Rollback on db. The context will be used when executing the transaction
    control statements (BEGIN, ROLLBACK, and COMMIT) but does not otherwise
    affect the execution of fn.

func BeginTxFunc(
	ctx context.Context,
	db interface {
		BeginTx(ctx context.Context, txOptions TxOptions) (Tx, error)
	},
	txOptions TxOptions,
	fn func(Tx) error,
) (err error)
    BeginTxFunc calls BeginTx on db and then calls fn. If fn does not return
    an error then it calls Tx.Commit on db. If fn returns an error it calls
    Tx.Rollback on db. The context will be used when executing the transaction
    control statements (BEGIN, ROLLBACK, and COMMIT) but does not otherwise
    affect the execution of fn.

func CollectExactlyOneRow[T any](rows Rows, fn RowToFunc[T]) (T, error)
    CollectExactlyOneRow calls fn for the first row in rows and returns the
    result.
      - If no rows are found returns an error where errors.Is(ErrNoRows) is
        true.
      - If more than 1 row is found returns an error where
        errors.Is(ErrTooManyRows) is true.

    This function closes the rows automatically on return.

func CollectOneRow[T any](rows Rows, fn RowToFunc[T]) (T, error)
    CollectOneRow calls fn for the first row in rows and returns the result.
    If no rows are found returns an error where errors.Is(ErrNoRows) is true.
    CollectOneRow is to CollectRows as Conn.QueryRow is to Conn.Query.

    This function closes the rows automatically on return.

func CollectRows[T any](rows Rows, fn RowToFunc[T]) ([]T, error)
    CollectRows iterates through rows, calling fn for each row, and collecting
    the results into a slice of T.

    This function closes the rows automatically on return.

func ForEachRow(rows Rows, scans []any, fn func() error) (pgconn.CommandTag, error)
    ForEachRow iterates through rows. For each row it scans into the elements
    of scans and calls fn. If any row fails to scan or fn returns an error the
    query will be aborted and the error will be returned. Rows will be closed
    when ForEachRow returns.

func RowTo[T any](row CollectableRow) (T, error)
    RowTo returns a T scanned from row.

func RowToAddrOf[T any](row CollectableRow) (*T, error)
    RowToAddrOf returns the address of a T scanned from row.

func RowToAddrOfStructByName[T any](row CollectableRow) (*T, error)
    RowToAddrOfStructByName returns the address of a T scanned from row.
    T must be a struct. T must have the same number of named public fields as
    row has fields. The row and T fields will be matched by name. The match is
    case-insensitive. The database column name can be overridden with a "db"
    struct tag. If the "db" struct tag is "-" then the field will be ignored.

func RowToAddrOfStructByNameLax[T any](row CollectableRow) (*T, error)
    RowToAddrOfStructByNameLax returns the address of a T scanned from row.
    T must be a struct. T must have greater than or equal number of named public
    fields as row has fields. The row and T fields will be matched by name.
    The match is case-insensitive. The database column name can be overridden
    with a "db" struct tag. If the "db" struct tag is "-" then the field will be
    ignored.

func RowToAddrOfStructByPos[T any](row CollectableRow) (*T, error)
    RowToAddrOfStructByPos returns the address of a T scanned from row. T must
    be a struct. T must have the same number a public fields as row has fields.
    The row and T fields will be matched by position. If the "db" struct tag is
    "-" then the field will be ignored.

func RowToMap(row CollectableRow) (map[string]any, error)
    RowToMap returns a map scanned from row.

func RowToStructByName[T any](row CollectableRow) (T, error)
    RowToStructByName returns a T scanned from row. T must be a struct.
    T must have the same number of named public fields as row has fields.
    The row and T fields will be matched by name. The match is case-insensitive.
    The database column name can be overridden with a "db" struct tag. If the
    "db" struct tag is "-" then the field will be ignored.

func RowToStructByNameLax[T any](row CollectableRow) (T, error)
    RowToStructByNameLax returns a T scanned from row. T must be a struct.
    T must have greater than or equal number of named public fields as row
    has fields. The row and T fields will be matched by name. The match is
    case-insensitive. The database column name can be overridden with a "db"
    struct tag. If the "db" struct tag is "-" then the field will be ignored.

func RowToStructByPos[T any](row CollectableRow) (T, error)
    RowToStructByPos returns a T scanned from row. T must be a struct.
    T must have the same number of public fields as row has fields. The row and
    T fields will be matched by position. If the "db" struct tag is "-" then the
    field will be ignored.

func ScanRow(typeMap *pgtype.Map, fieldDescriptions []pgconn.FieldDescription, values [][]byte, dest ...any) error
    ScanRow decodes raw row data into dest. It can be used to scan rows read
    from the lower level pgconn interface.

    typeMap - OID to Go type mapping. fieldDescriptions - OID and format of
    values values - the raw data as returned from the PostgreSQL server dest -
    the destination that values will be decoded into


TYPES

type Batch struct {
	QueuedQueries []*QueuedQuery
}
    Batch queries are a way of bundling multiple queries together to avoid
    unnecessary network round trips. A Batch must only be sent once.

func (b *Batch) Len() int
    Len returns number of queries that have been queued so far.

func (b *Batch) Queue(query string, arguments ...any) *QueuedQuery
    Queue queues a query to batch b. query can be an SQL query or the
    name of a prepared statement. The only pgx option argument that is
    supported is QueryRewriter. Queries are executed using the connection's
    DefaultQueryExecMode (see ConnConfig.DefaultQueryExecMode).

    While query can contain multiple statements if the connection's
    DefaultQueryExecMode is QueryExecModeSimpleProtocol, this should be
    avoided. QueuedQuery.Fn must not be set as it will only be called for
    the first query. That is, QueuedQuery.Query, QueuedQuery.QueryRow,
    and QueuedQuery.Exec must not be called. In addition, any error messages or
    tracing that include the current query may reference the wrong query.

type BatchResults interface {
	// Exec reads the results from the next query in the batch as if the query has been sent with [Conn.Exec]. Prefer
	// calling Exec on the QueuedQuery, or just calling Close.
	Exec() (pgconn.CommandTag, error)

	// Query reads the results from the next query in the batch as if the query has been sent with [Conn.Query]. Prefer
	// calling [QueuedQuery.Query].
	Query() (Rows, error)

	// QueryRow reads the results from the next query in the batch as if the query has been sent with [Conn.QueryRow].
	// Prefer calling [QueuedQuery.QueryRow].
	QueryRow() Row

	// Close closes the batch operation. All unread results are read and any callback functions registered with
	// [QueuedQuery.Query], [QueuedQuery.QueryRow], or [QueuedQuery.Exec] will be called. If a callback function returns an
	// error or the batch encounters an error subsequent callback functions will not be called.
	//
	// For simple batch inserts inside a transaction or similar queries, it's sufficient to not set any callbacks,
	// and just handle the return value of Close.
	//
	// Close must be called before the underlying connection can be used again. Any error that occurred during a batch
	// operation may have made it impossible to resyncronize the connection with the server. In this case the underlying
	// connection will have been closed.
	//
	// Close is safe to call multiple times. If it returns an error subsequent calls will return the same error. Callback
	// functions will not be rerun.
	Close() error
}

type BatchTracer interface {
	// TraceBatchStart is called at the beginning of SendBatch calls. The returned context is used for the
	// rest of the call and will be passed to TraceBatchQuery and TraceBatchEnd.
	TraceBatchStart(ctx context.Context, conn *Conn, data TraceBatchStartData) context.Context

	TraceBatchQuery(ctx context.Context, conn *Conn, data TraceBatchQueryData)
	TraceBatchEnd(ctx context.Context, conn *Conn, data TraceBatchEndData)
}
    BatchTracer traces SendBatch.

type CollectableRow interface {
	FieldDescriptions() []pgconn.FieldDescription
	Scan(dest ...any) error
	Values() ([]any, error)
	RawValues() [][]byte
}
    CollectableRow is the subset of Rows methods that a RowToFunc is allowed to
    call.

type Conn struct {
	// Has unexported fields.
}
    Conn is a PostgreSQL connection handle. It is not safe for concurrent usage.
    Use a connection pool to manage access to multiple database connections from
    multiple goroutines.

func Connect(ctx context.Context, connString string) (*Conn, error)
    Connect establishes a connection with a PostgreSQL server with a connection
    string. See pgconn.Connect for details.

func ConnectConfig(ctx context.Context, connConfig *ConnConfig) (*Conn, error)
    ConnectConfig establishes a connection with a PostgreSQL server with a
    configuration struct. connConfig must have been created by ParseConfig.

func ConnectWithOptions(ctx context.Context, connString string, options ParseConfigOptions) (*Conn, error)
    ConnectWithOptions behaves exactly like Connect with the addition
    of options. At the present options is only used to provide a
    pgconn.GetSSLPasswordFunc function.

func (c *Conn) Begin(ctx context.Context) (Tx, error)
    Begin starts a transaction. Unlike database/sql, the context only affects
    the begin command. i.e. there is no auto-rollback on context cancellation.

func (c *Conn) BeginTx(ctx context.Context, txOptions TxOptions) (Tx, error)
    BeginTx starts a transaction with txOptions determining the transaction
    mode. Unlike database/sql, the context only affects the begin command. i.e.
    there is no auto-rollback on context cancellation.

func (c *Conn) Close(ctx context.Context) error
    Close closes a connection. It is safe to call Close on an already closed
    connection.

func (c *Conn) Config() *ConnConfig
    Config returns a copy of config that was used to establish this connection.

func (c *Conn) CopyFrom(ctx context.Context, tableName Identifier, columnNames []string, rowSrc CopyFromSource) (int64, error)
    CopyFrom uses the PostgreSQL copy protocol to perform bulk data insertion.
    It returns the number of rows copied and an error.

    CopyFrom requires all values use the binary format. A pgtype.Type that
    supports the binary format must be registered for the type of each column.
    Almost all types implemented by pgx support the binary format.

    Even though enum types appear to be strings they still must be registered
    to use with Conn.CopyFrom. This can be done with Conn.LoadType and
    pgtype.Map.RegisterType.

func (c *Conn) Deallocate(ctx context.Context, name string) error
    Deallocate releases a prepared statement. Calling Deallocate on a
    non-existent prepared statement will succeed.

func (c *Conn) DeallocateAll(ctx context.Context) error
    DeallocateAll releases all previously prepared statements from the server
    and client, where it also resets the statement and description cache.

func (c *Conn) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
    Exec executes sql. sql can be either a prepared statement name or an SQL
    string. arguments should be referenced positionally from the sql string as
    $1, $2, etc.

func (c *Conn) IsClosed() bool
    IsClosed reports if the connection has been closed.

func (c *Conn) LoadType(ctx context.Context, typeName string) (*pgtype.Type, error)
    LoadType inspects the database for typeName and produces a pgtype.Type
    suitable for registration. typeName must be the name of a type where the
    underlying type(s) is already understood by pgx. It is for derived types.
    In particular, typeName must be one of the following:
      - An array type name of a type that is already registered. e.g. "_foo"
        when "foo" is registered.
      - A composite type name where all field types are already registered.
      - A domain type name where the base type is already registered.
      - An enum type name.
      - A range type name where the element type is already registered.
      - A multirange type name where the element type is already registered.

func (c *Conn) LoadTypes(ctx context.Context, typeNames []string) ([]*pgtype.Type, error)
    LoadTypes performs a single (complex) query, returning all the required
    information to register the named types, as well as any other types directly
    or indirectly required to complete the registration. The result of this call
    can be passed into RegisterTypes to complete the process.

func (c *Conn) PgConn() *pgconn.PgConn
    PgConn returns the underlying *pgconn.PgConn. This is an escape hatch
    method that allows lower level access to the PostgreSQL connection than pgx
    exposes.

    It is strongly recommended that the connection be idle (no in-progress
    queries) before the underlying *pgconn.PgConn is used and the connection
    must be returned to the same state before any *pgx.Conn methods are again
    used.

func (c *Conn) Ping(ctx context.Context) error
    Ping delegates to the underlying *pgconn.PgConn.Ping.

func (c *Conn) Prepare(ctx context.Context, name, sql string) (sd *pgconn.StatementDescription, err error)
    Prepare creates a prepared statement with name and sql. sql can contain
    placeholders for bound parameters. These placeholders are referenced
    positionally as $1, $2, etc. name can be used instead of sql with
    Conn.Query, Conn.QueryRow, and Conn.Exec to execute the statement. It can
    also be used with Batch.Queue.

    The underlying PostgreSQL identifier for the prepared statement will be name
    if name != sql or a digest of sql if name == sql.

    Prepare is idempotent; i.e. it is safe to call Prepare multiple times with
    the same name and sql arguments. This allows a code path to Prepare and
    Query/Exec without concern for if the statement has already been prepared.

func (c *Conn) Query(ctx context.Context, sql string, args ...any) (Rows, error)
    Query sends a query to the server and returns a Rows to read the results.
    Only errors encountered sending the query and initializing Rows will be
    returned. Err() on the returned Rows must be checked after the Rows is
    closed to determine if the query executed successfully.

    The returned Rows must be closed before the connection can be used again.
    It is safe to attempt to read from the returned Rows even if an error is
    returned. The error will be the available in rows.Err() after rows are
    closed. It is allowed to ignore the error returned from Query and handle it
    in Rows.

    It is possible for a call of FieldDescriptions on the returned Rows to
    return nil even if the Query call did not return an error.

    It is possible for a query to return one or more rows before encountering
    an error. In most cases the rows should be collected before processing
    rather than processed while receiving each row. This avoids the possibility
    of the application processing rows from a query that the server rejected.
    The CollectRows function is useful here.

    An implementor of QueryRewriter may be passed as the first element of args.
    It can rewrite the sql and change or replace args. For example, NamedArgs is
    QueryRewriter that implements named arguments.

    For extra control over how the query is executed, the types QueryExecMode,
    QueryResultFormats, and QueryResultFormatsByOID may be used as the first
    args to control exactly how the query is executed. This is rarely needed.
    See the documentation for those types for details.

func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) Row
    QueryRow is a convenience wrapper over Query. Any error that occurs while
    querying is deferred until calling Scan on the returned Row. That Row will
    error with ErrNoRows if no rows are returned.

func (c *Conn) SendBatch(ctx context.Context, b *Batch) (br BatchResults)
    SendBatch sends all queued queries to the server at once. All queries
    are run in an implicit transaction unless explicit transaction control
    statements are executed. The returned BatchResults must be closed before the
    connection is used again.

    Depending on the QueryExecMode, all queries may be prepared before any are
    executed. This means that creating a table and using it in a subsequent
    query in the same batch can fail.

func (c *Conn) TypeMap() *pgtype.Map
    TypeMap returns the connection info used for this connection.

func (c *Conn) WaitForNotification(ctx context.Context) (*pgconn.Notification, error)
    WaitForNotification waits for a PostgreSQL notification. It wraps the
    underlying pgconn notification system in a slightly more convenient form.

type ConnConfig struct {
	pgconn.Config

	Tracer QueryTracer

	// StatementCacheCapacity is maximum size of the statement cache used when executing a query with "cache_statement"
	// query exec mode.
	StatementCacheCapacity int

	// DescriptionCacheCapacity is the maximum size of the description cache used when executing a query with
	// "cache_describe" query exec mode.
	DescriptionCacheCapacity int

	// DefaultQueryExecMode controls the default mode for executing queries. By default pgx uses the extended protocol
	// and automatically prepares and caches prepared statements. However, this may be incompatible with proxies such as
	// PGBouncer. In this case it may be preferable to use [QueryExecModeExec] or [QueryExecModeSimpleProtocol]. The same
	// functionality can be controlled on a per query basis by passing a [QueryExecMode] as the first query argument.
	DefaultQueryExecMode QueryExecMode

	// Has unexported fields.
}
    ConnConfig contains all the options used to establish a connection.
    It must be created by ParseConfig and then it can be modified. A manually
    initialized ConnConfig will cause ConnectConfig to panic.

func ParseConfig(connString string) (*ConnConfig, error)
    ParseConfig creates a ConnConfig from a connection string. ParseConfig
    handles all options that pgconn.ParseConfig does. In addition, it accepts
    the following options:

      - default_query_exec_mode. Possible values: "cache_statement",
        "cache_describe", "describe_exec", "exec", and "simple_protocol". See
        QueryExecMode constant documentation for the meaning of these values.
        Default: "cache_statement".

      - statement_cache_capacity. The maximum size of the statement cache used
        when executing a query with "cache_statement" query exec mode. Default:
        512.

      - description_cache_capacity. The maximum size of the description cache
        used when executing a query with "cache_describe" query exec mode.
        Default: 512.

func ParseConfigWithOptions(connString string, options ParseConfigOptions) (*ConnConfig, error)
    ParseConfigWithOptions behaves exactly as ParseConfig does with the
    addition of options. At the present options is only used to provide a
    pgconn.GetSSLPasswordFunc function.

func (cc *ConnConfig) ConnString() string
    ConnString returns the connection string as parsed by pgx.ParseConfig into
    pgx.ConnConfig.

func (cc *ConnConfig) Copy() *ConnConfig
    Copy returns a deep copy of the config that is safe to use and modify.
    The only exception is the tls.Config: according to the tls.Config docs it
    must not be modified after creation.

type ConnectTracer interface {
	// TraceConnectStart is called at the beginning of Connect and ConnectConfig calls. The returned context is used for
	// the rest of the call and will be passed to TraceConnectEnd.
	TraceConnectStart(ctx context.Context, data TraceConnectStartData) context.Context

	TraceConnectEnd(ctx context.Context, data TraceConnectEndData)
}
    ConnectTracer traces Connect and ConnectConfig.

type CopyFromSource interface {
	// Next returns true if there is another row and makes the next row data
	// available to Values(). When there are no more rows available or an error
	// has occurred it returns false.
	Next() bool

	// Values returns the values for the current row.
	Values() ([]any, error)

	// Err returns any error that has been encountered by the CopyFromSource. If
	// this is not nil *Conn.CopyFrom will abort the copy.
	Err() error
}
    CopyFromSource is the interface used by Conn.CopyFrom as the source for copy
    data.

func CopyFromFunc(nxtf func() (row []any, err error)) CopyFromSource
    CopyFromFunc returns a CopyFromSource interface that relies on nxtf for
    values. nxtf returns rows until it either signals an 'end of data' by
    returning row=nil and err=nil, or it returns an error. If nxtf returns an
    error, the copy is aborted.

func CopyFromRows(rows [][]any) CopyFromSource
    CopyFromRows returns a CopyFromSource interface over the provided rows slice
    making it usable by Conn.CopyFrom.

func CopyFromSlice(length int, next func(int) ([]any, error)) CopyFromSource
    CopyFromSlice returns a CopyFromSource interface over a dynamic func making
    it usable by Conn.CopyFrom.

type CopyFromTracer interface {
	// TraceCopyFromStart is called at the beginning of CopyFrom calls. The returned context is used for the
	// rest of the call and will be passed to TraceCopyFromEnd.
	TraceCopyFromStart(ctx context.Context, conn *Conn, data TraceCopyFromStartData) context.Context

	TraceCopyFromEnd(ctx context.Context, conn *Conn, data TraceCopyFromEndData)
}
    CopyFromTracer traces CopyFrom.

type ErrPreprocessingBatch struct {
	// Has unexported fields.
}
    ErrPreprocessingBatch occurs when an error is encountered while
    preprocessing a batch. The two preprocessing steps are "prepare"
    (server-side SQL parse/plan) and "build" (client-side argument encoding).

func (e ErrPreprocessingBatch) Error() string

func (e ErrPreprocessingBatch) SQL() string

func (e ErrPreprocessingBatch) Unwrap() error

type ExtendedQueryBuilder struct {
	ParamValues [][]byte

	ParamFormats  []int16
	ResultFormats []int16
	// Has unexported fields.
}
    ExtendedQueryBuilder is used to choose the parameter formats, to format the
    parameters and to choose the result formats for an extended query.

func (eqb *ExtendedQueryBuilder) Build(m *pgtype.Map, sd *pgconn.StatementDescription, args []any) error
    Build sets ParamValues, ParamFormats, and ResultFormats for use
    with *PgConn.ExecParams or *PgConn.ExecPrepared. If sd is nil then
    QueryExecModeExec behavior will be used.

type Identifier []string
    Identifier a PostgreSQL identifier or name. Identifiers can be composed of
    multiple parts such as ["schema", "table"] or ["table", "column"].

func (ident Identifier) Sanitize() string
    Sanitize returns a sanitized string safe for SQL interpolation.

type LargeObject struct {
	// Has unexported fields.
}
    A LargeObject is a large object stored on the server. It is only valid
    within the transaction that it was initialized in. It uses the context it
    was initialized with for all operations. It implements these interfaces:

        io.Writer
        io.Reader
        io.Seeker
        io.Closer

func (o *LargeObject) Close() error
    Close the large object descriptor.

func (o *LargeObject) Read(p []byte) (int, error)
    Read reads up to len(p) bytes into p returning the number of bytes read.

func (o *LargeObject) Seek(offset int64, whence int) (n int64, err error)
    Seek moves the current location pointer to the new location specified by
    offset.

func (o *LargeObject) Tell() (n int64, err error)
    Tell returns the current read or write location of the large object
    descriptor.

func (o *LargeObject) Truncate(size int64) (err error)
    Truncate the large object to size.

func (o *LargeObject) Write(p []byte) (int, error)
    Write writes p to the large object and returns the number of bytes written
    and an error if not all of p was written.

type LargeObjectMode int32

const (
	LargeObjectModeWrite LargeObjectMode = 0x20000
	LargeObjectModeRead  LargeObjectMode = 0x40000
)
type LargeObjects struct {
	// Has unexported fields.
}
    LargeObjects is a structure used to access the large objects API. It is only
    valid within the transaction where it was created.

    For more details see:
    http://www.postgresql.org/docs/current/static/largeobjects.html

func (o *LargeObjects) Create(ctx context.Context, oid uint32) (uint32, error)
    Create creates a new large object. If oid is zero, the server assigns an
    unused OID.

func (o *LargeObjects) Open(ctx context.Context, oid uint32, mode LargeObjectMode) (*LargeObject, error)
    Open opens an existing large object with the given mode. ctx will also be
    used for all operations on the opened large object.

func (o *LargeObjects) Unlink(ctx context.Context, oid uint32) error
    Unlink removes a large object from the database.

type NamedArgs map[string]any
    NamedArgs can be used as the first argument to a query method. It will
    replace every '@' named placeholder with a '$' ordinal placeholder and
    construct the appropriate arguments.

    For example, the following two queries are equivalent:

        conn.Query(ctx, "select * from widgets where foo = @foo and bar = @bar", pgx.NamedArgs{"foo": 1, "bar": 2})
        conn.Query(ctx, "select * from widgets where foo = $1 and bar = $2", 1, 2)

    Named placeholders are case sensitive and must start with a letter or
    underscore. Subsequent characters can be letters, numbers, or underscores.

func (na NamedArgs) RewriteQuery(ctx context.Context, conn *Conn, sql string, args []any) (newSQL string, newArgs []any, err error)
    RewriteQuery implements the QueryRewriter interface.

type ParseConfigOptions struct {
	pgconn.ParseConfigOptions
}
    ParseConfigOptions contains options that control how a config is built such
    as getsslpassword.

type PrepareTracer interface {
	// TracePrepareStart is called at the beginning of Prepare calls. The returned context is used for the
	// rest of the call and will be passed to TracePrepareEnd.
	TracePrepareStart(ctx context.Context, conn *Conn, data TracePrepareStartData) context.Context

	TracePrepareEnd(ctx context.Context, conn *Conn, data TracePrepareEndData)
}
    PrepareTracer traces Prepare.

type QueryExecMode int32

const (

	// Automatically prepare and cache statements. This uses the extended protocol. Queries are executed in a single round
	// trip after the statement is cached. This is the default. If the database schema is modified or the search_path is
	// changed after a statement is cached then the first execution of a previously cached query may fail. e.g. If the
	// number of columns returned by a "SELECT *" changes or the type of a column is changed.
	QueryExecModeCacheStatement QueryExecMode

	// Cache statement descriptions (i.e. argument and result types) and assume they do not change. This uses the extended
	// protocol. Queries are executed in a single round trip after the description is cached. If the database schema is
	// modified or the search_path is changed after a statement is cached then the first execution of a previously cached
	// query may fail. e.g. If the number of columns returned by a "SELECT *" changes or the type of a column is changed.
	QueryExecModeCacheDescribe

	// Get the statement description on every execution. This uses the extended protocol. Queries require two round trips
	// to execute. It does not use named prepared statements. But it does use the unnamed prepared statement to get the
	// statement description on the first round trip and then uses it to execute the query on the second round trip. This
	// may cause problems with connection poolers that switch the underlying connection between round trips. It is safe
	// even when the database schema is modified concurrently.
	QueryExecModeDescribeExec

	// Assume the PostgreSQL query parameter types based on the Go type of the arguments. This uses the extended protocol
	// with text formatted parameters and results. Queries are executed in a single round trip. Type mappings can be
	// registered with pgtype.Map.RegisterDefaultPgType. Queries will be rejected that have arguments that are
	// unregistered or ambiguous. e.g. A map[string]string may have the PostgreSQL type json or hstore. Modes that know
	// the PostgreSQL type can use a map[string]string directly as an argument. This mode cannot.
	//
	// On rare occasions user defined types may behave differently when encoded in the text format instead of the binary
	// format. For example, this could happen if a "type RomanNumeral int32" implements fmt.Stringer to format integers as
	// Roman numerals (e.g. 7 is VII). The binary format would properly encode the integer 7 as the binary value for 7.
	// But the text format would encode the integer 7 as the string "VII". As QueryExecModeExec uses the text format, it
	// is possible that changing query mode from another mode to QueryExecModeExec could change the behavior of the query.
	// This should not occur with types pgx supports directly and can be avoided by registering the types with
	// pgtype.Map.RegisterDefaultPgType and implementing the appropriate type interfaces. In the cas of RomanNumeral, it
	// should implement pgtype.Int64Valuer.
	QueryExecModeExec

	// Use the simple protocol. Assume the PostgreSQL query parameter types based on the Go type of the arguments. This is
	// especially significant for []byte values. []byte values are encoded as PostgreSQL bytea. string must be used
	// instead for text type values including json and jsonb. Type mappings can be registered with
	// pgtype.Map.RegisterDefaultPgType. Queries will be rejected that have arguments that are unregistered or ambiguous.
	// e.g. A map[string]string may have the PostgreSQL type json or hstore. Modes that know the PostgreSQL type can use a
	// map[string]string directly as an argument. This mode cannot. Queries are executed in a single round trip.
	//
	// QueryExecModeSimpleProtocol should have the user application visible behavior as QueryExecModeExec. This includes
	// the warning regarding differences in text format and binary format encoding with user defined types. There may be
	// other minor exceptions such as behavior when multiple result returning queries are erroneously sent in a single
	// string.
	//
	// QueryExecModeSimpleProtocol uses client side parameter interpolation. All values are quoted and escaped. Prefer
	// QueryExecModeExec over QueryExecModeSimpleProtocol whenever possible. In general QueryExecModeSimpleProtocol should
	// only be used if connecting to a proxy server, connection pool server, or non-PostgreSQL server that does not
	// support the extended protocol.
	QueryExecModeSimpleProtocol
)
func (m QueryExecMode) String() string

type QueryResultFormats []int16
    QueryResultFormats controls the result format (text=0, binary=1) of a query
    by result column position.

type QueryResultFormatsByOID map[uint32]int16
    QueryResultFormatsByOID controls the result format (text=0, binary=1) of a
    query by the result column OID.

type QueryRewriter interface {
	RewriteQuery(ctx context.Context, conn *Conn, sql string, args []any) (newSQL string, newArgs []any, err error)
}
    QueryRewriter rewrites a query when used as the first arguments to a query
    method.

type QueryTracer interface {
	// TraceQueryStart is called at the beginning of Query, QueryRow, and Exec calls. The returned context is used for the
	// rest of the call and will be passed to TraceQueryEnd.
	TraceQueryStart(ctx context.Context, conn *Conn, data TraceQueryStartData) context.Context

	TraceQueryEnd(ctx context.Context, conn *Conn, data TraceQueryEndData)
}
    QueryTracer traces Query, QueryRow, and Exec.

type QueuedQuery struct {
	SQL       string
	Arguments []any
	Fn        batchItemFunc
	// Has unexported fields.
}
    QueuedQuery is a query that has been queued for execution via a Batch.

func (qq *QueuedQuery) Exec(fn func(ct pgconn.CommandTag) error)
    Exec sets fn to be called when the response to qq is received.

    Note: for simple batch insert uses where it is not required to handle each
    potential error individually, it's sufficient to not set any callbacks,
    and just handle the return value of BatchResults.Close.

func (qq *QueuedQuery) Query(fn func(rows Rows) error)
    Query sets fn to be called when the response to qq is received.

func (qq *QueuedQuery) QueryRow(fn func(row Row) error)
    Query sets fn to be called when the response to qq is received.

type Row interface {
	// Scan works the same as Rows. with the following exceptions. If no
	// rows were found it returns ErrNoRows. If multiple rows are returned it
	// ignores all but the first.
	Scan(dest ...any) error
}
    Row is a convenience wrapper over Rows that is returned by Conn.QueryRow.

    Row is an interface instead of a struct to allow tests to mock QueryRow.
    However, adding a method to an interface is technically a breaking change.
    Because of this the Row interface is partially excluded from semantic
    version requirements. Methods will not be removed or changed, but new
    methods may be added.

type RowScanner interface {
	// ScanRows scans the row.
	ScanRow(rows Rows) error
}
    RowScanner scans an entire row at a time into the RowScanner.

type RowToFunc[T any] func(row CollectableRow) (T, error)
    RowToFunc is a function that scans or otherwise converts row to a T.

type Rows interface {
	// Close closes the rows, making the connection ready for use again. It is safe
	// to call Close after rows is already closed.
	Close()

	// Err returns any error that occurred while executing a query or reading its results. Err must be called after the
	// Rows is closed (either by calling Close or by Next returning false) to check if the query was successful. If it is
	// called before the Rows is closed it may return nil even if the query failed on the server.
	Err() error

	// CommandTag returns the command tag from this query. It is only available after Rows is closed.
	CommandTag() pgconn.CommandTag

	// FieldDescriptions returns the field descriptions of the columns. It may return nil. In particular this can occur
	// when there was an error executing the query.
	FieldDescriptions() []pgconn.FieldDescription

	// Next prepares the next row for reading. It returns true if there is another row and false if no more rows are
	// available or a fatal error has occurred. It automatically closes rows upon returning false (whether due to all rows
	// having been read or due to an error).
	//
	// Callers should check rows.Err() after rows.Next() returns false to detect whether result-set reading ended
	// prematurely due to an error. See [Conn.Query] for details.
	//
	// For simpler error handling, consider using the higher-level pgx v5 [CollectRows()] and [ForEachRow()] helpers instead.
	Next() bool

	// Scan reads the values from the current row into dest values positionally. dest can include pointers to core types,
	// values implementing the Scanner interface, and nil. nil will skip the value entirely. It is an error to call Scan
	// without first calling Next() and checking that it returned true. Rows is automatically closed upon error.
	Scan(dest ...any) error

	// Values returns the decoded row values. As with Scan(), it is an error to
	// call Values without first calling Next() and checking that it returned
	// true.
	Values() ([]any, error)

	// RawValues returns the unparsed bytes of the row values. The returned data is only valid until the next Next
	// call or the Rows is closed.
	RawValues() [][]byte

	// Conn returns the underlying *Conn on which the query was executed. This may return nil if Rows did not come from a
	// *Conn (e.g. if it was created by RowsFromResultReader)
	Conn() *Conn
}
    Rows is the result set returned from Conn.Query. Rows must be closed
    before the Conn can be used again. Rows are closed by explicitly calling
    Rows.Close, calling Rows.Next until it returns false, or when a fatal error
    occurs.

    Once a Rows is closed the only methods that may be called are Rows.Close,
    Rows.Err, and Rows.CommandTag.

    Rows is an interface instead of a struct to allow tests to mock Query.
    However, adding a method to an interface is technically a breaking change.
    Because of this the Rows interface is partially excluded from semantic
    version requirements. Methods will not be removed or changed, but new
    methods may be added.

func RowsFromResultReader(typeMap *pgtype.Map, resultReader *pgconn.ResultReader) Rows
    RowsFromResultReader returns a Rows that will read from values resultReader
    and decode with typeMap. It can be used to read from the lower level pgconn
    interface.

type ScanArgError struct {
	ColumnIndex int
	FieldName   string
	Err         error
}

func (e ScanArgError) Error() string

func (e ScanArgError) Unwrap() error

type StrictNamedArgs map[string]any
    StrictNamedArgs can be used in the same way as NamedArgs, but provided
    arguments are also checked to include all named arguments that the sql query
    uses, and no extra arguments.

func (sna StrictNamedArgs) RewriteQuery(ctx context.Context, conn *Conn, sql string, args []any) (newSQL string, newArgs []any, err error)
    RewriteQuery implements the QueryRewriter interface.

type TraceBatchEndData struct {
	Err error
}

type TraceBatchQueryData struct {
	SQL        string
	Args       []any
	CommandTag pgconn.CommandTag
	Err        error
}

type TraceBatchStartData struct {
	Batch *Batch
}

type TraceConnectEndData struct {
	Conn *Conn
	Err  error
}

type TraceConnectStartData struct {
	ConnConfig *ConnConfig
}

type TraceCopyFromEndData struct {
	CommandTag pgconn.CommandTag
	Err        error
}

type TraceCopyFromStartData struct {
	TableName   Identifier
	ColumnNames []string
}

type TracePrepareEndData struct {
	AlreadyPrepared bool
	Err             error
}

type TracePrepareStartData struct {
	Name string
	SQL  string
}

type TraceQueryEndData struct {
	CommandTag pgconn.CommandTag
	Err        error
}

type TraceQueryStartData struct {
	SQL  string
	Args []any
}

type Tx interface {
	// Begin starts a pseudo nested transaction.
	Begin(ctx context.Context) (Tx, error)

	// Commit commits the transaction if this is a real transaction or releases the savepoint if this is a pseudo nested
	// transaction. Commit will return an error where errors.Is(ErrTxClosed) is true if the Tx is already closed, but is
	// otherwise safe to call multiple times. If the commit fails with a rollback status (e.g. the transaction was already
	// in a broken state) then an error where errors.Is(ErrTxCommitRollback) is true will be returned.
	Commit(ctx context.Context) error

	// Rollback rolls back the transaction if this is a real transaction or rolls back to the savepoint if this is a
	// pseudo nested transaction. Rollback will return an error where errors.Is(ErrTxClosed) is true if the Tx is already
	// closed, but is otherwise safe to call multiple times. Hence, a defer tx.Rollback() is safe even if tx.Commit() will
	// be called first in a non-error condition. Any other failure of a real transaction will result in the connection
	// being closed.
	Rollback(ctx context.Context) error

	CopyFrom(ctx context.Context, tableName Identifier, columnNames []string, rowSrc CopyFromSource) (int64, error)
	SendBatch(ctx context.Context, b *Batch) BatchResults
	LargeObjects() LargeObjects

	Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error)

	Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row

	// Conn returns the underlying *Conn that on which this transaction is executing.
	Conn() *Conn
}
    Tx represents a database transaction.

    Tx is an interface instead of a struct to enable connection pools to be
    implemented without relying on internal pgx state, to support pseudo-nested
    transactions with savepoints, and to allow tests to mock transactions.
    However, adding a method to an interface is technically a breaking change.
    If new methods are added to Conn it may be desirable to add them to Tx as
    well. Because of this the Tx interface is partially excluded from semantic
    version requirements. Methods will not be removed or changed, but new
    methods may be added.

type TxAccessMode string
    TxAccessMode is the transaction access mode (read write or read only)

const (
	ReadWrite TxAccessMode = "read write"
	ReadOnly  TxAccessMode = "read only"
)
    Transaction access modes

type TxDeferrableMode string
    TxDeferrableMode is the transaction deferrable mode (deferrable or not
    deferrable)

const (
	Deferrable    TxDeferrableMode = "deferrable"
	NotDeferrable TxDeferrableMode = "not deferrable"
)
    Transaction deferrable modes

type TxIsoLevel string
    TxIsoLevel is the transaction isolation level (serializable, repeatable
    read, read committed or read uncommitted)

const (
	Serializable    TxIsoLevel = "serializable"
	RepeatableRead  TxIsoLevel = "repeatable read"
	ReadCommitted   TxIsoLevel = "read committed"
	ReadUncommitted TxIsoLevel = "read uncommitted"
)
    Transaction isolation levels

type TxOptions struct {
	IsoLevel       TxIsoLevel
	AccessMode     TxAccessMode
	DeferrableMode TxDeferrableMode

	// BeginQuery is the SQL query that will be executed to begin the transaction. This allows using non-standard syntax
	// such as BEGIN PRIORITY HIGH with CockroachDB. If set this will override the other settings.
	BeginQuery string
	// CommitQuery is the SQL query that will be executed to commit the transaction.
	CommitQuery string
}
    TxOptions are transaction modes within a transaction block

