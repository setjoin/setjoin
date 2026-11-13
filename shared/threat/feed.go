package threat

import (
	"bufio"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var feedHTTPClient = &http.Client{Timeout: 30 * time.Second}

// RefreshFeeds runs a periodic goroutine that fetches the Spamhaus DROP list
// and hot-swaps it into the threat_feed_blocks table atomically.
func RefreshFeeds(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := refreshOnce(ctx, pool, logger); err != nil {
		logger.Error("threat feed initial refresh failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshOnce(ctx, pool, logger); err != nil {
				logger.Error("threat feed refresh failed", "error", err)
			}
		}
	}
}

func refreshOnce(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	entries, err := fetchDROPLines(ctx)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		logger.Warn("threat feed returned zero CIDR entries")
		return nil
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Truncate and re-insert for atomic hot-swap
	if _, err := tx.Exec(ctx, `DELETE FROM threat_feed_blocks`); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, e := range entries {
		if _, err := tx.Exec(ctx,
			`INSERT INTO threat_feed_blocks (cidr, source, added_at) VALUES ($1::INET, $2, $3) ON CONFLICT (cidr) DO NOTHING`,
			e.cidr, "spamhaus-drop", now,
		); err != nil {
			logger.Warn("threat feed skip invalid CIDR", "cidr", e.cidr, "error", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	logger.Info("threat feed refreshed", "cidr_count", len(entries))
	return nil
}

type feedEntry struct {
	cidr string
}

// fetchDROPLines fetches the Spamhaus DROP list and parses CIDR lines.
func fetchDROPLines(ctx context.Context) ([]feedEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.spamhaus.org/drop/drop.txt", nil)
	if err != nil {
		return nil, err
	}

	resp, err := feedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []feedEntry
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		// Extract CIDR — first field before semicolon or space
		cidr := line
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			cidr = strings.TrimSpace(line[:idx])
		} else if idx := strings.IndexByte(line, ' '); idx >= 0 {
			cidr = strings.TrimSpace(line[:idx])
		}
		if cidr != "" && strings.Contains(cidr, "/") {
			entries = append(entries, feedEntry{cidr: cidr})
		}
	}
	return entries, scanner.Err()
}
