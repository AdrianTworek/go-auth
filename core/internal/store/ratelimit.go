package store

import (
	"context"
	"math"
	"time"

	"github.com/jmoiron/sqlx"
)

// RateLimitStore is the Postgres-backed token-bucket counter used when the library
// runs across multiple replicas and needs shared, authoritative rate-limit state.
// Each key maps to one row holding the current token level and when it was last
// touched; refill is computed from elapsed time on read.
type RateLimitStore struct {
	db *sqlx.DB
}

// Allow refills the bucket for key based on time elapsed since it was last updated,
// then consumes one token if any are available. It reports whether the request is
// allowed and, when not, how long until a token frees up.
//
// The read-modify-write runs in a transaction with SELECT ... FOR UPDATE so
// concurrent requests on the same key serialize on the row and can't double-spend.
// All timing is measured with the database clock (NOW()) so app/DB clock skew can't
// distort the bucket.
func (s *RateLimitStore) Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, time.Duration, error) {
	if capacity <= 0 || refillPerSecond <= 0 {
		return true, 0, nil
	}

	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, 0, err
	}
	// Rollback is a no-op once the tx is committed; safe to always defer.
	defer func() { _ = tx.Rollback() }()

	// Ensure the row exists so the subsequent FOR UPDATE has something to lock. A
	// brand-new bucket starts full.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO rate_limits (key, tokens, updated_at) VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO NOTHING`, key, capacity); err != nil {
		return false, 0, err
	}

	var tokens, elapsed float64
	if err = tx.QueryRowxContext(ctx,
		`SELECT tokens, EXTRACT(EPOCH FROM (NOW() - updated_at)) FROM rate_limits WHERE key = $1 FOR UPDATE`,
		key).Scan(&tokens, &elapsed); err != nil {
		return false, 0, err
	}

	if elapsed > 0 {
		tokens = math.Min(capacity, tokens+elapsed*refillPerSecond)
	}

	allowed := tokens >= 1
	var retryAfter time.Duration
	if allowed {
		tokens--
	} else {
		retryAfter = time.Duration((1 - tokens) / refillPerSecond * float64(time.Second))
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE rate_limits SET tokens = $1, updated_at = NOW() WHERE key = $2`, tokens, key); err != nil {
		return false, 0, err
	}

	if err = tx.Commit(); err != nil {
		return false, 0, err
	}

	return allowed, retryAfter, nil
}

// Reset clears the bucket for key (e.g. after a successful login), so the next
// request starts from a full bucket.
func (s *RateLimitStore) Reset(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limits WHERE key = $1`, key)
	return err
}

// DeleteStale removes buckets untouched for a day. Such a bucket has long since
// refilled to full, so it carries no state and dropping it is equivalent to keeping
// it — this just stops the table growing unbounded. Call it periodically.
func (s *RateLimitStore) DeleteStale(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limits WHERE updated_at < NOW() - INTERVAL '1 day'`)
	return err
}
