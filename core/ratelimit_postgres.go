package core

import (
	"context"
	"time"
)

// postgresRateLimiter adapts the Postgres-backed token-bucket store to the
// RateLimiter interface, translating the {limit, window} contract into the store's
// {capacity, refillPerSecond} token-bucket parameters.
type postgresRateLimiter struct {
	store interface {
		Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, time.Duration, error)
		Reset(ctx context.Context, key string) error
	}
}

var _ RateLimiter = (*postgresRateLimiter)(nil)

func (p *postgresRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if limit <= 0 || window <= 0 {
		return true, 0, nil
	}
	capacity := float64(limit)
	refillPerSecond := capacity / window.Seconds()
	return p.store.Allow(ctx, key, capacity, refillPerSecond)
}

func (p *postgresRateLimiter) Reset(ctx context.Context, key string) error {
	return p.store.Reset(ctx, key)
}
