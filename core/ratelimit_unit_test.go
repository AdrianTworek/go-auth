package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	m := newMemoryRateLimiter()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, _, err := m.Allow(ctx, "k", 3, time.Minute)
		require.NoError(t, err)
		require.True(t, allowed, "request %d should be allowed", i+1)
	}

	allowed, retryAfter, err := m.Allow(ctx, "k", 3, time.Minute)
	require.NoError(t, err)
	assert.False(t, allowed, "request over the limit should be blocked")
	assert.Greater(t, retryAfter, time.Duration(0), "a blocked request should report a positive Retry-After")
}

func TestMemoryRateLimiter_RefillsOverTime(t *testing.T) {
	m := newMemoryRateLimiter()
	now := time.Now()
	m.now = func() time.Time { return now }
	ctx := context.Background()

	// limit 2 / 2s => refill of 1 token per second.
	allow := func() (bool, time.Duration) {
		a, r, err := m.Allow(ctx, "k", 2, 2*time.Second)
		require.NoError(t, err)
		return a, r
	}

	a, _ := allow()
	require.True(t, a)
	a, _ = allow()
	require.True(t, a)
	a, retry := allow()
	require.False(t, a, "bucket should be empty after 2 requests")
	assert.InDelta(t, time.Second.Seconds(), retry.Seconds(), 0.05, "should need ~1s to refill 1 token")

	// After 1 second, exactly one token is available again.
	now = now.Add(time.Second)
	a, _ = allow()
	assert.True(t, a, "one token should have refilled")
	a, _ = allow()
	assert.False(t, a, "only one token should have refilled")
}

func TestMemoryRateLimiter_Reset(t *testing.T) {
	m := newMemoryRateLimiter()
	ctx := context.Background()

	a, _, _ := m.Allow(ctx, "k", 1, time.Minute)
	require.True(t, a)
	a, _, _ = m.Allow(ctx, "k", 1, time.Minute)
	require.False(t, a)

	require.NoError(t, m.Reset(ctx, "k"))

	a, _, _ = m.Allow(ctx, "k", 1, time.Minute)
	assert.True(t, a, "Reset should refill the bucket")
}

func TestMemoryRateLimiter_ZeroLimitAlwaysAllows(t *testing.T) {
	m := newMemoryRateLimiter()
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		a, _, err := m.Allow(ctx, "k", 0, time.Minute)
		require.NoError(t, err)
		require.True(t, a)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		proxy      *TrustedProxyConfig
		want       string
	}{
		{
			name:       "no proxy config uses direct peer",
			remoteAddr: "203.0.113.9:5555",
			xff:        "1.1.1.1",
			proxy:      nil,
			want:       "203.0.113.9",
		},
		{
			name:       "proxy header not trusted uses direct peer",
			remoteAddr: "10.0.0.1:5555",
			xff:        "1.1.1.1, 2.2.2.2",
			proxy:      &TrustedProxyConfig{TrustForwardedHeader: false},
			want:       "10.0.0.1",
		},
		{
			name:       "one trusted hop takes rightmost forwarded entry",
			remoteAddr: "10.0.0.1:5555",
			xff:        "1.1.1.1, 2.2.2.2",
			proxy:      &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 1},
			want:       "2.2.2.2",
		},
		{
			name:       "two trusted hops walk further left",
			remoteAddr: "10.0.0.1:5555",
			xff:        "1.1.1.1, 2.2.2.2",
			proxy:      &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 2},
			want:       "1.1.1.1",
		},
		{
			name:       "more hops than present falls back to direct peer",
			remoteAddr: "10.0.0.1:5555",
			xff:        "1.1.1.1, 2.2.2.2",
			proxy:      &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 9},
			want:       "10.0.0.1",
		},
		{
			name:       "trusted but no forwarded header uses direct peer",
			remoteAddr: "10.0.0.1:5555",
			xff:        "",
			proxy:      &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 1},
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthClient{trustedProxy: tt.proxy}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			assert.Equal(t, tt.want, ac.clientIP(req))
		})
	}
}

func TestResolveRateLimitRules(t *testing.T) {
	t.Run("nil config enables conservative defaults", func(t *testing.T) {
		rl := resolveRateLimitRules(nil)
		assert.True(t, rl.enabled)
		assert.Equal(t, 10, rl.login.perIP.limit)
		assert.Equal(t, 15*time.Minute, rl.login.perIP.window)
		assert.Equal(t, 5, rl.login.perAccount.limit)
		assert.Equal(t, 3, rl.sendEmail.perAccount.limit)
		assert.Equal(t, 10, rl.register.perIP.limit)
	})

	t.Run("Enabled false disables limiting", func(t *testing.T) {
		rl := resolveRateLimitRules(&RateLimitConfig{Enabled: Ptr(false)})
		assert.False(t, rl.enabled)
	})

	t.Run("negative Max disables a single dimension", func(t *testing.T) {
		rl := resolveRateLimitRules(&RateLimitConfig{
			Login: Rule{PerIP: Limit{Max: -1}},
		})
		assert.False(t, rl.login.perIP.enabled(), "per-IP should be disabled")
		assert.True(t, rl.login.perAccount.enabled(), "per-account should still use the default")
	})

	t.Run("explicit values override defaults", func(t *testing.T) {
		rl := resolveRateLimitRules(&RateLimitConfig{
			Login: Rule{PerIP: Limit{Max: 42, Window: 2 * time.Hour}},
		})
		assert.Equal(t, 42, rl.login.perIP.limit)
		assert.Equal(t, 2*time.Hour, rl.login.perIP.window)
	})
}
