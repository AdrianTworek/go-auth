package core

import (
	"context"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// RateLimiter records and checks request counts for abuse protection. The library
// ships an in-memory implementation (default) and a Postgres-backed one, and callers
// may plug in their own (e.g. Redis) via RateLimitConfig.Store.
//
// Allow records one hit against key and reports whether the caller is still under
// limit; when not, retryAfter is how long until the next request would be allowed.
// limit and window describe a token bucket (burst of limit, refilling to full over
// window). Implementations MUST fail open — return allowed on their own internal
// errors — so a limiter outage degrades to "no limiting" rather than an auth outage.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
	Reset(ctx context.Context, key string) error
}

// Built-in default limits, applied to any Rule field left at its zero value.
var (
	defaultLoginPerIP        = Limit{Max: 10, Window: 15 * time.Minute}
	defaultLoginPerAccount   = Limit{Max: 5, Window: 15 * time.Minute}
	defaultSendPerIP         = Limit{Max: 20, Window: time.Hour}
	defaultSendPerAccount    = Limit{Max: 3, Window: time.Hour}
	defaultRegisterPerIP     = Limit{Max: 10, Window: time.Hour}
	defaultSensitivePerIP    = Limit{Max: 20, Window: time.Hour}
	defaultSensitivePerActor = Limit{Max: 10, Window: time.Hour}
)

// resolvedLimit is a Limit with defaults applied. A disabled limit has limit <= 0.
type resolvedLimit struct {
	limit  int
	window time.Duration
}

func (l resolvedLimit) enabled() bool { return l.limit > 0 && l.window > 0 }

type resolvedRule struct {
	perIP      resolvedLimit
	perAccount resolvedLimit
}

// resolvedRateLimit holds the effective, defaulted rate-limit settings for an
// AuthClient. When enabled is false the guards are no-ops.
type resolvedRateLimit struct {
	enabled   bool
	login     resolvedRule
	sendEmail resolvedRule
	register  resolvedRule
	sensitive resolvedRule
}

func resolveLimit(c, def Limit) resolvedLimit {
	if c.Max < 0 {
		return resolvedLimit{} // explicitly disabled
	}
	limit := c.Max
	if limit == 0 {
		limit = def.Max
	}
	window := c.Window
	if window == 0 {
		window = def.Window
	}
	return resolvedLimit{limit: limit, window: window}
}

func resolveRateLimitRules(cfg *RateLimitConfig) resolvedRateLimit {
	enabled := true
	var c RateLimitConfig
	if cfg != nil {
		c = *cfg
		if cfg.Enabled != nil {
			enabled = *cfg.Enabled
		}
	}
	return resolvedRateLimit{
		enabled: enabled,
		login: resolvedRule{
			perIP:      resolveLimit(c.Login.PerIP, defaultLoginPerIP),
			perAccount: resolveLimit(c.Login.PerAccount, defaultLoginPerAccount),
		},
		sendEmail: resolvedRule{
			perIP:      resolveLimit(c.SendEmail.PerIP, defaultSendPerIP),
			perAccount: resolveLimit(c.SendEmail.PerAccount, defaultSendPerAccount),
		},
		register: resolvedRule{
			perIP: resolveLimit(c.Register.PerIP, defaultRegisterPerIP),
		},
		sensitive: resolvedRule{
			perIP:      resolveLimit(c.Sensitive.PerIP, defaultSensitivePerIP),
			perAccount: resolveLimit(c.Sensitive.PerAccount, defaultSensitivePerActor),
		},
	}
}

// buildRateLimiter selects the RateLimiter implementation for the config. It returns
// nil when limiting is disabled (the guards short-circuit on rl.enabled first, so the
// limiter is never consulted).
func buildRateLimiter(cfg *RateLimitConfig, s *store.Storage, rl resolvedRateLimit) RateLimiter {
	if !rl.enabled {
		return nil
	}
	if cfg != nil && cfg.Store != nil {
		return cfg.Store
	}
	if cfg != nil && cfg.Backend == RateLimitPostgres {
		return &postgresRateLimiter{store: s.RateLimit}
	}
	return newMemoryRateLimiter()
}

// clientIP derives the caller's IP for keying rate limits. It defaults to the direct
// peer (RemoteAddr) and only consults X-Forwarded-For when a trusted-proxy config
// opts in, taking the entry TrustedHops from the right of the chain so a spoofed
// left-most value is ignored. On any ambiguity it falls back to the direct peer,
// which is the safe (non-spoofable) choice.
func (ac *AuthClient) clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}

	tp := ac.trustedProxy
	if tp == nil || !tp.TrustForwardedHeader {
		return host
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}

	parts := strings.Split(xff, ",")
	// chain is the forwarded addresses followed by the direct peer (RemoteAddr),
	// which is always trustworthy. Build it fresh rather than appending onto parts.
	chain := make([]string, 0, len(parts)+1)
	for _, p := range parts {
		chain = append(chain, strings.TrimSpace(p))
	}
	chain = append(chain, host)

	idx := len(chain) - 1 - tp.TrustedHops
	if idx < 0 || idx >= len(chain) || chain[idx] == "" {
		return host
	}
	return chain[idx]
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// check consumes one token for the given dimension and reports whether the request is
// allowed. A disabled limit always allows. On limiter error it fails open.
func (ac *AuthClient) check(ctx context.Context, flow, dimension, value string, l resolvedLimit) (RateLimitInfo, bool) {
	if !l.enabled() {
		return RateLimitInfo{}, true
	}
	key := flow + ":" + dimension + ":" + value
	allowed, retryAfter, err := ac.limiter.Allow(ctx, key, l.limit, l.window)
	if err != nil {
		// Fail open: a limiter outage must not become an auth outage.
		slog.Error("rate limiter failed, allowing request", "error", err, "flow", flow, "dimension", dimension)
		return RateLimitInfo{}, true
	}
	return RateLimitInfo{Flow: flow, Dimension: dimension, Key: key, RetryAfter: retryAfter}, allowed
}

// fireRateLimitHook runs the EventRateLimited hook and reports whether the caller
// should still write the default throttled response (true) or a hook already
// responded (false).
func (ac *AuthClient) fireRateLimitHook(w http.ResponseWriter, r *http.Request, info RateLimitInfo) bool {
	ev := NewAuthEvent(EventRateLimited, w, r, nil)
	ev.RateLimit = &info
	cont, err := ac.hookStore.Trigger(r.Context(), ev)
	if err != nil {
		serverError(w, r, err)
		return false
	}
	return cont
}

func (ac *AuthClient) write429(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
	}
	writeJSONError(w, http.StatusTooManyRequests, "Too many requests. Please slow down and try again later.")
}

// blocked429 fires the hook then (unless the hook responded) writes a 429. It always
// returns false so callers can `return ac.blocked429(...)`.
func (ac *AuthClient) blocked429(w http.ResponseWriter, r *http.Request, info RateLimitInfo) bool {
	if ac.fireRateLimitHook(w, r, info) {
		ac.write429(w, info.RetryAfter)
	}
	return false
}

// blockedSilent fires the hook then (unless the hook responded) writes the endpoint's
// normal generic 200 while silently dropping the work — used for the per-account cap
// on email-sending endpoints so throttling can't be used to enumerate accounts.
func (ac *AuthClient) blockedSilent(w http.ResponseWriter, r *http.Request, info RateLimitInfo, genericMsg string) bool {
	if ac.fireRateLimitHook(w, r, info) {
		writeJSONResponse(w, http.StatusOK, map[string]any{"message": genericMsg})
	}
	return false
}

// --- per-flow guards -------------------------------------------------------
//
// Each guard returns true when the request may proceed, and false when it was
// throttled (in which case the guard has already written the response).

func (ac *AuthClient) guardLogin(w http.ResponseWriter, r *http.Request, email string) bool {
	if !ac.rl.enabled {
		return true
	}
	ctx := r.Context()
	if info, ok := ac.check(ctx, "login", "ip", ac.clientIP(r), ac.rl.login.perIP); !ok {
		return ac.blocked429(w, r, info)
	}
	if info, ok := ac.check(ctx, "login", "account", normalizeEmail(email), ac.rl.login.perAccount); !ok {
		return ac.blocked429(w, r, info)
	}
	return true
}

// resetLoginLimit clears the per-account login counter after a successful login, so a
// user who mistyped their password a few times isn't left throttled.
func (ac *AuthClient) resetLoginLimit(ctx context.Context, email string) {
	if !ac.rl.enabled || !ac.rl.login.perAccount.enabled() {
		return
	}
	key := "login:account:" + normalizeEmail(email)
	if err := ac.limiter.Reset(ctx, key); err != nil {
		slog.Error("failed to reset login rate limit", "error", err)
	}
}

func (ac *AuthClient) guardRegister(w http.ResponseWriter, r *http.Request) bool {
	if !ac.rl.enabled {
		return true
	}
	if info, ok := ac.check(r.Context(), "register", "ip", ac.clientIP(r), ac.rl.register.perIP); !ok {
		return ac.blocked429(w, r, info)
	}
	return true
}

// guardSend enforces the send-email rule: per-IP abuse gets a 429, but the per-account
// cap stays silent (generic 200) to preserve anti-enumeration. flow namespaces the key
// per endpoint so each has its own budget.
func (ac *AuthClient) guardSend(w http.ResponseWriter, r *http.Request, flow, email, genericMsg string) bool {
	if !ac.rl.enabled {
		return true
	}
	ctx := r.Context()
	if info, ok := ac.check(ctx, flow, "ip", ac.clientIP(r), ac.rl.sendEmail.perIP); !ok {
		return ac.blocked429(w, r, info)
	}
	if info, ok := ac.check(ctx, flow, "account", normalizeEmail(email), ac.rl.sendEmail.perAccount); !ok {
		return ac.blockedSilent(w, r, info, genericMsg)
	}
	return true
}

// guardSensitive enforces the rule for authenticated re-auth actions, keyed on client
// IP and on the acting user. Both dimensions return a 429 (the caller is already
// authenticated, so there is no account to enumerate).
func (ac *AuthClient) guardSensitive(w http.ResponseWriter, r *http.Request, flow, userID string) bool {
	if !ac.rl.enabled {
		return true
	}
	ctx := r.Context()
	if info, ok := ac.check(ctx, flow, "ip", ac.clientIP(r), ac.rl.sensitive.perIP); !ok {
		return ac.blocked429(w, r, info)
	}
	if info, ok := ac.check(ctx, flow, "user", userID, ac.rl.sensitive.perAccount); !ok {
		return ac.blocked429(w, r, info)
	}
	return true
}
