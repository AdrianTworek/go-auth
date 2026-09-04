package core

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/AdrianTworek/go-auth/core/mailer"
)

type AuthClient struct {
	config       *AuthConfig
	store        *store.Storage
	hookStore    *HookStore
	cookieOpts   auth.CookieOptions
	durations    resolvedDurations
	limiter      RateLimiter
	rl           resolvedRateLimit
	trustedProxy *TrustedProxyConfig
}

// resolvedDurations holds the session and token lifetimes for an AuthClient with
// all defaults already applied, so handlers and middleware never read raw config.
type resolvedDurations struct {
	session           time.Duration
	refreshThreshold  time.Duration
	emailVerification time.Duration
	passwordReset     time.Duration
	magicLink         time.Duration
	emailChange       time.Duration
}

// Checks if mailer is configured and magic link redirect urls are also provided
func (c *AuthClient) CanLoginWithMagicLink() bool {
	return c.config.Session.MagicLinkSuccessfulRedirectURL != "" && c.config.Session.MagicLinkFailedRedirectURL != "" && c.config.Mailer != nil
}

// Redirects from the endpoint to the success frontend url provided by user
func (c *AuthClient) SuccessMagicLinkRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.config.Session.MagicLinkSuccessfulRedirectURL, http.StatusFound)
}

// Redirects from the endpoint to the failed frontend url provided by user
func (c *AuthClient) FailedMagicLinkRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.config.Session.MagicLinkFailedRedirectURL, http.StatusSeeOther)
}

func (c *AuthClient) CanLoginWithOAuth() bool {
	return c.config.OAuth != nil && len(c.config.OAuth.Providers) > 0
}

func (c *AuthClient) SetupGoth() {
	if !c.CanLoginWithOAuth() {
		panic("OAuth providers are not configured. Please provide at least one OAuth provider in the AuthConfig.")
	}

	gothic.GetProviderName = func(r *http.Request) (string, error) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			return "", fmt.Errorf("provider is required")
		}
		return provider, nil
	}

	sessionStore := sessions.NewCookieStore([]byte(c.config.SessionSecret))
	gothic.Store = sessionStore

	goth.UseProviders(
		c.config.OAuth.Providers...,
	)
}

// resolveCookieOptions builds the session cookie options from the session config,
// applying secure-by-default values for anything the consumer left unset.
func resolveCookieOptions(s *SessionConfig) auth.CookieOptions {
	opts := auth.CookieOptions{
		Name:     "session",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if s == nil {
		return opts
	}
	if s.CookieName != "" {
		opts.Name = s.CookieName
	}
	if s.CookieSecure != nil {
		opts.Secure = *s.CookieSecure
	}
	if s.CookieSameSite != 0 {
		opts.SameSite = s.CookieSameSite
	}
	opts.Domain = s.CookieDomain
	return opts
}

// resolveDurations builds the effective session and token lifetimes, applying the
// library defaults for anything the consumer left at zero. The slide threshold
// defaults to half the (resolved) session duration.
func resolveDurations(s *SessionConfig, t *TokenConfig) resolvedDurations {
	d := resolvedDurations{
		session:           auth.DefaultSessionDuration,
		emailVerification: auth.DefaultTokenDuration,
		passwordReset:     auth.DefaultTokenDuration,
		magicLink:         auth.DefaultTokenDuration,
		emailChange:       auth.DefaultTokenDuration,
	}

	if s != nil && s.Duration > 0 {
		d.session = s.Duration
	}
	d.refreshThreshold = d.session / 2
	if s != nil && s.RefreshThreshold > 0 {
		d.refreshThreshold = s.RefreshThreshold
	}

	if t != nil {
		if t.EmailVerification > 0 {
			d.emailVerification = t.EmailVerification
		}
		if t.PasswordReset > 0 {
			d.passwordReset = t.PasswordReset
		}
		if t.MagicLink > 0 {
			d.magicLink = t.MagicLink
		}
		if t.EmailChange > 0 {
			d.emailChange = t.EmailChange
		}
	}

	return d
}

func NewAuthClient(config *AuthConfig) (*AuthClient, error) {
	// Default the session config so cookie/option resolution is always safe.
	if config.Session == nil {
		config.Session = &SessionConfig{}
	}

	// SessionSecret is the gothic OAuth-state cookie key; require a strong value
	// when OAuth is enabled. Validate before opening any resources.
	if config.OAuth != nil && len(config.OAuth.Providers) > 0 && len(config.SessionSecret) < 32 {
		return nil, fmt.Errorf("SessionSecret must be at least 32 bytes when OAuth is enabled")
	}

	// Apply a custom bcrypt cost if configured (0 leaves the default).
	if config.BcryptCost != 0 {
		if err := auth.SetBcryptCost(config.BcryptCost); err != nil {
			return nil, err
		}
	}

	db, err := db.NewPostgres(config.Db.Dsn)
	if err != nil {
		return nil, err
	}

	// If no mailer is provided, use the default one that only logs the messages
	if config.Mailer == nil {
		config.Mailer = mailer.New(config.BaseURL)
	}

	var hookStore *HookStore
	if config.Hooks != nil {
		hookStore = NewHookStore(*config.Hooks)
	} else {
		// Create an empty hook store if no hooks are provided
		hookStore = NewHookStore(HookMap{})
	}

	storage := store.NewStorage(db)
	rl := resolveRateLimitRules(config.RateLimit)

	return &AuthClient{
		config:       config,
		store:        storage,
		hookStore:    hookStore,
		cookieOpts:   resolveCookieOptions(config.Session),
		durations:    resolveDurations(config.Session, config.Tokens),
		rl:           rl,
		limiter:      buildRateLimiter(config.RateLimit, storage, rl),
		trustedProxy: config.TrustedProxy,
	}, nil
}

func (ac *AuthClient) newSessionCookie(token string, expiresAt time.Time) *http.Cookie {
	return auth.NewSessionCookie(token, expiresAt, ac.cookieOpts)
}

// sessionExpiry returns the absolute expiry for a freshly created or refreshed
// session, based on the configured session duration.
func (ac *AuthClient) sessionExpiry() time.Time {
	return time.Now().Add(ac.durations.session)
}

// tokenExpiry returns the absolute expiry for an emailed single-use token of the
// given intent, based on the configured per-intent token durations.
func (ac *AuthClient) tokenExpiry(intent auth.VerificationIntent) time.Time {
	var d time.Duration
	switch intent {
	case auth.EmailVerificationIntent:
		d = ac.durations.emailVerification
	case auth.PasswordResetIntent:
		d = ac.durations.passwordReset
	case auth.MagicLinkIntent:
		d = ac.durations.magicLink
	case auth.EmailChangeIntent:
		d = ac.durations.emailChange
	default:
		d = auth.DefaultTokenDuration
	}
	return time.Now().Add(d)
}

// newVerification builds a verification row with its expiry already set from the
// configured token durations, so callers can't accidentally leave it unset.
func (ac *AuthClient) newVerification(intent auth.VerificationIntent, email, userID *auth.NullString) *store.Verification {
	v := store.NewVerification(intent, email, userID)
	v.ExpiresAt = ac.tokenExpiry(intent)
	return v
}

func (ac *AuthClient) deleteSessionCookie() *http.Cookie {
	return auth.DeleteSessionCookie(ac.cookieOpts)
}

func (ac *AuthClient) cookieName() string {
	return ac.cookieOpts.Name
}

// CleanupExpired deletes expired sessions and verification tokens. Expired rows are
// already ignored by lookups (which filter on expires_at), so this is housekeeping
// to keep the tables from growing unbounded; call it periodically (e.g. from a cron).
func (ac *AuthClient) CleanupExpired(ctx context.Context) error {
	if err := ac.store.Session.DeleteExpired(ctx); err != nil {
		return err
	}
	if err := ac.store.Verification.DeleteExpired(ctx); err != nil {
		return err
	}
	// Prune idle rate-limit buckets (Postgres backend only; a no-op-ish DELETE that
	// matches nothing when the in-memory backend is used).
	return ac.store.RateLimit.DeleteStale(ctx)
}
