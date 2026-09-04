package core

import (
	"net/http"
	"time"

	"github.com/markbates/goth"

	"github.com/AdrianTworek/go-auth/core/mailer"
)

// Ptr returns a pointer to v. It's a convenience for setting optional pointer
// config fields from a literal, e.g. CookieSecure: core.Ptr(false).
func Ptr[T any](v T) *T {
	return &v
}

type AuthConfig struct {
	Db            *DatabaseConfig
	Session       *SessionConfig
	Tokens        *TokenConfig
	OAuth         *OAuthConfig
	Mailer        mailer.Mailer
	Hooks         *HookMap
	BaseURL       string
	SessionSecret string
	// BcryptCost sets the bcrypt work factor for password hashing. When 0 the
	// library default (bcrypt.DefaultCost, 10) is used. Valid range is 4-31.
	//
	// Default: 10
	BcryptCost int
	// RateLimit configures abuse protection on the auth endpoints (brute-force and
	// email flooding). When nil, rate limiting is ON with conservative defaults and
	// an in-memory store — correct for a single instance. See RateLimitConfig.
	//
	// Default: enabled, in-memory
	RateLimit *RateLimitConfig
	// TrustedProxy controls how the client IP is derived for rate limiting and
	// session records. When nil the library uses the direct peer (RemoteAddr), which
	// is correct when the app is exposed directly. Set it when behind a proxy or load
	// balancer so the real client IP is read from X-Forwarded-For.
	//
	// Default: nil (use RemoteAddr)
	TrustedProxy *TrustedProxyConfig
}

type OAuthConfig struct {
	// Goth provider objects that are used to setup goth authentication without any additional configuration.
	Providers []goth.Provider
}

type DatabaseConfig struct {
	Dsn string
}

type SessionConfig struct {
	// Duration is how long a session is valid for. It sets both the session's
	// server-side expiry and the session cookie's lifetime. When zero the library
	// default is used.
	//
	// Default: 7 days
	Duration time.Duration
	// RefreshThreshold controls sliding sessions: on an authenticated request, when
	// the session's remaining lifetime drops below this threshold, the middleware
	// rotates the token and extends the session by a full Duration. When zero it
	// defaults to half of Duration. Set it larger than Duration to refresh on every
	// request, or leave it at the default for typical sliding behaviour.
	//
	// Default: Duration / 2
	RefreshThreshold time.Duration
	// LoginAfterRegister specifies whether to log in the user after registration.
	//
	// Default: false
	LoginAfterRegister bool
	// RequireVerifiedEmail, when true, blocks password login (403) for users whose
	// email has not been verified. Magic-link and OAuth logins are unaffected since
	// they establish a verified email. When true, auto-login after registration is
	// also suppressed, since the freshly registered user is not yet verified.
	//
	// Default: false
	RequireVerifiedEmail bool
	// MagicLinkSuccessfulRedirectURL is used when logging in using magic link, when login was successful user will be redirected to this URL.
	// It is required if magic link is used, otherwise magic link login will not work properly.
	//
	// Default: ""
	MagicLinkSuccessfulRedirectURL string
	// MagicLinkFailedRedirectURL is used when logging in using magic link, when login failed user will be redirected to this URL.
	// It is required if magic link is used, otherwise magic link login will not work properly.
	//
	// Default: ""
	MagicLinkFailedRedirectURL string
	// CookieSecure controls the Secure attribute on the session cookie. When nil it
	// defaults to true; set it to a pointer to false only for local HTTP development.
	//
	// Default: true
	CookieSecure *bool
	// CookieSameSite controls the SameSite attribute on the session cookie. When unset
	// (zero value) it defaults to http.SameSiteLaxMode.
	//
	// SameSite is the library's built-in CSRF mitigation: with the default Lax, browsers
	// do not attach the session cookie to cross-site POST/PUT/DELETE requests, so
	// state-changing endpoints are protected from classic CSRF. For especially sensitive
	// actions, add an application-layer CSRF token as defense in depth. SameSiteStrictMode
	// hardens this further but breaks the OAuth callback (a cross-site top-level GET), so
	// prefer Lax if you use OAuth.
	//
	// Default: Lax
	CookieSameSite http.SameSite
	// CookieDomain sets the Domain attribute on the session cookie. Empty produces a
	// host-only cookie.
	//
	// Default: ""
	CookieDomain string
	// CookieName overrides the session cookie name.
	//
	// Default: "session"
	CookieName string
}

// TokenConfig sets how long the single-use tokens emailed to users stay valid.
// Each field maps to one verification flow; a zero value falls back to the library
// default. Keep these short — they bound the window an intercepted link is usable.
type TokenConfig struct {
	// EmailVerification is the lifetime of the email-verification link sent on
	// registration.
	//
	// Default: 5 minutes
	EmailVerification time.Duration
	// PasswordReset is the lifetime of the password-reset link.
	//
	// Default: 5 minutes
	PasswordReset time.Duration
	// MagicLink is the lifetime of the passwordless magic-link sign-in link.
	//
	// Default: 5 minutes
	MagicLink time.Duration
	// EmailChange is the lifetime of the confirmation link sent to a new email
	// address when an authenticated user changes their email.
	//
	// Default: 5 minutes
	EmailChange time.Duration
}

// RateLimitBackend selects a built-in counter store for rate limiting.
type RateLimitBackend int

const (
	// RateLimitMemory keeps counters in process. It is the default and is correct
	// for a single instance, but limits are per-process (N replicas = N times the
	// limit) and reset on restart.
	RateLimitMemory RateLimitBackend = iota
	// RateLimitPostgres keeps counters in Postgres (using the library's existing
	// pool), so limits are shared and authoritative across replicas. Use it when you
	// run more than one instance.
	RateLimitPostgres
)

// RateLimitConfig tunes abuse protection on the auth endpoints. A nil RateLimitConfig
// enables the built-in defaults; set Enabled to a pointer to false to turn protection
// off entirely.
//
// Limits are enforced with a token-bucket algorithm derived from each Rule's
// {Max, Window}: a burst of up to Max is allowed, refilling to full over Window. Over
// the limit, callers receive HTTP 429 with a Retry-After header — except the
// per-account cap on the email-sending endpoints, which stays silent (the generic 200
// response is unchanged and the extra email is dropped) so it can't be used to
// enumerate accounts.
type RateLimitConfig struct {
	// Enabled toggles all rate limiting. When nil it defaults to true.
	//
	// Default: true
	Enabled *bool
	// Backend selects a built-in counter store (in-memory or Postgres). Ignored when
	// Store is set.
	//
	// Default: RateLimitMemory
	Backend RateLimitBackend
	// Store plugs in a custom RateLimiter (e.g. Redis), overriding Backend.
	//
	// Default: nil (use Backend)
	Store RateLimiter
	// Login throttles failed password logins, keyed on client IP and on the targeted
	// account. A successful login clears the account counter.
	//
	// Default: 10 / 15m per IP, 5 / 15m per account
	Login Rule
	// SendEmail throttles the address-sending endpoints (password reset,
	// resend-verification, magic link) to curb email flooding.
	//
	// Default: 20 / 1h per IP, 3 / 1h per account
	SendEmail Rule
	// Register throttles account creation. Keyed on client IP (PerAccount is unused).
	//
	// Default: 10 / 1h per IP
	Register Rule
	// Sensitive throttles authenticated re-authentication actions (change password,
	// change email), keyed on client IP and on the acting user.
	//
	// Default: 20 / 1h per IP, 10 / 1h per user
	Sensitive Rule
}

// Rule is a per-flow limit with two independent dimensions. A zero-valued Limit uses
// the flow's default; set a Limit's Max to a negative number to disable that
// dimension.
type Rule struct {
	// PerIP caps requests from a single client IP (catches spray / stuffing).
	PerIP Limit
	// PerAccount caps requests targeting a single account or user (catches a focused
	// attack on one victim). Unused by the Register flow.
	PerAccount Limit
}

// Limit is one token-bucket limit: at most Max requests per Window.
type Limit struct {
	// Max is the burst size and the number of requests allowed per Window. Zero uses
	// the default; a negative value disables this dimension.
	Max int
	// Window is the period over which the bucket refills to full. Zero uses the
	// default.
	Window time.Duration
}

// TrustedProxyConfig controls client-IP resolution when the app runs behind a
// proxy or load balancer. Only enable this for infrastructure you control:
// X-Forwarded-For is client-supplied and trivially spoofable otherwise.
type TrustedProxyConfig struct {
	// TrustForwardedHeader turns on X-Forwarded-For parsing. When false the direct
	// peer (RemoteAddr) is always used.
	TrustForwardedHeader bool
	// TrustedHops is how many trusted proxies sit in front of the app. The client IP
	// is taken that many entries from the right of the forwarded chain, so a
	// client-supplied left-most value can't be trusted. For a single load balancer,
	// set this to 1.
	//
	// Default: 0
	TrustedHops int
}
