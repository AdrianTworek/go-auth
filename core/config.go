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
