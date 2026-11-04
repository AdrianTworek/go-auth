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
	// Password describes what counts as an acceptable password, and optionally enables a
	// breached-password check. When nil the library's historical rule applies (8 to 72
	// characters, no breach check).
	//
	// Default: nil
	Password *PasswordConfig
	// TrustedProxy controls how the client IP is derived for rate limiting and
	// session records. When nil the library uses the direct peer (RemoteAddr), which
	// is correct when the app is exposed directly. Set it when behind a proxy or load
	// balancer so the real client IP is read from X-Forwarded-For.
	//
	// Default: nil (use RemoteAddr)
	TrustedProxy *TrustedProxyConfig
	// MFA enables two-factor authentication with an authenticator app (TOTP) and
	// single-use backup codes.
	//
	// When nil the capability does not exist: login behaves exactly as it does without
	// it, no encryption key is required, and the management routes are not mounted at
	// all. Note this is the opposite of RateLimit, where nil means ON. The difference is
	// deliberate — rate limiting needs no configuration and changes nothing for a
	// well-behaved caller, whereas this requires a secret you must generate and keep,
	// and it changes how every enrolled user signs in.
	//
	// There are two independent opt-ins, and a second factor is only ever demanded when
	// both are true: you enable the capability here, and the individual user chooses to
	// enrol. Enabling it for your service changes nothing visible until users start
	// enrolling — which reads as a bug to whoever tests it first, and is the intended
	// behaviour.
	//
	// Default: nil (off)
	MFA *MFAConfig
}

// MFAConfig configures two-factor authentication. Setting it at all enables the
// capability, so the only genuinely required field is EncryptionKey.
//
// Turning the feature back off downgrades anyone already enrolled, and the library
// cannot prevent that: verifying a code needs the encryption key, and removing this
// config removes the key. At construction the library logs loudly if enrolments exist
// while the feature is disabled. It is not an error — rolling back deliberately is
// legitimate, and refusing to start would be worse than the downgrade — but it is not
// allowed to be invisible either.
type MFAConfig struct {
	// EncryptionKey encrypts TOTP secrets at rest with AES-256-GCM. Required.
	//
	// Unlike a password, a TOTP secret has to be recoverable in order to verify a code,
	// so hashing is not an option; encryption is what stops a leaked database dump from
	// handing over every user's second factor.
	//
	// Supply either 64 hex characters — generate one with `openssl rand -hex 32` — or
	// exactly 32 raw bytes. Anything else fails at construction rather than silently
	// storing secrets in the clear.
	//
	// This is a real operational obligation: a secret you must generate, store and never
	// lose. Losing it means every enrolled user has to re-enrol, so keep it wherever you
	// keep your other secrets, and rotate it only with a plan — the library does not
	// re-encrypt existing secrets for you.
	EncryptionKey string
	// Issuer is the service name shown in the user's authenticator app, which is how
	// they tell your code apart from the dozen others in the list.
	//
	// Default: the host from BaseURL, or "go-auth" if that is unset or unparseable
	Issuer string
	// Period is how long each generated code is valid for.
	//
	// Changing this away from 30 seconds breaks compatibility with every mainstream
	// authenticator app, which implement the RFC's default and nothing else. It is
	// configurable for completeness, not because you should reach for it.
	//
	// Default: 30 seconds
	Period time.Duration
	// Digits is the length of a generated code. Like Period, moving away from the
	// default breaks real authenticator apps.
	//
	// Default: 6
	Digits int
	// SkewSteps accepts codes from this many time steps either side of the current one,
	// because phone clocks drift and a user who is told their correct code is wrong has
	// no way to fix it.
	//
	// It is a direct trade of usability against exposure: each extra step is another
	// Period-long window in which a given code is live. Zero uses the default; a
	// negative value accepts only the current step.
	//
	// Default: 1
	SkewSteps int
	// BackupCodeCount is how many single-use recovery codes are issued when a user
	// confirms enrolment, and again whenever they regenerate.
	//
	// Default: 10
	BackupCodeCount int
	// OAuthSatisfiesSecondFactor exempts OAuth sign-in from the second factor, for an
	// operator who considers the provider's own second factor sufficient.
	//
	// It defaults to false, meaning an OAuth sign-in is challenged like any other: the
	// safe behaviour is the default, and the exemption is a deliberate statement. Every
	// other path that creates a session honours the factor unconditionally.
	//
	// Default: false (challenge OAuth sign-ins)
	OAuthSatisfiesSecondFactor bool
}

type OAuthConfig struct {
	// Goth provider objects that are used to setup goth authentication without any additional configuration.
	Providers []goth.Provider
	// TrustedProviders names the providers whose asserted email address may be used to
	// attach them automatically to an existing account. Naming a provider here is a
	// statement that you trust it to verify email addresses before asserting them.
	//
	// Leave it empty and a provider signing in with an address that already belongs to
	// an account is refused, and told to sign in by their existing method and link
	// deliberately. That is the safe behaviour, and it is the default: a provider that
	// lets its users set an arbitrary address would otherwise be a route into somebody
	// else's account.
	//
	// Default: nil (never auto-link)
	TrustedProviders []string
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
	// MagicLinkMFARedirectURL is where a magic-link sign-in is sent when the user has a
	// second factor enabled. The challenge is appended as a "challenge" query parameter,
	// and the page there is expected to collect a code and post it to /auth/mfa/verify.
	//
	// It is REQUIRED when AuthConfig.MFA is set and magic-link sign-in is configured,
	// and client construction fails without it. Magic-link completion ends in a redirect
	// rather than a response body, so there is nowhere else to put a challenge; the
	// alternative of reusing MagicLinkSuccessfulRedirectURL would hand a user a page
	// saying they are signed in when no session was issued, and nothing would say so.
	//
	// The challenge travels in a query string, which is more exposed than a body —
	// referrer headers, browser history, server logs. That is accepted here because this
	// flow already puts a stronger credential (the magic-link token itself) in a URL, and
	// a challenge is single-use, expires in minutes, and is worthless without a valid
	// code.
	//
	// Default: ""
	MagicLinkMFARedirectURL string
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
// default. Keep these short — they bound the window an intercepted link is usable. The
// exception is EmailVerification, whose link arrives unprompted and so has to outlast
// ordinary mail delivery.
type TokenConfig struct {
	// EmailVerification is the lifetime of the email-verification link sent on
	// registration. It defaults to longer than the other tokens because the link is not
	// requested interactively: the user may not read their mail for a while, and the
	// link is recoverable via the resend endpoint in any case.
	//
	// Default: 1 hour
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
	// TwoFactorChallenge is the lifetime of the challenge issued when a correct password
	// (or magic link, or OAuth sign-in) meets a user with a second factor enabled. It is
	// exchanged for a session by submitting a valid code.
	//
	// Unlike the others this one is never emailed — it is held by someone standing at a
	// login form — so it belongs in the short family: it bounds how long an abandoned
	// half-finished sign-in stays usable.
	//
	// Default: 5 minutes
	TwoFactorChallenge time.Duration
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
	// MFAVerify throttles second-factor code submissions, keyed on client IP and on the
	// challenged account.
	//
	// It is a tighter rule than Login rather than a reuse of it, because a six-digit code
	// has a far smaller space than a password: at the default of 10 attempts per 15
	// minutes, guessing one is out of reach by orders of magnitude, while a user who
	// fumbles a code or two is unaffected.
	//
	// Backup-code attempts count against the same budget. That is deliberate — both are
	// attempts at the same factor, so counting them separately would double the
	// allowance.
	//
	// This limit is load-bearing beyond its own endpoint: a failed code deliberately does
	// NOT consume the challenge, so that one mistyped digit doesn't send the user back to
	// re-enter their password. That is only safe because the attempts are bounded here.
	// Loosening this rule means revisiting that decision with it.
	//
	// Default: 20 / 15m per IP, 10 / 15m per account
	MFAVerify Rule
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
