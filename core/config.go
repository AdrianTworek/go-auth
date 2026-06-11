package core

import (
	"net/http"

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
	OAuth         *OAuthConfig
	Mailer        mailer.Mailer
	Hooks         *HookMap
	BaseURL       string
	SessionSecret string
}

type OAuthConfig struct {
	// Goth provider objects that are used to setup goth authentication without any additional configuration.
	Providers []goth.Provider
}

type DatabaseConfig struct {
	Dsn string
}

type SessionConfig struct {
	// LoginAfterRegister specifies whether to log in the user after registration.
	//
	// Default: false
	LoginAfterRegister bool
	// MagicLinkSuccesfulRedirectURL is used when logging in using magic link, when login was successful user will be redirected to this URL.
	// It is required if magic link is used, otherwise magic link login will not work properly.
	//
	// Default: ""
	MagicLinkSuccesfulRedirectURL string
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
