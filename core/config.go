package core

import (
	"github.com/AdrianTworek/go-auth/core/mailer"
	"github.com/markbates/goth"
)

type AuthConfig struct {
	Db            *DatabaseConfig
	Session       *SessionConfig
	OAuth         *OAuthConfig
	Mailer        mailer.Mailer
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
	// Default: true
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
}
