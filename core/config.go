package core

import "github.com/AdrianTworek/go-auth/core/mailer"

type AuthConfig struct {
	Db      DatabaseConfig
	Session SessionConfig
	Mailer  mailer.Mailer
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
