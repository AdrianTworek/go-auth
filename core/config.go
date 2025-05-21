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
	// FrontendRedirectURL is used when logging in using magic link, it declares where to redirect user after successful login.
	// It is required if magic link is used, otherwise magic link login will not work properly.
	//
	// Default: ""
	FrontendRedirectURL string
}
