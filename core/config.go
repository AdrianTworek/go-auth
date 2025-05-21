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

// TODO: Implement
type SessionConfig struct{}
