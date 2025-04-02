package core

type AuthConfig struct {
	Db      DatabaseConfig
	Mailer  MailerConfig
	Session SessionConfig
}

type DatabaseConfig struct {
	Dsn string
}

// TODO: Implement
type MailerConfig struct{}

// TODO: Implement
type SessionConfig struct{}
