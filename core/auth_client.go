package core

import (
	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/AdrianTworek/go-auth/core/mailer"
)

type AuthClient struct {
	config *AuthConfig
	store  *store.Storage
}

func NewAuthClient(config *AuthConfig) (*AuthClient, error) {
	db, err := db.NewPostgres(config.Db.Dsn)
	if err != nil {
		return nil, err
	}

	// If no mailer is provided, use the default one that only logs the messages
	if config.Mailer == nil {
		config.Mailer = mailer.New()
	}

	return &AuthClient{
		config: config,
		store:  store.NewStorage(db),
	}, nil
}
