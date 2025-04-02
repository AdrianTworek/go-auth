package core

import (
	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
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

	return &AuthClient{
		config: config,
		store:  store.NewStorage(db),
	}, nil
}
