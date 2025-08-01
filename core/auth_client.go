package core

import (
	"net/http"

	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/AdrianTworek/go-auth/core/mailer"
)

type AuthClient struct {
	config *AuthConfig
	store  *store.Storage
}

// Checks if mailer is configured and magic link redirect urls are also provided
func (c *AuthClient) CanLoginWithMagicLink() bool {
	return c.config.Session.MagicLinkSuccesfulRedirectURL != "" && c.config.Session.MagicLinkFailedRedirectURL != "" && c.config.Mailer != nil
}

// Redirects from the endpoint to the success frontend url provided by user
func (c *AuthClient) SuccessMagicLinkRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.config.Session.MagicLinkSuccesfulRedirectURL, http.StatusFound)
}

// Redirects from the endpoint to the failed frontend url provided by user
func (c *AuthClient) FailedMagicLinkRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.config.Session.MagicLinkFailedRedirectURL, http.StatusSeeOther)
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
