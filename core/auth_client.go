package core

import (
	"fmt"
	"net/http"

	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/AdrianTworek/go-auth/core/mailer"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type AuthClient struct {
	config    *AuthConfig
	store     *store.Storage
	hookStore *HookStore
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

func (c *AuthClient) CanLoginWithOAuth() bool {
	return c.config.OAuth != nil && len(c.config.OAuth.Providers) > 0
}

func (c *AuthClient) SetupGoth() {
	if !c.CanLoginWithOAuth() {
		panic("OAuth providers are not configured. Please provide at least one OAuth provider in the AuthConfig.")
	}

	gothic.GetProviderName = func(r *http.Request) (string, error) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			return "", fmt.Errorf("provider is required")
		}
		return provider, nil
	}

	sessionStore := sessions.NewCookieStore([]byte(c.config.SessionSecret))
	gothic.Store = sessionStore

	goth.UseProviders(
		c.config.OAuth.Providers...,
	)
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

	var hookStore *HookStore
	if config.Hooks != nil {
		hookStore = NewHookStore(*config.Hooks)
	} else {
		hookStore = nil
	}

	return &AuthClient{
		config:    config,
		store:     store.NewStorage(db),
		hookStore: hookStore,
	}, nil
}
