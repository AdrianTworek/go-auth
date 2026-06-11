package core

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/db"
	"github.com/AdrianTworek/go-auth/core/internal/store"
	"github.com/AdrianTworek/go-auth/core/mailer"
)

type AuthClient struct {
	config     *AuthConfig
	store      *store.Storage
	hookStore  *HookStore
	cookieOpts auth.CookieOptions
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

// resolveCookieOptions builds the session cookie options from the session config,
// applying secure-by-default values for anything the consumer left unset.
func resolveCookieOptions(s *SessionConfig) auth.CookieOptions {
	opts := auth.CookieOptions{
		Name:     "session",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if s == nil {
		return opts
	}
	if s.CookieName != "" {
		opts.Name = s.CookieName
	}
	if s.CookieSecure != nil {
		opts.Secure = *s.CookieSecure
	}
	if s.CookieSameSite != 0 {
		opts.SameSite = s.CookieSameSite
	}
	opts.Domain = s.CookieDomain
	return opts
}

func NewAuthClient(config *AuthConfig) (*AuthClient, error) {
	// Default the session config so cookie/option resolution is always safe.
	if config.Session == nil {
		config.Session = &SessionConfig{}
	}

	// SessionSecret is the gothic OAuth-state cookie key; require a strong value
	// when OAuth is enabled. Validate before opening any resources.
	if config.OAuth != nil && len(config.OAuth.Providers) > 0 && len(config.SessionSecret) < 32 {
		return nil, fmt.Errorf("SessionSecret must be at least 32 bytes when OAuth is enabled")
	}

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
		// Create an empty hook store if no hooks are provided
		hookStore = NewHookStore(HookMap{})
	}

	return &AuthClient{
		config:     config,
		store:      store.NewStorage(db),
		hookStore:  hookStore,
		cookieOpts: resolveCookieOptions(config.Session),
	}, nil
}

func (ac *AuthClient) newSessionCookie(token string) *http.Cookie {
	return auth.NewSessionCookie(token, ac.cookieOpts)
}

func (ac *AuthClient) deleteSessionCookie() *http.Cookie {
	return auth.DeleteSessionCookie(ac.cookieOpts)
}

func (ac *AuthClient) cookieName() string {
	return ac.cookieOpts.Name
}
