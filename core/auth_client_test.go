package core

import (
	"net/http"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCookieOptions_Defaults(t *testing.T) {
	for _, s := range []*SessionConfig{nil, {}} {
		opts := resolveCookieOptions(s)
		assert.Equal(t, "session", opts.Name)
		assert.True(t, opts.Secure) // secure by default
		assert.Equal(t, http.SameSiteLaxMode, opts.SameSite)
		assert.Empty(t, opts.Domain)
	}
}

func TestResolveCookieOptions_Custom(t *testing.T) {
	opts := resolveCookieOptions(&SessionConfig{
		CookieName:     "sid",
		CookieSecure:   Ptr(false),
		CookieSameSite: http.SameSiteStrictMode,
		CookieDomain:   "example.com",
	})
	assert.Equal(t, "sid", opts.Name)
	assert.False(t, opts.Secure)
	assert.Equal(t, http.SameSiteStrictMode, opts.SameSite)
	assert.Equal(t, "example.com", opts.Domain)
}

func TestPtr(t *testing.T) {
	assert.False(t, *Ptr(false))
	assert.Equal(t, 7, *Ptr(7))
	assert.Equal(t, "x", *Ptr("x"))
}

func TestCanLoginWithOAuth(t *testing.T) {
	none := &AuthClient{config: &AuthConfig{}}
	assert.False(t, none.CanLoginWithOAuth())

	empty := &AuthClient{config: &AuthConfig{OAuth: &OAuthConfig{}}}
	assert.False(t, empty.CanLoginWithOAuth())

	withProvider := &AuthClient{config: &AuthConfig{
		OAuth: &OAuthConfig{Providers: make([]goth.Provider, 1)},
	}}
	assert.True(t, withProvider.CanLoginWithOAuth())
}

func TestCanLoginWithMagicLink(t *testing.T) {
	missingURLs := &AuthClient{config: &AuthConfig{Session: &SessionConfig{}, Mailer: &MockMailer{}}}
	assert.False(t, missingURLs.CanLoginWithMagicLink())

	ready := &AuthClient{config: &AuthConfig{
		Session: &SessionConfig{
			MagicLinkSuccessfulRedirectURL: "https://app/success",
			MagicLinkFailedRedirectURL:     "https://app/failed",
		},
		Mailer: &MockMailer{},
	}}
	assert.True(t, ready.CanLoginWithMagicLink())
}

// These validations run before any database connection is opened, so they can be
// exercised without a container.
func TestNewAuthClient_RejectsWeakSessionSecretWithOAuth(t *testing.T) {
	_, err := NewAuthClient(&AuthConfig{
		Mailer:        &MockMailer{},
		Db:            &DatabaseConfig{Dsn: "postgres://unused"},
		OAuth:         &OAuthConfig{Providers: make([]goth.Provider, 1)},
		SessionSecret: "too-short",
	})
	assert.ErrorContains(t, err, "SessionSecret")
}

func TestNewAuthClient_RejectsInvalidBcryptCost(t *testing.T) {
	_, err := NewAuthClient(&AuthConfig{
		Db:         &DatabaseConfig{Dsn: "postgres://unused"},
		Mailer:     &MockMailer{},
		BcryptCost: 99,
	})
	assert.ErrorContains(t, err, "bcrypt cost")
}

// Leaving Mailer unset used to fall back silently to a stub that prints every token —
// reset and magic-link ones included — to stdout. It is now a construction error that
// names both the production and the development choice.
func TestNewAuthClient_RequiresAMailer(t *testing.T) {
	_, err := NewAuthClient(&AuthConfig{Db: &DatabaseConfig{Dsn: "postgres://unused"}})
	require.Error(t, err)
	assert.ErrorContains(t, err, "Mailer is required")
	assert.ErrorContains(t, err, "mailer.NewSMTP")
	assert.ErrorContains(t, err, "mailer.NewConsole")
}
