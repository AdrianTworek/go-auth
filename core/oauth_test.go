package core

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeOAuthProvider is a minimal goth.Provider whose FetchUser returns a fixed
// user, letting us drive OAuthCallbackHandler without a real OAuth provider.
type fakeOAuthProvider struct {
	name string
	user goth.User
}

func (p *fakeOAuthProvider) Name() string                           { return p.name }
func (p *fakeOAuthProvider) SetName(name string)                    { p.name = name }
func (p *fakeOAuthProvider) BeginAuth(string) (goth.Session, error) { return &fakeOAuthSession{}, nil }
func (p *fakeOAuthProvider) UnmarshalSession(string) (goth.Session, error) {
	return &fakeOAuthSession{}, nil
}
func (p *fakeOAuthProvider) FetchUser(goth.Session) (goth.User, error) { return p.user, nil }
func (p *fakeOAuthProvider) Debug(bool)                                {}
func (p *fakeOAuthProvider) RefreshTokenAvailable() bool               { return false }
func (p *fakeOAuthProvider) RefreshToken(string) (*oauth2.Token, error) {
	return nil, errors.New("not implemented")
}

type fakeOAuthSession struct{}

// GetAuthURL returns a URL without a state parameter so gothic's state check is a no-op.
func (s *fakeOAuthSession) GetAuthURL() (string, error)                          { return "https://example.com/auth", nil }
func (s *fakeOAuthSession) Marshal() string                                      { return "{}" }
func (s *fakeOAuthSession) Authorize(goth.Provider, goth.Params) (string, error) { return "", nil }

func newOAuthClient(t *testing.T, app *TestApp, user goth.User) *AuthClient {
	t.Helper()
	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		SessionSecret: app.env.SessionSecret,
		Mailer:        app.mailer,
		OAuth:         &OAuthConfig{Providers: []goth.Provider{&fakeOAuthProvider{name: "fake", user: user}}},
	})
	require.NoError(t, err)
	ac.SetupGoth() // registers the provider and configures gothic (global state)
	return ac
}

// newOAuthCallbackRequest builds a callback request carrying a valid gothic session
// cookie for the "fake" provider. SetupGoth must have been called first.
func newOAuthCallbackRequest(t *testing.T) *http.Request {
	t.Helper()
	tmpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tmpRec := httptest.NewRecorder()
	require.NoError(t, gothic.StoreInSession("fake", (&fakeOAuthSession{}).Marshal(), tmpReq, tmpRec))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=fake", nil)
	for _, c := range tmpRec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	return nil
}

func Test_Integration_OAuthCallbackCreatesUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	fakeUser := goth.User{
		Provider:  "fake",
		UserID:    "fake-123",
		Email:     "oauth_new@example.com",
		AvatarURL: "https://img.example.com/avatar.png",
	}
	ac := newOAuthClient(t, app, fakeUser)

	rec := httptest.NewRecorder()
	ac.OAuthCallbackHandler()(rec, newOAuthCallbackRequest(t))

	assert.Equal(t, http.StatusOK, rec.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, fakeUser.Email)
	require.NoError(t, err)
	assert.True(t, dbUser.EmailVerified)
	assert.Equal(t, "fake", dbUser.OAuthProvider.String)
	assert.Equal(t, "fake-123", dbUser.OAuthID.String)

	c := sessionCookie(rec)
	require.NotNil(t, c)
	assert.NotEmpty(t, c.Value)
}

func Test_Integration_OAuthCallbackLinksExistingUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	// DefaultUser is a seeded password account; logging in via OAuth with the same
	// email links the OAuth identity to it.
	fakeUser := goth.User{
		Provider: "fake",
		UserID:   "fake-999",
		Email:    TestUserData[DefaultUser].Email,
	}
	ac := newOAuthClient(t, app, fakeUser)

	rec := httptest.NewRecorder()
	ac.OAuthCallbackHandler()(rec, newOAuthCallbackRequest(t))

	assert.Equal(t, http.StatusOK, rec.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, fakeUser.Email)
	require.NoError(t, err)
	assert.Equal(t, "fake", dbUser.OAuthProvider.String)
	assert.Equal(t, "fake-999", dbUser.OAuthID.String)
	require.NotNil(t, sessionCookie(rec))
}

func Test_Integration_OAuthCallbackUnauthorizedWithoutSession(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	ac := newOAuthClient(t, app, goth.User{Provider: "fake", Email: "x@example.com"})

	// No gothic session cookie -> CompleteUserAuth fails.
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider=fake", nil)
	rec := httptest.NewRecorder()
	ac.OAuthCallbackHandler()(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
