package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---------------------------------------------------------------

// oauthClientFor builds a client whose fake provider is registered under an arbitrary
// name, so one test can drive two different providers against the same database.
// SetupGoth replaces the global provider registry, so callbacks must be driven one at a
// time — which they are, since tests here do not run in parallel.
func oauthClientFor(t *testing.T, app *TestApp, provider string, user goth.User, trusted ...string) *AuthClient {
	t.Helper()
	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		SessionSecret: app.env.SessionSecret,
		Mailer:        app.mailer,
		OAuth: &OAuthConfig{
			Providers:        []goth.Provider{&fakeOAuthProvider{name: provider, user: user}},
			TrustedProviders: trusted,
		},
	})
	require.NoError(t, err)
	ac.SetupGoth()
	return ac
}

func oauthCallbackRequestFor(t *testing.T, provider string) *http.Request {
	t.Helper()
	tmpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tmpRec := httptest.NewRecorder()
	require.NoError(t, gothic.StoreInSession(provider, (&fakeOAuthSession{}).Marshal(), tmpReq, tmpRec))

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/callback?provider="+provider, nil)
	for _, c := range tmpRec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// signInWithProvider drives one OAuth callback and returns the recorder.
func signInWithProvider(t *testing.T, ac *AuthClient, provider string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := oauthCallbackRequestFor(t, provider)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	ac.OAuthCallbackHandler()(rec, req)
	return rec
}

// --- the regressions that motivated the feature ----------------------------

// Linking a second provider used to destroy the first: the user record held one
// provider/id pair, so the later sign-in simply overwrote it and the original way of
// signing in stopped working, silently.
func Test_Integration_SecondProviderDoesNotDisplaceTheFirst(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := "two-providers@example.com"

	first := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-1", Email: email})
	require.Equal(t, http.StatusOK, signInWithProvider(t, first, "alpha", nil).Code)

	// The same person signing in with a second provider, on the same address. "beta" is
	// trusted, so it is allowed to attach rather than being refused.
	second := oauthClientFor(t, app, "beta", goth.User{Provider: "beta", UserID: "beta-1", Email: email}, "beta")
	require.Equal(t, http.StatusOK, signInWithProvider(t, second, "beta", nil).Code)

	linked, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, email))
	require.NoError(t, err)
	require.Len(t, linked, 2, "both links must survive")

	providers := []string{linked[0].Provider, linked[1].Provider}
	assert.ElementsMatch(t, []string{"alpha", "beta"}, providers)

	// And the original provider still signs the same person in.
	again := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-1", Email: email})
	require.Equal(t, http.StatusOK, signInWithProvider(t, again, "alpha", nil).Code)
}

// Identity is the provider's own account id, so the same account signing in repeatedly
// resolves to one user and one link.
func Test_Integration_RepeatedProviderSignInIsIdempotent(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := "repeat@example.com"
	user := goth.User{Provider: "alpha", UserID: "alpha-1", Email: email}

	for i := 0; i < 3; i++ {
		ac := oauthClientFor(t, app, "alpha", user)
		require.Equal(t, http.StatusOK, signInWithProvider(t, ac, "alpha", nil).Code)
	}

	linked, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, email))
	require.NoError(t, err)
	assert.Len(t, linked, 1)
}

// A provider that changes the email it asserts must still resolve to the same account:
// the provider account id is the identity, not the address.
func Test_Integration_ProviderSignInFollowsTheAccountIDNotTheEmail(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	original := "stable@example.com"
	first := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-1", Email: original})
	require.Equal(t, http.StatusOK, signInWithProvider(t, first, "alpha", nil).Code)
	uid := userID(t, db, original)

	// Same provider account, different asserted address.
	second := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-1", Email: "changed@example.com"})
	require.Equal(t, http.StatusOK, signInWithProvider(t, second, "alpha", nil).Code)

	linked, err := app.storage.Account.ListForUser(t.Context(), uid)
	require.NoError(t, err)
	assert.Len(t, linked, 1, "the same provider account must not create a second user or link")
}

// --- linking while signed in -----------------------------------------------

func Test_Integration_LinkProviderWhileSignedIn(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[DefaultUser].Email
	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)

	// An untrusted provider, to show that a deliberate link needs no trust: trust only
	// governs attaching on the strength of an asserted email, with nobody signed in.
	ac := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-7", Email: "other@example.com"})
	rec := signInWithProvider(t, ac, "alpha", cookie)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	linked, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, email))
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assert.Equal(t, "alpha-7", linked[0].ProviderAccountID)
}

func Test_Integration_LinkingAnAccountOwnedByAnotherUserIsRefused(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	// Someone else already holds this provider account.
	owner := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-9", Email: "owner@example.com"})
	require.Equal(t, http.StatusOK, signInWithProvider(t, owner, "alpha", nil).Code)
	ownerID := userID(t, db, "owner@example.com")

	// A different, signed-in user tries to claim it.
	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	thief := oauthClientFor(t, app, "alpha", goth.User{Provider: "alpha", UserID: "alpha-9", Email: "owner@example.com"})
	rec := signInWithProvider(t, thief, "alpha", cookie)

	require.Equal(t, http.StatusConflict, rec.Code)

	stillOwned, err := app.storage.Account.ListForUser(t.Context(), ownerID)
	require.NoError(t, err)
	require.Len(t, stillOwned, 1, "the link must not be moved away from its owner")

	claimed, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, TestUserData[DefaultUser].Email))
	require.NoError(t, err)
	assert.Empty(t, claimed)
}

func Test_Integration_LinkingAProviderAlreadyLinkedToYouIsANoOp(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	gothUser := goth.User{Provider: "alpha", UserID: "alpha-3", Email: "x@example.com"}

	ac := oauthClientFor(t, app, "alpha", gothUser)
	require.Equal(t, http.StatusOK, signInWithProvider(t, ac, "alpha", cookie).Code)

	again := oauthClientFor(t, app, "alpha", gothUser)
	require.Equal(t, http.StatusOK, signInWithProvider(t, again, "alpha", cookie).Code)

	linked, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, TestUserData[DefaultUser].Email))
	require.NoError(t, err)
	assert.Len(t, linked, 1)
}

// --- audit -----------------------------------------------------------------

func Test_Integration_AuditAccountLinked(t *testing.T) {
	rec := &auditRecorder{}
	app, dbCtr, db := SetupIntegration(t, auditConfig(rec, EventAccountLinked))
	defer CleanupIntegration(t, dbCtr, db)

	hooks := HookMap{EventAccountLinked: HookList{rec.hook}}
	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		SessionSecret: app.env.SessionSecret,
		Mailer:        app.mailer,
		Hooks:         &hooks,
		OAuth: &OAuthConfig{
			Providers: []goth.Provider{&fakeOAuthProvider{
				name: "alpha",
				user: goth.User{Provider: "alpha", UserID: "alpha-5", Email: "audit-link@example.com"},
			}},
		},
	})
	require.NoError(t, err)
	ac.SetupGoth()

	require.Equal(t, http.StatusOK, signInWithProvider(t, ac, "alpha", nil).Code)

	ev := rec.only(t, EventAccountLinked)
	require.NotNil(t, ev.Audit)
	assert.Equal(t, AuditTargetAccount, ev.Audit.TargetType)
	assert.Equal(t, "alpha", ev.Audit.Provider)
	assert.NotEmpty(t, ev.Audit.TargetID)

	linked, err := app.storage.Account.ListForUser(t.Context(), userID(t, db, "audit-link@example.com"))
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assert.Equal(t, linked[0].ID, ev.Audit.TargetID, "the event names the link it created")
}
