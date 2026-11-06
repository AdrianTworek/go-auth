package core

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The pre-hijack these tests close: anyone can register someone else's address with a
// password of their choosing. The seeded UnverifiedUser plays that account — registered,
// never verified — and its password is the attacker's.

const attackerEmail = "attacker@evil.example"

// completeMagicLink requests a magic link for email and follows it, returning the
// completion response.
func completeMagicLink(t *testing.T, app *TestApp, email string) *http.Response {
	t.Helper()
	app.mailer.On("SendMagicLinkEmail", email, mock.Anything).Return(nil)
	rr := doJSON(t, app, http.MethodPost, PathSendMagicLink, nil, map[string]string{"email": email})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return doGet(t, app, "/auth/magic-link/"+mailToken(t, app, "SendMagicLinkEmail"), nil).Result()
}

func countRows(t *testing.T, db *sql.DB, table, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM `+table+` WHERE user_id = $1`, userID).Scan(&n))
	return n
}

func insertAccountLink(t *testing.T, db *sql.DB, userID, provider, providerAccountID, email string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO accounts (user_id, provider, provider_account_id, email) VALUES ($1, $2, $3, $4)`,
		userID, provider, providerAccountID, email)
	require.NoError(t, err)
}

// The owner proves the address with a magic link, and gets an account the attacker can
// no longer reach by any of the routes they set up beforehand.
func Test_Integration_MagicLinkClaimsAPreRegisteredAccount(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	victim := TestUserData[UnverifiedUser].Email
	attackerPassword := TestUserData[UnverifiedUser].Password
	uid := userID(t, db, victim)

	// Everything the attacker attaches while the account is unverified: a session, a
	// second factor, a pending email change to an address they control, and a provider.
	attacker := mfaLongSessionCookie(t, app, uid)
	mfaCompleteEnrolment(t, app, attacker, attackerPassword)
	app.mailer.On("SendEmailChangeEmail", attackerEmail, mock.Anything).Return(nil)
	app.mailer.On("SendEmailChangeNotification", victim, attackerEmail, mock.Anything).Return(nil)
	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, attacker, map[string]string{
		"newEmail": attackerEmail, "currentPassword": attackerPassword,
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	pendingChange := mailToken(t, app, "SendEmailChangeEmail")
	insertAccountLink(t, db, uid, "attackerhub", "attacker-1", attackerEmail)

	res := completeMagicLink(t, app, victim)

	t.Run("the owner is signed in, not sent to the attacker's second factor", func(t *testing.T) {
		require.Equal(t, http.StatusFound, res.StatusCode)
		loc, err := res.Location()
		require.NoError(t, err)
		assert.Equal(t, "/success", loc.Path)

		var owner *http.Cookie
		for _, c := range res.Cookies() {
			if c.Name == "session" {
				owner = c
			}
		}
		require.NotNil(t, owner, "the owner must get a session")
		assert.Equal(t, http.StatusOK, doGet(t, app, PathMe, owner).Code)
	})

	t.Run("the attacker's session is revoked", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, doGet(t, app, PathMe, attacker).Code)
	})

	t.Run("the attacker's password no longer signs in", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
			"email": victim, "password": attackerPassword,
		})
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var password []byte
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT password FROM users WHERE id = $1`, uid).Scan(&password))
		assert.Nil(t, password, "the attacker's password hash must be cleared, not merely bypassed")
	})

	t.Run("the attacker's pending email change cannot be confirmed", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, doGet(t, app, "/auth/change-email/"+pendingChange, nil).Code)
	})

	t.Run("the attacker's second factor and provider link are gone", func(t *testing.T) {
		assert.Zero(t, countRows(t, db, "totp_credentials", uid))
		assert.Zero(t, countRows(t, db, "totp_backup_codes", uid))
		assert.Zero(t, countRows(t, db, "accounts", uid))
		assert.Zero(t, countRows(t, db, "verifications", uid))
	})
}

// A verified account has already been proven by its owner; a magic link is just another
// way in, and must not cost them their password or their other sessions.
func Test_Integration_MagicLinkLeavesAVerifiedAccountAlone(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[DefaultUser].Email
	uid := userID(t, db, email)
	other := mfaLongSessionCookie(t, app, uid)
	insertAccountLink(t, db, uid, "alpha", "alpha-1", email)

	res := completeMagicLink(t, app, email)
	require.Equal(t, http.StatusFound, res.StatusCode)

	assert.Equal(t, http.StatusOK, doGet(t, app, PathMe, other).Code, "existing sessions survive")
	assertCanLogin(t, app, email, TestUserData[DefaultUser].Password)
	assert.Equal(t, 1, countRows(t, db, "accounts", uid), "provider links survive")
}

// A trusted provider asserting the account's own address is the same proof as a magic
// link, and claims the account the same way. The new link is the only one left.
func Test_Integration_TrustedAutoLinkClaimsAPreRegisteredAccount(t *testing.T) {
	// Not parallel: SetupGoth writes goth's provider registry and gothic's store, which
	// are package-level globals.
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	victim := TestUserData[UnverifiedUser].Email
	uid := userID(t, db, victim)
	attacker := mfaLongSessionCookie(t, app, uid)
	insertAccountLink(t, db, uid, "attackerhub", "attacker-1", attackerEmail)

	ac := oauthClientFor(t, app, "github",
		goth.User{Provider: "github", UserID: "victim-gh", Email: victim}, "github")
	rec := signInWithProvider(t, ac, "github", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	assert.Equal(t, http.StatusUnauthorized, doGet(t, app, PathMe, attacker).Code)
	rr := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email": victim, "password": TestUserData[UnverifiedUser].Password,
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	linked, err := app.storage.Account.ListForUser(t.Context(), uid)
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assert.Equal(t, "victim-gh", linked[0].ProviderAccountID)
}

// Signing in through a linked provider proves the provider account, whose address can
// be anything. It used to mark the user verified regardless, which let whoever linked
// it verify an address they never proved — and so skip the claim above entirely.
func Test_Integration_ProviderSignInDoesNotVerifyADifferentAddress(t *testing.T) {
	// Not parallel: SetupGoth writes goth's provider registry and gothic's store, which
	// are package-level globals.
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	victim := TestUserData[UnverifiedUser].Email
	uid := userID(t, db, victim)
	insertAccountLink(t, db, uid, "github", "attacker-gh", attackerEmail)

	ac := oauthClientFor(t, app, "github",
		goth.User{Provider: "github", UserID: "attacker-gh", Email: attackerEmail})
	rec := signInWithProvider(t, ac, "github", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var verified bool
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT email_verified FROM users WHERE id = $1`, uid).Scan(&verified))
	assert.False(t, verified, "a provider account's own address says nothing about the user's")
}
