package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// --- helpers ---------------------------------------------------------------

func loginCookie(t *testing.T, helper *TestHelper, userType TestUserType) *http.Cookie {
	t.Helper()
	_, rr := helper.LoginAs(userType)
	cookie := helper.GetSessionCookie(rr)
	require.NotNil(t, cookie, "expected a session cookie after login")
	return cookie
}

// sessionCookieFor mints a valid session for a user directly, for accounts that can't
// log in with a password (OAuth-only / magic-link-only).
func sessionCookieFor(t *testing.T, app *TestApp, userID string) *http.Cookie {
	t.Helper()
	token, err := app.storage.Session.Create(t.Context(), nil, &store.Session{
		UserID:    userID,
		IPAddress: "",
		UserAgent: "",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	return &http.Cookie{Name: "session", Value: token}
}

// insertPasswordlessUser creates a verified user with a NULL password and no OAuth
// link — the shape of a magic-link-only account.
func insertPasswordlessUser(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`INSERT INTO users (email, email_verified) VALUES ($1, true) RETURNING id`, email,
	).Scan(&id))
	return id
}

func userID(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&id))
	return id
}

func doJSON(t *testing.T, app *TestApp, method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

func doGet(t *testing.T, app *TestApp, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

// mailToken returns the token argument from the first recorded call to the named
// mailer method.
func mailToken(t *testing.T, app *TestApp, method string) string {
	t.Helper()
	for _, c := range app.mailer.Calls {
		if c.Method == method {
			return c.Arguments[1].(string)
		}
	}
	t.Fatalf("no %s mailer call was recorded", method)
	return ""
}

// --- change password -------------------------------------------------------

func Test_Integration_ChangePasswordSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// A second, unrelated session for the same user, to prove it gets revoked.
	otherCookie := sessionCookieFor(t, app, userID(t, db, TestUserData[DefaultUser].Email))

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie, map[string]string{
		"currentPassword": TestUserData[DefaultUser].Password,
		"newPassword":     "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123!",
	})
	require.Equal(t, http.StatusOK, rr.Code)
	app.mailer.AssertExpectations(t)

	// The new password now works.
	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, TestUserData[DefaultUser].Email)
	require.NoError(t, err)
	assert.True(t, dbUser.Password.Compare("NewP@ssword123!"))

	// The other device's session was revoked.
	_, err = app.storage.Session.Validate(t.Context(), nil, otherCookie.Value)
	assert.Error(t, err)

	// A fresh session was issued for the current device.
	newCookie := helper.GetSessionCookie(rr)
	require.NotNil(t, newCookie)
	_, err = app.storage.Session.Validate(t.Context(), nil, newCookie.Value)
	assert.NoError(t, err)
}

func Test_Integration_ChangePasswordWrongCurrent(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie, map[string]string{
		"currentPassword": "not-my-password",
		"newPassword":     "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123!",
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func Test_Integration_ChangePasswordNoPasswordUserDirectedToReset(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	uid := insertPasswordlessUser(t, db, "nopass@example.com")
	cookie := sessionCookieFor(t, app, uid)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie, map[string]string{
		"currentPassword": "anything",
		"newPassword":     "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123!",
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "password reset")
}

func Test_Integration_ChangePasswordRequiresAuth(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, nil, map[string]string{
		"currentPassword": "x",
		"newPassword":     "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123!",
	})
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- change email ----------------------------------------------------------

func Test_Integration_ChangeEmailFullFlow(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	newEmail := "changed@example.com"
	app.mailer.On("SendEmailChangeEmail", newEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        newEmail,
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	require.Equal(t, http.StatusOK, rr.Code)
	app.mailer.AssertExpectations(t)

	// The email is NOT changed until the link is visited.
	_, err := app.storage.User.GetByEmail(t.Context(), nil, TestUserData[DefaultUser].Email)
	require.NoError(t, err)

	// Visit the confirmation link.
	token := mailToken(t, app, "SendEmailChangeEmail")
	confirmRR := doGet(t, app, strings.Replace(PathConfirmEmailChange, "{token}", token, 1), nil)
	require.Equal(t, http.StatusOK, confirmRR.Code)

	// The account now uses the new (verified) email, and the old one no longer resolves.
	changed, err := app.storage.User.GetByEmail(t.Context(), nil, newEmail)
	require.NoError(t, err)
	assert.True(t, changed.EmailVerified)
	_, err = app.storage.User.GetByEmail(t.Context(), nil, TestUserData[DefaultUser].Email)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func Test_Integration_ChangeEmailOAuthLinkedBlocked(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	// Link an OAuth provider to the account.
	_, err := db.ExecContext(t.Context(),
		`UPDATE users SET oauth_provider = 'google', oauth_id = 'oauth-123' WHERE email = $1`,
		TestUserData[DefaultUser].Email)
	require.NoError(t, err)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        "brand-new@example.com",
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.Contains(t, rr.Body.String(), "google")
}

func Test_Integration_ChangeEmailAlreadyTaken(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail":        TestUserData[UnverifiedUser].Email, // already registered
		"currentPassword": TestUserData[DefaultUser].Password,
	})
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func Test_Integration_ChangeEmailNoPasswordUserSkipsReauth(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	newEmail := "ml-new@example.com"
	app.mailer.On("SendEmailChangeEmail", newEmail, mock.Anything).Return(nil)

	uid := insertPasswordlessUser(t, db, "magiclink@example.com")
	cookie := sessionCookieFor(t, app, uid)

	// No currentPassword supplied; the session plus new-email verification is the control.
	rr := doJSON(t, app, http.MethodPost, PathChangeEmail, cookie, map[string]string{
		"newEmail": newEmail,
	})
	assert.Equal(t, http.StatusOK, rr.Code)
	app.mailer.AssertExpectations(t)
}

func Test_Integration_ConfirmEmailChangeInvalidToken(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := doGet(t, app, strings.Replace(PathConfirmEmailChange, "{token}", "not-a-real-token", 1), nil)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
