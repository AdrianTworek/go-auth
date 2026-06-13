package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/AdrianTworek/go-auth/core/internal/store"
)

type TestUser struct {
	Email         string
	EmailVerified bool
	Password      string
	SessionID     string
}

type TestHelper struct {
	t   *testing.T
	app *TestApp
}

func newTestHelper(t *testing.T, app *TestApp) *TestHelper {
	return &TestHelper{
		t:   t,
		app: app,
	}
}

func (th *TestHelper) GetSessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "session" {
			return cookie
		}
	}
	return nil
}

func (th *TestHelper) CreateUser(email, password string) (*TestUser, *httptest.ResponseRecorder) {
	user := &TestUser{
		Email:    email,
		Password: password,
	}

	body := map[string]string{
		"email":           email,
		"password":        password,
		"confirmPassword": password,
	}
	json, err := json.Marshal(body)
	assert.NoError(th.t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	th.app.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		th.t.Logf("Registration failed with status %d: %s", rr.Code, rr.Body.String())
		return nil, rr
	}

	return user, rr
}

func (th *TestHelper) LoginUser(email, password string) (*TestUser, *httptest.ResponseRecorder) {
	user := &TestUser{
		Email:    email,
		Password: password,
	}

	body := map[string]string{
		"email":    email,
		"password": password,
	}
	json, err := json.Marshal(body)
	assert.NoError(th.t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/login",
		bytes.NewReader(json),
	)
	rr := httptest.NewRecorder()
	th.app.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		th.t.Logf("Login failed with status %d: %s", rr.Code, rr.Body.String())
		return user, rr
	}

	// Set session ID to the user
	sessionCookie := th.GetSessionCookie(rr)
	if sessionCookie == nil {
		th.t.Error("No session cookie found after successful login")
		return user, rr
	}
	user.SessionID = sessionCookie.Value

	return user, rr
}

func (th *TestHelper) LoginAs(userType TestUserType) (*TestUser, *httptest.ResponseRecorder) {
	userData, exists := TestUserData[userType]
	if !exists {
		th.t.Fatalf("Test user type %s not found", userType)
		return nil, nil
	}

	return th.LoginUser(userData.Email, userData.Password)
}

func Test_Application_Start(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	assert.NotNil(t, app)
	assert.NotNil(t, dbCtr)
	assert.NotNil(t, db)
}

func Test_Integration_RegisterUserSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	app.mailer.AssertExpectations(t)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, user.Email)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.Equal(t, user.Email, dbUser.Email)
	assert.True(t, dbUser.Password.Compare("Password123!"))
	assert.NotEmpty(t, dbUser.ID)
}

func Test_Integration_DontCreateSessionAfterRegister(t *testing.T) {
	c := NewTestAuthConfig(nil, &SessionConfig{LoginAfterRegister: false}, nil)
	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)

	user, rr := helper.CreateUser(
		userEmail,
		"Password123!",
	)

	app.mailer.AssertExpectations(t)

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Empty(t, user.SessionID)
	sessionCookie := helper.GetSessionCookie(rr)
	assert.Nil(t, sessionCookie)
}

func Test_Integration_RegisterUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test", "short")

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, "test")
	assert.Error(t, err)
	assert.Nil(t, dbUser)
}

func Test_Integration_LoginUserSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.LoginAs(DefaultUser)
	sessionCookie := helper.GetSessionCookie(rr)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, user.SessionID)
	assert.Equal(t, user.SessionID, sessionCookie.Value)
	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)

	session, err := app.storage.Session.Validate(t.Context(), nil, user.SessionID)
	assert.NoError(t, err)
	assert.NotNil(t, session)
}

func Test_Integration_LoginUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginUser("test", "short")
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	_, rr = helper.LoginUser("test_invalid@example.com", "WrongP@ssword")
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	cookies := rr.Result().Cookies()
	assert.Empty(t, cookies)
}

func Test_Integration_GetMeSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.LoginAs(DefaultUser)
	sessionCookie := helper.GetSessionCookie(rr)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/me",
		nil,
	)
	req.AddCookie(sessionCookie)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotNil(t, sessionCookie)

	var response map[string]any
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, user.Email, response["data"].(map[string]any)["user"].(map[string]any)["email"])
}

func Test_Integration_LogoutUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginAs(DefaultUser)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/logout",
		nil,
	)
	req.AddCookie(helper.GetSessionCookie(rr))

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	sessionCookie := helper.GetSessionCookie(rr)
	assert.NotNil(t, sessionCookie)
	assert.Equal(t, sessionCookie.MaxAge, 0)

	session, err := app.storage.Session.Validate(t.Context(), nil, sessionCookie.Value)
	assert.Error(t, err)
	assert.Nil(t, session)
}

func Test_Integration_VerifyEmailSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	helper.CreateUser(userEmail, "Password123!")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, "new_user@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.False(t, dbUser.EmailVerified)

	app.mailer.AssertExpectations(t)

	calls := app.mailer.Calls
	token := calls[0].Arguments[1].(string)
	assert.NotEmpty(t, token)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/verify/"+token,
		nil,
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	dbUser, err = app.storage.User.GetByEmail(t.Context(), nil, "new_user@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.EmailVerified)
}

func Test_Integration_VerifyEmailInvalidToken(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/verify/invalid_token",
		nil,
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func Test_Integration_SendPasswordResetLinkSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordResetEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	body := map[string]string{
		"email": user.Email,
	}
	json, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/reset-password",
		bytes.NewReader(json),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	app.mailer.AssertExpectations(t)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func Test_Integration_SendPasswordResetLinkInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	// A malformed email fails request validation.
	body := map[string]string{
		"email": "not-an-email",
	}
	json, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/reset-password",
		bytes.NewReader(json),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// Test_Integration_SendPasswordResetLinkUnknownEmailIsGeneric verifies that an
// unregistered (but well-formed) email gets the same generic 200 as a registered
// one, so the response can't be used to enumerate accounts.
func Test_Integration_SendPasswordResetLinkUnknownEmailIsGeneric(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	body, err := json.Marshal(map[string]string{"email": "does_not_exist@example.com"})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, genericResetMessage, resp["data"].(map[string]any)["message"])
}

func Test_Integration_CompletePasswordResetSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"

	app.mailer.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordResetEmail", userEmail, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordChangedEmail", userEmail).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	// Send password reset link
	body := map[string]string{
		"email": user.Email,
	}
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/reset-password",
		bytes.NewReader(jsonBody),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	calls := app.mailer.Calls
	token := calls[1].Arguments[1].(string)
	assert.NotEmpty(t, token)

	// Complete password reset
	body = map[string]string{
		"password":        "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123!",
	}
	jsonBody, err = json.Marshal(body)
	assert.NoError(t, err)

	req = httptest.NewRequest(
		http.MethodPut,
		"/auth/reset-password/"+token,
		bytes.NewReader(jsonBody),
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, user.Email)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.Password.Compare("NewP@ssword123!"))
}

func Test_Integration_CompletePasswordResetInvalidPassword(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordResetEmail", mock.Anything, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	// Send password reset link
	body := map[string]string{
		"email": user.Email,
	}
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/reset-password",
		bytes.NewReader(jsonBody),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	calls := app.mailer.Calls
	token := calls[0].Arguments[1].(string)
	assert.NotEmpty(t, token)

	// Complete password reset
	body = map[string]string{
		"password":        "NewP@ssword123!",
		"confirmPassword": "NewP@ssword123456!",
	}
	jsonBody, err = json.Marshal(body)
	assert.NoError(t, err)

	req = httptest.NewRequest(
		http.MethodPut,
		"/auth/reset-password/"+token,
		bytes.NewReader(jsonBody),
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, user.Email)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.Password.Compare("Password123!"))
}

func Test_Integration_SendMagicLink(t *testing.T) {
	sc := &SessionConfig{
		MagicLinkSuccesfulRedirectURL: "http://localhost:6969/success",
		MagicLinkFailedRedirectURL:    "http://localhost:6969/failed",
		LoginAfterRegister:            true,
	}
	c := NewTestAuthConfig(nil, sc, nil)
	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendMagicLinkEmail", userEmail, mock.Anything).Return(nil)

	body := map[string]string{
		"email": userEmail,
	}
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/magic-link",
		bytes.NewReader(jsonBody),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	calls := app.mailer.Calls
	token := calls[0].Arguments[1].(string)
	assert.NotEmpty(t, token)

	app.mailer.AssertExpectations(t)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func Test_Integration_CompleteMagicLink(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendMagicLinkEmail", userEmail, mock.Anything).Return(nil)

	body := map[string]string{
		"email": userEmail,
	}
	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/magic-link",
		bytes.NewReader(jsonBody),
	)

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// NOTE: first send request with invalid magic link to check if redirect to failed page works
	token := "invalid_token"

	req = httptest.NewRequest(
		http.MethodGet,
		"/auth/magic-link/"+token,
		nil,
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)

	// NOTE: now send valid token to check if redirect worked correctly and if cookies are set properly
	token = app.mailer.Calls[0].Arguments[1].(string)
	assert.NotEmpty(t, token)

	req = httptest.NewRequest(
		http.MethodGet,
		"/auth/magic-link/"+token,
		nil,
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	app.mailer.AssertExpectations(t)

	assert.Equal(t, http.StatusFound, rr.Code)
}

// Test_Integration_UserWithoutPasswordStoresNull verifies that a user created
// without a password (e.g. an OAuth-only account) is persisted with a NULL
// password rather than an empty byte array.
func Test_Integration_UserWithoutPasswordStoresNull(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	u := store.NewUser("oauth_only@example.com", true, nil, nil, nil, nil)
	err := app.storage.User.Create(t.Context(), nil, u)
	assert.NoError(t, err)

	var passwordIsNull bool
	err = db.QueryRowContext(
		t.Context(),
		`SELECT password IS NULL FROM users WHERE email = $1`,
		"oauth_only@example.com",
	).Scan(&passwordIsNull)
	assert.NoError(t, err)
	assert.True(t, passwordIsNull)
}

// Test_Integration_RequireVerifiedEmailBlocksUnverifiedLogin verifies that with
// RequireVerifiedEmail enabled, an unverified user is blocked from password login
// while a verified user is still allowed.
func Test_Integration_RequireVerifiedEmailBlocksUnverifiedLogin(t *testing.T) {
	c := NewTestAuthConfig(nil, &SessionConfig{RequireVerifiedEmail: true}, nil)
	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)

	// Unverified user is blocked with 403.
	_, rr := helper.LoginAs(UnverifiedUser)
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Verified user can still log in.
	_, rr = helper.LoginAs(DefaultUser)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// Test_Integration_PasswordResetTokenIsSingleUse verifies that a verification
// token is consumed atomically: once a reset succeeds, the same token cannot be
// replayed, and the rejected attempt has no side effects.
func Test_Integration_PasswordResetTokenIsSingleUse(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "single_use@example.com"
	app.mailer.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordResetEmail", userEmail, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordChangedEmail", userEmail).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	// Request a reset link and grab the emailed token.
	body, err := json.Marshal(map[string]string{"email": user.Email})
	assert.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	token := app.mailer.Calls[1].Arguments[1].(string)
	assert.NotEmpty(t, token)

	completeReset := func(newPassword string) *httptest.ResponseRecorder {
		b, err := json.Marshal(map[string]string{
			"password":        newPassword,
			"confirmPassword": newPassword,
		})
		assert.NoError(t, err)
		r := httptest.NewRequest(http.MethodPut, "/auth/reset-password/"+token, bytes.NewReader(b))
		w := httptest.NewRecorder()
		app.Router().ServeHTTP(w, r)
		return w
	}

	// First use succeeds.
	assert.Equal(t, http.StatusOK, completeReset("FirstNewP@ss1!").Code)

	// Reusing the same token must be rejected.
	assert.Equal(t, http.StatusBadRequest, completeReset("SecondNewP@ss1!").Code)

	// The password from the rejected second attempt must never have been applied.
	dbUser, err := app.storage.User.GetByEmail(t.Context(), nil, user.Email)
	assert.NoError(t, err)
	assert.True(t, dbUser.Password.Compare("FirstNewP@ss1!"))
	assert.False(t, dbUser.Password.Compare("SecondNewP@ss1!"))

	// The "password changed" side effect must have happened exactly once.
	app.mailer.AssertNumberOfCalls(t, "SendPasswordChangedEmail", 1)
}

// Test_Integration_PasswordResetInvalidatesExistingSessions verifies that
// completing a password reset revokes all of the user's existing sessions.
func Test_Integration_PasswordResetInvalidatesExistingSessions(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)

	// Establish an existing session by logging in.
	user, rr := helper.LoginAs(DefaultUser)
	assert.Equal(t, http.StatusOK, rr.Code)
	oldSession := helper.GetSessionCookie(rr)
	assert.NotNil(t, oldSession)

	// Sanity: the session is valid before the reset.
	session, err := app.storage.Session.Validate(t.Context(), nil, oldSession.Value)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	app.mailer.On("SendPasswordResetEmail", user.Email, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordChangedEmail", user.Email).Return(nil)

	// Request a reset link and grab the emailed token.
	body, err := json.Marshal(map[string]string{"email": user.Email})
	assert.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	token := app.mailer.Calls[0].Arguments[1].(string)
	assert.NotEmpty(t, token)

	// Complete the reset.
	body, err = json.Marshal(map[string]string{
		"password":        "BrandNewP@ss1!",
		"confirmPassword": "BrandNewP@ss1!",
	})
	assert.NoError(t, err)
	req = httptest.NewRequest(http.MethodPut, "/auth/reset-password/"+token, bytes.NewReader(body))
	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// The pre-existing session must now be invalid, both at the store level...
	session, err = app.storage.Session.Validate(t.Context(), nil, oldSession.Value)
	assert.Error(t, err)
	assert.Nil(t, session)

	// ...and end-to-end through the auth middleware.
	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(oldSession)
	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
