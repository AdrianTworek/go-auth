package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	assert.NotNil(t, app)
	assert.NotNil(t, dbCtr)
	assert.NotNil(t, db)
}

func Test_Integration_RegisterUserSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	user, _ := helper.CreateUser(userEmail, "Password123!")

	app.mailer.AssertExpectations(t)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), user.Email, nil)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.Equal(t, user.Email, dbUser.Email)
	assert.True(t, dbUser.Password.Compare("Password123!"))
	assert.NotEmpty(t, dbUser.ID)
}

func Test_Integration_RegisterUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser("test", "short")

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	dbUser, err := app.storage.User.GetByEmail(t.Context(), "test", nil)
	assert.Error(t, err)
	assert.Nil(t, dbUser)
}

func Test_Integration_LoginUserSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	user, rr := helper.LoginAs(DefaultUser)
	sessionCookie := helper.GetSessionCookie(rr)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, user.SessionID)
	assert.Equal(t, user.SessionID, sessionCookie.Value)
	assert.NotNil(t, sessionCookie)
	assert.NotEmpty(t, sessionCookie.Value)

	session, err := app.storage.Session.Validate(t.Context(), user.SessionID)
	assert.NoError(t, err)
	assert.NotNil(t, session)
}

func Test_Integration_LoginUserInvalidInput(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
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
	app, dbCtr, db := SetupIntegration(t)
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
	app, dbCtr, db := SetupIntegration(t)
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

	session, err := app.storage.Session.Validate(t.Context(), sessionCookie.Value)
	assert.Error(t, err)
	assert.Nil(t, session)
}

func Test_Integration_VerifyEmailSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "new_user@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	helper.CreateUser(userEmail, "Password123!")

	dbUser, err := app.storage.User.GetByEmail(t.Context(), "new_user@example.com", nil)
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

	dbUser, err = app.storage.User.GetByEmail(t.Context(), "new_user@example.com", nil)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.EmailVerified)
}

func Test_Integration_VerifyEmailInvalidToken(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
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
	app, dbCtr, db := SetupIntegration(t)
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
	app, dbCtr, db := SetupIntegration(t)
	defer CleanupIntegration(t, dbCtr, db)

	body := map[string]string{
		"email": "invalid_email@example.com",
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

func Test_Integration_CompletePasswordResetSuccess(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
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

	dbUser, err := app.storage.User.GetByEmail(t.Context(), user.Email, nil)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.Password.Compare("NewP@ssword123!"))
}

func Test_Integration_CompletePasswordResetInvalidPassword(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
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

	dbUser, err := app.storage.User.GetByEmail(t.Context(), user.Email, nil)
	assert.NoError(t, err)
	assert.NotNil(t, dbUser)
	assert.True(t, dbUser.Password.Compare("Password123!"))
}

func Test_Integration_SendMagicLink(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t)
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
	app, dbCtr, db := SetupIntegration(t)
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

	// Invalid magic link
	token := "invalid_token"

	req = httptest.NewRequest(
		http.MethodGet,
		"/auth/magic-link/"+token,
		nil,
	)

	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Valid magic link
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

	assert.Equal(t, http.StatusOK, rr.Code)
}
