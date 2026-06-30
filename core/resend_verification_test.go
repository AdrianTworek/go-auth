package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func postResendVerification(t *testing.T, app *TestApp, email string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, PathResendVerification, bytes.NewReader(body))
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

func assertGenericVerificationMessage(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok, "response missing data object: %s", rr.Body.String())
	assert.Equal(t, genericVerificationMessage, data["message"])
}

// Test_Integration_ResendVerificationResendsForUnverifiedUser verifies that an
// unverified account gets a fresh verification email and a new token row.
func Test_Integration_ResendVerificationResendsForUnverifiedUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[UnverifiedUser].Email
	app.mailer.On("SendVerificationEmail", email, mock.Anything).Return(nil)

	rr := postResendVerification(t, app, email)

	assert.Equal(t, http.StatusOK, rr.Code)
	assertGenericVerificationMessage(t, rr)
	app.mailer.AssertExpectations(t)

	var count int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM verifications v
		 JOIN users u ON u.id = v.user_id
		 WHERE u.email = $1 AND v.intent = 'email_verification'`, email,
	).Scan(&count))
	assert.Equal(t, 1, count, "a verification token should have been created")
}

// Test_Integration_ResendVerificationSkipsVerifiedUser verifies that an already-verified
// account gets the generic response but no email.
func Test_Integration_ResendVerificationSkipsVerifiedUser(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := postResendVerification(t, app, TestUserData[DefaultUser].Email) // already verified

	assert.Equal(t, http.StatusOK, rr.Code)
	assertGenericVerificationMessage(t, rr)
	app.mailer.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
}

// Test_Integration_ResendVerificationUnknownEmailIsGeneric verifies that an unregistered
// (but well-formed) email gets the same generic 200 and sends nothing, so the response
// can't be used to enumerate accounts.
func Test_Integration_ResendVerificationUnknownEmailIsGeneric(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := postResendVerification(t, app, "does_not_exist@example.com")

	assert.Equal(t, http.StatusOK, rr.Code)
	assertGenericVerificationMessage(t, rr)
	app.mailer.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
}

func Test_Integration_ResendVerificationInvalidEmail(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := postResendVerification(t, app, "not-an-email")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
