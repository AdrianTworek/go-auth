package core

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// policyClient builds one persistent AuthClient with an explicit password config, so
// in-memory rate-limit counters survive across the requests a test makes (TestApp.Router()
// builds a fresh client per call).
func policyClient(t *testing.T, app *TestApp, pw *PasswordConfig, rl *RateLimitConfig) (*AuthClient, *MockMailer) {
	t.Helper()
	m := &MockMailer{}
	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		Mailer:        m,
		Session:       &SessionConfig{},
		SessionSecret: app.env.SessionSecret,
		BaseURL:       "http://localhost",
		Password:      pw,
		RateLimit:     rl,
	})
	require.NoError(t, err)
	return ac, m
}

func policyConfig(pw *PasswordConfig) *AuthConfig {
	c := NewTestAuthConfig(nil, nil, nil)
	c.Password = pw
	return c
}

// --- the policy applies at every place a password is set -------------------

func Test_Integration_PasswordPolicyEnforcedAtRegister(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, policyConfig(&PasswordConfig{MinLength: 12, MinCharClasses: 3}))
	defer CleanupIntegration(t, dbCtr, db)

	rr := doJSON(t, app, http.MethodPost, PathRegister, nil, map[string]string{
		"email":           "policy@example.com",
		"password":        "lowercase",
		"confirmPassword": "lowercase",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// One response naming every unmet rule, so a sign-up form shows the whole picture
	// rather than rejecting the user once per rule.
	body := rr.Body.String()
	assert.Contains(t, body, "12")
	assert.Contains(t, body, "3")
}

func Test_Integration_PasswordPolicyEnforcedAtChangePassword(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, policyConfig(&PasswordConfig{MinLength: 12}))
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)

	rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie, map[string]string{
		"currentPassword": TestUserData[DefaultUser].Password,
		"newPassword":     "Short1!",
		"confirmPassword": "Short1!",
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "12")
}

// The reset flow is the interesting one: the token is single-use and consumed inside the
// transaction, so a rejected password must not leave the user holding a dead link.
func Test_Integration_PasswordPolicyAtResetPreservesTheToken(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, policyConfig(&PasswordConfig{MinLength: 12}))
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[DefaultUser].Email
	app.mailer.On("SendPasswordResetEmail", email, mock.Anything).Return(nil)
	app.mailer.On("SendPasswordChangedEmail", email).Return(nil)

	rr := doJSON(t, app, http.MethodPost, PathSendPasswordReset, nil, map[string]string{"email": email})
	require.Equal(t, http.StatusOK, rr.Code)

	token := mailToken(t, app, "SendPasswordResetEmail")
	path := strings.Replace(PathPasswordReset, "{token}", token, 1)

	weak := doJSON(t, app, http.MethodPut, path, nil, map[string]string{
		"password":        "Short1!",
		"confirmPassword": "Short1!",
	})
	require.Equal(t, http.StatusBadRequest, weak.Code)
	assert.Contains(t, weak.Body.String(), "12")

	strong := doJSON(t, app, http.MethodPut, path, nil, map[string]string{
		"password":        "LongEnoughPassword1",
		"confirmPassword": "LongEnoughPassword1",
	})
	assert.Equal(t, http.StatusOK, strong.Code,
		"the rejected attempt must not have burned the single-use token")
}

// Upgrading without configuring anything must not invalidate existing users' passwords.
func Test_Integration_PasswordPolicyDefaultsAcceptTheHistoricalRule(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	email := "eight@example.com"
	app.mailer.On("SendVerificationEmail", email, mock.Anything).Return(nil)

	rr := doJSON(t, app, http.MethodPost, PathRegister, nil, map[string]string{
		"email":           email,
		"password":        "abcdefgh", // exactly 8, no class requirement by default
		"confirmPassword": "abcdefgh",
	})
	assert.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
}

func Test_Integration_PasswordOverBcryptLimitRejected(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	long := strings.Repeat("a", MaxPasswordBytes+1)
	rr := doJSON(t, app, http.MethodPost, PathRegister, nil, map[string]string{
		"email":           "toolong@example.com",
		"password":        long,
		"confirmPassword": long,
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "72", "bcrypt would silently truncate it")
}

// --- breached-password check ----------------------------------------------

func Test_Integration_BreachedPasswordBlockedAtRegister(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	stub := &stubChecker{count: 4000}
	ac, _ := policyClient(t, app, &PasswordConfig{
		BreachCheck: &BreachCheckConfig{Mode: BreachCheckBlock, Checker: stub},
	}, nil)

	rr := rlPost(t, ac.RegisterHandler(),
		`{"email":"breached@example.com","password":"Password123!","confirmPassword":"Password123!"}`)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "breaches")
	assert.Equal(t, 1, stub.calls)
}

func Test_Integration_BreachCheckFailsOpenAtRegister(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	stub := &stubChecker{err: assert.AnError}
	ac, m := policyClient(t, app, &PasswordConfig{
		BreachCheck: &BreachCheckConfig{Mode: BreachCheckBlock, Checker: stub},
	}, nil)
	m.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)

	rr := rlPost(t, ac.RegisterHandler(),
		`{"email":"failopen@example.com","password":"Password123!","confirmPassword":"Password123!"}`)

	assert.Equal(t, http.StatusCreated, rr.Code,
		"an unreachable corpus must not take registration down with it")
}

func Test_Integration_BreachCheckIsOffByDefault(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	stub := &stubChecker{count: 4000}
	// A checker supplied without a mode must stay unused: upgrading a library must not
	// start contacting a third party.
	ac, m := policyClient(t, app, &PasswordConfig{
		BreachCheck: &BreachCheckConfig{Checker: stub},
	}, nil)
	m.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)

	rr := rlPost(t, ac.RegisterHandler(),
		`{"email":"nocheck@example.com","password":"Password123!","confirmPassword":"Password123!"}`)

	require.Equal(t, http.StatusCreated, rr.Code)
	assert.Zero(t, stub.calls)
}

// Throttling runs first, so a caller can't drive unbounded outbound lookups from the
// server by submitting passwords in a loop.
func Test_Integration_BreachCheckRunsAfterThrottling(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	stub := &stubChecker{count: 0}
	ac, m := policyClient(t, app,
		&PasswordConfig{BreachCheck: &BreachCheckConfig{Mode: BreachCheckBlock, Checker: stub}},
		&RateLimitConfig{Register: Rule{PerIP: Limit{Max: 1, Window: time.Hour}}},
	)
	m.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(nil)

	first := rlPost(t, ac.RegisterHandler(),
		`{"email":"throttle1@example.com","password":"Password123!","confirmPassword":"Password123!"}`)
	second := rlPost(t, ac.RegisterHandler(),
		`{"email":"throttle2@example.com","password":"Password123!","confirmPassword":"Password123!"}`)

	require.Equal(t, http.StatusCreated, first.Code)
	require.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Equal(t, 1, stub.calls, "the throttled request must not reach the corpus")
}
