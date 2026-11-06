package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

// --- helpers ---------------------------------------------------------------

// testClock is the clock a test drives in place of the wall clock, so TOTP skew and
// replay can be exercised without sleeping. It is read from request goroutines, hence
// the mutex.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Now()}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// mustKeyBytes decodes the test encryption key, for the tests that write an enrolment
// straight to the database rather than through the endpoints.
func mustKeyBytes(t *testing.T) []byte {
	t.Helper()
	key, err := resolveEncryptionKey(testHexKey)
	require.NoError(t, err)
	return key
}

// challengeFrom reads the challenge out of a login response, and asserts the property
// that actually matters: that no session cookie came with it.
func challengeFrom(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var envelope struct {
		Data struct {
			MFARequired bool   `json:"mfaRequired"`
			Challenge   string `json:"challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))

	assert.True(t, envelope.Data.MFARequired)
	require.NotEmpty(t, envelope.Data.Challenge)
	return envelope.Data.Challenge
}

// mfaCompleteEnrolmentAt is mfaCompleteEnrolment for a test driving an injected clock:
// the confirming code has to be generated at the client's notion of now rather than the
// wall clock's, or it falls outside the accepted window.
func mfaCompleteEnrolmentAt(
	t *testing.T,
	app *TestApp,
	clock *testClock,
	cookie *http.Cookie,
	password string,
) (secret string, codes []string) {
	t.Helper()
	secret, _ = mfaBeginEnrolment(t, app, cookie, password)

	rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
		"code": mfaCodeAt(t, secret, clock.now()),
	})
	require.Equal(t, http.StatusOK, rr.Code, "confirm failed: %s", rr.Body.String())
	return secret, mfaBackupCodesFrom(t, rr)
}

// mfaLogin submits a correct password and requires that no session was issued, returning
// the challenge. The absence of the cookie is the security property under test; a body
// check alone would pass against an implementation that set the cookie too.
func mfaLogin(t *testing.T, app *TestApp, userType TestUserType) string {
	t.Helper()
	rr := doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[userType].Email,
		"password": TestUserData[userType].Password,
	})

	helper := newTestHelper(t, app)
	require.Nil(t, helper.GetSessionCookie(rr), "a correct password must NOT issue a session when a second factor is active")
	return challengeFrom(t, rr)
}

func mfaVerify(t *testing.T, app *TestApp, challenge, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, app, http.MethodPost, PathMFAVerify, nil, map[string]string{
		"challenge": challenge,
		"code":      code,
	})
}

// --- password login --------------------------------------------------------

func Test_Integration_MFALoginIssuesAChallengeNotASession(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)
	secret, _ := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)

	// Confirming the enrolment claimed its own time step, so that the code the user
	// typed to prove the app works cannot immediately be replayed to sign in. Move to
	// the next window before signing in, or this test would be exercising that guard
	// rather than what it means to.
	clock.advance(auth.DefaultTOTPPeriod)

	challenge := mfaLogin(t, app, DefaultUser)

	t.Run("a wrong code does not issue a session and leaves the challenge usable", func(t *testing.T) {
		rr := mfaVerify(t, app, challenge, mfaWrongCode(t, secret, clock.now()))
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Nil(t, helper.GetSessionCookie(rr))

		// The usability guarantee: one mistyped digit must not send the user back to
		// re-enter their password.
		rr = mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now()))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.NotNil(t, helper.GetSessionCookie(rr))
	})

	t.Run("a consumed challenge cannot be reused", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		rr := mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now()))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("the issued session works", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		fresh := mfaLogin(t, app, DefaultUser)
		rr := mfaVerify(t, app, fresh, mfaCodeAt(t, secret, clock.now()))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

		issued := helper.GetSessionCookie(rr)
		require.NotNil(t, issued)
		assert.Equal(t, http.StatusOK, doGet(t, app, PathMe, issued).Code)
	})
}

func Test_Integration_MFAVerifyRejectsBadChallenges(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	secret, _ := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)

	t.Run("an unknown challenge", func(t *testing.T) {
		rr := mfaVerify(t, app, "not-a-real-challenge", mfaCodeAt(t, secret, clock.now()))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("an expired challenge", func(t *testing.T) {
		challenge := mfaLogin(t, app, DefaultUser)

		// Expiry is enforced by the database (expires_at > NOW()), not by the injected
		// clock, so the row is aged directly. That is the condition under test.
		_, err := db.ExecContext(t.Context(),
			`UPDATE verifications SET expires_at = NOW() - INTERVAL '1 minute'
			 WHERE intent = 'two_factor_challenge'`)
		require.NoError(t, err)

		rr := mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now()))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	// The challenge is tied to a factor. If the user disables it in between, the
	// challenge cannot be satisfied — and must not fall through to issuing a session.
	t.Run("a challenge whose factor has since been disabled", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		challenge := mfaLogin(t, app, DefaultUser)

		rr := doJSON(t, app, http.MethodPost, PathMFATOTPDisable, cookie, map[string]string{
			"password": TestUserData[DefaultUser].Password,
		})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

		rr = mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now()))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Nil(t, newTestHelper(t, app).GetSessionCookie(rr))
	})
}

// --- replay and skew -------------------------------------------------------

// Test_Integration_MFACodeReplayIsRefused needs two challenges, because a successful
// verification consumes the one it used — so a second attempt with the same code has to
// arrive holding a valid challenge for the refusal to be about the *code*. That is
// exactly the shape of the attack: a code observed in transit, replayed inside its
// remaining validity.
func Test_Integration_MFACodeReplayIsRefused(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	secret, _ := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)

	// Move past the step the confirming code claimed, so this test is about its own
	// code rather than enrolment's.
	clock.advance(auth.DefaultTOTPPeriod)

	first := mfaLogin(t, app, DefaultUser)
	second := mfaLogin(t, app, DefaultUser)
	code := mfaCodeAt(t, secret, clock.now())

	require.Equal(t, http.StatusOK, mfaVerify(t, app, first, code).Code)

	rr := mfaVerify(t, app, second, code)
	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"the same code must not be accepted twice inside its window")
	assert.Nil(t, newTestHelper(t, app).GetSessionCookie(rr))

	t.Run("the next window's code works", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		rr := mfaVerify(t, app, second, mfaCodeAt(t, secret, clock.now()))
		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})
}

// Test_Integration_MFAClockSkew is the usability counterpart: a phone whose clock drifts
// by a window still works, one that is wildly wrong does not.
func Test_Integration_MFAClockSkew(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	secret, _ := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)

	// Two windows, not one: the first subtest reaches a step *behind* the current one,
	// which has to be a step the confirming code did not already claim.
	clock.advance(2 * auth.DefaultTOTPPeriod)

	t.Run("a code from the previous step is accepted", func(t *testing.T) {
		stale := mfaCodeAt(t, secret, clock.now().Add(-auth.DefaultTOTPPeriod))
		challenge := mfaLogin(t, app, DefaultUser)
		assert.Equal(t, http.StatusOK, mfaVerify(t, app, challenge, stale).Code)
	})

	t.Run("a code from the next step is accepted", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		ahead := mfaCodeAt(t, secret, clock.now().Add(auth.DefaultTOTPPeriod))
		challenge := mfaLogin(t, app, DefaultUser)
		assert.Equal(t, http.StatusOK, mfaVerify(t, app, challenge, ahead).Code)
	})

	t.Run("a code from well outside the window is refused", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		far := mfaCodeAt(t, secret, clock.now().Add(10*auth.DefaultTOTPPeriod))
		challenge := mfaLogin(t, app, DefaultUser)
		assert.Equal(t, http.StatusUnauthorized, mfaVerify(t, app, challenge, far).Code)
	})
}

// --- backup codes ----------------------------------------------------------

func Test_Integration_MFABackupCodeSignIn(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)
	password := TestUserData[DefaultUser].Password
	_, codes := mfaCompleteEnrolmentAt(t, app, clock, cookie, password)

	t.Run("a backup code signs the user in", func(t *testing.T) {
		challenge := mfaLogin(t, app, DefaultUser)
		rr := mfaVerify(t, app, challenge, codes[0])
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.NotNil(t, helper.GetSessionCookie(rr))
	})

	t.Run("the same code then fails", func(t *testing.T) {
		challenge := mfaLogin(t, app, DefaultUser)
		rr := mfaVerify(t, app, challenge, codes[0])
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Nil(t, helper.GetSessionCookie(rr))
	})

	t.Run("the remaining count drops by one", func(t *testing.T) {
		_, remaining := mfaStatusOf(t, app, cookie)
		assert.Equal(t, defaultBackupCodeCount-1, remaining)
	})

	t.Run("a code typed without its hyphen still works", func(t *testing.T) {
		challenge := mfaLogin(t, app, DefaultUser)
		stripped := codes[1][:5] + codes[1][6:]
		rr := mfaVerify(t, app, challenge, stripped)
		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})

	// Closes the loop slice 04 could only half-assert: regenerating does not merely
	// return a different set, it makes the old one stop working.
	t.Run("regenerating invalidates the previous set", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFABackupCodes, cookie, map[string]string{"password": password})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		fresh := mfaBackupCodesFrom(t, rr)

		challenge := mfaLogin(t, app, DefaultUser)
		assert.Equal(t, http.StatusUnauthorized, mfaVerify(t, app, challenge, codes[2]).Code,
			"a retired code must not sign anyone in")

		assert.Equal(t, http.StatusOK, mfaVerify(t, app, challenge, fresh[0]).Code,
			"and the challenge should survive that failure")
	})
}

// --- the bypass paths ------------------------------------------------------

// Test_Integration_MFAMagicLinkHonoursTheFactor is the bypass the spec singles out: a
// magic link proves control of the inbox, not possession of the second factor, so
// without this a user with a factor enabled could sign in by requesting one.
func Test_Integration_MFAMagicLinkHonoursTheFactor(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)
	email := TestUserData[DefaultUser].Email
	secret, _ := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)
	clock.advance(auth.DefaultTOTPPeriod)

	app.mailer.On("SendMagicLinkEmail", email, mock.Anything).Return(nil)
	rr := doJSON(t, app, http.MethodPost, PathSendMagicLink, nil, map[string]string{"email": email})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	token := mailToken(t, app, "SendMagicLinkEmail")
	require.NotEmpty(t, token)

	rr = doGet(t, app, "/auth/magic-link/"+token, nil)

	t.Run("no session is issued", func(t *testing.T) {
		assert.Nil(t, helper.GetSessionCookie(rr), "completing a magic link must withhold the session")
	})

	var challenge string
	t.Run("it redirects to the configured MFA page with a challenge", func(t *testing.T) {
		require.Equal(t, http.StatusFound, rr.Code)

		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "/mfa", location.Path)

		challenge = location.Query().Get("challenge")
		require.NotEmpty(t, challenge)
	})

	t.Run("the challenge is exchangeable for a session", func(t *testing.T) {
		rr := mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now()))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.NotNil(t, helper.GetSessionCookie(rr))
	})
}

// Test_Integration_MFAOAuthHonoursTheFactor covers the configurable case. The callback
// returns JSON (consumers redirect from a hook), so the challenge goes in the body.
func Test_Integration_MFAOAuthHonoursTheFactor(t *testing.T) {
	// Not parallel: SetupGoth writes goth's provider registry and gothic's store, which
	// are package-level globals.
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	email := TestUserData[DefaultUser].Email
	uid := userID(t, db, email)
	gothUser := goth.User{Provider: "fake", UserID: "fake-provider-id", Email: email}

	// Link the provider up front so the callback resolves to this existing user, and
	// enrol them directly — the enrolment endpoints are exercised elsewhere.
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO accounts (user_id, provider, provider_account_id, email)
		 VALUES ($1, 'fake', 'fake-provider-id', $2)`, uid, email)
	require.NoError(t, err)

	secret, err := auth.NewTOTPSecret()
	require.NoError(t, err)
	ciphertext, nonce, err := auth.Encrypt(mustKeyBytes(t), secret)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO totp_credentials (user_id, secret, nonce, confirmed_at)
		 VALUES ($1, $2, $3, NOW())`, uid, ciphertext, nonce)
	require.NoError(t, err)

	newClient := func(t *testing.T, oauthSatisfies bool) *AuthClient {
		t.Helper()
		ac, err := NewAuthClient(&AuthConfig{
			Db:            &DatabaseConfig{Dsn: app.env.DSN},
			SessionSecret: app.env.SessionSecret,
			Mailer:        app.mailer,
			OAuth: &OAuthConfig{
				Providers: []goth.Provider{&fakeOAuthProvider{name: "fake", user: gothUser}},
			},
			MFA: &MFAConfig{
				EncryptionKey:              testHexKey,
				OAuthSatisfiesSecondFactor: oauthSatisfies,
			},
		})
		require.NoError(t, err)
		ac.SetupGoth()
		return ac
	}

	t.Run("challenged by default", func(t *testing.T) {
		ac := newClient(t, false)
		rec := httptest.NewRecorder()
		ac.OAuthCallbackHandler()(rec, newOAuthCallbackRequest(t))

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Nil(t, sessionCookie(rec), "an OAuth sign-in must be challenged unless exempted")
		assert.Contains(t, rec.Body.String(), "mfaRequired")
	})

	t.Run("exempted when the operator says the provider is enough", func(t *testing.T) {
		ac := newClient(t, true)
		rec := httptest.NewRecorder()
		ac.OAuthCallbackHandler()(rec, newOAuthCallbackRequest(t))

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotNil(t, sessionCookie(rec), "the exemption should issue a session directly")
	})
}

// Test_Integration_MFADoesNotAffectOtherSessionPaths is the negative half of the
// enforcement claim, and what would catch an over-broad implementation. Registration
// creates a user who cannot yet have a factor, and change-password has already
// re-authenticated and is replacing the caller's own session.
func Test_Integration_MFADoesNotAffectOtherSessionPaths(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	helper := newTestHelper(t, app)

	t.Run("registration still issues a session", func(t *testing.T) {
		newEmail := "mfa-register@example.com"
		app.mailer.On("SendVerificationEmail", newEmail, mock.Anything).Return(nil)

		_, rr := helper.CreateUser(newEmail, "P@ssword123_new")
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		assert.NotNil(t, helper.GetSessionCookie(rr), "a brand-new user has no factor to satisfy")
	})

	t.Run("change-password still issues its replacement session", func(t *testing.T) {
		cookie := loginCookie(t, helper, DefaultUser)
		password := TestUserData[DefaultUser].Password
		mfaCompleteEnrolmentAt(t, app, clock, cookie, password)

		app.mailer.On("SendPasswordChangedEmail", TestUserData[DefaultUser].Email).Return(nil)
		newPassword := "An0ther-P@ssword!"
		rr := doJSON(t, app, http.MethodPost, PathChangePassword, cookie, map[string]string{
			"currentPassword": password,
			"newPassword":     newPassword,
			"confirmPassword": newPassword,
		})

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.NotNil(t, helper.GetSessionCookie(rr),
			"change-password re-authenticates already; challenging again would be step-up auth")
	})
}

// --- anti-enumeration ------------------------------------------------------

// Test_Integration_MFALoginDoesNotRevealEnrolment is the property that keeps the login
// endpoint from being used to discover who has a second factor. Compared byte for byte,
// in the manner the failed-login audit tests already use.
func Test_Integration_MFALoginDoesNotRevealEnrolment(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)
	mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)

	wrongPassword := func(email string) *httptest.ResponseRecorder {
		return doJSON(t, app, http.MethodPost, PathLogin, nil, map[string]string{
			"email":    email,
			"password": "definitely-not-the-password",
		})
	}

	enrolled := wrongPassword(TestUserData[DefaultUser].Email)
	notEnrolled := wrongPassword(TestUserData[UnverifiedUser].Email)

	assert.Equal(t, notEnrolled.Code, enrolled.Code)
	assert.Equal(t, notEnrolled.Body.String(), enrolled.Body.String(),
		"the wrong-password response must not reveal whether a second factor is enrolled")
	assert.Nil(t, helper.GetSessionCookie(enrolled))
}

// --- hooks and audit -------------------------------------------------------

// Test_Integration_MFAChallengeIssuedHook covers the hook that exists because the
// challenged paths do not all have the same shape: an API caller reads the body, but the
// OAuth callback is a browser navigation that needs redirecting.
func Test_Integration_MFAChallengeIssuedHook(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	rec := &auditRecorder{}
	c := auditConfig(rec, EventMFAChallengeIssued, EventAfterLogin, EventMFAVerified, EventMFABackupCodeUsed, EventMFAVerificationFailed)
	c.MFA = &MFAConfig{EncryptionKey: testHexKey}
	c.Session.MagicLinkMFARedirectURL = "http://localhost:6969/mfa"

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	uid := userID(t, db, TestUserData[DefaultUser].Email)
	secret, codes := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)
	clock.advance(auth.DefaultTOTPPeriod)

	// Captured BEFORE the challenged login. The setup above signed this user in for real
	// — before they enrolled — and that login legitimately fired EventAfterLogin, so the
	// baseline has to be taken here for the assertion below to mean anything.
	loginsBeforeChallenge := len(rec.allOf(EventAfterLogin))
	require.NotZero(t, loginsBeforeChallenge, "the setup login should have fired the event")

	challenge := mfaLogin(t, app, DefaultUser)

	t.Run("the hook carries the challenge and its flow", func(t *testing.T) {
		event := rec.only(t, EventMFAChallengeIssued)
		require.NotNil(t, event.MFA)
		assert.Equal(t, challenge, event.MFA.Challenge)
		assert.Equal(t, MFAChallengeFlowLogin, event.MFA.Flow)
		require.NotNil(t, event.User)
		assert.Equal(t, uid, event.User.ID)
	})

	// EventAfterLogin must not fire at the password step: a consumer using it to mint
	// application state would otherwise treat a half-finished sign-in as a completed one.
	t.Run("EventAfterLogin does not fire until the challenge is satisfied", func(t *testing.T) {
		assert.Len(t, rec.allOf(EventAfterLogin), loginsBeforeChallenge,
			"the challenged login must not have counted as a sign-in")

		require.Equal(t, http.StatusOK, mfaVerify(t, app, challenge, mfaCodeAt(t, secret, clock.now())).Code)
		assert.Len(t, rec.allOf(EventAfterLogin), loginsBeforeChallenge+1,
			"verifying is the point at which the user is actually signed in")
		assert.Len(t, rec.allOf(EventMFAVerified), 1)
	})

	t.Run("a backup code also reports itself used", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		fresh := mfaLogin(t, app, DefaultUser)
		require.Equal(t, http.StatusOK, mfaVerify(t, app, fresh, codes[0]).Code)

		event := rec.only(t, EventMFABackupCodeUsed)
		require.NotNil(t, event.Audit)
		assert.Equal(t, AuditTargetMFA, event.Audit.TargetType)
		assert.Equal(t, uid, event.Audit.TargetID)
	})
}

func Test_Integration_MFAVerificationFailureReasons(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	rec := &auditRecorder{}
	c := auditConfig(rec, EventMFAVerificationFailed)
	c.MFA = &MFAConfig{EncryptionKey: testHexKey}
	c.Session.MagicLinkMFARedirectURL = "http://localhost:6969/mfa"

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)
	app.nowFn = clock.now

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	secret, codes := mfaCompleteEnrolmentAt(t, app, clock, cookie, TestUserData[DefaultUser].Password)
	clock.advance(auth.DefaultTOTPPeriod)

	reasons := func() []string {
		var out []string
		for _, e := range rec.allOf(EventMFAVerificationFailed) {
			if e.Audit != nil {
				out = append(out, e.Audit.Reason)
			}
		}
		return out
	}

	// An unknown challenge: nobody to attribute it to, but still worth emitting.
	mfaVerify(t, app, "nope", "123456")
	assert.Contains(t, reasons(), MFAFailureInvalidChallenge)

	challenge := mfaLogin(t, app, DefaultUser)
	mfaVerify(t, app, challenge, mfaWrongCode(t, secret, clock.now()))
	assert.Contains(t, reasons(), MFAFailureInvalidCode)

	mfaVerify(t, app, challenge, "ZZZZZ-99999")
	assert.Contains(t, reasons(), MFAFailureInvalidBackupCode)

	// Replay: spend the code on one challenge, then present it on another.
	second := mfaLogin(t, app, DefaultUser)
	code := mfaCodeAt(t, secret, clock.now())
	require.Equal(t, http.StatusOK, mfaVerify(t, app, challenge, code).Code)
	mfaVerify(t, app, second, code)
	assert.Contains(t, reasons(), MFAFailureReplayedCode)

	// Every one of those produced the same response, which is the point.
	t.Run("the response is uniform across every reason", func(t *testing.T) {
		clock.advance(auth.DefaultTOTPPeriod)
		third := mfaLogin(t, app, DefaultUser)

		wrongCode := mfaVerify(t, app, third, mfaWrongCode(t, secret, clock.now()))
		wrongBackup := mfaVerify(t, app, third, "YYYYY-88888")
		unknown := mfaVerify(t, app, "still-not-a-challenge", "123456")

		assert.Equal(t, wrongCode.Code, wrongBackup.Code)
		assert.Equal(t, wrongCode.Body.String(), wrongBackup.Body.String())
		assert.Equal(t, wrongCode.Code, unknown.Code)
		assert.Equal(t, wrongCode.Body.String(), unknown.Body.String())

		// And the still-unspent backup codes remain usable afterwards.
		require.Equal(t, http.StatusOK, mfaVerify(t, app, third, codes[1]).Code)
	})
}

// --- verify is absent when the capability is off ---------------------------

func Test_Integration_MFAVerifyAbsentWhenUnconfigured(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := mfaVerify(t, app, "anything", "123456")
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
