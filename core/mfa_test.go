package core

import (
	"crypto/sha1" // #nosec G505 -- TOTP is defined in terms of HMAC-SHA-1
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
	"github.com/AdrianTworek/go-auth/core/internal/store"
)

// --- helpers ---------------------------------------------------------------

// mfaConfig returns a test config with the capability enabled. Note that enabling it
// changes nothing for any user until they enrol — the two opt-ins are independent.
func mfaConfig() *AuthConfig {
	c := NewTestAuthConfig(nil, nil, nil)
	c.MFA = &MFAConfig{EncryptionKey: testHexKey}
	// NewTestAuthConfig configures magic-link sign-in, which makes this required:
	// construction refuses the combination without it, since magic-link completion
	// redirects rather than returning a body.
	c.Session.MagicLinkMFARedirectURL = "http://localhost:6969/mfa"
	return c
}

func mfaDecodeSecret(t *testing.T, secretB32 string) []byte {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	require.NoError(t, err, "the setup endpoint must return a base32 secret an app can read")
	return secret
}

func mfaCodeAtStep(t *testing.T, secretB32 string, step int64) string {
	t.Helper()
	return auth.GenerateTOTP(mfaDecodeSecret(t, secretB32), step, auth.DefaultTOTPDigits, sha1.New)
}

// mfaCodeAt is the code an authenticator app would show at a given instant. Tests that
// drive an injected clock pass that clock's time, not the wall clock's.
func mfaCodeAt(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	return mfaCodeAtStep(t, secretB32, auth.TOTPStep(at, auth.DefaultTOTPPeriod))
}

// mfaCurrentCode is what the user's authenticator app would be showing right now.
func mfaCurrentCode(t *testing.T, secretB32 string) string {
	t.Helper()
	return mfaCodeAt(t, secretB32, time.Now())
}

// mfaWrongCode is a real code from a step far outside the skew window, so it is
// deterministically wrong rather than merely unlikely to be right.
func mfaWrongCode(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	return mfaCodeAtStep(t, secretB32, auth.TOTPStep(at, auth.DefaultTOTPPeriod)+1000)
}

func mfaBeginEnrolment(t *testing.T, app *TestApp, cookie *http.Cookie, password string) (secret, uri string) {
	t.Helper()
	rr := doJSON(t, app, http.MethodPost, PathMFATOTPSetup, cookie, map[string]string{"password": password})
	require.Equal(t, http.StatusOK, rr.Code, "setup failed: %s", rr.Body.String())

	var envelope struct {
		Data struct {
			Secret string `json:"secret"`
			URI    string `json:"uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	return envelope.Data.Secret, envelope.Data.URI
}

func mfaBackupCodesFrom(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	var envelope struct {
		Data struct {
			BackupCodes []string `json:"backupCodes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	return envelope.Data.BackupCodes
}

// mfaCompleteEnrolment takes a user all the way through both steps.
func mfaCompleteEnrolment(t *testing.T, app *TestApp, cookie *http.Cookie, password string) (secret string, codes []string) {
	t.Helper()
	secret, _ = mfaBeginEnrolment(t, app, cookie, password)

	rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
		"code": mfaCurrentCode(t, secret),
	})
	require.Equal(t, http.StatusOK, rr.Code, "confirm failed: %s", rr.Body.String())
	return secret, mfaBackupCodesFrom(t, rr)
}

func mfaStatusOf(t *testing.T, app *TestApp, cookie *http.Cookie) (enabled bool, remaining int) {
	t.Helper()
	rr := doGet(t, app, PathMFAStatus, cookie)
	require.Equal(t, http.StatusOK, rr.Code, "status failed: %s", rr.Body.String())

	var envelope struct {
		Data struct {
			Enabled              bool `json:"enabled"`
			BackupCodesRemaining int  `json:"backupCodesRemaining"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	return envelope.Data.Enabled, envelope.Data.BackupCodesRemaining
}

// mfaLongSessionCookie mints a session that outlives the middleware's refresh
// threshold, so its token is not rotated between the requests of a multi-step test.
//
// sessionCookieFor's one-hour expiry sits below the default threshold (half of seven
// days), so the middleware slides the session on every request and the caller's previous
// token stops working. That is invisible in a single-request test and fatal in an
// enrolment flow.
func mfaLongSessionCookie(t *testing.T, app *TestApp, userID string) *http.Cookie {
	t.Helper()
	token, err := app.storage.Session.Create(t.Context(), nil, &store.Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(auth.DefaultSessionDuration),
	})
	require.NoError(t, err)
	return &http.Cookie{Name: "session", Value: token}
}

// doPostNoBody sends a request with no body at all, which is what a passwordless
// account has to send to the re-authenticating endpoints.
func doPostNoBody(t *testing.T, app *TestApp, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

// --- enrolment -------------------------------------------------------------

func Test_Integration_MFASetupReturnsSecretAndURI(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	cookie := loginCookie(t, helper, DefaultUser)

	secret, uri := mfaBeginEnrolment(t, app, cookie, TestUserData[DefaultUser].Password)

	t.Run("the secret is usable by hand as well as by scanning", func(t *testing.T) {
		// User story 3: enrolment has to work on a device with no camera.
		assert.Len(t, mfaDecodeSecret(t, secret), auth.TOTPSecretBytes)
	})

	t.Run("the URI carries the same secret", func(t *testing.T) {
		parsed, err := url.Parse(uri)
		require.NoError(t, err)
		assert.Equal(t, "otpauth", parsed.Scheme)
		assert.Equal(t, "totp", parsed.Host)
		assert.Equal(t, secret, parsed.Query().Get("secret"))
		// Defaulted from BaseURL, since the test config sets no explicit Issuer.
		assert.NotEmpty(t, parsed.Query().Get("issuer"))
	})

	t.Run("the factor is not active yet", func(t *testing.T) {
		enabled, remaining := mfaStatusOf(t, app, cookie)
		assert.False(t, enabled, "an unconfirmed enrolment is not an enabled factor")
		assert.Equal(t, 0, remaining, "codes are issued at confirmation, not at setup")
	})

	// This property survives slice 05: an enrolment nobody confirmed must never affect
	// sign-in, or a mis-scanned QR code would lock the user out of their own account.
	t.Run("sign-in is unaffected until confirmation", func(t *testing.T) {
		_, rr := helper.LoginAs(DefaultUser)
		require.Equal(t, http.StatusOK, rr.Code)
		assert.NotNil(t, helper.GetSessionCookie(rr), "an unconfirmed enrolment must not withhold a session")
	})
}

func Test_Integration_MFAConfirmActivatesTheFactor(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	secret, _ := mfaBeginEnrolment(t, app, cookie, TestUserData[DefaultUser].Password)

	// User story 4, and the reason enrolment is two-step at all.
	t.Run("a wrong code leaves the factor inactive", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
			"code": mfaWrongCode(t, secret, time.Now()),
		})
		assert.Equal(t, http.StatusBadRequest, rr.Code)

		enabled, _ := mfaStatusOf(t, app, cookie)
		assert.False(t, enabled)
	})

	t.Run("a correct code activates it and returns backup codes", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
			"code": mfaCurrentCode(t, secret),
		})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

		codes := mfaBackupCodesFrom(t, rr)
		assert.Len(t, codes, defaultBackupCodeCount)
		for _, code := range codes {
			assert.Regexp(t, `^[0-9A-Z]{5}-[0-9A-Z]{5}$`, code)
		}

		enabled, remaining := mfaStatusOf(t, app, cookie)
		assert.True(t, enabled)
		assert.Equal(t, defaultBackupCodeCount, remaining)
	})

	// User story 6: the codes' secrecy must not depend on the service continuing to
	// hold them in readable form.
	t.Run("the codes are never returned again", func(t *testing.T) {
		rr := doGet(t, app, PathMFAStatus, cookie)

		// Asserted on the decoded key rather than as a substring: the payload carries
		// backupCodesRemaining, which contains "backupCodes", so a substring check here
		// could never fail.
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
		assert.NotContains(t, envelope.Data, "backupCodes")
	})
}

func Test_Integration_MFAConfirmRejectsWrongState(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password

	t.Run("no enrolment in progress", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{"code": "123456"})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "No enrolment is in progress")
	})

	secret, _ := mfaCompleteEnrolment(t, app, cookie, password)

	t.Run("already confirmed", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
			"code": mfaCurrentCode(t, secret),
		})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "already enabled")
	})

	t.Run("a code is required", func(t *testing.T) {
		rr := doPostNoBody(t, app, PathMFATOTPConfirm, cookie)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// Test_Integration_MFASetupRespectsExistingFactor separates the two cases that look the
// same from the outside: replacing an abandoned enrolment has to keep working, while
// replacing a live one must not, because it would invalidate the authenticator the user
// is currently relying on.
func Test_Integration_MFASetupRespectsExistingFactor(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password

	t.Run("an unconfirmed enrolment is replaceable", func(t *testing.T) {
		first, _ := mfaBeginEnrolment(t, app, cookie, password)
		second, _ := mfaBeginEnrolment(t, app, cookie, password)
		assert.NotEqual(t, first, second, "a fresh scan should get a fresh secret")

		// The replacement is the one that counts; the abandoned one is gone.
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
			"code": mfaCurrentCode(t, first),
		})
		assert.Equal(t, http.StatusBadRequest, rr.Code, "the abandoned secret must not confirm")

		rr = doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
			"code": mfaCurrentCode(t, second),
		})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})

	t.Run("a confirmed factor is not replaceable", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPSetup, cookie, map[string]string{"password": password})
		assert.Equal(t, http.StatusConflict, rr.Code)
		assert.Contains(t, rr.Body.String(), "Disable it first")
	})
}

// --- backup codes ----------------------------------------------------------

func Test_Integration_MFARegenerateBackupCodes(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password
	_, first := mfaCompleteEnrolment(t, app, cookie, password)

	rr := doJSON(t, app, http.MethodPost, PathMFABackupCodes, cookie, map[string]string{"password": password})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	second := mfaBackupCodesFrom(t, rr)

	assert.Len(t, second, defaultBackupCodeCount)

	// User story 10: codes the user believes are retired have to actually be. Proving
	// that an old code no longer *works* needs the verify endpoint, so slice 05 closes
	// the loop — see Test_Integration_MFABackupCodeSignIn. Here we can at least show
	// the sets are disjoint and the count did not grow.
	t.Run("the previous set is replaced, not added to", func(t *testing.T) {
		for _, old := range first {
			assert.NotContains(t, second, old)
		}
		_, remaining := mfaStatusOf(t, app, cookie)
		assert.Equal(t, defaultBackupCodeCount, remaining)
	})
}

func Test_Integration_MFARegenerateRequiresAFactor(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password

	rr := doJSON(t, app, http.MethodPost, PathMFABackupCodes, cookie, map[string]string{"password": password})
	assert.Equal(t, http.StatusBadRequest, rr.Code, "codes without a factor are meaningless")

	// Nor for an enrolment that was started but never confirmed.
	mfaBeginEnrolment(t, app, cookie, password)
	rr = doJSON(t, app, http.MethodPost, PathMFABackupCodes, cookie, map[string]string{"password": password})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --- disable ---------------------------------------------------------------

func Test_Integration_MFADisable(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password

	t.Run("refused when no factor is enabled", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPDisable, cookie, map[string]string{"password": password})
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	mfaCompleteEnrolment(t, app, cookie, password)

	t.Run("removes the secret and every backup code", func(t *testing.T) {
		rr := doJSON(t, app, http.MethodPost, PathMFATOTPDisable, cookie, map[string]string{"password": password})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

		enabled, remaining := mfaStatusOf(t, app, cookie)
		assert.False(t, enabled)
		assert.Equal(t, 0, remaining)

		// Asserted at the database too, because "removed rather than flagged inactive"
		// is the property, and the endpoint would answer the same way either way.
		for _, table := range []string{"totp_credentials", "totp_backup_codes"} {
			var count int
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT count(*) FROM `+table+` WHERE user_id = $1`,
				userID(t, db, TestUserData[DefaultUser].Email)).Scan(&count))
			assert.Equal(t, 0, count, "%s should hold nothing after disabling", table)
		}
	})

	t.Run("the user can enrol again afterwards", func(t *testing.T) {
		mfaCompleteEnrolment(t, app, cookie, password)
		enabled, _ := mfaStatusOf(t, app, cookie)
		assert.True(t, enabled)
	})
}

// --- re-authentication -----------------------------------------------------

// Test_Integration_MFAManagementRequiresReauthentication covers the group rather than
// any one endpoint: a stolen session must not be able to switch off the protection that
// exists to make a stolen credential insufficient.
func Test_Integration_MFAManagementRequiresReauthentication(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password
	mfaCompleteEnrolment(t, app, cookie, password)

	for _, path := range []string{PathMFATOTPSetup, PathMFATOTPDisable, PathMFABackupCodes} {
		t.Run("wrong password rejected: "+path, func(t *testing.T) {
			rr := doJSON(t, app, http.MethodPost, path, cookie, map[string]string{"password": "not-my-password"})
			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Contains(t, rr.Body.String(), "Current password is incorrect")
		})

		t.Run("missing password rejected: "+path, func(t *testing.T) {
			rr := doPostNoBody(t, app, path, cookie)
			assert.Equal(t, http.StatusBadRequest, rr.Code)
		})
	}

	t.Run("status needs no re-authentication", func(t *testing.T) {
		// It is a read of the caller's own state, like GET /auth/sessions.
		enabled, _ := mfaStatusOf(t, app, cookie)
		assert.True(t, enabled)
	})
}

// Test_Integration_MFAPasswordlessAccountCanManageTheFactor is the case the spec left
// open. An OAuth-only or magic-link-only account has no password to re-submit, so its
// session is the control — otherwise the users who most want a second factor could
// never enrol one. ChangeEmailHandler already reasons this way.
//
// Uses insertPasswordlessUser rather than the NoPasswordUser fixture: that fixture's
// password is the *empty string*, which PopulateDB hashes like any other, so it holds a
// real bcrypt hash and would satisfy re-authentication by submitting "". It would pass
// this test without ever reaching the branch under test.
func Test_Integration_MFAPasswordlessAccountCanManageTheFactor(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	uid := insertPasswordlessUser(t, db, "mfa-passwordless@example.com")
	cookie := mfaLongSessionCookie(t, app, uid)

	rr := doPostNoBody(t, app, PathMFATOTPSetup, cookie)
	require.Equal(t, http.StatusOK, rr.Code, "a passwordless account must be able to enrol: %s", rr.Body.String())

	var envelope struct {
		Data struct{ Secret string } `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))

	rr = doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
		"code": mfaCurrentCode(t, envelope.Data.Secret),
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	t.Run("can regenerate codes with no password", func(t *testing.T) {
		rr := doPostNoBody(t, app, PathMFABackupCodes, cookie)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Len(t, mfaBackupCodesFrom(t, rr), defaultBackupCodeCount)
	})

	t.Run("can disable with no password", func(t *testing.T) {
		rr := doPostNoBody(t, app, PathMFATOTPDisable, cookie)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

		enabled, _ := mfaStatusOf(t, app, cookie)
		assert.False(t, enabled)
	})
}

func Test_Integration_MFARoutesRequireAuthentication(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, mfaConfig())
	defer CleanupIntegration(t, dbCtr, db)

	for _, path := range []string{PathMFATOTPSetup, PathMFATOTPConfirm, PathMFATOTPDisable, PathMFABackupCodes} {
		rr := doPostNoBody(t, app, path, nil)
		assert.Equal(t, http.StatusUnauthorized, rr.Code, "%s should be behind the auth middleware", path)
	}
	assert.Equal(t, http.StatusUnauthorized, doGet(t, app, PathMFAStatus, nil).Code)
}

// --- the capability is off by default --------------------------------------

// Test_Integration_MFARoutesAbsentWhenUnconfigured is the "upgrading the library changes
// nothing" guarantee. The spec asks for it as a test rather than a sentence because it is
// the property most likely to be quietly broken by a later change.
func Test_Integration_MFARoutesAbsentWhenUnconfigured(t *testing.T) {
	t.Parallel()
	// NewTestAuthConfig leaves MFA nil, which is the default a consumer gets.
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)

	for _, path := range []string{PathMFATOTPSetup, PathMFATOTPConfirm, PathMFATOTPDisable, PathMFABackupCodes} {
		rr := doPostNoBody(t, app, path, cookie)
		assert.Equal(t, http.StatusNotFound, rr.Code, "%s must not be served when MFA is unconfigured", path)
	}
	assert.Equal(t, http.StatusNotFound, doGet(t, app, PathMFAStatus, cookie).Code)
}

// Test_Integration_LoginUnchangedWhenMFAUnconfigured is the other half of that
// guarantee: not merely that the new routes are absent, but that the login response a
// consumer already depends on is untouched.
func Test_Integration_LoginUnchangedWhenMFAUnconfigured(t *testing.T) {
	t.Parallel()
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginAs(DefaultUser)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotNil(t, helper.GetSessionCookie(rr))
	assert.NotContains(t, rr.Body.String(), "mfaRequired")
	assert.NotContains(t, rr.Body.String(), "challenge")
}

// --- audit events ----------------------------------------------------------

func Test_Integration_MFAAuditEvents(t *testing.T) {
	t.Parallel()
	rec := &auditRecorder{}
	c := auditConfig(rec,
		EventMFAEnabled,
		EventMFADisabled,
		EventMFABackupCodesRegenerated,
		EventMFAVerificationFailed,
	)
	c.MFA = &MFAConfig{EncryptionKey: testHexKey}
	c.Session.MagicLinkMFARedirectURL = "http://localhost:6969/mfa"

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	password := TestUserData[DefaultUser].Password
	uid := userID(t, db, TestUserData[DefaultUser].Email)

	secret, _ := mfaBeginEnrolment(t, app, cookie, password)

	// A failed confirmation is a second-factor failure like any other, and user story 29
	// asks for every second-factor event to be accountable.
	doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
		"code": mfaWrongCode(t, secret, time.Now()),
	})

	t.Run("a failed code is recorded with a reason", func(t *testing.T) {
		event := rec.only(t, EventMFAVerificationFailed)
		require.NotNil(t, event.Audit)
		assert.Equal(t, AuditTargetMFA, event.Audit.TargetType)
		assert.Equal(t, uid, event.Audit.TargetID)
		assert.Equal(t, MFAFailureInvalidCode, event.Audit.Reason)
	})

	doJSON(t, app, http.MethodPost, PathMFATOTPConfirm, cookie, map[string]string{
		"code": mfaCurrentCode(t, secret),
	})

	assertMFAEvent := func(t *testing.T, eventType AuthEventType) {
		t.Helper()
		event := rec.only(t, eventType)
		require.NotNil(t, event.Audit)
		assert.Equal(t, AuditTargetMFA, event.Audit.TargetType)
		assert.Equal(t, uid, event.Audit.TargetID)
		assert.NotEmpty(t, event.Audit.IP)
		assert.False(t, event.Audit.OccurredAt.IsZero())
		require.NotNil(t, event.User)
		assert.Equal(t, uid, event.User.ID)
	}

	t.Run("enabled", func(t *testing.T) { assertMFAEvent(t, EventMFAEnabled) })

	doJSON(t, app, http.MethodPost, PathMFABackupCodes, cookie, map[string]string{"password": password})
	t.Run("codes regenerated", func(t *testing.T) { assertMFAEvent(t, EventMFABackupCodesRegenerated) })

	doJSON(t, app, http.MethodPost, PathMFATOTPDisable, cookie, map[string]string{"password": password})
	t.Run("disabled", func(t *testing.T) { assertMFAEvent(t, EventMFADisabled) })
}

// Test_Integration_MFAIssuerIsConfigurable covers user story 24: an operator naming
// their service so users can tell which code belongs to them.
func Test_Integration_MFAIssuerIsConfigurable(t *testing.T) {
	t.Parallel()
	c := NewTestAuthConfig(nil, nil, nil)
	c.MFA = &MFAConfig{EncryptionKey: testHexKey, Issuer: "Acme: Staging"}
	c.Session.MagicLinkMFARedirectURL = "http://localhost:6969/mfa"

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	cookie := loginCookie(t, newTestHelper(t, app), DefaultUser)
	_, uri := mfaBeginEnrolment(t, app, cookie, TestUserData[DefaultUser].Password)

	parsed, err := url.Parse(uri)
	require.NoError(t, err)
	assert.Equal(t, "Acme: Staging", parsed.Query().Get("issuer"))

	// The label is "issuer:account", so the colon inside the issuer has to be escaped
	// or an authenticator app would split the label in the wrong place.
	label := strings.TrimPrefix(parsed.EscapedPath(), "/")
	assert.Equal(t, 1, strings.Count(label, ":"), "label %q", label)
	assert.Contains(t, label, url.PathEscape(TestUserData[DefaultUser].Email))
}
