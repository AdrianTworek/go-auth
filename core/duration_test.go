package core

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

func TestResolveDurations(t *testing.T) {
	t.Run("applies defaults when config is nil", func(t *testing.T) {
		d := resolveDurations(nil, nil)
		assert.Equal(t, auth.DefaultSessionDuration, d.session)
		assert.Equal(t, auth.DefaultSessionDuration/2, d.refreshThreshold)
		assert.Equal(t, auth.DefaultTokenDuration, d.emailVerification)
		assert.Equal(t, auth.DefaultTokenDuration, d.passwordReset)
		assert.Equal(t, auth.DefaultTokenDuration, d.magicLink)
	})

	t.Run("defaults the refresh threshold to half the configured session duration", func(t *testing.T) {
		d := resolveDurations(&SessionConfig{Duration: 2 * time.Hour}, nil)
		assert.Equal(t, 2*time.Hour, d.session)
		assert.Equal(t, time.Hour, d.refreshThreshold)
	})

	t.Run("honors an explicit refresh threshold", func(t *testing.T) {
		d := resolveDurations(&SessionConfig{Duration: 2 * time.Hour, RefreshThreshold: 15 * time.Minute}, nil)
		assert.Equal(t, 15*time.Minute, d.refreshThreshold)
	})

	t.Run("overrides only the token durations that are set", func(t *testing.T) {
		d := resolveDurations(nil, &TokenConfig{
			EmailVerification: time.Hour,
			MagicLink:         10 * time.Minute,
		})
		assert.Equal(t, time.Hour, d.emailVerification)
		assert.Equal(t, 10*time.Minute, d.magicLink)
		assert.Equal(t, auth.DefaultTokenDuration, d.passwordReset) // left unset -> default
	})

	t.Run("treats zero values as unset and falls back to defaults", func(t *testing.T) {
		d := resolveDurations(&SessionConfig{Duration: 0, RefreshThreshold: 0}, &TokenConfig{})
		assert.Equal(t, auth.DefaultSessionDuration, d.session)
		assert.Equal(t, auth.DefaultSessionDuration/2, d.refreshThreshold)
		assert.Equal(t, auth.DefaultTokenDuration, d.emailVerification)
	})
}

// Test_Integration_ConfiguredDurations verifies that a configured session duration
// reaches both the session cookie and the persisted session row (and that the two
// agree), and that a configured per-intent token duration reaches the verification
// row — proving the durations are no longer hard-coded in the store layer.
func Test_Integration_ConfiguredDurations(t *testing.T) {
	c := NewTestAuthConfig(nil, &SessionConfig{
		LoginAfterRegister: true,
		Duration:           2 * time.Hour,
	}, nil)
	c.Tokens = &TokenConfig{EmailVerification: 30 * time.Minute}

	app, dbCtr, db := SetupIntegration(t, c)
	defer CleanupIntegration(t, dbCtr, db)

	userEmail := "durations@example.com"
	app.mailer.On("SendVerificationEmail", userEmail, mock.Anything).Return(nil)

	helper := newTestHelper(t, app)
	_, rr := helper.CreateUser(userEmail, "Password123!")
	require.Equal(t, http.StatusCreated, rr.Code)
	app.mailer.AssertExpectations(t)

	// The session cookie reflects the configured 2h duration, not the 7d default.
	cookie := helper.GetSessionCookie(rr)
	require.NotNil(t, cookie)
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), cookie.Expires, time.Minute)

	// The persisted session expiry matches the configured duration, and agrees with
	// the cookie (modulo the column's one-second precision).
	var dbSessionExpiry time.Time
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT s.expires_at FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE u.email = $1`, userEmail,
	).Scan(&dbSessionExpiry))
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), dbSessionExpiry, time.Minute)
	assert.WithinDuration(t, cookie.Expires, dbSessionExpiry, 2*time.Second)

	// The email-verification token reflects the configured 30m duration, not the 5m default.
	var dbTokenExpiry time.Time
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT expires_at FROM verifications WHERE intent = 'email_verification'`,
	).Scan(&dbTokenExpiry))
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), dbTokenExpiry, time.Minute)
}
