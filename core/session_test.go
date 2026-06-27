package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AdrianTworek/go-auth/core/internal/auth"
)

// Test_Integration_SessionSlidesWhenNearExpiry verifies the middleware rotates the
// session token when it is close to expiry, and that the old token is invalidated.
func Test_Integration_SessionSlidesWhenNearExpiry(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	helper := newTestHelper(t, app)
	_, rr := helper.LoginAs(DefaultUser)
	oldCookie := helper.GetSessionCookie(rr)
	require.NotNil(t, oldCookie)

	// Push the session close to expiry (within the refresh threshold). Tokens are
	// stored hashed, so match on the hash of the raw cookie value.
	_, err := db.ExecContext(
		t.Context(),
		`UPDATE sessions SET expires_at = NOW() + INTERVAL '1 hour' WHERE token = $1`,
		auth.HashToken(oldCookie.Value),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(oldCookie)
	rr = httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	newCookie := helper.GetSessionCookie(rr)
	require.NotNil(t, newCookie)
	assert.NotEqual(t, oldCookie.Value, newCookie.Value) // token rotated

	// New token is valid, old token no longer is.
	newSession, err := app.storage.Session.Validate(t.Context(), nil, newCookie.Value)
	assert.NoError(t, err)
	assert.NotNil(t, newSession)

	oldSession, err := app.storage.Session.Validate(t.Context(), nil, oldCookie.Value)
	assert.Error(t, err)
	assert.Nil(t, oldSession)
}

// Test_Integration_CleanupExpired verifies that expired sessions and verification
// tokens are pruned while valid ones are kept.
func Test_Integration_CleanupExpired(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	ctx := t.Context()

	var userID string
	require.NoError(t, db.QueryRowContext(
		ctx, `SELECT id FROM users WHERE email = $1`, TestUserData[DefaultUser].Email,
	).Scan(&userID))

	_, err := db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent) VALUES
		 ($1, 'expired_session', NOW() - INTERVAL '1 hour', '', ''),
		 ($1, 'valid_session',   NOW() + INTERVAL '1 hour', '', '')`,
		userID,
	)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO verifications (value, intent, expires_at) VALUES
		 ('expired_ver', 'email_verification', NOW() - INTERVAL '1 hour'),
		 ('valid_ver',   'email_verification', NOW() + INTERVAL '1 hour')`,
	)
	require.NoError(t, err)

	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		SessionSecret: app.env.SessionSecret,
	})
	require.NoError(t, err)
	require.NoError(t, ac.CleanupExpired(ctx))

	var sessions, verifications int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM verifications`).Scan(&verifications))
	assert.Equal(t, 1, sessions)      // only the valid session remains
	assert.Equal(t, 1, verifications) // only the valid verification remains
}
