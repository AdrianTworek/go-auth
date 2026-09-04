package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// rateLimitedClient builds an AuthClient against the test database with an explicit
// rate-limit config, plus a fresh mailer mock. Unlike TestApp.Router() it is a single
// persistent client, so its in-memory limiter (and any Postgres counters) survive
// across the requests a test makes.
func rateLimitedClient(t *testing.T, app *TestApp, rl *RateLimitConfig) (*AuthClient, *MockMailer) {
	t.Helper()
	m := &MockMailer{}
	ac, err := NewAuthClient(&AuthConfig{
		Db:            &DatabaseConfig{Dsn: app.env.DSN},
		Mailer:        m,
		Session:       &SessionConfig{},
		SessionSecret: app.env.SessionSecret,
		BaseURL:       "http://localhost",
		RateLimit:     rl,
	})
	require.NoError(t, err)
	return ac, m
}

// rlPost invokes a handler with a JSON body from the default httptest client IP
// (192.0.2.1), so repeated calls share the same per-IP rate-limit key.
func rlPost(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func loginBody(email, password string) string {
	return fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
}

func Test_Integration_RateLimiting(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	// Login: per-IP abuse returns 429 with a Retry-After header once the burst is
	// spent (fires before bcrypt).
	t.Run("LoginPerIPReturns429", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, &RateLimitConfig{
			Login: Rule{
				PerIP:      Limit{Max: 3, Window: time.Minute},
				PerAccount: Limit{Max: 100, Window: time.Minute},
			},
		})
		h := ac.LoginHandler()
		body := loginBody("nobody@example.com", "wrong-password")

		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, body).Code, "attempt %d", i+1)
		}
		rr := rlPost(t, h, body)
		require.Equal(t, http.StatusTooManyRequests, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Retry-After"))
	})

	// A successful login clears the per-account counter, so earlier failed attempts
	// don't leave a legitimate user throttled.
	t.Run("LoginResetOnSuccess", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, &RateLimitConfig{
			Login: Rule{
				PerIP:      Limit{Max: -1}, // isolate the per-account dimension
				PerAccount: Limit{Max: 3, Window: time.Minute},
			},
		})
		h := ac.LoginHandler()
		email := TestUserData[DefaultUser].Email
		wrong := loginBody(email, "wrong-password")
		correct := loginBody(email, TestUserData[DefaultUser].Password)

		for i := 0; i < 2; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, wrong).Code)
		}
		require.Equal(t, http.StatusOK, rlPost(t, h, correct).Code, "correct login should succeed and reset the counter")

		// The reset gives a full bucket again: three more failures are all served
		// (401), never throttled (429).
		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, wrong).Code, "post-reset attempt %d", i+1)
		}
	})

	// Send endpoints: the per-account cap stays silent (same generic 200) and simply
	// drops the extra email, so throttling can't be used to enumerate accounts.
	t.Run("SendResetSilentPerAccount", func(t *testing.T) {
		ac, m := rateLimitedClient(t, app, &RateLimitConfig{
			SendEmail: Rule{
				PerIP:      Limit{Max: 100, Window: time.Hour},
				PerAccount: Limit{Max: 2, Window: time.Hour},
			},
		})
		m.On("SendPasswordResetEmail", mock.Anything, mock.Anything).Return(nil)
		h := ac.SendPasswordResetLinkHandler()
		body := fmt.Sprintf(`{"email":%q}`, TestUserData[DefaultUser].Email)

		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusOK, rlPost(t, h, body).Code, "every response stays a generic 200 (attempt %d)", i+1)
		}
		m.AssertNumberOfCalls(t, "SendPasswordResetEmail", 2)
	})

	// Send endpoints: coarse per-IP abuse (across different accounts) does get an
	// honest 429, since it reveals nothing about any single account.
	t.Run("SendPerIPReturns429", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, &RateLimitConfig{
			SendEmail: Rule{
				PerIP:      Limit{Max: 2, Window: time.Hour},
				PerAccount: Limit{Max: 100, Window: time.Hour},
			},
		})
		h := ac.SendPasswordResetLinkHandler()
		// Distinct unknown addresses: per-account never trips, per-IP does.
		var last *httptest.ResponseRecorder
		for _, e := range []string{"a@example.com", "b@example.com", "c@example.com"} {
			last = rlPost(t, h, fmt.Sprintf(`{"email":%q}`, e))
		}
		require.Equal(t, http.StatusTooManyRequests, last.Code)
		require.NotEmpty(t, last.Header().Get("Retry-After"))
	})

	// The off switch fully disables limiting.
	t.Run("Disabled", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, &RateLimitConfig{
			Enabled: Ptr(false),
			Login:   Rule{PerIP: Limit{Max: 1, Window: time.Hour}},
		})
		h := ac.LoginHandler()
		body := loginBody("nobody@example.com", "wrong-password")
		for i := 0; i < 5; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, body).Code, "attempt %d should never be throttled", i+1)
		}
	})

	// A nil RateLimit config is ON with defaults (per-account login default is 5).
	t.Run("OnByDefault", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, nil)
		h := ac.LoginHandler()
		body := loginBody("default-on@example.com", "wrong-password")
		for i := 0; i < 5; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, body).Code, "attempt %d", i+1)
		}
		require.Equal(t, http.StatusTooManyRequests, rlPost(t, h, body).Code, "6th attempt should hit the default per-account cap")
	})

	// The Postgres backend enforces the same behaviour via the rate_limits table,
	// exercising the migration and the atomic token-bucket SQL.
	t.Run("PostgresBackendReturns429", func(t *testing.T) {
		ac, _ := rateLimitedClient(t, app, &RateLimitConfig{
			Backend: RateLimitPostgres,
			Login: Rule{
				PerIP:      Limit{Max: 3, Window: time.Minute},
				PerAccount: Limit{Max: 100, Window: time.Minute},
			},
		})
		h := ac.LoginHandler()
		body := loginBody("pg-nobody@example.com", "wrong-password")
		for i := 0; i < 3; i++ {
			require.Equal(t, http.StatusUnauthorized, rlPost(t, h, body).Code, "attempt %d", i+1)
		}
		rr := rlPost(t, h, body)
		require.Equal(t, http.StatusTooManyRequests, rr.Code)
		require.NotEmpty(t, rr.Header().Get("Retry-After"))
	})
}
