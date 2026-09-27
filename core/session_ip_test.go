package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- helpers ---------------------------------------------------------------

// serve issues a request through the router with optional cookie, JSON body and extra
// headers, so a test can drive a session-creating path as though it arrived via a proxy.
func serve(
	t *testing.T,
	app *TestApp,
	method, path string,
	cookie *http.Cookie,
	body any,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}

	req := httptest.NewRequest(method, path, reader)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	app.Router().ServeHTTP(rr, req)
	return rr
}

func requireSessionCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	c := sessionCookie(rr)
	require.NotNil(t, c, "expected a session cookie, got status %d: %s", rr.Code, rr.Body.String())
	return c
}

// currentSessionIP reads back the address recorded for the session behind a cookie,
// through the sessions endpoint rather than the database, so the assertion binds to what
// a user actually sees in their device list.
func currentSessionIP(t *testing.T, app *TestApp, cookie *http.Cookie) string {
	t.Helper()
	rr := doGet(t, app, PathSessions, cookie)
	require.Equal(t, http.StatusOK, rr.Code)

	for _, s := range decodeSessionList(t, rr).Data.Sessions {
		if s.Current {
			return s.IPAddress
		}
	}
	t.Fatal("no session was flagged as current")
	return ""
}

// sessionCreator drives one of the paths that creates a session and returns its cookie.
type sessionCreator struct {
	name   string
	create func(t *testing.T, app *TestApp, headers map[string]string) *http.Cookie
}

// sessionCreatingPaths is every path that creates a session. The defect this guards
// against was duplicated across all of them, so each one is exercised rather than login
// alone. (Password-reset completion is absent on purpose: it revokes sessions without
// creating one.)
func sessionCreatingPaths() []sessionCreator {
	return []sessionCreator{
		{"register", func(t *testing.T, app *TestApp, h map[string]string) *http.Cookie {
			email := "ip-register@example.com"
			app.mailer.On("SendVerificationEmail", email, mock.Anything).Return(nil)
			rr := serve(t, app, http.MethodPost, PathRegister, nil, map[string]string{
				"email":           email,
				"password":        "P@ssword123_reg",
				"confirmPassword": "P@ssword123_reg",
			}, h)
			require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
			return requireSessionCookie(t, rr)
		}},

		{"login", func(t *testing.T, app *TestApp, h map[string]string) *http.Cookie {
			rr := serve(t, app, http.MethodPost, PathLogin, nil, map[string]string{
				"email":    TestUserData[DefaultUser].Email,
				"password": TestUserData[DefaultUser].Password,
			}, h)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			return requireSessionCookie(t, rr)
		}},

		{"magic link", func(t *testing.T, app *TestApp, h map[string]string) *http.Cookie {
			email := TestUserData[DefaultUser].Email
			app.mailer.On("SendMagicLinkEmail", email, mock.Anything).Return(nil)

			rr := serve(t, app, http.MethodPost, PathSendMagicLink, nil,
				map[string]string{"email": email}, nil)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			token := mailToken(t, app, "SendMagicLinkEmail")
			rr = serve(t, app, http.MethodGet,
				strings.Replace(PathMagicLink, "{token}", token, 1), nil, nil, h)
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
			return requireSessionCookie(t, rr)
		}},

		{"change password", func(t *testing.T, app *TestApp, h map[string]string) *http.Cookie {
			email := TestUserData[DefaultUser].Email
			app.mailer.On("SendPasswordChangedEmail", email).Return(nil)

			// Change-password revokes every session and issues a fresh one; that new
			// session is the one under test.
			first := loginCookie(t, newTestHelper(t, app), DefaultUser)
			rr := serve(t, app, http.MethodPost, PathChangePassword, first, map[string]string{
				"currentPassword": TestUserData[DefaultUser].Password,
				"newPassword":     "NewP@ssword123_ip",
				"confirmPassword": "NewP@ssword123_ip",
			}, h)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			return requireSessionCookie(t, rr)
		}},

		{"oauth callback", func(t *testing.T, app *TestApp, h map[string]string) *http.Cookie {
			// Built here rather than via newOAuthClient so the client inherits the test's
			// trusted-proxy config.
			ac, err := NewAuthClient(&AuthConfig{
				Db:            &DatabaseConfig{Dsn: app.env.DSN},
				SessionSecret: app.env.SessionSecret,
				Mailer:        app.mailer,
				OAuth: &OAuthConfig{Providers: []goth.Provider{&fakeOAuthProvider{
					name: "fake",
					user: goth.User{Provider: "fake", UserID: "ip-oauth-1", Email: "ip-oauth@example.com"},
				}}},
				TrustedProxy: app.config.TrustedProxy,
				RateLimit:    &RateLimitConfig{Enabled: Ptr(false)},
			})
			require.NoError(t, err)
			ac.SetupGoth()

			req := newOAuthCallbackRequest(t)
			for k, v := range h {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			ac.OAuthCallbackHandler()(rr, req)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			return requireSessionCookie(t, rr)
		}},
	}
}

func trustedProxyConfig() *AuthConfig {
	c := NewTestAuthConfig(nil, nil, nil)
	c.TrustedProxy = &TrustedProxyConfig{TrustForwardedHeader: true, TrustedHops: 1}
	return c
}

// --- tests -----------------------------------------------------------------

// Every session-creating path records the peer host and nothing else. This is the
// regression guard: the old behaviour stored r.RemoteAddr verbatim, so the port would
// still be attached here.
func Test_Integration_SessionRecordsPeerAddressOnEveryPath(t *testing.T) {
	for _, path := range sessionCreatingPaths() {
		t.Run(path.name, func(t *testing.T) {
			app, dbCtr, db := SetupIntegration(t, nil)
			defer CleanupIntegration(t, dbCtr, db)

			cookie := path.create(t, app, nil)

			assert.Equal(t, "192.0.2.1", currentSessionIP(t, app, cookie),
				"the peer host, with no port attached")
		})
	}
}

// With a trusted proxy configured, the forwarded client address is recorded rather than
// the proxy's own. Asserted on login alone: the previous test already proves every path
// goes through the shared resolution, and this covers that resolution's wiring.
func Test_Integration_SessionRecordsForwardedClientIPWhenProxyTrusted(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, trustedProxyConfig())
	defer CleanupIntegration(t, dbCtr, db)

	rr := serve(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[DefaultUser].Email,
		"password": TestUserData[DefaultUser].Password,
	}, map[string]string{"X-Forwarded-For": "203.0.113.7"})
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "203.0.113.7", currentSessionIP(t, app, requireSessionCookie(t, rr)),
		"the real client, not the load balancer")
}

// The security-relevant case: with no trusted-proxy config, a forwarded header is
// client-supplied and must be ignored, so a caller can't choose what their own session
// record says.
func Test_Integration_SessionIgnoresForwardedHeaderWhenProxyUntrusted(t *testing.T) {
	app, dbCtr, db := SetupIntegration(t, nil)
	defer CleanupIntegration(t, dbCtr, db)

	rr := serve(t, app, http.MethodPost, PathLogin, nil, map[string]string{
		"email":    TestUserData[DefaultUser].Email,
		"password": TestUserData[DefaultUser].Password,
	}, map[string]string{"X-Forwarded-For": "203.0.113.7"})
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "192.0.2.1", currentSessionIP(t, app, requireSessionCookie(t, rr)),
		"a spoofed header must not reach the session record")
}
