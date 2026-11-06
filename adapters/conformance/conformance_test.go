package conformance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chiadapter "github.com/AdrianTworek/go-auth/adapters/chi"
	echoadapter "github.com/AdrianTworek/go-auth/adapters/echo"
	fiberadapter "github.com/AdrianTworek/go-auth/adapters/fiber"
	ginadapter "github.com/AdrianTworek/go-auth/adapters/gin"
	gorillaadapter "github.com/AdrianTworek/go-auth/adapters/gorilla"
	stdadapter "github.com/AdrianTworek/go-auth/adapters/stdhttp"
	"github.com/AdrianTworek/go-auth/core"
	"github.com/AdrianTworek/go-auth/core/mailer"
)

// Test_Conformance_AdaptersRegisterAllRoutes mounts every framework adapter from the
// same AuthClient and asserts each one serves every canonical route. Because the
// route table is shared via core's path constants, this is what guarantees a new
// endpoint can't be added to one adapter and forgotten in the others: any missing
// route returns 404 here and fails the test.
func Test_Conformance_AdaptersRegisterAllRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	db, ctr, err := core.CreateTestPostgres(t.Context())
	require.NoError(t, err)
	core.CleanupIntegration(t, ctr, db)

	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)

	// Enable OAuth, magic-link and MFA so every conditionally-mounted route is present.
	ac, err := core.NewAuthClient(&core.AuthConfig{
		Mailer: mailer.NewConsole("http://localhost"),
		Db:     &core.DatabaseConfig{Dsn: dsn},
		Session: &core.SessionConfig{
			MagicLinkSuccessfulRedirectURL: "http://localhost/success",
			MagicLinkFailedRedirectURL:     "http://localhost/failed",
			MagicLinkMFARedirectURL:        "http://localhost/mfa",
		},
		OAuth: &core.OAuthConfig{Providers: []goth.Provider{
			github.New("client-id", "client-secret", "http://localhost"+core.PathOAuthCallback),
		}},
		MFA: &core.MFAConfig{
			// #nosec G101 -- a fixed test key, not a credential
			EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		BaseURL:       "http://localhost",
		SessionSecret: "conformance-test-session-secret-0123456789",
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)

	chiMux := chi.NewRouter()
	chiadapter.InitAuth(ac, chiMux)

	ginEngine := gin.New()
	ginadapter.InitAuth(ac, ginEngine)

	echoSrv := echo.New()
	echoadapter.InitAuth(ac, echoSrv)

	gorillaRouter := mux.NewRouter()
	gorillaadapter.InitAuth(ac, gorillaRouter)

	stdMux := http.NewServeMux()
	stdadapter.InitAuth(ac, stdMux)

	fiberApp := fiber.New()
	fiberadapter.InitAuth(ac, fiberApp)

	// httpProbe serves an in-memory request against an http.Handler-based router and
	// returns the status code.
	httpProbe := func(h http.Handler) func(method, path string) int {
		return func(method, path string) int {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			return rec.Code
		}
	}

	probers := map[string]func(method, path string) int{
		"chi":     httpProbe(chiMux),
		"gin":     httpProbe(ginEngine),
		"echo":    httpProbe(echoSrv),
		"gorilla": httpProbe(gorillaRouter),
		"stdhttp": httpProbe(stdMux),
		// fiber is fasthttp-based, so it's probed through its own test harness.
		"fiber": func(method, path string) int {
			resp, err := fiberApp.Test(httptest.NewRequest(method, path, nil))
			if err != nil {
				return 0
			}
			return resp.StatusCode
		},
	}

	const token = "conformance-token"
	withToken := func(pattern string) string {
		return strings.Replace(pattern, "{token}", token, 1)
	}

	routes := []struct{ method, path string }{
		{http.MethodPost, core.PathRegister},
		{http.MethodPost, core.PathLogin},
		{http.MethodGet, withToken(core.PathVerifyEmail)},
		{http.MethodPost, core.PathResendVerification},
		{http.MethodGet, core.PathOAuthBegin + "?provider=github"},
		{http.MethodGet, core.PathOAuthCallback},
		{http.MethodPost, core.PathSendMagicLink},
		{http.MethodGet, withToken(core.PathMagicLink)},
		{http.MethodPost, core.PathSendPasswordReset},
		{http.MethodPut, withToken(core.PathPasswordReset)},
		{http.MethodGet, withToken(core.PathConfirmEmailChange)},
		{http.MethodGet, withToken(core.PathCancelEmailChange)},
		{http.MethodGet, core.PathMe},
		{http.MethodPost, core.PathLogout},
		{http.MethodPost, core.PathChangePassword},
		{http.MethodPost, core.PathChangeEmail},
		{http.MethodGet, core.PathSessions},
		{http.MethodDelete, core.PathSessions},
		{http.MethodDelete, strings.Replace(core.PathSession, "{id}", "conformance-session-id", 1)},
		{http.MethodGet, core.PathAccounts},
		{http.MethodDelete, strings.Replace(core.PathAccount, "{id}", "conformance-account-id", 1)},
		{http.MethodPost, core.PathMFATOTPSetup},
		{http.MethodPost, core.PathMFATOTPConfirm},
		{http.MethodPost, core.PathMFATOTPDisable},
		{http.MethodPost, core.PathMFABackupCodes},
		{http.MethodGet, core.PathMFAStatus},
		{http.MethodPost, core.PathMFAVerify},
	}

	for name, probe := range probers {
		for _, rt := range routes {
			t.Run(name+" "+rt.method+" "+rt.path, func(t *testing.T) {
				code := probe(rt.method, rt.path)
				// A registered route runs its handler/middleware and returns something
				// other than 404; only an unrouted path returns 404.
				assert.NotEqual(t, http.StatusNotFound, code,
					"adapter %q does not register %s %s", name, rt.method, rt.path)
			})
		}
	}
}

// Test_Conformance_MiddlewareExposesTheUserToConsumerRoutes protects a route the
// consumer owns with each adapter's Middleware and asserts the handler can read the
// signed-in user through core.UserFromContext. This is the path a consumer's own API
// takes, and the one that broke silently on gin, echo and fiber when the net/http
// middleware was wrapped by hand: the request carrying the user never reached the
// framework's context.
func Test_Conformance_MiddlewareExposesTheUserToConsumerRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	db, ctr, err := core.CreateTestPostgres(t.Context())
	require.NoError(t, err)
	core.CleanupIntegration(t, ctr, db)
	require.NoError(t, core.RunUpMigrations(db))

	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)
	ac, err := core.NewAuthClient(&core.AuthConfig{
		Mailer:        mailer.NewConsole("http://localhost"),
		Db:            &core.DatabaseConfig{Dsn: dsn},
		Session:       &core.SessionConfig{},
		RateLimit:     &core.RateLimitConfig{Enabled: core.Ptr(false)},
		BaseURL:       "http://localhost",
		SessionSecret: "conformance-test-session-secret-0123456789",
	})
	require.NoError(t, err)

	// Sign a user in through the library's own routes to get a real session cookie.
	const email, password = "consumer@example.com", "P@ssword123_0"
	authMux := chi.NewRouter()
	chiadapter.InitAuth(ac, authMux)
	post := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		authMux.ServeHTTP(rec, req)
		return rec
	}
	require.Equal(t, http.StatusCreated,
		post(core.PathRegister, `{"email":"`+email+`","password":"`+password+`","confirmPassword":"`+password+`"}`).Code)
	login := post(core.PathLogin, `{"email":"`+email+`","password":"`+password+`"}`)
	require.Equal(t, http.StatusOK, login.Code)
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == "session" {
			session = c
		}
	}
	require.NotNil(t, session, "login set no session cookie")

	// whoami is the consumer's handler: it answers with whoever UserFromContext says.
	const path = "/api/whoami"
	whoami := func(w http.ResponseWriter, r *http.Request) {
		u, ok := core.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "no user in context", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(u.Email))
	}

	gin.SetMode(gin.TestMode)

	chiMux := chi.NewRouter()
	chiMux.With(chiadapter.Middleware(ac)).Get(path, whoami)

	ginEngine := gin.New()
	ginEngine.GET(path, ginadapter.Middleware(ac), func(c *gin.Context) { whoami(c.Writer, c.Request) })

	echoSrv := echo.New()
	echoSrv.GET(path, func(c echo.Context) error {
		whoami(c.Response(), c.Request())
		return nil
	}, echoadapter.Middleware(ac))

	gorillaRouter := mux.NewRouter()
	gorillaRouter.Handle(path, gorillaadapter.Middleware(ac)(http.HandlerFunc(whoami)))

	stdMux := http.NewServeMux()
	stdMux.Handle("GET "+path, stdadapter.Middleware(ac)(http.HandlerFunc(whoami)))

	fiberApp := fiber.New()
	fiberApp.Get(path, fiberadapter.Middleware(ac), func(c *fiber.Ctx) error {
		u, ok := core.UserFromContext(c.UserContext())
		if !ok {
			return c.Status(http.StatusInternalServerError).SendString("no user in context")
		}
		return c.SendString(u.Email)
	})

	type result struct {
		code int
		body string
	}
	httpProbe := func(h http.Handler) func(*http.Request) result {
		return func(req *http.Request) result {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return result{rec.Code, rec.Body.String()}
		}
	}
	probers := map[string]func(*http.Request) result{
		"chi":     httpProbe(chiMux),
		"gin":     httpProbe(ginEngine),
		"echo":    httpProbe(echoSrv),
		"gorilla": httpProbe(gorillaRouter),
		"stdhttp": httpProbe(stdMux),
		"fiber": func(req *http.Request) result {
			resp, err := fiberApp.Test(req)
			if err != nil {
				return result{}
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return result{resp.StatusCode, string(b)}
		},
	}

	for name, probe := range probers {
		t.Run(name, func(t *testing.T) {
			anon := probe(httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusUnauthorized, anon.code, "%s let an anonymous request through", name)
			assert.NotContains(t, anon.body, email)

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(session)
			got := probe(req)
			assert.Equal(t, http.StatusOK, got.code, "%s: %s", name, got.body)
			assert.Equal(t, email, got.body, "%s did not expose the user to the consumer route", name)
		})
	}
}
