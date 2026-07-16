package conformance

import (
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
)

// Test_Conformance_AdaptersRegisterAllRoutes mounts every framework adapter from the
// same AuthClient and asserts each one serves every canonical route. Because the
// route table is shared via core's path constants, this is what guarantees a new
// endpoint can't be added to one adapter and forgotten in the others: any missing
// route returns 404 here and fails the test.
func Test_Conformance_AdaptersRegisterAllRoutes(t *testing.T) {
	db, ctr, err := core.CreateTestPostgres(t.Context())
	require.NoError(t, err)
	core.CleanupIntegration(t, ctr, db)

	dsn, err := ctr.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)

	// Enable both OAuth and magic-link so every conditionally-mounted route is present.
	ac, err := core.NewAuthClient(&core.AuthConfig{
		Db: &core.DatabaseConfig{Dsn: dsn},
		Session: &core.SessionConfig{
			MagicLinkSuccessfulRedirectURL: "http://localhost/success",
			MagicLinkFailedRedirectURL:     "http://localhost/failed",
		},
		OAuth: &core.OAuthConfig{Providers: []goth.Provider{
			github.New("client-id", "client-secret", "http://localhost"+core.PathOAuthCallback),
		}},
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
