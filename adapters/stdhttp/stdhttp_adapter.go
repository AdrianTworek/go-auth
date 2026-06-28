package stdhttp_adapter

import (
	"net/http"

	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type StdHTTPParamExtractor struct {
	Req *http.Request
}

func (s *StdHTTPParamExtractor) GetParam(key string) string {
	return s.Req.PathValue(key)
}

func InitAuth(ac *core.AuthClient, mux *http.ServeMux) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}

	mux.Handle("POST /auth/register", ac.RegisterHandler())
	mux.Handle("POST /auth/login", ac.LoginHandler())
	mux.HandleFunc("GET /auth/verify/{token}", func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&StdHTTPParamExtractor{Req: r})(w, r)
	})

	if ac.CanLoginWithOAuth() {
		mux.HandleFunc("GET /auth/oauth", gothic.BeginAuthHandler)
		mux.Handle("GET /auth/oauth/callback", ac.OAuthCallbackHandler())
	}

	mux.Handle("POST /auth/magic-link", ac.SendMagicLinkHandler())
	mux.HandleFunc("GET /auth/magic-link/{token}", func(w http.ResponseWriter, r *http.Request) {
		ac.CompleteMagicLinkSignInHandler(&StdHTTPParamExtractor{Req: r})(w, r)
	})

	mux.Handle("POST /auth/reset-password", ac.SendPasswordResetLinkHandler())
	mux.HandleFunc("PUT /auth/reset-password/{token}", func(w http.ResponseWriter, r *http.Request) {
		ac.CompletePasswordResetHandler(&StdHTTPParamExtractor{Req: r})(w, r)
	})

	authMiddleware := ac.AuthMiddleware()
	mux.Handle("GET /auth/me", authMiddleware(ac.GetMeHandler()))
	mux.Handle("POST /auth/logout", authMiddleware(ac.LogoutHandler()))
}
