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
	mw := ac.AuthMiddleware()

	mux.Handle("POST "+core.PathRegister, ac.RegisterHandler())
	mux.Handle("POST "+core.PathLogin, ac.LoginHandler())
	mux.HandleFunc("GET "+core.PathVerifyEmail, func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&StdHTTPParamExtractor{Req: r})(w, r)
	})
	mux.Handle("POST "+core.PathResendVerification, ac.ResendVerificationHandler())

	if ac.CanLoginWithOAuth() {
		mux.HandleFunc("GET "+core.PathOAuthBegin, gothic.BeginAuthHandler)
		mux.Handle("GET "+core.PathOAuthCallback, ac.OAuthCallbackHandler())
	}

	if ac.CanLoginWithMagicLink() {
		mux.Handle("POST "+core.PathSendMagicLink, ac.SendMagicLinkHandler())
		mux.HandleFunc("GET "+core.PathMagicLink, func(w http.ResponseWriter, r *http.Request) {
			ac.CompleteMagicLinkSignInHandler(&StdHTTPParamExtractor{Req: r})(w, r)
		})
	}

	mux.Handle("POST "+core.PathSendPasswordReset, ac.SendPasswordResetLinkHandler())
	mux.HandleFunc("PUT "+core.PathPasswordReset, func(w http.ResponseWriter, r *http.Request) {
		ac.CompletePasswordResetHandler(&StdHTTPParamExtractor{Req: r})(w, r)
	})

	mux.Handle("GET "+core.PathMe, mw(ac.GetMeHandler()))
	mux.Handle("POST "+core.PathLogout, mw(ac.LogoutHandler()))
}
