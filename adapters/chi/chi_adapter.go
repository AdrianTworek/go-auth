package chi_adapter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth/gothic"

	"github.com/AdrianTworek/go-auth/core"
)

type ChiParamExtractor struct {
	Req *http.Request
}

func (c *ChiParamExtractor) GetParam(key string) string {
	return chi.URLParam(c.Req, key)
}

func InitAuth(ac *core.AuthClient, r *chi.Mux) {
	if ac.CanLoginWithOAuth() {
		ac.SetupGoth()
	}
	// Protected handlers are pre-wrapped with the auth middleware so /me and /logout
	// need no special routing.
	mw := ac.AuthMiddleware()

	r.Post(core.PathRegister, ac.RegisterHandler())
	r.Post(core.PathLogin, ac.LoginHandler())
	r.Get(core.PathVerifyEmail, func(w http.ResponseWriter, r *http.Request) {
		ac.VerifyEmailHandler(&ChiParamExtractor{Req: r})(w, r)
	})

	if ac.CanLoginWithOAuth() {
		r.Get(core.PathOAuthBegin, gothic.BeginAuthHandler)
		r.Get(core.PathOAuthCallback, ac.OAuthCallbackHandler())
	}

	if ac.CanLoginWithMagicLink() {
		r.Post(core.PathSendMagicLink, ac.SendMagicLinkHandler())
		r.Get(core.PathMagicLink, func(w http.ResponseWriter, r *http.Request) {
			ac.CompleteMagicLinkSignInHandler(&ChiParamExtractor{Req: r})(w, r)
		})
	}

	r.Post(core.PathSendPasswordReset, ac.SendPasswordResetLinkHandler())
	r.Put(core.PathPasswordReset, func(w http.ResponseWriter, r *http.Request) {
		ac.CompletePasswordResetHandler(&ChiParamExtractor{Req: r})(w, r)
	})

	r.Method(http.MethodGet, core.PathMe, mw(ac.GetMeHandler()))
	r.Method(http.MethodPost, core.PathLogout, mw(ac.LogoutHandler()))
}
